package api

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

//go:embed agentinstall/linux-uninstall.sh
var linuxUninstallScriptRaw []byte

//go:embed agentinstall/mac-uninstall.sh
var macUninstallScriptRaw []byte

// Line endings are normalised because a Windows checkout may have turned them into CRLF.
var (
	linuxUninstallScriptSource = bytes.ReplaceAll(linuxUninstallScriptRaw, []byte("\r\n"), []byte("\n"))
	macUninstallScriptSource   = bytes.ReplaceAll(macUninstallScriptRaw, []byte("\r\n"), []byte("\n"))
)

// readVerifiedAgents reads each named agent from the agents folder and checks it against the signed manifest. A file
// that is missing, not listed, or whose hash differs means nothing is served. The returned status is the HTTP status
// to answer with (0 when everything is fine).
func (h *Handler) readVerifiedAgents(names []string) (map[string][]byte, int, string) {
	if h.manifest == nil || !h.manifest.Loaded() {
		return nil, http.StatusServiceUnavailable, "the integrity manifest is not loaded, so the uninstaller cannot be verified"
	}
	out := map[string][]byte{}
	for _, name := range names {
		data, err := os.ReadFile(filepath.Join(agentArtifactDir, name))
		if err != nil {
			return nil, http.StatusNotFound, "the agent " + name + " is not available on this server"
		}
		want, listed := h.manifest.KnownHash(name)
		sum := sha256.Sum256(data)
		if !listed || hex.EncodeToString(sum[:]) != want {
			log.Printf("[!!] TAMPER: %q is not listed in, or does not match, the signed manifest -- refusing to serve", name)
			return nil, http.StatusInternalServerError, "agent installer failed integrity verification"
		}
		out[name] = data
	}
	return out, 0, ""
}

func sortedNames(files map[string][]byte) []string {
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// sumsFile is the "hash  name" list the uninstall scripts check an agent against before running it.
func sumsFile(files map[string][]byte) string {
	var b strings.Builder
	for _, n := range sortedNames(files) {
		s := sha256.Sum256(files[n])
		b.WriteString(hex.EncodeToString(s[:]) + "  " + n + "\n")
	}
	return b.String()
}

// buildLinuxUninstallRun is the self-extracting Linux uninstaller: the shell header followed by a tar.gz holding the
// agents and their hashes.
func buildLinuxUninstallRun(files map[string][]byte) ([]byte, error) {
	return buildLinuxUninstallRunWithSums(files, sumsFile(files))
}

func buildLinuxUninstallRunWithSums(files map[string][]byte, sums string) ([]byte, error) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	now := time.Now()
	add := func(name string, mode int64, data []byte) error {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: mode, Size: int64(len(data)), ModTime: now, Typeflag: tar.TypeReg}); err != nil {
			return err
		}
		_, err := tw.Write(data)
		return err
	}
	for _, n := range sortedNames(files) {
		if err := add(n, 0o755, files[n]); err != nil {
			return nil, err
		}
	}
	if err := add("agents.sha256", 0o644, []byte(sums)); err != nil {
		return nil, err
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return append(append([]byte{}, linuxUninstallScriptSource...), buf.Bytes()...), nil
}

// serveLinuxUninstall serves the Linux uninstaller. It carries no server details and no secret.
func (h *Handler) serveLinuxUninstall(w http.ResponseWriter, r *http.Request) {
	agents, status, msg := h.readVerifiedAgents([]string{"bas-agent-linux-amd64", "bas-agent-linux-arm64"})
	if status != 0 {
		jsonError(w, msg, status)
		return
	}
	body, err := buildLinuxUninstallRun(agents)
	if err != nil {
		jsonError(w, "could not pack the uninstaller", http.StatusInternalServerError)
		return
	}
	if h.db != nil {
		h.auditLog(r, "agent.download_uninstaller", "linux", nil, "ok")
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="bas-agent-uninstall-linux.run"`)
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(body)
}

const macUninstallAppDir = "Audspect Agent Uninstall.app/"

const macUninstallInfoPlist = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleName</key><string>Audspect Agent Uninstall</string>
	<key>CFBundleDisplayName</key><string>Audspect Agent Uninstall</string>
	<key>CFBundleIdentifier</key><string>com.audspect.agent-uninstall</string>
	<key>CFBundleExecutable</key><string>uninstall</string>
	<key>CFBundleIconFile</key><string>AppIcon</string>
	<key>CFBundlePackageType</key><string>APPL</string>
	<key>CFBundleVersion</key><string>1</string>
	<key>CFBundleShortVersionString</key><string>1.0</string>
	<key>LSMinimumSystemVersion</key><string>12.0</string>
	<key>LSUIElement</key><true/>
</dict>
</plist>
`

// buildMacUninstallApp zips "Audspect Agent Uninstall.app". agents is keyed by "arm64" and "x86_64".
func buildMacUninstallApp(agents map[string][]byte) ([]byte, error) {
	files := map[string][]byte{}
	for arch, data := range agents {
		if arch != "arm64" && arch != "x86_64" {
			return nil, fmt.Errorf("unknown architecture %q", arch)
		}
		if len(data) == 0 {
			return nil, fmt.Errorf("the %s agent is empty", arch)
		}
		files["bas-agent-"+arch] = data
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("no agent to pack")
	}
	type entry struct {
		name string
		mode os.FileMode
		data []byte
	}
	entries := []entry{
		{"Contents/Info.plist", 0o644, []byte(macUninstallInfoPlist)},
		{"Contents/MacOS/uninstall", 0o755, macUninstallScriptSource},
		{"Contents/Resources/AppIcon.icns", 0o644, macAppIcon},
		{"Contents/Resources/agents.sha256", 0o644, []byte(sumsFile(files))},
	}
	for _, n := range sortedNames(files) {
		entries = append(entries, entry{"Contents/Resources/" + n, 0o755, files[n]})
	}
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	now := time.Now()
	for _, e := range entries {
		hdr := &zip.FileHeader{Name: macUninstallAppDir + e.name, Method: zip.Deflate, Modified: now}
		hdr.SetMode(e.mode)
		w, err := zw.CreateHeader(hdr)
		if err != nil {
			return nil, err
		}
		if _, err := w.Write(e.data); err != nil {
			return nil, err
		}
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// serveMacUninstall serves the macOS uninstall app (both Mac builds inside, verified against the signed manifest).
func (h *Handler) serveMacUninstall(w http.ResponseWriter, r *http.Request) {
	agents, status, msg := h.readVerifiedAgents([]string{"bas-agent-darwin-arm64", "bas-agent-darwin-amd64"})
	if status != 0 {
		jsonError(w, msg, status)
		return
	}
	body, err := buildMacUninstallApp(map[string][]byte{"arm64": agents["bas-agent-darwin-arm64"], "x86_64": agents["bas-agent-darwin-amd64"]})
	if err != nil {
		jsonError(w, "could not build the uninstall app", http.StatusInternalServerError)
		return
	}
	if h.db != nil {
		h.auditLog(r, "agent.download_uninstaller", "macos", nil, "ok")
	}
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", `attachment; filename="AudspectAgent-Uninstall-mac.zip"`)
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(body)
}
