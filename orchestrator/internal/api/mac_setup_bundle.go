package api

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/audspect/bas/internal/deployconfig"
)

//go:embed agentinstall/mac-setup.sh
var macSetupScriptRaw []byte

// macSetupScriptSource is the program inside the app. Line endings are normalised because a Windows checkout may
// have turned them into CRLF, which /bin/sh on macOS would read as part of every command.
var macSetupScriptSource = bytes.ReplaceAll(macSetupScriptRaw, []byte("\r\n"), []byte("\n"))

const macAppDir = "Audspect Agent Setup.app/"

const macInfoPlist = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleName</key><string>Audspect Agent Setup</string>
	<key>CFBundleDisplayName</key><string>Audspect Agent Setup</string>
	<key>CFBundleIdentifier</key><string>com.audspect.agent-setup</string>
	<key>CFBundleExecutable</key><string>setup</string>
	<key>CFBundlePackageType</key><string>APPL</string>
	<key>CFBundleVersion</key><string>1</string>
	<key>CFBundleShortVersionString</key><string>1.0</string>
	<key>LSMinimumSystemVersion</key><string>12.0</string>
	<key>LSUIElement</key><true/>
</dict>
</plist>
`

// macArchitectures maps the download's architecture to what `uname -m` reports on that Mac.
var macArchitectures = map[string]string{"arm64": "arm64", "amd64": "x86_64"}

// buildMacSetupApp zips "Audspect Agent Setup.app": a double-clickable app whose program is the setup script and whose
// Resources hold the verified agent, its hash, the signed deployment configuration and the signing fingerprint.
// The agent secret is never part of it. When the server issues enrolment tokens the app also carries the marker
// that makes it ask for one.
func buildMacSetupApp(agent, deploymentJSON []byte, fingerprint, arch string, tokenRequired bool) ([]byte, error) {
	if !fingerprintRe.MatchString(fingerprint) {
		return nil, fmt.Errorf("fingerprint must be 64 lowercase hex characters")
	}
	uname, ok := macArchitectures[arch]
	if !ok {
		return nil, fmt.Errorf("unknown architecture %q", arch)
	}
	if len(agent) == 0 {
		return nil, fmt.Errorf("the agent binary is empty")
	}
	sum := sha256.Sum256(agent)
	files := []struct {
		name string
		mode os.FileMode
		data []byte
	}{
		{"Contents/Info.plist", 0o644, []byte(macInfoPlist)},
		{"Contents/MacOS/setup", 0o755, macSetupScriptSource},
		{"Contents/Resources/bas-agent", 0o755, agent},
		{"Contents/Resources/agent.sha256", 0o644, []byte(hex.EncodeToString(sum[:]) + "\n")},
		{"Contents/Resources/arch", 0o644, []byte(uname + "\n")},
		{"Contents/Resources/deployment.json", 0o644, deploymentJSON},
		{"Contents/Resources/deployment.fingerprint", 0o644, []byte(fingerprint + "\n")},
	}
	if tokenRequired {
		files = append(files, struct {
			name string
			mode os.FileMode
			data []byte
		}{"Contents/Resources/enrollment-token.required", 0o644, []byte("This server issues single-use enrolment tokens; the setup asks for one.\n")})
	}
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	now := time.Now()
	for _, f := range files {
		hdr := &zip.FileHeader{Name: macAppDir + f.name, Method: zip.Deflate, Modified: now}
		hdr.SetMode(f.mode)
		w, err := zw.CreateHeader(hdr)
		if err != nil {
			return nil, err
		}
		if _, err := w.Write(f.data); err != nil {
			return nil, err
		}
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// serveMacSetup builds the per-request macOS setup app for one architecture: the agent (verified against the signed
// manifest before it is packed), a freshly signed deployment configuration and the setup script. It fails closed in
// the same way as the Windows bundle: no signing key, no loaded manifest, or an agent that is missing, unlisted or
// altered means nothing is served.
func (h *Handler) serveMacSetup(w http.ResponseWriter, r *http.Request, arch string) {
	if h.signingKey == nil {
		jsonError(w, "no signing key is configured on this server", http.StatusServiceUnavailable)
		return
	}
	if h.manifest == nil || !h.manifest.Loaded() {
		jsonError(w, "the integrity manifest is not loaded, so the installer cannot be verified", http.StatusServiceUnavailable)
		return
	}
	filename := "bas-agent-darwin-" + arch
	data, err := os.ReadFile(filepath.Join(agentArtifactDir, filename))
	if err != nil {
		jsonError(w, "the macOS agent is not available on this server", http.StatusNotFound)
		return
	}
	want, listed := h.manifest.KnownHash(filename)
	sum := sha256.Sum256(data)
	if !listed || hex.EncodeToString(sum[:]) != want {
		log.Printf("[!!] TAMPER: %q is not listed in, or does not match, the signed manifest -- refusing to serve", filename)
		jsonError(w, "agent installer failed integrity verification", http.StatusInternalServerError)
		return
	}
	cfg := deployconfig.Config{
		ServerURL:  "https://" + requestHost(r) + ":" + portOrDefault(h.advertisedMTLSPort, "9443"),
		EnrollPort: portOrDefault(h.advertisedEnrollPort, "9444"),
		IssuedAt:   time.Now().UTC(),
	}
	if h.pki != nil {
		cfg.CARootPEM = string(h.pki.RootCertPEM())
	}
	env, err := deployconfig.Build(h.signingKey, cfg)
	if err != nil {
		jsonError(w, "could not build the deployment configuration: "+err.Error(), http.StatusInternalServerError)
		return
	}
	fp, err := deployconfig.Fingerprint(h.signingKey.CertPEM())
	if err != nil {
		jsonError(w, "could not compute the signing fingerprint: "+err.Error(), http.StatusInternalServerError)
		return
	}
	bundle, err := buildMacSetupApp(data, env, fp, arch, h.tokenEnrollment())
	if err != nil {
		jsonError(w, "could not build the setup app: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if h.db != nil {
		h.auditLog(r, "agent.download_mac_setup", "darwin-"+arch, map[string]any{"fingerprint": fp}, "ok")
	}
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", `attachment; filename="AudspectAgent-Setup-mac-`+arch+`.zip"`)
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(bundle)
}
