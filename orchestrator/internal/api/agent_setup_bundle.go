package api

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)


// linuxSetupFileName is the name the browser saves the setup file under.
const linuxSetupFileName = "bas-agent-setup-linux.run"

// linuxSetupScriptTemplate is the shell header of the setup file. The archive follows the line
// __ARCHIVE_BELOW__; the header finds that line, cuts the archive off with tail, and extracts it. Only
// the host and the four ports are filled in, and both are validated before they reach this template.
const linuxSetupScriptTemplate = `#!/bin/sh
# Audspect BAS agent setup for Linux (x86_64). Run as root:  sudo ./bas-agent-setup-linux.run
# It asks for the agent secret. The server details, the deployment CA and the agent are inside this file.
set -eu
if [ "$(id -u)" -ne 0 ]; then echo "run as root: sudo sh $0" >&2; exit 1; fi
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
OFFSET=$(awk '/^__ARCHIVE_BELOW__$/ { print NR + 1; exit 0 }' "$0")
tail -n +"$OFFSET" "$0" | tar -xz -C "$TMP"
cd "$TMP"
BAS_SERVER_HOST=%s BAS_ENROLL_PORT=%d BAS_MTLS_PORT=%d BAS_DASHBOARD_PORT=%d %s\
  bash install-agent-linux.sh --ca-file ./deployment-ca.pem --agent ./bas-agent-linux-%s
exit 0
__ARCHIVE_BELOW__
`

// setupHostPattern allows a DNS name or an IPv4 address. Anything else (IPv6 literals, spaces, shell
// metacharacters) is refused, because the host is written into a shell script.
var setupHostPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$`)

// buildLinuxSetupScript returns the amd64 shell header for a setup file, with the server details filled in.
func buildLinuxSetupScript(host string, enrollPort, mtlsPort, dashPort int) ([]byte, error) {
	return buildLinuxSetupScriptFor(host, enrollPort, mtlsPort, dashPort, "amd64", false)
}

// linuxSetupArchitectures are the CPU architectures the Linux setup file is built for.
var linuxSetupArchitectures = map[string]bool{"amd64": true, "arm64": true}

// buildLinuxSetupScriptFor is buildLinuxSetupScript for one architecture. When the server issues enrolment
// tokens the header sets BAS_TOKEN_REQUIRED, so the installer insists on a token instead of offering to skip it.
func buildLinuxSetupScriptFor(host string, enrollPort, mtlsPort, dashPort int, arch string, tokenRequired bool) ([]byte, error) {
	if !linuxSetupArchitectures[arch] {
		return nil, fmt.Errorf("unknown architecture %q", arch)
	}
	if !setupHostPattern.MatchString(host) {
		return nil, fmt.Errorf("server host %q is not a plain host name or IPv4 address", host)
	}
	for name, p := range map[string]int{"enroll": enrollPort, "mTLS": mtlsPort, "dashboard": dashPort} {
		if p < 1 || p > 65535 {
			return nil, fmt.Errorf("%s port %d is out of range", name, p)
		}
	}
	tokenEnv := ""
	if tokenRequired {
		tokenEnv = "BAS_TOKEN_REQUIRED=1 "
	}
	return []byte(fmt.Sprintf(linuxSetupScriptTemplate, host, enrollPort, mtlsPort, dashPort, tokenEnv, arch)), nil
}

// buildLinuxSetupArchive packs the installer, the agent and the deployment CA into a gzip'd tar.
func buildLinuxSetupArchive(agent, installScript, caPEM []byte) ([]byte, error) {
	return buildLinuxSetupArchiveFor("amd64", agent, installScript, caPEM)
}

// buildLinuxSetupArchiveFor packs the agent under the name the header expects for its architecture.
func buildLinuxSetupArchiveFor(arch string, agent, installScript, caPEM []byte) ([]byte, error) {
	if !linuxSetupArchitectures[arch] {
		return nil, fmt.Errorf("unknown architecture %q", arch)
	}
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	entries := []struct {
		name string
		mode int64
		data []byte
	}{
		{"install-agent-linux.sh", 0o755, installScript},
		{"bas-agent-linux-" + arch, 0o755, agent},
		{"deployment-ca.pem", 0o644, caPEM},
	}
	now := time.Now()
	for _, e := range entries {
		hdr := &tar.Header{Name: e.name, Mode: e.mode, Size: int64(len(e.data)), ModTime: now, Typeflag: tar.TypeReg}
		if err := tw.WriteHeader(hdr); err != nil {
			return nil, err
		}
		if _, err := tw.Write(e.data); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// verifiedAgentFile reads an agent binary from ./agents and checks it against the signed manifest,
// the same check DownloadAgent makes. A file that is not listed, or whose hash differs, is refused.
func (h *Handler) verifiedAgentFile(filename string) ([]byte, error) {
	data, err := os.ReadFile(filepath.Join(agentArtifactDir, filename))
	if err != nil {
		return nil, fmt.Errorf("agent binary not found: %s", filename)
	}
	if m := h.manifest; m != nil && m.Loaded() {
		want, listed := m.KnownHash(filename)
		if !listed {
			log.Printf("[!!] TAMPER: agent binary %q is not listed in the signed manifest -- refusing to pack it", filename)
			return nil, fmt.Errorf("agent binary failed integrity verification")
		}
		sum := sha256.Sum256(data)
		if got := hex.EncodeToString(sum[:]); got != want {
			log.Printf("[!!] TAMPER: agent binary %q hash mismatch -- manifest %s, on disk %s -- refusing to pack it", filename, want, got)
			return nil, fmt.Errorf("agent binary failed integrity verification")
		}
	}
	return data, nil
}

// serveLinuxSetup builds the Linux setup file for this deployment: the CA, the server details and the
// verified agent, with the secret left to be typed at install time.
func (h *Handler) serveLinuxSetup(w http.ResponseWriter, r *http.Request) {
	h.serveLinuxSetupFor(w, r, "amd64")
}

// serveLinuxSetupFor is serveLinuxSetup for one architecture.
func (h *Handler) serveLinuxSetupFor(w http.ResponseWriter, r *http.Request, arch string) {
	if h.pki == nil {
		jsonError(w, "the deployment CA is not configured on this server", http.StatusServiceUnavailable)
		return
	}
	caPEM := []byte(h.pki.RootCertPEM())
	if len(caPEM) == 0 {
		jsonError(w, "the deployment CA is not configured on this server", http.StatusServiceUnavailable)
		return
	}
	agentBin, err := h.verifiedAgentFile("bas-agent-linux-" + arch)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	enrollPort := h.advertisedEnrollPort
	if enrollPort <= 0 {
		enrollPort = 9444
	}
	mtlsPort := h.advertisedMTLSPort
	if mtlsPort <= 0 {
		mtlsPort = 9443
	}
	dashPort := 9543
	if _, p, err := net.SplitHostPort(r.Host); err == nil {
		if n, err := strconv.Atoi(p); err == nil {
			dashPort = n
		}
	}
	script, err := buildLinuxSetupScriptFor(requestHost(r), enrollPort, mtlsPort, dashPort, arch, h.tokenEnrollment())
	if err != nil {
		jsonError(w, "could not build the setup file: "+err.Error(), http.StatusBadRequest)
		return
	}
	archive, err := buildLinuxSetupArchiveFor(arch, agentBin, installAgentLinuxScript, caPEM)
	if err != nil {
		jsonError(w, "could not pack the setup file", http.StatusInternalServerError)
		return
	}
	body := append(script, archive...)
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="`+strings.Replace(linuxSetupFileName, "linux", "linux-"+arch, 1)+`"`)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	_, _ = w.Write(body)
}
