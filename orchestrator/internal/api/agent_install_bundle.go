package api

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
)

// Sentinel markers and slot size mirror installer/embedconfig.go,
// byte-for-byte. They cannot share a Go const across these two separate
// modules, so each side's own test pins its copy to this exact literal --
// a drift between the two shows up as a test failure on whichever side
// changes first, not as a silent runtime mismatch.
const (
	embeddedConfigBeginMarker = "BAS_AGENT_DEFAULTS_BEGIN_v1::"
	embeddedConfigEndMarker   = "::BAS_AGENT_DEFAULTS_END_v1"
	embeddedConfigSlotSize    = 8192
	embeddedConfigFillByte    = '~'
)

// agentInstallConfig is the deployment-specific configuration patched into
// a GUI installer's embed slot. Mirrors installer/embedconfig.go's type
// of the same shape on the other side of the module boundary.
type agentInstallConfig struct {
	ServerURL  string `json:"serverURL"`
	EnrollPort string `json:"enrollPort"`
	CARootPEM  string `json:"caRootPem"`
}

// requestHost returns the hostname the browser used to reach this request,
// with any port stripped -- the agent must connect on the mTLS port
// (advertisedMTLSPort), never the dashboard port this request itself
// arrived on.
func requestHost(r *http.Request) string {
	if h, _, err := net.SplitHostPort(r.Host); err == nil {
		return h
	}
	return r.Host
}

// buildAgentInstallConfigJSON mirrors the same 9443/9444 fallbacks
// web/src/features/attack-path.js's buildAgentInstallCommands already
// bakes into the copy-paste CLI commands, so a GUI installer download and
// the CLI command shown on the same page always agree. caRootPEM is the
// deployment's own CA root (h.pki.RootCertPEM() at the call site) --
// embedding it here, inside the same manifest-verified artifact, is what
// lets the installer verify its own bootstrap connection instead of
// trusting serverURL blindly (see installer/ca_fetch.go's
// trustingHTTPClient). Empty when PKI isn't configured server-side; the
// installer falls back to its pre-existing insecure-bootstrap behavior in
// that case, same residual exposure as before this mechanism existed.
func buildAgentInstallConfigJSON(host string, mtlsPort, enrollPort int, caRootPEM string) ([]byte, error) {
	if mtlsPort <= 0 {
		mtlsPort = 9443
	}
	if enrollPort <= 0 {
		enrollPort = 9444
	}
	cfg := agentInstallConfig{
		ServerURL:  "https://" + host + ":" + strconv.Itoa(mtlsPort),
		EnrollPort: strconv.Itoa(enrollPort),
		CARootPEM:  caRootPEM,
	}
	return json.Marshal(cfg)
}

// findEmbedSlot scans binary for the unique occurrence of the full embed
// slot pattern (begin marker, exactly embeddedConfigSlotSize bytes, end
// marker) and returns the offset of the content region (right after the
// begin marker). Deliberately does NOT count bare occurrences of the
// marker text: the marker constants are also used as plain
// strings.Index/Contains arguments on the installer side (see
// embedconfig.go there), which the Go compiler keeps as their own
// independent rodata entry -- so a real compiled installer binary
// legitimately contains the bare marker text more than once. What must
// be unique is the position where a begin marker is immediately followed,
// at exactly the right distance, by an end marker.
func findEmbedSlot(binary []byte) (contentStart int, err error) {
	s := string(binary)
	if !strings.Contains(s, embeddedConfigBeginMarker) && !strings.Contains(s, embeddedConfigEndMarker) {
		return 0, fmt.Errorf("binary has no embed-config markers at all")
	}

	var found, matches int
	searchFrom := 0
	for {
		idx := strings.Index(s[searchFrom:], embeddedConfigBeginMarker)
		if idx == -1 {
			break
		}
		idx += searchFrom
		cs := idx + len(embeddedConfigBeginMarker)
		ce := cs + embeddedConfigSlotSize
		if ce+len(embeddedConfigEndMarker) <= len(s) && s[ce:ce+len(embeddedConfigEndMarker)] == embeddedConfigEndMarker {
			matches++
			found = cs
		}
		searchFrom = idx + 1
	}

	if matches != 1 {
		return 0, fmt.Errorf("embed-config slot pattern (begin marker + %d-byte gap + end marker) occurs %d times, want exactly 1", embeddedConfigSlotSize, matches)
	}
	return found, nil
}

// patchEmbeddedConfig overwrites the verified binary's unique embed slot
// with cfgJSON, fill-byte-padded to the slot's fixed size, and returns a
// NEW byte slice (never mutates binary) of the exact same total length.
//
// This function patches ONLY the slot region it locates; it does nothing
// to re-establish a signature over the result. The caller (DownloadAgent)
// is expected to have already verified binary's bytes against the signed
// BINARIES.sha256 manifest BEFORE calling this -- that verification
// covers the pristine, as-built artifact only. The bytes patchEmbeddedConfig
// returns are a new, per-request artifact whose trustworthiness rests on
// (a) that prior verification of the base binary, (b) this function's own
// strict validation of the patch target and size, and (c) cfgJSON being
// built here, server-side, from data this deployment's own authenticated
// state (advertised ports, this server's own PKI root) rather than from
// anything caller-supplied -- never on a signature over the final bytes,
// which this deliberately does not attempt (see the package doc comment
// on why that would not add real protection for an on-prem server whose
// own address is inherently the varying, non-hardcodable part).
func patchEmbeddedConfig(binary, cfgJSON []byte) ([]byte, error) {
	contentStart, err := findEmbedSlot(binary)
	if err != nil {
		return nil, err
	}
	if len(cfgJSON) > embeddedConfigSlotSize {
		return nil, fmt.Errorf("embedded config is %d bytes, exceeds the %d-byte slot", len(cfgJSON), embeddedConfigSlotSize)
	}

	patched := make([]byte, len(binary))
	copy(patched, binary)

	slot := patched[contentStart : contentStart+embeddedConfigSlotSize]
	for i := range slot {
		slot[i] = embeddedConfigFillByte
	}
	copy(slot, cfgJSON)

	return patched, nil
}

// patchEmbeddedConfigInZip applies patchEmbeddedConfig to the single entry
// of a pre-built installer zip (the Windows BASAgent-Setup.zip shape) and
// re-zips it under the same entry name and compression method. Fails
// closed on anything other than exactly one entry: a zip with more than
// one file is not a shape this mechanism was built to patch, and silently
// patching only the first would leave operators thinking the whole
// archive was handled.
func patchEmbeddedConfigInZip(zipBytes, cfgJSON []byte) ([]byte, error) {
	zr, err := zip.NewReader(bytes.NewReader(zipBytes), int64(len(zipBytes)))
	if err != nil {
		return nil, fmt.Errorf("open installer zip: %w", err)
	}
	if len(zr.File) != 1 {
		return nil, fmt.Errorf("installer zip has %d entries, want exactly 1", len(zr.File))
	}
	entry := zr.File[0]

	rc, err := entry.Open()
	if err != nil {
		return nil, fmt.Errorf("open zip entry %s: %w", entry.Name, err)
	}
	content, err := io.ReadAll(rc)
	rc.Close()
	if err != nil {
		return nil, fmt.Errorf("read zip entry %s: %w", entry.Name, err)
	}

	patchedContent, err := patchEmbeddedConfig(content, cfgJSON)
	if err != nil {
		return nil, fmt.Errorf("patch zip entry %s: %w", entry.Name, err)
	}

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.CreateHeader(&entry.FileHeader)
	if err != nil {
		return nil, fmt.Errorf("recreate zip entry %s: %w", entry.Name, err)
	}
	if _, err := w.Write(patchedContent); err != nil {
		return nil, fmt.Errorf("write patched zip entry %s: %w", entry.Name, err)
	}
	if err := zw.Close(); err != nil {
		return nil, fmt.Errorf("close patched zip: %w", err)
	}
	return buf.Bytes(), nil
}
