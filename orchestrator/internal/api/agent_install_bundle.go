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
)

// agentInstallDefaults is the per-download, per-deployment config bundled
// alongside a GUI installer so it never has to ask the operator for the
// Server URL -- only the Secret. Not sensitive: a server URL and a port are
// not credentials, so this rides along unencrypted in the downloaded zip.
type agentInstallDefaults struct {
	ServerURL  string `json:"serverURL"`
	EnrollPort string `json:"enrollPort,omitempty"`
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

// buildAgentDefaultsJSON mirrors the defaults web/src/features/attack-path.js's
// buildAgentInstallCommands already bakes into the copy-paste CLI commands
// (same 9443/9444 fallbacks), so a GUI installer download and the CLI
// command shown on the same page always agree.
func buildAgentDefaultsJSON(host string, mtlsPort, enrollPort int) ([]byte, error) {
	if mtlsPort <= 0 {
		mtlsPort = 9443
	}
	if enrollPort <= 0 {
		enrollPort = 9444
	}
	d := agentInstallDefaults{
		ServerURL:  "https://" + host + ":" + strconv.Itoa(mtlsPort),
		EnrollPort: strconv.Itoa(enrollPort),
	}
	return json.Marshal(d)
}

// bundleInstallerZip wraps a bare installer executable (the macOS one-click
// installer, which is not itself a zip) together with bas-agent-defaults.json
// into a new zip, so the installer finds its defaults sitting right next to
// itself once the operator extracts it. execName is used as both the zip
// entry name and, by convention, what callers should extract it to.
func bundleInstallerZip(execName string, execBytes, defaults []byte) ([]byte, error) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)

	exeHeader := &zip.FileHeader{Name: execName, Method: zip.Deflate}
	exeHeader.SetMode(0755)
	exeWriter, err := zw.CreateHeader(exeHeader)
	if err != nil {
		return nil, fmt.Errorf("create %s entry: %w", execName, err)
	}
	if _, err := exeWriter.Write(execBytes); err != nil {
		return nil, fmt.Errorf("write %s entry: %w", execName, err)
	}

	defWriter, err := zw.Create("bas-agent-defaults.json")
	if err != nil {
		return nil, fmt.Errorf("create defaults entry: %w", err)
	}
	if _, err := defWriter.Write(defaults); err != nil {
		return nil, fmt.Errorf("write defaults entry: %w", err)
	}

	if err := zw.Close(); err != nil {
		return nil, fmt.Errorf("close zip: %w", err)
	}
	return buf.Bytes(), nil
}

// addDefaultsToZip copies every entry of an existing zip (the pre-built
// Windows BASAgent-Setup.zip) byte-for-byte into a new zip and adds
// bas-agent-defaults.json alongside them. The original entries' bytes are
// never touched -- only a new file is added -- so this never has to
// re-verify anything about them beyond what the caller already checked
// against the signed manifest before calling this.
func addDefaultsToZip(existingZip, defaults []byte) ([]byte, error) {
	zr, err := zip.NewReader(bytes.NewReader(existingZip), int64(len(existingZip)))
	if err != nil {
		return nil, fmt.Errorf("open existing zip: %w", err)
	}

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, f := range zr.File {
		w, err := zw.CreateHeader(&f.FileHeader)
		if err != nil {
			return nil, fmt.Errorf("copy entry %s: %w", f.Name, err)
		}
		rc, err := f.Open()
		if err != nil {
			return nil, fmt.Errorf("open entry %s: %w", f.Name, err)
		}
		if _, err := io.Copy(w, rc); err != nil {
			rc.Close()
			return nil, fmt.Errorf("copy entry %s contents: %w", f.Name, err)
		}
		rc.Close()
	}

	defWriter, err := zw.Create("bas-agent-defaults.json")
	if err != nil {
		return nil, fmt.Errorf("create defaults entry: %w", err)
	}
	if _, err := defWriter.Write(defaults); err != nil {
		return nil, fmt.Errorf("write defaults entry: %w", err)
	}

	if err := zw.Close(); err != nil {
		return nil, fmt.Errorf("close zip: %w", err)
	}
	return buf.Bytes(), nil
}
