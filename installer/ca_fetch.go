//go:build windows

package main

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// bootstrapHTTPClient returns an HTTP client for talking to the orchestrator
// BEFORE the deployment CA is trusted. Like the dashboard's generated install
// command (curl -fsSk) and the Linux package's systemd unit (curl -sfk), it
// skips TLS verification for these pre-trust calls. This is correct and
// necessary: the default deployment (BAS_TLS=false) serves a self-signed cert
// that chains only to the very CA we are about to fetch, so a verifying client
// could never connect; /api/config/ca-root returns only the PUBLIC CA
// certificate (never a key); and enrollment is authenticated by the agent
// secret, not by this transport. Once the CA is placed, the agent verifies the
// full chain against it for every later connection (see agent/bootstrap.go).
func bootstrapHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // pre-trust bootstrap fetch; see doc comment
		},
	}
}

// fetchDeploymentCA downloads the public deployment CA root from the
// orchestrator's unauthenticated /api/config/ca-root endpoint and writes it
// next to the agent binary, returning the path to pass to the agent as
// --ca-root. Without this the agent has no trust anchor on disk: its bootstrap
// aborts ("read deployment CA root ... expected to be placed by the
// installer") and it is stranded on legacy transport forever. The fetch uses
// bootstrapHTTPClient because it runs before any trust exists.
func fetchDeploymentCA(serverURL, destDir string) (string, error) {
	url := strings.TrimRight(serverURL, "/") + "/api/config/ca-root"
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return "", fmt.Errorf("invalid server URL: %w", err)
	}
	resp, err := bootstrapHTTPClient().Do(req)
	if err != nil {
		return "", fmt.Errorf("cannot fetch deployment CA from %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("deployment CA fetch returned HTTP %d from %s", resp.StatusCode, url)
	}
	pem, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", fmt.Errorf("read deployment CA response: %w", err)
	}
	if !bytes.Contains(pem, []byte("BEGIN CERTIFICATE")) {
		return "", fmt.Errorf("response from %s is not a PEM certificate", url)
	}
	caPath := filepath.Join(destDir, "deployment-ca.pem")
	if err := os.WriteFile(caPath, pem, 0o644); err != nil {
		return "", fmt.Errorf("write deployment CA to %s: %w", caPath, err)
	}
	return caPath, nil
}
