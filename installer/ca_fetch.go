package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
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

// trustingHTTPClient returns an HTTP client that verifies the server's
// certificate chain against caPool -- the opposite of bootstrapHTTPClient
// above. Used once a trustworthy CA root is already in hand (the
// orchestrator's download handler embedded it in this binary at serve
// time, after verifying the base artifact against the signed manifest),
// so the pre-install probe below actually authenticates the endpoint
// instead of blindly trusting whatever serverURL happens to point at. A
// serverURL redirected to a server not signed by caPool -- the rogue-
// collector scenario a tampered or substituted config would produce --
// fails the TLS handshake here, before the agent secret is ever sent.
func trustingHTTPClient(caPool *x509.CertPool) *http.Client {
	return &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: caPool}},
	}
}

// writeEmbeddedCA writes an already-trusted CA root (extracted from this
// binary's own embedded config, see embedconfig.go) to disk, in the same
// place and format fetchDeploymentCA would have produced it -- but
// without a network fetch, since the bytes are already in hand and
// already validated as a well-formed CA certificate.
func writeEmbeddedCA(pemBytes []byte, destDir string) (string, error) {
	caPath := filepath.Join(destDir, "deployment-ca.pem")
	if err := os.WriteFile(caPath, pemBytes, 0o644); err != nil {
		return "", fmt.Errorf("write embedded CA to %s: %w", caPath, err)
	}
	return caPath, nil
}

// validateEnrollment performs the pre-install connectivity check both the
// Windows and macOS installers run before touching disk: a plain health
// check (confirms the server is reachable at all) and an authenticated
// WebSocket-upgrade endpoint probe with the agent secret (confirms the
// secret is accepted before a service gets installed with a wrong one).
//
// caPool, when non-nil, is used to actually verify the server's
// certificate chain (trustingHTTPClient) instead of skipping verification
// (bootstrapHTTPClient) -- pass it whenever an embedded CA root is
// available. nil preserves the original pre-trust-bootstrap behavior for
// a deployment with no embedded CA (PKI not configured server-side, or an
// older binary): the same residual TOFU exposure that existed before this
// mechanism, never worse, and honestly still present in that fallback.
func validateEnrollment(serverURL, secret string, caPool *x509.CertPool) error {
	client := bootstrapHTTPClient()
	if caPool != nil {
		client = trustingHTTPClient(caPool)
	}
	req, err := http.NewRequest(http.MethodGet, serverURL+"/health", nil)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("cannot reach server at %s — check URL and firewall", serverURL)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("server health check returned HTTP %d", resp.StatusCode)
	}
	req2, err := http.NewRequest(http.MethodGet, serverURL+"/ws/agent", nil)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}
	req2.Header.Set("X-Agent-Token", secret)
	resp2, err := client.Do(req2)
	if err != nil {
		return fmt.Errorf("token check failed — cannot reach %s/ws/agent", serverURL)
	}
	resp2.Body.Close()
	if resp2.StatusCode == http.StatusUnauthorized {
		return fmt.Errorf("agent secret rejected (HTTP 401) — check AGENT_SECRET on the server")
	}
	return nil
}
