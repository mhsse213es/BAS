// agent/bootstrap.go
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"audspect/agent/protocol"
)

// ensureCertificate guarantees the agent holds a valid, unexpired mTLS
// client certificate before connectWS is called. If one already exists and
// isn't expiring soon, this is a fast no-op (Review Focus: an
// already-enrolled agent restarting must never re-bootstrap — that would
// also just get rejected by the orchestrator's reuse-limit check, Task 5).
// Otherwise it performs the CSR bootstrap flow against the enrollment
// listener (:9444 in production, derived from a.cfg.ServerURL below).
func (a *Agent) ensureCertificate(ctx context.Context) error {
	existing, loadErr := loadAgentCertificate()
	hasValidCert := loadErr == nil && !certExpiringSoon(existing)
	if hasValidCert {
		return nil
	}

	key, err := loadOrGenerateAgentKey()
	if err != nil {
		return fmt.Errorf("load/generate agent key: %w", err)
	}
	csrPEM, err := generateCSR(key, a.id.AgentID)
	if err != nil {
		return fmt.Errorf("generate CSR: %w", err)
	}

	renewing := loadErr == nil // a cert exists (just expiring soon) — renew via mTLS, don't re-bootstrap
	var client *http.Client
	var targetURL string
	if renewing {
		// Renewal goes over the normal mTLS listener (9443), authenticated
		// by the agent's own still-valid current certificate — never the
		// bootstrap secret, per spec Section 2. mtlsTLSConfig reads the
		// CURRENT on-disk cert/key, which is still valid at this point
		// (only "expiring soon," not yet expired).
		tlsCfg, err := mtlsTLSConfig(a.cfg)
		if err != nil || tlsCfg == nil {
			return fmt.Errorf("build mTLS config for renewal: %w", err)
		}
		client = &http.Client{
			Timeout:   30 * time.Second,
			Transport: &http.Transport{DialContext: proxyAwareNetDialContext(a.cfg), TLSClientConfig: tlsCfg},
		}
		targetURL = a.cfg.ServerURL // 9443, the normal operational endpoint
	} else {
		client, err = bootstrapHTTPClient(a.cfg)
		if err != nil {
			return fmt.Errorf("build bootstrap HTTP client: %w", err)
		}
		targetURL, err = enrollmentURL(a.cfg.ServerURL) // 9444
		if err != nil {
			return fmt.Errorf("derive enrollment URL: %w", err)
		}
	}

	// The bootstrap secret is only meaningful on the initial-bootstrap
	// path; a renewing agent authenticates via its presented mTLS client
	// certificate instead, so the secret is withheld entirely rather than
	// sent alongside it — the orchestrator's Task 5 EnrollCSR handler
	// rejects a bootstrap-secret re-submission for an already-certified
	// identity, so renewal MUST go through mTLS-only auth or be rejected.
	bootstrapSecret := a.cfg.AgentSecret
	if renewing {
		bootstrapSecret = ""
	}

	resp, err := protocol.SubmitCSR(ctx, client, targetURL, bootstrapSecret, protocol.CSRRequest{
		AgentID: a.id.AgentID,
		CSRPEM:  string(csrPEM),
	})
	if err != nil {
		return fmt.Errorf("submit CSR (renewing=%v): %w", renewing, err)
	}
	if err := saveAgentCertificate([]byte(resp.CertPEM)); err != nil {
		return fmt.Errorf("save issued certificate: %w", err)
	}
	log.Printf("[*] certificate %s (expires %s)", map[bool]string{true: "renewed", false: "issued"}[renewing], resp.ExpiresAt)
	return nil
}

// enrollmentURL rewrites serverURL's port to the enrollment listener's port
// (9444 by default — matches config.EnrollHTTPPort's orchestrator-side
// default from Task 1). BAS_ENROLL_PORT overrides for non-default
// deployments, mirroring how BAS_SERVER_URL itself is already overridable.
func enrollmentURL(serverURL string) (string, error) {
	port := os.Getenv("BAS_ENROLL_PORT")
	if port == "" {
		port = "9444"
	}
	// serverURL is like "https://host:9443" (or "http://host:9000" for a
	// still-legacy-configured agent) — swap only the port.
	idx := strings.LastIndex(serverURL, ":")
	if idx <= strings.Index(serverURL, "//")+2 { // no explicit port present
		return serverURL + ":" + port, nil
	}
	return serverURL[:idx] + ":" + port, nil
}

// bootstrapHTTPClient builds an *http.Client that trusts the deployment CA
// root (bundled by the installer alongside the bootstrap secret — see the
// spec's installer artifacts list) for verifying the orchestrator's TLS
// server certificate during bootstrap, before this agent has any client
// certificate of its own to present.
//
// It deliberately does NOT perform hostname/SAN verification: the
// orchestrator's server TLS identity is the deployment CA's own
// certificate (no SAN entries — this is a single-appliance, air-gapped
// deployment where the CA root distributed via the installer IS the trust
// anchor, not a DNS name that may not even be stable across an install).
// InsecureSkipVerify disables Go's built-in verification (which would
// otherwise fail on the missing SAN); verifyServerCertChain below replaces
// it with real chain-to-trusted-CA verification, just without the
// hostname check. This is NOT "skip verification" — it is "verify the
// chain, skip the hostname," which is the correct trust model here.
func bootstrapHTTPClient(cfg Config) (*http.Client, error) {
	_, caPath, _, _ := certPaths()
	caPEM, err := os.ReadFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("read deployment CA root %s (expected to be placed by the installer): %w", caPath, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("parse deployment CA root %s: not a valid PEM certificate", caPath)
	}
	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			DialContext: proxyAwareNetDialContext(cfg),
			TLSClientConfig: &tls.Config{
				RootCAs:               pool,
				InsecureSkipVerify:    true, // see verifyServerCertChain: hostname check is meaningless here, chain check is NOT skipped
				VerifyPeerCertificate: verifyServerCertChain(pool),
			},
		},
	}, nil
}

// verifyServerCertChain returns a VerifyPeerCertificate callback that
// checks the presented certificate chain against pool, with NO hostname
// verification (see bootstrapHTTPClient's doc comment for why that's
// correct here). Shared with Task 11's mtlsTLSConfig, which needs the
// exact same trust model for the agent's ongoing mTLS connection to the
// orchestrator.
func verifyServerCertChain(pool *x509.CertPool) func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return fmt.Errorf("no certificate presented by server")
		}
		certs := make([]*x509.Certificate, len(rawCerts))
		for i, raw := range rawCerts {
			cert, err := x509.ParseCertificate(raw)
			if err != nil {
				return fmt.Errorf("parse server certificate: %w", err)
			}
			certs[i] = cert
		}
		opts := x509.VerifyOptions{Roots: pool}
		if len(certs) > 1 {
			intermediates := x509.NewCertPool()
			for _, c := range certs[1:] {
				intermediates.AddCert(c)
			}
			opts.Intermediates = intermediates
		}
		_, err := certs[0].Verify(opts)
		if err != nil {
			return fmt.Errorf("server certificate does not chain to trusted deployment CA: %w", err)
		}
		return nil
	}
}
