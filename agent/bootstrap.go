// agent/bootstrap.go
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"audspect/agent/protocol"
)

// Default orchestrator listener ports (config.HTTPPort / config.EnrollHTTPPort
// on the orchestrator side, Task 1/7). BAS_MTLS_PORT / BAS_ENROLL_PORT
// override them for non-default deployments, mirroring how BAS_SERVER_URL
// itself is already overridable.
const (
	defaultMTLSPort   = "9443"
	defaultEnrollPort = "9444"
)

// resolveOperationalConfig runs certificate bootstrap/renewal BEFORE any
// long-lived client is built (agent/main.go calls it ahead of newAgent) and
// returns the Config every later client must be built from:
//
//   - success: ServerURL is rewritten to the mTLS listener
//     (https://<host>:<mTLS port>) and MTLS is set, so newAgent's HTTP
//     client, the log shipper and the WS dialer all target the mTLS
//     endpoint with the agent's client certificate attached.
//   - failure: cfg is returned unchanged (the originally configured URL,
//     legacy shared-secret path), matching the pre-existing fallback.
//
// Nothing is written back to the service configuration: the mTLS URL is a
// pure function of the configured URL plus the on-disk certificate, so it
// is re-derived identically on every start, and an agent whose certificate
// store is wiped falls back to the configured URL and re-bootstraps.
func resolveOperationalConfig(ctx context.Context, cfg Config, agentID string) Config {
	opURL, err := ensureCertificate(ctx, cfg, agentID)
	if err != nil {
		log.Printf("[!] certificate bootstrap failed, falling back to legacy auth on %s: %v", cfg.ServerURL, err)
		return cfg
	}
	if opURL != cfg.ServerURL {
		log.Printf("[*] operational endpoint: %s (configured: %s)", opURL, cfg.ServerURL)
	}
	cfg.ServerURL = opURL
	cfg.MTLS = true
	return cfg
}

// ensureCertificate guarantees the agent holds a valid, unexpired mTLS
// client certificate bound to its own key, and returns the operational mTLS
// URL (operationalURL of the configured ServerURL) that all traffic must
// use from then on. Three states:
//
//   - no certificate on disk, or one that has actually EXPIRED: initial
//     bootstrap against the enrollment listener with the bootstrap secret.
//     An expired certificate cannot authenticate an mTLS handshake (the
//     orchestrator's RequireAndVerifyClientCert listener rejects it before
//     HTTP), and the orchestrator's reuse check no longer matches it
//     (expires_at > NOW()), so bootstrap is both the only possible and the
//     permitted path.
//   - valid and not yet at the renewal threshold: no network I/O (Review
//     Focus: an already-enrolled agent restarting must never re-bootstrap).
//   - valid but past the renewal threshold (certExpiringSoon): renew over
//     the mTLS listener authenticated by the current certificate, never the
//     bootstrap secret (spec Section 2). A failed renewal is logged and is
//     NOT an error: the current certificate is still valid, so the agent
//     keeps operating over mTLS and retries renewal on its next start.
func ensureCertificate(ctx context.Context, cfg Config, agentID string) (string, error) {
	opURL, err := operationalURL(cfg.ServerURL)
	if err != nil {
		return "", fmt.Errorf("derive operational mTLS URL: %w", err)
	}

	existing, loadErr := loadAgentCertificate()
	expired := loadErr == nil && !time.Now().Before(existing.NotAfter)
	if loadErr == nil && !expired && !certExpiringSoon(existing) {
		if err := checkMTLSUsable(cfg); err != nil {
			return "", err
		}
		return opURL, nil
	}
	renewing := loadErr == nil && !expired

	key, err := loadOrGenerateAgentKey()
	if err != nil {
		return "", fmt.Errorf("load/generate agent key: %w", err)
	}
	csrPEM, err := generateCSR(key, agentID)
	if err != nil {
		return "", fmt.Errorf("generate CSR: %w", err)
	}

	var client *http.Client
	var targetURL, bootstrapSecret string
	if renewing {
		// Renewal goes to the mTLS listener, authenticated by the agent's
		// own still-valid current certificate (read from disk by
		// mtlsTLSConfig's GetClientCertificate at handshake time). The
		// bootstrap secret is withheld entirely: the orchestrator's
		// EnrollCSR authenticates renewal by the verified certificate alone.
		targetURL = opURL
		tlsCfg, err := mtlsTLSConfig(cfg)
		if err != nil {
			return "", fmt.Errorf("build mTLS config for renewal: %w", err)
		}
		if tlsCfg == nil {
			return "", fmt.Errorf("build mTLS config for renewal: deployment CA root not installed")
		}
		client = &http.Client{
			Timeout:   30 * time.Second,
			Transport: &http.Transport{DialContext: proxyAwareNetDialContext(withServerURL(cfg, targetURL)), TLSClientConfig: tlsCfg},
		}
	} else {
		targetURL, err = enrollmentURL(cfg.ServerURL)
		if err != nil {
			return "", fmt.Errorf("derive enrollment URL: %w", err)
		}
		client, err = bootstrapHTTPClient(withServerURL(cfg, targetURL))
		if err != nil {
			return "", fmt.Errorf("build bootstrap HTTP client: %w", err)
		}
		bootstrapSecret = cfg.AgentSecret
	}

	resp, err := protocol.SubmitCSR(ctx, client, targetURL, bootstrapSecret, protocol.CSRRequest{
		AgentID: agentID,
		CSRPEM:  string(csrPEM),
	})
	if err != nil {
		err = fmt.Errorf("submit CSR (renewing=%v): %w", renewing, err)
	} else if saveErr := saveAgentCertificate([]byte(resp.CertPEM)); saveErr != nil {
		err = fmt.Errorf("save issued certificate: %w", saveErr)
	}
	if err != nil {
		if renewing {
			log.Printf("[!] certificate renewal failed, continuing with the current certificate (expires %s): %v",
				existing.NotAfter.Format(time.RFC3339), err)
			return opURL, nil
		}
		return "", err
	}
	log.Printf("[*] certificate %s (expires %s)", map[bool]string{true: "renewed", false: "issued"}[renewing], resp.ExpiresAt)
	return opURL, nil
}

// checkMTLSUsable confirms the on-disk certificate/key pair loads and the
// deployment CA root is installed -- the fast path's guard that switching
// to the mTLS URL will actually work, since that path makes no request.
func checkMTLSUsable(cfg Config) error {
	_, _, certPath, keyPath := certPaths()
	if _, err := tls.LoadX509KeyPair(certPath, keyPath); err != nil {
		return fmt.Errorf("load agent client keypair: %w", err)
	}
	tlsCfg, err := mtlsTLSConfig(cfg)
	if err != nil {
		return err
	}
	if tlsCfg == nil {
		return fmt.Errorf("deployment CA root not installed")
	}
	return nil
}

// withServerURL returns cfg with ServerURL replaced, so a client built for
// a specific target resolves its proxy for that target
// (proxyAwareNetDialContext reads cfg.ServerURL's scheme to choose
// HTTPS_PROXY vs HTTP_PROXY).
func withServerURL(cfg Config, serverURL string) Config {
	cfg.ServerURL = serverURL
	return cfg
}

// enrollmentURL returns the initial-bootstrap endpoint for serverURL's host:
// always https:// (the enrollment listener is TLS server-authenticated,
// Task 7) on BAS_ENROLL_PORT or 9444, whatever scheme and port serverURL
// itself carries -- a legacy http://host:9000 configuration included.
func enrollmentURL(serverURL string) (string, error) {
	host, _, _, err := splitServerURL(serverURL)
	if err != nil {
		return "", err
	}
	return "https://" + net.JoinHostPort(host, enrollPort()), nil
}

// operationalURL returns the mTLS listener URL for serverURL's host, always
// https://. The port is BAS_MTLS_PORT if set; otherwise serverURL's own
// port when serverURL is already https:// on a port other than the
// enrollment port (an https URL already names the orchestrator's HTTP_PORT,
// i.e. the mTLS listener, possibly non-default); otherwise 9443 -- which
// covers a legacy http:// URL (the plaintext :9000 listener, or a pre-TLS
// http://host:9443 setting) and a URL pointing at the enrollment port.
func operationalURL(serverURL string) (string, error) {
	host, scheme, port, err := splitServerURL(serverURL)
	if err != nil {
		return "", err
	}
	switch p := os.Getenv("BAS_MTLS_PORT"); {
	case p != "":
		port = p
	case scheme == "https" && port != "" && port != enrollPort():
		// already the mTLS listener -- keep its port
	default:
		port = defaultMTLSPort
	}
	return "https://" + net.JoinHostPort(host, port), nil
}

func enrollPort() string {
	if p := os.Getenv("BAS_ENROLL_PORT"); p != "" {
		return p
	}
	return defaultEnrollPort
}

// splitServerURL parses serverURL with net/url (so IPv6 literals such as
// https://[::1]:9443 are handled correctly) and returns its bare host (no
// brackets), lower-cased scheme and port ("" if none).
func splitServerURL(serverURL string) (host, scheme, port string, err error) {
	u, err := url.Parse(serverURL)
	if err != nil {
		return "", "", "", fmt.Errorf("parse server URL %q: %w", serverURL, err)
	}
	host = u.Hostname()
	if host == "" {
		return "", "", "", fmt.Errorf("server URL %q has no host", serverURL)
	}
	return host, strings.ToLower(u.Scheme), u.Port(), nil
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
