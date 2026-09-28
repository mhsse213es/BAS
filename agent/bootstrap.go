// agent/bootstrap.go
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
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

// errBlocked wraps an ensureCertificate error to signal "an already-enrolled
// identity's mTLS path is currently unusable." resolveOperationalConfig
// must never fall back to legacy transport for this -- only retry mTLS.
// Never returned for a never-enrolled identity (see isEnrolled()): legacy
// transport is a bootstrap compatibility mechanism, never a recovery path
// for an identity that has already proven itself over mTLS.
type errBlocked struct{ err error }

func (e *errBlocked) Error() string { return e.err.Error() }
func (e *errBlocked) Unwrap() error { return e.err }

// bootstrapOutcome tells agent/main.go how to proceed after
// resolveOperationalConfig, replacing the old binary
// success/fall-back-to-legacy contract now that legacy transport is never a
// recovery path for an already-enrolled identity. See each constant's own
// comment for the caller's required handling.
type bootstrapOutcome int

const (
	// outcomeMTLSReady: cfg.ServerURL/MTLS are the operational mTLS
	// endpoint, ready to use immediately.
	outcomeMTLSReady bootstrapOutcome = iota
	// outcomeLegacyPending: never-enrolled, initial bootstrap failed. The
	// caller starts the agent on legacy transport now (cfg unchanged) while
	// Agent.retryBootstrapUntilEnrolled retries bootstrap in the
	// background; on success it upgrades permanently via Agent.upgradeToMTLS.
	outcomeLegacyPending
	// outcomeBlocked: already enrolled, but mTLS is not currently usable --
	// either a transient local problem (e.g. the CA root file is
	// temporarily unreadable) or the certificate has expired outright with
	// no successful renewal along the way. The caller must block, retrying
	// with backoff, and must NEVER start the agent on cfg as returned:
	// there is no legacy operation for this outcome at all.
	outcomeBlocked
)

// resolveOperationalConfig runs certificate bootstrap/renewal BEFORE any
// long-lived client is built (agent/main.go calls it ahead of newAgent),
// and reports which of bootstrapOutcome's three states the caller is now
// in. The core invariant across all three: legacy transport is a bootstrap
// compatibility mechanism, never a recovery path for an identity that has
// already proven itself over mTLS.
//
// Nothing is written back to the service configuration: the mTLS URL is a
// pure function of the configured URL plus the on-disk certificate, so it
// is re-derived identically on every call.
func resolveOperationalConfig(ctx context.Context, cfg Config, agentID string) (Config, bootstrapOutcome) {
	opURL, err := ensureCertificate(ctx, cfg, agentID)
	if err == nil {
		if opURL != cfg.ServerURL {
			log.Printf("[*] operational endpoint: %s (configured: %s)", opURL, cfg.ServerURL)
		}
		cfg.ServerURL = opURL
		cfg.MTLS = true
		return cfg, outcomeMTLSReady
	}
	var blocked *errBlocked
	if errors.As(err, &blocked) {
		log.Printf("[!] mTLS unusable for this already-enrolled agent identity -- refusing legacy fallback, will retry mTLS only: %v", blocked)
		return cfg, outcomeBlocked
	}
	log.Printf("[!] certificate bootstrap failed, operating on legacy transport temporarily while retrying: %v", err)
	return cfg, outcomeLegacyPending
}

// ensureCertificate guarantees the agent holds a valid, unexpired mTLS
// client certificate bound to its own key, and returns the operational mTLS
// URL (operationalURL of the configured ServerURL) that all traffic must
// use from then on. Gated first by the persisted enrollment marker
// (isEnrolled — never by the certificate file's mere existence), then:
//
//   - enrolled, and the certificate is gone/unreadable or has actually
//     EXPIRED with no successful renewal along the way: an expired
//     certificate cannot authenticate an mTLS handshake, and there is no
//     automatic recovery path once that's happened -- returns errBlocked
//     rather than falling back to the now-forbidden bootstrap secret.
//   - enrolled, valid, and not yet at the renewal threshold: no network I/O
//     (Review Focus: an already-enrolled agent restarting must never
//     re-bootstrap). If the local mTLS setup is otherwise unusable (e.g.
//     the CA root file is transiently unreadable), returns errBlocked --
//     never a silent downgrade to legacy for an identity that has already
//     proven itself.
//   - enrolled, valid, but past the renewal threshold (certExpiringSoon):
//     renew over the mTLS listener authenticated by the current
//     certificate, never the bootstrap secret (spec Section 2). A failed
//     renewal is logged and is NOT an error: the current certificate is
//     still valid, so the agent keeps operating over mTLS and retries
//     renewal on its next attempt.
//   - never enrolled: the only state that may use the bootstrap secret,
//     against the enrollment listener. Any stray/partial certificate file
//     on disk is deliberately ignored -- only the persisted marker decides
//     this branch. On success, markEnrolled persists the ENROLLED state;
//     from that moment on this identity can never use the secret again.
func ensureCertificate(ctx context.Context, cfg Config, agentID string) (string, error) {
	opURL, err := operationalURL(cfg.ServerURL)
	if err != nil {
		return "", fmt.Errorf("derive operational mTLS URL: %w", err)
	}

	enrolled := isEnrolled()
	existing, loadErr := loadAgentCertificate()
	expired := loadErr == nil && !time.Now().Before(existing.NotAfter)

	if enrolled && (loadErr != nil || expired) {
		reason := "no usable certificate on disk for an enrolled identity"
		if loadErr == nil && expired {
			reason = "certificate has expired with no successful renewal"
		}
		return "", &errBlocked{errors.New(reason)}
	}

	if enrolled && !certExpiringSoon(existing) {
		if err := checkMTLSUsable(cfg); err != nil {
			return "", &errBlocked{err}
		}
		return opURL, nil
	}

	// Two cases reach here: (a) enrolled, valid, but past the renewal
	// threshold -- renew over mTLS; (b) never enrolled -- initial bootstrap
	// over the enrollment listener with the shared secret.
	renewing := enrolled

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
			return "", &errBlocked{fmt.Errorf("build mTLS config for renewal: %w", err)}
		}
		if tlsCfg == nil {
			return "", &errBlocked{errors.New("build mTLS config for renewal: deployment CA root not installed")}
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
	if resp.CommandSigningTrust.CertPEM != "" {
		if err := saveCommandSigningCert([]byte(resp.CommandSigningTrust.CertPEM)); err != nil {
			// Non-fatal: the agent still has a valid mTLS certificate and
			// can operate; it will simply reject every execution-triggering
			// command until this is resolved (see agent/commandsig.go),
			// which is the correct fail-closed behavior for a missing
			// trust anchor, not a reason to fail bootstrap/renewal itself.
			log.Printf("[!] could not persist command-signing trust: %v", err)
		}
	}
	if !renewing {
		// First-ever successful bootstrap: persist the ENROLLED marker.
		// From this moment on, this identity can never use the bootstrap
		// secret again -- see the invariant in resolveOperationalConfig.
		if err := markEnrolled(); err != nil {
			return "", fmt.Errorf("certificate issued but could not persist enrollment state: %w", err)
		}
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
