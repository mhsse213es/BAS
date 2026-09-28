package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"
)

// certExpiringSoonThreshold: renew at 75% of the certificate's lifetime
// elapsed (spec Section 2 default), independent of the re-enroll-on-upgrade
// trigger Task 12 also wires in.
const certExpiringSoonThreshold = 0.75

// certPaths returns the directory holding the agent's cert/key material and
// the individual file paths within it. BAS_CERT_DIR overrides the
// platform default for tests; production installs never set it and get
// certDirPlatform()'s real per-OS path (agent/certstore_windows.go /
// agent/certstore_posix.go).
func certPaths() (dir, caPath, certPath, keyPath string) {
	dir = os.Getenv("BAS_CERT_DIR")
	if dir == "" {
		dir = certDirPlatform()
	}
	return dir, filepath.Join(dir, "deployment-ca.pem"), filepath.Join(dir, "agent-cert.pem"), filepath.Join(dir, "agent-key.pem")
}

// loadOrGenerateAgentKey loads the agent's persisted ECDSA P-256 private
// key, generating and saving a new one on first run. The private key never
// leaves this function's callers' process — it is never transmitted over
// the network (only its public half, embedded in a CSR, is — see
// generateCSR).
func loadOrGenerateAgentKey() (*ecdsa.PrivateKey, error) {
	dir, _, _, keyPath := certPaths()
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("create cert dir %s: %w", dir, err)
	}
	if data, err := os.ReadFile(keyPath); err == nil {
		block, _ := pem.Decode(data)
		if block == nil {
			return nil, fmt.Errorf("decode agent key PEM %s: no PEM block found", keyPath)
		}
		return x509.ParseECPrivateKey(block.Bytes)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate agent key: %w", err)
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal agent key: %w", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	if err := os.WriteFile(keyPath, pemBytes, 0600); err != nil {
		return nil, fmt.Errorf("write agent key: %w", err)
	}
	if err := hardenCertDirPlatform(dir); err != nil {
		// Non-fatal: log-worthy but the key was still written. Callers in
		// Task 10/11 log this; certstore itself stays a pure storage layer.
		return key, fmt.Errorf("key saved, but directory hardening failed: %w", err)
	}
	return key, nil
}

// generateCSR builds a PEM-encoded PKCS#10 CSR for key, requesting agentID
// as its CommonName. The orchestrator (Task 5's EnrollCSR handler) treats
// this as a REQUEST only — it is the server, not this CSR, that is
// authoritative for what identity ends up in the signed certificate.
func generateCSR(key *ecdsa.PrivateKey, agentID string) ([]byte, error) {
	tmpl := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: agentID},
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		return nil, fmt.Errorf("create CSR: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), nil
}

// saveAgentCertificate persists a newly issued (or renewed) certificate,
// after confirming it is a parseable certificate bound to this agent's own
// persisted private key. A certificate for any other key would be unusable
// (tls.LoadX509KeyPair rejects the pair on the next handshake, far from the
// cause) and would overwrite the still-good certificate on disk, so it is
// rejected here instead, before anything is written.
func saveAgentCertificate(certPEM []byte) error {
	dir, _, certPath, keyPath := certPaths()
	cert, err := parseCertificatePEM(certPEM)
	if err != nil {
		return fmt.Errorf("issued certificate: %w", err)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return fmt.Errorf("read agent key %s to match against issued certificate: %w", keyPath, err)
	}
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return fmt.Errorf("decode agent key PEM %s: no PEM block found", keyPath)
	}
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("parse agent key %s: %w", keyPath, err)
	}
	certPub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || !certPub.Equal(&key.PublicKey) {
		return fmt.Errorf("issued certificate's public key does not match this agent's private key — refusing to persist it")
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create cert dir %s: %w", dir, err)
	}
	return os.WriteFile(certPath, certPEM, 0644)
}

// parseCertificatePEM decodes the first PEM block in data, requires it to
// be a CERTIFICATE, and parses it.
func parseCertificatePEM(data []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("PEM block is %q, want CERTIFICATE", block.Type)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse certificate: %w", err)
	}
	return cert, nil
}

// saveDeploymentCARoot writes pemBytes to the canonical CA-root location
// (certPaths()'s caPath) — called during --install (agent/main.go) with a
// PEM an admin fetched from the orchestrator's GET /api/config/connection
// (Task 6) and handed to the installer. Not secret (a public certificate),
// so no permission-hardening beyond the directory's own 0700/icacls
// treatment (already applied by loadOrGenerateAgentKey's MkdirAll +
// hardenCertDirPlatform, called here too in case --install runs before any
// key operation has created the directory yet).
//
// pemBytes must parse as an X.509 certificate: a wrong file handed to
// --ca-root (a key, a CSR, an HTML error page saved from a browser) is
// rejected here at install time with a clear error, instead of surfacing
// later as an opaque bootstrap failure on the service's first start.
func saveDeploymentCARoot(pemBytes []byte) error {
	if _, err := parseCertificatePEM(pemBytes); err != nil {
		return fmt.Errorf("deployment CA root is not a valid PEM certificate: %w", err)
	}
	dir, caPath, _, _ := certPaths()
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create cert dir %s: %w", dir, err)
	}
	if err := hardenCertDirPlatform(dir); err != nil {
		return fmt.Errorf("harden cert dir: %w", err)
	}
	return os.WriteFile(caPath, pemBytes, 0644)
}

// loadAgentCertificate returns the currently persisted certificate, or an
// error wrapping os.ErrNotExist if none has been saved yet (the caller,
// Task 10's bootstrap orchestration, treats that as "run initial bootstrap").
func loadAgentCertificate() (*x509.Certificate, error) {
	_, _, certPath, _ := certPaths()
	data, err := os.ReadFile(certPath)
	if err != nil {
		return nil, err // os.ReadFile already wraps os.ErrNotExist correctly
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("decode agent cert PEM %s: no PEM block found", certPath)
	}
	return x509.ParseCertificate(block.Bytes)
}

// mtlsTLSConfig builds the *tls.Config the agent uses for its HTTP client,
// log shipper and WS dialer: the deployment CA root for verifying the
// orchestrator's server certificate, plus the agent's own client
// certificate supplied through GetClientCertificate.
//
// The client certificate is deliberately NOT loaded here. GetClientCertificate
// re-reads agent-cert.pem/agent-key.pem from disk on every handshake that
// asks for a client certificate, so one *tls.Config built at any point --
// including before the first bootstrap has produced a certificate at all --
// presents whatever certificate is on disk at handshake time: the first one
// right after bootstrap, and the new one right after a renewal, with no need
// to rebuild clients or restart the process. If no certificate exists yet
// at handshake time, that handshake fails with a descriptive error (there is
// nothing to authenticate with before bootstrap completes). The enrollment
// listener never requests a client certificate, so the callback is not
// invoked there.
//
// Returns (nil, nil) only when the deployment CA root file does not exist:
// without a trust anchor no chain-verified TLS connection to the
// orchestrator is possible, so callers keep their default transport (the
// legacy plaintext path). A CA root file that exists but does not parse is
// an error.
//
// Verification deliberately mirrors agent/bootstrap.go's
// bootstrapHTTPClient / verifyServerCertChain: the orchestrator's server
// TLS identity is the deployment CA's own self-signed certificate reused
// directly (Task 7), which carries no SAN entries, so Go's default
// hostname verification would fail every real handshake.
// InsecureSkipVerify disables that default check; VerifyPeerCertificate
// replaces it with real chain-to-trusted-CA verification (no hostname
// check) via verifyServerCertChain -- this is "verify the chain, skip the
// hostname," not "skip verification," and is the correct trust model for
// this single-appliance deployment where the installer-distributed CA
// root IS the trust anchor.
func mtlsTLSConfig(cfg Config) (*tls.Config, error) {
	_, caPath, certPath, keyPath := certPaths()
	caPEM, err := os.ReadFile(caPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil // no trust anchor installed -- legacy fallback, not an error
	}
	if err != nil {
		return nil, fmt.Errorf("read deployment CA root: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("parse deployment CA root: not valid PEM")
	}
	return &tls.Config{
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			clientCert, err := tls.LoadX509KeyPair(certPath, keyPath)
			if err != nil {
				return nil, fmt.Errorf("load agent client certificate (bootstrap not yet completed?): %w", err)
			}
			return &clientCert, nil
		},
		RootCAs:               pool,
		InsecureSkipVerify:    true, // see agent/bootstrap.go's verifyServerCertChain doc comment: chain-only verification, hostname check is meaningless for this single-appliance deployment model
		VerifyPeerCertificate: verifyServerCertChain(pool),
	}, nil
}

// agentTLSConfig is what every long-lived client (newAgent's HTTP client,
// the log shipper, the WS dialer) attaches: mtlsTLSConfig when cfg.MTLS
// says ServerURL is the mTLS listener, otherwise nil (Go's default TLS
// config -- the legacy path, unchanged). Because mtlsTLSConfig supplies the
// client certificate through GetClientCertificate, the returned config
// never goes stale: a renewed certificate is presented on the next
// handshake without rebuilding any client.
func agentTLSConfig(cfg Config) *tls.Config {
	if !cfg.MTLS {
		return nil
	}
	tlsCfg, err := mtlsTLSConfig(cfg)
	if err != nil {
		log.Printf("[!] mTLS config unavailable: %v", err)
		return nil
	}
	return tlsCfg
}

// enrollmentStatePath is the persisted marker distinguishing NeverEnrolled
// from Enrolled -- deliberately a file separate from agent-cert.pem, not
// inferred from that file's mere existence (see isEnrolled).
func enrollmentStatePath() string {
	dir, _, _, _ := certPaths()
	return filepath.Join(dir, "enrollment-state")
}

// isEnrolled reports whether this agent identity has EVER successfully
// completed enrollment, per the marker markEnrolled writes -- NOT inferred
// from "a certificate file exists" alone. A corrupted or partially-written
// certificate file (a truncated write, a bad upgrade, disk corruption) must
// never be mistaken for a successfully-enrolled identity: doing so could
// flip an untrusted/never-enrolled agent into the ENROLLED state's stricter
// fail-closed behavior for the wrong reason, or worse, let a real ENROLLED
// identity's state get silently lost and fall back to bootstrap. This is
// the persisted half of the invariant resolveOperationalConfig enforces:
// legacy transport is a bootstrap compatibility mechanism, never a
// recovery path for an already-enrolled identity.
func isEnrolled() bool {
	data, err := os.ReadFile(enrollmentStatePath())
	return err == nil && bytes.Equal(bytes.TrimSpace(data), []byte("enrolled"))
}

// markEnrolled persists the ENROLLED state atomically: write to a temp file
// in the same directory, then rename. Rename is atomic on both POSIX and
// Windows (NTFS) for a same-volume move, so a crash or power loss
// mid-write can never leave a half-written marker for isEnrolled to
// misread as either state. Callers (agent/bootstrap.go's ensureCertificate)
// call this only after saveAgentCertificate has confirmed a real,
// key-matched certificate was persisted -- never before.
func markEnrolled() error {
	dir, _, _, _ := certPaths()
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create cert dir %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, "enrollment-state-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp enrollment-state file: %w", err)
	}
	tmpName := tmp.Name()
	if _, err := tmp.WriteString("enrolled"); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return fmt.Errorf("write enrollment-state: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("close temp enrollment-state file: %w", err)
	}
	if err := os.Rename(tmpName, enrollmentStatePath()); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("rename enrollment-state into place: %w", err)
	}
	return nil
}

// certExpiringSoon reports whether cert has crossed 75% of its total
// lifetime — the renewal trigger threshold (spec Section 2 default).
func certExpiringSoon(cert *x509.Certificate) bool {
	total := cert.NotAfter.Sub(cert.NotBefore)
	elapsed := time.Since(cert.NotBefore)
	if total <= 0 {
		return true // malformed lifetime — treat as needing renewal rather than trusting it
	}
	return float64(elapsed)/float64(total) >= certExpiringSoonThreshold
}
