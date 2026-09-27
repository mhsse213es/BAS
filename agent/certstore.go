package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
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

// saveAgentCertificate persists a newly issued (or renewed) certificate.
func saveAgentCertificate(certPEM []byte) error {
	dir, _, certPath, _ := certPaths()
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create cert dir %s: %w", dir, err)
	}
	return os.WriteFile(certPath, certPEM, 0644)
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
