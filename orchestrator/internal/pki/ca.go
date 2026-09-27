// Package pki implements the deployment certificate authority used to issue
// per-agent mTLS client certificates (B1/B3). See
// docs/superpowers/specs/2026-09-27-agent-trust-model-b1-b3-b4-design.md.
//
// This is a separate trust domain from the command-signing keypair (B4,
// implemented in a later plan) -- the two are never chained together, so
// compromise of one does not automatically compromise the other.
package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

// caValidity is the deployment CA root's lifetime. Long-lived by design --
// air-gapped operators don't want frequent root rotation -- with overlapping
// trust support (documented in the spec) available whenever rotation does
// happen. CA compromise is substantially more consequential than a single
// client-cert compromise (full fleet impersonation vs. one agent), which is
// why the CA private key file is written 0600 and must never leave this host.
const caValidity = 10 * 365 * 24 * time.Hour

// CA holds the deployment certificate authority's keypair and root
// certificate. The private key never leaves the orchestrator host.
type CA struct {
	cert    *x509.Certificate
	certDER []byte
	key     *ecdsa.PrivateKey
}

// LoadOrGenerateCA loads an existing CA keypair from dir, or generates a new
// one if dir contains no ca-key.pem. dir is created if it does not exist.
// A CA that exists but fails to parse (corrupt/truncated file) is a hard
// error -- silently regenerating would invalidate every already-issued
// agent certificate without warning.
func LoadOrGenerateCA(dir string) (*CA, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("create PKI dir %s: %w", dir, err)
	}
	keyPath := filepath.Join(dir, "ca-key.pem")
	certPath := filepath.Join(dir, "ca-cert.pem")

	if _, err := os.Stat(keyPath); err == nil {
		return loadCA(keyPath, certPath)
	}
	return generateCA(keyPath, certPath)
}

func generateCA(keyPath, certPath string) (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate CA key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generate CA serial: %w", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "Audspect Deployment CA", Organization: []string{"Audspect"}},
		NotBefore:             time.Now().Add(-5 * time.Minute),
		NotAfter:              time.Now().Add(caValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("create CA certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("parse generated CA certificate: %w", err)
	}
	if err := writeECKeyPEM(keyPath, key); err != nil {
		return nil, err
	}
	if err := writeCertPEM(certPath, certDER); err != nil {
		return nil, err
	}
	return &CA{cert: cert, certDER: certDER, key: key}, nil
}

func loadCA(keyPath, certPath string) (*CA, error) {
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("read CA key: %w", err)
	}
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("read CA cert: %w", err)
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, fmt.Errorf("decode CA key PEM %s: no PEM block found (corrupt or truncated file)", keyPath)
	}
	key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CA private key: %w", err)
	}
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, fmt.Errorf("decode CA cert PEM %s: no PEM block found (corrupt or truncated file)", certPath)
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CA certificate: %w", err)
	}
	return &CA{cert: cert, certDER: certBlock.Bytes, key: key}, nil
}

func writeECKeyPEM(path string, key *ecdsa.PrivateKey) error {
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return fmt.Errorf("marshal EC private key: %w", err)
	}
	block := &pem.Block{Type: "EC PRIVATE KEY", Bytes: der}
	// 0600: readable only by the orchestrator process owner. The
	// orchestrator ships as a Linux container (packaging/compose/), so this
	// is a real, enforced restriction, not a Windows no-op.
	return os.WriteFile(path, pem.EncodeToMemory(block), 0600)
}

func writeCertPEM(path string, der []byte) error {
	block := &pem.Block{Type: "CERTIFICATE", Bytes: der}
	return os.WriteFile(path, pem.EncodeToMemory(block), 0644)
}

// RootCertPEM returns the CA's root certificate in PEM form, for
// distribution to admins (to bundle into agent installers, Task 6's
// GET /api/config/connection extension) and for the mTLS listeners' own
// ClientCAs pool (Task 7).
func (c *CA) RootCertPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.certDER})
}

// Certificate returns the parsed CA certificate.
func (c *CA) Certificate() *x509.Certificate { return c.cert }

// TLSCertificate returns the CA's own certificate+key as a tls.Certificate,
// used as the orchestrator's server identity on the 9443 and 9444 listeners
// (the CA signs its own server-identity leaf implicitly by presenting itself
// directly -- see Task 7 for why this is sufficient for a single-orchestrator
// on-prem deployment rather than issuing a separate server leaf cert).
func (c *CA) TLSCertificate() (tls.Certificate, error) {
	keyDER, err := x509.MarshalECPrivateKey(c.key)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("marshal CA key for TLS: %w", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return tls.X509KeyPair(certPEM, keyPEM)
}
