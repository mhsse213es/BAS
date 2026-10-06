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
	"net"
	"os"
	"path/filepath"
	"strings"
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
// one (with no Subject Alternative Names beyond its own identity) if dir
// contains no ca-key.pem. Prefer LoadOrGenerateCAWithSANs for any deployment
// whose agents will dial the orchestrator by IP address -- see that
// function's doc comment for why a bare LoadOrGenerateCA is not enough on
// its own.
func LoadOrGenerateCA(dir string) (*CA, error) {
	return LoadOrGenerateCAWithSANs(dir, nil)
}

// LoadOrGenerateCAWithSANs is LoadOrGenerateCA, plus sans: hostnames and/or
// IP addresses (mixed freely; each entry is parsed as an IP first, falling
// back to a DNS name) to embed as this cert's Subject Alternative Names.
//
// TLSCertificate presents this same CA certificate directly as the
// orchestrator's TLS server identity (see that method's doc comment). Since
// Go's x509 verification (crypto/x509, since Go 1.15) requires a SAN match
// for the exact address the client dialed and no longer falls back to
// Subject.CommonName, a CA generated via bare LoadOrGenerateCA carries no
// SAN at all -- so *every* Go TLS client (every agent; a browser merely
// warns and lets a human click through, which is why this was missed
// during interactive testing) fails to verify it against ANY address,
// producing exactly this error: "x509: cannot validate certificate for
// <ip>, because it doesn't contain any IP SANs". Confirmed live against a
// real deployment, 2026-09-30 -- see
// docs/superpowers/plans/2026-09-30-... incident notes. sans is only
// consulted the first time a CA is generated for dir; an existing CA is
// loaded as-is regardless of what's passed here (this function shares
// LoadOrGenerateCA's "never silently regenerate" guarantee).
func LoadOrGenerateCAWithSANs(dir string, sans []string) (*CA, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("create PKI dir %s: %w", dir, err)
	}
	keyPath := filepath.Join(dir, "ca-key.pem")
	certPath := filepath.Join(dir, "ca-cert.pem")

	if _, err := os.Stat(keyPath); err == nil {
		return loadCA(keyPath, certPath)
	}
	return generateCA(keyPath, certPath, sans)
}

func generateCA(keyPath, certPath string, sans []string) (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate CA key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generate CA serial: %w", err)
	}
	var ips []net.IP
	var dnsNames []string
	for _, san := range sans {
		san = strings.TrimSpace(san)
		if san == "" {
			continue
		}
		if ip := net.ParseIP(san); ip != nil {
			ips = append(ips, ip)
		} else {
			dnsNames = append(dnsNames, san)
		}
	}
	// A CA's EKUs constrain every cert chained beneath it, so ClientAuth must
	// be listed or the agent client certs it issues fail mTLS verification
	// ("incompatible key usage"). ServerAuth: this cert is also the
	// orchestrator's TLS server identity.
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "Audspect Deployment CA", Organization: []string{"Audspect"}},
		NotBefore:             time.Now().Add(-5 * time.Minute),
		NotAfter:              time.Now().Add(caValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		IPAddresses:           ips,
		DNSNames:              dnsNames,
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
