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
	"log"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"runtime"
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

	_, keyErr := os.Stat(keyPath)
	_, certErr := os.Stat(certPath)
	keyThere, certThere := keyErr == nil, certErr == nil

	switch {
	case keyThere && certThere:
		return loadCA(keyPath, certPath)
	case !keyThere && !certThere:
		return generateCA(keyPath, certPath, sans)
	default:
		// Exactly one of the two exists: a damaged or half-restored CA. Generating a replacement
		// here would overwrite the survivor and silently lock out every enrolled agent.
		return nil, fmt.Errorf("incomplete CA in %s (key present: %t, certificate present: %t): "+
			"restore both ca-key.pem and ca-cert.pem from backup; if you really want a new CA, remove both files "+
			"and set BAS_CONFIRM_NEW_CA=true -- every enrolled agent must then re-enroll", dir, keyThere, certThere)
	}
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
	if err := validateLoadedCA(cert, key, time.Now()); err != nil {
		return nil, fmt.Errorf("CA in %s is not usable: %w", filepath.Dir(keyPath), err)
	}
	tightenKeyPermissions(keyPath)
	return &CA{cert: cert, certDER: certBlock.Bytes, key: key}, nil
}

// caExpiryWarning is how far ahead of expiry a startup warning is logged. An expired CA locks out
// the whole fleet, so it must be noticed long before it happens.
const caExpiryWarning = 180 * 24 * time.Hour

// validateLoadedCA rejects a CA that would fail later in confusing ways: a key that does not belong
// to the certificate, a certificate that is not a CA or cannot sign, and one outside its validity.
func validateLoadedCA(cert *x509.Certificate, key *ecdsa.PrivateKey, now time.Time) error {
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || !pub.Equal(&key.PublicKey) {
		return fmt.Errorf("the private key does not match the CA certificate (wrong or mixed-up backup files?)")
	}
	if !cert.IsCA || !cert.BasicConstraintsValid {
		return fmt.Errorf("the certificate is not a certificate authority")
	}
	if cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return fmt.Errorf("the certificate is not allowed to sign certificates")
	}
	if now.Before(cert.NotBefore) {
		return fmt.Errorf("the certificate is not yet valid (starts %s): check this machine's clock", cert.NotBefore.UTC().Format(time.RFC3339))
	}
	if now.After(cert.NotAfter) {
		return fmt.Errorf("the certificate expired on %s: agents can no longer enroll or connect; this needs a planned CA replacement", cert.NotAfter.UTC().Format(time.RFC3339))
	}
	if remaining := cert.NotAfter.Sub(now); remaining < caExpiryWarning {
		log.Printf("[!] The deployment CA expires in %d days (%s). Plan its replacement now: expiry locks out every agent.",
			int(remaining.Hours()/24), cert.NotAfter.UTC().Format("2006-01-02"))
	}
	return nil
}

// tightenKeyPermissions repairs a CA key that group or others can read, for example after a backup
// restore. Best effort: POSIX file modes are not enforced on Windows, and a failure is only logged
// because refusing to start would turn a permissions slip into an outage.
func tightenKeyPermissions(keyPath string) {
	if runtime.GOOS == "windows" {
		return
	}
	st, err := os.Stat(keyPath)
	if err != nil || st.Mode().Perm()&0o077 == 0 {
		return
	}
	if err := os.Chmod(keyPath, 0o600); err != nil {
		log.Printf("[!] The CA private key %s is readable by other users (mode %v) and could not be restricted: %v", keyPath, st.Mode().Perm(), err)
		return
	}
	log.Printf("[!] The CA private key %s was readable by other users (mode %v); restricted to 0600.", keyPath, st.Mode().Perm())
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
