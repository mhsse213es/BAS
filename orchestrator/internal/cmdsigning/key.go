// Package cmdsigning implements the deployment command-signing keypair
// used to sign every execution-triggering WS command dispatched to an
// agent (B4). This is a separate trust domain from both the mTLS
// deployment CA (internal/pki -- see that package's own doc comment,
// which already anticipated this package) and the offline vendor
// scenario-signing key (internal/integrity) -- the three are never
// chained together, so compromise of one does not automatically
// compromise another. Unlike the vendor key, this key's private half
// necessarily lives with the running orchestrator, because it signs
// commands generated at runtime, not static content signed offline.
// See docs/superpowers/specs/2026-09-28-command-envelope-signing-design.md.
package cmdsigning

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

// signingKeyValidity mirrors the deployment CA's long-lived-by-design
// choice (internal/pki/ca.go's caValidity) -- air-gapped operators don't
// want frequent rotation, and the full rotation flow (accepting a
// current + next key during an overlap period) is explicitly out of
// scope for this initial implementation; see the spec.
const signingKeyValidity = 10 * 365 * 24 * time.Hour

// SigningKey holds the deployment command-signing keypair and its
// self-signed identity certificate. The private key never leaves the
// orchestrator host.
type SigningKey struct {
	cert    *x509.Certificate
	certDER []byte
	key     *rsa.PrivateKey
	keyID   string
}

// LoadOrGenerateSigningKey loads an existing signing keypair from dir, or
// generates a new one if dir contains no command-signing.key. dir is
// created if it does not exist. A key that exists but fails to parse
// (corrupt/truncated file) is a hard error -- silently regenerating would
// invalidate every already-distributed agent's trust in the old key with
// no warning, exactly like internal/pki/ca.go's LoadOrGenerateCA.
func LoadOrGenerateSigningKey(dir string) (*SigningKey, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("create signing dir %s: %w", dir, err)
	}
	keyPath := filepath.Join(dir, "command-signing.key")
	certPath := filepath.Join(dir, "command-signing.crt")

	if _, err := os.Stat(keyPath); err == nil {
		return loadSigningKey(keyPath, certPath)
	}
	return generateSigningKey(keyPath, certPath)
}

func generateSigningKey(keyPath, certPath string) (*SigningKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, fmt.Errorf("generate command-signing key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generate command-signing cert serial: %w", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "Audspect Deployment Command-Signing Key", Organization: []string{"Audspect"}},
		NotBefore:             time.Now().Add(-5 * time.Minute),
		NotAfter:              time.Now().Add(signingKeyValidity),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("create command-signing certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("parse generated command-signing certificate: %w", err)
	}
	if err := writeRSAKeyPEM(keyPath, key); err != nil {
		return nil, err
	}
	if err := writeCertPEM(certPath, certDER); err != nil {
		return nil, err
	}
	return &SigningKey{cert: cert, certDER: certDER, key: key, keyID: keyIDFor(certDER)}, nil
}

func loadSigningKey(keyPath, certPath string) (*SigningKey, error) {
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("read command-signing key: %w", err)
	}
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("read command-signing cert: %w", err)
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, fmt.Errorf("decode command-signing key PEM %s: no PEM block found (corrupt or truncated file)", keyPath)
	}
	key, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse command-signing private key: %w", err)
	}
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, fmt.Errorf("decode command-signing cert PEM %s: no PEM block found (corrupt or truncated file)", certPath)
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse command-signing certificate: %w", err)
	}
	certPub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok || !certPub.Equal(&key.PublicKey) {
		// A mismatched pair here means command-signing.crt and
		// command-signing.key came from different generations (a partial
		// restore, a manual file swap) -- signing with key would produce
		// signatures no agent's pinned cert can verify, failing silently
		// and unrecoverably at the next dispatched command rather than
		// loudly here at startup.
		return nil, fmt.Errorf("command-signing cert %s does not match the public key of command-signing key %s -- files may be from different generations", certPath, keyPath)
	}
	return &SigningKey{cert: cert, certDER: certBlock.Bytes, key: key, keyID: keyIDFor(certBlock.Bytes)}, nil
}

func writeRSAKeyPEM(path string, key *rsa.PrivateKey) error {
	der := x509.MarshalPKCS1PrivateKey(key)
	block := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: der}
	// 0600: readable only by the orchestrator process owner, matching
	// internal/pki/ca.go's CA key -- this file staying on the orchestrator
	// host is the entire point of this key's trust model.
	return os.WriteFile(path, pem.EncodeToMemory(block), 0600)
}

func writeCertPEM(path string, der []byte) error {
	block := &pem.Block{Type: "CERTIFICATE", Bytes: der}
	return os.WriteFile(path, pem.EncodeToMemory(block), 0644)
}

// keyIDFor derives a stable key identifier from the certificate's DER
// bytes -- forward-compatibility for the future key-rotation flow (out of
// scope for this plan; see the spec), so agents can already record which
// key they were told to trust without a future wire-format change.
func keyIDFor(certDER []byte) string {
	h := sha256Sum(certDER)
	return "command-signing-key-" + hex.EncodeToString(h[:8])
}

// PrivateKey returns the RSA private key used to sign envelopes.
func (s *SigningKey) PrivateKey() *rsa.PrivateKey { return s.key }

// CertPEM returns the signing certificate in PEM form, for distribution
// to agents via the enrollment response (Task 6).
func (s *SigningKey) CertPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.certDER})
}

// KeyID returns this key's stable identifier.
func (s *SigningKey) KeyID() string { return s.keyID }
