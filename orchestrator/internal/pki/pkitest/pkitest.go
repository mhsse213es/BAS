// orchestrator/internal/pki/pkitest/pkitest.go
package pkitest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
)

// GenerateTestCSR generates an ECDSA P-256 keypair and a CSR for it, the
// same shape Task 8's real agent code produces. Lives in this dedicated
// test-support subpackage (the same pattern the standard library uses for
// httptest) rather than in package pki itself: production code never
// imports pkitest, so Go's linker excludes it from any build that doesn't
// reference it -- unlike a plain non-_test.go file in package pki, which
// would compile into every binary that imports pki, including the
// orchestrator server. Used by Task 3's own pki tests, Task 5's handler
// test, and Task 9's protocol test.
func GenerateTestCSR(commonName string) ([]byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: commonName},
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), nil
}

// NewTestKey generates an ECDSA P-256 private key for tests that need to reuse one key across requests.
func NewTestKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// GenerateTestCSRWith returns a CSR for the given key, so a test can present the same key again.
func GenerateTestCSRWith(key *ecdsa.PrivateKey, commonName string) ([]byte, error) {
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: commonName},
	}, key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), nil
}
