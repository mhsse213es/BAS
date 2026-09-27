// orchestrator/internal/pki/testcsr.go
package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
)

// GenerateTestCSR generates an ECDSA P-256 keypair and a CSR for it, the
// same shape Task 8's real agent code produces. Exported (not _test.go-only
// -- Go excludes _test.go files from normal package compilation, so a
// function defined there is invisible to other packages' own tests) so
// Task 5's handler test and Task 9's protocol test can reuse it without
// duplicating CSR-construction code, as well as within this package's own
// tests.
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
