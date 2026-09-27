// orchestrator/internal/pki/issue_test.go
package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"testing"
)

// GenerateTestCSR mirrors what a real agent does in Task 8: generate an
// ECDSA P-256 keypair locally and produce a CSR PEM for it. Exported (not
// _test.go-only) so Task 5's handler test and Task 9's protocol test can
// reuse it without duplicating CSR-construction code.
func TestIssueClientCertificate_ValidCSR(t *testing.T) {
	dir := t.TempDir()
	ca, err := LoadOrGenerateCA(dir)
	if err != nil {
		t.Fatalf("LoadOrGenerateCA: %v", err)
	}
	csrPEM, err := GenerateTestCSR("requested-cn-is-ignored")
	if err != nil {
		t.Fatalf("GenerateTestCSR: %v", err)
	}

	issued, err := ca.IssueClientCertificate("abc123deadbeef01", csrPEM)
	if err != nil {
		t.Fatalf("IssueClientCertificate: %v", err)
	}
	block, _ := pem.Decode(issued.CertPEM)
	if block == nil {
		t.Fatal("issued cert is not valid PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse issued cert: %v", err)
	}
	if cert.Subject.CommonName != "abc123deadbeef01" {
		t.Errorf("CommonName = %q, want the server-supplied agentID, not the CSR's requested CN", cert.Subject.CommonName)
	}
	if err := cert.CheckSignatureFrom(ca.Certificate()); err != nil {
		t.Errorf("issued cert does not chain to the CA: %v", err)
	}
	if issued.SerialNumber == "" {
		t.Error("SerialNumber is empty")
	}
	if issued.ExpiresAt.Before(cert.NotBefore) {
		t.Error("ExpiresAt is before the certificate's own NotBefore")
	}
}

func TestIssueClientCertificate_RejectsMalformedCSR(t *testing.T) {
	dir := t.TempDir()
	ca, err := LoadOrGenerateCA(dir)
	if err != nil {
		t.Fatalf("LoadOrGenerateCA: %v", err)
	}
	for name, bad := range map[string][]byte{
		"not PEM at all":       []byte("this is not a CSR"),
		"PEM but wrong type":   pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("garbage")}),
		"PEM CSR type but bad DER": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: []byte("garbage")}),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ca.IssueClientCertificate("some-agent-id", bad); err == nil {
				t.Errorf("expected IssueClientCertificate to reject %s, got nil error", name)
			}
		})
	}
}

// GenerateTestCSR generates an ECDSA P-256 keypair and a CSR for it, the
// same shape Task 8's real agent code produces. Exported for reuse by other
// packages' tests (Task 5, Task 9) as well as within this package.
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
