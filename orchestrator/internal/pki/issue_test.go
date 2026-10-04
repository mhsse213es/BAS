// orchestrator/internal/pki/issue_test.go
package pki

import (
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/audspect/bas/internal/pki/pkitest"
)

func TestIssueClientCertificate_ValidCSR(t *testing.T) {
	dir := t.TempDir()
	ca, err := LoadOrGenerateCA(dir)
	if err != nil {
		t.Fatalf("LoadOrGenerateCA: %v", err)
	}
	csrPEM, err := pkitest.GenerateTestCSR("requested-cn-is-ignored")
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
		"not PEM at all":           []byte("this is not a CSR"),
		"PEM but wrong type":       pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("garbage")}),
		"PEM CSR type but bad DER": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: []byte("garbage")}),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ca.IssueClientCertificate("some-agent-id", bad); err == nil {
				t.Errorf("expected IssueClientCertificate to reject %s, got nil error", name)
			}
		})
	}
}
