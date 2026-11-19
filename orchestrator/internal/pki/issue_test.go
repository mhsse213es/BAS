// orchestrator/internal/pki/issue_test.go
package pki

import (
	"crypto/x509"
	"encoding/pem"
	"testing"

	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509/pkix"
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

// The :9443 listener verifies agent certs with RequireAndVerifyClientCert,
// i.e. a full chain verification for ClientAuth -- not just a signature
// check. A CA whose own ExtKeyUsage omits ClientAuth makes every agent cert
// fail with "incompatible key usage".
func TestIssueClientCertificate_VerifiesForClientAuthAgainstCA(t *testing.T) {
	ca, err := LoadOrGenerateCAWithSANs(t.TempDir(), []string{"192.168.10.78"})
	if err != nil {
		t.Fatalf("LoadOrGenerateCAWithSANs: %v", err)
	}
	csrPEM, err := pkitest.GenerateTestCSR("agent")
	if err != nil {
		t.Fatalf("GenerateTestCSR: %v", err)
	}
	issued, err := ca.IssueClientCertificate("abc123deadbeef01", csrPEM)
	if err != nil {
		t.Fatalf("IssueClientCertificate: %v", err)
	}
	block, _ := pem.Decode(issued.CertPEM)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse issued cert: %v", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca.Certificate())
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		t.Fatalf("agent cert does not verify for ClientAuth against the CA: %v", err)
	}
}

// The CA certificate is also the orchestrator's TLS server identity, which
// agents verify for ServerAuth by IP (c67548e9). Fixing ClientAuth must not
// break that.
func TestCACertificate_StillVerifiesAsServerIdentity(t *testing.T) {
	ca, err := LoadOrGenerateCAWithSANs(t.TempDir(), []string{"192.168.10.78"})
	if err != nil {
		t.Fatalf("LoadOrGenerateCAWithSANs: %v", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca.Certificate())
	if _, err := ca.Certificate().Verify(x509.VerifyOptions{
		Roots:     roots,
		DNSName:   "192.168.10.78",
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		t.Fatalf("CA certificate no longer verifies as server identity: %v", err)
	}
}

func csrForKey(t *testing.T, key any) []byte {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "x"}}, key)
	if err != nil {
		t.Fatalf("build CSR: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

func TestIssueClientCertificate_KeyPolicy(t *testing.T) {
	ca, err := LoadOrGenerateCA(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	gen := func(c elliptic.Curve) any { k, _ := ecdsa.GenerateKey(c, rand.Reader); return k }
	rsaKey := func(bits int) any {
		k, err := rsa.GenerateKey(rand.Reader, bits)
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	_, ed, _ := ed25519.GenerateKey(rand.Reader)

	cases := []struct {
		name string
		key  any
		ok   bool
	}{
		{"ECDSA P-256", gen(elliptic.P256()), true},
		{"ECDSA P-384", gen(elliptic.P384()), true},
		{"RSA-2048", rsaKey(2048), true},
		{"ECDSA P-224", gen(elliptic.P224()), false},
		{"RSA-1024", rsaKey(1024), false},
		{"Ed25519", ed, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ca.IssueClientCertificate("0123456789abcdef", csrForKey(t, tc.key))
			if tc.ok && err != nil {
				t.Fatalf("a %s key must be accepted: %v", tc.name, err)
			}
			if !tc.ok && err == nil {
				t.Fatalf("a %s key must be rejected", tc.name)
			}
		})
	}
}
