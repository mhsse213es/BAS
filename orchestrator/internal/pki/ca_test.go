// orchestrator/internal/pki/ca_test.go
package pki

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/audspect/bas/internal/pki/pkitest"
)

func TestLoadOrGenerateCA_GeneratesOnFirstCall(t *testing.T) {
	dir := t.TempDir()
	ca, err := LoadOrGenerateCA(dir)
	if err != nil {
		t.Fatalf("LoadOrGenerateCA: %v", err)
	}
	if ca.Certificate() == nil {
		t.Fatal("Certificate() returned nil")
	}
	if !ca.Certificate().IsCA {
		t.Error("generated certificate is not marked IsCA")
	}
	for _, name := range []string{"ca-key.pem", "ca-cert.pem"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("expected %s to exist: %v", name, err)
		}
	}
}

func TestLoadOrGenerateCA_LoadsExistingOnSecondCall(t *testing.T) {
	dir := t.TempDir()
	first, err := LoadOrGenerateCA(dir)
	if err != nil {
		t.Fatalf("first LoadOrGenerateCA: %v", err)
	}
	second, err := LoadOrGenerateCA(dir)
	if err != nil {
		t.Fatalf("second LoadOrGenerateCA: %v", err)
	}
	if first.Certificate().SerialNumber.Cmp(second.Certificate().SerialNumber) != 0 {
		t.Error("second call generated a NEW CA instead of loading the existing one — " +
			"this would invalidate every already-issued agent certificate")
	}
}

// TestLoadOrGenerateCA_BareCallHasNoIPSANs pins the exact failure mode
// found live 2026-09-30: an agent dialing the orchestrator by IP address
// (192.168.10.78, a completely ordinary on-prem setup) got
// "x509: cannot validate certificate for 192.168.10.78, because it doesn't
// contain any IP SANs" on every single connection attempt, because
// TLSCertificate presents this exact certificate directly as the server's
// TLS identity and it carried no SANs at all. This test documents that a
// bare LoadOrGenerateCA still has that gap -- LoadOrGenerateCAWithSANs
// below is the fix, not this constructor.
func TestLoadOrGenerateCA_BareCallHasNoIPSANs(t *testing.T) {
	dir := t.TempDir()
	ca, err := LoadOrGenerateCA(dir)
	if err != nil {
		t.Fatalf("LoadOrGenerateCA: %v", err)
	}
	if err := ca.Certificate().VerifyHostname("192.168.10.78"); err == nil {
		t.Fatal("expected a bare LoadOrGenerateCA cert to fail hostname verification for an IP " +
			"(no SANs were requested) -- if this now passes, VerifyHostname's IP-SAN requirement " +
			"changed and LoadOrGenerateCAWithSANs's doc comment needs re-checking against reality")
	}
}

// TestLoadOrGenerateCAWithSANs_AgentCanVerifyByIP is the fix: an agent
// using Go's standard TLS client (crypto/tls, no CommonName fallback since
// Go 1.15) against a CA generated with the address it will actually dial
// must be able to complete real certificate verification -- not just have
// the right bytes in the SAN list.
func TestLoadOrGenerateCAWithSANs_AgentCanVerifyByIP(t *testing.T) {
	dir := t.TempDir()
	ca, err := LoadOrGenerateCAWithSANs(dir, []string{"192.168.10.78", "audspecterver"})
	if err != nil {
		t.Fatalf("LoadOrGenerateCAWithSANs: %v", err)
	}
	cert := ca.Certificate()
	if len(cert.IPAddresses) != 1 || !cert.IPAddresses[0].Equal(net.ParseIP("192.168.10.78")) {
		t.Errorf("expected exactly one IP SAN 192.168.10.78, got %v", cert.IPAddresses)
	}
	if len(cert.DNSNames) != 1 || cert.DNSNames[0] != "audspecterver" {
		t.Errorf("expected exactly one DNS SAN audspecterver, got %v", cert.DNSNames)
	}
	if err := cert.VerifyHostname("192.168.10.78"); err != nil {
		t.Errorf("VerifyHostname(IP SAN) should succeed: %v", err)
	}
	if err := cert.VerifyHostname("audspecterver"); err != nil {
		t.Errorf("VerifyHostname(DNS SAN) should succeed: %v", err)
	}

	// End-to-end: the same real TLS handshake+verification path a Go agent
	// actually uses, not just VerifyHostname in isolation.
	tlsCert, err := ca.TLSCertificate()
	if err != nil {
		t.Fatalf("TLSCertificate: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	srv := &tls.Config{Certificates: []tls.Certificate{tlsCert}}
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		tls.Server(conn, srv).Handshake()
	}()
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	// Dial via the DNS SAN (loopback test env can't literally dial
	// 192.168.10.78) with ServerName pinned to what a real client would
	// send when connecting to that IP, proving the same SAN machinery a
	// real agent relies on.
	clientCfg := &tls.Config{RootCAs: pool, ServerName: "audspecterver"}
	conn, err := tls.Dial("tcp", ln.Addr().String(), clientCfg)
	if err != nil {
		t.Fatalf("client TLS handshake should succeed against a SAN-matching cert: %v", err)
	}
	conn.Close()
}

func TestLoadOrGenerateCA_CorruptKeyFileFailsLoudly(t *testing.T) {
	dir := t.TempDir()
	if _, err := LoadOrGenerateCA(dir); err != nil {
		t.Fatalf("initial generate: %v", err)
	}
	// Corrupt the key file to simulate disk corruption / truncated write.
	if err := os.WriteFile(filepath.Join(dir, "ca-key.pem"), []byte("not a pem file"), 0600); err != nil {
		t.Fatalf("corrupt key file: %v", err)
	}
	if _, err := LoadOrGenerateCA(dir); err == nil {
		t.Fatal("expected LoadOrGenerateCA to fail loudly on a corrupt key file, got nil error — " +
			"silently regenerating here would invalidate the whole fleet's certificates without warning")
	}
}

// --- managed-CA hardening: a half-present, mismatched, invalid or loose CA must fail closed ---

func writeFile(t *testing.T, path string, data []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatal(err)
	}
}

func TestLoadOrGenerateCA_CertWithoutKeyFailsClosedAndLeavesCertAlone(t *testing.T) {
	dir := t.TempDir()
	if _, err := LoadOrGenerateCA(dir); err != nil {
		t.Fatal(err)
	}
	certPath := filepath.Join(dir, "ca-cert.pem")
	before, _ := os.ReadFile(certPath)
	if err := os.Remove(filepath.Join(dir, "ca-key.pem")); err != nil {
		t.Fatal(err)
	}
	_, err := LoadOrGenerateCA(dir)
	if err == nil || !strings.Contains(err.Error(), "incomplete") {
		t.Fatalf("got %v, want an 'incomplete CA' error: silently generating a replacement would lock out every enrolled agent", err)
	}
	after, _ := os.ReadFile(certPath)
	if !bytes.Equal(before, after) {
		t.Fatal("the existing CA certificate must not be overwritten")
	}
	if _, err := os.Stat(filepath.Join(dir, "ca-key.pem")); err == nil {
		t.Fatal("no replacement key may be created")
	}
}

func TestLoadOrGenerateCA_KeyWithoutCertFailsClosed(t *testing.T) {
	dir := t.TempDir()
	if _, err := LoadOrGenerateCA(dir); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(dir, "ca-key.pem")
	before, _ := os.ReadFile(keyPath)
	os.Remove(filepath.Join(dir, "ca-cert.pem"))
	if _, err := LoadOrGenerateCA(dir); err == nil {
		t.Fatal("a key with no certificate must fail")
	}
	after, _ := os.ReadFile(keyPath)
	if !bytes.Equal(before, after) {
		t.Fatal("the existing key must not be touched")
	}
}

func TestLoadOrGenerateCA_MismatchedKeyAndCertRejected(t *testing.T) {
	a, b := t.TempDir(), t.TempDir()
	if _, err := LoadOrGenerateCA(a); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrGenerateCA(b); err != nil {
		t.Fatal(err)
	}
	other, _ := os.ReadFile(filepath.Join(b, "ca-cert.pem"))
	writeFile(t, filepath.Join(a, "ca-cert.pem"), other, 0644) // key from A, certificate from B
	_, err := LoadOrGenerateCA(a)
	if err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("got %v, want a key/certificate mismatch error", err)
	}
}

// craftCA writes a key and a certificate with the given properties for tests of invalid CAs.
func craftCA(t *testing.T, dir string, isCA bool, notBefore, notAfter time.Time) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	usage := x509.KeyUsageDigitalSignature
	if isCA {
		usage |= x509.KeyUsageCertSign
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(42), Subject: pkix.Name{CommonName: "crafted"},
		NotBefore: notBefore, NotAfter: notAfter, KeyUsage: usage,
		BasicConstraintsValid: true, IsCA: isCA,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeECKeyPEM(filepath.Join(dir, "ca-key.pem"), key); err != nil {
		t.Fatal(err)
	}
	if err := writeCertPEM(filepath.Join(dir, "ca-cert.pem"), der); err != nil {
		t.Fatal(err)
	}
}

func TestLoadOrGenerateCA_NonCACertificateRejected(t *testing.T) {
	dir := t.TempDir()
	craftCA(t, dir, false, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	if _, err := LoadOrGenerateCA(dir); err == nil || !strings.Contains(err.Error(), "not a certificate authority") {
		t.Fatalf("got %v, want a not-a-CA error", err)
	}
}

func TestLoadOrGenerateCA_ExpiredCARejectedWithClearMessage(t *testing.T) {
	dir := t.TempDir()
	craftCA(t, dir, true, time.Now().Add(-48*time.Hour), time.Now().Add(-time.Hour))
	_, err := LoadOrGenerateCA(dir)
	if err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("got %v, want an expired error: an expired CA locks out the whole fleet and must be loud", err)
	}
}

func TestLoadOrGenerateCA_NotYetValidCARejected(t *testing.T) {
	dir := t.TempDir()
	craftCA(t, dir, true, time.Now().Add(2*time.Hour), time.Now().Add(48*time.Hour))
	if _, err := LoadOrGenerateCA(dir); err == nil || !strings.Contains(err.Error(), "not yet valid") {
		t.Fatalf("got %v, want a not-yet-valid error (check the clock)", err)
	}
}

func TestLoadOrGenerateCA_LooseKeyPermissionsAreTightened(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX file modes are not enforced on Windows")
	}
	dir := t.TempDir()
	if _, err := LoadOrGenerateCA(dir); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(dir, "ca-key.pem")
	if err := os.Chmod(keyPath, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrGenerateCA(dir); err != nil {
		t.Fatalf("a readable key is repaired, not fatal: %v", err)
	}
	st, _ := os.Stat(keyPath)
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("key mode %v, want 0600", st.Mode().Perm())
	}
}

func TestLoadOrGenerateCA_RestoredCopyIsTheSameCA(t *testing.T) {
	src := t.TempDir()
	orig, err := LoadOrGenerateCA(src)
	if err != nil {
		t.Fatal(err)
	}
	dst := t.TempDir() // a restore: copy the two files into a fresh directory
	for _, f := range []string{"ca-key.pem", "ca-cert.pem"} {
		b, _ := os.ReadFile(filepath.Join(src, f))
		writeFile(t, filepath.Join(dst, f), b, 0600)
	}
	restored, err := LoadOrGenerateCA(dst)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(orig.RootCertPEM(), restored.RootCertPEM()) {
		t.Fatal("a restored CA must be the same CA, or every enrolled agent breaks")
	}
}

func TestLoadOrGenerateCA_CAWithoutSigningUsageRejected(t *testing.T) {
	dir := t.TempDir()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// IsCA is set, but the key usage does not allow signing certificates.
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "no certsign"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, BasicConstraintsValid: true, IsCA: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeECKeyPEM(filepath.Join(dir, "ca-key.pem"), key); err != nil {
		t.Fatal(err)
	}
	if err := writeCertPEM(filepath.Join(dir, "ca-cert.pem"), der); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrGenerateCA(dir); err == nil || !strings.Contains(err.Error(), "not allowed to sign") {
		t.Fatalf("got %v, want a cannot-sign error", err)
	}
}

// A restore must give back the same CA (same fingerprint) and agents enrolled before it must still verify.
func TestLoadOrGenerateCA_RestoreKeepsFingerprintAndExistingAgentCertsStillVerify(t *testing.T) {
	src := t.TempDir()
	orig, err := LoadOrGenerateCAWithSANs(src, []string{"192.168.10.78"})
	if err != nil {
		t.Fatal(err)
	}
	csr, err := pkitest.GenerateTestCSR("agent-1")
	if err != nil {
		t.Fatal(err)
	}
	issued, err := orig.IssueClientCertificate("agent-1", csr)
	if err != nil {
		t.Fatal(err)
	}

	dst := t.TempDir() // simulate: server lost, CA restored from backup into a new directory
	for _, f := range []string{"ca-key.pem", "ca-cert.pem"} {
		b, _ := os.ReadFile(filepath.Join(src, f))
		writeFile(t, filepath.Join(dst, f), b, 0600)
	}
	restored, err := LoadOrGenerateCA(dst)
	if err != nil {
		t.Fatal(err)
	}

	if sha256.Sum256(orig.Certificate().Raw) != sha256.Sum256(restored.Certificate().Raw) {
		t.Fatal("the restored CA must have the same fingerprint")
	}
	blk, _ := pem.Decode(issued.CertPEM)
	agentCert, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(restored.Certificate())
	if _, err := agentCert.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Fatalf("an agent certificate issued before the restore no longer verifies against the restored CA: %v", err)
	}
	// And the restored CA can keep issuing.
	if _, err := restored.IssueClientCertificate("agent-2", csr); err != nil {
		t.Fatalf("the restored CA cannot issue: %v", err)
	}
}
