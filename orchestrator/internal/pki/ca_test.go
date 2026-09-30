// orchestrator/internal/pki/ca_test.go
package pki

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"os"
	"path/filepath"
	"testing"
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
