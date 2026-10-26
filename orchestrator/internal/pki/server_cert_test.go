package pki

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func newSource(t *testing.T, ca *CA, dir string, sans []string, now func() time.Time) *ServerCertSource {
	t.Helper()
	s, err := NewServerCertSource(ca, dir, sans)
	if err != nil {
		t.Fatalf("NewServerCertSource: %v", err)
	}
	if now != nil {
		s.now = now
	}
	return s
}

func leafOf(t *testing.T, s *ServerCertSource) *x509.Certificate {
	t.Helper()
	c, err := s.GetCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(c.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	return leaf
}

// F-10: the server's TLS identity is its own leaf certificate, not the CA certificate.
func TestServerCert_IsALeafDistinctFromTheCA(t *testing.T) {
	ca, err := LoadOrGenerateCA(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s := newSource(t, ca, t.TempDir(), []string{"bas.example.internal", "192.168.10.78"}, nil)
	leaf := leafOf(t, s)

	if leaf.IsCA {
		t.Error("the server certificate must not be a CA")
	}
	if len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth {
		t.Errorf("ExtKeyUsage = %v, want server authentication only", leaf.ExtKeyUsage)
	}
	if leaf.KeyUsage&x509.KeyUsageCertSign != 0 {
		t.Error("the server certificate must not be able to sign certificates")
	}
	if pub, ok := leaf.PublicKey.(*ecdsa.PublicKey); !ok || pub.Equal(&ca.key.PublicKey) {
		t.Error("the server certificate must use its own key, not the CA key")
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca.Certificate())
	for _, name := range []string{"bas.example.internal", "192.168.10.78"} {
		if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: name, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
			t.Errorf("does not verify for %s against the CA: %v", name, err)
		}
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: "other.example", KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err == nil {
		t.Error("a name that was not requested must not verify")
	}
}

func TestServerCert_IsReusedAcrossRestarts(t *testing.T) {
	ca, _ := LoadOrGenerateCA(t.TempDir())
	dir := t.TempDir()
	sans := []string{"192.168.10.78"}
	first := leafOf(t, newSource(t, ca, dir, sans, nil))
	second := leafOf(t, newSource(t, ca, dir, sans, nil))
	if first.SerialNumber.Cmp(second.SerialNumber) != 0 {
		t.Error("a restart must reuse the stored server certificate")
	}
}

// Changing the server's names must not touch the CA or the trust anchor agents hold.
func TestServerCert_NamesChangeReissuesTheLeafOnly(t *testing.T) {
	ca, _ := LoadOrGenerateCA(t.TempDir())
	caBefore := sha256.Sum256(ca.Certificate().Raw)
	dir := t.TempDir()
	first := leafOf(t, newSource(t, ca, dir, []string{"192.168.10.78"}, nil))
	second := leafOf(t, newSource(t, ca, dir, []string{"192.168.10.99", "bas.example.internal"}, nil))
	if first.SerialNumber.Cmp(second.SerialNumber) == 0 {
		t.Fatal("new names require a new server certificate")
	}
	if !second.IPAddresses[0].Equal(net.ParseIP("192.168.10.99")) {
		t.Errorf("IP SANs = %v", second.IPAddresses)
	}
	if caBefore != sha256.Sum256(ca.Certificate().Raw) {
		t.Error("the CA must be unchanged")
	}
}

// Renewal is independent of the CA: it happens in the running server and never changes the CA.
func TestServerCert_RenewsBeforeExpiryWithoutTouchingTheCA(t *testing.T) {
	caDir := t.TempDir()
	ca, _ := LoadOrGenerateCA(caDir)
	caKeyBefore, _ := os.ReadFile(filepath.Join(caDir, "ca-key.pem"))
	start := time.Now()
	clock := start
	s := newSource(t, ca, t.TempDir(), []string{"192.168.10.78"}, func() time.Time { return clock })

	first := leafOf(t, s)
	clock = start.Add(100 * 24 * time.Hour)
	if got := leafOf(t, s); got.SerialNumber.Cmp(first.SerialNumber) != 0 {
		t.Error("a certificate far from expiry must not be replaced")
	}
	clock = start.Add(345 * 24 * time.Hour) // inside the 30-day renewal window
	renewed := leafOf(t, s)
	if renewed.SerialNumber.Cmp(first.SerialNumber) == 0 {
		t.Fatal("a certificate inside the renewal window must be replaced while the server keeps running")
	}
	if !renewed.NotAfter.After(first.NotAfter) {
		t.Error("the renewed certificate should expire later")
	}
	caKeyAfter, _ := os.ReadFile(filepath.Join(caDir, "ca-key.pem"))
	if string(caKeyBefore) != string(caKeyAfter) {
		t.Error("renewing the server certificate must not touch the CA")
	}
}

func TestServerCert_DamagedOrMissingFilesAreReissuedSafely(t *testing.T) {
	ca, _ := LoadOrGenerateCA(t.TempDir())
	for name, damage := range map[string]func(dir string){
		"key missing":  func(d string) { os.Remove(filepath.Join(d, "server-key.pem")) },
		"cert missing": func(d string) { os.Remove(filepath.Join(d, "server-cert.pem")) },
		"cert corrupt": func(d string) { os.WriteFile(filepath.Join(d, "server-cert.pem"), []byte("junk"), 0644) },
		"key corrupt":  func(d string) { os.WriteFile(filepath.Join(d, "server-key.pem"), []byte("junk"), 0600) },
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			sans := []string{"192.168.10.78"}
			first := leafOf(t, newSource(t, ca, dir, sans, nil))
			damage(dir)
			second := leafOf(t, newSource(t, ca, dir, sans, nil))
			if first.SerialNumber.Cmp(second.SerialNumber) == 0 {
				t.Error("a damaged server certificate must be replaced")
			}
		})
	}
}

// A server certificate signed by some other CA is never kept: only the loaded CA signs the server identity.
func TestServerCert_SignedByAnotherCAIsReplacedNotTrusted(t *testing.T) {
	caA, _ := LoadOrGenerateCA(t.TempDir())
	caB, _ := LoadOrGenerateCA(t.TempDir())
	dir := t.TempDir()
	sans := []string{"192.168.10.78"}
	underA := leafOf(t, newSource(t, caA, dir, sans, nil))
	underB := leafOf(t, newSource(t, caB, dir, sans, nil))
	if underA.SerialNumber.Cmp(underB.SerialNumber) == 0 {
		t.Fatal("a leaf issued by a different CA must be replaced")
	}
	roots := x509.NewCertPool()
	roots.AddCert(caB.Certificate())
	if _, err := underB.Verify(x509.VerifyOptions{Roots: roots}); err != nil {
		t.Errorf("the replacement must chain to the CA that is actually loaded: %v", err)
	}
}

// What an agent does: verify the server by chain to the pinned CA only.
func TestServerCert_AgentStyleChainVerificationOverARealHandshake(t *testing.T) {
	ca, _ := LoadOrGenerateCA(t.TempDir())
	s := newSource(t, ca, t.TempDir(), []string{"192.168.10.78"}, nil)
	cfg := NewAgentTLSConfig(s.GetCertificate, ca, nil)
	leafClient := clientCertSignedBy(t, ca, "0123456789abcdef", time.Now().Add(-time.Hour), time.Now().Add(time.Hour), []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})

	cc, sc := net.Pipe()
	defer cc.Close()
	defer sc.Close()
	dl := time.Now().Add(5 * time.Second)
	cc.SetDeadline(dl)
	sc.SetDeadline(dl)
	roots := x509.NewCertPool()
	roots.AddCert(ca.Certificate())
	errc := make(chan error, 1)
	go func() {
		c := tls.Client(cc, &tls.Config{
			Certificates:       []tls.Certificate{leafClient},
			InsecureSkipVerify: true, // as the agent does: chain-only, via VerifyPeerCertificate
			VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
				cert, err := x509.ParseCertificate(raw[0])
				if err != nil {
					return err
				}
				_, err = cert.Verify(x509.VerifyOptions{Roots: roots})
				return err
			},
		})
		errc <- c.Handshake()
	}()
	if err := tls.Server(sc, cfg).Handshake(); err != nil {
		t.Fatalf("server handshake: %v", err)
	}
	if err := <-errc; err != nil {
		t.Fatalf("an agent could not verify the server's own certificate: %v", err)
	}
}
