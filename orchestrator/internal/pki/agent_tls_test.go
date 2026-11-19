package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"testing"
	"time"
)

// serverHandshake runs one TLS handshake between an in-memory client presenting clientCert and a
// server using cfg. It returns the SERVER's handshake error: the side that decides.
func serverHandshake(t *testing.T, cfg *tls.Config, clientCert *tls.Certificate) error {
	t.Helper()
	cc, sc := net.Pipe()
	defer cc.Close()
	defer sc.Close()
	deadline := time.Now().Add(5 * time.Second)
	cc.SetDeadline(deadline)
	sc.SetDeadline(deadline)

	ccfg := &tls.Config{InsecureSkipVerify: true}
	if clientCert != nil {
		ccfg.Certificates = []tls.Certificate{*clientCert}
	}
	go func() {
		c := tls.Client(cc, ccfg)
		if c.Handshake() == nil {
			c.Read(make([]byte, 1)) // TLS 1.3: the client only learns of a server-side rejection on first read
		}
	}()
	return tls.Server(sc, cfg).Handshake()
}

func clientCertSignedBy(t *testing.T, ca *CA, agentID string, notBefore, notAfter time.Time, eku []x509.ExtKeyUsage) tls.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 100))
	tmpl := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: agentID}, DNSNames: []string{agentID},
		NotBefore: notBefore, NotAfter: notAfter, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: eku,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func TestNewAgentTLSConfig_Handshakes(t *testing.T) {
	ca, err := LoadOrGenerateCA(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	server, err := ca.TLSCertificate()
	if err != nil {
		t.Fatal(err)
	}
	other, _ := LoadOrGenerateCA(t.TempDir())
	now := time.Now()
	client := []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	good := clientCertSignedBy(t, ca, "0123456789abcdef", now.Add(-time.Hour), now.Add(time.Hour), client)
	expired := clientCertSignedBy(t, ca, "0123456789abcdef", now.Add(-48*time.Hour), now.Add(-time.Hour), client)
	foreign := clientCertSignedBy(t, other, "0123456789abcdef", now.Add(-time.Hour), now.Add(time.Hour), client)
	serverOnly := clientCertSignedBy(t, ca, "0123456789abcdef", now.Add(-time.Hour), now.Add(time.Hour), []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})

	revokedSerials := map[string]bool{}
	var checkErr error
	check := func(serial, agentID string) (bool, error) {
		if checkErr != nil {
			return false, checkErr
		}
		return revokedSerials[serial], nil
	}
	cfg := NewAgentTLSConfig(func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return &server, nil }, ca, check)
	serialOf := func(c tls.Certificate) string {
		leaf, _ := x509.ParseCertificate(c.Certificate[0])
		return leaf.SerialNumber.Text(16)
	}

	if err := serverHandshake(t, cfg, &good); err != nil {
		t.Fatalf("a valid agent certificate must be accepted: %v", err)
	}
	if err := serverHandshake(t, cfg, nil); err == nil {
		t.Error("no client certificate must be refused")
	}
	if err := serverHandshake(t, cfg, &expired); err == nil {
		t.Error("an expired certificate must be refused")
	}
	if err := serverHandshake(t, cfg, &foreign); err == nil {
		t.Error("a certificate from another CA must be refused")
	}
	if err := serverHandshake(t, cfg, &serverOnly); err == nil {
		t.Error("a certificate without the client-auth usage must be refused")
	}

	revokedSerials[serialOf(good)] = true
	if err := serverHandshake(t, cfg, &good); err == nil {
		t.Error("a revoked certificate must be refused at connection time")
	}

	revokedSerials = map[string]bool{}
	checkErr = errors.New("database unavailable")
	if err := serverHandshake(t, cfg, &good); err == nil {
		t.Error("a failing revocation lookup must refuse the connection (fail closed)")
	}

	if cfg.MinVersion < tls.VersionTLS12 {
		t.Errorf("MinVersion = %x, want at least TLS 1.2", cfg.MinVersion)
	}
}

// During a CA rotation the server accepts agent certificates from every trusted root (audit F-09), and
// still refuses a CA that is not on the list.
func TestNewAgentTLSConfigWithRoots_AcceptsEveryTrustedRootOnly(t *testing.T) {
	oldCA, _ := LoadOrGenerateCA(t.TempDir())
	newCA, _ := LoadOrGenerateCA(t.TempDir())
	stranger, _ := LoadOrGenerateCA(t.TempDir())
	server, err := newCA.TLSCertificate()
	if err != nil {
		t.Fatal(err)
	}
	cfg := NewAgentTLSConfigWithRoots(func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return &server, nil },
		[]*x509.Certificate{newCA.Certificate(), oldCA.Certificate()}, nil)
	now := time.Now()
	client := []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	underOld := clientCertSignedBy(t, oldCA, "0123456789abcdef", now.Add(-time.Hour), now.Add(time.Hour), client)
	underNew := clientCertSignedBy(t, newCA, "0123456789abcdef", now.Add(-time.Hour), now.Add(time.Hour), client)
	underStranger := clientCertSignedBy(t, stranger, "0123456789abcdef", now.Add(-time.Hour), now.Add(time.Hour), client)
	if err := serverHandshake(t, cfg, &underOld); err != nil {
		t.Errorf("an agent certificate from the previous CA must still be accepted: %v", err)
	}
	if err := serverHandshake(t, cfg, &underNew); err != nil {
		t.Errorf("an agent certificate from the new CA must be accepted: %v", err)
	}
	if err := serverHandshake(t, cfg, &underStranger); err == nil {
		t.Error("a certificate from a CA that is not trusted must be refused")
	}
}
