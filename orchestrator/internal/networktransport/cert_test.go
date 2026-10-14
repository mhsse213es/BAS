package networktransport

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/audspect/bas/internal/networkgraph"
	"github.com/audspect/bas/internal/networksecurity"
)

// testCA is a minimal, self-contained certificate authority for tests
// -- entirely deterministic, no dependency on real internet PKI.
type testCA struct {
	cert *x509.Certificate
	key  *rsa.PrivateKey
	pool *x509.CertPool
}

func newTestCA(t *testing.T) *testCA {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &testCA{cert: cert, key: key, pool: pool}
}

// issueLeaf signs a leaf certificate for name with the given validity
// window, using ca -- or, if selfSigned is true, signs it with its own
// freshly generated key instead (producing a cert the CA pool never
// trusts, for the untrusted-chain test case).
//
// Go's x509.Certificate.VerifyHostname (invoked internally by Verify
// when VerifyOptions.DNSName is set) checks ONLY IPAddresses -- never
// DNSNames -- whenever the name being verified parses as a literal IP.
// Every test server here listens on "127.0.0.1" and the probe dials
// that same literal IP, so a leaf meant to match must carry an
// IPAddresses SAN, not a DNSNames one, or even the happy-path case
// would fail hostname verification for the wrong reason.
func (ca *testCA) issueLeaf(t *testing.T, name string, notBefore, notAfter time.Time, selfSigned bool) tls.Certificate {
	t.Helper()
	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(name); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{name}
	}
	parent, signer := ca.cert, (any)(ca.key)
	if selfSigned {
		parent, signer = template, leafKey
	}
	der, err := x509.CreateCertificate(rand.Reader, template, parent, &leafKey.PublicKey, signer)
	if err != nil {
		t.Fatalf("create leaf cert: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: leafKey}
}

// startTestTLSServer starts a real local TLS listener presenting cert,
// handshaking every accepted connection and otherwise doing nothing --
// mirrors Phase 1's own real-local-listener pattern, extended to TLS.
func startTestTLSServer(t *testing.T, cert tls.Certificate) (host string, port int) {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatalf("listen tls: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				if tlsConn, ok := c.(*tls.Conn); ok {
					_ = tlsConn.Handshake()
				}
			}(conn)
		}
	}()
	addr := ln.Addr().(*net.TCPAddr)
	return addr.IP.String(), addr.Port
}

func TestTLSCertProbe_ValidCertSignedByTrustedCA_Secure(t *testing.T) {
	ca := newTestCA(t)
	cert := ca.issueLeaf(t, "127.0.0.1", time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour), false)
	host, port := startTestTLSServer(t, cert)

	p := TLSCertProbe{roots: ca.pool}
	state, reason := p.Probe(context.Background(), networkgraph.Target{Host: host, Port: port}, time.Second)
	if state != networksecurity.Secure {
		t.Fatalf("state = %q (reason: %s), want Secure", state, reason)
	}
}

func TestTLSCertProbe_ExpiredCert_Insecure(t *testing.T) {
	ca := newTestCA(t)
	cert := ca.issueLeaf(t, "127.0.0.1", time.Now().Add(-48*time.Hour), time.Now().Add(-time.Hour), false)
	host, port := startTestTLSServer(t, cert)

	p := TLSCertProbe{roots: ca.pool}
	state, reason := p.Probe(context.Background(), networkgraph.Target{Host: host, Port: port}, time.Second)
	if state != networksecurity.Insecure {
		t.Fatalf("state = %q (reason: %s), want Insecure -- an expired certificate is a positively demonstrated weakness", state, reason)
	}
}

func TestTLSCertProbe_HostnameMismatch_Insecure(t *testing.T) {
	ca := newTestCA(t)
	cert := ca.issueLeaf(t, "other-service.test", time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour), false)
	host, port := startTestTLSServer(t, cert)

	p := TLSCertProbe{roots: ca.pool}
	state, reason := p.Probe(context.Background(), networkgraph.Target{Host: host, Port: port}, time.Second)
	if state != networksecurity.Insecure {
		t.Fatalf("state = %q (reason: %s), want Insecure -- the cert is for other-service.test, not %s", state, reason, host)
	}
}

func TestTLSCertProbe_UntrustedChain_Insecure(t *testing.T) {
	ca := newTestCA(t)
	cert := ca.issueLeaf(t, "127.0.0.1", time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour), true) // self-signed, not issued by ca
	host, port := startTestTLSServer(t, cert)

	p := TLSCertProbe{roots: ca.pool} // ca's pool never trusts the self-signed leaf
	state, reason := p.Probe(context.Background(), networkgraph.Target{Host: host, Port: port}, time.Second)
	if state != networksecurity.Insecure {
		t.Fatalf("state = %q (reason: %s), want Insecure -- a self-signed leaf the trust pool never issued must not verify", state, reason)
	}
}

func TestTLSCertProbe_HandshakeFails_Unknown(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close() // nothing is listening -- the handshake can't even start

	p := TLSCertProbe{}
	state, reason := p.Probe(context.Background(), networkgraph.Target{Host: "127.0.0.1", Port: port}, time.Second)
	if state != networksecurity.Unknown {
		t.Fatalf("state = %q (reason: %s), want Unknown -- a failed handshake must never be read as a bad certificate", state, reason)
	}
}
