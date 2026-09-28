package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/audspect/bas/config"
	"github.com/audspect/bas/internal/pki"
)

// TestThreeListeners_EnrollListenerAcceptsNoClientCert is the regression
// test the spec calls for: a client presenting NO certificate must be able
// to complete a TLS handshake against the enrollment listener (proving the
// circular-dependency bug -- a brand-new agent can't get a cert from a
// listener that requires one -- cannot reoccur), while the same bare
// handshake against the mTLS listener must fail.
func TestThreeListeners_EnrollListenerAcceptsNoClientCert(t *testing.T) {
	dir := t.TempDir()
	ca, err := pki.LoadOrGenerateCA(dir)
	if err != nil {
		t.Fatalf("LoadOrGenerateCA: %v", err)
	}
	serverCert, err := ca.TLSCertificate()
	if err != nil {
		t.Fatalf("TLSCertificate: %v", err)
	}

	pool := x509.NewCertPool()
	pool.AddCert(ca.Certificate())

	mtlsSrv := newTLSListenerForTest(t, serverCert, tls.RequireAndVerifyClientCert, pool)
	enrollSrv := newTLSListenerForTest(t, serverCert, tls.NoClientCert, pool)
	defer mtlsSrv.Close()
	defer enrollSrv.Close()

	// InsecureSkipVerify: the CA's own certificate (reused as the server's
	// TLS identity per ca.TLSCertificate()'s doc comment) carries no SANs,
	// so standard hostname verification against "127.0.0.1" always fails
	// regardless of ClientAuth mode -- that's a separate, orthogonal gap
	// (see this task's report) from what this test verifies: ClientAuth
	// enforcement. No client certificate is presented either way.
	clientCfg := &tls.Config{RootCAs: pool, InsecureSkipVerify: true}

	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp", enrollSrv.Listener.Addr().String(), clientCfg)
	if err != nil {
		t.Errorf("enrollment listener rejected a no-client-cert handshake (this is the exact circular-dependency bug the 3-listener design fixes): %v", err)
	} else {
		conn.Close()
	}

	// The mTLS listener must reject this same bare handshake. Note: with
	// TLS 1.3, tls.DialWithDialer's Handshake() can return success from the
	// CLIENT's point of view even when RequireAndVerifyClientCert will
	// reject the connection -- the client's own handshake state completes
	// once it has sent its (empty) Certificate/Finished and processed the
	// server's earlier Finished, before it has seen the server's fatal
	// alert rejecting that empty certificate. A real HTTP client (e.g. the
	// curl smoke check in this task's brief) only observes the rejection on
	// its first read/write, so this test does the same round-trip rather
	// than trusting Dial's return value alone.
	conn2, err := tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp", mtlsSrv.Listener.Addr().String(), clientCfg)
	if err != nil {
		return // rejected during the handshake itself -- expected
	}
	defer conn2.Close()
	conn2.SetDeadline(time.Now().Add(2 * time.Second))
	if _, werr := conn2.Write([]byte("GET / HTTP/1.0\r\n\r\n")); werr != nil {
		return // rejected on write -- expected
	}
	buf := make([]byte, 1)
	if _, rerr := conn2.Read(buf); rerr != nil {
		return // rejected on read -- expected
	}
	t.Error("mTLS listener accepted a no-client-cert handshake — RequireAndVerifyClientCert is not being enforced")
}

// newTLSListenerForTest starts a real TLS listener on 127.0.0.1 with the
// given ClientAuth mode, mirroring the tls.Config shape Task 7's real
// main.go wiring builds for the 9443/9444 servers.
func newTLSListenerForTest(t *testing.T, serverCert tls.Certificate, clientAuth tls.ClientAuthType, clientCAs *x509.CertPool) *httptestServer {
	t.Helper()
	cfg := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   clientAuth,
		ClientCAs:    clientCAs,
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatalf("tls.Listen: %v", err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })}
	go srv.Serve(ln)
	return &httptestServer{Listener: ln, srv: srv}
}

type httptestServer struct {
	Listener net.Listener
	srv      *http.Server
}

func (s *httptestServer) Close() { s.srv.Close() }

// TestDashboardListener_AcceptsNoClientCert confirms the new dashboard
// listener, like the enrollment listener, completes a TLS handshake with
// NO client certificate presented -- a browser has none, and this listener
// must not require one (that's the whole reason it exists separately from
// the mTLS listener).
func TestDashboardListener_AcceptsNoClientCert(t *testing.T) {
	dir := t.TempDir()
	ca, err := pki.LoadOrGenerateCA(dir)
	if err != nil {
		t.Fatalf("LoadOrGenerateCA: %v", err)
	}
	serverCert, err := ca.TLSCertificate()
	if err != nil {
		t.Fatalf("TLSCertificate: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca.Certificate())

	dashboardSrv := newTLSListenerForTest(t, serverCert, tls.NoClientCert, pool)
	defer dashboardSrv.Close()

	clientCfg := &tls.Config{InsecureSkipVerify: true} // no SANs on the CA's own cert, see existing tests in this file
	if _, err := tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp", dashboardSrv.Listener.Addr().String(), clientCfg); err != nil {
		t.Errorf("dashboard listener rejected a no-client-cert handshake: %v", err)
	}
}

// TestResolveDashboardTLSCert_FallsBackToCAWhenNoCustomCertConfigured pins
// the Review Focus item: BAS_TLS=false (the default -- no TLS_CERT/TLS_KEY
// configured) must make the dashboard listener use the CA's own
// certificate, not fail to start or use a zero-value tls.Certificate.
func TestResolveDashboardTLSCert_FallsBackToCAWhenNoCustomCertConfigured(t *testing.T) {
	dir := t.TempDir()
	ca, err := pki.LoadOrGenerateCA(dir)
	if err != nil {
		t.Fatalf("LoadOrGenerateCA: %v", err)
	}
	fallback, err := ca.TLSCertificate()
	if err != nil {
		t.Fatalf("TLSCertificate: %v", err)
	}

	got, err := resolveDashboardTLSCert(config.Config{}, fallback) // no DashboardTLSCertPath/DashboardTLSKeyPath set
	if err != nil {
		t.Fatalf("resolveDashboardTLSCert: %v", err)
	}
	if len(got.Certificate) == 0 || string(got.Certificate[0]) != string(fallback.Certificate[0]) {
		t.Error("expected the CA's own certificate to be used when no custom cert is configured")
	}
}

// TestResolveDashboardTLSCert_UsesCustomCertWhenConfigured pins the other
// half: when TLS_CERT/TLS_KEY ARE configured (BAS_TLS=true), the dashboard
// listener must use that certificate, not the CA's.
func TestResolveDashboardTLSCert_UsesCustomCertWhenConfigured(t *testing.T) {
	dir := t.TempDir()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "custom-dashboard-cert"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	certPath := filepath.Join(dir, "custom.crt")
	keyPath := filepath.Join(dir, "custom.key")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	fallback := tls.Certificate{Certificate: [][]byte{[]byte("not-the-real-fallback")}}
	cfg := config.Config{DashboardTLSCertPath: certPath, DashboardTLSKeyPath: keyPath}

	got, err := resolveDashboardTLSCert(cfg, fallback)
	if err != nil {
		t.Fatalf("resolveDashboardTLSCert: %v", err)
	}
	if string(got.Certificate[0]) == "not-the-real-fallback" {
		t.Error("expected the custom cert to be used, got the fallback")
	}
}
