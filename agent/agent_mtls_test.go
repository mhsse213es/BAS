// agent/agent_mtls_test.go
package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestMTLSTLSConfig_NilWhenNoCARootInstalled(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("BAS_CERT_DIR", dir)

	cfg, err := mtlsTLSConfig(Config{})
	if err != nil {
		t.Fatalf("mtlsTLSConfig: %v", err)
	}
	if cfg != nil {
		t.Error("expected a nil *tls.Config when no deployment CA root is installed (legacy fallback path)")
	}
}

// Finding 2 regression: a *tls.Config built BEFORE any certificate exists
// (as a client built early in startup would be) must present a certificate
// written to disk afterwards -- and a later renewal -- without being
// rebuilt.
func TestMTLSTLSConfig_PicksUpCertificateWrittenAfterConstruction(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("BAS_CERT_DIR", dir)
	ca := newTestCA(t)
	if err := writeCARootFile(t, dir, ca.cert.Raw); err != nil {
		t.Fatalf("writeCARootFile: %v", err)
	}

	cfg, err := mtlsTLSConfig(Config{})
	if err != nil || cfg == nil {
		t.Fatalf("mtlsTLSConfig before bootstrap = %v, %v; want a usable config", cfg, err)
	}
	if cfg.GetClientCertificate == nil {
		t.Fatal("client certificate must be supplied via GetClientCertificate, not a static Certificates slice")
	}
	if len(cfg.Certificates) != 0 {
		t.Error("static Certificates would go stale after bootstrap/renewal")
	}
	if _, err := cfg.GetClientCertificate(&tls.CertificateRequestInfo{}); err == nil {
		t.Error("expected an error from GetClientCertificate before any certificate exists")
	}

	// A real HTTP client built from this one config, before bootstrap.
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(r.TLS.PeerCertificates[0].SerialNumber.Text(16)))
	}))
	pool := x509.NewCertPool()
	pool.AddCert(ca.cert)
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{ca.cert.Raw}, PrivateKey: ca.key}},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
	}
	srv.StartTLS()
	defer srv.Close()
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: cfg, DisableKeepAlives: true}}

	if resp, err := client.Get(srv.URL); err == nil {
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			t.Fatal("handshake succeeded with no client certificate on disk")
		}
	}

	// "Bootstrap": key + certificate appear on disk.
	key, err := loadOrGenerateAgentKey()
	if err != nil {
		t.Fatalf("loadOrGenerateAgentKey: %v", err)
	}
	first := leafCertPEMForKeyPublic(t, ca, "abc123deadbeef01", key)
	if err := saveAgentCertificate(first); err != nil {
		t.Fatalf("saveAgentCertificate: %v", err)
	}
	if got := getSerial(t, client, srv.URL); got != serialOfPEM(t, first) {
		t.Errorf("after bootstrap: server saw serial %s, want %s", got, serialOfPEM(t, first))
	}

	// "Renewal": a new certificate replaces the old one on disk.
	second := leafCertPEMForKeyPublic(t, ca, "abc123deadbeef01", key)
	if err := saveAgentCertificate(second); err != nil {
		t.Fatalf("saveAgentCertificate (renewal): %v", err)
	}
	if got := getSerial(t, client, srv.URL); got != serialOfPEM(t, second) {
		t.Errorf("after renewal: server saw serial %s, want the renewed %s", got, serialOfPEM(t, second))
	}
}

func getSerial(t *testing.T, client *http.Client, u string) string {
	t.Helper()
	resp, err := client.Get(u)
	if err != nil {
		t.Fatalf("GET over mTLS: %v", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return string(b)
}

func serialOfPEM(t *testing.T, certPEM []byte) string {
	t.Helper()
	block, _ := pem.Decode(certPEM)
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return c.SerialNumber.Text(16)
}

func TestAgentTLSConfig_OnlyWhenMTLSResolved(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("BAS_CERT_DIR", dir)
	ca := newTestCA(t)
	if err := writeCARootFile(t, dir, ca.cert.Raw); err != nil {
		t.Fatalf("writeCARootFile: %v", err)
	}
	if agentTLSConfig(Config{ServerURL: "http://h:9000"}) != nil {
		t.Error("legacy (MTLS=false) config must keep the default TLS config")
	}
	if c := agentTLSConfig(Config{ServerURL: "https://h:9443", MTLS: true}); c == nil || c.GetClientCertificate == nil {
		t.Error("MTLS=true config must attach the mTLS TLS config")
	}
}

func TestMTLSTLSConfig_PopulatedWhenCertificateExists(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("BAS_CERT_DIR", dir)

	key, err := loadOrGenerateAgentKey()
	if err != nil {
		t.Fatalf("loadOrGenerateAgentKey: %v", err)
	}

	// Real CA-signed setup: a genuine self-signed CA (newTestCA, from
	// agent/bootstrap_test.go's Task 10 helpers, visible here since both
	// files are in package main) signs a leaf certificate bound to this
	// test's actual agent key via a real x509.CreateCertificate call, so
	// mtlsTLSConfig's VerifyPeerCertificate (verifyServerCertChain) has a
	// real chain to verify -- not the brief's "reuse the same self-signed
	// cert as a stand-in CA" shortcut, which would never exercise the
	// chain-verification path meaningfully.
	ca := newTestCA(t)
	leafPEM := leafCertPEMForKeyPublic(t, ca, "abc123deadbeef01", key)
	if err := saveAgentCertificate(leafPEM); err != nil {
		t.Fatalf("saveAgentCertificate: %v", err)
	}
	if err := writeCARootFile(t, dir, ca.cert.Raw); err != nil {
		t.Fatalf("writeCARootFile: %v", err)
	}

	cfg, err := mtlsTLSConfig(Config{})
	if err != nil {
		t.Fatalf("mtlsTLSConfig: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected a populated *tls.Config when a local certificate exists")
	}
	cc, err := cfg.GetClientCertificate(&tls.CertificateRequestInfo{})
	if err != nil || cc == nil || len(cc.Certificate) != 1 {
		t.Errorf("GetClientCertificate = %v, %v; want the persisted certificate", cc, err)
	}
	if cfg.VerifyPeerCertificate == nil {
		t.Error("expected VerifyPeerCertificate to be set (paired with InsecureSkipVerify)")
	}
	if !cfg.InsecureSkipVerify {
		t.Error("expected InsecureSkipVerify true, backed by VerifyPeerCertificate's real chain check")
	}

	// Confirm VerifyPeerCertificate actually performs real chain
	// verification against the CA root we wrote above: a leaf signed by
	// that CA is accepted, and a leaf signed by a different, untrusted CA
	// is rejected.
	otherCA := newTestCA(t)
	untrustedLeaf := leafSignedBy(t, otherCA, "server-identity")
	if err := cfg.VerifyPeerCertificate([][]byte{untrustedLeaf.Raw}, nil); err == nil {
		t.Error("expected VerifyPeerCertificate to reject a leaf signed by an untrusted CA")
	}

	trustedLeaf := leafSignedBy(t, ca, "server-identity")
	if err := cfg.VerifyPeerCertificate([][]byte{trustedLeaf.Raw}, nil); err != nil {
		t.Errorf("expected VerifyPeerCertificate to accept a leaf signed by the trusted CA, got: %v", err)
	}
}

// leafCertPEMForKeyPublic mints a PEM-encoded leaf certificate for
// commonName, signed by ca, bound to key's already-generated private key --
// unlike leafSignedBy (agent/bootstrap_test.go), which always generates a
// fresh key of its own. This is needed here because mtlsTLSConfig calls
// tls.LoadX509KeyPair(certPath, keyPath), which requires the persisted
// certificate's public key to actually match the persisted private key on
// disk (written by loadOrGenerateAgentKey).
func leafCertPEMForKeyPublic(t *testing.T, ca testCA, commonName string, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("generate leaf serial: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatalf("create leaf cert bound to test agent key: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// writeCARootFile places der (as PEM-encoded CERTIFICATE) at the canonical
// CA-root path within dir, standing in for what a real installer places
// there before first run (Task 13).
func writeCARootFile(t *testing.T, dir string, der []byte) error {
	t.Helper()
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return os.WriteFile(filepath.Join(dir, "deployment-ca.pem"), pemBytes, 0644)
}
