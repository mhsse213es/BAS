// agent/bootstrap_test.go
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"audspect/agent/protocol"
)

func TestEnsureCertificate_SkipsBootstrapWhenValidCertExists(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("BAS_CERT_DIR", dir)

	key, err := loadOrGenerateAgentKey()
	if err != nil {
		t.Fatalf("loadOrGenerateAgentKey: %v", err)
	}
	// Seed a still-valid certificate directly, bypassing the network —
	// this pins the "already enrolled agent restarts, does NOT re-bootstrap"
	// Review Focus item.
	certPEM := selfSignedTestCertPEMWithKey(t, key, "abc123deadbeef01")
	if err := saveAgentCertificate(certPEM); err != nil {
		t.Fatalf("saveAgentCertificate: %v", err)
	}

	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))
	defer srv.Close()

	a := &Agent{cfg: Config{ServerURL: srv.URL, AgentSecret: "secret"}, id: Identity{AgentID: "abc123deadbeef01"}}
	if err := a.ensureCertificate(context.Background()); err != nil {
		t.Fatalf("ensureCertificate: %v", err)
	}
	if called {
		t.Error("ensureCertificate hit the network bootstrap endpoint despite already holding a valid certificate")
	}
}

func TestEnsureCertificate_BootstrapsWhenNoCertExists(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("BAS_CERT_DIR", dir)
	// bootstrapHTTPClient reads the deployment CA root the installer would
	// have placed alongside the bootstrap secret in production; seed it here
	// so the test's plain httptest.NewServer (no real TLS handshake occurs,
	// so its content is never actually validated against) still lets
	// bootstrapHTTPClient construct successfully.
	writeTestDeploymentCA(t, dir)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req protocol.CSRRequest
		json.NewDecoder(r.Body).Decode(&req)
		json.NewEncoder(w).Encode(protocol.CSRResponse{
			CertPEM:   string(selfSignedTestCertPEMForRequestedID(t, req.AgentID)),
			CAPEM:     "ca-pem-placeholder",
			ExpiresAt: "2027-01-01T00:00:00Z",
		})
	}))
	defer srv.Close()
	// enrollmentURL rewrites the configured server URL's port to
	// BAS_ENROLL_PORT (9444 by default, where the orchestrator's real
	// enrollment listener lives); point it at this test server's actual
	// (randomly assigned) port instead, since the mock handler above serves
	// every path including /api/agents/enroll-csr on the one port srv.URL
	// carries.
	t.Setenv("BAS_ENROLL_PORT", srv.URL[strings.LastIndex(srv.URL, ":")+1:])

	a := &Agent{cfg: Config{ServerURL: srv.URL, AgentSecret: "secret"}, id: Identity{AgentID: "abc123deadbeef01"}}
	if err := a.ensureCertificate(context.Background()); err != nil {
		t.Fatalf("ensureCertificate: %v", err)
	}
	cert, err := loadAgentCertificate()
	if err != nil {
		t.Fatalf("loadAgentCertificate after bootstrap: %v", err)
	}
	if cert.Subject.CommonName != "abc123deadbeef01" {
		t.Errorf("persisted cert CommonName = %q, want abc123deadbeef01", cert.Subject.CommonName)
	}
}

// selfSignedTestCertPEMWithKey builds a throwaway self-signed certificate
// for an EXISTING key -- used wherever a test needs the certificate to
// correspond to a specific already-generated agent key (so
// tls.LoadX509KeyPair-style pairing works in Task 11's tests).
func selfSignedTestCertPEMWithKey(t *testing.T, key *ecdsa.PrivateKey, commonName string) []byte {
	t.Helper()
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("generate serial: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create self-signed test cert: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// writeTestDeploymentCA writes a throwaway self-signed CA certificate PEM to
// dir/deployment-ca.pem, standing in for the deployment CA root the real
// installer places there. bootstrapHTTPClient needs a well-formed PEM file
// at that path to construct its client at all, independent of whether any
// real TLS handshake against it occurs in a given test.
func writeTestDeploymentCA(t *testing.T, dir string) {
	t.Helper()
	ca := newTestCA(t)
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.cert.Raw})
	if err := os.WriteFile(filepath.Join(dir, "deployment-ca.pem"), caPEM, 0644); err != nil {
		t.Fatalf("write test deployment CA: %v", err)
	}
}

// selfSignedTestCertPEMForRequestedID generates a FRESH key and a
// self-signed cert for commonName -- used by the fake-server side of a
// bootstrap test (the mock orchestrator handler), which has no reason to
// share the agent-under-test's own key.
func selfSignedTestCertPEMForRequestedID(t *testing.T, commonName string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return selfSignedTestCertPEMWithKey(t, key, commonName)
}

// --- verifyServerCertChain tests ---

// testCA holds a self-signed CA cert (DER + parsed) plus its key, used to
// mint leaf certs signed by that CA for verifyServerCertChain tests.
type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newTestCA(t *testing.T) testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("generate CA serial: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "test deployment CA"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create test CA cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse test CA cert: %v", err)
	}
	return testCA{cert: cert, key: key}
}

// leafSignedBy mints a leaf certificate for commonName (deliberately NOT a
// real hostname), signed by ca, with no SAN entries — mirroring the
// orchestrator's actual server TLS identity (Task 7), which reuses the
// deployment CA's own self-signed certificate directly as the server leaf.
func leafSignedBy(t *testing.T, ca testCA, commonName string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
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
		t.Fatalf("create leaf cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse leaf cert: %v", err)
	}
	return cert
}

func TestVerifyServerCertChain_AcceptsTrustedCARegardlessOfCommonName(t *testing.T) {
	ca := newTestCA(t)
	leaf := leafSignedBy(t, ca, "not-a-real-hostname")

	pool := x509.NewCertPool()
	pool.AddCert(ca.cert)

	verify := verifyServerCertChain(pool)
	if err := verify([][]byte{leaf.Raw}, nil); err != nil {
		t.Errorf("expected chain-to-trusted-CA cert to be accepted despite mismatched CommonName, got error: %v", err)
	}
}

func TestVerifyServerCertChain_RejectsUntrustedCA(t *testing.T) {
	trustedCA := newTestCA(t)
	untrustedCA := newTestCA(t)
	leaf := leafSignedBy(t, untrustedCA, "not-a-real-hostname")

	pool := x509.NewCertPool()
	pool.AddCert(trustedCA.cert)

	verify := verifyServerCertChain(pool)
	if err := verify([][]byte{leaf.Raw}, nil); err == nil {
		t.Error("expected cert signed by an untrusted CA to be rejected, but verification succeeded")
	}
}
