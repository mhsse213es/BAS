// agent/bootstrap_test.go
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"audspect/agent/protocol"
)

// --- fixtures shared by the ensureCertificate tests ---

// seedDeploymentCA writes ca's certificate as the installed deployment CA
// root (what --ca-root places in production).
func seedDeploymentCA(t *testing.T, dir string, ca testCA) {
	t.Helper()
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.cert.Raw})
	if err := os.WriteFile(filepath.Join(dir, "deployment-ca.pem"), caPEM, 0644); err != nil {
		t.Fatalf("write deployment CA: %v", err)
	}
}

// caSignedCertPEM mints a certificate for pub, signed by ca, with the given
// lifetime offsets from now -- what the orchestrator's CA issues.
func caSignedCertPEM(t *testing.T, ca testCA, pub *ecdsa.PublicKey, cn string, notBeforeOffset, notAfterOffset time.Duration) []byte {
	t.Helper()
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("serial: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(notBeforeOffset),
		NotAfter:     time.Now().Add(notAfterOffset),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, pub, ca.key)
	if err != nil {
		t.Fatalf("sign cert: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// issueFromCSR is the mock orchestrator's signing step: it signs the CSR's
// OWN public key (as pki.IssueClientCertificate does), so the result pairs
// with the agent's persisted private key.
func issueFromCSR(t *testing.T, ca testCA, csrPEM, cn string) []byte {
	t.Helper()
	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil {
		t.Errorf("mock server: CSR is not PEM")
		return nil
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil || csr.CheckSignature() != nil {
		t.Errorf("mock server: bad CSR: %v", err)
		return nil
	}
	return caSignedCertPEM(t, ca, csr.PublicKey.(*ecdsa.PublicKey), cn, -time.Minute, 365*24*time.Hour)
}

// csrRecord captures what a mock orchestrator endpoint saw.
type csrRecord struct {
	mu            sync.Mutex
	calls         int
	token         string
	clientCertCN  string
	hadClientCert bool
}

// newMockOrchestrator serves POST /api/agents/enroll-csr over real TLS with
// the production server identity shape (the deployment CA's own
// certificate, see Task 7) and the given client-auth mode. status != 200
// makes it fail every request with that status.
func newMockOrchestrator(t *testing.T, ca testCA, clientAuth tls.ClientAuthType, status int, rec *csrRecord) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/agents/enroll-csr" {
			http.NotFound(w, r)
			return
		}
		var req protocol.CSRRequest
		json.NewDecoder(r.Body).Decode(&req)
		rec.mu.Lock()
		rec.calls++
		rec.token = r.Header.Get("X-Agent-Token")
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			rec.hadClientCert = true
			rec.clientCertCN = r.TLS.PeerCertificates[0].Subject.CommonName
		}
		rec.mu.Unlock()
		if status != http.StatusOK {
			w.WriteHeader(status)
			return
		}
		json.NewEncoder(w).Encode(protocol.CSRResponse{
			CertPEM:   string(issueFromCSR(t, ca, req.CSRPEM, req.AgentID)),
			ExpiresAt: time.Now().Add(365 * 24 * time.Hour).Format(time.RFC3339),
		})
	}))
	pool := x509.NewCertPool()
	pool.AddCert(ca.cert)
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{ca.cert.Raw}, PrivateKey: ca.key}},
		ClientAuth:   clientAuth,
		ClientCAs:    pool,
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

// newMockOrchestratorWithSigningTrust mirrors newMockOrchestrator but also
// returns a non-empty commandSigningTrust.certPem -- protocol.CSRResponse's
// CommandSigningTrust field is of an unexported type, so callers outside
// the protocol package can't construct one directly; encoding the response
// as a plain map (matching CSRResponse's own JSON tags) sidesteps that
// without needing an exported constructor solely for this test.
func newMockOrchestratorWithSigningTrust(t *testing.T, ca testCA, signingCertPEM string, rec *csrRecord) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/agents/enroll-csr" {
			http.NotFound(w, r)
			return
		}
		var req protocol.CSRRequest
		json.NewDecoder(r.Body).Decode(&req)
		rec.mu.Lock()
		rec.calls++
		rec.token = r.Header.Get("X-Agent-Token")
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			rec.hadClientCert = true
			rec.clientCertCN = r.TLS.PeerCertificates[0].Subject.CommonName
		}
		rec.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"certPem":   string(issueFromCSR(t, ca, req.CSRPEM, req.AgentID)),
			"expiresAt": time.Now().Add(365 * 24 * time.Hour).Format(time.RFC3339),
			"commandSigningTrust": map[string]string{
				"keyId":   "test-key-id",
				"certPem": signingCertPEM,
			},
		})
	}))
	pool := x509.NewCertPool()
	pool.AddCert(ca.cert)
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{ca.cert.Raw}, PrivateKey: ca.key}},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

func portOf(t *testing.T, rawURL string) string {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse %s: %v", rawURL, err)
	}
	return u.Port()
}

// unusedPort returns a port nothing listens on (bound then released), so a
// request that wrongly goes there fails fast with connection refused.
func unusedPort(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(http.NotFoundHandler())
	p := portOf(t, srv.URL)
	srv.Close()
	return p
}

func mustLoadCert(t *testing.T) *x509.Certificate {
	t.Helper()
	c, err := loadAgentCertificate()
	if err != nil {
		t.Fatalf("loadAgentCertificate: %v", err)
	}
	return c
}

// --- ensureCertificate ---

func TestEnsureCertificate_SkipsBootstrapWhenValidCertExists(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("BAS_CERT_DIR", dir)
	t.Setenv("BAS_MTLS_PORT", "")
	ca := newTestCA(t)
	seedDeploymentCA(t, dir, ca)
	key, err := loadOrGenerateAgentKey()
	if err != nil {
		t.Fatalf("loadOrGenerateAgentKey: %v", err)
	}
	// A still-valid certificate, seeded directly -- pins the "already
	// enrolled agent restarts, does NOT re-bootstrap" Review Focus item.
	if err := saveAgentCertificate(caSignedCertPEM(t, ca, &key.PublicKey, "abc123deadbeef01", -time.Hour, 24*365*time.Hour)); err != nil {
		t.Fatalf("saveAgentCertificate: %v", err)
	}
	if err := markEnrolled(); err != nil {
		t.Fatalf("markEnrolled: %v", err)
	}
	// Already holds command-signing trust too -- otherwise the fast path
	// falls through to a renewal attempt (see the test below), which would
	// make this test's "zero network I/O" assertion pass for the wrong
	// reason (a failed DNS lookup, not a skipped renewal).
	if err := saveCommandSigningCert(selfSignedTestCertPEM(t, "test-command-signing")); err != nil {
		t.Fatalf("saveCommandSigningCert: %v", err)
	}

	rec := &csrRecord{}
	srv := newMockOrchestrator(t, ca, tls.NoClientCert, http.StatusOK, rec)
	t.Setenv("BAS_ENROLL_PORT", portOf(t, srv.URL))

	opURL, err := ensureCertificate(context.Background(), Config{ServerURL: "http://orchestrator.local:9000", AgentSecret: "secret"}, "abc123deadbeef01")
	if err != nil {
		t.Fatalf("ensureCertificate: %v", err)
	}
	if rec.calls != 0 {
		t.Error("ensureCertificate hit the network despite already holding a valid certificate")
	}
	if opURL != "https://orchestrator.local:9443" {
		t.Errorf("operational URL = %q, want https://orchestrator.local:9443", opURL)
	}
}

// A valid, non-expiring-soon mTLS certificate normally means zero network
// I/O (the test above). But an agent missing its command-signing trust
// material -- enrolled before B4 shipped, or with a lost/reset
// command-signing.pem -- must not stay stuck on that fast path until its
// certificate's own renewal threshold, up to ~9 months away; it renews
// early, over mTLS, specifically to obtain the missing trust material.
func TestEnsureCertificate_MissingCommandSigningCertTriggersRenewalDespiteValidMTLSCert(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("BAS_CERT_DIR", dir)
	ca := newTestCA(t)
	seedDeploymentCA(t, dir, ca)
	key, err := loadOrGenerateAgentKey()
	if err != nil {
		t.Fatalf("loadOrGenerateAgentKey: %v", err)
	}
	// Not expiring soon -- would take the zero-network fast path if it
	// weren't for the missing command-signing certificate.
	if err := saveAgentCertificate(caSignedCertPEM(t, ca, &key.PublicKey, "abc123deadbeef01", -time.Hour, 24*365*time.Hour)); err != nil {
		t.Fatalf("saveAgentCertificate: %v", err)
	}
	if err := markEnrolled(); err != nil {
		t.Fatalf("markEnrolled: %v", err)
	}
	if _, err := loadCommandSigningCert(); err == nil {
		t.Fatal("test setup: command-signing cert unexpectedly already present")
	}

	signingCertPEM := selfSignedTestCertPEM(t, "test-command-signing")
	rec := &csrRecord{}
	srv := newMockOrchestratorWithSigningTrust(t, ca, string(signingCertPEM), rec)
	t.Setenv("BAS_MTLS_PORT", portOf(t, srv.URL))
	t.Setenv("BAS_ENROLL_PORT", unusedPort(t)) // must renew over mTLS, never re-bootstrap

	opURL, err := ensureCertificate(context.Background(), Config{ServerURL: "http://127.0.0.1:9000", AgentSecret: "secret"}, "abc123deadbeef01")
	if err != nil {
		t.Fatalf("ensureCertificate: %v", err)
	}
	if rec.calls != 1 {
		t.Fatalf("mTLS endpoint calls = %d, want 1 (missing signing cert must force a renewal call)", rec.calls)
	}
	if !rec.hadClientCert || rec.clientCertCN != "abc123deadbeef01" {
		t.Error("renewal request did not present the agent's existing client certificate")
	}
	if rec.token != "" {
		t.Error("request sent the bootstrap secret -- a valid enrolled identity must authenticate via mTLS only")
	}
	if _, err := loadCommandSigningCert(); err != nil {
		t.Fatalf("loadCommandSigningCert after ensureCertificate: %v", err)
	}
	if opURL != "https://127.0.0.1:"+portOf(t, srv.URL) {
		t.Errorf("operational URL = %q", opURL)
	}
}

// Fresh install configured with a LEGACY plaintext URL: bootstrap must go
// to https:// on the enrollment port (not plaintext to the configured
// port), and the returned operational URL must be the https mTLS URL.
func TestEnsureCertificate_BootstrapsFromLegacyHTTPConfigOverHTTPS(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("BAS_CERT_DIR", dir)
	ca := newTestCA(t)
	seedDeploymentCA(t, dir, ca)

	rec := &csrRecord{}
	srv := newMockOrchestrator(t, ca, tls.NoClientCert, http.StatusOK, rec)
	t.Setenv("BAS_ENROLL_PORT", portOf(t, srv.URL))
	t.Setenv("BAS_MTLS_PORT", "19443")

	opURL, err := ensureCertificate(context.Background(), Config{ServerURL: "http://127.0.0.1:9000", AgentSecret: "secret"}, "abc123deadbeef01")
	if err != nil {
		t.Fatalf("ensureCertificate: %v", err)
	}
	if rec.calls != 1 {
		t.Fatalf("enrollment endpoint calls = %d, want 1", rec.calls)
	}
	if rec.token != "secret" {
		t.Errorf("bootstrap X-Agent-Token = %q, want the bootstrap secret", rec.token)
	}
	if rec.hadClientCert {
		t.Error("bootstrap presented a client certificate; the agent has none yet")
	}
	if cn := mustLoadCert(t).Subject.CommonName; cn != "abc123deadbeef01" {
		t.Errorf("persisted cert CommonName = %q, want abc123deadbeef01", cn)
	}
	if opURL != "https://127.0.0.1:19443" {
		t.Errorf("operational URL = %q, want https://127.0.0.1:19443 (not the configured http://127.0.0.1:9000)", opURL)
	}
	if !isEnrolled() {
		t.Error("expected isEnrolled to be true after a successful first-time bootstrap")
	}
}

func TestEnsureCertificate_RenewsExpiringCertViaMTLSNotBootstrapSecret(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("BAS_CERT_DIR", dir)
	ca := newTestCA(t)
	seedDeploymentCA(t, dir, ca)
	key, err := loadOrGenerateAgentKey()
	if err != nil {
		t.Fatalf("loadOrGenerateAgentKey: %v", err)
	}
	// ~82% elapsed: past the 75% renewal threshold, still valid.
	if err := saveAgentCertificate(caSignedCertPEM(t, ca, &key.PublicKey, "abc123deadbeef01", -300*24*time.Hour, 65*24*time.Hour)); err != nil {
		t.Fatalf("saveAgentCertificate: %v", err)
	}
	if err := markEnrolled(); err != nil {
		t.Fatalf("markEnrolled: %v", err)
	}
	before := mustLoadCert(t)

	// Production-shaped mTLS listener: RequireAndVerifyClientCert against
	// the deployment CA.
	rec := &csrRecord{}
	srv := newMockOrchestrator(t, ca, tls.RequireAndVerifyClientCert, http.StatusOK, rec)
	t.Setenv("BAS_MTLS_PORT", portOf(t, srv.URL))
	t.Setenv("BAS_ENROLL_PORT", unusedPort(t)) // renewal must NOT go to the enrollment listener

	opURL, err := ensureCertificate(context.Background(), Config{ServerURL: "http://127.0.0.1:9000", AgentSecret: "secret"}, "abc123deadbeef01")
	if err != nil {
		t.Fatalf("ensureCertificate (renewal): %v", err)
	}
	if rec.calls != 1 {
		t.Fatalf("mTLS endpoint calls = %d, want 1", rec.calls)
	}
	if !rec.hadClientCert || rec.clientCertCN != "abc123deadbeef01" {
		t.Error("renewal request did not present the agent's existing client certificate")
	}
	if rec.token != "" {
		t.Error("renewal request sent the bootstrap secret — must authenticate via mTLS only, per spec Section 2")
	}
	after := mustLoadCert(t)
	if after.SerialNumber.Cmp(before.SerialNumber) == 0 {
		t.Error("renewed certificate was not persisted")
	}
	if opURL != "https://127.0.0.1:"+portOf(t, srv.URL) {
		t.Errorf("operational URL = %q", opURL)
	}
}

// An EXPIRED certificate cannot authenticate an mTLS renewal. Per the
// locked security invariant, an already-enrolled identity must NOT fall
// back to a fresh bootstrap via the shared secret in this case -- that
// would be exactly the "legacy transport as a recovery mechanism for an
// enrolled identity" the design explicitly prohibits. It halts instead
// (errBlocked), with zero calls to the bootstrap endpoint.
func TestEnsureCertificate_EnrolledExpiredCertHaltsWithoutRebootstrapping(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("BAS_CERT_DIR", dir)
	ca := newTestCA(t)
	seedDeploymentCA(t, dir, ca)
	key, err := loadOrGenerateAgentKey()
	if err != nil {
		t.Fatalf("loadOrGenerateAgentKey: %v", err)
	}
	if err := saveAgentCertificate(caSignedCertPEM(t, ca, &key.PublicKey, "abc123deadbeef01", -400*24*time.Hour, -time.Hour)); err != nil {
		t.Fatalf("saveAgentCertificate: %v", err)
	}
	if err := markEnrolled(); err != nil {
		t.Fatalf("markEnrolled: %v", err)
	}

	rec := &csrRecord{}
	srv := newMockOrchestrator(t, ca, tls.NoClientCert, http.StatusOK, rec)
	t.Setenv("BAS_ENROLL_PORT", portOf(t, srv.URL))
	t.Setenv("BAS_MTLS_PORT", unusedPort(t)) // a renewal attempt would fail here

	_, err = ensureCertificate(context.Background(), Config{ServerURL: "https://127.0.0.1:9443", AgentSecret: "secret"}, "abc123deadbeef01")
	var blocked *errBlocked
	if !errors.As(err, &blocked) {
		t.Fatalf("ensureCertificate error = %v, want an *errBlocked", err)
	}
	if rec.calls != 0 {
		t.Errorf("expected zero bootstrap calls for an enrolled identity's expired certificate, got %d", rec.calls)
	}
	if c := mustLoadCert(t); time.Now().Before(c.NotAfter) {
		t.Error("expected the still-expired certificate to remain untouched on disk")
	}
}

// TestEnsureCertificate_NeverEnrolledIgnoresStrayCertFile locks in the
// "not inferred from cert-file existence" invariant: a stray/partial
// certificate file left on disk for a never-enrolled identity (no
// enrollment marker) must be ignored entirely -- bootstrap runs via the
// shared secret exactly as if no file were present.
func TestEnsureCertificate_NeverEnrolledIgnoresStrayCertFile(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("BAS_CERT_DIR", dir)
	ca := newTestCA(t)
	seedDeploymentCA(t, dir, ca)
	key, err := loadOrGenerateAgentKey()
	if err != nil {
		t.Fatalf("loadOrGenerateAgentKey: %v", err)
	}
	// A valid, unexpired stray certificate -- but markEnrolled was never
	// called, so isEnrolled() is false.
	if err := saveAgentCertificate(caSignedCertPEM(t, ca, &key.PublicKey, "abc123deadbeef01", -time.Hour, 24*365*time.Hour)); err != nil {
		t.Fatalf("saveAgentCertificate: %v", err)
	}

	rec := &csrRecord{}
	srv := newMockOrchestrator(t, ca, tls.NoClientCert, http.StatusOK, rec)
	t.Setenv("BAS_ENROLL_PORT", portOf(t, srv.URL))

	if _, err := ensureCertificate(context.Background(), Config{ServerURL: "http://127.0.0.1:9000", AgentSecret: "secret"}, "abc123deadbeef01"); err != nil {
		t.Fatalf("ensureCertificate: %v", err)
	}
	if rec.calls != 1 || rec.token != "secret" {
		t.Errorf("expected one bootstrap call with the bootstrap secret despite the stray cert file, got calls=%d token=%q", rec.calls, rec.token)
	}
}

// A failed renewal leaves the still-valid certificate in place and keeps
// the agent on the mTLS endpoint rather than downgrading it to legacy.
func TestEnsureCertificate_RenewalFailureKeepsCurrentCertAndMTLSURL(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("BAS_CERT_DIR", dir)
	ca := newTestCA(t)
	seedDeploymentCA(t, dir, ca)
	key, _ := loadOrGenerateAgentKey()
	if err := saveAgentCertificate(caSignedCertPEM(t, ca, &key.PublicKey, "abc123deadbeef01", -300*24*time.Hour, 65*24*time.Hour)); err != nil {
		t.Fatalf("saveAgentCertificate: %v", err)
	}
	if err := markEnrolled(); err != nil {
		t.Fatalf("markEnrolled: %v", err)
	}
	before := mustLoadCert(t)

	rec := &csrRecord{}
	srv := newMockOrchestrator(t, ca, tls.RequireAndVerifyClientCert, http.StatusInternalServerError, rec)
	t.Setenv("BAS_MTLS_PORT", portOf(t, srv.URL))

	opURL, err := ensureCertificate(context.Background(), Config{ServerURL: "https://127.0.0.1:9443", AgentSecret: "secret"}, "abc123deadbeef01")
	if err != nil {
		t.Fatalf("renewal failure must not be fatal while the current cert is valid: %v", err)
	}
	if opURL != "https://127.0.0.1:"+portOf(t, srv.URL) {
		t.Errorf("operational URL = %q", opURL)
	}
	if mustLoadCert(t).SerialNumber.Cmp(before.SerialNumber) != 0 {
		t.Error("current certificate was replaced despite the failed renewal")
	}
}

// A certificate that does not match the agent's own key is refused rather
// than persisted.
func TestEnsureCertificate_RejectsIssuedCertForDifferentKey(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("BAS_CERT_DIR", dir)
	ca := newTestCA(t)
	seedDeploymentCA(t, dir, ca)

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		otherKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		json.NewEncoder(w).Encode(protocol.CSRResponse{
			CertPEM:   string(caSignedCertPEM(t, ca, &otherKey.PublicKey, "abc123deadbeef01", -time.Minute, time.Hour)),
			ExpiresAt: time.Now().Add(time.Hour).Format(time.RFC3339),
		})
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{ca.cert.Raw}, PrivateKey: ca.key}}}
	srv.StartTLS()
	defer srv.Close()
	t.Setenv("BAS_ENROLL_PORT", portOf(t, srv.URL))

	if _, err := ensureCertificate(context.Background(), Config{ServerURL: "http://127.0.0.1:9000", AgentSecret: "secret"}, "abc123deadbeef01"); err == nil {
		t.Fatal("expected an error for an issued certificate that does not match the agent key")
	}
	if _, err := loadAgentCertificate(); err == nil {
		t.Error("a certificate for a different key was persisted")
	}
}

// --- resolveOperationalConfig: the Config main.go builds every client from ---

func TestResolveOperationalConfig_UsesMTLSURLAfterBootstrap(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("BAS_CERT_DIR", dir)
	ca := newTestCA(t)
	seedDeploymentCA(t, dir, ca)
	rec := &csrRecord{}
	srv := newMockOrchestrator(t, ca, tls.NoClientCert, http.StatusOK, rec)
	t.Setenv("BAS_ENROLL_PORT", portOf(t, srv.URL))
	t.Setenv("BAS_MTLS_PORT", "")

	configured := Config{ServerURL: "http://127.0.0.1:9000", AgentSecret: "secret"}
	got, outcome := resolveOperationalConfig(context.Background(), configured, "abc123deadbeef01")
	if outcome != outcomeMTLSReady {
		t.Fatalf("outcome = %v, want outcomeMTLSReady", outcome)
	}
	if got.ServerURL != "https://127.0.0.1:9443" {
		t.Errorf("ServerURL = %q, want https://127.0.0.1:9443 (not the configured %s)", got.ServerURL, configured.ServerURL)
	}
	if !got.MTLS {
		t.Error("MTLS flag not set after a successful bootstrap")
	}
	if got.AgentSecret != "secret" {
		t.Error("other Config fields must be preserved")
	}
	if !isEnrolled() {
		t.Error("expected isEnrolled to be true after a successful first-time bootstrap")
	}
}

// TestResolveOperationalConfig_NeverEnrolledBootstrapFailureIsLegacyPending
// covers the never-enrolled row of the locked state table: bootstrap
// failing for an identity with no prior enrollment must report
// outcomeLegacyPending (operate on legacy now, retry in the background),
// never outcomeBlocked (which is reserved for an already-enrolled identity).
func TestResolveOperationalConfig_NeverEnrolledBootstrapFailureIsLegacyPending(t *testing.T) {
	t.Setenv("BAS_CERT_DIR", t.TempDir()) // no CA root installed -> bootstrap cannot run
	configured := Config{ServerURL: "http://orchestrator.local:9000", AgentSecret: "secret"}
	got, outcome := resolveOperationalConfig(context.Background(), configured, "abc123deadbeef01")
	if outcome != outcomeLegacyPending {
		t.Fatalf("outcome = %v, want outcomeLegacyPending", outcome)
	}
	if got != configured {
		t.Errorf("config changed on bootstrap failure: %+v", got)
	}
}

// TestResolveOperationalConfig_EnrolledCheckMTLSUsableFailureIsBlocked covers
// the "Enrolled + valid cert, checkMTLSUsable fails" row: must report
// outcomeBlocked, never outcomeLegacyPending -- an already-enrolled identity
// never falls back to legacy transport.
func TestResolveOperationalConfig_EnrolledCheckMTLSUsableFailureIsBlocked(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("BAS_CERT_DIR", dir)
	ca := newTestCA(t)
	seedDeploymentCA(t, dir, ca)
	key, err := loadOrGenerateAgentKey()
	if err != nil {
		t.Fatalf("loadOrGenerateAgentKey: %v", err)
	}
	if err := saveAgentCertificate(caSignedCertPEM(t, ca, &key.PublicKey, "abc123deadbeef01", -time.Hour, 24*365*time.Hour)); err != nil {
		t.Fatalf("saveAgentCertificate: %v", err)
	}
	if err := markEnrolled(); err != nil {
		t.Fatalf("markEnrolled: %v", err)
	}
	// Remove the CA root after enrolling -- checkMTLSUsable's mtlsTLSConfig
	// call will fail to find it.
	if err := os.Remove(filepath.Join(dir, "deployment-ca.pem")); err != nil {
		t.Fatalf("remove deployment CA: %v", err)
	}

	configured := Config{ServerURL: "http://orchestrator.local:9000", AgentSecret: "secret"}
	got, outcome := resolveOperationalConfig(context.Background(), configured, "abc123deadbeef01")
	if outcome != outcomeBlocked {
		t.Fatalf("outcome = %v, want outcomeBlocked", outcome)
	}
	if got != configured {
		t.Errorf("config changed while blocked: %+v", got)
	}
}

// TestResolveOperationalConfig_EnrolledExpiredCertIsBlocked covers the
// "Enrolled + cert expired" row: must halt (outcomeBlocked), never
// re-bootstrap via the shared secret.
func TestResolveOperationalConfig_EnrolledExpiredCertIsBlocked(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("BAS_CERT_DIR", dir)
	ca := newTestCA(t)
	seedDeploymentCA(t, dir, ca)
	key, err := loadOrGenerateAgentKey()
	if err != nil {
		t.Fatalf("loadOrGenerateAgentKey: %v", err)
	}
	if err := saveAgentCertificate(caSignedCertPEM(t, ca, &key.PublicKey, "abc123deadbeef01", -400*24*time.Hour, -time.Hour)); err != nil {
		t.Fatalf("saveAgentCertificate: %v", err)
	}
	if err := markEnrolled(); err != nil {
		t.Fatalf("markEnrolled: %v", err)
	}

	rec := &csrRecord{}
	srv := newMockOrchestrator(t, ca, tls.NoClientCert, http.StatusOK, rec)
	t.Setenv("BAS_ENROLL_PORT", portOf(t, srv.URL))

	configured := Config{ServerURL: "http://orchestrator.local:9000", AgentSecret: "secret"}
	got, outcome := resolveOperationalConfig(context.Background(), configured, "abc123deadbeef01")
	if outcome != outcomeBlocked {
		t.Fatalf("outcome = %v, want outcomeBlocked", outcome)
	}
	if got != configured {
		t.Errorf("config changed while blocked: %+v", got)
	}
	if rec.calls != 0 {
		t.Error("an enrolled identity's expired certificate must never trigger a bootstrap-secret call")
	}
}

// --- URL derivation ---

func TestEnrollmentURL_AlwaysHTTPSOnEnrollmentPort(t *testing.T) {
	t.Setenv("BAS_ENROLL_PORT", "")
	cases := map[string]string{
		"http://orchestrator.local:9000":  "https://orchestrator.local:9444",
		"http://orchestrator.local:9443":  "https://orchestrator.local:9444",
		"https://orchestrator.local:9443": "https://orchestrator.local:9444",
		"http://orchestrator.local":       "https://orchestrator.local:9444",
		"http://10.0.0.5:9000":            "https://10.0.0.5:9444",
		"http://[::1]:9000":               "https://[::1]:9444",
		"https://[::1]:9443":              "https://[::1]:9444",
		"https://[fe80::1]":               "https://[fe80::1]:9444",
		"HTTP://Orchestrator.local:9000/": "https://Orchestrator.local:9444",
	}
	for in, want := range cases {
		got, err := enrollmentURL(in)
		if err != nil || got != want {
			t.Errorf("enrollmentURL(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	t.Setenv("BAS_ENROLL_PORT", "10444")
	if got, _ := enrollmentURL("http://[::1]:9000"); got != "https://[::1]:10444" {
		t.Errorf("BAS_ENROLL_PORT override: got %q", got)
	}
	if _, err := enrollmentURL("not a url"); err == nil {
		t.Error("expected an error for a URL with no host")
	}
}

func TestOperationalURL_AlwaysHTTPSOnMTLSPort(t *testing.T) {
	t.Setenv("BAS_MTLS_PORT", "")
	t.Setenv("BAS_ENROLL_PORT", "")
	cases := map[string]string{
		"http://orchestrator.local:9000":   "https://orchestrator.local:9443", // legacy plaintext listener
		"http://orchestrator.local:9443":   "https://orchestrator.local:9443", // pre-TLS setting, scheme fixed
		"http://orchestrator.local":        "https://orchestrator.local:9443",
		"https://orchestrator.local:9443":  "https://orchestrator.local:9443",
		"https://orchestrator.local:18443": "https://orchestrator.local:18443", // non-default mTLS port kept
		"https://orchestrator.local:9444":  "https://orchestrator.local:9443",  // enrollment port is never operational
		"https://orchestrator.local":       "https://orchestrator.local:9443",
		"http://[::1]:9000":                "https://[::1]:9443",
		"https://[2001:db8::1]:18443":      "https://[2001:db8::1]:18443",
	}
	for in, want := range cases {
		got, err := operationalURL(in)
		if err != nil || got != want {
			t.Errorf("operationalURL(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	t.Setenv("BAS_MTLS_PORT", "20443")
	if got, _ := operationalURL("https://orchestrator.local:18443"); got != "https://orchestrator.local:20443" {
		t.Errorf("BAS_MTLS_PORT override: got %q", got)
	}
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
