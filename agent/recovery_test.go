package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"audspect/agent/protocol"
)

const recoveryAgent = "abc123deadbeef01"

// recoveryServer stands in for the enrolment listener. It serves the recovery endpoint (verifying the proof the
// way the real server does) and the ordinary enrolment endpoint, and records what reached each.
type recoveryServer struct {
	mu             sync.Mutex
	recoverCalls   int
	enrollCalls    int
	recoverStatus  int // 0 = serve normally
	proofOK        bool
	enrollToken    string
	enrollSecret   string
	recoverHadCert bool
}

func newRecoveryServer(t *testing.T, ca testCA, rs *recoveryServer) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/agents/recover-csr":
			var req protocol.RecoverRequest
			json.NewDecoder(r.Body).Decode(&req)
			rs.mu.Lock()
			rs.recoverCalls++
			rs.recoverHadCert = r.TLS != nil && len(r.TLS.PeerCertificates) > 0
			status := rs.recoverStatus
			rs.mu.Unlock()
			if status != 0 {
				w.WriteHeader(status)
				return
			}
			blk, _ := pem.Decode([]byte(req.ExpiredCertPEM))
			old, err := x509.ParseCertificate(blk.Bytes)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			sig, _ := base64.StdEncoding.DecodeString(req.Proof)
			digest := recoveryProofDigest(req.AgentID, req.SignedAt, req.CSRPEM)
			ok := ecdsa.VerifyASN1(old.PublicKey.(*ecdsa.PublicKey), digest[:], sig)
			rs.mu.Lock()
			rs.proofOK = ok
			rs.mu.Unlock()
			if !ok {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			json.NewEncoder(w).Encode(protocol.CSRResponse{
				CertPEM:   string(issueFromCSR(t, ca, req.CSRPEM, req.AgentID)),
				ExpiresAt: time.Now().Add(365 * 24 * time.Hour).Format(time.RFC3339),
			})
		case "/api/agents/enroll-csr":
			var req protocol.CSRRequest
			json.NewDecoder(r.Body).Decode(&req)
			rs.mu.Lock()
			rs.enrollCalls++
			rs.enrollToken = r.Header.Get("X-Enrollment-Token")
			rs.enrollSecret = r.Header.Get("X-Agent-Token")
			rs.mu.Unlock()
			json.NewEncoder(w).Encode(protocol.CSRResponse{
				CertPEM:   string(issueFromCSR(t, ca, req.CSRPEM, req.AgentID)),
				ExpiresAt: time.Now().Add(365 * 24 * time.Hour).Format(time.RFC3339),
			})
		default:
			http.NotFound(w, r)
		}
	}))
	pool := x509.NewCertPool()
	pool.AddCert(ca.cert)
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{ca.cert.Raw}, PrivateKey: ca.key}},
		ClientAuth:   tls.NoClientCert,
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

// enrolledExpired sets up an agent that enrolled once and whose certificate expired expiredFor ago.
func enrolledExpired(t *testing.T, expiredFor time.Duration) testCA {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("BAS_CERT_DIR", dir)
	ca := newTestCA(t)
	seedDeploymentCA(t, dir, ca)
	key, err := loadOrGenerateAgentKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := saveAgentCertificate(caSignedCertPEM(t, ca, &key.PublicKey, recoveryAgent, -400*24*time.Hour, -expiredFor)); err != nil {
		t.Fatal(err)
	}
	if err := markEnrolled(); err != nil {
		t.Fatal(err)
	}
	return ca
}

func TestRecovery_ExpiredAgentRecoversWithoutTheSecretOrAToken(t *testing.T) {
	ca := enrolledExpired(t, 2*time.Hour)
	rs := &recoveryServer{}
	srv := newRecoveryServer(t, ca, rs)
	t.Setenv("BAS_ENROLL_PORT", portOf(t, srv.URL))
	t.Setenv("BAS_MTLS_PORT", unusedPort(t))

	if _, err := ensureCertificate(context.Background(), Config{ServerURL: "https://127.0.0.1:9443", AgentSecret: "secret"}, recoveryAgent); err != nil {
		t.Fatalf("ensureCertificate = %v", err)
	}
	if rs.recoverCalls != 1 || !rs.proofOK {
		t.Errorf("recoverCalls=%d proofOK=%v, want one call with a valid proof of possession", rs.recoverCalls, rs.proofOK)
	}
	if rs.enrollCalls != 0 {
		t.Error("recovery succeeded, so the shared-secret enrolment endpoint must not be used")
	}
	if rs.recoverHadCert {
		t.Error("recovery must not rely on a client certificate in the TLS handshake")
	}
	if c := mustLoadCert(t); !time.Now().Before(c.NotAfter) {
		t.Error("expected a fresh certificate on disk")
	}
}

func TestRecovery_RefusedFallsBackToTheConfiguredCredentialAndNeverInventsOne(t *testing.T) {
	ca := enrolledExpired(t, 2*time.Hour)
	rs := &recoveryServer{recoverStatus: http.StatusForbidden}
	srv := newRecoveryServer(t, ca, rs)
	t.Setenv("BAS_ENROLL_PORT", portOf(t, srv.URL))
	t.Setenv("BAS_MTLS_PORT", unusedPort(t))

	cfg := Config{ServerURL: "https://127.0.0.1:9443", AgentSecret: "secret", EnrollmentToken: "bas_enr_fresh"}
	if _, err := ensureCertificate(context.Background(), cfg, recoveryAgent); err != nil {
		t.Fatalf("ensureCertificate = %v", err)
	}
	if rs.recoverCalls != 1 || rs.enrollCalls != 1 {
		t.Errorf("recoverCalls=%d enrollCalls=%d, want recovery tried once then the normal enrolment", rs.recoverCalls, rs.enrollCalls)
	}
	if rs.enrollToken != "bas_enr_fresh" || rs.enrollSecret != "secret" {
		t.Errorf("fallback sent token=%q secret=%q, want the configured credentials", rs.enrollToken, rs.enrollSecret)
	}
}

func TestRecovery_AnOlderServerWithoutTheEndpointStillWorks(t *testing.T) {
	ca := enrolledExpired(t, 2*time.Hour)
	rs := &recoveryServer{recoverStatus: http.StatusNotFound}
	srv := newRecoveryServer(t, ca, rs)
	t.Setenv("BAS_ENROLL_PORT", portOf(t, srv.URL))
	t.Setenv("BAS_MTLS_PORT", unusedPort(t))
	if _, err := ensureCertificate(context.Background(), Config{ServerURL: "https://127.0.0.1:9443", AgentSecret: "secret"}, recoveryAgent); err != nil {
		t.Fatalf("ensureCertificate = %v", err)
	}
	if rs.enrollCalls != 1 {
		t.Errorf("enrollCalls=%d, want the ordinary re-enrolment", rs.enrollCalls)
	}
}

func TestRecovery_ExpiredBeyondGraceAndNoCredentialStaysBlocked(t *testing.T) {
	ca := enrolledExpired(t, 30*time.Hour)
	rs := &recoveryServer{recoverStatus: http.StatusForbidden}
	srv := newRecoveryServer(t, ca, rs)
	t.Setenv("BAS_ENROLL_PORT", portOf(t, srv.URL))
	t.Setenv("BAS_MTLS_PORT", unusedPort(t))

	// Token-mode server: the ordinary endpoint would refuse; model it by closing it off.
	srvDeny := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/agents/recover-csr" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srvDeny.Close()
	t.Setenv("BAS_ENROLL_PORT", portOf(t, srvDeny.URL))
	_ = srv

	_, err := ensureCertificate(context.Background(), Config{ServerURL: "https://127.0.0.1:9443", AgentSecret: "secret"}, recoveryAgent)
	var blocked *errBlocked
	if !errors.As(err, &blocked) {
		t.Fatalf("error = %v, want an *errBlocked", err)
	}
	if c := mustLoadCert(t); time.Now().Before(c.NotAfter) {
		t.Error("the expired certificate on disk must be left untouched")
	}
}

func TestRecovery_ValidCertificateOrFirstEnrolmentNeverUsesTheRecoveryEndpoint(t *testing.T) {
	// First enrolment: nothing enrolled yet.
	dir := t.TempDir()
	t.Setenv("BAS_CERT_DIR", dir)
	ca := newTestCA(t)
	seedDeploymentCA(t, dir, ca)
	rs := &recoveryServer{}
	srv := newRecoveryServer(t, ca, rs)
	t.Setenv("BAS_ENROLL_PORT", portOf(t, srv.URL))
	t.Setenv("BAS_MTLS_PORT", unusedPort(t))
	if _, err := ensureCertificate(context.Background(), Config{ServerURL: "https://127.0.0.1:9443", AgentSecret: "secret"}, recoveryAgent); err != nil {
		t.Fatalf("first enrolment = %v", err)
	}
	if rs.recoverCalls != 0 || rs.enrollCalls != 1 {
		t.Errorf("recoverCalls=%d enrollCalls=%d, want a plain first enrolment", rs.recoverCalls, rs.enrollCalls)
	}
}

// Pinned vector: the server computes the same digest (orchestrator/internal/api TestRecoveryProofDigest_GoldenVector).
func TestRecoveryProofDigest_GoldenVector(t *testing.T) {
	d := recoveryProofDigest("abc123deadbeef07", "2030-01-02T03:04:05Z", "CSR-TEXT")
	if got := base64.StdEncoding.EncodeToString(d[:]); got != "NWqLAxH4+nmcIumsDKag7LtlZUMa1KLLWZ4Jzyu6Ols=" {
		t.Errorf("digest = %s", got)
	}
}
