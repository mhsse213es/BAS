package api

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

const recAgent = "abc123deadbeef07"

type recoverFixture struct {
	h       *Handler
	pool    *pgxpool.Pool
	key     *ecdsa.PrivateKey
	certPEM string
	cert    *x509.Certificate
}

func newCSRPEM(t *testing.T, key *ecdsa.PrivateKey) string {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "ignored"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

// enrolled sets up an agent that enrolled normally and holds a certificate whose key we control.
func enrolled(t *testing.T, pool *pgxpool.Pool, agentID string) *recoverFixture {
	t.Helper()
	h, _ := newTestHandlerWithPKI(t, pool)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	body, _ := json.Marshal(map[string]string{"agentId": agentID, "csrPem": newCSRPEM(t, key)})
	req := httptest.NewRequest(http.MethodPost, "/api/agents/enroll-csr", bytes.NewReader(body))
	req.Header.Set("X-Agent-Token", "test-bootstrap-secret")
	rec := httptest.NewRecorder()
	h.EnrollCSR(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("enrol = %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		CertPEM string `json:"certPem"`
	}
	json.Unmarshal(rec.Body.Bytes(), &resp)
	blk, _ := pem.Decode([]byte(resp.CertPEM))
	cert, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	seedAgentRow(t, pool, agentID)
	return &recoverFixture{h: h, pool: pool, key: key, certPEM: resp.CertPEM, cert: cert}
}

// at makes the server believe it is d after the certificate's expiry.
func (f *recoverFixture) at(d time.Duration) { f.h.now = func() time.Time { return f.cert.NotAfter.Add(d) } }

type recoverOpts struct {
	agentID    string
	signKey    *ecdsa.PrivateKey // key that makes the proof (default: the certificate's key)
	csrKey     *ecdsa.PrivateKey // key in the CSR (default: a fresh key)
	proofCSR   string            // CSR text the proof covers (default: the submitted CSR)
	signedAt   time.Time
	certPEM    string
	skipProof  bool
}

func (f *recoverFixture) recover(t *testing.T, o recoverOpts) *httptest.ResponseRecorder {
	t.Helper()
	if o.agentID == "" {
		o.agentID = recAgent
	}
	if o.signKey == nil {
		o.signKey = f.key
	}
	if o.csrKey == nil {
		o.csrKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	}
	if o.certPEM == "" {
		o.certPEM = f.certPEM
	}
	csr := newCSRPEM(t, o.csrKey)
	if o.proofCSR == "" {
		o.proofCSR = csr
	}
	signedAt := o.signedAt
	if signedAt.IsZero() {
		signedAt = f.h.timeNow()
	}
	ts := signedAt.UTC().Format(time.RFC3339)
	proof := ""
	if !o.skipProof {
		digest := recoveryProofDigest(o.agentID, ts, o.proofCSR)
		sig, err := ecdsa.SignASN1(rand.Reader, o.signKey, digest[:])
		if err != nil {
			t.Fatal(err)
		}
		proof = base64.StdEncoding.EncodeToString(sig)
	}
	body, _ := json.Marshal(map[string]string{
		"agentId": o.agentID, "csrPem": csr, "expiredCertPem": o.certPEM, "signedAt": ts, "proof": proof,
	})
	rec := httptest.NewRecorder()
	f.h.RecoverCSR(rec, httptest.NewRequest(http.MethodPost, "/api/agents/recover-csr", bytes.NewReader(body)))
	return rec
}

func countRows(t *testing.T, pool *pgxpool.Pool, q string, args ...any) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(), q, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestRecover_ExpiredWithinGraceGetsANewCertificateForTheSameAgent(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		f := enrolled(t, pool, recAgent)
		f.at(2 * time.Hour)
		rec := f.recover(t, recoverOpts{})
		if rec.Code != http.StatusOK {
			t.Fatalf("recover = %d: %s", rec.Code, rec.Body.String())
		}
		var resp struct{ CertPEM string `json:"certPem"` }
		json.Unmarshal(rec.Body.Bytes(), &resp)
		blk, _ := pem.Decode([]byte(resp.CertPEM))
		nc, err := x509.ParseCertificate(blk.Bytes)
		if err != nil || nc.Subject.CommonName != recAgent {
			t.Fatalf("new certificate CN = %v err %v, want %s", nc, err, recAgent)
		}
		if countRows(t, pool, `SELECT count(*) FROM agent_certificates WHERE agent_id=$1`, recAgent) != 2 {
			t.Error("the new certificate should be recorded next to the old one")
		}
		if countRows(t, pool, `SELECT count(*) FROM agent_certificates WHERE serial_number=$1 AND superseded_at IS NOT NULL`, f.cert.SerialNumber.Text(16)) != 1 {
			t.Error("the old certificate must be marked as used up")
		}
		if auditActionCount(t, pool, "agent.recover", recAgent, 1) != 1 {
			t.Error("a successful recovery must be audited")
		}
	})
}

func TestRecover_ReplayOfTheSameRequestIsRefused(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		f := enrolled(t, pool, recAgent)
		f.at(time.Hour)
		if rec := f.recover(t, recoverOpts{}); rec.Code != http.StatusOK {
			t.Fatalf("first recovery = %d: %s", rec.Code, rec.Body.String())
		}
		if rec := f.recover(t, recoverOpts{}); rec.Code != http.StatusForbidden {
			t.Errorf("second use of the same expired certificate = %d, want 403", rec.Code)
		}
		if auditActionCount(t, pool, "agent.recover_denied", recAgent, 1) < 1 {
			t.Error("the refused attempt must be audited")
		}
	})
}

func TestRecover_BoundaryOfTheTwentyFourHourGrace(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		f := enrolled(t, pool, recAgent)
		f.at(24*time.Hour + time.Minute)
		if rec := f.recover(t, recoverOpts{}); rec.Code != http.StatusForbidden {
			t.Errorf("expired 24h01m ago = %d, want 403 (fresh authorized enrolment required)", rec.Code)
		}
		f.at(23*time.Hour + 59*time.Minute)
		if rec := f.recover(t, recoverOpts{}); rec.Code != http.StatusOK {
			t.Errorf("expired 23h59m ago = %d, want 200: %s", rec.Code, rec.Body.String())
		}
	})
}

func TestRecover_AStillValidCertificateMustRenewOverMTLSInstead(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		f := enrolled(t, pool, recAgent)
		f.at(-time.Hour)
		if rec := f.recover(t, recoverOpts{}); rec.Code != http.StatusConflict {
			t.Errorf("valid certificate = %d, want 409", rec.Code)
		}
	})
}

func TestRecover_RevokedAgentOrCertificateGetsNoGracePeriod(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		f := enrolled(t, pool, recAgent)
		f.at(time.Hour)
		pool.Exec(context.Background(), `UPDATE agents SET state='revoked' WHERE agent_id=$1`, recAgent)
		if rec := f.recover(t, recoverOpts{}); rec.Code != http.StatusForbidden {
			t.Errorf("revoked agent = %d, want 403", rec.Code)
		}
		pool.Exec(context.Background(), `UPDATE agents SET state='active' WHERE agent_id=$1`, recAgent)
		pool.Exec(context.Background(), `UPDATE agent_certificates SET revoked=true WHERE serial_number=$1`, f.cert.SerialNumber.Text(16))
		if rec := f.recover(t, recoverOpts{}); rec.Code != http.StatusForbidden {
			t.Errorf("revoked certificate = %d, want 403", rec.Code)
		}
		pool.Exec(context.Background(), `UPDATE agent_certificates SET revoked=false WHERE serial_number=$1`, f.cert.SerialNumber.Text(16))
		pool.Exec(context.Background(), `UPDATE agents SET state='uninstalling' WHERE agent_id=$1`, recAgent)
		if rec := f.recover(t, recoverOpts{}); rec.Code != http.StatusForbidden {
			t.Errorf("uninstalling agent = %d, want 403", rec.Code)
		}
	})
}

func TestRecover_CannotBeUsedToTakeOverAnotherAgentOrWithAnotherKey(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		f := enrolled(t, pool, recAgent)
		f.at(time.Hour)
		other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

		if rec := f.recover(t, recoverOpts{agentID: "abc123deadbeef99"}); rec.Code != http.StatusForbidden {
			t.Errorf("a certificate for one agent used for another = %d, want 403", rec.Code)
		}
		if rec := f.recover(t, recoverOpts{signKey: other}); rec.Code != http.StatusForbidden {
			t.Errorf("a proof made with a different key = %d, want 403", rec.Code)
		}
		if rec := f.recover(t, recoverOpts{skipProof: true}); rec.Code != http.StatusForbidden && rec.Code != http.StatusBadRequest {
			t.Errorf("no proof = %d, want 400/403", rec.Code)
		}
		// The proof covers the CSR, so a captured request cannot be re-pointed at an attacker's key.
		attacker, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		victimCSR := newCSRPEM(t, other)
		if rec := f.recover(t, recoverOpts{csrKey: attacker, proofCSR: victimCSR}); rec.Code != http.StatusForbidden {
			t.Errorf("a proof for a different CSR = %d, want 403", rec.Code)
		}
		if countRows(t, pool, `SELECT count(*) FROM agent_certificates WHERE agent_id=$1`, recAgent) != 1 {
			t.Error("no certificate may be issued by a refused recovery")
		}
	})
}

func TestRecover_StaleProofTimestampIsRefused(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		f := enrolled(t, pool, recAgent)
		f.at(time.Hour)
		if rec := f.recover(t, recoverOpts{signedAt: f.h.timeNow().Add(-10 * time.Minute)}); rec.Code != http.StatusForbidden {
			t.Errorf("a proof signed 10 minutes ago = %d, want 403", rec.Code)
		}
		if rec := f.recover(t, recoverOpts{signedAt: f.h.timeNow().Add(10 * time.Minute)}); rec.Code != http.StatusForbidden {
			t.Errorf("a proof signed 10 minutes in the future = %d, want 403", rec.Code)
		}
	})
}

func TestRecover_ACertificateFromAnotherCAIsRefused(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		f := enrolled(t, pool, recAgent)
		stranger := enrolled(t, pool, "abc123deadbeef08") // a different handler, so a different CA
		stranger.at(time.Hour)
		f.at(time.Hour)
		if rec := f.recover(t, recoverOpts{certPEM: stranger.certPEM, signKey: stranger.key, agentID: "abc123deadbeef08"}); rec.Code != http.StatusForbidden {
			t.Errorf("a certificate signed by another CA = %d, want 403", rec.Code)
		}
	})
}

// The 24 hours are measured by the server's clock; nothing the agent says about time is used.
func TestRecover_UsesServerTimeNotTheAgentsClaim(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		f := enrolled(t, pool, recAgent)
		f.at(48 * time.Hour) // far outside the grace period on the server's clock
		// The agent signs a timestamp matching the server's clock, so the only thing that can refuse is the age.
		if rec := f.recover(t, recoverOpts{}); rec.Code != http.StatusForbidden {
			t.Errorf("= %d, want 403", rec.Code)
		}
	})
}

func TestRecover_RepeatedFailuresAreThrottled(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		f := enrolled(t, pool, recAgent)
		f.at(time.Hour)
		other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		last := 0
		for i := 0; i < 30; i++ {
			last = f.recover(t, recoverOpts{signKey: other}).Code
		}
		if last != http.StatusTooManyRequests {
			t.Errorf("after many failures = %d, want 429", last)
		}
	})
}

// Pinned vector: the agent computes the same digest (agent/recovery_proof_test.go).
func TestRecoveryProofDigest_GoldenVector(t *testing.T) {
	d := recoveryProofDigest("abc123deadbeef07", "2030-01-02T03:04:05Z", "CSR-TEXT")
	got := base64.StdEncoding.EncodeToString(d[:])
	const want = "NWqLAxH4+nmcIumsDKag7LtlZUMa1KLLWZ4Jzyu6Ols="
	if got != want {
		t.Errorf("digest = %s", got)
	}
}
