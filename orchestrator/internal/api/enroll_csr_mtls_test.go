// orchestrator/internal/api/enroll_csr_mtls_test.go
package api

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/pki"
	"github.com/audspect/bas/internal/pki/pkitest"
)

const renewalTestAgentID = "0123456789abcdef"

// csrForKey builds a PEM CSR for key -- the same shape agent/certstore.go's
// generateCSR produces (the agent reuses its persisted key on renewal, so
// renewal CSRs are for the SAME key as the certificate being renewed).
func csrForKey(t *testing.T, key *ecdsa.PrivateKey, cn string) []byte {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}}, key)
	if err != nil {
		t.Fatalf("CreateCertificateRequest: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

// bootstrapForTest performs a real initial bootstrap through h.EnrollCSR
// with the shared secret and returns the issued certificate as a
// tls.Certificate bound to key, ready to present on a real mTLS handshake.
func bootstrapForTest(t *testing.T, h *Handler, key *ecdsa.PrivateKey, agentID string) (tls.Certificate, *x509.Certificate) {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"agentId": agentID, "csrPem": string(csrForKey(t, key, agentID))})
	req := httptest.NewRequest(http.MethodPost, "/api/agents/enroll-csr", bytes.NewReader(body))
	req.Header.Set("X-Agent-Token", "test-bootstrap-secret")
	rec := httptest.NewRecorder()
	h.EnrollCSR(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("bootstrap: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var resp enrollCSRResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode bootstrap response: %v", err)
	}
	block, _ := pem.Decode([]byte(resp.CertPEM))
	if block == nil {
		t.Fatal("bootstrap response certPem is not PEM")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse bootstrap cert: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{block.Bytes}, PrivateKey: key, Leaf: leaf}, leaf
}

// newMTLSEnrollServer stands up h.EnrollCSR behind the exact trust shape of
// the production :9443 listener (cmd/server/main.go's mtlsSrv): the CA's
// own certificate as server identity, RequireAndVerifyClientCert against
// the deployment CA, and WithMTLSIdentity attaching the verified CN.
// RequireAndVerifyClientCert (rather than RequireAnyClientCert) is used on
// purpose: it is what production runs, so the handshake this test performs
// is the one a real renewing agent performs.
func newMTLSEnrollServer(t *testing.T, h *Handler, ca *pki.CA) *httptest.Server {
	t.Helper()
	serverCert, err := ca.TLSCertificate()
	if err != nil {
		t.Fatalf("TLSCertificate: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca.Certificate())
	srv := httptest.NewUnstartedServer(WithMTLSIdentity(http.HandlerFunc(h.EnrollCSR)))
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

// mtlsClient presents clientCert and verifies the server chain against the
// deployment CA. InsecureSkipVerify only disables the hostname check (the
// CA-as-server certificate carries no SANs, see agent/bootstrap.go's
// verifyServerCertChain); the chain check is done explicitly.
func mtlsClient(ca *pki.CA, clientCert tls.Certificate) *http.Client {
	pool := x509.NewCertPool()
	pool.AddCert(ca.Certificate())
	return &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		Certificates:       []tls.Certificate{clientCert},
		InsecureSkipVerify: true,
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			c, err := x509.ParseCertificate(raw[0])
			if err != nil {
				return err
			}
			_, err = c.Verify(x509.VerifyOptions{Roots: pool})
			return err
		},
	}}}
}

// postRenewal sends exactly what agent/bootstrap.go's renewal path sends:
// POST /api/agents/enroll-csr with an EMPTY X-Agent-Token (the bootstrap
// secret is withheld on renewal) and a fresh CSR for the same key.
func postRenewal(t *testing.T, client *http.Client, url, agentID string, csrPEM []byte) *http.Response {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"agentId": agentID, "csrPem": string(csrPEM)})
	req, _ := http.NewRequest(http.MethodPost, url+"/api/agents/enroll-csr", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Agent-Token", "")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("renewal POST: %v", err)
	}
	return resp
}

// TestEnrollCSR_RenewalOverRealMTLSSucceeds drives the renewal request the
// agent actually makes against the real handler over a real mTLS
// handshake. Before the renewal fix this returned 401 (bootstrap-secret
// check with an empty secret) -- or 409 with no secret configured -- so no
// agent could ever renew.
func TestEnrollCSR_RenewalOverRealMTLSSucceeds(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h, ca := newTestHandlerWithPKI(t, pool)
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("GenerateKey: %v", err)
		}
		clientCert, original := bootstrapForTest(t, h, key, renewalTestAgentID)
		srv := newMTLSEnrollServer(t, h, ca)

		resp := postRenewal(t, mtlsClient(ca, clientCert), srv.URL, renewalTestAgentID, csrForKey(t, key, renewalTestAgentID))
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			var b bytes.Buffer
			b.ReadFrom(resp.Body)
			t.Fatalf("renewal status = %d, body = %s", resp.StatusCode, b.String())
		}
		var out enrollCSRResponse
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
			t.Fatalf("decode renewal response: %v", err)
		}
		block, _ := pem.Decode([]byte(out.CertPEM))
		if block == nil {
			t.Fatal("renewal certPem is not PEM")
		}
		renewed, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatalf("parse renewed cert: %v", err)
		}
		if renewed.Subject.CommonName != renewalTestAgentID {
			t.Errorf("renewed CN = %q, want %q", renewed.Subject.CommonName, renewalTestAgentID)
		}
		if renewed.SerialNumber.Cmp(original.SerialNumber) == 0 {
			t.Error("renewal returned the original certificate instead of a new one")
		}
		if !renewed.PublicKey.(*ecdsa.PublicKey).Equal(&key.PublicKey) {
			t.Error("renewed certificate is not bound to the agent's own key")
		}
		if _, err := renewed.Verify(x509.VerifyOptions{
			Roots:     func() *x509.CertPool { p := x509.NewCertPool(); p.AddCert(ca.Certificate()); return p }(),
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		}); err != nil {
			t.Errorf("renewed certificate does not chain to the deployment CA: %v", err)
		}

		var rows int
		if err := pool.QueryRow(context.Background(),
			`SELECT COUNT(*) FROM agent_certificates WHERE agent_id = $1`, renewalTestAgentID).Scan(&rows); err != nil {
			t.Fatalf("count rows: %v", err)
		}
		if rows != 2 {
			t.Errorf("agent_certificates rows = %d, want 2 (bootstrap + renewal)", rows)
		}
	})
}

// A certificate issued to one agent must never obtain a certificate for a
// different identity, even though the handshake itself is valid.
func TestEnrollCSR_RenewalRejectsMismatchedAgentID(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h, ca := newTestHandlerWithPKI(t, pool)
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		clientCert, _ := bootstrapForTest(t, h, key, renewalTestAgentID)
		srv := newMTLSEnrollServer(t, h, ca)

		other := "fedcba9876543210"
		resp := postRenewal(t, mtlsClient(ca, clientCert), srv.URL, other, csrForKey(t, key, other))
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("status = %d, want 401 for agentId not matching the presented certificate", resp.StatusCode)
		}
		var rows int
		pool.QueryRow(context.Background(), `SELECT COUNT(*) FROM agent_certificates WHERE agent_id = $1`, other).Scan(&rows)
		if rows != 0 {
			t.Errorf("a certificate was issued for %s via another agent's certificate", other)
		}
	})
}

// An explicitly revoked certificate must not be able to renew itself into a
// fresh, unrevoked one.
func TestEnrollCSR_RenewalRejectsRevokedCertificate(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h, ca := newTestHandlerWithPKI(t, pool)
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		clientCert, original := bootstrapForTest(t, h, key, renewalTestAgentID)
		if _, err := pool.Exec(context.Background(),
			`UPDATE agent_certificates SET revoked = true, revoked_at = NOW() WHERE serial_number = $1`,
			original.SerialNumber.Text(16)); err != nil {
			t.Fatalf("revoke: %v", err)
		}
		srv := newMTLSEnrollServer(t, h, ca)

		resp := postRenewal(t, mtlsClient(ca, clientCert), srv.URL, renewalTestAgentID, csrForKey(t, key, renewalTestAgentID))
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("status = %d, want 401 for a revoked certificate", resp.StatusCode)
		}
	})
}

func TestEnrollCSR_MalformedAgentIDRejectedWith400(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h, _ := newTestHandlerWithPKI(t, pool)
		csrPEM, _ := pkitest.GenerateTestCSR("cn")
		for _, id := range []string{
			"abc123",              // too short
			"abc123deadbeef0123",  // too long
			"abc123deadbeef0g",    // non-hex character
			"ABC123DEADBEEF01",    // uppercase (identity.go emits lowercase)
			"abc123deadbeef0\n",   // control character
			"../../../etc/passwd", // arbitrary string
		} {
			body, _ := json.Marshal(map[string]string{"agentId": id, "csrPem": string(csrPEM)})
			req := httptest.NewRequest(http.MethodPost, "/api/agents/enroll-csr", bytes.NewReader(body))
			req.Header.Set("X-Agent-Token", "test-bootstrap-secret")
			rec := httptest.NewRecorder()
			h.EnrollCSR(rec, req)
			if rec.Code != http.StatusBadRequest {
				t.Errorf("agentId %q: status = %d, want 400", id, rec.Code)
			}
		}
		var rows int
		pool.QueryRow(context.Background(), `SELECT COUNT(*) FROM agent_certificates`).Scan(&rows)
		if rows != 0 {
			t.Errorf("agent_certificates rows = %d, want 0 — a malformed agentId reached issuance", rows)
		}
	})
}

// Concurrent initial bootstraps for the same never-seen AgentID: exactly one
// may succeed. Without the per-AgentID lock the reuse check and INSERT race
// and several requests each walk away with a certificate.
func TestEnrollCSR_ConcurrentBootstrapIssuesExactlyOneCertificate(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h, _ := newTestHandlerWithPKI(t, pool)
		const n = 12
		bodies := make([][]byte, n)
		for i := range bodies {
			csrPEM, _ := pkitest.GenerateTestCSR("cn")
			bodies[i], _ = json.Marshal(map[string]string{"agentId": renewalTestAgentID, "csrPem": string(csrPEM)})
		}
		codes := make([]int, n)
		var wg sync.WaitGroup
		start := make(chan struct{})
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				req := httptest.NewRequest(http.MethodPost, "/api/agents/enroll-csr", bytes.NewReader(bodies[i]))
				req.Header.Set("X-Agent-Token", "test-bootstrap-secret")
				rec := httptest.NewRecorder()
				<-start
				h.EnrollCSR(rec, req)
				codes[i] = rec.Code
			}(i)
		}
		close(start)
		wg.Wait()

		ok, conflict := 0, 0
		for _, c := range codes {
			switch c {
			case http.StatusOK:
				ok++
			case http.StatusConflict:
				conflict++
			default:
				t.Errorf("unexpected status %d", c)
			}
		}
		if ok != 1 || conflict != n-1 {
			t.Errorf("got %d x 200 and %d x 409, want exactly 1 x 200 and %d x 409", ok, conflict, n-1)
		}
		var rows int
		pool.QueryRow(context.Background(), `SELECT COUNT(*) FROM agent_certificates WHERE agent_id = $1`, renewalTestAgentID).Scan(&rows)
		if rows != 1 {
			t.Errorf("agent_certificates rows = %d, want 1", rows)
		}
	})
}
