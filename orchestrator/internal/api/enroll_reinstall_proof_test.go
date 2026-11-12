package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/pki/pkitest"
)

// postBootstrap sends one shared-secret bootstrap for agentID with the given CSR and returns the recorder.
func postBootstrap(t *testing.T, h *Handler, agentID string, csrPEM []byte) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"agentId": agentID, "csrPem": string(csrPEM)})
	req := httptest.NewRequest(http.MethodPost, "/api/agents/enroll-csr", bytes.NewReader(body))
	req.Header.Set("X-Agent-Token", "test-bootstrap-secret")
	rec := httptest.NewRecorder()
	h.EnrollCSR(rec, req)
	return rec
}

func countCerts(t *testing.T, pool *pgxpool.Pool, agentID string, revoked bool) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(t.Context(),
		`SELECT count(*) FROM agent_certificates WHERE agent_id = $1 AND revoked = $2`, agentID, revoked,
	).Scan(&n); err != nil {
		t.Fatalf("count certificates: %v", err)
	}
	return n
}

// A reinstall that presents the same key as the agent's live certificate is the same identity: it gets a new
// certificate, and the old one stops working. The AgentID and key are unchanged.
func TestEnrollCSR_ReinstallWithSameKeyReissuesSameIdentity(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h, _ := newTestHandlerWithPKI(t, pool)
		const id = "abc123de00000001"
		key, err := pkitest.NewTestKey()
		if err != nil {
			t.Fatal(err)
		}
		csr1, _ := pkitest.GenerateTestCSRWith(key, "first")
		if rec := postBootstrap(t, h, id, csr1); rec.Code != http.StatusOK {
			t.Fatalf("first bootstrap: status = %d, body = %s", rec.Code, rec.Body.String())
		}

		csr2, _ := pkitest.GenerateTestCSRWith(key, "reinstall")
		if rec := postBootstrap(t, h, id, csr2); rec.Code != http.StatusOK {
			t.Fatalf("reinstall with the same key: status = %d, want 200, body = %s", rec.Code, rec.Body.String())
		}
		if got := countCerts(t, pool, id, true); got != 1 {
			t.Errorf("revoked certificates = %d, want 1 (the replaced one)", got)
		}
		if got := countCerts(t, pool, id, false); got != 1 {
			t.Errorf("live certificates = %d, want 1 (the new one)", got)
		}
	})
}

// Presenting a different key is still a new identity, so the shared secret alone must not replace the old one.
func TestEnrollCSR_ReinstallWithDifferentKeyStillRejected(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h, _ := newTestHandlerWithPKI(t, pool)
		const id = "abc123de00000002"
		keyA, _ := pkitest.NewTestKey()
		keyB, _ := pkitest.NewTestKey()
		csrA, _ := pkitest.GenerateTestCSRWith(keyA, "first")
		if rec := postBootstrap(t, h, id, csrA); rec.Code != http.StatusOK {
			t.Fatalf("first bootstrap: status = %d", rec.Code)
		}
		csrB, _ := pkitest.GenerateTestCSRWith(keyB, "other")
		if rec := postBootstrap(t, h, id, csrB); rec.Code != http.StatusConflict {
			t.Errorf("reinstall with a different key: status = %d, want 409", rec.Code)
		}
		if got := countCerts(t, pool, id, false); got != 1 {
			t.Errorf("live certificates = %d, want 1 (the original is untouched)", got)
		}
	})
}

// A certificate issued before this change has no recorded key, so nothing can prove the key matches. It keeps
// the old behaviour: 409, and an administrator's reinstall approval is the way through.
func TestEnrollCSR_ReinstallWithoutRecordedKeyStillRejected(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h, _ := newTestHandlerWithPKI(t, pool)
		const id = "abc123de00000003"
		if _, err := pool.Exec(t.Context(),
			`INSERT INTO agents (agent_id, hostname, state) VALUES ($1, $1, 'active') ON CONFLICT DO NOTHING`, id); err != nil {
			t.Fatalf("seed agent: %v", err)
		}
		if _, err := pool.Exec(t.Context(),
			`INSERT INTO agent_certificates (serial_number, agent_id, issued_at, expires_at) VALUES ('legacy-serial-3', $1, NOW(), NOW() + interval '1 day')`, id); err != nil {
			t.Fatalf("seed legacy certificate: %v", err)
		}
		key, _ := pkitest.NewTestKey()
		csr, _ := pkitest.GenerateTestCSRWith(key, "reinstall")
		if rec := postBootstrap(t, h, id, csr); rec.Code != http.StatusConflict {
			t.Errorf("reinstall against a certificate with no recorded key: status = %d, want 409", rec.Code)
		}
	})
}
