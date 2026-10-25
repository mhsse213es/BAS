package api

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/pki/pkitest"
)

const (
	revAgentA = "abc123deadbeef01"
	revAgentB = "abc123deadbeef02"
)

// enrollForTest bootstraps agentID with the shared secret and returns the issued serial and status.
func enrollForTest(t *testing.T, h *Handler, agentID string) (serial string, status int) {
	t.Helper()
	csr, err := pkitest.GenerateTestCSR("ignored")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]string{"agentId": agentID, "csrPem": string(csr)})
	req := httptest.NewRequest(http.MethodPost, "/api/agents/enroll-csr", bytes.NewReader(body))
	req.Header.Set("X-Agent-Token", "test-bootstrap-secret")
	rec := httptest.NewRecorder()
	h.EnrollCSR(rec, req)
	if rec.Code != http.StatusOK {
		return "", rec.Code
	}
	var resp struct {
		CertPEM string `json:"certPem"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	blk, _ := pem.Decode([]byte(resp.CertPEM))
	cert, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return cert.SerialNumber.Text(16), rec.Code
}

func adminRouter(h *Handler) http.Handler {
	r := chi.NewRouter()
	r.Post("/api/agents/{agentId}/revoke", h.RevokeAgent)
	r.Post("/api/agents/{agentId}/reinstate", h.ReinstateAgent)
	return r
}

func postJSON(h http.Handler, path string, body any) *httptest.ResponseRecorder {
	b, _ := json.Marshal(body)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, path, bytes.NewReader(b)))
	return rec
}

func seedAgentRow(t *testing.T, pool *pgxpool.Pool, id string) {
	t.Helper()
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO agents (agent_id, hostname) VALUES ($1, $2) ON CONFLICT (agent_id) DO NOTHING`, id, "host-"+id); err != nil {
		t.Fatal(err)
	}
}

func TestRevokeAgent_RevokesOnlyThatAgentsCertificatesAndBlocksIt(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h, _ := newTestHandlerWithPKI(t, pool)
		seedAgentRow(t, pool, revAgentA)
		seedAgentRow(t, pool, revAgentB)
		serialA, _ := enrollForTest(t, h, revAgentA)
		serialB, _ := enrollForTest(t, h, revAgentB)
		router := adminRouter(h)

		if rec := postJSON(router, "/api/agents/"+revAgentA+"/revoke", map[string]string{}); rec.Code != http.StatusBadRequest {
			t.Errorf("revoke without a reason = %d, want 400", rec.Code)
		}
		if rec := postJSON(router, "/api/agents/ffffffffffffffff/revoke", map[string]string{"reason": "x"}); rec.Code != http.StatusNotFound {
			t.Errorf("revoke of an unknown agent = %d, want 404", rec.Code)
		}
		rec := postJSON(router, "/api/agents/"+revAgentA+"/revoke", map[string]string{"reason": "laptop stolen"})
		if rec.Code != http.StatusOK {
			t.Fatalf("revoke = %d: %s", rec.Code, rec.Body.String())
		}

		ctx := context.Background()
		if revoked, err := h.AgentCertRevoked(ctx, serialA, revAgentA); err != nil || !revoked {
			t.Errorf("agent A's certificate: revoked=%v err=%v, want revoked", revoked, err)
		}
		if revoked, err := h.AgentCertRevoked(ctx, serialB, revAgentB); err != nil || revoked {
			t.Errorf("agent B's certificate: revoked=%v err=%v, want NOT revoked", revoked, err)
		}
		// A certificate the database does not know, for a revoked agent, is refused too.
		if revoked, _ := h.AgentCertRevoked(ctx, "deadbeef", revAgentA); !revoked {
			t.Error("any certificate presented by a revoked agent must be refused")
		}
		var state string
		pool.QueryRow(ctx, `SELECT state FROM agents WHERE agent_id=$1`, revAgentA).Scan(&state)
		if state != "revoked" {
			t.Errorf("agent state = %q, want revoked", state)
		}

		// The shared secret must not let a revoked agent enrol again.
		if _, status := enrollForTest(t, h, revAgentA); status != http.StatusForbidden {
			t.Errorf("re-bootstrap of a revoked agent = %d, want 403", status)
		}
	})
}

func TestReinstateAgent_AllowsAFreshEnrolment(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h, _ := newTestHandlerWithPKI(t, pool)
		seedAgentRow(t, pool, revAgentA)
		oldSerial, _ := enrollForTest(t, h, revAgentA)
		router := adminRouter(h)

		if rec := postJSON(router, "/api/agents/"+revAgentA+"/reinstate", map[string]string{"reason": "x"}); rec.Code != http.StatusConflict {
			t.Errorf("reinstating an agent that is not revoked = %d, want 409", rec.Code)
		}
		postJSON(router, "/api/agents/"+revAgentA+"/revoke", map[string]string{"reason": "r"})
		if rec := postJSON(router, "/api/agents/"+revAgentA+"/reinstate", map[string]string{}); rec.Code != http.StatusBadRequest {
			t.Errorf("reinstate without a reason = %d, want 400", rec.Code)
		}
		if rec := postJSON(router, "/api/agents/"+revAgentA+"/reinstate", map[string]string{"reason": "re-imaged"}); rec.Code != http.StatusOK {
			t.Fatalf("reinstate = %d", rec.Code)
		}
		newSerial, status := enrollForTest(t, h, revAgentA)
		if status != http.StatusOK {
			t.Fatalf("enrolment after reinstatement = %d, want 200", status)
		}
		if revoked, _ := h.AgentCertRevoked(context.Background(), newSerial, revAgentA); revoked {
			t.Error("the new certificate must not be revoked")
		}
		if revoked, _ := h.AgentCertRevoked(context.Background(), oldSerial, revAgentA); !revoked {
			t.Error("the old certificate must stay revoked after reinstatement")
		}
	})
}
