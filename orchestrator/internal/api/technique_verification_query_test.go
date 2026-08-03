package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/remediation"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

func TestGetTechniqueVerification_ReturnsCurrentStatus(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('tv-q1', 'TV-Q1')`)
		mustExecAPI(t, pool, `
			INSERT INTO remediation_requests (id, remediation_id, agent_id, check_id, tier, status, requested_by, reason)
			VALUES ('rr-tvq-1', 'enable_windows_firewall', 'tv-q1', 'windows-firewall-enabled', 1, 'completed', 'user-1', 'test')`)
		mustExecAPI(t, pool, `
			INSERT INTO technique_verification_runs (id, request_id, agent_id, check_id, technique_id, status, reason, requested_by)
			VALUES ('tvr-q1', 'rr-tvq-1', 'tv-q1', 'windows-firewall-enabled', 'T1562.004', 'blocked', 'firewall blocked it', 'user-1')`)

		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		req := withURLParam(httptest.NewRequest(http.MethodGet, "/x", nil), "id", "tvr-q1")
		w := httptest.NewRecorder()
		h.GetTechniqueVerification(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
		}
		var got remediation.TechniqueVerificationRun
		if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if got.Status != "blocked" || got.Reason != "firewall blocked it" {
			t.Errorf("got = %+v, want Status=blocked Reason='firewall blocked it'", got)
		}
	})
}

func TestGetTechniqueVerification_NotFound_404(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		req := withURLParam(httptest.NewRequest(http.MethodGet, "/x", nil), "id", "no-such-id")
		w := httptest.NewRecorder()
		h.GetTechniqueVerification(w, req)
		if w.Code != http.StatusNotFound {
			t.Errorf("status = %d, want 404", w.Code)
		}
	})
}
