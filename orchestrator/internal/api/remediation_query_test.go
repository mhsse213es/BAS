package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/remediation"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

func TestGetRemediation_ReturnsCurrentStatus(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('er-q-a1', 'ER-Q-HOST')`)
		mustExecAPI(t, pool, `
			INSERT INTO remediation_requests (id, remediation_id, agent_id, check_id, tier, status, requested_by, reason)
			VALUES ('rr-q-1', 'enable_windows_firewall', 'er-q-a1', 'windows-firewall-enabled', 1, 'completed', 'user-1', 'test')`)

		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		req := withURLParam(httptest.NewRequest(http.MethodGet, "/x", nil), "requestId", "rr-q-1")
		w := httptest.NewRecorder()
		h.GetRemediation(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
		}
		var got remediation.RemediationRequest
		if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if got.Status != remediation.StatusCompleted {
			t.Errorf("Status = %q, want %q", got.Status, remediation.StatusCompleted)
		}
	})
}

func TestGetRemediation_NotFound_404(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		req := withURLParam(httptest.NewRequest(http.MethodGet, "/x", nil), "requestId", "no-such-request")
		w := httptest.NewRecorder()
		h.GetRemediation(w, req)
		if w.Code != http.StatusNotFound {
			t.Errorf("status = %d, want 404", w.Code)
		}
	})
}

func TestGetRemediation_LazilyReapsTimedOut(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('er-q-a2', 'ER-Q-HOST-2')`)
		longAgo := time.Now().UTC().Add(-1 * time.Hour)
		mustExecAPI(t, pool, `
			INSERT INTO remediation_requests (id, remediation_id, agent_id, check_id, tier, status, requested_by, reason, dispatched_at)
			VALUES ('rr-q-2', 'enable_windows_firewall', 'er-q-a2', 'windows-firewall-enabled', 1, 'dispatched', 'user-1', 'test', $1)`,
			longAgo)

		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		cat, _ := remediation.NewCatalog()
		h.remediationCatalog = cat

		req := withURLParam(httptest.NewRequest(http.MethodGet, "/x", nil), "requestId", "rr-q-2")
		w := httptest.NewRecorder()
		h.GetRemediation(w, req)
		var got remediation.RemediationRequest
		json.Unmarshal(w.Body.Bytes(), &got)
		if got.Status != remediation.StatusTimedOut {
			t.Errorf("Status = %q, want %q (dispatched 1h ago, well past the ~120s deadline)", got.Status, remediation.StatusTimedOut)
		}

		var dbStatus string
		pool.QueryRow(req.Context(), `SELECT status FROM remediation_requests WHERE id='rr-q-2'`).Scan(&dbStatus)
		if dbStatus != remediation.StatusTimedOut {
			t.Errorf("db status = %q, want persisted as %q", dbStatus, remediation.StatusTimedOut)
		}
	})
}

func TestGetRemediation_RecentDispatch_NotReaped(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('er-q-a3', 'ER-Q-HOST-3')`)
		mustExecAPI(t, pool, `
			INSERT INTO remediation_requests (id, remediation_id, agent_id, check_id, tier, status, requested_by, reason, dispatched_at)
			VALUES ('rr-q-3', 'enable_windows_firewall', 'er-q-a3', 'windows-firewall-enabled', 1, 'dispatched', 'user-1', 'test', NOW())`)

		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		cat, _ := remediation.NewCatalog()
		h.remediationCatalog = cat

		req := withURLParam(httptest.NewRequest(http.MethodGet, "/x", nil), "requestId", "rr-q-3")
		w := httptest.NewRecorder()
		h.GetRemediation(w, req)
		var got remediation.RemediationRequest
		json.Unmarshal(w.Body.Bytes(), &got)
		if got.Status != remediation.StatusDispatched {
			t.Errorf("Status = %q, want %q (just dispatched, well within deadline)", got.Status, remediation.StatusDispatched)
		}
	})
}

func TestListAgentRemediations_ReturnsHistoryMostRecentFirst(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('er-q-a4', 'ER-Q-HOST-4')`)
		mustExecAPI(t, pool, `
			INSERT INTO remediation_requests (id, remediation_id, agent_id, check_id, tier, status, requested_by, reason, requested_at)
			VALUES ('rr-q-4a', 'enable_windows_firewall', 'er-q-a4', 'windows-firewall-enabled', 1, 'completed', 'user-1', 'test', NOW() - INTERVAL '1 hour')`)
		mustExecAPI(t, pool, `
			INSERT INTO remediation_requests (id, remediation_id, agent_id, check_id, tier, status, requested_by, reason, requested_at)
			VALUES ('rr-q-4b', 'disable_windows_smbv1', 'er-q-a4', 'windows-smbv1-disabled', 2, 'requested', 'user-1', 'test', NOW())`)

		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		req := withURLParam(httptest.NewRequest(http.MethodGet, "/x", nil), "agentId", "er-q-a4")
		w := httptest.NewRecorder()
		h.ListAgentRemediations(w, req)
		var body struct {
			Remediations []remediation.RemediationRequest `json:"remediations"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if len(body.Remediations) != 2 {
			t.Fatalf("got %d remediations, want 2", len(body.Remediations))
		}
		if body.Remediations[0].ID != "rr-q-4b" {
			t.Errorf("first result = %s, want rr-q-4b (most recent)", body.Remediations[0].ID)
		}
	})
}
