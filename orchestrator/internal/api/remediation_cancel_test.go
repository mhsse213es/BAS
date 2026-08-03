package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/remediation"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

func TestCancelRemediation_NoRunInFlight_Conflict(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('er-cx-a1', 'ER-CX-HOST')`)
		mustExecAPI(t, pool, `
			INSERT INTO remediation_requests (id, remediation_id, agent_id, check_id, tier, status, requested_by, reason)
			VALUES ('rr-cx-1', 'enable_windows_firewall', 'er-cx-a1', 'windows-firewall-enabled', 1, 'requested', 'user-1', 'test')`)

		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		req := withURLParam(httptest.NewRequest(http.MethodPost, "/x", nil), "requestId", "rr-cx-1")
		w := httptest.NewRecorder()
		h.CancelRemediation(w, req)
		if w.Code != http.StatusConflict {
			t.Errorf("status = %d, want 409 (no fix_run_id/verify_run_id yet)", w.Code)
		}
	})
}

func TestCancelRemediation_InFlight_MarksCancelled(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('er-cx-a2', 'ER-CX-HOST-2')`)
		mustExecAPI(t, pool, `
			INSERT INTO scenario_runs (id, scenario_id, agent_id, name, status, started_at)
			VALUES ('run-cx-2', 'remediation-fix:enable_windows_firewall', 'er-cx-a2', 'remediation-fix', 'running', NOW())`)
		mustExecAPI(t, pool, `
			INSERT INTO remediation_requests (id, remediation_id, agent_id, check_id, tier, status, fix_run_id, requested_by, reason)
			VALUES ('rr-cx-2', 'enable_windows_firewall', 'er-cx-a2', 'windows-firewall-enabled', 1, 'dispatched', 'run-cx-2', 'user-1', 'test')`)

		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		req := withURLParam(httptest.NewRequest(http.MethodPost, "/x", nil), "requestId", "rr-cx-2")
		w := httptest.NewRecorder()
		h.CancelRemediation(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
		}

		var status string
		pool.QueryRow(context.Background(), `SELECT status FROM remediation_requests WHERE id='rr-cx-2'`).Scan(&status)
		if status != remediation.StatusCancelled {
			t.Errorf("status = %q, want %q", status, remediation.StatusCancelled)
		}
	})
}

func TestCancelRemediation_NotFound_404(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		req := withURLParam(httptest.NewRequest(http.MethodPost, "/x", nil), "requestId", "no-such-request")
		w := httptest.NewRecorder()
		h.CancelRemediation(w, req)
		if w.Code != http.StatusNotFound {
			t.Errorf("status = %d, want 404", w.Code)
		}
	})
}
