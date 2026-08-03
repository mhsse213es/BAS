package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/models"
	"github.com/audspect/bas/internal/remediation"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

func TestRollbackRemediation_NotCompleted_Conflict(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname, os_version) VALUES ('er-rb-a1', 'ER-RB-HOST', 'windows')`)
		mustExecAPI(t, pool, `
			INSERT INTO remediation_requests (id, remediation_id, agent_id, check_id, tier, status, requested_by, reason, rollback_available)
			VALUES ('rr-rb-1', 'enable_windows_firewall', 'er-rb-a1', 'windows-firewall-enabled', 1, 'dispatched', 'user-1', 'test', true)`)

		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		cat, _ := remediation.NewCatalog()
		h.remediationCatalog = cat

		req := withURLParam(httptest.NewRequest(http.MethodPost, "/x", nil), "requestId", "rr-rb-1")
		w := httptest.NewRecorder()
		h.RollbackRemediation(w, req)
		if w.Code != http.StatusConflict {
			t.Errorf("status = %d, want 409 (not yet completed)", w.Code)
		}
	})
}

func TestRollbackRemediation_NotAvailable_Rejected(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname, os_version) VALUES ('er-rb-a2', 'ER-RB-HOST-2', 'windows')`)
		mustExecAPI(t, pool, `
			INSERT INTO remediation_requests (id, remediation_id, agent_id, check_id, tier, status, requested_by, reason, rollback_available)
			VALUES ('rr-rb-2', 'enable_windows_firewall', 'er-rb-a2', 'windows-firewall-enabled', 1, 'completed', 'user-1', 'test', false)`)

		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		cat, _ := remediation.NewCatalog()
		h.remediationCatalog = cat

		req := withURLParam(httptest.NewRequest(http.MethodPost, "/x", nil), "requestId", "rr-rb-2")
		w := httptest.NewRecorder()
		h.RollbackRemediation(w, req)
		if w.Code != http.StatusUnprocessableEntity {
			t.Errorf("status = %d, want 422 (rollback_available=false)", w.Code)
		}
	})
}

func TestRollbackRemediation_AlreadyRequested_Conflict(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname, os_version) VALUES ('er-rb-a3', 'ER-RB-HOST-3', 'windows')`)
		mustExecAPI(t, pool, `
			INSERT INTO remediation_requests (id, remediation_id, agent_id, check_id, tier, status, requested_by, reason, rollback_available, rollback_status)
			VALUES ('rr-rb-3', 'enable_windows_firewall', 'er-rb-a3', 'windows-firewall-enabled', 1, 'completed', 'user-1', 'test', true, 'requested')`)

		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		cat, _ := remediation.NewCatalog()
		h.remediationCatalog = cat

		req := withURLParam(httptest.NewRequest(http.MethodPost, "/x", nil), "requestId", "rr-rb-3")
		w := httptest.NewRecorder()
		h.RollbackRemediation(w, req)
		if w.Code != http.StatusConflict {
			t.Errorf("status = %d, want 409 (rollback already requested)", w.Code)
		}
	})
}

func TestContinueRemediation_RollbackSucceeds_DispatchesRollbackVerify(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname, os_version) VALUES ('er-rb-a4', 'ER-RB-HOST-4', 'windows')`)
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		cat, err := remediation.NewCatalog()
		if err != nil {
			t.Fatalf("NewCatalog: %v", err)
		}
		h.remediationCatalog = cat
		registerFixtureScenario(t, h.engine, "windows-firewall-enabled")
		fake := startFakeAgent(t, h.hub, "er-rb-a4")
		defer fake.Disconnect(t)

		requestID := "rr-rb-4"
		rollbackRunID := "run-rb-4"
		mustExecAPI(t, pool, `
			INSERT INTO remediation_requests (id, remediation_id, agent_id, check_id, tier, status, requested_by, reason, rollback_available, rollback_status, rollback_run_id)
			VALUES ($1, 'enable_windows_firewall', 'er-rb-a4', 'windows-firewall-enabled', 1, 'completed', 'user-1', 'test', true, 'requested', $2)`,
			requestID, rollbackRunID)
		mustExecAPI(t, pool, `
			INSERT INTO scenario_runs (id, scenario_id, agent_id, name, status, started_at, completed_at)
			VALUES ($1, 'remediation-rollback:enable_windows_firewall', 'er-rb-a4', 'remediation-rollback', 'completed', NOW(), NOW())`,
			rollbackRunID)

		passResult := []models.SimulationResult{{ID: "t1", Result: models.ResultPass, ExecutedAt: time.Now().UTC()}}
		req := httptest.NewRequest(http.MethodPost, "/x", nil)
		h.continueRemediationFromResult(req, rollbackRunID, passResult)

		var rollbackVerifyRunID, rollbackStatus string
		pool.QueryRow(context.Background(), `SELECT rollback_verify_run_id, rollback_status FROM remediation_requests WHERE id=$1`, requestID).
			Scan(&rollbackVerifyRunID, &rollbackStatus)
		if rollbackVerifyRunID == "" {
			t.Errorf("expected rollback_verify_run_id to be set after a successful rollback dispatch (rollback_status=%q)", rollbackStatus)
		}
	})
}

func TestContinueRemediation_RollbackVerifyStillPasses_MarksRollbackFailed(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('er-rb-a5', 'ER-RB-HOST-5')`)
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")

		requestID := "rr-rb-5"
		rollbackVerifyRunID := "run-rbv-5"
		mustExecAPI(t, pool, `
			INSERT INTO remediation_requests (id, remediation_id, agent_id, check_id, tier, status, requested_by, reason, rollback_available, rollback_status, rollback_verify_run_id)
			VALUES ($1, 'enable_windows_firewall', 'er-rb-a5', 'windows-firewall-enabled', 1, 'completed', 'user-1', 'test', true, 'requested', $2)`,
			requestID, rollbackVerifyRunID)

		// The check STILL PASSES after rollback -- the rollback did NOT take effect.
		stillPassing := []models.SimulationResult{{ID: "t1", Result: models.ResultPass, ExecutedAt: time.Now().UTC()}}
		req := httptest.NewRequest(http.MethodPost, "/x", nil)
		h.continueRemediationFromResult(req, rollbackVerifyRunID, stillPassing)

		var rollbackStatus string
		pool.QueryRow(context.Background(), `SELECT rollback_status FROM remediation_requests WHERE id=$1`, requestID).Scan(&rollbackStatus)
		if rollbackStatus != "failed" {
			t.Errorf("rollback_status = %q, want failed (control still active after rollback)", rollbackStatus)
		}
	})
}

func TestContinueRemediation_RollbackVerifyNowFails_MarksRollbackCompleted(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('er-rb-a6', 'ER-RB-HOST-6')`)
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")

		requestID := "rr-rb-6"
		rollbackVerifyRunID := "run-rbv-6"
		mustExecAPI(t, pool, `
			INSERT INTO remediation_requests (id, remediation_id, agent_id, check_id, tier, status, requested_by, reason, rollback_available, rollback_status, rollback_verify_run_id)
			VALUES ($1, 'enable_windows_firewall', 'er-rb-a6', 'windows-firewall-enabled', 1, 'completed', 'user-1', 'test', true, 'requested', $2)`,
			requestID, rollbackVerifyRunID)

		// The check now FAILS after rollback -- the rollback worked.
		nowFailing := []models.SimulationResult{{ID: "t1", Result: models.ResultFail, ExecutedAt: time.Now().UTC()}}
		req := httptest.NewRequest(http.MethodPost, "/x", nil)
		h.continueRemediationFromResult(req, rollbackVerifyRunID, nowFailing)

		var rollbackStatus string
		pool.QueryRow(context.Background(), `SELECT rollback_status FROM remediation_requests WHERE id=$1`, requestID).Scan(&rollbackStatus)
		if rollbackStatus != "completed" {
			t.Errorf("rollback_status = %q, want completed", rollbackStatus)
		}
	})
}
