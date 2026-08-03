package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/models"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

func TestSubmitScenarioResult_TechniqueVerificationPasses_MarksPass(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('tv-c1', 'TV-C1')`)
		mustExecAPI(t, pool, `
			INSERT INTO remediation_requests (id, remediation_id, agent_id, check_id, tier, status, requested_by, reason)
			VALUES ('rr-tvc-1', 'enable_windows_firewall', 'tv-c1', 'windows-firewall-enabled', 1, 'completed', 'user-1', 'test')`)
		runID := "run-tvc-1"
		mustExecAPI(t, pool, `
			INSERT INTO technique_verification_runs (id, request_id, agent_id, check_id, technique_id, status, run_id, requested_by)
			VALUES ('tvr-c1', 'rr-tvc-1', 'tv-c1', 'windows-firewall-enabled', 'T1562.004', 'dispatched', $1, 'user-1')`,
			runID)

		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		passResult := []models.SimulationResult{{ID: "t1", Result: models.ResultBlocked, Details: "firewall blocked the technique", ExecutedAt: time.Now().UTC()}}
		req := httptest.NewRequest(http.MethodPost, "/x", nil)
		h.continueRemediationFromResult(req, runID, passResult)

		var status, reason string
		pool.QueryRow(context.Background(), `SELECT status, reason FROM technique_verification_runs WHERE id='tvr-c1'`).Scan(&status, &reason)
		if status != "blocked" {
			t.Errorf("status = %q, want blocked", status)
		}
		if reason != "firewall blocked the technique" {
			t.Errorf("reason = %q, want the result's Details text", reason)
		}
	})
}

func TestSubmitScenarioResult_TechniqueVerificationFails_MarksFail(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('tv-c2', 'TV-C2')`)
		mustExecAPI(t, pool, `
			INSERT INTO remediation_requests (id, remediation_id, agent_id, check_id, tier, status, requested_by, reason)
			VALUES ('rr-tvc-2', 'enable_windows_firewall', 'tv-c2', 'windows-firewall-enabled', 1, 'completed', 'user-1', 'test')`)
		runID := "run-tvc-2"
		mustExecAPI(t, pool, `
			INSERT INTO technique_verification_runs (id, request_id, agent_id, check_id, technique_id, status, run_id, requested_by)
			VALUES ('tvr-c2', 'rr-tvc-2', 'tv-c2', 'windows-firewall-enabled', 'T1562.004', 'dispatched', $1, 'user-1')`,
			runID)

		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		failResult := []models.SimulationResult{{ID: "t1", Result: models.ResultFail, Details: "reverse shell still succeeded", ExecutedAt: time.Now().UTC()}}
		req := httptest.NewRequest(http.MethodPost, "/x", nil)
		h.continueRemediationFromResult(req, runID, failResult)

		var status, reason string
		pool.QueryRow(context.Background(), `SELECT status, reason FROM technique_verification_runs WHERE id='tvr-c2'`).Scan(&status, &reason)
		if status != "fail" {
			t.Errorf("status = %q, want fail", status)
		}
		if reason != "reverse shell still succeeded" {
			t.Errorf("reason = %q, want the result's Details text", reason)
		}
	})
}

func TestSubmitScenarioResult_TechniqueVerificationSkipped_MarksSkipped(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('tv-c3', 'TV-C3')`)
		mustExecAPI(t, pool, `
			INSERT INTO remediation_requests (id, remediation_id, agent_id, check_id, tier, status, requested_by, reason)
			VALUES ('rr-tvc-3', 'enable_windows_firewall', 'tv-c3', 'windows-firewall-enabled', 1, 'completed', 'user-1', 'test')`)
		runID := "run-tvc-3"
		mustExecAPI(t, pool, `
			INSERT INTO technique_verification_runs (id, request_id, agent_id, check_id, technique_id, status, run_id, requested_by)
			VALUES ('tvr-c3', 'rr-tvc-3', 'tv-c3', 'windows-firewall-enabled', 'T1562.004', 'dispatched', $1, 'user-1')`,
			runID)

		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		skipResult := []models.SimulationResult{{ID: "t1", Result: models.ResultSkipped, Details: "ART technique not in local store", ExecutedAt: time.Now().UTC()}}
		req := httptest.NewRequest(http.MethodPost, "/x", nil)
		h.continueRemediationFromResult(req, runID, skipResult)

		var status string
		pool.QueryRow(context.Background(), `SELECT status FROM technique_verification_runs WHERE id='tvr-c3'`).Scan(&status)
		if status != "skipped" {
			t.Errorf("status = %q, want skipped", status)
		}
	})
}
