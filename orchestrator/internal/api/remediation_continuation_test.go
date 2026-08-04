package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/jobs"
	"github.com/audspect/bas/internal/models"
	"github.com/audspect/bas/internal/remediation"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

// registerFixtureScenario registers a minimal scenario directly in the
// engine's in-memory map via Save -- this bypasses the file+RSA-signature
// verification path Load() enforces for every YAML file it reads
// (including test fixtures written to a temp dir), which would otherwise
// reject an unsigned scenario as a TAMPER ALERT.
func registerFixtureScenario(t *testing.T, eng *scenario.Engine, checkID string) {
	t.Helper()
	sc := &scenario.Scenario{
		ID:         "fixture-scenario",
		Name:       "Fixture Scenario",
		LocalCheck: true,
		Steps: []scenario.Step{{
			Name:        "Fixture Check",
			TechniqueID: "T1082",
			CheckID:     checkID,
			Framework:   "custom",
			Executor:    "local",
			Command:     "echo PASS: fixture",
			TimeoutSec:  10,
		}},
	}
	if err := eng.Save(sc); err != nil {
		t.Fatalf("register fixture scenario: %v", err)
	}
}

// TestSubmitScenarioResult_AdvancesRemediationFromFixToVerifying exercises
// Task 6's dispatch + Task 7's continuation hook together: a fix dispatch
// followed by the agent's (simulated) result submission must move the
// remediation into "verifying" and dispatch a second synthetic scenario.
func TestSubmitScenarioResult_AdvancesRemediationFromFixToVerifying(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname, os_version) VALUES ('er-cont-a1', 'ER-CONT-HOST', 'windows')`)

		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		cat, err := remediation.NewCatalog()
		if err != nil {
			t.Fatalf("NewCatalog: %v", err)
		}
		h.remediationCatalog = cat
		registerFixtureScenario(t, h.engine, "windows-firewall-enabled")
		fake := startFakeAgent(t, h.hub, "er-cont-a1")
		defer fake.Disconnect(t)

		requestID := "rr-cont-1"
		fixRunID := "run-cont-fix-1"
		mustExecAPI(t, pool, `
			INSERT INTO remediation_requests (id, remediation_id, agent_id, check_id, tier, status, fix_run_id, requested_by, reason, rollback_available)
			VALUES ($1, 'enable_windows_firewall', 'er-cont-a1', 'windows-firewall-enabled', 1, 'dispatched', $2, 'user-1', 'test', true)`,
			requestID, fixRunID)
		mustExecAPI(t, pool, `
			INSERT INTO scenario_runs (id, scenario_id, agent_id, name, status, started_at, completed_at)
			VALUES ($1, 'remediation-fix:enable_windows_firewall', 'er-cont-a1', 'remediation-fix', 'completed', NOW(), NOW())`,
			fixRunID)

		passResult := []models.SimulationResult{{ID: "t1", Result: models.ResultPass, ExecutedAt: time.Now().UTC()}}
		req := httptest.NewRequest(http.MethodPost, "/x", nil)
		h.continueRemediationFromResult(req, fixRunID, passResult)

		var status, verifyRunID, errText string
		pool.QueryRow(context.Background(), `SELECT status, verify_run_id, error FROM remediation_requests WHERE id=$1`, requestID).
			Scan(&status, &verifyRunID, &errText)
		if status != remediation.StatusVerifying {
			t.Errorf("status = %q, want %q (error=%q)", status, remediation.StatusVerifying, errText)
		}
		if verifyRunID == "" {
			t.Error("expected verify_run_id to be set")
		}
	})
}

func TestSubmitScenarioResult_FixFails_MarksFailed(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname, os_version) VALUES ('er-cont-a2', 'ER-CONT-HOST-2', 'windows')`)
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		cat, _ := remediation.NewCatalog()
		h.remediationCatalog = cat

		requestID := "rr-cont-2"
		fixRunID := "run-cont-fix-2"
		mustExecAPI(t, pool, `
			INSERT INTO remediation_requests (id, remediation_id, agent_id, check_id, tier, status, fix_run_id, requested_by, reason)
			VALUES ($1, 'enable_windows_firewall', 'er-cont-a2', 'windows-firewall-enabled', 1, 'dispatched', $2, 'user-1', 'test')`,
			requestID, fixRunID)

		failResult := []models.SimulationResult{{ID: "t1", Result: models.ResultFail, ExecutedAt: time.Now().UTC()}}
		req := httptest.NewRequest(http.MethodPost, "/x", nil)
		h.continueRemediationFromResult(req, fixRunID, failResult)

		var status string
		pool.QueryRow(context.Background(), `SELECT status FROM remediation_requests WHERE id=$1`, requestID).Scan(&status)
		if status != remediation.StatusFailed {
			t.Errorf("status = %q, want %q", status, remediation.StatusFailed)
		}
	})
}

func TestSubmitScenarioResult_VerifyPasses_MarksCompleted(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname, os_version) VALUES ('er-cont-a3', 'ER-CONT-HOST-3', 'windows')`)
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")

		requestID := "rr-cont-3"
		verifyRunID := "run-cont-verify-3"
		mustExecAPI(t, pool, `
			INSERT INTO remediation_requests (id, remediation_id, agent_id, check_id, tier, status, verify_run_id, requested_by, reason)
			VALUES ($1, 'enable_windows_firewall', 'er-cont-a3', 'windows-firewall-enabled', 1, 'verifying', $2, 'user-1', 'test')`,
			requestID, verifyRunID)

		passResult := []models.SimulationResult{{ID: "t1", Result: models.ResultPass, ExecutedAt: time.Now().UTC()}}
		req := httptest.NewRequest(http.MethodPost, "/x", nil)
		h.continueRemediationFromResult(req, verifyRunID, passResult)

		var status string
		pool.QueryRow(context.Background(), `SELECT status FROM remediation_requests WHERE id=$1`, requestID).Scan(&status)
		if status != remediation.StatusCompleted {
			t.Errorf("status = %q, want %q", status, remediation.StatusCompleted)
		}
	})
}

func TestSubmitScenarioResult_VerifyFails_MarksVerificationFailed(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname, os_version) VALUES ('er-cont-a4', 'ER-CONT-HOST-4', 'windows')`)
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")

		requestID := "rr-cont-4"
		verifyRunID := "run-cont-verify-4"
		mustExecAPI(t, pool, `
			INSERT INTO remediation_requests (id, remediation_id, agent_id, check_id, tier, status, verify_run_id, requested_by, reason)
			VALUES ($1, 'enable_windows_firewall', 'er-cont-a4', 'windows-firewall-enabled', 1, 'verifying', $2, 'user-1', 'test')`,
			requestID, verifyRunID)

		failResult := []models.SimulationResult{{ID: "t1", Result: models.ResultFail, ExecutedAt: time.Now().UTC()}}
		req := httptest.NewRequest(http.MethodPost, "/x", nil)
		h.continueRemediationFromResult(req, verifyRunID, failResult)

		var status string
		pool.QueryRow(context.Background(), `SELECT status FROM remediation_requests WHERE id=$1`, requestID).Scan(&status)
		if status != remediation.StatusVerificationFailed {
			t.Errorf("status = %q, want %q", status, remediation.StatusVerificationFailed)
		}
	})
}

func TestSubmitScenarioResult_UnrelatedRunID_NoOp(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		req := httptest.NewRequest(http.MethodPost, "/x", nil)
		// Must not panic or error for a run_id that matches nothing.
		h.continueRemediationFromResult(req, "no-such-run-id", nil)
	})
}

func TestHandleRemediationRollbackVerifyResult_Confirmed_CancelsPendingRevalidations(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname, os_version) VALUES ('rb-cv1', 'RB-CV1', 'windows')`)
		mustExecAPI(t, pool, `
			INSERT INTO remediation_requests (id, remediation_id, agent_id, check_id, tier, status, requested_by, reason, continuous_validation)
			VALUES ('rr-rb-cv1', 'enable_windows_firewall', 'rb-cv1', 'windows-firewall-enabled', 1, 'completed', 'user-1', 'test', true)`)

		jobsStore := jobs.NewStore(pool)
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "").WithJobsDispatcher(jobsStore, jobs.NewDispatcher(jobsStore))

		payload, _ := json.Marshal(basRevalidationPayload{RequestID: "rr-rb-cv1", AgentID: "rb-cv1", CheckID: "windows-firewall-enabled", TechniqueID: "T1082"})
		future := time.Now().UTC().Add(24 * time.Hour)
		job, err := jobsStore.CreateBatchScheduled(context.Background(), "bas_revalidation", payload, "user-1", []string{"rb-cv1"}, &future)
		if err != nil {
			t.Fatalf("CreateBatchScheduled: %v", err)
		}

		req := httptest.NewRequest(http.MethodPost, "/x", nil)
		// passed=false: the check fails again, confirming the rollback took effect.
		h.handleRemediationRollbackVerifyResult(req, "rr-rb-cv1", false)

		got, err := jobsStore.Get(context.Background(), job.ID)
		if err != nil {
			t.Fatalf("Get job: %v", err)
		}
		if got.State != jobs.JobStateCancelled {
			t.Errorf("job.State = %q, want cancelled", got.State)
		}
	})
}

func TestHandleRemediationVerifyResult_ContinuousValidationEnabled_CreatesThreeRevalidationJobs(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname, os_version) VALUES ('cv-tr1', 'CV-TR1', 'windows')`)
		mustExecAPI(t, pool, `
			INSERT INTO remediation_requests (id, remediation_id, agent_id, check_id, tier, status, verify_run_id, requested_by, reason, continuous_validation)
			VALUES ('rr-cv-tr1', 'enable_windows_firewall', 'cv-tr1', 'windows-firewall-enabled', 1, 'verifying', 'run-cv-tr1', 'user-1', 'test', true)`)

		eng := scenario.NewEngine(t.TempDir())
		registerFixtureScenario(t, eng, "windows-firewall-enabled")
		jobsStore := jobs.NewStore(pool)
		h := New(pool, ws.NewHub(), eng, "").WithJobsDispatcher(jobsStore, jobs.NewDispatcher(jobsStore))

		req := httptest.NewRequest(http.MethodPost, "/x", nil)
		h.handleRemediationVerifyResult(req, "rr-cv-tr1", true)

		var count int
		if err := pool.QueryRow(context.Background(),
			`SELECT count(*) FROM jobs WHERE type='bas_revalidation' AND payload->>'requestId'='rr-cv-tr1'`,
		).Scan(&count); err != nil {
			t.Fatalf("query jobs: %v", err)
		}
		if count != 3 {
			t.Errorf("bas_revalidation job count = %d, want 3", count)
		}

		rows, err := pool.Query(context.Background(),
			`SELECT scheduled_at FROM jobs WHERE type='bas_revalidation' AND payload->>'requestId'='rr-cv-tr1' ORDER BY scheduled_at`)
		if err != nil {
			t.Fatalf("query scheduled_at: %v", err)
		}
		defer rows.Close()
		var scheduledAts []time.Time
		for rows.Next() {
			var at time.Time
			rows.Scan(&at)
			scheduledAts = append(scheduledAts, at)
		}
		if len(scheduledAts) != 3 {
			t.Fatalf("got %d scheduled_at values, want 3", len(scheduledAts))
		}
		gap1 := scheduledAts[1].Sub(scheduledAts[0])
		gap2 := scheduledAts[2].Sub(scheduledAts[1])
		if gap1 < 6*24*time.Hour || gap2 < 22*24*time.Hour {
			t.Errorf("gaps between scheduled_at values = %v, %v, want roughly 6d and 23d (24h -> 7d -> 30d)", gap1, gap2)
		}
	})
}

func TestHandleRemediationVerifyResult_ContinuousValidationDisabled_NoRevalidationJobs(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname, os_version) VALUES ('cv-tr2', 'CV-TR2', 'windows')`)
		mustExecAPI(t, pool, `
			INSERT INTO remediation_requests (id, remediation_id, agent_id, check_id, tier, status, verify_run_id, requested_by, reason, continuous_validation)
			VALUES ('rr-cv-tr2', 'enable_windows_firewall', 'cv-tr2', 'windows-firewall-enabled', 1, 'verifying', 'run-cv-tr2', 'user-1', 'test', false)`)

		eng := scenario.NewEngine(t.TempDir())
		registerFixtureScenario(t, eng, "windows-firewall-enabled")
		jobsStore := jobs.NewStore(pool)
		h := New(pool, ws.NewHub(), eng, "").WithJobsDispatcher(jobsStore, jobs.NewDispatcher(jobsStore))

		req := httptest.NewRequest(http.MethodPost, "/x", nil)
		h.handleRemediationVerifyResult(req, "rr-cv-tr2", true)

		var count int
		pool.QueryRow(context.Background(), `SELECT count(*) FROM jobs WHERE type='bas_revalidation' AND payload->>'requestId'='rr-cv-tr2'`).Scan(&count)
		if count != 0 {
			t.Errorf("bas_revalidation job count = %d, want 0 (continuous_validation is false)", count)
		}
	})
}

func TestHandleRemediationVerifyResult_ContinuousValidationEnabled_IneligibleCheck_NoRevalidationJobs(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname, os_version) VALUES ('cv-tr3', 'CV-TR3', 'windows')`)
		mustExecAPI(t, pool, `
			INSERT INTO remediation_requests (id, remediation_id, agent_id, check_id, tier, status, verify_run_id, requested_by, reason, continuous_validation)
			VALUES ('rr-cv-tr3', 'enable_bitlocker', 'cv-tr3', 'windows-bitlocker-enabled', 4, 'verifying', 'run-cv-tr3', 'user-1', 'test', true)`)

		// engine has no scenario registered at all -- findStepByCheckID finds
		// nothing, EligibleForBASVerification returns false.
		eng := scenario.NewEngine(t.TempDir())
		jobsStore := jobs.NewStore(pool)
		h := New(pool, ws.NewHub(), eng, "").WithJobsDispatcher(jobsStore, jobs.NewDispatcher(jobsStore))

		req := httptest.NewRequest(http.MethodPost, "/x", nil)
		h.handleRemediationVerifyResult(req, "rr-cv-tr3", true)

		var count int
		pool.QueryRow(context.Background(), `SELECT count(*) FROM jobs WHERE type='bas_revalidation' AND payload->>'requestId'='rr-cv-tr3'`).Scan(&count)
		if count != 0 {
			t.Errorf("bas_revalidation job count = %d, want 0 (check has no mapped technique_id)", count)
		}
	})
}
