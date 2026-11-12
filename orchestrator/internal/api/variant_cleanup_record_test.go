package api

import (
	"context"
	"testing"

	"github.com/audspect/bas/internal/models"
	"github.com/jackc/pgx/v5/pgxpool"
)

func seedVariantRunWithSteps(t *testing.T, pool *pgxpool.Pool, vrID, scenarioRunID string, steps [][3]string) {
	t.Helper()
	ctx := context.Background()
	if _, err := pool.Exec(ctx, `INSERT INTO variant_runs (id, agent_id, technique_id, scenario_run_id, status) VALUES ($1,'agent-cr','T1547.001',$2,'completed')`, vrID, scenarioRunID); err != nil {
		t.Fatalf("seed variant run: %v", err)
	}
	for _, s := range steps {
		// s = {taskID, hasCleanup "true"/"false", cleanupStatus}
		if _, err := pool.Exec(ctx, `INSERT INTO variant_run_steps (variant_run_id, task_id, technique_id, encoding, exec_context, evasion, executor, cmd_preview, risk_level, variant_hash, has_cleanup, cleanup_status) VALUES ($1,$2,'T1547.001','','','','powershell','','SAFE','',$3::boolean,$4)`, vrID, s[0], s[1], s[2]); err != nil {
			t.Fatalf("seed step: %v", err)
		}
	}
}

// The run's cleanup outcome is written beside its attack verdict and reads back as a remediation item when a revert
// failed. The attack verdict on the results is left untouched.
func TestRecordVariantCleanupState_FailedRevertNeedsRemediation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := &Handler{db: pool}
		seedRunRow(t, pool, "cr-scn-1", "sc-cr", "agent-cr", "completed")
		seedVariantRunWithSteps(t, pool, "cr-vr-1", "cr-scn-1", [][3]string{
			{"task-a", "true", "verified"},
			{"task-b", "true", "verified"},
		})
		results := []models.SimulationResult{
			{ID: "task-a", Result: models.ResultBlocked, CleanupVerdict: "reverted"},
			{ID: "task-b", Result: models.ResultBlocked, CleanupVerdict: "leaked", CleanupError: "scheduled task still present"},
		}
		if err := h.recordVariantCleanupState(context.Background(), "cr-scn-1", results); err != nil {
			t.Fatalf("record: %v", err)
		}
		var status, errText string
		var remediation bool
		if err := pool.QueryRow(context.Background(),
			`SELECT cleanup_status, cleanup_error, remediation_required FROM variant_runs WHERE id='cr-vr-1'`,
		).Scan(&status, &errText, &remediation); err != nil {
			t.Fatalf("read back: %v", err)
		}
		if status != "FAILED" || !remediation {
			t.Errorf("cleanup_status=%q remediation=%v, want FAILED and true", status, remediation)
		}
		if errText == "" {
			t.Error("cleanup_error should say what was left behind")
		}
		var attack models.CheckResult
		attack = results[1].Result
		if attack != models.ResultBlocked {
			t.Errorf("attack verdict changed: %v", attack)
		}
	})
}

func TestRecordVariantCleanupState_AllRevertedSucceeds(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := &Handler{db: pool}
		seedRunRow(t, pool, "cr-scn-2", "sc-cr", "agent-cr", "completed")
		seedVariantRunWithSteps(t, pool, "cr-vr-2", "cr-scn-2", [][3]string{{"task-c", "true", "verified"}})
		results := []models.SimulationResult{{ID: "task-c", Result: models.ResultPass, CleanupVerdict: "reverted"}}
		if err := h.recordVariantCleanupState(context.Background(), "cr-scn-2", results); err != nil {
			t.Fatalf("record: %v", err)
		}
		var status string
		var remediation bool
		_ = pool.QueryRow(context.Background(), `SELECT cleanup_status, remediation_required FROM variant_runs WHERE id='cr-vr-2'`).Scan(&status, &remediation)
		if status != "SUCCEEDED" || remediation {
			t.Errorf("cleanup_status=%q remediation=%v, want SUCCEEDED and false", status, remediation)
		}
	})
}

// A run that used a variant with no verified cleanup is recorded as failed, not as clean.
func TestRecordVariantCleanupState_UnverifiedStepFailsClosed(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := &Handler{db: pool}
		seedRunRow(t, pool, "cr-scn-3", "sc-cr", "agent-cr", "completed")
		seedVariantRunWithSteps(t, pool, "cr-vr-3", "cr-scn-3", [][3]string{{"task-d", "false", "unverified"}})
		results := []models.SimulationResult{{ID: "task-d", Result: models.ResultFail}}
		if err := h.recordVariantCleanupState(context.Background(), "cr-scn-3", results); err != nil {
			t.Fatalf("record: %v", err)
		}
		var status string
		var remediation bool
		_ = pool.QueryRow(context.Background(), `SELECT cleanup_status, remediation_required FROM variant_runs WHERE id='cr-vr-3'`).Scan(&status, &remediation)
		if status != "FAILED" || !remediation {
			t.Errorf("cleanup_status=%q remediation=%v, want FAILED and true", status, remediation)
		}
	})
}

// A scenario run that is not a variant run records nothing.
func TestRecordVariantCleanupState_NotAVariantRunIsNoOp(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := &Handler{db: pool}
		seedRunRow(t, pool, "cr-plain", "sc-cr", "agent-cr", "completed")
		if err := h.recordVariantCleanupState(context.Background(), "cr-plain", nil); err != nil {
			t.Fatalf("record on a plain run: %v", err)
		}
	})
}
