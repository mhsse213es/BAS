package api

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/audspect/bas/internal/models"
	"github.com/jackc/pgx/v5/pgxpool"
)

// dispatchVariantForTest runs a real variant dispatch (command override,
// PowerShell executor — always generates templates) against a connected fake
// agent, and returns the resulting scenario_run/variant_run ids plus one
// step's task_id to drive result-submission tests.
func dispatchVariantForTest(t *testing.T, h *Handler, pool *pgxpool.Pool, agentID, techniqueID, executionMode string) (scenarioRunID, variantRunID, taskID string) {
	t.Helper()
	seedActiveAgent(t, pool, agentID, "Windows")
	fake := startFakeAgent(t, h.hub, agentID)
	defer fake.Disconnect(t)

	body := map[string]any{
		"agentId": agentID, "techniqueId": techniqueID, "command": "whoami", "executor": "powershell",
	}
	if executionMode != "" {
		body["executionMode"] = executionMode
	}
	rec := httptest.NewRecorder()
	h.RunVariants(rec, variantsRunReq(body))
	var out struct {
		VariantRunID  string `json:"variantRunId"`
		ScenarioRunID string `json:"scenarioRunId"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("dispatchVariantForTest: decode: %v", err)
	}
	fake.WaitForMessage(t, 2*time.Second)

	if err := pool.QueryRow(context.Background(),
		`SELECT task_id FROM variant_run_steps WHERE variant_run_id=$1 LIMIT 1`, out.VariantRunID,
	).Scan(&taskID); err != nil {
		t.Fatalf("dispatchVariantForTest: query task_id: %v", err)
	}
	return out.ScenarioRunID, out.VariantRunID, taskID
}

func TestUpsertVariantFindingsForRun_NonVariantScenario_NoOp(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := variantHandler(t, pool)
		h.upsertVariantFindingsForRun(context.Background(), "some-run", "sc-not-variant",
			[]models.SimulationResult{{ID: "t1", Result: models.ResultFail}})
		var n int
		pool.QueryRow(context.Background(), `SELECT COUNT(*) FROM variant_findings`).Scan(&n)
		if n != 0 {
			t.Fatalf("expected no-op for a non-variant scenario id, got %d finding rows", n)
		}
	})
}

func TestUpsertVariantFindingsForRun_NoVariantRun_NoOp(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := variantHandler(t, pool)
		h.upsertVariantFindingsForRun(context.Background(), "no-such-scenario-run", "__variant__t1059.001",
			[]models.SimulationResult{{ID: "t1", Result: models.ResultFail}})
		var n int
		pool.QueryRow(context.Background(), `SELECT COUNT(*) FROM variant_findings`).Scan(&n)
		if n != 0 {
			t.Fatalf("expected no-op when no variant_run links to the scenario_run, got %d finding rows", n)
		}
	})
}

func TestUpsertVariantFindingsForRun_AllowedCreatesFinding(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := variantHandler(t, pool)
		scenarioRunID, variantRunID, taskID := dispatchVariantForTest(t, h, pool, "uvf-allow-agent", "T1059.001", "")

		h.upsertVariantFindingsForRun(context.Background(), scenarioRunID, "__variant__t1059.001",
			[]models.SimulationResult{{ID: taskID, Result: models.ResultFail}})

		var gapSummary, recommendation string
		if err := pool.QueryRow(context.Background(),
			`SELECT gap_summary, recommendation FROM variant_findings WHERE variant_run_id=$1 AND task_id=$2`,
			variantRunID, taskID,
		).Scan(&gapSummary, &recommendation); err != nil {
			t.Fatalf("expected a variant_findings row: %v", err)
		}
		if gapSummary == "" || recommendation == "" {
			t.Errorf("gapSummary=%q recommendation=%q, want both populated", gapSummary, recommendation)
		}
	})
}

func TestUpsertVariantFindingsForRun_PassedDoesNotCreateFinding(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := variantHandler(t, pool)
		scenarioRunID, _, taskID := dispatchVariantForTest(t, h, pool, "uvf-pass-agent", "T1059.001", "")

		h.upsertVariantFindingsForRun(context.Background(), scenarioRunID, "__variant__t1059.001",
			[]models.SimulationResult{{ID: taskID, Result: models.ResultPass}})

		var n int
		pool.QueryRow(context.Background(), `SELECT COUNT(*) FROM variant_findings WHERE task_id=$1`, taskID).Scan(&n)
		if n != 0 {
			t.Fatalf("a PASS (blocked) result should not create a finding, got %d rows", n)
		}
	})
}

// TestUpsertVariantFindingsForRun_AdaptiveAutoCompletes pins adaptive mode:
// the first ALLOWED result closes the variant_run immediately.
func TestUpsertVariantFindingsForRun_AdaptiveAutoCompletes(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := variantHandler(t, pool)
		scenarioRunID, variantRunID, taskID := dispatchVariantForTest(t, h, pool, "uvf-adaptive-agent", "T1059.001", "adaptive")

		h.upsertVariantFindingsForRun(context.Background(), scenarioRunID, "__variant__t1059.001",
			[]models.SimulationResult{{ID: taskID, Result: models.ResultFail}})

		var status string
		pool.QueryRow(context.Background(), `SELECT status FROM variant_runs WHERE id=$1`, variantRunID).Scan(&status)
		if status != "completed" {
			t.Fatalf("variant_run status = %q, want completed (adaptive mode closes on first bypass)", status)
		}
	})
}

// TestUpsertVariantFindingsForRun_SequentialStaysRunning is the negative
// counterpart: sequential mode (the default) does NOT auto-close on a bypass.
func TestUpsertVariantFindingsForRun_SequentialStaysRunning(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := variantHandler(t, pool)
		scenarioRunID, variantRunID, taskID := dispatchVariantForTest(t, h, pool, "uvf-seq-agent", "T1059.001", "")

		h.upsertVariantFindingsForRun(context.Background(), scenarioRunID, "__variant__t1059.001",
			[]models.SimulationResult{{ID: taskID, Result: models.ResultFail}})

		var status string
		pool.QueryRow(context.Background(), `SELECT status FROM variant_runs WHERE id=$1`, variantRunID).Scan(&status)
		if status != "running" {
			t.Fatalf("variant_run status = %q, want running (sequential mode doesn't auto-close)", status)
		}
	})
}

// TestUpsertVariantFindingsForRun_RepeatedCallIsIdempotent pins the fixed
// dedup contract: variant_findings now has a unique index on
// (variant_run_id, task_id) (internal/db/postgres.go), so the `ON CONFLICT DO
// NOTHING` in upsertVariantFindingsForRun's INSERT has a real constraint to
// arbitrate against. Calling this function twice with the same ALLOWED
// result — as happens on an at-least-once result redelivery, see
// [[project_run_reconciliation]] — now produces exactly one row, not two.
func TestUpsertVariantFindingsForRun_RepeatedCallIsIdempotent(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := variantHandler(t, pool)
		scenarioRunID, variantRunID, taskID := dispatchVariantForTest(t, h, pool, "uvf-dup-agent", "T1059.001", "")

		results := []models.SimulationResult{{ID: taskID, Result: models.ResultFail}}
		h.upsertVariantFindingsForRun(context.Background(), scenarioRunID, "__variant__t1059.001", results)
		h.upsertVariantFindingsForRun(context.Background(), scenarioRunID, "__variant__t1059.001", results)

		var n int
		pool.QueryRow(context.Background(),
			`SELECT COUNT(*) FROM variant_findings WHERE variant_run_id=$1 AND task_id=$2`, variantRunID, taskID,
		).Scan(&n)
		if n != 1 {
			t.Fatalf("got %d rows after two identical calls, want 1 (unique index should dedup via ON CONFLICT DO NOTHING)", n)
		}
	})
}
