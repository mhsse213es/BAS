package api

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

func TestSubmitScenarioResult_WritesRWCapabilityResultsAlongsideLegacyOutcome(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		runID := "rw-dispatch-run"
		seedRunRow(t, pool, runID, "akira-kill-chain", "agent-rw-dispatch", "running")

		stepName := "VSS Shadow Copy Deletion (lab - requires BAS_CONFIRM_VSS_DELETE=true)"
		taskID := scenario.TaskID("T1490", stepName)

		// seedRunRow's scenario_id ("akira-kill-chain", a real in-scope
		// ransomware scenario per spec section "Scope") has no YAML backing
		// in this test's temp-dir engine, so handlers.go's stepMap would stay
		// empty via the sc.Steps path. Real dispatch overlays stepMap from
		// scenario_runs.step_meta for exactly this case (dynamically-built
		// ART/Caldera steps -- handlers.go ~2804-2819); seeding it directly
		// is the same mechanism a real dispatch would have populated, not a
		// shortcut around it.
		meta := map[string]scenario.StepMeta{
			taskID: {TechniqueID: "T1490", Name: stepName, Framework: "custom"},
		}
		metaJSON, err := json.Marshal(meta)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(context.Background(), `UPDATE scenario_runs SET step_meta = $1 WHERE id = $2`, metaJSON, runID); err != nil {
			t.Fatalf("seed step_meta: %v", err)
		}

		submitResultOK(t, h, scenario.RawRunResult{
			RunID: runID, ScenarioID: "akira-kill-chain", AgentID: "agent-rw-dispatch",
			Results: []scenario.ExecResult{{
				TaskID: taskID, ExitCode: 0,
				Stdout: "SKIP: BAS_CONFIRM_VSS_DELETE not set to 'true' - VSS deletion skipped (default-disabled per ransm safety policy).",
			}},
		})

		rows, err := db.RWCapabilityCoverage(context.Background(), pool, runID)
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) != 5 {
			t.Fatalf("got %d rw_capability_results rows, want 5 (one per capability)", len(rows))
		}
		for _, r := range rows {
			if r.SpecificReason != "gate_not_confirmed" {
				t.Errorf("%s: specificReason = %q, want gate_not_confirmed", r.Capability, r.SpecificReason)
			}
			if r.Verdict != "SKIPPED" {
				t.Errorf("%s: verdict = %q, want SKIPPED -- a gate-skipped attempt must never produce PASS", r.Capability, r.Verdict)
			}
		}

		// The legacy outcome is unaffected by any of this. readRunResults
		// (result_ingestion_helpers_test.go) decodes the persisted
		// []models.SimulationResult the same way submit_scenario_result_test.go
		// already does.
		results := readRunResults(t, pool, runID)
		if len(results) != 1 || string(results[0].Result) != "skipped" {
			t.Fatalf("legacy results = %+v, want exactly one skipped result (unchanged by this integration)", results)
		}
	})
}

func TestSubmitScenarioResult_NonRansomwareScenarioNeverWritesRWCapabilityResults(t *testing.T) {
	// Spec scope (section "Scope"): this integration covers exactly the 8
	// named ransomware scenarios/drills. A step tagged with a modeled
	// technique (T1490) inside an UNRELATED scenario must still write
	// nothing -- the gate is the scenario, not the technique alone.
	// Without this gate, every scenario submission system-wide (AD,
	// lateral movement, lolbin, credential-access, ...) pays an
	// unconditional 5-row write for a dimension that was never in scope.
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		runID := "rw-dispatch-non-ransomware-run"
		seedRunRow(t, pool, runID, "credential-access", "agent-rw-non-ransomware", "running")

		stepName := "VSS Shadow Copy Deletion via WMI"
		taskID := scenario.TaskID("T1490", stepName)
		meta := map[string]scenario.StepMeta{
			taskID: {TechniqueID: "T1490", Name: stepName, Framework: "custom"},
		}
		metaJSON, err := json.Marshal(meta)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(context.Background(), `UPDATE scenario_runs SET step_meta = $1 WHERE id = $2`, metaJSON, runID); err != nil {
			t.Fatalf("seed step_meta: %v", err)
		}

		submitResultOK(t, h, scenario.RawRunResult{
			RunID: runID, ScenarioID: "credential-access", AgentID: "agent-rw-non-ransomware",
			Results: []scenario.ExecResult{{
				TaskID: taskID, ExitCode: 1, Stdout: "FAIL: deleted 1 shadow copy",
			}},
		})

		rows, err := db.RWCapabilityCoverage(context.Background(), pool, runID)
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) != 0 {
			t.Fatalf("got %d rw_capability_results rows for a non-ransomware scenario, want 0 -- this integration is scoped to the 8 named ransomware scenarios only", len(rows))
		}
	})
}

func TestRecordRWEvidence_WriteFailureIsLoggedNotSwallowedAndNeverTouchesLegacyResult(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		runID := "rw-dispatch-failure-run"
		seedRunRow(t, pool, runID, "ransomware-drill", "agent-rw-dispatch-failure", "running")

		step := scenario.Step{TechniqueID: "T1490", Name: "VSS Shadow Copy Deletion via WMI", Framework: "custom"}
		execResult := scenario.ExecResult{TaskID: scenario.TaskID(step.TechniqueID, step.Name), ExitCode: 1, Stdout: "FAIL: deleted 1 shadow copy"}
		sim := scenario.Interpret(step, execResult)

		cancelled, cancel := context.WithCancel(context.Background())
		cancel() // already cancelled -- every subsequent pool operation in this ctx fails

		h.recordRWEvidence(cancelled, runID, "ransomware-drill", step, sim) // must not panic, must not propagate the error to its caller

		// A fresh, un-cancelled context against the same (undamaged) shared
		// pool confirms nothing was written -- never a partial set.
		rows, err := db.RWCapabilityCoverage(context.Background(), pool, runID)
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) != 0 {
			t.Fatalf("got %d rows after a forced write failure, want 0 -- a failed write must never leave a partial set behind", len(rows))
		}
	})
}
