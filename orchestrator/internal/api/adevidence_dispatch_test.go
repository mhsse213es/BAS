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

func TestSubmitScenarioResult_WritesADControlVerificationForDCSync(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		runID := "ad-dispatch-run"
		seedRunRow(t, pool, runID, "dcsync-replication-rights-live-verification", "agent-ad-dispatch", "running")

		stepName := "Stage 1 — Negative Control: Replication Request Without Rights (T1003.006)"
		taskID := scenario.TaskID("T1003.006", stepName)
		meta := map[string]scenario.StepMeta{
			taskID: {TechniqueID: "T1003.006", Name: stepName, Framework: "custom"},
		}
		metaJSON, err := json.Marshal(meta)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(context.Background(), `UPDATE scenario_runs SET step_meta = $1 WHERE id = $2`, metaJSON, runID); err != nil {
			t.Fatalf("seed step_meta: %v", err)
		}

		submitResultOK(t, h, scenario.RawRunResult{
			RunID: runID, ScenarioID: "dcsync-replication-rights-live-verification", AgentID: "agent-ad-dispatch",
			Results: []scenario.ExecResult{{
				TaskID: taskID, ExitCode: 0,
				Stdout: "EXEC T1003.006: replication request as the rights-less principal was refused (access denied), as expected of the control. [BAS-SIM-DCSYNC-NEG]",
			}},
		})

		got, found, err := db.LatestADControlVerification(context.Background(), pool, "dcsync")
		if err != nil {
			t.Fatal(err)
		}
		if !found {
			t.Fatal("expected an ad_control_verifications row for the dcsync primitive")
		}
		if got.DRSUAPIResult != "access_denied" {
			t.Fatalf("DRSUAPIResult = %q, want access_denied", got.DRSUAPIResult)
		}
	})
}

func TestSubmitScenarioResult_NeverWritesADControlVerificationOutsideScope(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		runID := "ad-dispatch-out-of-scope"
		seedRunRow(t, pool, runID, "akira-kill-chain", "agent-ad-dispatch-2", "running")

		stepName := "Some Other Technique Step"
		taskID := scenario.TaskID("T1003.006", stepName)
		meta := map[string]scenario.StepMeta{
			taskID: {TechniqueID: "T1003.006", Name: stepName, Framework: "custom"},
		}
		metaJSON, err := json.Marshal(meta)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(context.Background(), `UPDATE scenario_runs SET step_meta = $1 WHERE id = $2`, metaJSON, runID); err != nil {
			t.Fatalf("seed step_meta: %v", err)
		}

		submitResultOK(t, h, scenario.RawRunResult{
			RunID: runID, ScenarioID: "akira-kill-chain", AgentID: "agent-ad-dispatch-2",
			Results: []scenario.ExecResult{{
				TaskID: taskID, ExitCode: 0,
				Stdout: "EXEC T1003.006: replication request as the rights-less principal was refused (access denied), as expected of the control. [BAS-SIM-DCSYNC-NEG]",
			}},
		})

		// akira-kill-chain is not in adControlScenarioIDs -- even though the
		// output text would parse cleanly, no row should be written for it.
		rows, err := pool.Query(context.Background(), `SELECT 1 FROM ad_control_verifications WHERE run_id = $1`, runID)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		if rows.Next() {
			t.Fatal("expected no ad_control_verifications row for a scenario outside adControlScenarioIDs")
		}
	})
}
