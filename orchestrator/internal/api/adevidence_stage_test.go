package api

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

// The two DCSync control stages must each keep their own evidence row. A
// shared action would let the positive stage overwrite the negative one.
func TestADEvidence_NegativeAndPositiveStagesAreDistinct(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		runID := "ad-two-stages"
		seedRunRow(t, pool, runID, "dcsync-replication-rights-live-verification", "agent-ad-two", "running")

		neg := "Stage 1 — Negative Control"
		pos := "Stage 2 — Positive Control"
		negTask := scenario.TaskID("T1003.006", neg)
		posTask := scenario.TaskID("T1003.006", pos)
		raw, err := json.Marshal(map[string]scenario.StepMeta{
			negTask: {TechniqueID: "T1003.006", Name: neg, Framework: "custom", ActionKey: "negative"},
			posTask: {TechniqueID: "T1003.006", Name: pos, Framework: "custom", ActionKey: "positive"},
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(context.Background(), `UPDATE scenario_runs SET step_meta=$2 WHERE id=$1`, runID, raw); err != nil {
			t.Fatal(err)
		}

		submitResultOK(t, h, scenario.RawRunResult{
			RunID: runID, ScenarioID: "dcsync-replication-rights-live-verification", AgentID: "agent-ad-two",
			Results: []scenario.ExecResult{
				{TaskID: negTask, ExitCode: 0, Stdout: "EXEC T1003.006: replication request as the rights-less principal was refused (access denied), as expected of the control. [BAS-SIM-DCSYNC-NEG]"},
				{TaskID: posTask, ExitCode: 0, Stdout: "EXEC T1003.006: replication request as the rights-holding principal returned account data, as expected when the control correctly honours granted rights. [BAS-SIM-DCSYNC-POS]"},
			},
		})

		var rows int
		if err := pool.QueryRow(context.Background(), `SELECT COUNT(*) FROM ad_control_verifications WHERE run_id=$1`, runID).Scan(&rows); err != nil {
			t.Fatal(err)
		}
		if rows != 2 {
			t.Fatalf("got %d ad_control_verifications rows, want 2 (one per stage)", rows)
		}
	})
}
