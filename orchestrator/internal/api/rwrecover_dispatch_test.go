package api

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

// seedVSSChain submits the enumerate, deletion, and survival steps of one run
// together, the way the agent reports them. The deletion step's Recovery row
// is graded from the other two.
func seedVSSChain(t *testing.T, h *Handler, pool *pgxpool.Pool, runID, agentID, enumOut, deleteOut, survivalOut string) {
	t.Helper()
	enumName, delName, survName := "VSS Snapshot Enumeration (lab)", "VSS Shadow Copy Deletion (lab)", "Post-Deletion Survival Check (lab)"
	enumTask := scenario.TaskID("T1490", enumName)
	delTask := scenario.TaskID("T1490", delName)
	survTask := scenario.TaskID("T1490", survName)
	seedRunRow(t, pool, runID, "akira-kill-chain", agentID, "running")
	raw, err := json.Marshal(map[string]scenario.StepMeta{
		enumTask: {TechniqueID: "T1490", Name: enumName, Framework: "custom", ActionKey: "enumerate"},
		delTask:  {TechniqueID: "T1490", Name: delName, Framework: "custom", ActionKey: "vss_delete"},
		survTask: {TechniqueID: "T1490", Name: survName, Framework: "custom", ActionKey: "survival"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(context.Background(), `UPDATE scenario_runs SET step_meta=$2 WHERE id=$1`, runID, raw); err != nil {
		t.Fatal(err)
	}
	submitResultOK(t, h, scenario.RawRunResult{
		RunID: runID, ScenarioID: "akira-kill-chain", AgentID: agentID,
		Results: []scenario.ExecResult{
			{TaskID: enumTask, ExitCode: 0, Stdout: enumOut},
			{TaskID: delTask, ExitCode: 0, Stdout: deleteOut},
			{TaskID: survTask, ExitCode: 0, Stdout: survivalOut},
		},
	})
}

func recoveryVerdict(t *testing.T, pool *pgxpool.Pool, runID string) string {
	t.Helper()
	var verdict string
	if err := pool.QueryRow(context.Background(),
		`SELECT verdict FROM rw_capability_results WHERE run_id=$1 AND capability='recovery' AND action=$2`,
		runID, scenario.TaskID("T1490", "VSS Shadow Copy Deletion (lab)")).Scan(&verdict); err != nil {
		t.Fatalf("read recovery row for %s: %v", runID, err)
	}
	return verdict
}

func TestRWRecovery_CopyCountDroppedFailsRecovery(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		runID := "rwrec-lost"
		seedVSSChain(t, h, pool, runID, "agent-rwrec-lost",
			"EXEC T1490: 2 VSS shadow copy(ies) enumerated. [BAS-SIM-AKIRA-S7]",
			"FAIL: VSS shadow copy deleted (test fixture). [BAS-SIM-AKIRA-S8]",
			"EXEC T1490: survival check -- 1 VSS shadow copy(ies) present after the deletion step. [BAS-SIM-AKIRA-S8B]")
		if v := recoveryVerdict(t, pool, runID); v != "FAIL" {
			t.Fatalf("recovery verdict = %q, want FAIL (copies were destroyed)", v)
		}
	})
}

func TestRWRecovery_NoSurvivalStepLeavesRecoveryNotTested(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		runID := "rwrec-nosurv"
		enumName, delName := "VSS Snapshot Enumeration (lab)", "VSS Shadow Copy Deletion (lab)"
		enumTask := scenario.TaskID("T1490", enumName)
		delTask := scenario.TaskID("T1490", delName)
		seedRunRow(t, pool, runID, "akira-kill-chain", "agent-rwrec-nosurv", "running")
		raw, _ := json.Marshal(map[string]scenario.StepMeta{
			enumTask: {TechniqueID: "T1490", Name: enumName, Framework: "custom", ActionKey: "enumerate"},
			delTask:  {TechniqueID: "T1490", Name: delName, Framework: "custom", ActionKey: "vss_delete"},
		})
		if _, err := pool.Exec(context.Background(), `UPDATE scenario_runs SET step_meta=$2 WHERE id=$1`, runID, raw); err != nil {
			t.Fatal(err)
		}
		submitResultOK(t, h, scenario.RawRunResult{
			RunID: runID, ScenarioID: "akira-kill-chain", AgentID: "agent-rwrec-nosurv",
			Results: []scenario.ExecResult{
				{TaskID: enumTask, ExitCode: 0, Stdout: "EXEC T1490: 2 VSS shadow copy(ies) enumerated."},
				{TaskID: delTask, ExitCode: 0, Stdout: "FAIL: VSS shadow copy deleted (test fixture)."},
			},
		})
		if v := recoveryVerdict(t, pool, runID); v != "SKIPPED" {
			t.Fatalf("recovery verdict = %q, want SKIPPED without a survival check", v)
		}
	})
}
