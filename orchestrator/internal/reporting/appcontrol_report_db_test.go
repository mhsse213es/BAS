package reporting

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/audspect/bas/internal/models"
	"github.com/jackc/pgx/v5/pgxpool"
)

// seedAppCtlRun inserts one completed run whose results are the given
// step results. Only the run's own row is written, so the test can show that
// BuildFromRun scopes the section to the run it was asked for.
func seedAppCtlRun(t *testing.T, pool *pgxpool.Pool, id, agent string, results []models.SimulationResult) {
	t.Helper()
	ctx := context.Background()
	rj, _ := json.Marshal(results)
	sj, _ := json.Marshal(models.Score{PreventionScore: 50, RiskScore: 50})
	if _, err := pool.Exec(ctx,
		`INSERT INTO scenario_runs (id, scenario_id, agent_id, name, status, results, score, started_at)
		 VALUES ($1,'scen-appctl',$2,'Application Control Efficacy','completed',$3,$4, NOW())`,
		id, agent, rj, sj); err != nil {
		t.Fatalf("seed run %s: %v", id, err)
	}
}

// The run report for one run shows that run's application-control evidence
// only. A run with no application-control steps shows no section.
func TestBuildFromRun_AppControlSectionMapsToItsRun(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		e := NewEngine(pool)
		const agent = "agent-appctl-run"
		if _, err := pool.Exec(ctx, `INSERT INTO agents (agent_id) VALUES ($1)`, agent); err != nil {
			t.Fatalf("seed agent: %v", err)
		}

		seedAppCtlRun(t, pool, "appctl-run-a", agent, []models.SimulationResult{
			appCtlResult("Application control indirect execution via cmd.exe parent (T1202)", "T1202", appCtlIndirectOut),
		})
		seedAppCtlRun(t, pool, "appctl-run-b", agent, []models.SimulationResult{
			appCtlResult("Application control alternate binary: renamed powershell.exe copy (T1036)", "T1036",
				"APPCTL_FAMILY: alternate_binary\nAPPCTL_DETECTION: source=sysmon_process_create result=not_visible\nAPPCTL_OUTCOME: allowed_unexpectedly\n"),
		})
		seedAppCtlRun(t, pool, "appctl-run-c", agent, []models.SimulationResult{
			{StepName: "Credential dumping", Technique: models.AttackTechnique{ID: "T1003"}, RawOutput: "PASS: nothing"},
		})

		repA, err := e.BuildFromRun(ctx, "appctl-run-a", "all")
		if err != nil {
			t.Fatalf("BuildFromRun A: %v", err)
		}
		if repA.AppControl.RunID != "appctl-run-a" {
			t.Errorf("section RunID = %q, want appctl-run-a", repA.AppControl.RunID)
		}
		if len(repA.AppControl.Rows) != 1 || repA.AppControl.Rows[0].Family != "indirect_execution" {
			t.Errorf("run A rows = %+v, want exactly its own indirect_execution row", repA.AppControl.Rows)
		}
		if st := familyStatus(t, repA.AppControl, "alternate_binary").Status; st != "not_run" {
			t.Errorf("run A alternate_binary = %q, want not_run (run B's evidence must not leak)", st)
		}

		repB, err := e.BuildFromRun(ctx, "appctl-run-b", "all")
		if err != nil {
			t.Fatalf("BuildFromRun B: %v", err)
		}
		if len(repB.AppControl.Rows) != 1 || repB.AppControl.Rows[0].Visibility != "not_visible" ||
			repB.AppControl.Rows[0].Outcome != "allowed_unexpectedly" {
			t.Errorf("run B row = %+v, want allowed_unexpectedly with not_visible telemetry", repB.AppControl.Rows)
		}
		if st := familyStatus(t, repB.AppControl, "indirect_execution").Status; st != "not_run" {
			t.Errorf("run B indirect_execution = %q, want not_run", st)
		}

		repC, err := e.BuildFromRun(ctx, "appctl-run-c", "all")
		if err != nil {
			t.Fatalf("BuildFromRun C: %v", err)
		}
		if repC.AppControl.HasData {
			t.Error("a run with no application-control steps must not show the section")
		}
	})
}
