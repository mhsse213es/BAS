package detecteffectiveness

import (
	"context"
	"flag"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/testutil"
)

var sharedDB *testutil.TestDB

func TestMain(m *testing.M) {
	flag.Parse()
	if testing.Short() {
		os.Exit(m.Run())
	}
	sharedDB = testutil.MustSharedTestDB()
	code := m.Run()
	sharedDB.Cleanup()
	os.Exit(code)
}

func mustExec(t *testing.T, pool *pgxpool.Pool, sql string, args ...any) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), sql, args...); err != nil {
		t.Fatalf("exec %q: %v", sql, err)
	}
}

const seedResults = `[
	{"technique":{"id":"T1059","name":"Command and Scripting Interpreter","tactic":"execution"},"result":"pass"},
	{"technique":{"id":"T1003","name":"OS Credential Dumping","tactic":"credential-access"},"result":"fail"},
	{"technique":{"id":"T1078","name":"Valid Accounts","tactic":"defense-evasion"},"result":"fail"}
]`

const seedDetectionSummary = `{"techniques":[{"techniqueId":"T1003","verdict":"detected"}]}`

func TestCompute_TalliesPreventedDetectedOnlyMissed(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExec(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('a1', 'HOST-1')`)
		mustExec(t, pool, `
			INSERT INTO scenario_runs (id, scenario_id, name, agent_id, status, results, detection_summary, started_at)
			VALUES ('run-1', 'scn-1', 'Test Run', 'a1', 'completed', $1, $2, NOW())`,
			seedResults, seedDetectionSummary)

		got, err := Compute(context.Background(), pool, "", "", 20)
		if err != nil {
			t.Fatalf("Compute: %v", err)
		}
		if got.RunsAnalyzed != 1 {
			t.Fatalf("RunsAnalyzed = %d, want 1", got.RunsAnalyzed)
		}
		want := AnalyticsSummary{Attempted: 3, Prevented: 1, DetectedOnly: 1, Missed: 1, PreventionRate: 33, DetectionCoverage: 66}
		if got.Summary != want {
			t.Errorf("Summary = %+v, want %+v (T1059=prevented, T1003=detectedOnly via sweep, T1078=missed)", got.Summary, want)
		}
		if len(got.ByTactic) != 3 {
			t.Fatalf("ByTactic = %+v, want 3 tactics (execution/credential-access/defense-evasion)", got.ByTactic)
		}
	})
}

func TestCompute_FiltersByScenarioID(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExec(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('a1', 'HOST-1')`)
		mustExec(t, pool, `
			INSERT INTO scenario_runs (id, scenario_id, name, agent_id, status, results, started_at)
			VALUES ('run-1', 'scn-1', 'Run 1', 'a1', 'completed', $1, NOW())`, seedResults)
		mustExec(t, pool, `
			INSERT INTO scenario_runs (id, scenario_id, name, agent_id, status, results, started_at)
			VALUES ('run-2', 'scn-2', 'Run 2', 'a1', 'completed', $1, NOW())`, seedResults)

		got, err := Compute(context.Background(), pool, "scn-1", "", 20)
		if err != nil {
			t.Fatalf("Compute: %v", err)
		}
		if got.RunsAnalyzed != 1 {
			t.Fatalf("RunsAnalyzed = %d, want 1 (filtered to scn-1 only)", got.RunsAnalyzed)
		}
		if len(got.RecentRuns) != 1 || got.RecentRuns[0].ScenarioID != "scn-1" {
			t.Errorf("RecentRuns = %+v, want exactly the scn-1 run", got.RecentRuns)
		}
	})
}

func TestCompute_NoRuns_ReturnsZeroSummary(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		got, err := Compute(context.Background(), pool, "", "", 20)
		if err != nil {
			t.Fatalf("Compute: %v", err)
		}
		if got.RunsAnalyzed != 0 || got.Summary != (AnalyticsSummary{}) {
			t.Errorf("Compute() = %+v, want zero-value on an empty fleet (no divide-by-zero panic)", got)
		}
	})
}
