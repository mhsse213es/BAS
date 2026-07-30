package analytics

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

func TestFleetRisk_AveragesRecentCompletedRuns(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExec(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('a1', 'HOST-1')`)
		mustExec(t, pool, `
			INSERT INTO scenario_runs (scenario_id, agent_id, status, score, completed_at)
			VALUES ('scn-1', 'a1', 'completed', '{"riskScore": 42}'::jsonb, NOW())`)
		mustExec(t, pool, `
			INSERT INTO scenario_runs (scenario_id, agent_id, status, score, completed_at)
			VALUES ('scn-2', 'a1', 'completed', '{"riskScore": 58}'::jsonb, NOW())`)
		// Old run, outside the 30-day window -- must not affect the average.
		mustExec(t, pool, `
			INSERT INTO scenario_runs (scenario_id, agent_id, status, score, completed_at)
			VALUES ('scn-3', 'a1', 'completed', '{"riskScore": 0}'::jsonb, NOW() - INTERVAL '90 days')`)

		got, err := FleetRisk(context.Background(), pool)
		if err != nil {
			t.Fatalf("FleetRisk: %v", err)
		}
		if got.FleetAvgScore != 50 {
			t.Errorf("FleetAvgScore = %d, want 50 (avg of 42 and 58, excluding the 90-day-old run)", got.FleetAvgScore)
		}
	})
}

func TestFleetRisk_NoCompletedRuns_ReturnsZero(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		got, err := FleetRisk(context.Background(), pool)
		if err != nil {
			t.Fatalf("FleetRisk: %v", err)
		}
		if got.FleetAvgScore != 0 {
			t.Errorf("FleetAvgScore = %d, want 0 (no completed runs)", got.FleetAvgScore)
		}
	})
}
