package analytics

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// A fleet average over zero scored runs is "not measured", not a perfect score of 0. A genuine 0 (every run
// fully prevented) is measured. Runs without a score do not count.
func TestFleetRisk_MeasurableOnlyWithScoredRuns(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		got, err := FleetRisk(ctx, pool)
		if err != nil {
			t.Fatalf("FleetRisk: %v", err)
		}
		if got.Measurable || got.ScoredRuns != 0 || got.FleetAvgScore != 0 {
			t.Fatalf("no runs: got %+v, want not measurable, 0 scored runs", got)
		}

		mustExec(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('a1', 'HOST-1')`)
		// Completed but unscored, and a scored run outside the window: neither makes the fleet measurable.
		mustExec(t, pool, `INSERT INTO scenario_runs (scenario_id, agent_id, status, completed_at) VALUES ('s0', 'a1', 'completed', NOW())`)
		mustExec(t, pool, `INSERT INTO scenario_runs (scenario_id, agent_id, status, score, completed_at)
			VALUES ('s1', 'a1', 'completed', '{"riskScore": 30}'::jsonb, NOW() - INTERVAL '90 days')`)
		got, err = FleetRisk(ctx, pool)
		if err != nil {
			t.Fatalf("FleetRisk: %v", err)
		}
		if got.Measurable || got.ScoredRuns != 0 {
			t.Fatalf("unscored/out-of-window runs: got %+v, want not measurable", got)
		}

		// A genuine zero risk is a measurement.
		mustExec(t, pool, `INSERT INTO scenario_runs (scenario_id, agent_id, status, score, completed_at)
			VALUES ('s2', 'a1', 'completed', '{"riskScore": 0}'::jsonb, NOW())`)
		got, err = FleetRisk(ctx, pool)
		if err != nil {
			t.Fatalf("FleetRisk: %v", err)
		}
		if !got.Measurable || got.ScoredRuns != 1 || got.FleetAvgScore != 0 {
			t.Fatalf("one scored run at 0: got %+v, want measurable, 1 scored run, avg 0", got)
		}
	})
}
