package analytics

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestDetectionEffectiveness_EmptyFleet_ReturnsZeroSummary(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		got, err := DetectionEffectiveness(context.Background(), pool, "", "", 20)
		if err != nil {
			t.Fatalf("DetectionEffectiveness: %v", err)
		}
		if got.RunsAnalyzed != 0 {
			t.Errorf("RunsAnalyzed = %d, want 0 on an empty fleet", got.RunsAnalyzed)
		}
	})
}

func TestDetectionEffectiveness_DelegatesToCompute(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExec(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('a1', 'HOST-1')`)
		mustExec(t, pool, `
			INSERT INTO scenario_runs (id, scenario_id, name, agent_id, status, results, started_at)
			VALUES ('run-1', 'scn-1', 'Test Run', 'a1', 'completed',
				'[{"technique":{"id":"T1059","name":"Command and Scripting Interpreter","tactic":"execution"},"result":"pass"}]', NOW())`)

		got, err := DetectionEffectiveness(context.Background(), pool, "", "", 20)
		if err != nil {
			t.Fatalf("DetectionEffectiveness: %v", err)
		}
		if got.RunsAnalyzed != 1 || got.Summary.Prevented != 1 {
			t.Errorf("DetectionEffectiveness() = %+v, want RunsAnalyzed=1 Summary.Prevented=1", got)
		}
	})
}
