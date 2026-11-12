package api

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/audspect/bas/internal/models"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestRunExecutionCoverage_CountsEachOutcome(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedRunRow(t, pool, "cov-run-1", "sc-cov", "agent-cov", "completed")
		results := []models.SimulationResult{
			{Result: models.ResultPass},
			{Result: models.ResultBlocked},
			{Result: models.ResultError, ExecutionFailure: &models.ExecutionFailure{ExecutionStatus: "not_executed"}},
			{Result: models.ResultSkipped, SkipReason: "platform-unavailable"},
		}
		raw, err := json.Marshal(results)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(context.Background(), `UPDATE scenario_runs SET results = $2::jsonb WHERE id = $1`, "cov-run-1", string(raw)); err != nil {
			t.Fatalf("seed results: %v", err)
		}

		c, err := runExecutionCoverage(context.Background(), pool, "cov-run-1")
		if err != nil {
			t.Fatalf("runExecutionCoverage: %v", err)
		}
		if c.Scheduled != 4 || c.Executed != 1 || c.Prevented != 1 || c.NotExecuted != 1 || c.Unsupported != 1 {
			t.Errorf("coverage = %+v", c)
		}
		if c.CoveragePct != 50 {
			t.Errorf("CoveragePct = %v, want 50", c.CoveragePct)
		}
	})
}

func TestRunExecutionCoverage_UnknownRunIsAnError(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		if _, err := runExecutionCoverage(context.Background(), pool, "no-such-run"); err == nil {
			t.Error("expected an error for a run that does not exist")
		}
	})
}
