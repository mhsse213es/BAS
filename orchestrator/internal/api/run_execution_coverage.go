package api

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/audspect/bas/internal/models"
	"github.com/jackc/pgx/v5/pgxpool"
)

// runExecutionCoverage tallies the execution outcome of every step in a stored run. An unknown run is an error, so a
// typo in the run ID cannot read as a run with no steps.
func runExecutionCoverage(ctx context.Context, pool *pgxpool.Pool, runID string) (models.ExecutionCoverage, error) {
	var raw []byte
	if err := pool.QueryRow(ctx, `SELECT COALESCE(results, '[]'::jsonb) FROM scenario_runs WHERE id = $1`, runID).Scan(&raw); err != nil {
		return models.ExecutionCoverage{}, fmt.Errorf("load run %s: %w", runID, err)
	}
	var results []models.SimulationResult
	if err := json.Unmarshal(raw, &results); err != nil {
		return models.ExecutionCoverage{}, fmt.Errorf("decode results for run %s: %w", runID, err)
	}
	return models.ComputeExecutionCoverage(results), nil
}
