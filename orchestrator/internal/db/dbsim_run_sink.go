package db

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

// CountDBSimRunsForRun returns how many graded rows a database run has stored
// (the deadline reaper uses it to tell failed from partial).
func CountDBSimRunsForRun(ctx context.Context, pool *pgxpool.Pool, runID string) (int, error) {
	var n int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM dbsim_runs WHERE run_id = $1`, runID).Scan(&n); err != nil {
		return 0, fmt.Errorf("count dbsim runs: %w", err)
	}
	return n, nil
}
