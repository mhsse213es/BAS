package db

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrAPIBASJobPlanNotFound means the job has no stored plan.
var ErrAPIBASJobPlanNotFound = errors.New("apibas job plan not found")

// SaveAPIBASJobPlan stores the customer-bound plan a job runs from: the inventory and test data as they were at submission, so the
// job is reproducible and a later edit of either cannot change what ran. The plan holds credential names, never values.
func SaveAPIBASJobPlan(ctx context.Context, pool *pgxpool.Pool, jobID string, inventoryVersion int, plan []byte) error {
	_, err := pool.Exec(ctx, `INSERT INTO apibas_job_plans (job_id, inventory_version, plan) VALUES ($1, $2, $3::jsonb) ON CONFLICT (job_id) DO NOTHING`,
		jobID, inventoryVersion, string(plan))
	if err != nil {
		return fmt.Errorf("save apibas job plan: %w", err)
	}
	return nil
}

// GetAPIBASJobPlan returns the stored plan of a job.
func GetAPIBASJobPlan(ctx context.Context, pool *pgxpool.Pool, jobID string) ([]byte, error) {
	var plan string
	err := pool.QueryRow(ctx, `SELECT plan::text FROM apibas_job_plans WHERE job_id = $1`, jobID).Scan(&plan)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrAPIBASJobPlanNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("read apibas job plan: %w", err)
	}
	return []byte(plan), nil
}
