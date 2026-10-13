package db

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/cloudrun"
)

// EnsureCloudRunSchema creates the cloud_runs table -- the execution-tracking
// record for one cloud scenario run against one account scope. See
// docs/superpowers/specs/2026-10-13-cloud-run-data-model-design.md. Unlike
// scenario_runs, there is deliberately no agent_id / FK to agents: a cloud
// scenario has no endpoint agent to dispatch to.
func EnsureCloudRunSchema(ctx context.Context, pool *pgxpool.Pool) error {
	_, err := pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS cloud_runs (
			id            text        PRIMARY KEY DEFAULT gen_random_uuid()::text,
			scenario_id   text        NOT NULL,
			provider      text        NOT NULL,
			account_id    text        NOT NULL DEFAULT '',
			tenant_id     text        NOT NULL DEFAULT '',
			region        text        NOT NULL DEFAULT '',
			status        text        NOT NULL DEFAULT 'pending',
			result        jsonb,
			error         text,
			initiated_by  text,
			started_at    timestamptz NOT NULL DEFAULT NOW(),
			completed_at  timestamptz,
			CONSTRAINT cloud_runs_status_check   CHECK (status IN ('pending','running','completed','failed','partial')),
			CONSTRAINT cloud_runs_provider_check CHECK (provider IN ('aws','azure','gcp'))
		)`)
	if err != nil {
		return fmt.Errorf("cloud_runs: ensure schema: %w", err)
	}
	return nil
}

// InsertCloudRun writes a new cloud_runs row. The caller supplies run.ID
// already generated (matching scenario_runs' existing convention of
// generating the run ID in Go before insert) and run.Status explicitly --
// the column's DEFAULT 'pending' is a fallback for direct SQL, not relied
// on here, since the lifecycle spec leaves "created pending or running" to
// the caller.
func InsertCloudRun(ctx context.Context, pool *pgxpool.Pool, run *cloudrun.CloudRun) error {
	_, err := pool.Exec(ctx, `
		INSERT INTO cloud_runs (id, scenario_id, provider, account_id, tenant_id, region, status, result, error, initiated_by, started_at, completed_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
		run.ID, run.ScenarioID, run.Provider, run.AccountID, run.TenantID, run.Region,
		string(run.Status), run.Result, run.Error, run.InitiatedBy, run.StartedAt, run.CompletedAt)
	if err != nil {
		return fmt.Errorf("cloud_runs: insert %s: %w", run.ID, err)
	}
	return nil
}

// scanCloudRun scans one cloud_runs row, shared by GetCloudRun and
// ListCloudRuns so the column list exists in exactly one place.
func scanCloudRun(row pgx.Row) (*cloudrun.CloudRun, error) {
	run := &cloudrun.CloudRun{}
	var status string
	if err := row.Scan(&run.ID, &run.ScenarioID, &run.Provider, &run.AccountID, &run.TenantID, &run.Region,
		&status, &run.Result, &run.Error, &run.InitiatedBy, &run.StartedAt, &run.CompletedAt); err != nil {
		return nil, err
	}
	run.Status = cloudrun.Status(status)
	return run, nil
}

// GetCloudRun returns one cloud_runs row by id. A missing id returns an
// error satisfying errors.Is(err, pgx.ErrNoRows) -- the standard pgx idiom,
// not a custom "not found" sentinel.
func GetCloudRun(ctx context.Context, pool *pgxpool.Pool, id string) (*cloudrun.CloudRun, error) {
	row := pool.QueryRow(ctx, `
		SELECT id, scenario_id, provider, account_id, tenant_id, region, status, result, error, initiated_by, started_at, completed_at
		FROM cloud_runs WHERE id = $1`, id)
	run, err := scanCloudRun(row)
	if err != nil {
		return nil, fmt.Errorf("cloud_runs: get %s: %w", id, err)
	}
	return run, nil
}
