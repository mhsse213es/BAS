package db

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
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
