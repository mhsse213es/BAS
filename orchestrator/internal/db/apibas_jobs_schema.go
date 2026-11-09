package db

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

// EnsureAPIBASJobSchema creates the API BAS assessment job tables. A job is one orchestrator-owned execution of the
// runner against one target. apibas_jobs holds its lifecycle and audit fields; apibas_job_reports holds one row per
// scenario report. Reports are written in the same transaction that marks the job completed, so a completed job always
// has its complete set of reports.
//
// This is deliberately separate from apibas_runs, which records lab builds (build must be vulnerable or fixed). A target
// assessment has no such build.
func EnsureAPIBASJobSchema(ctx context.Context, pool *pgxpool.Pool) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS apibas_targets (
			id                text        PRIMARY KEY CHECK (id ~ '^[a-z0-9][a-z0-9_-]{1,62}$'),
			name              text        NOT NULL,
			base_url          text        NOT NULL,
			environment       text        NOT NULL CHECK (environment IN ('lab', 'staging', 'production')),
			allowed_hosts     jsonb       NOT NULL DEFAULT '[]',
			allowed_scenarios jsonb       NOT NULL DEFAULT '[]',
			credential_refs   jsonb       NOT NULL DEFAULT '{}',
			enabled           boolean     NOT NULL DEFAULT true,
			created_by        text        NOT NULL,
			created_at        timestamptz NOT NULL DEFAULT NOW()
		)`,
		`CREATE TABLE IF NOT EXISTS apibas_approvals (
			id           uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
			binding_hash text        NOT NULL,
			target_id    text        NOT NULL,
			requested_by text        NOT NULL,
			approved_by  text        NOT NULL DEFAULT '',
			approved_at  timestamptz,
			created_at   timestamptz NOT NULL DEFAULT NOW()
		)`,
		`CREATE TABLE IF NOT EXISTS apibas_jobs (
			id              uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
			job_key         text        NOT NULL UNIQUE,
			requested_by    text        NOT NULL,
			target_base_url text        NOT NULL,
			environment     text        NOT NULL CHECK (environment IN ('lab', 'staging')),
			fixture         text        NOT NULL,
			scenario_ids    jsonb       NOT NULL,
			credential_refs jsonb       NOT NULL DEFAULT '{}',
			status          text        NOT NULL CHECK (status IN ('queued', 'running', 'completed', 'failed', 'cancelled')),
			failure_reason  text        NOT NULL DEFAULT '',
			created_at      timestamptz NOT NULL DEFAULT NOW(),
			started_at      timestamptz,
			finished_at     timestamptz
		)`,
		`ALTER TABLE apibas_jobs ADD COLUMN IF NOT EXISTS target_id text NOT NULL DEFAULT ''`,
		`CREATE INDEX IF NOT EXISTS apibas_jobs_target_active_idx ON apibas_jobs (target_id) WHERE status IN ('queued', 'running')`,
		`CREATE TABLE IF NOT EXISTS apibas_job_reports (
			job_id         uuid        NOT NULL REFERENCES apibas_jobs(id) ON DELETE CASCADE,
			scenario_id    text        NOT NULL,
			run_tag        text        NOT NULL,
			result         text        NOT NULL CHECK (result IN ('PASS', 'FAIL', 'ERROR', 'SKIPPED')),
			exploitability text        NOT NULL DEFAULT '',
			control        text        NOT NULL DEFAULT '',
			detection      text        NOT NULL DEFAULT '',
			reason         text        NOT NULL DEFAULT '',
			report         jsonb       NOT NULL,
			created_at     timestamptz NOT NULL DEFAULT NOW(),
			PRIMARY KEY (job_id, scenario_id)
		)`,
	}
	for _, s := range stmts {
		if _, err := pool.Exec(ctx, s); err != nil {
			return fmt.Errorf("ensure apibas job schema: %w", err)
		}
	}
	return nil
}
