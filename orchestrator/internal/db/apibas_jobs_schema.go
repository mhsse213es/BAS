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
		`ALTER TABLE apibas_approvals ADD COLUMN IF NOT EXISTS expires_at timestamptz`,
		`ALTER TABLE apibas_approvals ADD COLUMN IF NOT EXISTS revoked_by text NOT NULL DEFAULT ''`,
		`ALTER TABLE apibas_approvals ADD COLUMN IF NOT EXISTS revoked_at timestamptz`,
		`ALTER TABLE apibas_approvals ADD COLUMN IF NOT EXISTS revoke_reason text NOT NULL DEFAULT ''`,
		`ALTER TABLE apibas_approvals ADD COLUMN IF NOT EXISTS consumed_by_job text NOT NULL DEFAULT ''`,
		`ALTER TABLE apibas_approvals ADD COLUMN IF NOT EXISTS consumed_at timestamptz`,
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
		`ALTER TABLE apibas_jobs ADD COLUMN IF NOT EXISTS allowed_hosts jsonb NOT NULL DEFAULT '[]'`,
		`ALTER TABLE apibas_jobs ADD COLUMN IF NOT EXISTS allowed_paths jsonb NOT NULL DEFAULT '[]'`,
		`ALTER TABLE apibas_targets ADD COLUMN IF NOT EXISTS allowed_paths jsonb NOT NULL DEFAULT '[]'`,
		`CREATE INDEX IF NOT EXISTS apibas_jobs_target_active_idx ON apibas_jobs (target_id) WHERE status IN ('queued', 'running')`,
		`CREATE TABLE IF NOT EXISTS apibas_target_inventories (
			id              uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
			target_id       text        NOT NULL REFERENCES apibas_targets(id) ON DELETE CASCADE,
			version         integer     NOT NULL CHECK (version >= 1),
			imported_by     text        NOT NULL,
			imported_at     timestamptz NOT NULL DEFAULT NOW(),
			source_sha256   text        NOT NULL,
			source_bytes    integer     NOT NULL,
			title           text        NOT NULL DEFAULT '',
			api_version     text        NOT NULL DEFAULT '',
			openapi_version text        NOT NULL,
			operations      integer     NOT NULL,
			body            jsonb       NOT NULL,
			UNIQUE (target_id, version)
		)`,
		`CREATE TABLE IF NOT EXISTS apibas_target_bindings (
			target_id           text        PRIMARY KEY REFERENCES apibas_targets(id) ON DELETE CASCADE,
			spec                jsonb       NOT NULL,
			updated_by          text        NOT NULL,
			updated_at          timestamptz NOT NULL DEFAULT NOW(),
			validated_inventory integer     NOT NULL CHECK (validated_inventory >= 1)
		)`,
		`CREATE TABLE IF NOT EXISTS apibas_schedules (
			target_id            text        PRIMARY KEY REFERENCES apibas_targets(id) ON DELETE CASCADE,
			every_hours          integer     NOT NULL CHECK (every_hours BETWEEN 1 AND 720),
			include_writes       boolean     NOT NULL DEFAULT false,
			enabled              boolean     NOT NULL DEFAULT true,
			next_run_at          timestamptz NOT NULL,
			created_by           text        NOT NULL,
			created_at           timestamptz NOT NULL DEFAULT NOW(),
			updated_at           timestamptz NOT NULL DEFAULT NOW(),
			last_run_at          timestamptz,
			last_job_id          text        NOT NULL DEFAULT '',
			last_result          text        NOT NULL DEFAULT '',
			consecutive_failures integer     NOT NULL DEFAULT 0
		)`,
		`ALTER TABLE apibas_schedules ADD COLUMN IF NOT EXISTS at_time text NOT NULL DEFAULT ''`,
		`ALTER TABLE apibas_schedules ADD COLUMN IF NOT EXISTS timezone text NOT NULL DEFAULT ''`,
		`ALTER TABLE apibas_schedules ADD COLUMN IF NOT EXISTS run_days text NOT NULL DEFAULT ''`,
		`CREATE INDEX IF NOT EXISTS apibas_schedules_due_idx ON apibas_schedules (next_run_at) WHERE enabled`,
		`CREATE TABLE IF NOT EXISTS apibas_job_plans (
			job_id             uuid        PRIMARY KEY REFERENCES apibas_jobs(id) ON DELETE CASCADE,
			inventory_version  integer     NOT NULL,
			plan               jsonb       NOT NULL,
			created_at         timestamptz NOT NULL DEFAULT NOW()
		)`,
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
