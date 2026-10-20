package db

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
)

// EnsureAPIBASRunSchema creates apibas_runs, one row per scenario run per build. The full report is stored as
// jsonb, so the record is exactly what apibas-runner printed. Rows are unique per run tag and build.
func EnsureAPIBASRunSchema(ctx context.Context, pool *pgxpool.Pool) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS apibas_runs (
			id             text        PRIMARY KEY DEFAULT gen_random_uuid()::text,
			run_tag        text        NOT NULL,
			scenario_id    text        NOT NULL,
			build          text        NOT NULL CHECK (build IN ('vulnerable', 'fixed')),
			protocol       text        NOT NULL DEFAULT 'http',
			result         text        NOT NULL CHECK (result IN ('PASS', 'FAIL', 'ERROR', 'SKIPPED')),
			exploitability text        NOT NULL DEFAULT '',
			control        text        NOT NULL DEFAULT '',
			detection      text        NOT NULL DEFAULT '',
			reason         text        NOT NULL DEFAULT '',
			report         jsonb       NOT NULL,
			started_at     timestamptz NOT NULL DEFAULT NOW(),
			created_at     timestamptz NOT NULL DEFAULT NOW(),
			UNIQUE (run_tag, build)
		)`,
		`CREATE INDEX IF NOT EXISTS apibas_runs_scenario_idx ON apibas_runs (scenario_id, created_at DESC)`,
	}
	for _, s := range stmts {
		if _, err := pool.Exec(ctx, s); err != nil {
			return err
		}
	}
	return nil
}
