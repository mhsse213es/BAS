package db

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
)

// EnsureSegmentationSchema creates the segmentation lab tables. A run is one
// request to execute a pack; its probe results are the per-probe verdicts from
// each repeated pass. Verdicts are stored exactly as the verdict engine produced
// them. Nothing here recomputes or softens a result.
func EnsureSegmentationSchema(ctx context.Context, pool *pgxpool.Pool) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS segmentation_runs (
			id             uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
			pack_id        text        NOT NULL,
			requested_by   text        NOT NULL,
			status         text        NOT NULL CHECK (status IN ('queued', 'running', 'completed', 'failed')),
			runs           integer     NOT NULL DEFAULT 0,
			stable         boolean,
			failure_reason text        NOT NULL DEFAULT '',
			created_at     timestamptz NOT NULL DEFAULT NOW(),
			started_at     timestamptz,
			finished_at    timestamptz
		)`,
		`CREATE INDEX IF NOT EXISTS segmentation_runs_created_idx ON segmentation_runs (created_at DESC)`,
		`CREATE TABLE IF NOT EXISTS segmentation_probe_results (
			run_id      uuid        NOT NULL REFERENCES segmentation_runs(id) ON DELETE CASCADE,
			run_index   integer     NOT NULL,
			seq         integer     NOT NULL,
			probe_id    text        NOT NULL,
			src         text        NOT NULL,
			dst         text        NOT NULL,
			dst_port    integer     NOT NULL,
			proto       text        NOT NULL,
			expect      text        NOT NULL,
			outcome     text        NOT NULL,
			verdict     text        NOT NULL CHECK (verdict IN ('PASS', 'FAIL', 'UNKNOWN', 'ERROR')),
			reason      text        NOT NULL,
			rule_ids    jsonb       NOT NULL DEFAULT '[]',
			started_at  timestamptz,
			ended_at    timestamptz,
			PRIMARY KEY (run_id, run_index, seq)
		)`,
	}
	for _, stmt := range stmts {
		if _, err := pool.Exec(ctx, stmt); err != nil {
			return err
		}
	}
	return nil
}
