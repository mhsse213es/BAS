package legacy

import (
	"context"
	"fmt"
)

// EnsureIOCSchema creates the run_iocs table. Idempotent -- safe to call on
// every startup.
func EnsureIOCSchema(ctx context.Context, db DB) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS run_iocs (
			id               BIGSERIAL PRIMARY KEY,
			run_id           TEXT NOT NULL,
			scenario_id      TEXT NOT NULL,
			indicator_type   TEXT NOT NULL,
			indicator_value  TEXT NOT NULL,
			hash_algorithm   TEXT,
			confidence       SMALLINT NOT NULL,
			indicator_source TEXT NOT NULL,
			offset_start     INT NOT NULL,
			offset_end       INT NOT NULL,
			technique_ids    JSONB NOT NULL DEFAULT '[]',
			simulation_ids   JSONB NOT NULL DEFAULT '[]',
			extracted_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			UNIQUE(run_id, indicator_type, indicator_value)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_run_iocs_run_id ON run_iocs(run_id)`,
		`CREATE INDEX IF NOT EXISTS idx_run_iocs_value ON run_iocs(indicator_type, indicator_value)`,
	}
	for _, s := range stmts {
		if _, err := db.Exec(ctx, s); err != nil {
			return fmt.Errorf("ioc schema: %w", err)
		}
	}
	return nil
}
