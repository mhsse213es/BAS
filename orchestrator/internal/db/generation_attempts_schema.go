package db

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

// EnsureGenerationAttemptsSchema creates the TCF Phase 9 generation-attempt
// log (spec 2026-10-13 §2.1). Must run after EnsureThreatIdentitySchema
// (threats.id) and EnsureEvidenceSchema (this table is evidence-adjacent,
// not a dependency of it). Idempotent.
func EnsureGenerationAttemptsSchema(ctx context.Context, pool *pgxpool.Pool) error {
	for _, s := range generationAttemptsTables {
		if _, err := pool.Exec(ctx, s); err != nil {
			return fmt.Errorf("generation attempts schema: %w\n%s", err, s)
		}
	}
	return nil
}

var generationAttemptsTables = []string{
	`CREATE TABLE IF NOT EXISTS content_generation_attempts (
		id                  text        PRIMARY KEY DEFAULT ('cga-' || gen_random_uuid()::text),
		cycle_id            text        NOT NULL,
		threat_id           text,
		content_id          text,
		content_version_id text,
		outcome             text        NOT NULL CHECK (outcome IN ('created','changed','skipped','failed')),
		reason_code         text        NOT NULL,
		detail              text,
		generator_version   text        NOT NULL,
		fingerprint         text,
		started_at          timestamptz NOT NULL,
		completed_at        timestamptz NOT NULL DEFAULT NOW()
	)`,
	`CREATE INDEX IF NOT EXISTS idx_content_generation_attempts_cycle
		ON content_generation_attempts (cycle_id)`,
	`CREATE INDEX IF NOT EXISTS idx_content_generation_attempts_threat
		ON content_generation_attempts (threat_id, started_at DESC)`,
}
