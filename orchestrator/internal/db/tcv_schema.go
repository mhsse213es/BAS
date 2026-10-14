package db

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
)

// EnsureTCVSchema creates the TCV (Threat-to-Content-Velocity) tables and
// widens actor_resolution_candidates.kind to accept a builtin scenario's
// unresolvable `emulates` reference (spec §9.2, §10.2-§10.3). Must run
// after EnsureThreatIdentitySchema (actor_resolution_candidates, threats)
// and EnsureContentRegistrySchema (content_versions), and before
// EnsureAppRole (whose REVOKEs target these tables).
func EnsureTCVSchema(ctx context.Context, pool *pgxpool.Pool) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS threat_clock_starts (
			threat_id   text        NOT NULL REFERENCES threats(id),
			clock       text        NOT NULL CHECK (clock IN ('threat','intelligence')),
			started_at  timestamptz NOT NULL,
			source_ref  text        NOT NULL DEFAULT '',
			PRIMARY KEY (threat_id, clock)
		)`,
		`CREATE TABLE IF NOT EXISTS threat_coverage_firsts (
			threat_id          text        NOT NULL REFERENCES threats(id),
			relationship_kind  text        NOT NULL CHECK (relationship_kind IN ('emulates','generated_for')),
			content_version_id text        NOT NULL REFERENCES content_versions(id),
			first_executable_at timestamptz NOT NULL,
			PRIMARY KEY (threat_id, relationship_kind)
		)`,
		// Postgres auto-names the CREATE TABLE's inline CHECK
		// actor_resolution_candidates_kind_check; widen it idempotently by
		// dropping (if present) and re-adding with the new value included.
		// Cheap metadata-only operation, safe to run every boot.
		`DO $$
		BEGIN
			IF EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'actor_resolution_candidates_kind_check') THEN
				ALTER TABLE actor_resolution_candidates DROP CONSTRAINT actor_resolution_candidates_kind_check;
			END IF;
			ALTER TABLE actor_resolution_candidates ADD CONSTRAINT actor_resolution_candidates_kind_check
				CHECK (kind IN ('source_record','campaign_ref','malware_ref','tool_ref','content_emulates_ref'));
		END $$`,
	}
	for _, stmt := range stmts {
		if _, err := pool.Exec(ctx, stmt); err != nil {
			return err
		}
	}
	return nil
}
