package db

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

// EnsureTCFPipelineEventsSchema creates the append-only TCV SLA event ledger
// (spec 2026-10-31 §6). The ledger references authoritative source rows via
// provenance (source_table/source_pk) and carries the real event_time copied
// from that row; it never copies mutable facts, so it cannot drift from the
// lifecycle/validation tables it points at. Rows are written once via
// idempotency_key + ON CONFLICT DO NOTHING; corrections are new rows.
//
// Columns referencing other TCF tables (threat_id, content_version_id,
// generation_attempt_id, validation_run_id) are deliberately plain text, not
// REFERENCES: an event may be recorded before or without the referenced row
// in the same transaction, and provenance (source_table/source_pk) is the
// authoritative link. Idempotent; must run after EnsureThreatIdentitySchema
// and EnsureContentRegistrySchema, and before EnsureAppRole (whose REVOKE
// targets this table).
func EnsureTCFPipelineEventsSchema(ctx context.Context, pool *pgxpool.Pool) error {
	for _, stmt := range tcfPipelineEventsTables {
		if _, err := pool.Exec(ctx, stmt); err != nil {
			return fmt.Errorf("tcf pipeline events schema: %w\n%s", err, stmt)
		}
	}
	return nil
}

var tcfPipelineEventsTables = []string{
	`CREATE TABLE IF NOT EXISTS tcf_pipeline_events (
		event_id              text        PRIMARY KEY DEFAULT ('tpe-' || gen_random_uuid()::text),
		event_type            text        NOT NULL CHECK (event_type IN (
			'threat_observed','threat_eligible',
			'generation_attempted','generation_failed','content_created',
			'validation_dispatched','validation_resulted','validated_coverage',
			'published_executable','superseded','retired','rejected','bundle_packaged',
			'advisory_received','advisory_classified')),
		threat_id             text,
		content_id            text,
		content_version_id    text,
		generation_attempt_id text,
		validation_run_id     text,
		event_time            timestamptz NOT NULL,
		recorded_time         timestamptz NOT NULL DEFAULT now(),
		source_table          text        NOT NULL,
		source_pk             text        NOT NULL,
		payload               jsonb       NOT NULL DEFAULT '{}',
		idempotency_key       text        NOT NULL UNIQUE
	)`,
	`CREATE INDEX IF NOT EXISTS idx_tpe_threat ON tcf_pipeline_events (threat_id, event_time)`,
	`CREATE INDEX IF NOT EXISTS idx_tpe_version ON tcf_pipeline_events (content_version_id, event_time)`,
	`CREATE INDEX IF NOT EXISTS idx_tpe_type_time ON tcf_pipeline_events (event_type, event_time)`,
	// Migration for databases created before bundle_packaged existed: widen
	// the event_type CHECK. Idempotent: it re-adds the constraint with the full
	// value list whether or not the old one was present. The CREATE TABLE above
	// already carries the full list, so this is a no-op on fresh databases.
	// Acts only when the existing constraint lacks bundle_packaged, so a normal
	// boot takes no lock and does not re-validate the ledger.
	`DO $$
	BEGIN
		IF NOT EXISTS (
			SELECT 1 FROM pg_constraint
			WHERE conname = 'tcf_pipeline_events_event_type_check'
			  AND pg_get_constraintdef(oid) LIKE '%advisory_classified%') THEN
			ALTER TABLE tcf_pipeline_events DROP CONSTRAINT IF EXISTS tcf_pipeline_events_event_type_check;
			ALTER TABLE tcf_pipeline_events ADD CONSTRAINT tcf_pipeline_events_event_type_check CHECK (event_type IN (
				'threat_observed','threat_eligible',
				'generation_attempted','generation_failed','content_created',
				'validation_dispatched','validation_resulted','validated_coverage',
				'published_executable','superseded','retired','rejected','bundle_packaged',
				'advisory_received','advisory_classified'));
		END IF;
	END $$`,
}
