package db

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

// EnsureIngestSchema creates the ingested_events idempotency ledger used by
// the generic inbound security-event ingestion API (internal/ingest).
// Idempotent -- safe to call on every startup.
//
// ioc_id is nullable: an inbound event with no IOC payload (e.g. a pure
// "no detection" heartbeat, or one whose only indicator type we don't yet
// recognize) is still recorded here so a retry of the same
// (source, external_event_id) is still rejected as a duplicate, even
// though it produced no iocs row.
func EnsureIngestSchema(ctx context.Context, pool *pgxpool.Pool) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS ingested_events (
			id                 BIGSERIAL PRIMARY KEY,
			source             TEXT NOT NULL,
			external_event_id  TEXT NOT NULL,
			ioc_id             TEXT REFERENCES iocs(id) ON DELETE SET NULL,
			received_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			UNIQUE(source, external_event_id)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_ingested_events_received ON ingested_events(received_at)`,
	}
	for _, s := range stmts {
		if _, err := pool.Exec(ctx, s); err != nil {
			return fmt.Errorf("ingest schema: %w", err)
		}
	}
	return nil
}
