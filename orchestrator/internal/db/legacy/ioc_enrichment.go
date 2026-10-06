package legacy

import (
	"context"
	"fmt"
)

// EnsureIOCEnrichmentSchema creates the ioc_enrichment cache table. Idempotent
// -- safe to call on every startup.
func EnsureIOCEnrichmentSchema(ctx context.Context, db DB) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS ioc_enrichment (
			id                 BIGSERIAL PRIMARY KEY,
			indicator_type     TEXT NOT NULL,
			indicator_value    TEXT NOT NULL,
			provider           TEXT NOT NULL,
			provider_version   TEXT NOT NULL DEFAULT '',
			schema_version     SMALLINT NOT NULL DEFAULT 1,
			pulse_count        INT NOT NULL DEFAULT 0,
			pulse_names        JSONB NOT NULL DEFAULT '[]',
			malware_families   JSONB NOT NULL DEFAULT '[]',
			adversary_names    JSONB NOT NULL DEFAULT '[]',
			industries         JSONB NOT NULL DEFAULT '[]',
			tags               JSONB NOT NULL DEFAULT '[]',
			raw_response       JSONB,
			lookup_duration_ms INT,
			last_success_at    TIMESTAMPTZ,
			last_failure_at    TIMESTAMPTZ,
			last_error         TEXT,
			ttl_expires_at     TIMESTAMPTZ NOT NULL,
			UNIQUE(indicator_type, indicator_value, provider)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_ioc_enrichment_ttl ON ioc_enrichment(ttl_expires_at)`,
	}
	for _, s := range stmts {
		if _, err := db.Exec(ctx, s); err != nil {
			return fmt.Errorf("ioc enrichment schema: %w", err)
		}
	}
	return nil
}
