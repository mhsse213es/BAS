package db

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

// EnsureAdvisorySchema creates the REQ-018 Gap 2 advisory intake tables.
//
//   - advisory_intake: one row per advisory received from a source. Unique on
//     (source, external_id), so re-polling a feed never duplicates an advisory.
//   - advisory_relevance: the analyst decision. Append-only. The first decision
//     for an advisory has supersedes IS NULL, and a unique index allows only one
//     of those per advisory. A reversal is a new row that points at the row it
//     supersedes (spec section 8).
//
// Exclusions carry one of the five spec reason codes. Relevant decisions carry none.
func EnsureAdvisorySchema(ctx context.Context, pool *pgxpool.Pool) error {
	for _, stmt := range advisorySchemaStmts {
		if _, err := pool.Exec(ctx, stmt); err != nil {
			return fmt.Errorf("advisory schema: %w", err)
		}
	}
	return nil
}

var advisorySchemaStmts = []string{
	`CREATE TABLE IF NOT EXISTS advisory_intake (
		id            text        PRIMARY KEY DEFAULT ('adv-' || gen_random_uuid()::text),
		source        text        NOT NULL CHECK (source IN ('cert_in','fs_isac')),
		external_id   text        NOT NULL CHECK (external_id <> ''),
		title         text        NOT NULL,
		published_at  timestamptz,
		received_at   timestamptz NOT NULL DEFAULT NOW(),
		source_ref    text        NOT NULL,
		content_hash  text        NOT NULL,
		body          text        NOT NULL DEFAULT '',
		UNIQUE (source, external_id)
	)`,
	`CREATE TABLE IF NOT EXISTS advisory_relevance (
		id            bigserial   PRIMARY KEY,
		advisory_id   text        NOT NULL REFERENCES advisory_intake(id),
		decision      text        NOT NULL CHECK (decision IN ('relevant','excluded')),
		reason_code   text,
		supersedes    bigint      REFERENCES advisory_relevance(id),
		decided_by    text        NOT NULL CHECK (decided_by LIKE 'user:_%'),
		decided_at    timestamptz NOT NULL DEFAULT NOW(),
		note          text        NOT NULL DEFAULT '',
		CHECK (decision <> 'excluded' OR (reason_code IS NOT NULL AND reason_code IN (
			'relevance','insufficient_technical_detail','unsupported_platform',
			'validation_environment_unavailable','third_party_dependency'))),
		CHECK (decision <> 'relevant' OR reason_code IS NULL)
	)`,
	`CREATE UNIQUE INDEX IF NOT EXISTS advisory_relevance_one_original
		ON advisory_relevance (advisory_id) WHERE supersedes IS NULL`,
	`CREATE INDEX IF NOT EXISTS advisory_intake_source ON advisory_intake (source, received_at)`,
}
