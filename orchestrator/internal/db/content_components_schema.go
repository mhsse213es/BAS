package db

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
)

// EnsureContentComponentsSchema creates the component catalog and
// composition-provenance tables (TCF Phase 4, spec
// docs/superpowers/specs/2026-10-14-tcf-phase4-content-composition-design.md
// §2.1, §2.3). Must run after EnsureContentRegistrySchema (content_versions).
func EnsureContentComponentsSchema(ctx context.Context, pool *pgxpool.Pool) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS content_components (
			id                         text        PRIMARY KEY DEFAULT gen_random_uuid()::text,
			kind                       text        NOT NULL CHECK (kind IN ('internal','external')),
			technique_id               text        NOT NULL,
			title                      text        NOT NULL,
			supported_os               text[]      NOT NULL DEFAULT '{}',
			origin_content_version_id  text        REFERENCES content_versions(id),
			step_snapshot              jsonb,
			framework                  text,
			ability_id                 text,
			action_key                 text,
			test_index                 int,
			library_version            text,
			promoted_by                text        NOT NULL,
			promoted_at                timestamptz NOT NULL DEFAULT NOW(),
			CHECK (
				(kind = 'internal' AND origin_content_version_id IS NOT NULL AND step_snapshot IS NOT NULL
					AND framework IS NULL AND ability_id IS NULL AND library_version IS NULL AND action_key IS NULL)
				OR
				(kind = 'external' AND framework IS NOT NULL
					AND origin_content_version_id IS NULL AND step_snapshot IS NULL)
			)
		)`,
		`CREATE TABLE IF NOT EXISTS content_version_components (
			content_version_id text NOT NULL REFERENCES content_versions(id),
			component_id        text NOT NULL REFERENCES content_components(id),
			step_order           int NOT NULL,
			PRIMARY KEY (content_version_id, component_id)
		)`,
		`CREATE INDEX IF NOT EXISTS cvc_version ON content_version_components(content_version_id)`,
	}
	for _, s := range stmts {
		if _, err := pool.Exec(ctx, s); err != nil {
			return err
		}
	}
	return nil
}
