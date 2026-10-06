package legacy

import (
	"context"
	"fmt"
)

// addConstraint renders an idempotent ALTER TABLE ... ADD CONSTRAINT --
// PostgreSQL has no ADD CONSTRAINT IF NOT EXISTS, so this follows the DO $$
// precedent in postgres.go.
func addConstraint(table, name, def string) string {
	return fmt.Sprintf(`DO $$
BEGIN
	IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = '%s') THEN
		ALTER TABLE %s ADD CONSTRAINT %s %s;
	END IF;
END $$`, name, table, name, def)
}

// EnsureContentRegistrySchema creates the Threat Content Factory Phase 1
// Content Registry. See
// docs/superpowers/specs/2026-10-04-tcf-phase1-content-registry-design.md §4.
// Must run after EnsureSchema (scenario_runs) and EnsureContentSchema
// (scenarios), and before EnsureAppRole (whose REVOKEs target these tables).
func EnsureContentRegistrySchema(ctx context.Context, db DB) error {
	// scenarios is repurposed as content identity. No code has ever written
	// it, so it should be empty; if it is not, refuse rather than guess an
	// origin for rows nobody can explain.
	var hasOrigin bool
	if err := db.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM information_schema.columns
		  WHERE table_schema = current_schema() AND table_name = 'scenarios' AND column_name = 'origin')`,
	).Scan(&hasOrigin); err != nil {
		return fmt.Errorf("content registry: inspect scenarios: %w", err)
	}
	if !hasOrigin {
		var n int
		if err := db.QueryRow(ctx, `SELECT count(*) FROM scenarios`).Scan(&n); err != nil {
			return fmt.Errorf("content registry: count scenarios: %w", err)
		}
		if n > 0 {
			return fmt.Errorf("content registry migration: table scenarios has %d unexpected row(s); refusing to assign an origin -- inspect and clear them manually", n)
		}
	}

	stmts := []string{
		`ALTER TABLE scenarios ADD COLUMN IF NOT EXISTS origin text`,
		`ALTER TABLE scenarios ALTER COLUMN origin SET NOT NULL`,
		`ALTER TABLE scenarios ADD COLUMN IF NOT EXISTS created_at timestamptz NOT NULL DEFAULT NOW()`,
		`ALTER TABLE scenarios ADD COLUMN IF NOT EXISTS generation_key text`,
		addConstraint("scenarios", "scenarios_origin_check", `CHECK (origin IN ('VENDOR','LOCAL'))`),
		addConstraint("scenarios", "scenarios_id_origin_key", `UNIQUE (scenario_id, origin)`),

		`CREATE TABLE IF NOT EXISTS content_versions (
			id               text        PRIMARY KEY DEFAULT gen_random_uuid()::text,
			content_id       text        NOT NULL,
			origin           text        NOT NULL,
			version          int         NOT NULL CHECK (version >= 1),
			artifact_sha256  text        NOT NULL,
			artifact_size    int         NOT NULL,
			artifact_bytes   bytea       NOT NULL,
			signature_bytes  bytea,
			trust_level      text        NOT NULL CHECK (trust_level IN ('VENDOR_SIGNED','LOCAL_TRUSTED','UNTRUSTED')),
			lifecycle        text        NOT NULL CHECK (lifecycle IN ('DRAFT','VALIDATING','VALIDATED','APPROVED',
			                                                            'PUBLISHED','PUBLISHED_LOCAL','RETIRED','REJECTED')),
			intake_source    text        NOT NULL CHECK (intake_source IN ('builtin','custom','intel')),
			schema_version   int         NOT NULL,
			technique_ids    text[]      NOT NULL DEFAULT '{}',
			supported_os     text[]      NOT NULL DEFAULT '{}',
			generation       jsonb       NOT NULL DEFAULT '{}',
			created_by       text        NOT NULL,
			created_at       timestamptz NOT NULL DEFAULT NOW(),
			tenant_id        text        NOT NULL DEFAULT 'default',
			FOREIGN KEY (content_id, origin) REFERENCES scenarios (scenario_id, origin),
			UNIQUE (content_id, version),
			UNIQUE (content_id, artifact_sha256),
			CHECK (artifact_size = octet_length(artifact_bytes)),
			CHECK (trust_level <> 'VENDOR_SIGNED' OR (origin = 'VENDOR' AND signature_bytes IS NOT NULL)),
			CHECK (trust_level <> 'LOCAL_TRUSTED' OR origin = 'LOCAL'),
			CHECK (lifecycle <> 'PUBLISHED' OR origin = 'VENDOR'),
			CHECK (lifecycle <> 'PUBLISHED_LOCAL' OR origin = 'LOCAL')
		)`,
		`CREATE INDEX IF NOT EXISTS content_versions_techniques ON content_versions USING GIN (technique_ids)`,

		`CREATE TABLE IF NOT EXISTS content_version_events (
			id                  bigserial   PRIMARY KEY,
			content_version_id  text        NOT NULL REFERENCES content_versions(id),
			from_lifecycle      text,
			to_lifecycle        text        NOT NULL,
			from_trust          text,
			to_trust            text        NOT NULL,
			actor               text        NOT NULL,
			reason              text        NOT NULL DEFAULT '',
			at                  timestamptz NOT NULL DEFAULT NOW(),
			tenant_id           text        NOT NULL DEFAULT 'default',
			CHECK (to_lifecycle NOT IN ('APPROVED','PUBLISHED_LOCAL','REJECTED')
			       OR actor LIKE 'user:_%' OR actor = 'migration:pre-registry')
		)`,
		`CREATE INDEX IF NOT EXISTS content_version_events_vid ON content_version_events (content_version_id, at)`,

		`CREATE TABLE IF NOT EXISTS content_version_sources (
			content_version_id        text        NOT NULL REFERENCES content_versions(id),
			entity_type               text        NOT NULL CHECK (entity_type IN
			                              ('actor','campaign','malware','tool','technique_evidence')),
			entity_id                 text        NOT NULL,
			provider                  text        NOT NULL,
			external_id               text        NOT NULL DEFAULT '',
			confidence_at_generation  text        NOT NULL DEFAULT '',
			first_seen_at_generation  timestamptz,
			last_sync_at_generation   timestamptz,
			role                      text        NOT NULL CHECK (role IN ('primary','supporting')),
			tenant_id                 text        NOT NULL DEFAULT 'default',
			PRIMARY KEY (content_version_id, entity_type, entity_id, provider)
		)`,

		`CREATE TABLE IF NOT EXISTS content_safety_verdicts (
			id                  bigserial   PRIMARY KEY,
			content_version_id  text        NOT NULL REFERENCES content_versions(id),
			classifier          text        NOT NULL,
			classifier_version  text        NOT NULL,
			verdict             text        NOT NULL,
			detail              jsonb       NOT NULL DEFAULT '[]',
			evaluated_at        timestamptz NOT NULL DEFAULT NOW(),
			tenant_id           text        NOT NULL DEFAULT 'default',
			UNIQUE (content_version_id, classifier, classifier_version)
		)`,

		`CREATE TABLE IF NOT EXISTS content_validations (
			id                  text        PRIMARY KEY DEFAULT gen_random_uuid()::text,
			content_version_id  text        NOT NULL REFERENCES content_versions(id),
			level               text        NOT NULL CHECK (level IN
			                        ('STRUCTURAL','STATIC','EXECUTION','TELEMETRY','DETECTION')),
			outcome             text        NOT NULL CHECK (outcome IN
			                        ('PASS','FAIL','ERROR','DETECTED','PREVENTED','LOGGED','MISSED',
			                         'NO_DATA','NOT_APPLICABLE')),
			run_id              text        REFERENCES scenario_runs(id),
			validator           text        NOT NULL,
			validator_version   text        NOT NULL,
			environment         jsonb       NOT NULL DEFAULT '{}',
			detail              jsonb       NOT NULL DEFAULT '{}',
			created_at          timestamptz NOT NULL DEFAULT NOW(),
			tenant_id           text        NOT NULL DEFAULT 'default',
			CHECK (level IN ('STRUCTURAL','STATIC') OR outcome <> 'PASS' OR run_id IS NOT NULL),
			CHECK (level <> 'DETECTION' OR outcome NOT IN ('PASS','FAIL'))
		)`,
		`CREATE INDEX IF NOT EXISTS content_validations_vid ON content_validations (content_version_id, level)`,

		// Singleton migration marker (plan amendment 2). Custom files are
		// grandfathered only while this row does not exist.
		`CREATE TABLE IF NOT EXISTS content_registry_state (
			id           int         PRIMARY KEY DEFAULT 1 CHECK (id = 1),
			migrated_at  timestamptz NOT NULL DEFAULT NOW(),
			inventory    jsonb       NOT NULL DEFAULT '{}'
		)`,

		`ALTER TABLE scenario_runs ADD COLUMN IF NOT EXISTS content_version_id text REFERENCES content_versions(id)`,
		`ALTER TABLE scenario_runs ADD COLUMN IF NOT EXISTS execution_kind text NOT NULL DEFAULT 'legacy'`,
		addConstraint("scenario_runs", "scenario_runs_execution_kind_check",
			`CHECK (execution_kind IN ('content','remediation','technique_verification','variant','adhoc_adversary','legacy'))`),
		addConstraint("scenario_runs", "scenario_runs_content_needs_version_check",
			`CHECK (execution_kind <> 'content' OR content_version_id IS NOT NULL)`),
		`CREATE INDEX IF NOT EXISTS idx_scenario_runs_content_version ON scenario_runs (content_version_id) WHERE content_version_id IS NOT NULL`,
	}
	for _, s := range stmts {
		if _, err := db.Exec(ctx, s); err != nil {
			return fmt.Errorf("content registry schema exec failed:\n%s\nerror: %w", s, err)
		}
	}
	return nil
}
