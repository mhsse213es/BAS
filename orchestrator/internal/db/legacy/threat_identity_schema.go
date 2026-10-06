package legacy

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5"
)

// threatIdentitySchemaLockKey serializes concurrent boots running the
// actor primary-key swap. Distinct from contentregistry's migrationLockKey.
const threatIdentitySchemaLockKey int64 = 0x7C0F4D16A7100003

// actorNameChildren are the only tables that reference threat_actor_profiles
// today (all by name). The key swap refuses to run if any other table does,
// rather than guess how to re-point it.
var actorNameChildren = []string{"technique_evidence", "threat_actor_activity", "threat_actor_sources"}

// EnsureThreatIdentitySchema gives threat actors an immutable id and creates
// the TCF Phase 2A identity tables (spec 2026-10-06 §3, §4.3, §9.1).
// Must run after EnsureContentSchema (actor child tables, intelligence_*)
// and EnsureContentRegistrySchema (scenarios, content_versions), and before
// EnsureAppRole. Idempotent.
func EnsureThreatIdentitySchema(ctx context.Context, db DB) error {
	tx, err := db.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, threatIdentitySchemaLockKey); err != nil {
		return err
	}
	for _, s := range []string{
		`ALTER TABLE threat_actor_profiles ADD COLUMN IF NOT EXISTS id text`,
		`UPDATE threat_actor_profiles SET id = 'act-' || gen_random_uuid()::text WHERE id IS NULL`,
		`ALTER TABLE threat_actor_profiles ALTER COLUMN id SET DEFAULT ('act-' || gen_random_uuid()::text)`,
		`ALTER TABLE threat_actor_profiles ALTER COLUMN id SET NOT NULL`,
	} {
		if _, err := tx.Exec(ctx, s); err != nil {
			return fmt.Errorf("threat identity: %s: %w", s, err)
		}
	}
	if err := swapActorPrimaryKey(ctx, tx); err != nil {
		return err
	}
	for _, s := range threatIdentityTables {
		if _, err := tx.Exec(ctx, s); err != nil {
			return fmt.Errorf("threat identity: %w\n%s", err, s)
		}
	}
	return tx.Commit(ctx)
}

// swapActorPrimaryKey moves the primary key from name to id, keeping name
// UNIQUE as an ingestion constraint (spec §3.1) so the legacy name FKs still
// have a target, and re-creating those FKs with ON UPDATE CASCADE so a
// display-name change follows into the child tables.
func swapActorPrimaryKey(ctx context.Context, tx pgx.Tx) error {
	var pkName, pkCols string
	if err := tx.QueryRow(ctx, `
		SELECT c.conname, string_agg(a.attname, ',' ORDER BY a.attname)
		  FROM pg_constraint c
		  JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = ANY (c.conkey)
		 WHERE c.conrelid = 'threat_actor_profiles'::regclass AND c.contype = 'p'
		 GROUP BY c.conname`).Scan(&pkName, &pkCols); err != nil {
		return fmt.Errorf("threat identity: inspect primary key: %w", err)
	}
	if pkCols == "id" {
		return nil
	}
	if pkCols != "name" {
		return fmt.Errorf("threat identity: threat_actor_profiles primary key is (%s); refusing to guess", pkCols)
	}
	rows, err := tx.Query(ctx, `SELECT conrelid::regclass::text, conname FROM pg_constraint
		 WHERE confrelid = 'threat_actor_profiles'::regclass AND contype = 'f'`)
	if err != nil {
		return err
	}
	type fk struct{ table, name string }
	var fks []fk
	for rows.Next() {
		var f fk
		if err := rows.Scan(&f.table, &f.name); err != nil {
			rows.Close()
			return err
		}
		fks = append(fks, f)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	var tables []string
	for _, f := range fks {
		tables = append(tables, f.table)
	}
	sort.Strings(tables)
	if strings.Join(tables, ",") != strings.Join(actorNameChildren, ",") {
		return fmt.Errorf("threat identity: unexpected foreign keys to threat_actor_profiles: %v", tables)
	}
	var stmts []string
	for _, f := range fks {
		stmts = append(stmts, `ALTER TABLE `+pgx.Identifier{f.table}.Sanitize()+` DROP CONSTRAINT `+pgx.Identifier{f.name}.Sanitize())
	}
	stmts = append(stmts,
		`ALTER TABLE threat_actor_profiles ADD CONSTRAINT threat_actor_profiles_name_key UNIQUE (name)`,
		`ALTER TABLE threat_actor_profiles DROP CONSTRAINT `+pgx.Identifier{pkName}.Sanitize(),
		`ALTER TABLE threat_actor_profiles ADD CONSTRAINT threat_actor_profiles_pkey PRIMARY KEY (id)`,
	)
	for _, child := range actorNameChildren {
		stmts = append(stmts, `ALTER TABLE `+child+` ADD CONSTRAINT `+child+`_actor_name_fkey
			FOREIGN KEY (actor_name) REFERENCES threat_actor_profiles(name) ON UPDATE CASCADE ON DELETE CASCADE`)
	}
	for _, s := range stmts {
		if _, err := tx.Exec(ctx, s); err != nil {
			return fmt.Errorf("threat identity: %s: %w", s, err)
		}
	}
	return nil
}

var threatIdentityTables = []string{
	`CREATE TABLE IF NOT EXISTS threats (
		id             text        PRIMARY KEY,
		subject_type   text        NOT NULL CHECK (subject_type IN ('actor','campaign','malware','tool')),
		subject_id     text        NOT NULL,
		actor_id       text        REFERENCES threat_actor_profiles(id),
		title          text        NOT NULL,
		summary        text        NOT NULL DEFAULT '',
		first_seen_at  timestamptz,
		last_seen_at   timestamptz,
		status         text        NOT NULL DEFAULT 'active' CHECK (status IN ('active','inactive')),
		created_at     timestamptz NOT NULL DEFAULT NOW(),
		tenant_id      text        NOT NULL DEFAULT 'default',
		UNIQUE (subject_type, subject_id),
		CHECK ((subject_type = 'actor') = (actor_id IS NOT NULL)),
		CHECK (subject_type <> 'actor' OR actor_id = subject_id)
	)`,
	`CREATE TABLE IF NOT EXISTS actor_source_identities (
		source      text        NOT NULL,
		source_id   text        NOT NULL CHECK (source_id <> ''),
		actor_id    text        NOT NULL REFERENCES threat_actor_profiles(id),
		linked_by   text        NOT NULL CHECK (linked_by IN ('resolver','admin')),
		linked_ref  text        NOT NULL DEFAULT '',
		created_at  timestamptz NOT NULL DEFAULT NOW(),
		PRIMARY KEY (source, source_id)
	)`,
	`CREATE TABLE IF NOT EXISTS actor_resolution_candidates (
		id                     text        PRIMARY KEY DEFAULT ('arc-' || gen_random_uuid()::text),
		kind                   text        NOT NULL CHECK (kind IN ('source_record','campaign_ref','malware_ref','tool_ref')),
		source                 text        NOT NULL,
		external_id            text        NOT NULL DEFAULT '',
		raw_name               text        NOT NULL,
		ref_entity_id          text        NOT NULL DEFAULT '',
		reason                 text        NOT NULL,
		resolver_context       jsonb       NOT NULL,
		resolver_context_hash  text        NOT NULL,
		status                 text        NOT NULL DEFAULT 'unresolved'
		                       CHECK (status IN ('unresolved','linked','new_actor','dismissed')),
		decided_actor_id       text        REFERENCES threat_actor_profiles(id),
		decided_by             text,
		decided_at             timestamptz,
		decision_reason        text,
		created_at             timestamptz NOT NULL DEFAULT NOW(),
		CHECK ((status = 'unresolved') = (decided_at IS NULL)),
		CHECK (status = 'unresolved' OR (decided_by IS NOT NULL AND decision_reason IS NOT NULL AND decision_reason <> '')),
		CHECK ((status IN ('linked','new_actor')) = (decided_actor_id IS NOT NULL))
	)`,
	`CREATE UNIQUE INDEX IF NOT EXISTS actor_resolution_candidates_open
		ON actor_resolution_candidates (kind, source, external_id, raw_name, ref_entity_id)
		WHERE status = 'unresolved'`,
	// Admin decisions per source key (final review: a link must outrank
	// conflicting resolver mappings, which are append-only). Latest id wins.
	`CREATE TABLE IF NOT EXISTS actor_identity_overrides (
		id           bigserial   PRIMARY KEY,
		source       text        NOT NULL,
		source_id    text        NOT NULL CHECK (source_id <> ''),
		actor_id     text        NOT NULL REFERENCES threat_actor_profiles(id),
		candidate_id text        NOT NULL REFERENCES actor_resolution_candidates(id),
		created_at   timestamptz NOT NULL DEFAULT NOW()
	)`,
	`CREATE TABLE IF NOT EXISTS campaign_actors (
		campaign_id text        NOT NULL REFERENCES intelligence_campaigns(id) ON DELETE CASCADE,
		actor_id    text        NOT NULL REFERENCES threat_actor_profiles(id),
		linked_by   text        NOT NULL CHECK (linked_by IN ('resolver','admin')),
		created_at  timestamptz NOT NULL DEFAULT NOW(),
		PRIMARY KEY (campaign_id, actor_id)
	)`,
	`CREATE TABLE IF NOT EXISTS malware_actors (
		malware_id  text        NOT NULL REFERENCES intelligence_malware(id) ON DELETE CASCADE,
		actor_id    text        NOT NULL REFERENCES threat_actor_profiles(id),
		linked_by   text        NOT NULL CHECK (linked_by IN ('resolver','admin')),
		created_at  timestamptz NOT NULL DEFAULT NOW(),
		PRIMARY KEY (malware_id, actor_id)
	)`,
	`CREATE TABLE IF NOT EXISTS tool_actors (
		tool_id     text        NOT NULL REFERENCES intelligence_tools(id) ON DELETE CASCADE,
		actor_id    text        NOT NULL REFERENCES threat_actor_profiles(id),
		linked_by   text        NOT NULL CHECK (linked_by IN ('resolver','admin')),
		created_at  timestamptz NOT NULL DEFAULT NOW(),
		PRIMARY KEY (tool_id, actor_id)
	)`,
	`CREATE TABLE IF NOT EXISTS content_generation_owners (
		content_id  text        PRIMARY KEY REFERENCES scenarios(scenario_id),
		threat_id   text        NOT NULL UNIQUE REFERENCES threats(id),
		created_at  timestamptz NOT NULL DEFAULT NOW()
	)`,
	`CREATE TABLE IF NOT EXISTS content_version_threats (
		content_version_id  text        NOT NULL REFERENCES content_versions(id),
		threat_id           text        NOT NULL REFERENCES threats(id),
		relationship_kind   text        NOT NULL CHECK (relationship_kind IN ('generated_for','emulates')),
		provenance_type     text        NOT NULL CHECK (provenance_type IN ('generator','vendor_signed_metadata','admin')),
		provenance_ref      text        NOT NULL,
		created_at          timestamptz NOT NULL DEFAULT NOW(),
		PRIMARY KEY (content_version_id, threat_id, relationship_kind),
		CHECK (relationship_kind <> 'generated_for' OR provenance_type = 'generator')
	)`,
}
