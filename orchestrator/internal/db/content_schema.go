package db

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

// EnsureContentSchema creates the ART content + technique knowledge-graph tables.
//
// It is kept separate from EnsureSchema so the security-content model stays
// self-contained and easy to reason about. The design follows three rules:
//
//   - Payload binaries live on disk; the DB stores metadata + storage_path only.
//   - Atomics are split into a raw import layer (art_atomic_raw, original YAML)
//     and a runtime layer (art_atomic_tests, parsed execution-ready rows) so the
//     server never re-parses YAML at dispatch time.
//   - Techniques are first-class objects; CVE/OWASP/scenario link tables are
//     created now (even if unpopulated) to avoid a painful migration once the
//     platform grows a knowledge graph.
//
// Idempotent — safe to call on every startup.
func EnsureContentSchema(ctx context.Context, pool *pgxpool.Pool) error {
	stmts := []string{
		// ── Tactic reference (the 14 ATT&CK Enterprise tactics) ───────────────
		`CREATE TABLE IF NOT EXISTS tactics (
			tactic_id        text        PRIMARY KEY,            -- shortname, e.g. credential-access
			name             text        NOT NULL DEFAULT '',    -- display name, e.g. Credential Access
			attack_id        text        NOT NULL DEFAULT '',    -- ATT&CK tactic ID, e.g. TA0006
			kill_chain_order int         NOT NULL DEFAULT 0,
			updated_at       timestamptz NOT NULL DEFAULT NOW()
		)`,

		// ── Master security object ────────────────────────────────────────────
		`CREATE TABLE IF NOT EXISTS techniques (
			technique_id text        PRIMARY KEY,            -- e.g. T1059.001
			name         text        NOT NULL DEFAULT '',
			tactic       text        NOT NULL DEFAULT '',
			description  text        NOT NULL DEFAULT '',
			updated_at   timestamptz NOT NULL DEFAULT NOW()
		)`,

		// ── Import layer: original Atomic Red Team YAML, stored as received ────
		`CREATE TABLE IF NOT EXISTS art_atomic_raw (
			technique_id text        PRIMARY KEY REFERENCES techniques(technique_id) ON DELETE CASCADE,
			yaml         text        NOT NULL,
			content_hash text        NOT NULL,
			updated_at   timestamptz NOT NULL DEFAULT NOW()
		)`,

		// ── Runtime layer: parsed, execution-ready atomic tests ───────────────
		`CREATE TABLE IF NOT EXISTS art_atomic_tests (
			id                bigserial   PRIMARY KEY,
			technique_id      text        NOT NULL REFERENCES techniques(technique_id) ON DELETE CASCADE,
			test_index        int         NOT NULL,           -- ordinal within the technique file
			name              text        NOT NULL,
			executor          text        NOT NULL,           -- powershell | cmd
			command           text        NOT NULL,
			cleanup           text        NOT NULL DEFAULT '',
			platform          text        NOT NULL DEFAULT 'windows',
			timeout_sec       int         NOT NULL DEFAULT 120,
			required_payloads text[]      NOT NULL DEFAULT '{}',
			framework         text        NOT NULL DEFAULT 'art',
			updated_at        timestamptz NOT NULL DEFAULT NOW(),
			UNIQUE (technique_id, test_index)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_atomic_tests_technique ON art_atomic_tests(technique_id)`,
		`ALTER TABLE art_atomic_raw ADD COLUMN IF NOT EXISTS import_version int NOT NULL DEFAULT 1`,
		// requires_priv is the normalized effective privilege tier ('' | 'user' | 'admin'),
		// derived from the framework's raw elevation signal by the importer's
		// normalization layer (see mapARTElevation in internal/scenario/art.go).
		// original_elevation_required preserves ART's raw upstream boolean as
		// provenance, independent of how this platform currently interprets it.
		`ALTER TABLE art_atomic_tests ADD COLUMN IF NOT EXISTS requires_priv text NOT NULL DEFAULT ''`,
		`ALTER TABLE art_atomic_tests ADD COLUMN IF NOT EXISTS original_elevation_required boolean NOT NULL DEFAULT false`,

		// ── Payload metadata (binaries remain on disk) ────────────────────────
		`CREATE TABLE IF NOT EXISTS art_payloads (
			basename     text        PRIMARY KEY,             -- lowercase filename
			sha256       text        NOT NULL,
			size_bytes   bigint      NOT NULL,
			storage_path text        NOT NULL,                -- absolute path on the server's disk
			payload_type text        NOT NULL DEFAULT '',     -- exe, dll, ps1, ...
			source       text        NOT NULL DEFAULT '',     -- curated | atomics-src
			updated_at   timestamptz NOT NULL DEFAULT NOW()
		)`,

		// ── Content version tracking ──────────────────────────────────────────
		`CREATE TABLE IF NOT EXISTS art_content_meta (
			id              int         PRIMARY KEY DEFAULT 1 CHECK (id = 1),
			source_version  text        NOT NULL DEFAULT '',
			technique_count int         NOT NULL DEFAULT 0,
			payload_count   int         NOT NULL DEFAULT 0,
			source          text        NOT NULL DEFAULT '',
			imported_at     timestamptz NOT NULL DEFAULT NOW()
		)`,

		// ── OpenAEV Connector content: synced scenario definitions ────────────
		// See docs/superpowers/specs/2026-07-15-openaev-connector-design.md.
		`CREATE TABLE IF NOT EXISTS openaev_bundles (
			id                   text        PRIMARY KEY,
			openaev_scenario_id  text        NOT NULL,
			bundle               jsonb       NOT NULL,
			content_hash         text        NOT NULL,
			size_bytes           int         NOT NULL DEFAULT 0,
			source_version       int         NOT NULL DEFAULT 1,
			synced_at            timestamptz NOT NULL DEFAULT NOW()
		)`,

		`CREATE TABLE IF NOT EXISTS openaev_scenarios (
			openaev_scenario_id text        PRIMARY KEY,
			name                text        NOT NULL,
			category            text        NOT NULL DEFAULT '',
			severity            text        NOT NULL DEFAULT '',
			platforms           text[]      NOT NULL DEFAULT '{}',
			technique_ids       text[]      NOT NULL DEFAULT '{}',
			tags                text[]      NOT NULL DEFAULT '{}',
			objectives_count    int         NOT NULL DEFAULT 0,
			injects_count       int         NOT NULL DEFAULT 0,
			source_updated_at   timestamptz NOT NULL,
			content_hash        text        NOT NULL DEFAULT '',
			bundle_id           text        REFERENCES openaev_bundles(id),
			sync_revision       int         NOT NULL DEFAULT 1,
			imported_at         timestamptz NOT NULL DEFAULT NOW(),
			updated_at          timestamptz NOT NULL DEFAULT NOW()
		)`,

		// ── Knowledge graph: created now to avoid a future migration ──────────
		`CREATE TABLE IF NOT EXISTS cves (
			cve_id      text        PRIMARY KEY,              -- e.g. CVE-2024-3400
			description text        NOT NULL DEFAULT '',
			cvss        real,
			published   date,
			updated_at  timestamptz NOT NULL DEFAULT NOW()
		)`,
		// CISA KEV enrichment — added as idempotent ALTERs so an existing cves
		// table upgrades in place. KEV carries no CVSS, so that column stays null.
		`ALTER TABLE cves ADD COLUMN IF NOT EXISTS vendor            text NOT NULL DEFAULT ''`,
		`ALTER TABLE cves ADD COLUMN IF NOT EXISTS product           text NOT NULL DEFAULT ''`,
		`ALTER TABLE cves ADD COLUMN IF NOT EXISTS name              text NOT NULL DEFAULT ''`,
		`ALTER TABLE cves ADD COLUMN IF NOT EXISTS date_added        date`,
		`ALTER TABLE cves ADD COLUMN IF NOT EXISTS known_ransomware  boolean NOT NULL DEFAULT false`,
		`ALTER TABLE cves ADD COLUMN IF NOT EXISTS source            text NOT NULL DEFAULT ''`,
		// FIRST EPSS scores — seeded from epss_scores-current.csv or .csv.gz at /content/epss-scores.csv.
		// Only CVEs that appear in technique_cves are inserted (selective, not the full 220k-row catalog).
		`CREATE TABLE IF NOT EXISTS cve_epss (
			cve_id      text        PRIMARY KEY,
			epss_score  real        NOT NULL DEFAULT 0,  -- raw probability 0.0–1.0
			percentile  real        NOT NULL DEFAULT 0,  -- raw decimal 0.0–1.0 (× 100 for display)
			score_date  date,
			updated_at  timestamptz NOT NULL DEFAULT NOW()
		)`,
		`CREATE TABLE IF NOT EXISTS technique_cves (
			technique_id text NOT NULL REFERENCES techniques(technique_id) ON DELETE CASCADE,
			cve_id       text NOT NULL REFERENCES cves(cve_id) ON DELETE CASCADE,
			PRIMARY KEY (technique_id, cve_id)
		)`,

		// ── technique_cve_relationships: evidence-backed CVE↔ATT&CK provenance ──
		// Supersedes the bare technique_cves join as the source of truth for
		// scoring: a relationship carries WHY it exists (type, rationale), HOW
		// confident the claim is (proposed vs. effective — a reviewer can
		// promote/demote effective_confidence without rewriting the relationship),
		// and its lifecycle (status). A (technique,cve) pair may have several
		// relationships of different types; duplicates of the same type are
		// rejected. Rows are mutable curated content (not an audit ledger like
		// verification_history) — every change is instead written to the existing
		// audit_logs table, capturing old/new confidence and rationale.
		`CREATE TABLE IF NOT EXISTS technique_cve_relationships (
			id                   text        PRIMARY KEY DEFAULT gen_random_uuid()::text,
			technique_id         text        NOT NULL REFERENCES techniques(technique_id) ON DELETE CASCADE,
			cve_id               text        NOT NULL REFERENCES cves(cve_id) ON DELETE CASCADE,
			relationship_type    text        NOT NULL,
			proposed_confidence  text        NOT NULL DEFAULT 'Medium',
			effective_confidence text        NOT NULL DEFAULT 'Medium',
			primary_source       text        NOT NULL DEFAULT 'Analyst',
			rationale            text        NOT NULL DEFAULT '',
			status               text        NOT NULL DEFAULT 'Active', -- Active/Deprecated/Disputed/Retired
			status_changed_by    text        NOT NULL DEFAULT '',
			status_changed_at    timestamptz,
			status_reason        text        NOT NULL DEFAULT '',
			created_by           text        NOT NULL DEFAULT '',
			created_at           timestamptz NOT NULL DEFAULT NOW(),
			updated_by           text        NOT NULL DEFAULT '',
			updated_at           timestamptz NOT NULL DEFAULT NOW(),
			reviewed_by          text        NOT NULL DEFAULT '',
			last_reviewed_at     timestamptz,
			review_due_at        timestamptz,
			UNIQUE (technique_id, cve_id, relationship_type)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_tcr_technique ON technique_cve_relationships (technique_id)`,
		`CREATE INDEX IF NOT EXISTS idx_tcr_cve       ON technique_cve_relationships (cve_id)`,
		`CREATE INDEX IF NOT EXISTS idx_tcr_active_scored ON technique_cve_relationships (technique_id)
			WHERE status = 'Active' AND effective_confidence IN ('High','Medium')`,

		// relationship_evidence: one relationship → many supporting references.
		// Soft-delete only — evidence is provenance, never hard-erased.
		`CREATE TABLE IF NOT EXISTS relationship_evidence (
			id              text        PRIMARY KEY DEFAULT gen_random_uuid()::text,
			relationship_id text        NOT NULL REFERENCES technique_cve_relationships(id) ON DELETE CASCADE,
			source          text        NOT NULL DEFAULT 'Analyst',
			reference_type  text        NOT NULL DEFAULT 'URL', -- URL/CVE Advisory/PDF/Threat Report/Internal Note
			reference_value text        NOT NULL DEFAULT '',
			note            text        NOT NULL DEFAULT '',
			priority        int         NOT NULL DEFAULT 0, -- lower = more prominent in display ordering
			added_by        text        NOT NULL DEFAULT '',
			added_at        timestamptz NOT NULL DEFAULT NOW(),
			deleted         boolean     NOT NULL DEFAULT false,
			deleted_by      text        NOT NULL DEFAULT '',
			deleted_at      timestamptz
		)`,
		`CREATE INDEX IF NOT EXISTS idx_reve_relationship ON relationship_evidence (relationship_id) WHERE NOT deleted`,
		// Threat readiness history — one row per (run, actor) pair, written by the
		// reporting engine when BuildFromRun generates a report. Powers trend analysis
		// (are we improving against APT29 / LockBit over time?).
		`CREATE TABLE IF NOT EXISTS threat_readiness_history (
			id          bigserial   PRIMARY KEY,
			run_id      text        NOT NULL,
			agent_id    text        NOT NULL,
			actor_name  text        NOT NULL,
			prevention  real        NOT NULL DEFAULT 0,
			detection   real        NOT NULL DEFAULT 0,
			tested      int         NOT NULL DEFAULT 0,
			total       int         NOT NULL DEFAULT 0,
			confidence  text        NOT NULL DEFAULT '',
			recorded_at timestamptz NOT NULL DEFAULT NOW()
		)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS trh_run_actor
			ON threat_readiness_history(run_id, actor_name)`,
		`CREATE INDEX IF NOT EXISTS trh_agent_actor_time
			ON threat_readiness_history(agent_id, actor_name, recorded_at DESC)`,
		`CREATE TABLE IF NOT EXISTS owasp_risks (
			risk_id       text        PRIMARY KEY,            -- e.g. A03:2021
			version       text        NOT NULL DEFAULT '',    -- 2013 | 2017 | 2021 | future
			name          text        NOT NULL DEFAULT '',
			display_order int         NOT NULL DEFAULT 0,
			updated_at    timestamptz NOT NULL DEFAULT NOW()
		)`,
		`ALTER TABLE owasp_risks ADD COLUMN IF NOT EXISTS display_order int NOT NULL DEFAULT 0`,
		`CREATE TABLE IF NOT EXISTS technique_owasp (
			technique_id text NOT NULL REFERENCES techniques(technique_id) ON DELETE CASCADE,
			risk_id      text NOT NULL REFERENCES owasp_risks(risk_id) ON DELETE CASCADE,
			PRIMARY KEY (technique_id, risk_id)
		)`,
		`CREATE TABLE IF NOT EXISTS scenarios (
			scenario_id text        PRIMARY KEY,
			name        text        NOT NULL DEFAULT '',
			category    text        NOT NULL DEFAULT '',
			updated_at  timestamptz NOT NULL DEFAULT NOW()
		)`,
		`CREATE TABLE IF NOT EXISTS scenario_techniques (
			scenario_id  text NOT NULL REFERENCES scenarios(scenario_id) ON DELETE CASCADE,
			technique_id text NOT NULL REFERENCES techniques(technique_id) ON DELETE CASCADE,
			PRIMARY KEY (scenario_id, technique_id)
		)`,

		// Phase 7 Multi-Tenancy — the 5 tenant-owned tables in this file.
		// The other 13 tables here are the global ATT&CK/ART/CVE/OWASP catalog
		// and deliberately stay unscoped (spec Decision 5).
		`ALTER TABLE openaev_bundles ADD COLUMN IF NOT EXISTS tenant_id text NOT NULL DEFAULT 'default'`,
		`ALTER TABLE openaev_scenarios ADD COLUMN IF NOT EXISTS tenant_id text NOT NULL DEFAULT 'default'`,
		`ALTER TABLE scenario_techniques ADD COLUMN IF NOT EXISTS tenant_id text NOT NULL DEFAULT 'default'`,
		`ALTER TABLE scenarios ADD COLUMN IF NOT EXISTS tenant_id text NOT NULL DEFAULT 'default'`,
		`ALTER TABLE threat_readiness_history ADD COLUMN IF NOT EXISTS tenant_id text NOT NULL DEFAULT 'default'`,

		// Threat Prioritization — actor-level composite score (see
		// docs/superpowers/specs/2026-07-28-threat-prioritization-design.md).
		`ALTER TABLE threat_actor_profiles ADD COLUMN IF NOT EXISTS confidence text NOT NULL DEFAULT ''`,
		`ALTER TABLE threat_actor_profiles ADD COLUMN IF NOT EXISTS canonical_group_id text NOT NULL DEFAULT ''`,
		`CREATE TABLE IF NOT EXISTS threat_priority_history (
			id          bigserial   PRIMARY KEY,
			actor_name  text        NOT NULL,
			score       int         NOT NULL,
			tier        text        NOT NULL DEFAULT '',
			tenant_id   text        NOT NULL DEFAULT 'default',
			recorded_at timestamptz NOT NULL DEFAULT NOW()
		)`,
		`CREATE INDEX IF NOT EXISTS tph_actor_time ON threat_priority_history(actor_name, recorded_at DESC)`,

		// Intelligence Expansion Phase 1 — MISP-sourced Campaigns/Malware
		// (see docs/superpowers/specs/2026-07-28-intelligence-expansion-design.md).
		`CREATE TABLE IF NOT EXISTS intelligence_campaigns (
			id                  text        PRIMARY KEY,
			name                text        NOT NULL,
			description         text        NOT NULL DEFAULT '',
			actor_ids           text[]      NOT NULL DEFAULT '{}',
			technique_ids       text[]      NOT NULL DEFAULT '{}',
			source_provider     text        NOT NULL,
			source_external_id  text        NOT NULL DEFAULT '',
			source_confidence   text        NOT NULL DEFAULT '',
			last_updated        timestamptz NOT NULL DEFAULT NOW(),
			tenant_id           text        NOT NULL DEFAULT 'default'
		)`,
		`CREATE TABLE IF NOT EXISTS intelligence_malware (
			id                  text        PRIMARY KEY,
			name                text        NOT NULL,
			aliases             text[]      NOT NULL DEFAULT '{}',
			technique_ids       text[]      NOT NULL DEFAULT '{}',
			actor_ids           text[]      NOT NULL DEFAULT '{}',
			campaign_ids        text[]      NOT NULL DEFAULT '{}',
			source_provider     text        NOT NULL,
			source_external_id  text        NOT NULL DEFAULT '',
			source_confidence   text        NOT NULL DEFAULT '',
			last_updated        timestamptz NOT NULL DEFAULT NOW(),
			tenant_id           text        NOT NULL DEFAULT 'default'
		)`,

		// Intelligence Expansion Phase 4 — Tools entity
		// (see docs/superpowers/specs/2026-07-29-intelligence-expansion-phase4-design.md).
		`CREATE TABLE IF NOT EXISTS intelligence_tools (
			id                  text        PRIMARY KEY,
			name                text        NOT NULL,
			aliases             text[]      NOT NULL DEFAULT '{}',
			technique_ids       text[]      NOT NULL DEFAULT '{}',
			actor_ids           text[]      NOT NULL DEFAULT '{}',
			campaign_ids        text[]      NOT NULL DEFAULT '{}',
			source_provider     text        NOT NULL,
			source_external_id  text        NOT NULL DEFAULT '',
			source_confidence   text        NOT NULL DEFAULT '',
			last_updated        timestamptz NOT NULL DEFAULT NOW(),
			tenant_id           text        NOT NULL DEFAULT 'default'
		)`,

		// Intelligence Expansion Phase 5 -- multi-provider provenance
		// (see docs/superpowers/specs/2026-07-29-intelligence-expansion-phase5-design.md).
		// Existing intelligence_campaigns/malware/tools.source_* columns are
		// kept unchanged (no DROP COLUMN precedent in this file) and now mean
		// "the first provider that ever created this row" -- this table is
		// the authoritative multi-provider record.
		`CREATE TABLE IF NOT EXISTS intelligence_entity_sources (
			id           bigserial   PRIMARY KEY,
			entity_type  text        NOT NULL,
			entity_id    text        NOT NULL,
			provider     text        NOT NULL,
			external_id  text        NOT NULL,
			first_seen   timestamptz NOT NULL DEFAULT NOW(),
			last_sync    timestamptz NOT NULL,
			confidence   text        NOT NULL,
			tenant_id    text        NOT NULL DEFAULT 'default',
			UNIQUE (entity_type, entity_id, provider)
		)`,
		`ALTER TABLE intelligence_campaigns ADD COLUMN IF NOT EXISTS aliases text[] NOT NULL DEFAULT '{}'`,
		`ALTER TABLE intelligence_campaigns ADD COLUMN IF NOT EXISTS search_key text[] NOT NULL DEFAULT '{}'`,

		// Global Search Phase 1 -- maintained multi-entity search index
		// (see docs/superpowers/specs/2026-07-29-global-search-phase1-design.md).
		// Rebuilt by internal/search.ReindexAll on a timer + on-demand; never
		// written to by per-entity create/update code paths directly.
		//
		// search_vector is a plain column, NOT a GENERATED ALWAYS AS ...
		// STORED column -- to_tsvector(regconfig, text) is only STABLE, not
		// IMMUTABLE, so Postgres rejects it inside a generated-column
		// expression. Two wrapper-function workarounds (LANGUAGE sql
		// IMMUTABLE, then LANGUAGE plpgsql IMMUTABLE) were both tried and
		// both still failed with the same "generation expression is not
		// immutable" error, confirmed via a real Postgres instance during
		// implementation -- Postgres's generated-column check evidently
		// still detects the transitively-STABLE to_tsvector call inside
		// even a declared-IMMUTABLE wrapper. Computing search_vector
		// explicitly in each INSERT statement (see internal/search/store.go)
		// sidesteps this entirely: regular DML has no immutability
		// restriction on the values being inserted.
		`CREATE TABLE IF NOT EXISTS search_documents (
			id            bigserial   PRIMARY KEY,
			doc_type      text        NOT NULL,
			source_id     text        NOT NULL,
			title         text        NOT NULL,
			description   text        NOT NULL DEFAULT '',
			tags          text[]      NOT NULL DEFAULT '{}',
			search_vector tsvector    NOT NULL,
			updated_at    timestamptz NOT NULL DEFAULT NOW(),
			tenant_id     text        NOT NULL DEFAULT 'default',
			UNIQUE (doc_type, source_id)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_search_documents_vector ON search_documents USING GIN (search_vector)`,

		// search_selections is an append-only event log -- one row per time a
		// user opens a search result. Powers both personal recency (rows
		// filtered to one user_id) and org popularity (rows counted across all
		// users) from the same log. See docs/superpowers/specs/2026-07-29-
		// global-search-phase3-design.md Architecture §1.
		`CREATE TABLE IF NOT EXISTS search_selections (
			id         bigserial   PRIMARY KEY,
			user_id    text        NOT NULL REFERENCES users(id),
			doc_type   text        NOT NULL,
			source_id  text        NOT NULL,
			created_at timestamptz NOT NULL DEFAULT NOW()
		)`,
		`CREATE INDEX IF NOT EXISTS idx_search_selections_user ON search_selections (user_id, created_at DESC)`,
		`CREATE INDEX IF NOT EXISTS idx_search_selections_entity ON search_selections (doc_type, source_id, created_at DESC)`,

		// search_favorites is a real toggle table (insert/delete), not an
		// event log -- a favorite is a boolean state, not a history, and the
		// UNIQUE constraint makes "is this favorited" a single indexed lookup.
		`CREATE TABLE IF NOT EXISTS search_favorites (
			id         bigserial   PRIMARY KEY,
			user_id    text        NOT NULL REFERENCES users(id),
			doc_type   text        NOT NULL,
			source_id  text        NOT NULL,
			created_at timestamptz NOT NULL DEFAULT NOW(),
			UNIQUE (user_id, doc_type, source_id)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_search_favorites_user ON search_favorites (user_id)`,

		// vex_sweeps.current_technique_started_at -- lets vexsweep.Dispatcher
		// detect a technique whose underlying execution has genuinely hung
		// (e.g. an ART atomic test that launches a GUI executable with no
		// auto-exit) and force-cancel it instead of waiting forever. See
		// dispatcher.go's stuckThreshold.
		`ALTER TABLE vex_sweeps ADD COLUMN IF NOT EXISTS current_technique_started_at timestamptz`,
	}

	for _, s := range stmts {
		if _, err := pool.Exec(ctx, s); err != nil {
			return fmt.Errorf("content schema exec failed:\n%s\nerror: %w", s, err)
		}
	}
	return nil
}
