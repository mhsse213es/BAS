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
	}

	for _, s := range stmts {
		if _, err := pool.Exec(ctx, s); err != nil {
			return fmt.Errorf("content schema exec failed:\n%s\nerror: %w", s, err)
		}
	}
	return nil
}
