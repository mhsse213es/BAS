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

		// ── Knowledge graph: created now to avoid a future migration ──────────
		`CREATE TABLE IF NOT EXISTS cves (
			cve_id      text        PRIMARY KEY,              -- e.g. CVE-2024-3400
			description text        NOT NULL DEFAULT '',
			cvss        real,
			published   date,
			updated_at  timestamptz NOT NULL DEFAULT NOW()
		)`,
		`CREATE TABLE IF NOT EXISTS technique_cves (
			technique_id text NOT NULL REFERENCES techniques(technique_id) ON DELETE CASCADE,
			cve_id       text NOT NULL REFERENCES cves(cve_id) ON DELETE CASCADE,
			PRIMARY KEY (technique_id, cve_id)
		)`,
		`CREATE TABLE IF NOT EXISTS owasp_risks (
			risk_id    text        PRIMARY KEY,               -- e.g. A03:2021
			version    text        NOT NULL DEFAULT '',       -- 2013 | 2017 | 2021 | future
			name       text        NOT NULL DEFAULT '',
			updated_at timestamptz NOT NULL DEFAULT NOW()
		)`,
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
