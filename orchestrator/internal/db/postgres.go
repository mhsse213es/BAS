package db

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Connect creates a pgxpool connection and verifies reachability.
func Connect(ctx context.Context, dsn string) (*pgxpool.Pool, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("pgxpool.New: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("db ping: %w", err)
	}
	return pool, nil
}

// EnsureSchema creates all required tables if they do not exist.
// Idempotent — safe to call on every startup.
func EnsureSchema(ctx context.Context, pool *pgxpool.Pool) error {
	stmts := []string{
		`CREATE EXTENSION IF NOT EXISTS "pgcrypto"`,

		// Phase 7 Multi-Tenancy — tenant registry. Must precede users so
		// users.tenant_id's REFERENCES clause resolves. The 'default' bootstrap
		// row makes every pre-tenancy install a single-tenant instance whose
		// one tenant is id'd 'default'; existing behavior is unchanged.
		`CREATE TABLE IF NOT EXISTS tenants (
			id         text        PRIMARY KEY DEFAULT gen_random_uuid()::text,
			name       text        NOT NULL,
			slug       text        NOT NULL UNIQUE,
			status     text        NOT NULL DEFAULT 'active',
			created_at timestamptz NOT NULL DEFAULT NOW()
		)`,
		`INSERT INTO tenants (id, name, slug, status)
		 VALUES ('default', 'Default Tenant', 'default', 'active')
		 ON CONFLICT (id) DO NOTHING`,

		`CREATE TABLE IF NOT EXISTS users (
			id            text        PRIMARY KEY DEFAULT gen_random_uuid()::text,
			username      text        UNIQUE NOT NULL,
			password_hash text        NOT NULL,
			role          text        NOT NULL DEFAULT 'analyst',
			is_active     boolean     NOT NULL DEFAULT true,
			must_change_pw boolean    NOT NULL DEFAULT false,
			created_at    timestamptz NOT NULL DEFAULT NOW(),
			last_login    timestamptz
		)`,

		// Idempotent migrations for existing deployments
		`ALTER TABLE users ADD COLUMN IF NOT EXISTS is_active boolean NOT NULL DEFAULT true`,
		`ALTER TABLE users ADD COLUMN IF NOT EXISTS must_change_pw boolean NOT NULL DEFAULT false`,
		// tenant_id: NULL = platform-admin (belongs to no single tenant);
		// non-NULL = regular tenant user. DEFAULT 'default' backfills every
		// pre-tenancy row and covers INSERTs that omit the column.
		`ALTER TABLE users ADD COLUMN IF NOT EXISTS tenant_id text REFERENCES tenants(id) DEFAULT 'default'`,

		`CREATE TABLE IF NOT EXISTS agents (
			agent_id       text        PRIMARY KEY,
			hostname       text        NOT NULL DEFAULT '',
			ip_address     text        NOT NULL DEFAULT '',
			os_version     text        NOT NULL DEFAULT '',
			username       text        NOT NULL DEFAULT '',
			status         text        NOT NULL DEFAULT 'idle',
			env_label      text        NOT NULL DEFAULT 'Production',
			has_report     boolean     NOT NULL DEFAULT false,
			binary_hash    text        NOT NULL DEFAULT '',
			binary_trusted boolean     NOT NULL DEFAULT false,
			last_update    timestamptz NOT NULL DEFAULT NOW()
		)`,

		// Idempotent migrations for existing deployments
		`ALTER TABLE agents ADD COLUMN IF NOT EXISTS binary_hash    text    NOT NULL DEFAULT ''`,
		`ALTER TABLE agents ADD COLUMN IF NOT EXISTS binary_trusted boolean NOT NULL DEFAULT false`,
		`ALTER TABLE agents ADD COLUMN IF NOT EXISTS state          text    NOT NULL DEFAULT 'active'`,
		`ALTER TABLE agents ADD COLUMN IF NOT EXISTS policy_json    jsonb   NOT NULL DEFAULT '{}'`,
		`ALTER TABLE agents ADD COLUMN IF NOT EXISTS enrolled_at    timestamptz`,
		`ALTER TABLE agents ADD COLUMN IF NOT EXISTS protocol_version int  NOT NULL DEFAULT 1`,
		// security_products: installed AV/EDR inventory reported by the agent
		// heartbeat (presence only) — shown as the report's security context.
		`ALTER TABLE agents ADD COLUMN IF NOT EXISTS security_products jsonb NOT NULL DEFAULT '[]'`,
		`ALTER TABLE agents ADD COLUMN IF NOT EXISTS posture_catalog jsonb NOT NULL DEFAULT '{}'`,

		`CREATE TABLE IF NOT EXISTS scenario_runs (
			id             text        PRIMARY KEY DEFAULT gen_random_uuid()::text,
			scenario_id    text        NOT NULL,
			agent_id       text        NOT NULL,
			name           text        NOT NULL DEFAULT '',
			status         text        NOT NULL DEFAULT 'running',
			results        jsonb       NOT NULL DEFAULT '[]',
			score          jsonb,
			initiated_by   text,
			started_at     timestamptz NOT NULL DEFAULT NOW(),
			completed_at   timestamptz,
			CONSTRAINT fk_agent FOREIGN KEY (agent_id) REFERENCES agents(agent_id) ON DELETE CASCADE
		)`,

		`ALTER TABLE scenario_runs ADD COLUMN IF NOT EXISTS initiated_by text`,
		`ALTER TABLE scenario_runs ADD COLUMN IF NOT EXISTS score jsonb`,
		`ALTER TABLE scenario_runs ADD COLUMN IF NOT EXISTS name text NOT NULL DEFAULT ''`,
		// step_meta: TaskID→{techniqueId,name,framework} for the steps actually
		// dispatched. Needed to interpret results from dynamically-built ART/Caldera
		// runs, whose steps are not stored in the scenario's static Steps.
		`ALTER TABLE scenario_runs ADD COLUMN IF NOT EXISTS step_meta jsonb NOT NULL DEFAULT '{}'`,
		// Prevents a TOCTOU race in dispatchRun's busy guard: without this,
		// two concurrent dispatch requests to the same idle agent can both
		// pass the "no running run" check and both insert a 'running' row.
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_scenario_runs_agent_running ON scenario_runs(agent_id) WHERE status = 'running'`,
		// reverted: list of endpoint changes the agent rolled back after the run
		// (registry keys, files) — surfaced as the report's cleanup-verification.
		`ALTER TABLE scenario_runs ADD COLUMN IF NOT EXISTS reverted jsonb NOT NULL DEFAULT '[]'`,
		// variant_depth: depth selected by the operator at dispatch time.
		// "none" (default) = base test only; "quick" / "standard" / "full" = expanded.
		`ALTER TABLE scenario_runs ADD COLUMN IF NOT EXISTS variant_depth text NOT NULL DEFAULT 'none'`,

		`CREATE INDEX IF NOT EXISTS idx_scenario_runs_agent ON scenario_runs(agent_id)`,
		`CREATE INDEX IF NOT EXISTS idx_scenario_runs_scenario ON scenario_runs(scenario_id)`,

		// ── Per-variant execution results ─────────────────────────────────────
		// One row per executed variant step (not the base step). Written when
		// SubmitScenarioResult processes a run that had variant_depth != 'none'.
		// Drives coverage heatmaps, bypass reports, ATT&CK reporting, and the
		// "best bypass path" findings without any schema change later.
		`CREATE TABLE IF NOT EXISTS scenario_variant_results (
			id                  text        PRIMARY KEY DEFAULT gen_random_uuid()::text,
			run_id              text        NOT NULL,
			scenario_id         text        NOT NULL,
			step_id             text        NOT NULL,       -- base step TaskID
			variant_id          text        NOT NULL,       -- VariantSpec.ID(techniqueId) 16-hex
			technique_id        text        NOT NULL,
			proxy_technique_id  text,                       -- T1047/T1053.005/T1559.001 if non-direct
			encoding            text        NOT NULL DEFAULT 'plain',
			privilege           text        NOT NULL DEFAULT 'user',
			execution_context   text        NOT NULL DEFAULT 'direct',
			platform            text        NOT NULL DEFAULT 'windows',
			requested_privilege text,                       -- from ExecResult.RequestedPriv
			actual_privilege    text,                       -- from ExecResult.ExecutedAs
			verdict             text        NOT NULL,       -- blocked|detected|logged|bypassed|error|skipped
			duration_ms         bigint,
			executed_at         timestamptz,
			raw_result          jsonb,                      -- full SimulationResult JSON for forensics
			created_at          timestamptz NOT NULL DEFAULT NOW(),
			UNIQUE (run_id, step_id, variant_id)            -- idempotent on agent retry
		)`,
		`CREATE INDEX IF NOT EXISTS idx_svr_run_id    ON scenario_variant_results (run_id)`,
		`CREATE INDEX IF NOT EXISTS idx_svr_tech_verdict ON scenario_variant_results (technique_id, verdict)`,
		`CREATE INDEX IF NOT EXISTS idx_svr_variant_id ON scenario_variant_results (variant_id)`,

		// ── Variant Coverage Report — pre-computed per-technique summary ───────
		// Stores one row per (run_id, technique_id) with aggregate counts and the
		// best_bypass_variant_id pre-computed at result submission time so every
		// subsequent report render is a simple O(1) lookup rather than a re-sort.
		`CREATE TABLE IF NOT EXISTS scenario_variant_technique_summary (
			id                      text        PRIMARY KEY DEFAULT gen_random_uuid()::text,
			run_id                  text        NOT NULL,
			technique_id            text        NOT NULL,
			technique_name          text        NOT NULL DEFAULT '',
			tactic                  text        NOT NULL DEFAULT '',
			variants_executed       int         NOT NULL DEFAULT 0,
			blocked                 int         NOT NULL DEFAULT 0,
			detected                int         NOT NULL DEFAULT 0,
			logged                  int         NOT NULL DEFAULT 0,
			bypassed                int         NOT NULL DEFAULT 0,
			errors                  int         NOT NULL DEFAULT 0,
			skipped                 int         NOT NULL DEFAULT 0,
			best_bypass_variant_id  text,
			encodings_tested        text[]      NOT NULL DEFAULT '{}',
			privileges_tested       text[]      NOT NULL DEFAULT '{}',
			contexts_tested         text[]      NOT NULL DEFAULT '{}',
			computed_at             timestamptz NOT NULL DEFAULT NOW(),
			UNIQUE (run_id, technique_id)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_svts_run_id    ON scenario_variant_technique_summary (run_id)`,
		`CREATE INDEX IF NOT EXISTS idx_svts_bypassed  ON scenario_variant_technique_summary (run_id, bypassed DESC)`,

		// ── Campaign Variant Summary — pre-computed once per campaign ─────────
		// Aggregates scenario_variant_technique_summary across all child runs.
		// Refreshed async whenever a run result is submitted to the campaign.
		`CREATE TABLE IF NOT EXISTS campaign_variant_summary (
			campaign_id         text        PRIMARY KEY,
			techniques_tested   int         NOT NULL DEFAULT 0,
			variants_executed   int         NOT NULL DEFAULT 0,
			blocked             int         NOT NULL DEFAULT 0,
			detected            int         NOT NULL DEFAULT 0,
			bypassed            int         NOT NULL DEFAULT 0,
			run_count           int         NOT NULL DEFAULT 0,
			prevention_score    double precision NOT NULL DEFAULT 0,
			detection_score     double precision NOT NULL DEFAULT 0,
			top_bypasses        jsonb       NOT NULL DEFAULT '[]',
			tactic_breakdown    jsonb       NOT NULL DEFAULT '[]',
			prev_bypassed       int,
			computed_at         timestamptz NOT NULL DEFAULT NOW()
		)`,

		// ── Phase B-1: run-event stream + denormalized progress summary ───────
		`CREATE TABLE IF NOT EXISTS run_events (
			run_id       text        NOT NULL,
			seq          bigint      NOT NULL,
			type         text        NOT NULL,
			task_id      text        NOT NULL DEFAULT '',
			technique_id text        NOT NULL DEFAULT '',
			ts           timestamptz NOT NULL,
			payload      jsonb       NOT NULL DEFAULT '{}',
			PRIMARY KEY (run_id, seq)
		)`,

		`ALTER TABLE scenario_runs ADD COLUMN IF NOT EXISTS steps_total   int NOT NULL DEFAULT 0`,
		`ALTER TABLE scenario_runs ADD COLUMN IF NOT EXISTS steps_done    int NOT NULL DEFAULT 0`,
		`ALTER TABLE scenario_runs ADD COLUMN IF NOT EXISTS steps_running int NOT NULL DEFAULT 0`,
		`ALTER TABLE scenario_runs ADD COLUMN IF NOT EXISTS steps_passed  int NOT NULL DEFAULT 0`,
		`ALTER TABLE scenario_runs ADD COLUMN IF NOT EXISTS steps_failed  int NOT NULL DEFAULT 0`,
		`ALTER TABLE scenario_runs ADD COLUMN IF NOT EXISTS steps_timeout int NOT NULL DEFAULT 0`,

		`ALTER TABLE scenario_runs ADD COLUMN IF NOT EXISTS detections_raw   jsonb NOT NULL DEFAULT '[]'`,
		`ALTER TABLE scenario_runs ADD COLUMN IF NOT EXISTS detection_summary jsonb`,
		`ALTER TABLE scenario_runs ADD COLUMN IF NOT EXISTS detection_rate   int`,
		`ALTER TABLE scenario_runs ADD COLUMN IF NOT EXISTS undetected_rate  int`,
		`ALTER TABLE scenario_runs ADD COLUMN IF NOT EXISTS mttd_ms          bigint`,

		`CREATE TABLE IF NOT EXISTS campaigns (
			id            text PRIMARY KEY,
			name          text NOT NULL,
			scenario_id   text NOT NULL,
			scenario_name text NOT NULL DEFAULT '',
			mode          text NOT NULL DEFAULT 'posture',
			subset        jsonb NOT NULL DEFAULT '{}',
			reason        text NOT NULL DEFAULT '',
			targets       jsonb NOT NULL DEFAULT '[]',
			skips         jsonb NOT NULL DEFAULT '[]',
			notes         text NOT NULL DEFAULT '',
			tags          jsonb NOT NULL DEFAULT '[]',
			created_by    text,
			created_at    timestamptz NOT NULL DEFAULT NOW(),
			started_at    timestamptz NOT NULL DEFAULT NOW(),
			completed_at  timestamptz,
			stopped_at    timestamptz
		)`,
		`ALTER TABLE scenario_runs ADD COLUMN IF NOT EXISTS campaign_id text`,
		`CREATE INDEX IF NOT EXISTS idx_scenario_runs_campaign ON scenario_runs (campaign_id)`,
		// leaked_steps: count of steps whose cleanup command exited non-zero or timed out.
		// hygiene_score: stepsCleaned/(stepsCleaned+leaked)*100; 100.0 when no cleanup steps.
		// Written at SubmitScenarioResult; used for the Environment Restoration badge in UI.
		`ALTER TABLE scenario_runs ADD COLUMN IF NOT EXISTS leaked_steps int NOT NULL DEFAULT 0`,
		`ALTER TABLE scenario_runs ADD COLUMN IF NOT EXISTS hygiene_score double precision NOT NULL DEFAULT 100.0`,
		`ALTER TABLE scenario_runs ADD COLUMN IF NOT EXISTS alerts_total int NOT NULL DEFAULT 0`,
		`ALTER TABLE scenario_runs ADD COLUMN IF NOT EXISTS alerts_high_fidelity int NOT NULL DEFAULT 0`,
		`ALTER TABLE scenario_runs ADD COLUMN IF NOT EXISTS noise_score double precision NOT NULL DEFAULT 0.0`,
		`ALTER TABLE scenario_runs ADD COLUMN IF NOT EXISTS perf_cpu_before double precision NOT NULL DEFAULT 0.0`,
		`ALTER TABLE scenario_runs ADD COLUMN IF NOT EXISTS perf_cpu_after double precision NOT NULL DEFAULT 0.0`,
		`ALTER TABLE scenario_runs ADD COLUMN IF NOT EXISTS perf_ram_before double precision NOT NULL DEFAULT 0.0`,
		`ALTER TABLE scenario_runs ADD COLUMN IF NOT EXISTS perf_ram_after double precision NOT NULL DEFAULT 0.0`,
		`ALTER TABLE scenario_runs ADD COLUMN IF NOT EXISTS perf_disk_before double precision NOT NULL DEFAULT 0.0`,
		`ALTER TABLE scenario_runs ADD COLUMN IF NOT EXISTS perf_disk_after double precision NOT NULL DEFAULT 0.0`,

		// ── Findings: persistent, de-duplicated, analyst-triaged exposures ────
		`CREATE TABLE IF NOT EXISTS findings (
			id                        text PRIMARY KEY DEFAULT gen_random_uuid()::text,
			agent_id                  text NOT NULL,
			technique_id              text NOT NULL,
			control_class             text NOT NULL,
			technique_name            text NOT NULL DEFAULT '',
			tactic                    text NOT NULL DEFAULT '',
			severity                  text NOT NULL DEFAULT 'Medium',
			exposure_state            text NOT NULL DEFAULT 'missed',
			status                    text NOT NULL DEFAULT 'open',
			source_type               text NOT NULL DEFAULT '',
			attack_data_source        jsonb NOT NULL DEFAULT '[]',
			security_product_snapshot jsonb NOT NULL DEFAULT '[]',
			occurrence_count          int NOT NULL DEFAULT 1,
			reopened_count            int NOT NULL DEFAULT 0,
			last_run_id               text,
			last_campaign_id          text,
			first_seen                timestamptz NOT NULL DEFAULT NOW(),
			last_seen                 timestamptz NOT NULL DEFAULT NOW(),
			last_observed_at          timestamptz NOT NULL DEFAULT NOW(),
			resolved_at               timestamptz,
			resolved_by               text,
			resolved_reason           text,
			created_at                timestamptz NOT NULL DEFAULT NOW(),
			CONSTRAINT uq_finding UNIQUE (agent_id, technique_id, control_class)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_findings_status_sev ON findings (status, severity)`,
		`CREATE INDEX IF NOT EXISTS idx_findings_campaign ON findings (last_campaign_id)`,

		// ── Reports: lightweight, metadata-only generation log (no artifacts) ──
		`CREATE TABLE IF NOT EXISTS report_log (
			id            text PRIMARY KEY DEFAULT gen_random_uuid()::text,
			report_type   text NOT NULL,
			format        text NOT NULL DEFAULT '',
			scope_label   text NOT NULL DEFAULT '',
			parameters    jsonb NOT NULL DEFAULT '{}',
			source        text NOT NULL DEFAULT 'reports_hub',
			status        text NOT NULL DEFAULT 'generated',
			generated_by  text,
			generated_at  timestamptz NOT NULL DEFAULT NOW()
		)`,
		`CREATE INDEX IF NOT EXISTS idx_report_log_time ON report_log (generated_at DESC)`,

		// ── Agent logging tables ──────────────────────────────────────────────
		`CREATE TABLE IF NOT EXISTS agent_op_logs (
			id         bigserial    PRIMARY KEY,
			agent_id   text         NOT NULL,
			level      text         NOT NULL DEFAULT 'info',
			category   text         NOT NULL DEFAULT 'lifecycle',
			message    text         NOT NULL,
			seq        bigint       NOT NULL DEFAULT 0,
			schema_ver int          NOT NULL DEFAULT 1,
			created_at timestamptz  NOT NULL DEFAULT NOW()
		)`,
		`CREATE INDEX IF NOT EXISTS idx_op_logs_agent_time ON agent_op_logs(agent_id, created_at DESC)`,

		`CREATE TABLE IF NOT EXISTS agent_sec_logs (
			id           bigserial   PRIMARY KEY,
			agent_id     text        NOT NULL,
			level        text        NOT NULL DEFAULT 'info',
			scenario_id  text        NOT NULL DEFAULT '',
			run_id       text        NOT NULL DEFAULT '',
			step_id      text        NOT NULL DEFAULT '',
			technique_id text        NOT NULL DEFAULT '',
			category     text        NOT NULL DEFAULT 'scenario_step',
			message      text        NOT NULL,
			seq          bigint      NOT NULL DEFAULT 0,
			schema_ver   int         NOT NULL DEFAULT 1,
			created_at   timestamptz NOT NULL DEFAULT NOW()
		)`,
		`CREATE INDEX IF NOT EXISTS idx_sec_logs_agent_time ON agent_sec_logs(agent_id, created_at DESC)`,
		`CREATE INDEX IF NOT EXISTS idx_sec_logs_run        ON agent_sec_logs(run_id)`,

		`CREATE TABLE IF NOT EXISTS agent_telemetry (
			id         bigserial        PRIMARY KEY,
			agent_id   text             NOT NULL,
			metric     text             NOT NULL,
			value      double precision NOT NULL,
			unit       text             NOT NULL DEFAULT '',
			seq        bigint           NOT NULL DEFAULT 0,
			schema_ver int              NOT NULL DEFAULT 1,
			created_at timestamptz      NOT NULL DEFAULT NOW()
		)`,
		`CREATE INDEX IF NOT EXISTS idx_telemetry_agent_time ON agent_telemetry(agent_id, created_at DESC)`,
		`CREATE INDEX IF NOT EXISTS idx_telemetry_metric     ON agent_telemetry(agent_id, metric, created_at DESC)`,

		// attackpath_collections: one row per agent holding its latest attack-path
		// recon payload (nodes + edges as JSONB). The server rebuilds the fleet
		// graph by loading every row and running the analytics engine. Upserted on
		// agent_id so the newest collection replaces the old — matching the
		// idempotent, at-least-once delivery the rest of the pipeline uses.
		`CREATE TABLE IF NOT EXISTS attackpath_collections (
			agent_id     text        NOT NULL,
			hostname     text        NOT NULL DEFAULT '',
			source       text        NOT NULL DEFAULT 'agent',
			collected_at timestamptz NOT NULL DEFAULT NOW(),
			payload      jsonb       NOT NULL DEFAULT '{}',
			updated_at   timestamptz NOT NULL DEFAULT NOW(),
			PRIMARY KEY (agent_id, source)
		)`,

		// attackpath_schedule: single-row config for periodic fleet collection.
		// When enabled, the orchestrator re-dispatches the stored target list to
		// every connected agent every interval_minutes.
		`CREATE TABLE IF NOT EXISTS attackpath_schedule (
			id               int         PRIMARY KEY DEFAULT 1,
			enabled          boolean     NOT NULL DEFAULT false,
			interval_minutes int         NOT NULL DEFAULT 1440,
			targets          jsonb       NOT NULL DEFAULT '[]',
			segment          text        NOT NULL DEFAULT '',
			run_sharphound   boolean     NOT NULL DEFAULT false,
			last_run_at      timestamptz,
			updated_at       timestamptz NOT NULL DEFAULT NOW(),
			CONSTRAINT attackpath_schedule_singleton CHECK (id = 1)
		)`,

		// attackpath_asset_tags: operator-supplied host metadata (crown-jewel tag,
		// network segment, tier-0 override) the collectors cannot know. Keyed by
		// normalized hostname so a tag survives reconciliation to the SID node.
		`CREATE TABLE IF NOT EXISTS attackpath_asset_tags (
			host_key         text        PRIMARY KEY,
			label            text        NOT NULL DEFAULT '',
			crown_jewel      text        NOT NULL DEFAULT '',
			segment          text        NOT NULL DEFAULT '',
			high_value       boolean     NOT NULL DEFAULT false,
			criticality_tier text        NOT NULL DEFAULT '',
			internet_facing  boolean     NOT NULL DEFAULT false,
			identity_exposed boolean     NOT NULL DEFAULT false,
			production       boolean     NOT NULL DEFAULT false,
			compliance_scope text[]      NOT NULL DEFAULT '{}',
			updated_at       timestamptz NOT NULL DEFAULT NOW()
		)`,
		// SP6 asset criticality: widens the existing operator asset-tag row
		// (crown_jewel/high_value) with graduated criticality factors rather
		// than a parallel table — see docs/superpowers/specs/2026-07-17-sp6-asset-criticality-design.md.
		`ALTER TABLE attackpath_asset_tags ADD COLUMN IF NOT EXISTS criticality_tier text    NOT NULL DEFAULT ''`,
		`ALTER TABLE attackpath_asset_tags ADD COLUMN IF NOT EXISTS internet_facing  boolean NOT NULL DEFAULT false`,
		`ALTER TABLE attackpath_asset_tags ADD COLUMN IF NOT EXISTS identity_exposed boolean NOT NULL DEFAULT false`,
		`ALTER TABLE attackpath_asset_tags ADD COLUMN IF NOT EXISTS production       boolean NOT NULL DEFAULT false`,
		`ALTER TABLE attackpath_asset_tags ADD COLUMN IF NOT EXISTS compliance_scope text[]  NOT NULL DEFAULT '{}'`,

		// attackpath_jobs: lifecycle record for every operator-initiated or scheduled
		// attack-path collection. Tracks the full state machine from queued through
		// completed/failed so the UI can show real progress and the server can handle
		// agent disconnects, ACK timeouts, and retries without losing context.
		`CREATE TABLE IF NOT EXISTS attackpath_jobs (
			id                  text        PRIMARY KEY,
			agent_id            text        NOT NULL,
			status              text        NOT NULL DEFAULT 'queued',
			payload             jsonb       NOT NULL DEFAULT '{}',
			created_at          timestamptz NOT NULL DEFAULT NOW(),
			dispatched_at       timestamptz,
			ack_at              timestamptz,
			started_at          timestamptz,
			completed_at        timestamptz,
			last_heartbeat_at   timestamptz,
			attempts            int         NOT NULL DEFAULT 0,
			expires_at          timestamptz NOT NULL,
			error               text        NOT NULL DEFAULT '',
			progress            jsonb       NOT NULL DEFAULT '{}',
			metrics             jsonb       NOT NULL DEFAULT '{}'
		)`,
		// Idempotent migrations for tables that may already exist without these columns.
		`ALTER TABLE attackpath_jobs ADD COLUMN IF NOT EXISTS started_at timestamptz`,
		`ALTER TABLE attackpath_jobs ADD COLUMN IF NOT EXISTS metrics jsonb NOT NULL DEFAULT '{}'`,
		`CREATE INDEX IF NOT EXISTS idx_attackpath_jobs_agent
			ON attackpath_jobs(agent_id, status)`,
		`CREATE INDEX IF NOT EXISTS idx_attackpath_jobs_active
			ON attackpath_jobs(expires_at)
			WHERE status NOT IN ('completed','failed','timed_out','delivery_failed','cancelled')`,

		// attackpath_collection_history: one row per completed (or failed) collection
		// event. The full graph payload stays in attackpath_collections (latest only);
		// history stores only the lightweight metadata operators need for audit and
		// troubleshooting without growing unboundedly.
		`CREATE TABLE IF NOT EXISTS attackpath_collection_history (
			id              text        PRIMARY KEY DEFAULT gen_random_uuid()::text,
			agent_id        text        NOT NULL,
			hostname        text        NOT NULL DEFAULT '',
			source          text        NOT NULL DEFAULT 'agent',
			collected_at    timestamptz NOT NULL,
			node_count      int         NOT NULL DEFAULT 0,
			edge_count      int         NOT NULL DEFAULT 0,
			sharphound      boolean     NOT NULL DEFAULT false,
			duration_ms     bigint      NOT NULL DEFAULT 0,
			status          text        NOT NULL DEFAULT 'completed',
			error_msg       text        NOT NULL DEFAULT ''
		)`,
		`CREATE INDEX IF NOT EXISTS idx_aph_agent_time
			ON attackpath_collection_history(agent_id, collected_at DESC)`,

		// ── Tamper events: filesystem integrity violations ─────────────────────
		// Populated by integrity.StartWatcher when any protected file is modified,
		// deleted, or created unexpectedly. Acknowledged by an admin via the dashboard.
		`CREATE TABLE IF NOT EXISTS tamper_events (
			id            text        PRIMARY KEY DEFAULT gen_random_uuid()::text,
			detected_at   timestamptz NOT NULL DEFAULT NOW(),
			path          text        NOT NULL,
			event_type    text        NOT NULL,   -- 'write' | 'remove' | 'create'
			severity      text        NOT NULL,   -- 'critical' | 'warning'
			acknowledged  boolean     NOT NULL DEFAULT false,
			acked_by      text        REFERENCES users(id) ON DELETE SET NULL,
			acked_at      timestamptz
		)`,
		`CREATE INDEX IF NOT EXISTS idx_tamper_events_ack ON tamper_events (acknowledged, detected_at DESC)`,

		// audit_logs: immutable, append-only record of every significant operator
		// action. actor_id references users(id) but is stored as plain text so
		// deleted users' entries are preserved (no FK cascade). Username is resolved
		// via LEFT JOIN at query time so we never need to store it redundantly.
		`CREATE TABLE IF NOT EXISTS audit_logs (
			id         bigserial   PRIMARY KEY,
			ts         timestamptz NOT NULL DEFAULT NOW(),
			actor_id   text        NOT NULL DEFAULT '',
			action     text        NOT NULL,
			resource   text        NOT NULL DEFAULT '',
			detail     jsonb       NOT NULL DEFAULT '{}',
			ip         text        NOT NULL DEFAULT '',
			outcome    text        NOT NULL DEFAULT 'ok'
		)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_logs_ts     ON audit_logs (ts DESC)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_logs_actor  ON audit_logs (actor_id, ts DESC)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit_logs (action, ts DESC)`,

		// ── Variant executor: multi-variant technique execution ───────────────
		// variant_runs: one row per dispatched variant set (linked to scenario_runs).
		`CREATE TABLE IF NOT EXISTS variant_runs (
			id              text        PRIMARY KEY DEFAULT gen_random_uuid()::text,
			agent_id        text        NOT NULL,
			technique_id    text        NOT NULL,
			base_type       text        NOT NULL DEFAULT 'art',
			base_id         text        NOT NULL DEFAULT '',
			scenario_run_id text        NOT NULL,
			total_variants  int         NOT NULL DEFAULT 0,
			status          text        NOT NULL DEFAULT 'running',
			created_at      timestamptz NOT NULL DEFAULT NOW(),
			completed_at    timestamptz
		)`,
		`CREATE INDEX IF NOT EXISTS idx_variant_runs_agent     ON variant_runs (agent_id)`,
		`CREATE INDEX IF NOT EXISTS idx_variant_runs_technique ON variant_runs (technique_id)`,
		`CREATE INDEX IF NOT EXISTS idx_variant_runs_run       ON variant_runs (scenario_run_id)`,

		// variant_run_steps: per-template metadata stored at dispatch time.
		// Joined with scenario_runs.results on task_id to reconstruct per-variant verdicts.
		`CREATE TABLE IF NOT EXISTS variant_run_steps (
			id              text PRIMARY KEY DEFAULT gen_random_uuid()::text,
			variant_run_id  text NOT NULL,
			task_id         text NOT NULL,
			technique_id    text NOT NULL,
			encoding        text NOT NULL,
			exec_context    text NOT NULL,
			evasion         text NOT NULL,
			executor        text NOT NULL,
			cmd_preview     text NOT NULL DEFAULT ''
		)`,
		`CREATE INDEX IF NOT EXISTS idx_variant_run_steps_run  ON variant_run_steps (variant_run_id)`,
		`CREATE INDEX IF NOT EXISTS idx_variant_run_steps_task ON variant_run_steps (task_id)`,

		// Phase 2 migrations: risk classification and dedup fingerprint per step.
		`ALTER TABLE variant_run_steps ADD COLUMN IF NOT EXISTS risk_level   text NOT NULL DEFAULT 'SAFE'`,
		`ALTER TABLE variant_run_steps ADD COLUMN IF NOT EXISTS variant_hash text NOT NULL DEFAULT ''`,

		// variant_findings: structured gap findings linked to variant results.
		// Populated when an ALLOWED result maps to a specific remediation recommendation.
		`CREATE TABLE IF NOT EXISTS variant_findings (
			id             text        PRIMARY KEY DEFAULT gen_random_uuid()::text,
			variant_run_id text        NOT NULL,
			task_id        text        NOT NULL,
			technique_id   text        NOT NULL,
			encoding       text        NOT NULL,
			exec_context   text        NOT NULL,
			evasion        text        NOT NULL,
			risk_level     text        NOT NULL DEFAULT 'SAFE',
			gap_summary    text        NOT NULL DEFAULT '',
			recommendation text        NOT NULL DEFAULT '',
			created_at     timestamptz NOT NULL DEFAULT NOW()
		)`,
		`CREATE INDEX IF NOT EXISTS idx_variant_findings_run  ON variant_findings (variant_run_id)`,
		`CREATE INDEX IF NOT EXISTS idx_variant_findings_tech ON variant_findings (technique_id)`,

		// Dedup rows created before the unique index below existed (retried
		// result deliveries used to create duplicates — the ON CONFLICT DO
		// NOTHING in upsertVariantFindingsForRun's INSERT had no constraint to
		// arbitrate against). Keeps one arbitrary row per (variant_run_id, task_id).
		`DELETE FROM variant_findings a USING variant_findings b
			WHERE a.id > b.id AND a.variant_run_id = b.variant_run_id AND a.task_id = b.task_id`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_variant_findings_run_task ON variant_findings (variant_run_id, task_id)`,

		// payload_families: named PS script payloads per technique.
		// Generate() is applied to each family, so total variants scale with family count.
		`CREATE TABLE IF NOT EXISTS payload_families (
			id           text        PRIMARY KEY DEFAULT gen_random_uuid()::text,
			technique_id text        NOT NULL,
			name         text        NOT NULL,
			description  text        NOT NULL DEFAULT '',
			payload      text        NOT NULL,
			purpose      text        NOT NULL DEFAULT 'recon',
			risk_level   text        NOT NULL DEFAULT 'SAFE',
			platform     text        NOT NULL DEFAULT 'windows',
			executor     text        NOT NULL DEFAULT 'powershell',
			created_at   timestamptz NOT NULL DEFAULT NOW(),
			CONSTRAINT uq_payload_family UNIQUE (technique_id, name)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_payload_families_tech ON payload_families (technique_id)`,

		// Phase 4 migrations
		`ALTER TABLE variant_runs ADD COLUMN IF NOT EXISTS execution_mode    text NOT NULL DEFAULT 'sequential'`,
		`ALTER TABLE variant_runs ADD COLUMN IF NOT EXISTS generator_version text NOT NULL DEFAULT ''`,
		`ALTER TABLE payload_families ADD COLUMN IF NOT EXISTS tactic text NOT NULL DEFAULT ''`,

		// ── Seed: default payload families (with tactic) ─────────────────────────
		// T1059.001 — PowerShell Execution — tactic: execution
		`INSERT INTO payload_families (technique_id,name,description,payload,purpose,risk_level,tactic) VALUES
		 ('T1059.001','Recon - Identity','Current user and group memberships',
		  'whoami /all','recon','SAFE','execution')
		 ON CONFLICT (technique_id,name) DO UPDATE SET tactic = EXCLUDED.tactic`,

		`INSERT INTO payload_families (technique_id,name,description,payload,purpose,risk_level,tactic) VALUES
		 ('T1059.001','Recon - System Info','Full system information dump',
		  'systeminfo','recon','SAFE','execution')
		 ON CONFLICT (technique_id,name) DO UPDATE SET tactic = EXCLUDED.tactic`,

		`INSERT INTO payload_families (technique_id,name,description,payload,purpose,risk_level,tactic) VALUES
		 ('T1059.001','Recon - Network Config','IP config and active connections',
		  'ipconfig /all; netstat -ano','recon','SAFE','execution')
		 ON CONFLICT (technique_id,name) DO UPDATE SET tactic = EXCLUDED.tactic`,

		`INSERT INTO payload_families (technique_id,name,description,payload,purpose,risk_level,tactic) VALUES
		 ('T1059.001','Recon - Process List','Running processes with paths',
		  'Get-Process | Select-Object Name,Id,Path,CPU | Sort-Object CPU -Descending','recon','SAFE','execution')
		 ON CONFLICT (technique_id,name) DO UPDATE SET tactic = EXCLUDED.tactic`,

		`INSERT INTO payload_families (technique_id,name,description,payload,purpose,risk_level,tactic) VALUES
		 ('T1059.001','Recon - Domain Info','Active Directory domain information',
		  'try{[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()}catch{"Not domain-joined"}','recon','SAFE','execution')
		 ON CONFLICT (technique_id,name) DO UPDATE SET tactic = EXCLUDED.tactic`,

		`INSERT INTO payload_families (technique_id,name,description,payload,purpose,risk_level,tactic) VALUES
		 ('T1059.001','Download Stager','Simulates a download cradle (loopback only)',
		  '$wc=New-Object Net.WebClient;try{$wc.DownloadString(''http://127.0.0.1/bas-test'')}catch{"Connection refused - expected"}','download','MODERATE','execution')
		 ON CONFLICT (technique_id,name) DO UPDATE SET tactic = EXCLUDED.tactic`,

		// T1082 — System Information Discovery — tactic: discovery
		`INSERT INTO payload_families (technique_id,name,description,payload,purpose,risk_level,tactic) VALUES
		 ('T1082','WMI Computer System','Hardware and domain info via WMI',
		  'Get-WmiObject Win32_ComputerSystem | Select-Object Name,Domain,Manufacturer,Model,TotalPhysicalMemory','recon','SAFE','discovery')
		 ON CONFLICT (technique_id,name) DO UPDATE SET tactic = EXCLUDED.tactic`,

		`INSERT INTO payload_families (technique_id,name,description,payload,purpose,risk_level,tactic) VALUES
		 ('T1082','OS Version','Operating system version and build',
		  'Get-WmiObject Win32_OperatingSystem | Select-Object Caption,Version,BuildNumber,LastBootUpTime','recon','SAFE','discovery')
		 ON CONFLICT (technique_id,name) DO UPDATE SET tactic = EXCLUDED.tactic`,

		`INSERT INTO payload_families (technique_id,name,description,payload,purpose,risk_level,tactic) VALUES
		 ('T1082','Installed Software','List installed applications',
		  'Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName,DisplayVersion | Where-Object {$_.DisplayName} | Sort-Object DisplayName','recon','SAFE','discovery')
		 ON CONFLICT (technique_id,name) DO UPDATE SET tactic = EXCLUDED.tactic`,

		// T1016 — System Network Configuration Discovery — tactic: discovery
		`INSERT INTO payload_families (technique_id,name,description,payload,purpose,risk_level,tactic) VALUES
		 ('T1016','IP Configuration','Full IP configuration of all adapters',
		  'ipconfig /all','recon','SAFE','discovery')
		 ON CONFLICT (technique_id,name) DO UPDATE SET tactic = EXCLUDED.tactic`,

		`INSERT INTO payload_families (technique_id,name,description,payload,purpose,risk_level,tactic) VALUES
		 ('T1016','Routing Table','System routing table',
		  'route print','recon','SAFE','discovery')
		 ON CONFLICT (technique_id,name) DO UPDATE SET tactic = EXCLUDED.tactic`,

		`INSERT INTO payload_families (technique_id,name,description,payload,purpose,risk_level,tactic) VALUES
		 ('T1016','DNS Cache','Cached DNS entries',
		  'Get-DnsClientCache | Select-Object Entry,Data,TimeToLive','recon','SAFE','discovery')
		 ON CONFLICT (technique_id,name) DO UPDATE SET tactic = EXCLUDED.tactic`,

		// T1057 — Process Discovery — tactic: discovery
		`INSERT INTO payload_families (technique_id,name,description,payload,purpose,risk_level,tactic) VALUES
		 ('T1057','All Processes','Full process list with owner',
		  'Get-Process | Select-Object Name,Id,CPU,WorkingSet,Path -ErrorAction SilentlyContinue','recon','SAFE','discovery')
		 ON CONFLICT (technique_id,name) DO UPDATE SET tactic = EXCLUDED.tactic`,

		`INSERT INTO payload_families (technique_id,name,description,payload,purpose,risk_level,tactic) VALUES
		 ('T1057','Security Products','Identify running security/AV processes',
		  'Get-Process | Where-Object {$_.Name -match "defender|sentinel|crowdstrike|trellix|mcafee|symantec|sophos|cylance"} | Select-Object Name,Id,Path','recon','SAFE','discovery')
		 ON CONFLICT (technique_id,name) DO UPDATE SET tactic = EXCLUDED.tactic`,

		// T1049 — System Network Connections Discovery — tactic: discovery
		`INSERT INTO payload_families (technique_id,name,description,payload,purpose,risk_level,tactic) VALUES
		 ('T1049','Active TCP Connections','All active TCP connections with process IDs',
		  'netstat -ano','recon','SAFE','discovery')
		 ON CONFLICT (technique_id,name) DO UPDATE SET tactic = EXCLUDED.tactic`,

		`INSERT INTO payload_families (technique_id,name,description,payload,purpose,risk_level,tactic) VALUES
		 ('T1049','PowerShell TCP View','Active connections via PowerShell (includes process name)',
		  'Get-NetTCPConnection -State Established | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,OwningProcess | Sort-Object OwningProcess','recon','SAFE','discovery')
		 ON CONFLICT (technique_id,name) DO UPDATE SET tactic = EXCLUDED.tactic`,

		// T1033 — System Owner/User Discovery — tactic: discovery
		`INSERT INTO payload_families (technique_id,name,description,payload,purpose,risk_level,tactic) VALUES
		 ('T1033','Current User','Current user identity and privileges',
		  'whoami /all','recon','SAFE','discovery')
		 ON CONFLICT (technique_id,name) DO UPDATE SET tactic = EXCLUDED.tactic`,

		`INSERT INTO payload_families (technique_id,name,description,payload,purpose,risk_level,tactic) VALUES
		 ('T1033','Local Users','All local user accounts',
		  'Get-LocalUser | Select-Object Name,Enabled,LastLogon,PasswordRequired','recon','SAFE','discovery')
		 ON CONFLICT (technique_id,name) DO UPDATE SET tactic = EXCLUDED.tactic`,

		`INSERT INTO payload_families (technique_id,name,description,payload,purpose,risk_level,tactic) VALUES
		 ('T1033','Local Groups','Local group memberships',
		  'Get-LocalGroup | ForEach-Object {$g=$_.Name; Get-LocalGroupMember $g -ErrorAction SilentlyContinue | Select-Object @{n="Group";e={$g}},Name,ObjectClass}','recon','SAFE','discovery')
		 ON CONFLICT (technique_id,name) DO UPDATE SET tactic = EXCLUDED.tactic`,

		// Compliance score snapshots — one row per (agent, framework), upserted
		// after every run so the dashboard can read scores in O(1) without
		// recomputing across the full run history on each page load.
		`CREATE TABLE IF NOT EXISTS compliance_snapshots (
			agent_id          TEXT         NOT NULL,
			framework_id      TEXT         NOT NULL,
			snapshot_at       TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
			run_count         INT          NOT NULL DEFAULT 0,
			compliance_pct    NUMERIC(5,2) NOT NULL DEFAULT 0,
			coverage_pct      NUMERIC(5,2) NOT NULL DEFAULT 0,
			total_controls    INT          NOT NULL DEFAULT 0,
			testable_controls INT          NOT NULL DEFAULT 0,
			tested_controls   INT          NOT NULL DEFAULT 0,
			passing_controls  INT          NOT NULL DEFAULT 0,
			failing_controls  INT          NOT NULL DEFAULT 0,
			manual_controls   INT          NOT NULL DEFAULT 0,
			PRIMARY KEY (agent_id, framework_id)
		)`,
		`CREATE INDEX IF NOT EXISTS compliance_snapshots_agent ON compliance_snapshots (agent_id)`,

		// ── Ticketing: ITSM connector configs + per-finding ticket refs ───────
		`CREATE TABLE IF NOT EXISTS ticketing_configs (
			id          text        PRIMARY KEY DEFAULT gen_random_uuid()::text,
			name        text        NOT NULL,
			provider    text        NOT NULL,
			enabled     boolean     NOT NULL DEFAULT true,
			auto_create text        NOT NULL DEFAULT 'off',
			auto_update boolean     NOT NULL DEFAULT true,
			auto_close  boolean     NOT NULL DEFAULT true,
			settings    jsonb       NOT NULL DEFAULT '{}',
			created_at  timestamptz NOT NULL DEFAULT NOW(),
			updated_at  timestamptz NOT NULL DEFAULT NOW()
		)`,
		`CREATE TABLE IF NOT EXISTS finding_tickets (
			id                    text        PRIMARY KEY DEFAULT gen_random_uuid()::text,
			finding_id            text        NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
			config_id             text        NOT NULL REFERENCES ticketing_configs(id) ON DELETE CASCADE,
			ticket_id             text        NOT NULL,
			ticket_url            text        NOT NULL DEFAULT '',
			status                text        NOT NULL DEFAULT 'open',
			revalidation_required boolean     NOT NULL DEFAULT false,
			last_synced_at        timestamptz,
			created_at            timestamptz NOT NULL DEFAULT NOW(),
			CONSTRAINT uq_finding_ticket UNIQUE (finding_id, config_id)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_finding_tickets_finding ON finding_tickets (finding_id)`,
		`CREATE INDEX IF NOT EXISTS idx_finding_tickets_status  ON finding_tickets (status)`,

		// Idempotent migrations for ticketing_configs
		`ALTER TABLE ticketing_configs ADD COLUMN IF NOT EXISTS last_test_ok    boolean`,
		`ALTER TABLE ticketing_configs ADD COLUMN IF NOT EXISTS last_test_at    timestamptz`,
		`ALTER TABLE ticketing_configs ADD COLUMN IF NOT EXISTS last_test_error text NOT NULL DEFAULT ''`,

		// Idempotent migration for finding_tickets — tracks when an auto-revalidation
		// run was dispatched so the loop skips already-queued revalidations.
		`ALTER TABLE finding_tickets ADD COLUMN IF NOT EXISTS revalidation_dispatched_at timestamptz`,
		`CREATE INDEX IF NOT EXISTS idx_finding_tickets_reval ON finding_tickets (revalidation_required, revalidation_dispatched_at) WHERE revalidation_required = true`,

		// ── SIEM Correlation ──────────────────────────────────────────────────
		// siem_configs: one row per SIEM integration (QRadar, Splunk, Wazuh…).
		// Sensitive fields (token/password) are stored encrypted-at-rest via PG
		// column-level encryption when available; for on-prem BFSI we store them
		// as text and rely on PG TDE or LUKS for disk-level protection.
		`CREATE TABLE IF NOT EXISTS siem_configs (
			id                   text        PRIMARY KEY DEFAULT gen_random_uuid()::text,
			name                 text        NOT NULL,
			provider             text        NOT NULL,
			enabled              boolean     NOT NULL DEFAULT true,
			console_url          text        NOT NULL DEFAULT '',
			token                text        NOT NULL DEFAULT '',
			username             text        NOT NULL DEFAULT '',
			password             text        NOT NULL DEFAULT '',
			tenant_id            text        NOT NULL DEFAULT '',
			workspace_id         text        NOT NULL DEFAULT '',
			client_id            text        NOT NULL DEFAULT '',
			client_secret        text        NOT NULL DEFAULT '',
			insecure_skip_verify boolean     NOT NULL DEFAULT false,
			auto_correlate       boolean     NOT NULL DEFAULT true,
			created_at           timestamptz NOT NULL DEFAULT NOW(),
			updated_at           timestamptz NOT NULL DEFAULT NOW()
		)`,

		// siem_correlations: one row per (run_id, config_id) correlation run.
		// The full report JSON is stored in report_json for the detail view; the
		// summary columns drive the dashboard badge and run-list indicators.
		`CREATE TABLE IF NOT EXISTS siem_correlations (
			id               text        PRIMARY KEY DEFAULT gen_random_uuid()::text,
			run_id           text        NOT NULL,
			config_id        text        NOT NULL,
			agent_id         text        NOT NULL,
			agent_ip         text        NOT NULL DEFAULT '',
			provider         text        NOT NULL,
			window_start     timestamptz NOT NULL,
			window_end       timestamptz NOT NULL,
			total_alerts     int         NOT NULL DEFAULT 0,
			detected         int         NOT NULL DEFAULT 0,
			undetected       int         NOT NULL DEFAULT 0,
			not_executed     int         NOT NULL DEFAULT 0,
			detection_rate   int         NOT NULL DEFAULT 0,
			undetected_rate  int         NOT NULL DEFAULT 0,
			report_json      jsonb       NOT NULL DEFAULT '{}',
			correlated_at    timestamptz NOT NULL DEFAULT NOW(),
			UNIQUE (run_id, config_id)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_siem_corr_run    ON siem_correlations (run_id)`,
		`CREATE INDEX IF NOT EXISTS idx_siem_corr_agent  ON siem_correlations (agent_id, correlated_at DESC)`,

		// ── Detection Validation SP2: manual-verification store ───────────────
		// verification_history is APPEND-ONLY (audit-log semantics). A new
		// attestation inserts a fresh row (active=true), points supersedes_id at
		// the prior active row, and flips that row to active=false — never an
		// in-place UPDATE of a status. The partial unique index guarantees at most
		// one active row per (run_id, expectation_id) even under concurrent writes.
		// result (Detected/NotDetected/NotApplicable) is kept distinct from
		// workflow_state (Pending/NeedsReview/Approved/Rejected): only an Approved
		// workflow with a Detected/NotDetected result feeds Coverage.
		`CREATE TABLE IF NOT EXISTS verification_history (
			id                  text        PRIMARY KEY DEFAULT gen_random_uuid()::text,
			run_id              text        NOT NULL,
			expectation_id      text        NOT NULL,
			profile_name        text        NOT NULL DEFAULT '',
			profile_version     int         NOT NULL DEFAULT 0,
			technique_id        text        NOT NULL DEFAULT '',
			domain              text        NOT NULL DEFAULT '',
			provider            text        NOT NULL DEFAULT '',
			result              text        NOT NULL DEFAULT '',
			workflow_state      text        NOT NULL DEFAULT 'Pending',
			verification_source text        NOT NULL DEFAULT 'manual',
			note                text        NOT NULL DEFAULT '',
			alert_id            text        NOT NULL DEFAULT '',
			verified_by         text        NOT NULL DEFAULT '',
			verified_at         timestamptz NOT NULL DEFAULT NOW(),
			supersedes_id       text        NOT NULL DEFAULT '',
			active              boolean     NOT NULL DEFAULT true
		)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_verif_active_one
			ON verification_history (run_id, expectation_id) WHERE active`,
		`CREATE INDEX IF NOT EXISTS idx_verif_run     ON verification_history (run_id)`,
		`CREATE INDEX IF NOT EXISTS idx_verif_lookup  ON verification_history (run_id, expectation_id, verified_at DESC)`,

		// verification_evidence separates metadata from the bytes so storage can
		// move to filesystem/S3/Azure/URL later with NO schema migration — only a
		// new storage_type + storage_key written by the store. Every upload is
		// hashed (hash_algorithm + content_hash) at receipt. Soft-delete keeps the
		// row (evidence is audit material) and records who/when.
		`CREATE TABLE IF NOT EXISTS verification_evidence (
			id                text        PRIMARY KEY DEFAULT gen_random_uuid()::text,
			verification_id   text        NOT NULL,
			storage_type      text        NOT NULL DEFAULT 'database',
			storage_key       text        NOT NULL DEFAULT '',
			hash_algorithm    text        NOT NULL DEFAULT 'SHA-256',
			content_hash      text        NOT NULL DEFAULT '',
			original_filename text        NOT NULL DEFAULT '',
			display_filename  text        NOT NULL DEFAULT '',
			mime              text        NOT NULL DEFAULT '',
			size              bigint      NOT NULL DEFAULT 0,
			uploaded_by       text        NOT NULL DEFAULT '',
			uploaded_at       timestamptz NOT NULL DEFAULT NOW(),
			deleted           boolean     NOT NULL DEFAULT false,
			deleted_by        text        NOT NULL DEFAULT '',
			deleted_at        timestamptz
		)`,
		`CREATE INDEX IF NOT EXISTS idx_verif_evidence_vid ON verification_evidence (verification_id) WHERE NOT deleted`,

		// verification_evidence_blob holds bytes only when storage_type='database'.
		// Kept in its own table so the metadata row stays light and a move to
		// external storage just stops writing here.
		`CREATE TABLE IF NOT EXISTS verification_evidence_blob (
			id     text  PRIMARY KEY DEFAULT gen_random_uuid()::text,
			bytes  bytea NOT NULL
		)`,

		// ── Detection Verification Connectors (SP1 first slice) ────────────────
		// detection_connectors: one row per Sentinel/Defender XDR (and later
		// QRadar/Splunk/Elastic/CrowdStrike/Trellix) API connector. Deliberately
		// separate from siem_configs — Defender XDR is not a SIEM, and this
		// package (internal/detectverify) is independent of internal/siem. See
		// docs/superpowers/specs/2026-07-14-detection-verification-connectors-design.md.
		`CREATE TABLE IF NOT EXISTS detection_connectors (
			id                    text        PRIMARY KEY DEFAULT gen_random_uuid()::text,
			name                  text        NOT NULL,
			provider              text        NOT NULL,
			enabled               boolean     NOT NULL DEFAULT true,
			auto_verify           boolean     NOT NULL DEFAULT false,
			tenant_id             text        NOT NULL DEFAULT '',
			client_id             text        NOT NULL DEFAULT '',
			client_secret         text        NOT NULL DEFAULT '',
			workspace_id          text        NOT NULL DEFAULT '',
			base_url              text        NOT NULL DEFAULT '',
			api_token             text        NOT NULL DEFAULT '',
			verify_delay_seconds  int         NOT NULL DEFAULT 120,
			created_at            timestamptz NOT NULL DEFAULT NOW(),
			updated_at            timestamptz NOT NULL DEFAULT NOW()
		)`,
		// base_url/api_token: generic credential storage for non-Azure-shaped
		// providers (Splunk, QRadar, ...) that don't have tenant/client/secret.
		`ALTER TABLE detection_connectors ADD COLUMN IF NOT EXISTS base_url  text NOT NULL DEFAULT ''`,
		`ALTER TABLE detection_connectors ADD COLUMN IF NOT EXISTS api_token text NOT NULL DEFAULT ''`,

		// openaev_config: singleton row for the OpenAEV Connector's connection
		// settings. See docs/superpowers/specs/2026-07-15-openaev-connector-design.md.
		`CREATE TABLE IF NOT EXISTS openaev_config (
			id                  int         PRIMARY KEY DEFAULT 1 CHECK (id = 1),
			base_url            text        NOT NULL DEFAULT '',
			bearer_token        text        NOT NULL DEFAULT '',
			poll_interval_hours int         NOT NULL DEFAULT 24,
			enabled             boolean     NOT NULL DEFAULT false,
			last_sync_at        timestamptz,
			last_sync_status    text        NOT NULL DEFAULT 'never',
			last_error          text        NOT NULL DEFAULT '',
			updated_at          timestamptz NOT NULL DEFAULT NOW()
		)`,

		// dashboard_snapshots: Phase 6 executive dashboard. One row per day
		// (UNIQUE(snapshot_date) makes the daily scheduler's upsert idempotent).
		// See docs/superpowers/specs/2026-07-17-phase6-executive-dashboards-design.md.
		`CREATE TABLE IF NOT EXISTS dashboard_snapshots (
			id                 bigserial   PRIMARY KEY,
			snapshot_date      date        NOT NULL,
			avg_risk_score     int         NOT NULL,
			exposure_score     int         NOT NULL,
			detection_coverage int         NOT NULL,
			asset_count        int         NOT NULL DEFAULT 0,
			created_at         timestamptz NOT NULL DEFAULT NOW(),
			UNIQUE(snapshot_date)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_dashboard_snapshots_date ON dashboard_snapshots(snapshot_date DESC)`,
	}

	for _, s := range stmts {
		if _, err := pool.Exec(ctx, s); err != nil {
			return fmt.Errorf("schema exec failed:\n%s\nerror: %w", s, err)
		}
	}
	return nil
}

// ── Compliance snapshots ──────────────────────────────────────────────────────

// ComplianceSnapshot is the persisted compliance score for one (agent, framework) pair.
type ComplianceSnapshot struct {
	AgentID          string    `json:"agentId"`
	FrameworkID      string    `json:"frameworkId"`
	SnapshotAt       time.Time `json:"snapshotAt"`
	RunCount         int       `json:"runCount"`
	CompliancePct    float64   `json:"compliancePct"`
	CoveragePct      float64   `json:"coveragePct"`
	TotalControls    int       `json:"totalControls"`
	TestableControls int       `json:"testableControls"`
	TestedControls   int       `json:"testedControls"`
	PassingControls  int       `json:"passingControls"`
	FailingControls  int       `json:"failingControls"`
	ManualControls   int       `json:"manualControls"`
}

// UpsertComplianceSnapshot writes (or overwrites) the compliance score snapshot
// for the given (agent, framework) pair. Called asynchronously after every run.
func UpsertComplianceSnapshot(ctx context.Context, pool *pgxpool.Pool, s ComplianceSnapshot) error {
	_, err := pool.Exec(ctx, `
		INSERT INTO compliance_snapshots
		  (agent_id, framework_id, snapshot_at, run_count,
		   compliance_pct, coverage_pct,
		   total_controls, testable_controls, tested_controls,
		   passing_controls, failing_controls, manual_controls)
		VALUES ($1,$2,NOW(),$3,$4,$5,$6,$7,$8,$9,$10,$11)
		ON CONFLICT (agent_id, framework_id) DO UPDATE SET
		  snapshot_at       = EXCLUDED.snapshot_at,
		  run_count         = EXCLUDED.run_count,
		  compliance_pct    = EXCLUDED.compliance_pct,
		  coverage_pct      = EXCLUDED.coverage_pct,
		  total_controls    = EXCLUDED.total_controls,
		  testable_controls = EXCLUDED.testable_controls,
		  tested_controls   = EXCLUDED.tested_controls,
		  passing_controls  = EXCLUDED.passing_controls,
		  failing_controls  = EXCLUDED.failing_controls,
		  manual_controls   = EXCLUDED.manual_controls`,
		s.AgentID, s.FrameworkID, s.RunCount,
		s.CompliancePct, s.CoveragePct,
		s.TotalControls, s.TestableControls, s.TestedControls,
		s.PassingControls, s.FailingControls, s.ManualControls)
	return err
}

// GetComplianceScores returns the latest snapshot for every framework for a
// given agent, ordered by framework_id.
func GetComplianceScores(ctx context.Context, pool *pgxpool.Pool, agentID string) ([]ComplianceSnapshot, error) {
	rows, err := pool.Query(ctx, `
		SELECT agent_id, framework_id, snapshot_at, run_count,
		       compliance_pct, coverage_pct,
		       total_controls, testable_controls, tested_controls,
		       passing_controls, failing_controls, manual_controls
		FROM compliance_snapshots
		WHERE agent_id = $1
		ORDER BY framework_id`, agentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ComplianceSnapshot
	for rows.Next() {
		var s ComplianceSnapshot
		if err := rows.Scan(&s.AgentID, &s.FrameworkID, &s.SnapshotAt, &s.RunCount,
			&s.CompliancePct, &s.CoveragePct,
			&s.TotalControls, &s.TestableControls, &s.TestedControls,
			&s.PassingControls, &s.FailingControls, &s.ManualControls); err != nil {
			continue
		}
		out = append(out, s)
	}
	return out, nil
}

// GetFleetComplianceScores returns the worst-case (minimum) compliance percentage
// per framework aggregated across all agents — the fleet-wide CISO view.
func GetFleetComplianceScores(ctx context.Context, pool *pgxpool.Pool) ([]ComplianceSnapshot, error) {
	rows, err := pool.Query(ctx, `
		SELECT framework_id,
		       MIN(snapshot_at)        AS snapshot_at,
		       SUM(run_count)          AS run_count,
		       MIN(compliance_pct)     AS compliance_pct,
		       MIN(coverage_pct)       AS coverage_pct,
		       MAX(total_controls)     AS total_controls,
		       MAX(testable_controls)  AS testable_controls,
		       SUM(tested_controls)    AS tested_controls,
		       SUM(passing_controls)   AS passing_controls,
		       SUM(failing_controls)   AS failing_controls,
		       MAX(manual_controls)    AS manual_controls
		FROM compliance_snapshots
		GROUP BY framework_id
		ORDER BY framework_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ComplianceSnapshot
	for rows.Next() {
		var s ComplianceSnapshot
		s.AgentID = "*"
		if err := rows.Scan(&s.FrameworkID, &s.SnapshotAt, &s.RunCount,
			&s.CompliancePct, &s.CoveragePct,
			&s.TotalControls, &s.TestableControls, &s.TestedControls,
			&s.PassingControls, &s.FailingControls, &s.ManualControls); err != nil {
			continue
		}
		out = append(out, s)
	}
	return out, nil
}
