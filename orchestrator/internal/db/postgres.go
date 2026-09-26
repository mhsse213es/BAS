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
		// Remote stop (see docs/superpowers/specs/2026-07-22-agent-remote-stop-design.md).
		// stopped_by stores the acting user's ID, not a display name.
		`ALTER TABLE agents ADD COLUMN IF NOT EXISTS stopped_by  text`,
		`ALTER TABLE agents ADD COLUMN IF NOT EXISTS stopped_at  timestamptz`,
		`ALTER TABLE agents ADD COLUMN IF NOT EXISTS stop_reason text`,
		// Phase 0C: domain-joined is the first environmental prerequisite fact.
		// NULL = agent has never reported it (POSIX in this phase, or a
		// pre-upgrade Windows agent) -- the dispatch-time gate treats NULL as
		// "unknown, never skip on it." See
		// docs/superpowers/specs/2026-09-05-phase0c-prerequisite-evaluation-design.md.
		`ALTER TABLE agents ADD COLUMN IF NOT EXISTS domain_joined boolean`,

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
		// mode / max_privilege: the execution options actually chosen at dispatch
		// time ("posture"|"telemetry"|"lab", ""|"user"|"admin"|"system"). Neither
		// was persisted before — only their downstream *effects* were visible
		// (which steps got skipped), leaving no way to answer "was this the admin
		// run or the no-limit run?" after the fact. Set once in dispatchRun's
		// insert, surfaced read-only via scanRunRows for the Results/Live views.
		`ALTER TABLE scenario_runs ADD COLUMN IF NOT EXISTS mode text NOT NULL DEFAULT ''`,
		`ALTER TABLE scenario_runs ADD COLUMN IF NOT EXISTS max_privilege text NOT NULL DEFAULT ''`,
		// paused: true while an operator has paused this run's step scheduler.
		// status stays 'running' throughout a pause (see docs/superpowers/specs/
		// 2026-08-16-pause-resume-live-runs-design.md) -- every existing
		// status='running' check (busy guard, Live Runs button visibility,
		// dashboard counts) needs zero changes; only this flag distinguishes a
		// paused run from an actively-executing one.
		`ALTER TABLE scenario_runs ADD COLUMN IF NOT EXISTS paused boolean NOT NULL DEFAULT false`,

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
		// step_name is the agent-submitted human-readable test name (e.g. "T1003
		// - Test 3: ..."), sent on every event but previously never persisted --
		// only the live WS relay carried it, so a step's real name silently
		// reverted to its bare technique ID on any replay/reconnect (GET
		// .../events), for every scenario.
		`ALTER TABLE run_events ADD COLUMN IF NOT EXISTS step_name text NOT NULL DEFAULT ''`,

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
		// target_type/target_group_id record how a campaign's frozen `targets`
		// snapshot was produced (explicit list / a resolved group / the whole
		// fleet) -- for display and audit, not re-resolution. Every existing
		// campaign row reads as target_type='agents', which is simply true:
		// every campaign created before this column existed was an explicit
		// agent list.
		`ALTER TABLE campaigns ADD COLUMN IF NOT EXISTS target_type text NOT NULL DEFAULT 'agents'`,
		`ALTER TABLE campaigns ADD COLUMN IF NOT EXISTS target_group_id bigint`,
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

		// attackpath_collection_requests: one row per dispatch, recording what was
		// asked for -- lets the summary handler reconcile "requested" against
		// "represented in the resulting graph" without any agent protocol change
		// (an unreachable target already leaves no trace in the agent's own
		// submission, so absence already means "not represented"). See
		// docs/superpowers/specs/2026-07-31-attack-path-results-backend-design.md.
		`CREATE TABLE IF NOT EXISTS attackpath_collection_requests (
			id             text        PRIMARY KEY DEFAULT gen_random_uuid()::text,
			agent_id       text        NOT NULL,
			targets        jsonb       NOT NULL DEFAULT '[]',
			run_sharphound boolean     NOT NULL DEFAULT false,
			requested_at   timestamptz NOT NULL DEFAULT NOW()
		)`,
		`CREATE INDEX IF NOT EXISTS idx_attackpath_collection_requests_agent
			ON attackpath_collection_requests (agent_id, requested_at DESC)`,

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

		// iocs / ioc_sightings: canonical IOC registry (Phase 0+A of the IOC
		// handling initiative). One iocs row per distinct (type, value);
		// ioc_sightings is the per-observation junction, never deduped --
		// the same value seen on 2 agents is 2 sightings, 1 IOC. See
		// docs/superpowers/specs/2026-07-31-ioc-registry-design.md.
		`CREATE TABLE IF NOT EXISTS iocs (
			id             text        PRIMARY KEY DEFAULT gen_random_uuid()::text,
			type           text        NOT NULL,
			value          text        NOT NULL,
			source         text        NOT NULL,
			origin         text        NOT NULL DEFAULT 'built-in',
			status         text        NOT NULL DEFAULT 'observed',
			first_seen     timestamptz NOT NULL DEFAULT NOW(),
			last_seen      timestamptz NOT NULL DEFAULT NOW(),
			sighting_count int         NOT NULL DEFAULT 1,
			metadata       jsonb       NOT NULL DEFAULT '{}'
		)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_iocs_type_value ON iocs (type, value)`,
		`CREATE INDEX IF NOT EXISTS idx_iocs_status ON iocs (status)`,

		`CREATE TABLE IF NOT EXISTS ioc_sightings (
			id          text        PRIMARY KEY DEFAULT gen_random_uuid()::text,
			ioc_id      text        NOT NULL REFERENCES iocs(id) ON DELETE CASCADE,
			scenario_id text        NOT NULL DEFAULT '',
			run_id      text        NOT NULL DEFAULT '',
			agent_id    text        NOT NULL DEFAULT '',
			observed_at timestamptz NOT NULL DEFAULT NOW()
		)`,
		`CREATE INDEX IF NOT EXISTS idx_ioc_sightings_ioc   ON ioc_sightings (ioc_id)`,
		`CREATE INDEX IF NOT EXISTS idx_ioc_sightings_run   ON ioc_sightings (run_id)`,
		`CREATE INDEX IF NOT EXISTS idx_ioc_sightings_agent ON ioc_sightings (agent_id)`,

		// Phase B: correlation/analytics need to know which technique produced
		// a sighting and what its detection verdict was -- both already
		// computed by SubmitRunDetections at extraction time, just not
		// captured until now. See
		// docs/superpowers/specs/2026-07-31-ioc-relationships-analytics-design.md.
		`ALTER TABLE ioc_sightings ADD COLUMN IF NOT EXISTS technique_id text NOT NULL DEFAULT ''`,
		`ALTER TABLE ioc_sightings ADD COLUMN IF NOT EXISTS detection_verdict text NOT NULL DEFAULT ''`,
		`CREATE INDEX IF NOT EXISTS idx_ioc_sightings_technique ON ioc_sightings (technique_id)`,

		// Phase D: suppression awareness (iochandling.txt §22) -- an operator's
		// judgment that an IOC is a known false-positive/environment-specific
		// exception, distinct from the lifecycle Status column. See
		// docs/superpowers/specs/2026-07-31-ioc-intelligence-layer-design.md.
		`ALTER TABLE iocs ADD COLUMN IF NOT EXISTS suppressed boolean NOT NULL DEFAULT false`,
		`ALTER TABLE iocs ADD COLUMN IF NOT EXISTS suppression_reason text NOT NULL DEFAULT ''`,
		`CREATE INDEX IF NOT EXISTS idx_iocs_suppressed ON iocs (suppressed) WHERE suppressed = true`,

		// vex_sweeps: server-owned Full Variant Sweep orchestration state.
		// One row per sweep; the partial unique index below makes "one
		// running sweep per agent" race-safe (not an app-level
		// check-then-insert) -- two simultaneous creates for the same
		// agent can never both succeed. See
		// docs/superpowers/specs/2026-07-30-vex-full-sweep-server-orchestration-design.md.
		`CREATE TABLE IF NOT EXISTS vex_sweeps (
			id                       text        PRIMARY KEY DEFAULT gen_random_uuid()::text,
			agent_id                 text        NOT NULL,
			mode                     text        NOT NULL DEFAULT 'sequential',
			include_advanced         boolean     NOT NULL DEFAULT false,
			techniques               text[]      NOT NULL,
			technique_variant_counts int[]       NOT NULL,
			base_types               text[]      NOT NULL DEFAULT '{}',
			base_ids                 text[]      NOT NULL DEFAULT '{}',
			current_index            int         NOT NULL DEFAULT 0,
			current_variant_run_id   text        NOT NULL DEFAULT '',
			current_scenario_run_id  text        NOT NULL DEFAULT '',
			current_technique_started_at timestamptz,
			completed_variants       int         NOT NULL DEFAULT 0,
			total_variants           int         NOT NULL DEFAULT 0,
			status                   text        NOT NULL DEFAULT 'running',
			error                    text        NOT NULL DEFAULT '',
			created_by               text        NOT NULL DEFAULT '',
			started_at               timestamptz NOT NULL DEFAULT NOW(),
			completed_at             timestamptz
		)`,
		`CREATE INDEX IF NOT EXISTS idx_vex_sweeps_agent ON vex_sweeps (agent_id)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_vex_sweeps_one_running_per_agent
			ON vex_sweeps (agent_id) WHERE status = 'running'`,

		// em_sweeps: server-owned Endpoint Mastery Full Sweep orchestration
		// state. One row per sweep; the partial unique index makes "one
		// running sweep per agent" race-safe (not an app-level
		// check-then-insert). See
		// docs/superpowers/specs/2026-08-13-em-full-sweep-design.md.
		`CREATE TABLE IF NOT EXISTS em_sweeps (
			id                        text        PRIMARY KEY DEFAULT gen_random_uuid()::text,
			agent_id                  text        NOT NULL,
			layers                    text[]      NOT NULL,
			current_index             int         NOT NULL DEFAULT 0,
			current_scenario_run_id   text        NOT NULL DEFAULT '',
			current_layer_started_at  timestamptz,
			completed_layers          int         NOT NULL DEFAULT 0,
			total_layers              int         NOT NULL DEFAULT 0,
			status                    text        NOT NULL DEFAULT 'running',
			error                     text        NOT NULL DEFAULT '',
			created_by                text        NOT NULL DEFAULT '',
			started_at                timestamptz NOT NULL DEFAULT NOW(),
			completed_at              timestamptz
		)`,
		`CREATE INDEX IF NOT EXISTS idx_em_sweeps_agent ON em_sweeps (agent_id)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_em_sweeps_one_running_per_agent
			ON em_sweeps (agent_id) WHERE status = 'running'`,

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
		// insecure_tls: per-connector opt-out of TLS certificate verification,
		// for on-prem appliances presenting a self-signed cert. Defaults false
		// (verify) — these connectors carry the customer's API token, so the
		// insecure path has to be a deliberate operator choice. Same setting
		// name and meaning as internal/ticketing's insecure_tls.
		`ALTER TABLE detection_connectors ADD COLUMN IF NOT EXISTS insecure_tls boolean NOT NULL DEFAULT false`,

		// ── EPP Response Actions ─────────────────────────────────────────────
		// action_connectors: one row per CrowdStrike/Defender response-action
		// connector. Deliberately separate from detection_connectors — a
		// customer can enable detection verification against a vendor without
		// enabling write-capable response actions against the same vendor. See
		// docs/superpowers/specs/2026-07-21-epp-response-actions-design.md.
		`CREATE TABLE IF NOT EXISTS action_connectors (
			id                        text        PRIMARY KEY DEFAULT gen_random_uuid()::text,
			name                      text        NOT NULL,
			provider                  text        NOT NULL,
			enabled                   boolean     NOT NULL DEFAULT true,
			tenant_id                 text        NOT NULL DEFAULT '',
			client_id                 text        NOT NULL DEFAULT '',
			client_secret             text        NOT NULL DEFAULT '',
			base_url                  text        NOT NULL DEFAULT '',
			kill_process_script_name  text        NOT NULL DEFAULT '',
			created_at                timestamptz NOT NULL DEFAULT NOW(),
			updated_at                timestamptz NOT NULL DEFAULT NOW()
		)`,

		// action_requests IS the audit trail for every executed response
		// action — every field of internal/actions.Action is a column here,
		// not a derived log line. duration is one subtraction of
		// dispatched_at from completed_at, not a stored column (avoids drift).
		`CREATE TABLE IF NOT EXISTS action_requests (
			id                  text        PRIMARY KEY DEFAULT gen_random_uuid()::text,
			type                text        NOT NULL,
			target_type         text        NOT NULL,
			target_identifier   text        NOT NULL,
			parameters          jsonb       NOT NULL DEFAULT '{}',
			connector_id        text        NOT NULL,
			status              text        NOT NULL,
			resolved_device_id  text        NOT NULL DEFAULT '',
			vendor_request_id   text        NOT NULL DEFAULT '',
			error               text        NOT NULL DEFAULT '',
			requested_by        text        NOT NULL DEFAULT '',
			reason              text        NOT NULL DEFAULT '',
			ticket_ref          text        NOT NULL DEFAULT '',
			run_id              text        NOT NULL DEFAULT '',
			requested_at        timestamptz NOT NULL DEFAULT NOW(),
			dispatched_at       timestamptz,
			completed_at        timestamptz
		)`,
		`CREATE INDEX IF NOT EXISTS idx_action_requests_run_id ON action_requests (run_id) WHERE run_id != ''`,

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

		// report_branding: singleton white-label config for report deliverables
		// (product/org name, accent color, optional logo data URI, footer note).
		// Empty fields fall back to the Audspect defaults at render time.
		`CREATE TABLE IF NOT EXISTS report_branding (
			id            int         PRIMARY KEY DEFAULT 1 CHECK (id = 1),
			product_name  text        NOT NULL DEFAULT '',
			org_name      text        NOT NULL DEFAULT '',
			accent_color  text        NOT NULL DEFAULT '',
			logo_data_uri text        NOT NULL DEFAULT '',
			footer_note   text        NOT NULL DEFAULT '',
			updated_at    timestamptz NOT NULL DEFAULT NOW()
		)`,

		// report_schedules: recurring, emailed report deliveries. Each row is one
		// scheduled report (board/compliance/audit_pack) for one scope, delivered
		// to a recipient list on a daily/weekly/monthly cadence. See
		// internal/api/report_schedule_handlers.go.
		`CREATE TABLE IF NOT EXISTS report_schedules (
			id            text        PRIMARY KEY DEFAULT gen_random_uuid()::text,
			name          text        NOT NULL DEFAULT '',
			report_type   text        NOT NULL DEFAULT 'board',
			scope_kind    text        NOT NULL DEFAULT 'agent',
			scope_id      text        NOT NULL DEFAULT '',
			framework     text        NOT NULL DEFAULT '',
			format        text        NOT NULL DEFAULT 'pdf',
			recipients    text        NOT NULL DEFAULT '',
			frequency     text        NOT NULL DEFAULT 'weekly',
			hour_utc      int         NOT NULL DEFAULT 6,
			day_of_week   int         NOT NULL DEFAULT 1,
			day_of_month  int         NOT NULL DEFAULT 1,
			enabled       boolean     NOT NULL DEFAULT true,
			last_run_at   timestamptz,
			last_status   text        NOT NULL DEFAULT 'never',
			last_error    text        NOT NULL DEFAULT '',
			created_by    text        NOT NULL DEFAULT '',
			created_at    timestamptz NOT NULL DEFAULT NOW()
		)`,

		// threat_intel_config: one row per MISP/OpenCTI/OTX connector, DB-backed
		// replacement for the .env-only config those three used before this.
		// base_url is unused (stays '') for the 'otx' row -- it's a single
		// hosted service, not self-hosted like MISP/OpenCTI. See
		// docs/superpowers/specs/2026-08-10-threat-intel-connector-config-design.md.
		`CREATE TABLE IF NOT EXISTS threat_intel_config (
			connector         text        PRIMARY KEY,
			base_url          text        NOT NULL DEFAULT '',
			api_key           text        NOT NULL DEFAULT '',
			enabled           boolean     NOT NULL DEFAULT false,
			last_sync_at      timestamptz,
			last_sync_status  text        NOT NULL DEFAULT 'never',
			last_error        text        NOT NULL DEFAULT '',
			updated_at        timestamptz NOT NULL DEFAULT NOW()
		)`,
		// See detection_connectors.insecure_tls above — same opt-out, same
		// verify-by-default reasoning. MISP in particular is commonly deployed
		// air-gapped behind a self-signed cert.
		`ALTER TABLE threat_intel_config ADD COLUMN IF NOT EXISTS insecure_tls boolean NOT NULL DEFAULT false`,

		// taxii_connector_config: one row per configured TAXII 2.1 server
		// (e.g. FS-ISAC, HC-ISAC) -- unlike threat_intel_config's one-row-
		// per-connector-TYPE singleton, this is genuinely multi-instance: a
		// deployment may run zero, one, or several TAXII sources at once.
		// client_cert/client_key are reserved for a future mTLS phase and
		// unused today. See
		// docs/superpowers/specs/2026-08-13-taxii-connector-phase1-design.md.
		`CREATE TABLE IF NOT EXISTS taxii_connector_config (
			id                text        PRIMARY KEY DEFAULT gen_random_uuid()::text,
			name              text        NOT NULL,
			server_url        text        NOT NULL,
			api_root          text        NOT NULL DEFAULT '',
			collection_id     text        NOT NULL DEFAULT '',
			auth_type         text        NOT NULL DEFAULT 'none',
			username          text        NOT NULL DEFAULT '',
			password          text        NOT NULL DEFAULT '',
			client_cert       text        NOT NULL DEFAULT '',
			client_key        text        NOT NULL DEFAULT '',
			enabled           boolean     NOT NULL DEFAULT false,
			last_poll_at      timestamptz,
			last_poll_status  text        NOT NULL DEFAULT 'never',
			last_poll_summary jsonb       NOT NULL DEFAULT '{}',
			last_error        text        NOT NULL DEFAULT '',
			created_at        timestamptz NOT NULL DEFAULT NOW(),
			updated_at        timestamptz NOT NULL DEFAULT NOW()
		)`,
		// See detection_connectors.insecure_tls above.
		`ALTER TABLE taxii_connector_config ADD COLUMN IF NOT EXISTS insecure_tls boolean NOT NULL DEFAULT false`,

		// taxii_ingested_objects: the idempotency ledger. A poll re-seeing an
		// unchanged (connector_id, stix_id, modified) triple short-circuits
		// before re-parsing; a bumped `modified` on a known stix_id still
		// flows through and hits iocs' existing (type,value) upsert.
		`CREATE TABLE IF NOT EXISTS taxii_ingested_objects (
			connector_id text        NOT NULL REFERENCES taxii_connector_config(id) ON DELETE CASCADE,
			stix_id      text        NOT NULL,
			modified     timestamptz NOT NULL,
			ioc_id       text        NOT NULL REFERENCES iocs(id) ON DELETE CASCADE,
			ingested_at  timestamptz NOT NULL DEFAULT NOW(),
			PRIMARY KEY (connector_id, stix_id, modified)
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

		// Phase 7 Multi-Tenancy — tenant_id on every operational table.
		// DEFAULT 'default' backfills existing rows and covers every INSERT
		// that doesn't specify tenant_id explicitly (matches Task 1's users.tenant_id).
		`ALTER TABLE agent_op_logs ADD COLUMN IF NOT EXISTS tenant_id text NOT NULL DEFAULT 'default'`,
		`ALTER TABLE agent_sec_logs ADD COLUMN IF NOT EXISTS tenant_id text NOT NULL DEFAULT 'default'`,
		`ALTER TABLE agent_telemetry ADD COLUMN IF NOT EXISTS tenant_id text NOT NULL DEFAULT 'default'`,
		`ALTER TABLE agents ADD COLUMN IF NOT EXISTS tenant_id text NOT NULL DEFAULT 'default'`,
		`ALTER TABLE attackpath_asset_tags ADD COLUMN IF NOT EXISTS tenant_id text NOT NULL DEFAULT 'default'`,
		`ALTER TABLE attackpath_collection_history ADD COLUMN IF NOT EXISTS tenant_id text NOT NULL DEFAULT 'default'`,
		`ALTER TABLE attackpath_collections ADD COLUMN IF NOT EXISTS tenant_id text NOT NULL DEFAULT 'default'`,
		`ALTER TABLE attackpath_jobs ADD COLUMN IF NOT EXISTS tenant_id text NOT NULL DEFAULT 'default'`,
		`ALTER TABLE attackpath_schedule ADD COLUMN IF NOT EXISTS tenant_id text NOT NULL DEFAULT 'default'`,
		`ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS tenant_id text NOT NULL DEFAULT 'default'`,
		`ALTER TABLE campaign_variant_summary ADD COLUMN IF NOT EXISTS tenant_id text NOT NULL DEFAULT 'default'`,
		`ALTER TABLE campaigns ADD COLUMN IF NOT EXISTS tenant_id text NOT NULL DEFAULT 'default'`,
		`ALTER TABLE compliance_snapshots ADD COLUMN IF NOT EXISTS tenant_id text NOT NULL DEFAULT 'default'`,
		`ALTER TABLE dashboard_snapshots ADD COLUMN IF NOT EXISTS tenant_id text NOT NULL DEFAULT 'default'`,
		// detection_connectors already had a column named tenant_id — the
		// Azure AD tenant ID for that connector's OAuth (client_id/client_secret
		// neighbor), unrelated to Audspect's own multi-tenancy. The ADD COLUMN
		// IF NOT EXISTS above silently no-op'd on this table when the prior
		// Multi-Tenancy migration ran. Renamed here first (idempotent: only
		// fires once, since after the first run tenant_id no longer exists
		// under the old meaning), then the real column is added. See
		// docs/superpowers/specs/2026-07-19-phase7-sso-oidc-design.md.
		`DO $$
		BEGIN
			IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'detection_connectors' AND column_name = 'tenant_id')
			   AND NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'detection_connectors' AND column_name = 'azure_tenant_id')
			THEN
				ALTER TABLE detection_connectors RENAME COLUMN tenant_id TO azure_tenant_id;
			END IF;
		END $$`,
		`ALTER TABLE detection_connectors ADD COLUMN IF NOT EXISTS tenant_id text NOT NULL DEFAULT 'default'`,
		`ALTER TABLE finding_tickets ADD COLUMN IF NOT EXISTS tenant_id text NOT NULL DEFAULT 'default'`,
		`ALTER TABLE findings ADD COLUMN IF NOT EXISTS tenant_id text NOT NULL DEFAULT 'default'`,
		`ALTER TABLE openaev_config ADD COLUMN IF NOT EXISTS tenant_id text NOT NULL DEFAULT 'default'`,
		`ALTER TABLE payload_families ADD COLUMN IF NOT EXISTS tenant_id text NOT NULL DEFAULT 'default'`,
		`ALTER TABLE report_log ADD COLUMN IF NOT EXISTS tenant_id text NOT NULL DEFAULT 'default'`,
		`ALTER TABLE run_events ADD COLUMN IF NOT EXISTS tenant_id text NOT NULL DEFAULT 'default'`,
		`ALTER TABLE scenario_runs ADD COLUMN IF NOT EXISTS tenant_id text NOT NULL DEFAULT 'default'`,
		// steps_total_base/steps_eligible_base capture the run's base-technique
		// step counts at dispatch time — Total (before any runtime filtering)
		// and Eligible (after the lab-only and MaxPrivilege filters, before
		// variant expansion). Written once, mirroring policy_skipped_results;
		// no retroactive backfill for runs that predate this column.
		`ALTER TABLE scenario_runs ADD COLUMN IF NOT EXISTS steps_total_base int NOT NULL DEFAULT 0`,
		`ALTER TABLE scenario_runs ADD COLUMN IF NOT EXISTS steps_eligible_base int NOT NULL DEFAULT 0`,
		// policy_skipped_results holds SimulationResults the server itself
		// synthesized at dispatch time for steps a run's MaxPrivilege execution
		// policy excluded before ever contacting the agent. Written once at
		// dispatch, never touched again — kept separate from `results` (which
		// the agent's own submission always REPLACES wholesale) so a later
		// agent submission can never silently wipe these out. Merged into
		// `results` by SubmitScenarioResult before scoring/persisting.
		`ALTER TABLE scenario_runs ADD COLUMN IF NOT EXISTS policy_skipped_results jsonb NOT NULL DEFAULT '[]'`,
		`ALTER TABLE scenario_variant_results ADD COLUMN IF NOT EXISTS tenant_id text NOT NULL DEFAULT 'default'`,
		`ALTER TABLE scenario_variant_technique_summary ADD COLUMN IF NOT EXISTS tenant_id text NOT NULL DEFAULT 'default'`,
		`ALTER TABLE siem_configs ADD COLUMN IF NOT EXISTS tenant_id text NOT NULL DEFAULT 'default'`,
		`ALTER TABLE siem_correlations ADD COLUMN IF NOT EXISTS tenant_id text NOT NULL DEFAULT 'default'`,
		`ALTER TABLE tamper_events ADD COLUMN IF NOT EXISTS tenant_id text NOT NULL DEFAULT 'default'`,
		`ALTER TABLE ticketing_configs ADD COLUMN IF NOT EXISTS tenant_id text NOT NULL DEFAULT 'default'`,
		`ALTER TABLE variant_findings ADD COLUMN IF NOT EXISTS tenant_id text NOT NULL DEFAULT 'default'`,
		`ALTER TABLE variant_run_steps ADD COLUMN IF NOT EXISTS tenant_id text NOT NULL DEFAULT 'default'`,
		`ALTER TABLE variant_runs ADD COLUMN IF NOT EXISTS tenant_id text NOT NULL DEFAULT 'default'`,
		`ALTER TABLE verification_evidence ADD COLUMN IF NOT EXISTS tenant_id text NOT NULL DEFAULT 'default'`,
		`ALTER TABLE verification_evidence_blob ADD COLUMN IF NOT EXISTS tenant_id text NOT NULL DEFAULT 'default'`,
		`ALTER TABLE verification_history ADD COLUMN IF NOT EXISTS tenant_id text NOT NULL DEFAULT 'default'`,
		`ALTER TABLE verification_history ADD COLUMN IF NOT EXISTS rule_ids text[] NOT NULL DEFAULT '{}'`,
		`ALTER TABLE scenario_runs ADD COLUMN IF NOT EXISTS auto_verified boolean NOT NULL DEFAULT false`,

		// SP7 Multi-Tenancy — users-table pilot. Create a tenant-isolation RLS
		// policy on users so it is reviewable and syntax-checked at boot, but
		// deliberately DO NOT enable RLS: the production role (bas_user) is a
		// Postgres superuser and bypasses RLS regardless, and Login/ChangePassword/
		// bootstrap query users with no tenant context and would be blocked the
		// moment RLS enforces. Activation is gated on the bas_user ->
		// NOSUPERUSER/NOBYPASSRLS role-hardening follow-up, at which point a future
		// migration uncomments the ENABLE/FORCE lines below AND routes the
		// tenant-agnostic auth paths through a platform-admin WithTenant context.
		// Enable-when-ready (do NOT uncomment without that follow-up):
		//   ALTER TABLE users ENABLE ROW LEVEL SECURITY;
		//   ALTER TABLE users FORCE ROW LEVEL SECURITY;
		// See docs/superpowers/specs/2026-07-19-multitenancy-users-pilot-design.md.
		`DO $$
		BEGIN
			IF NOT EXISTS (
				SELECT 1 FROM pg_policies WHERE tablename = 'users' AND policyname = 'tenant_isolation'
			) THEN
				CREATE POLICY tenant_isolation ON users
					USING (
						tenant_id = current_setting('app.tenant_id', true)
						OR current_setting('app.is_platform_admin', true)::boolean
					);
			END IF;
		END
		$$;`,

		// SSO (OIDC) — Phase 7 Identity & Access, Part 2. One OIDC config per
		// tenant; client_secret is masked in every API response (never
		// returned in cleartext once saved). UNIQUE(tenant_id) — exactly one
		// IdP per tenant for this slice. See
		// docs/superpowers/specs/2026-07-19-phase7-sso-oidc-design.md.
		`CREATE TABLE IF NOT EXISTS sso_configs (
			id            text        PRIMARY KEY DEFAULT gen_random_uuid()::text,
			tenant_id     text        NOT NULL REFERENCES tenants(id),
			issuer_url    text        NOT NULL,
			client_id     text        NOT NULL,
			client_secret text        NOT NULL,
			default_role  text        NOT NULL DEFAULT 'viewer',
			enabled       boolean     NOT NULL DEFAULT true,
			created_at    timestamptz NOT NULL DEFAULT NOW(),
			updated_at    timestamptz NOT NULL DEFAULT NOW(),
			UNIQUE (tenant_id)
		)`,

		// users.auth_source: 'local' or 'sso'. Login (password flow) rejects
		// outright when auth_source = 'sso', in addition to the password
		// check already failing against a random placeholder hash — explicit
		// defense-in-depth, not reliance on the hash being merely
		// impractical to guess.
		`ALTER TABLE users ADD COLUMN IF NOT EXISTS auth_source text NOT NULL DEFAULT 'local'`,

		// SCIM provisioning — Phase 7 Identity & Access, Part 3. One SCIM
		// config per tenant; token_hash is a SHA-256 hash, the cleartext
		// token is never stored and is shown to the admin exactly once
		// (creation/rotation response). UNIQUE(tenant_id) — exactly one
		// SCIM app per tenant for this slice. See
		// docs/superpowers/specs/2026-07-19-phase7-scim-provisioning-design.md.
		`CREATE TABLE IF NOT EXISTS scim_configs (
			id            text        PRIMARY KEY DEFAULT gen_random_uuid()::text,
			tenant_id     text        NOT NULL REFERENCES tenants(id),
			token_hash    text        NOT NULL,
			default_role  text        NOT NULL DEFAULT 'viewer',
			enabled       boolean     NOT NULL DEFAULT true,
			created_at    timestamptz NOT NULL DEFAULT NOW(),
			updated_at    timestamptz NOT NULL DEFAULT NOW(),
			UNIQUE (tenant_id)
		)`,

		// Sector/region weighting — SP5's last item. Upserted by
		// internal/connector's scheduler after every sync; read by
		// internal/reporting to weight technique priority scores. See
		// docs/superpowers/specs/2026-07-19-sp5-sector-region-weighting-design.md.
		`CREATE TABLE IF NOT EXISTS threat_actor_profiles (
			name       text        PRIMARY KEY,
			aliases    text[]      NOT NULL DEFAULT '{}',
			sectors    text[]      NOT NULL DEFAULT '{}',
			regions    text[]      NOT NULL DEFAULT '{}',
			source     text        NOT NULL DEFAULT '',
			last_seen  timestamptz,
			updated_at timestamptz NOT NULL DEFAULT NOW()
		)`,

		// remediation_requests: full audit trail + state machine for one
		// endpoint's attempt to run one remediation catalog entry. See
		// docs/superpowers/specs/2026-08-03-remediation-execution-design.md.
		`CREATE TABLE IF NOT EXISTS remediation_requests (
			id                          text        PRIMARY KEY DEFAULT gen_random_uuid()::text,
			remediation_id              text        NOT NULL,
			agent_id                    text        NOT NULL,
			check_id                    text        NOT NULL,
			tier                        int         NOT NULL,
			status                      text        NOT NULL,
			fix_run_id                  text        NOT NULL DEFAULT '',
			verify_run_id               text        NOT NULL DEFAULT '',
			error                       text        NOT NULL DEFAULT '',
			requested_by                text        NOT NULL DEFAULT '',
			approved_by                 text        NOT NULL DEFAULT '',
			reason                      text        NOT NULL DEFAULT '',
			rollback_available          boolean     NOT NULL DEFAULT false,
			rollback_status             text        NOT NULL DEFAULT '',
			rollback_run_id             text        NOT NULL DEFAULT '',
			rollback_verify_run_id      text        NOT NULL DEFAULT '',
			requested_at                timestamptz NOT NULL DEFAULT NOW(),
			dispatched_at               timestamptz,
			execution_completed_at      timestamptz,
			verification_completed_at   timestamptz,
			completed_at                timestamptz
		)`,
		`CREATE INDEX IF NOT EXISTS idx_remediation_requests_agent_id ON remediation_requests (agent_id)`,
		`CREATE INDEX IF NOT EXISTS idx_remediation_requests_fix_run_id ON remediation_requests (fix_run_id) WHERE fix_run_id != ''`,
		`CREATE INDEX IF NOT EXISTS idx_remediation_requests_verify_run_id ON remediation_requests (verify_run_id) WHERE verify_run_id != ''`,
		`ALTER TABLE remediation_requests ADD COLUMN IF NOT EXISTS continuous_validation boolean NOT NULL DEFAULT false`,

		// technique_verification_runs: a second, independent verification layer
		// on top of remediation_requests -- proves the control stops the real
		// ATT&CK technique, not just that its configuration is correct. See
		// docs/superpowers/specs/2026-08-03-bas-verified-remediation-design.md.
		`CREATE TABLE IF NOT EXISTS technique_verification_runs (
			id            text        PRIMARY KEY DEFAULT gen_random_uuid()::text,
			request_id    text        NOT NULL REFERENCES remediation_requests(id),
			agent_id      text        NOT NULL,
			check_id      text        NOT NULL,
			technique_id  text        NOT NULL,
			engine        text        NOT NULL DEFAULT 'art',
			run_id        text        NOT NULL DEFAULT '',
			status        text        NOT NULL DEFAULT 'requested',
			reason        text        NOT NULL DEFAULT '',
			requested_by  text        NOT NULL DEFAULT '',
			requested_at  timestamptz NOT NULL DEFAULT NOW(),
			dispatched_at timestamptz,
			completed_at  timestamptz
		)`,
		`CREATE INDEX IF NOT EXISTS idx_technique_verification_runs_request_id ON technique_verification_runs (request_id)`,
		`CREATE INDEX IF NOT EXISTS idx_technique_verification_runs_agent_id ON technique_verification_runs (agent_id)`,
		`CREATE INDEX IF NOT EXISTS idx_technique_verification_runs_run_id ON technique_verification_runs (run_id) WHERE run_id != ''`,

		// jobs / job_targets: generic fleet-job infrastructure. internal/jobs
		// knows nothing about what a given Job.Type actually does -- that's
		// supplied by internal/api at wiring time. See
		// docs/superpowers/specs/2026-08-03-fleet-job-engine-design.md.
		`CREATE TABLE IF NOT EXISTS jobs (
			id           text        PRIMARY KEY DEFAULT gen_random_uuid()::text,
			type         text        NOT NULL,
			state        text        NOT NULL,
			payload      jsonb       NOT NULL DEFAULT '{}',
			created_by   text        NOT NULL DEFAULT '',
			created_at   timestamptz NOT NULL DEFAULT NOW(),
			started_at   timestamptz,
			completed_at timestamptz
		)`,
		`CREATE INDEX IF NOT EXISTS idx_jobs_state ON jobs (state)`,

		`CREATE TABLE IF NOT EXISTS job_targets (
			id           text        PRIMARY KEY DEFAULT gen_random_uuid()::text,
			job_id       text        NOT NULL REFERENCES jobs(id),
			agent_id     text        NOT NULL,
			state        text        NOT NULL,
			ref_id       text        NOT NULL DEFAULT '',
			error        text        NOT NULL DEFAULT '',
			retry_count  int         NOT NULL DEFAULT 0,
			max_retries  int         NOT NULL DEFAULT 0,
			created_at   timestamptz NOT NULL DEFAULT NOW(),
			started_at   timestamptz,
			completed_at timestamptz
		)`,
		`CREATE INDEX IF NOT EXISTS idx_job_targets_job_id ON job_targets (job_id)`,
		`CREATE INDEX IF NOT EXISTS idx_job_targets_state ON job_targets (state) WHERE state = 'pending'`,

		// Sub-project 7: Fleet Scheduling & Maintenance Freezes. See
		// docs/superpowers/specs/2026-08-03-fleet-scheduling-and-freezes-design.md.
		`ALTER TABLE jobs ADD COLUMN IF NOT EXISTS scheduled_at timestamptz`,

		// job_schedules: recurring template that spawns a fresh one-shot Job
		// each occurrence.
		`CREATE TABLE IF NOT EXISTS job_schedules (
			id                  text        PRIMARY KEY DEFAULT gen_random_uuid()::text,
			type                text        NOT NULL,
			payload             jsonb       NOT NULL DEFAULT '{}',
			agent_ids           jsonb       NOT NULL,
			day_of_week         int         NOT NULL,
			time_of_day         text        NOT NULL,
			timezone            text        NOT NULL DEFAULT 'UTC',
			enabled             boolean     NOT NULL DEFAULT true,
			created_by          text        NOT NULL DEFAULT '',
			created_at          timestamptz NOT NULL DEFAULT NOW(),
			last_occurrence_at  timestamptz,
			last_spawned_job_id text        NOT NULL DEFAULT ''
		)`,
		`CREATE INDEX IF NOT EXISTS idx_job_schedules_enabled ON job_schedules (enabled) WHERE enabled = true`,

		// Scheduled Assessments extensions to job_schedules/jobs -- all additive,
		// existing batch_remediation schedule rows are unaffected (new columns
		// default to their zero value; recurrence_type='' aliases to the existing
		// weekly behavior, see nextOccurrenceSince). See
		// docs/superpowers/specs/2026-08-08-scheduled-assessments-design.md.
		`ALTER TABLE job_schedules ADD COLUMN IF NOT EXISTS recurrence_type text NOT NULL DEFAULT ''`,
		`ALTER TABLE job_schedules ADD COLUMN IF NOT EXISTS run_at timestamptz`,
		`ALTER TABLE job_schedules ADD COLUMN IF NOT EXISTS day_of_month int NOT NULL DEFAULT 0`,
		`ALTER TABLE job_schedules ADD COLUMN IF NOT EXISTS end_date timestamptz`,
		`ALTER TABLE job_schedules ADD COLUMN IF NOT EXISTS concurrency_limit int NOT NULL DEFAULT 0`,
		`ALTER TABLE job_schedules ADD COLUMN IF NOT EXISTS group_ids jsonb NOT NULL DEFAULT '[]'`,
		`ALTER TABLE job_schedules ADD COLUMN IF NOT EXISTS mode text NOT NULL DEFAULT ''`,
		`ALTER TABLE job_schedules ADD COLUMN IF NOT EXISTS approved_by text NOT NULL DEFAULT ''`,
		`ALTER TABLE job_schedules ADD COLUMN IF NOT EXISTS approved_at timestamptz`,
		`ALTER TABLE job_schedules ADD COLUMN IF NOT EXISTS approval_version int NOT NULL DEFAULT 0`,
		`ALTER TABLE job_schedules ADD COLUMN IF NOT EXISTS reason text NOT NULL DEFAULT ''`,
		`ALTER TABLE jobs ADD COLUMN IF NOT EXISTS concurrency_limit int NOT NULL DEFAULT 0`,

		// agent_maintenance_freezes: one-shot absolute freeze window per
		// agent, checked at dispatch time by Dispatcher.Tick.
		`CREATE TABLE IF NOT EXISTS agent_maintenance_freezes (
			id         text        PRIMARY KEY DEFAULT gen_random_uuid()::text,
			agent_id   text        NOT NULL,
			from_at    timestamptz NOT NULL,
			to_at      timestamptz NOT NULL,
			reason     text        NOT NULL DEFAULT '',
			created_by text        NOT NULL DEFAULT '',
			created_at timestamptz NOT NULL DEFAULT NOW()
		)`,
		`CREATE INDEX IF NOT EXISTS idx_agent_maintenance_freezes_agent_id ON agent_maintenance_freezes (agent_id)`,

		// Sub-project 11 (Phase 7): Job-Event Notifications. See
		// docs/superpowers/specs/2026-08-05-job-event-notifications-design.md.
		`CREATE TABLE IF NOT EXISTS notifications (
			id         text        PRIMARY KEY DEFAULT gen_random_uuid()::text,
			type       text        NOT NULL,
			job_id     text        NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
			target_id  text        NOT NULL DEFAULT '',
			agent_id   text        NOT NULL DEFAULT '',
			severity   text        NOT NULL,
			message    text        NOT NULL,
			metadata   jsonb       NOT NULL DEFAULT '{}',
			created_at timestamptz NOT NULL DEFAULT NOW()
		)`,
		`CREATE INDEX IF NOT EXISTS idx_notifications_created_at ON notifications (created_at DESC)`,
		`CREATE INDEX IF NOT EXISTS idx_notifications_job_id ON notifications (job_id)`,
		// Sub-project B of the SLA initiative introduces the first
		// non-job-scoped event type (sla_breached, see
		// docs/superpowers/specs/2026-08-29-posture-finding-sla-policy-design.md).
		// job_id was mandatory because every event type so far was job-driven;
		// dropping NOT NULL lets a job-less event store NULL instead of
		// needing a fake jobs row. NULL is exempt from the FK check, so the
		// existing REFERENCES jobs(id) still holds for every job-scoped event.
		// Idempotent: re-running DROP NOT NULL on an already-nullable column
		// is a no-op, not an error.
		`ALTER TABLE notifications ALTER COLUMN job_id DROP NOT NULL`,

		`CREATE TABLE IF NOT EXISTS notification_webhooks (
			id           text        PRIMARY KEY DEFAULT gen_random_uuid()::text,
			name         text        NOT NULL,
			url          text        NOT NULL,
			secret       text        NOT NULL DEFAULT '',
			min_severity text        NOT NULL DEFAULT 'warning',
			enabled      boolean     NOT NULL DEFAULT true,
			created_at   timestamptz NOT NULL DEFAULT NOW()
		)`,

		// Sub-project 12 (Phase 8): Job-Target Ownership. See
		// docs/superpowers/specs/2026-08-05-job-target-ownership-design.md.
		`ALTER TABLE job_targets ADD COLUMN IF NOT EXISTS owner_id    text NOT NULL DEFAULT ''`,
		`ALTER TABLE job_targets ADD COLUMN IF NOT EXISTS assigned_at timestamptz`,
		`CREATE INDEX IF NOT EXISTS idx_job_targets_owner_id ON job_targets (owner_id) WHERE owner_id != ''`,

		// Live Runs: collapse Full Variant Sweep technique runs into one row.
		// See docs/superpowers/specs/2026-08-11-sweep-run-grouping-design.md.
		`ALTER TABLE scenario_runs ADD COLUMN IF NOT EXISTS sweep_id text REFERENCES vex_sweeps(id)`,
		`CREATE INDEX IF NOT EXISTS idx_scenario_runs_sweep_id ON scenario_runs (sweep_id)`,

		// Live Runs: collapse Endpoint Mastery Full Sweep layer runs into one
		// row, same pattern as sweep_id for Full Variant Sweep. See
		// docs/superpowers/specs/2026-08-13-em-full-sweep-design.md.
		`ALTER TABLE scenario_runs ADD COLUMN IF NOT EXISTS em_sweep_id text REFERENCES em_sweeps(id)`,
		`CREATE INDEX IF NOT EXISTS idx_scenario_runs_em_sweep_id ON scenario_runs (em_sweep_id)`,

		// OpenAEV sync-result visibility: last_sync_status alone can't
		// distinguish "genuinely imported nothing" from "imported real
		// content" -- both showed as a bare "ok". See
		// docs/superpowers/specs/2026-08-12-openaev-exercise-sync-design.md.
		`ALTER TABLE openaev_config ADD COLUMN IF NOT EXISTS last_sync_created int NOT NULL DEFAULT 0`,
		`ALTER TABLE openaev_config ADD COLUMN IF NOT EXISTS last_sync_updated int NOT NULL DEFAULT 0`,
		`ALTER TABLE openaev_config ADD COLUMN IF NOT EXISTS last_sync_skipped int NOT NULL DEFAULT 0`,
		`ALTER TABLE openaev_config ADD COLUMN IF NOT EXISTS last_sync_errored int NOT NULL DEFAULT 0`,

		// Backup & Recovery: console requests, host-side systemd timer
		// executes. See docs/superpowers/specs/2026-08-17-backup-recovery-design.md.
		// The 'manifest' column is a queryable summary the worker writes back
		// after success -- separate from the manifest.json file inside the
		// archive itself, which is what --restore actually trusts.
		`CREATE TABLE IF NOT EXISTS backup_jobs (
			id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			job_type           TEXT NOT NULL CHECK (job_type IN ('backup', 'restore_marker')),
			trigger            TEXT NOT NULL CHECK (trigger IN ('console', 'scheduled', 'cli', 'pre_restore')),
			requested_by       TEXT,
			requested_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
			started_at         TIMESTAMPTZ,
			finished_at        TIMESTAMPTZ,
			status             TEXT NOT NULL DEFAULT 'requested'
			                     CHECK (status IN ('requested','running','protected',
			                                        'local_success','remote_failed','failed')),
			archive_filename   TEXT,
			archive_size_bytes BIGINT,
			sha256             TEXT,
			local_path         TEXT,
			remote_path        TEXT,
			error_message      TEXT,
			restore_of_id      UUID REFERENCES backup_jobs(id),
			manifest           JSONB
		)`,
		`CREATE INDEX IF NOT EXISTS idx_backup_jobs_status ON backup_jobs(status)`,
		`CREATE INDEX IF NOT EXISTS idx_backup_jobs_requested_at ON backup_jobs(requested_at DESC)`,

		// Full Variant Sweep: combined ART + Caldera dispatch. base_types is
		// parallel to techniques (same index maps to the same technique's
		// source) so the dispatcher knows which store to resolve each step
		// against. Existing rows default to '{}' and are backfilled to all
		// 'art' below, since every sweep created before this change was
		// ART-only.
		`ALTER TABLE vex_sweeps ADD COLUMN IF NOT EXISTS base_types text[] NOT NULL DEFAULT '{}'`,
		`UPDATE vex_sweeps SET base_types = (SELECT array_agg('art'::text) FROM unnest(techniques)) WHERE base_types = '{}' AND array_length(techniques,1) > 0`,

		// base_ids is parallel to techniques -- base_ids[i] is the specific
		// atomic test / ability name techniques[i] resolves against, added so
		// a technique with multiple atomic tests gets one sweep entry per
		// test instead of always resolving to the first (see
		// vexsweep.Sweep.BaseIDs). Existing rows default to '{}' and are
		// backfilled to an array of '' per technique -- '' is
		// resolveBaseCommand's existing "resolve to the first match"
		// convention, so every sweep created before this change keeps its
		// original resolved behavior.
		`ALTER TABLE vex_sweeps ADD COLUMN IF NOT EXISTS base_ids text[] NOT NULL DEFAULT '{}'`,
		`UPDATE vex_sweeps SET base_ids = (SELECT array_agg(''::text) FROM unnest(techniques)) WHERE base_ids = '{}' AND array_length(techniques,1) > 0`,

		// Sweep agent-disconnect resilience: a sweep whose agent drops mid-run
		// transitions to 'agent_disconnected' (a new status value -- no CHECK
		// constraint exists to update) instead of being force-failed by the old
		// blind 3-minute stuck-timer. disconnected_at records when. The partial
		// unique index enforcing "one active sweep per agent" must treat this
		// status as active too, or a second sweep could be started against an
		// agent whose first sweep is merely paused waiting on reconnect --
		// CREATE UNIQUE INDEX IF NOT EXISTS won't redefine an index under an
		// unchanged name, so this is an explicit drop+recreate. See
		// docs/superpowers/specs/2026-08-18-sweep-disconnect-resilience-design.md.
		`ALTER TABLE em_sweeps ADD COLUMN IF NOT EXISTS disconnected_at timestamptz`,
		`DROP INDEX IF EXISTS idx_em_sweeps_one_running_per_agent`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_em_sweeps_one_running_per_agent
			ON em_sweeps (agent_id) WHERE status IN ('running', 'agent_disconnected')`,
		`ALTER TABLE vex_sweeps ADD COLUMN IF NOT EXISTS disconnected_at timestamptz`,
		`DROP INDEX IF EXISTS idx_vex_sweeps_one_running_per_agent`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_vex_sweeps_one_running_per_agent
			ON vex_sweeps (agent_id) WHERE status IN ('running', 'agent_disconnected')`,

		// DLP exfiltration sink service: dlp_sink_tokens records a per-attempt
		// token issued at dispatch time (crypto/rand, not newID() -- see
		// internal/api/dlp_sink.go); dlp_sink_receipts is an append-only log of
		// whatever the sink endpoint actually received. token is NOT unique in
		// dlp_sink_receipts -- a retried request can legitimately produce more
		// than one receipt for the same token; the verifier only needs "was it
		// received at least once", not exactly-once. See
		// docs/superpowers/specs/2026-08-19-dlp-exfiltration-sink-service-design.md.
		`CREATE TABLE IF NOT EXISTS dlp_sink_tokens (
			token text PRIMARY KEY,
			run_id text NOT NULL,
			technique_id text NOT NULL,
			created_at timestamptz NOT NULL DEFAULT NOW(),
			expires_at timestamptz NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_dlp_sink_tokens_run_id ON dlp_sink_tokens (run_id)`,
		`CREATE TABLE IF NOT EXISTS dlp_sink_receipts (
			id bigserial PRIMARY KEY,
			token text NOT NULL,
			received_at timestamptz NOT NULL DEFAULT NOW(),
			source_ip text NOT NULL DEFAULT '',
			payload_hash text NOT NULL DEFAULT '',
			payload_size integer NOT NULL DEFAULT 0,
			channel text NOT NULL DEFAULT ''
		)`,
		`CREATE INDEX IF NOT EXISTS idx_dlp_sink_receipts_token ON dlp_sink_receipts (token)`,

		// Re-run exact clone: the operator-selected subset (techniques/
		// abilities/steps/checks) captured verbatim at dispatch time, so
		// Re-run can replay it exactly instead of reconstructing a lossy
		// approximation from results after the fact -- the prior approach
		// couldn't recover Caldera ability IDs or step indices from results
		// at all and silently fell back to running everything.
		`ALTER TABLE scenario_runs ADD COLUMN IF NOT EXISTS dispatch_subset jsonb`,

		// Initiative layer: groups related internal/jobs.Job rows -- possibly
		// of different types -- into one auditable security initiative with
		// an explicit active/closed/archived lifecycle. No FK on
		// jobs.initiative_id, matching the unconstrained-text convention
		// already used for owner_id/created_by/requested_by elsewhere in
		// this schema. See
		// docs/superpowers/specs/2026-08-22-initiative-layer-design.md.
		`CREATE TABLE IF NOT EXISTS initiatives (
			id            text        PRIMARY KEY DEFAULT gen_random_uuid()::text,
			name          text        NOT NULL,
			description   text        NOT NULL DEFAULT '',
			state         text        NOT NULL DEFAULT 'active',
			created_by    text        NOT NULL DEFAULT '',
			created_at    timestamptz NOT NULL DEFAULT NOW(),
			closed_at     timestamptz,
			archived_at   timestamptz
		)`,
		`ALTER TABLE jobs ADD COLUMN IF NOT EXISTS initiative_id text NOT NULL DEFAULT ''`,
		`CREATE INDEX IF NOT EXISTS idx_jobs_initiative_id ON jobs (initiative_id) WHERE initiative_id <> ''`,

		// job_schedules.initiative_id: when set, every Job a schedule spawns
		// is auto-assigned to this initiative (see Dispatcher.spawnDueSchedules)
		// instead of requiring a manual per-occurrence attach afterward. Same
		// unconstrained-text, no-FK convention as jobs.initiative_id above.
		`ALTER TABLE job_schedules ADD COLUMN IF NOT EXISTS initiative_id text NOT NULL DEFAULT ''`,
		`CREATE INDEX IF NOT EXISTS idx_job_schedules_initiative_id ON job_schedules (initiative_id) WHERE initiative_id <> ''`,

		// fail_reason: a genuine, human-readable explanation for why a run's
		// status became 'failed' (dispatch-time only -- e.g. agent offline,
		// malformed scenario content, every step lab-only in a non-lab mode).
		// Previously status='failed' persisted with zero context -- the
		// Results drawer showed a bare "0 fail / 0 pass" and a red badge with
		// no way to tell "agent was offline" from "scenario is broken".
		`ALTER TABLE scenario_runs ADD COLUMN IF NOT EXISTS fail_reason text`,

		// posture_findings: persisted lifecycle for CIS Security Configuration
		// + Identity posture-check findings, keyed (agent_id, check_id) --
		// deliberately narrower than the BAS findings table's
		// (agent_id, technique_id, control_class) key, since a posture check_id
		// maps to exactly one finding per agent (unlike Application Risk, where
		// one check_id can produce many findings -- explicitly out of scope,
		// see docs/superpowers/specs/2026-08-26-posture-finding-sla-foundation-design.md).
		// Reuses internal/findings.Apply's state machine unchanged; this table
		// only differs from `findings` by dropping BAS-specific columns
		// (technique_name/tactic/source_type/attack_data_source/
		// security_product_snapshot/last_campaign_id/resolved_by) that have no
		// posture-check equivalent.
		`CREATE TABLE IF NOT EXISTS posture_findings (
			id                text        PRIMARY KEY DEFAULT gen_random_uuid()::text,
			agent_id          text        NOT NULL,
			check_id          text        NOT NULL,
			category          text        NOT NULL DEFAULT '',
			title             text        NOT NULL DEFAULT '',
			severity          text        NOT NULL DEFAULT 'Medium',
			exposure_state    text        NOT NULL DEFAULT 'missed',
			status            text        NOT NULL DEFAULT 'open',
			occurrence_count  int         NOT NULL DEFAULT 1,
			reopened_count    int         NOT NULL DEFAULT 0,
			last_run_id       text,
			first_seen        timestamptz NOT NULL DEFAULT NOW(),
			last_seen         timestamptz NOT NULL DEFAULT NOW(),
			last_observed_at  timestamptz NOT NULL DEFAULT NOW(),
			resolved_at       timestamptz,
			resolved_reason   text,
			created_at        timestamptz NOT NULL DEFAULT NOW(),
			tenant_id         text        NOT NULL DEFAULT 'default',
			CONSTRAINT uq_posture_finding UNIQUE (agent_id, check_id)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_posture_findings_agent ON posture_findings (agent_id)`,
		`CREATE INDEX IF NOT EXISTS idx_posture_findings_status ON posture_findings (status)`,

		// ── Posture Finding SLA Policy (Sub-project B of the SLA initiative,
		// see docs/superpowers/specs/2026-08-29-posture-finding-sla-policy-design.md).
		// Scoped to posture_findings only, same as Sub-project A -- no
		// polymorphic finding_type/finding_id reference.
		`CREATE TABLE IF NOT EXISTS sla_policy (
			severity       text PRIMARY KEY,
			duration_hours int  NOT NULL CHECK (duration_hours > 0 AND duration_hours <= 8760),
			updated_at     timestamptz NOT NULL DEFAULT NOW(),
			updated_by     text NOT NULL DEFAULT ''
		)`,
		`INSERT INTO sla_policy (severity, duration_hours) VALUES
			('Critical', 24), ('High', 72), ('Medium', 168), ('Low', 720)
		 ON CONFLICT (severity) DO NOTHING`,
		// finding_slas is one row per open EPISODE of a posture_findings row,
		// not 1:1 with it -- a finding that heals then reopens months later
		// gets a fresh row with a fresh clock; the prior episode's row stays
		// as history. severity_at_start is a snapshot so a later
		// postureCheckFindingText edit never rewrites history, and editing
		// sla_policy only affects episodes started after the edit (an
		// existing deadline_at is never recomputed).
		`CREATE TABLE IF NOT EXISTS finding_slas (
			id                 text PRIMARY KEY DEFAULT gen_random_uuid()::text,
			posture_finding_id text NOT NULL REFERENCES posture_findings(id),
			severity_at_start  text NOT NULL,
			started_at         timestamptz NOT NULL,
			deadline_at        timestamptz NOT NULL,
			status             text NOT NULL DEFAULT 'active',
			breached_at        timestamptz,
			resolved_at        timestamptz
		)`,
		`CREATE INDEX IF NOT EXISTS idx_finding_slas_posture_finding ON finding_slas (posture_finding_id)`,
		`CREATE INDEX IF NOT EXISTS idx_finding_slas_active_deadline ON finding_slas (status, deadline_at) WHERE status = 'active'`,
		// Backfill: any posture_findings row that was already 'open' before
		// this migration ran gets an SLA clock starting now (not backdated to
		// its original first_seen -- backdating would let some findings
		// arrive already breached, a migration artifact, not a real SLA
		// miss). The NOT EXISTS guard makes this statement idempotent across
		// repeated EnsureSchema runs.
		`INSERT INTO finding_slas (posture_finding_id, severity_at_start, started_at, deadline_at, status)
		 SELECT pf.id, pf.severity, NOW(), NOW() + (sp.duration_hours || ' hours')::interval, 'active'
		   FROM posture_findings pf
		   JOIN sla_policy sp ON sp.severity = pf.severity
		  WHERE pf.status = 'open'
		    AND NOT EXISTS (SELECT 1 FROM finding_slas fs WHERE fs.posture_finding_id = pf.id)`,

		`CREATE TABLE IF NOT EXISTS execution_attempts (
			id                  text        PRIMARY KEY DEFAULT gen_random_uuid()::text,
			source              text        NOT NULL CHECK (source IN ('art', 'caldera', 'exercise')),
			granularity         text        NOT NULL CHECK (granularity IN ('run', 'step')),
			source_execution_id text        NOT NULL,
			source_attempt_id   text        NOT NULL,
			technique_id        text,

			status              text        NOT NULL CHECK (status IN (
				'pending','dispatched','running','completed','timed_out',
				'cancelled','abandoned','failed_to_dispatch','skipped'
			)),
			skip_reason         text,

			created_at          timestamptz NOT NULL DEFAULT NOW(),
			-- dispatch_queued_at is written by the ART/Caldera (source='art'/'caldera')
			-- path only; exercise steps leave it NULL -- use source/granularity to
			-- discriminate; the exercise engine's queue timing lives in the executor's
			-- own Phase 0A StepExecution.PollSelectedAt instead.
			dispatch_queued_at  timestamptz,
			dispatch_sent_at    timestamptz,
			started_at          timestamptz,
			completed_at        timestamptz,
			decision_at         timestamptz,

			result              jsonb,

			CONSTRAINT execution_attempts_skip_reason_ck CHECK (
				(status = 'skipped' AND skip_reason IS NOT NULL) OR
				(status <> 'skipped' AND skip_reason IS NULL)
			),
			CONSTRAINT execution_attempts_decision_at_ck CHECK (
				(status = 'skipped' AND decision_at IS NOT NULL) OR
				(status <> 'skipped' AND decision_at IS NULL)
			),
			UNIQUE (source, source_attempt_id)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_execution_attempts_execution ON execution_attempts(source_execution_id)`,
		`CREATE INDEX IF NOT EXISTS idx_execution_attempts_technique ON execution_attempts(technique_id) WHERE technique_id IS NOT NULL`,
		`CREATE INDEX IF NOT EXISTS idx_execution_attempts_status ON execution_attempts(status)`,
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
	AgentID            string    `json:"agentId"`
	FrameworkID        string    `json:"frameworkId"`
	SnapshotAt         time.Time `json:"snapshotAt"`
	RunCount           int       `json:"runCount"`
	CompliancePct      float64   `json:"compliancePct"`
	CoveragePct        float64   `json:"coveragePct"`
	TotalControls      int       `json:"totalControls"`
	TestableControls   int       `json:"testableControls"`
	TestedControls     int       `json:"testedControls"`
	PassingControls    int       `json:"passingControls"`
	FailingControls    int       `json:"failingControls"`
	ManualControls     int       `json:"manualControls"`
	EnrolledAgentCount int       `json:"enrolledAgentCount,omitempty"` // fleet-wide only; 0 in single-agent queries
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
		SELECT DISTINCT ON (framework_id)
		       framework_id, agent_id, snapshot_at, run_count,
		       compliance_pct, coverage_pct,
		       total_controls, testable_controls, tested_controls,
		       passing_controls, failing_controls, manual_controls,
		       COUNT(*) OVER (PARTITION BY framework_id) AS enrolled_agent_count
		FROM compliance_snapshots
		ORDER BY framework_id, compliance_pct ASC, snapshot_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ComplianceSnapshot
	for rows.Next() {
		var s ComplianceSnapshot
		if err := rows.Scan(&s.FrameworkID, &s.AgentID, &s.SnapshotAt, &s.RunCount,
			&s.CompliancePct, &s.CoveragePct,
			&s.TotalControls, &s.TestableControls, &s.TestedControls,
			&s.PassingControls, &s.FailingControls, &s.ManualControls,
			&s.EnrolledAgentCount); err != nil {
			continue
		}
		out = append(out, s)
	}
	return out, nil
}
