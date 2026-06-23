package db

import (
	"context"
	"fmt"

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
		// reverted: list of endpoint changes the agent rolled back after the run
		// (registry keys, files) — surfaced as the report's cleanup-verification.
		`ALTER TABLE scenario_runs ADD COLUMN IF NOT EXISTS reverted jsonb NOT NULL DEFAULT '[]'`,

		`CREATE INDEX IF NOT EXISTS idx_scenario_runs_agent ON scenario_runs(agent_id)`,
		`CREATE INDEX IF NOT EXISTS idx_scenario_runs_scenario ON scenario_runs(scenario_id)`,

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
			host_key    text        PRIMARY KEY,
			label       text        NOT NULL DEFAULT '',
			crown_jewel text        NOT NULL DEFAULT '',
			segment     text        NOT NULL DEFAULT '',
			high_value  boolean     NOT NULL DEFAULT false,
			updated_at  timestamptz NOT NULL DEFAULT NOW()
		)`,

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

		// ── Seed: default payload families ───────────────────────────────────────
		// T1059.001 — PowerShell Execution
		`INSERT INTO payload_families (technique_id,name,description,payload,purpose,risk_level) VALUES
		 ('T1059.001','Recon - Identity','Current user and group memberships',
		  'whoami /all','recon','SAFE')
		 ON CONFLICT (technique_id,name) DO NOTHING`,

		`INSERT INTO payload_families (technique_id,name,description,payload,purpose,risk_level) VALUES
		 ('T1059.001','Recon - System Info','Full system information dump',
		  'systeminfo','recon','SAFE')
		 ON CONFLICT (technique_id,name) DO NOTHING`,

		`INSERT INTO payload_families (technique_id,name,description,payload,purpose,risk_level) VALUES
		 ('T1059.001','Recon - Network Config','IP config and active connections',
		  'ipconfig /all; netstat -ano','recon','SAFE')
		 ON CONFLICT (technique_id,name) DO NOTHING`,

		`INSERT INTO payload_families (technique_id,name,description,payload,purpose,risk_level) VALUES
		 ('T1059.001','Recon - Process List','Running processes with paths',
		  'Get-Process | Select-Object Name,Id,Path,CPU | Sort-Object CPU -Descending','recon','SAFE')
		 ON CONFLICT (technique_id,name) DO NOTHING`,

		`INSERT INTO payload_families (technique_id,name,description,payload,purpose,risk_level) VALUES
		 ('T1059.001','Recon - Domain Info','Active Directory domain information',
		  'try{[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()}catch{"Not domain-joined"}','recon','SAFE')
		 ON CONFLICT (technique_id,name) DO NOTHING`,

		`INSERT INTO payload_families (technique_id,name,description,payload,purpose,risk_level) VALUES
		 ('T1059.001','Download Stager','Simulates a download cradle (loopback only)',
		  '$wc=New-Object Net.WebClient;try{$wc.DownloadString(''http://127.0.0.1/bas-test'')}catch{"Connection refused - expected"}','download','MODERATE')
		 ON CONFLICT (technique_id,name) DO NOTHING`,

		// T1082 — System Information Discovery
		`INSERT INTO payload_families (technique_id,name,description,payload,purpose,risk_level) VALUES
		 ('T1082','WMI Computer System','Hardware and domain info via WMI',
		  'Get-WmiObject Win32_ComputerSystem | Select-Object Name,Domain,Manufacturer,Model,TotalPhysicalMemory','recon','SAFE')
		 ON CONFLICT (technique_id,name) DO NOTHING`,

		`INSERT INTO payload_families (technique_id,name,description,payload,purpose,risk_level) VALUES
		 ('T1082','OS Version','Operating system version and build',
		  'Get-WmiObject Win32_OperatingSystem | Select-Object Caption,Version,BuildNumber,LastBootUpTime','recon','SAFE')
		 ON CONFLICT (technique_id,name) DO NOTHING`,

		`INSERT INTO payload_families (technique_id,name,description,payload,purpose,risk_level) VALUES
		 ('T1082','Installed Software','List installed applications',
		  'Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName,DisplayVersion | Where-Object {$_.DisplayName} | Sort-Object DisplayName','recon','SAFE')
		 ON CONFLICT (technique_id,name) DO NOTHING`,

		// T1016 — System Network Configuration Discovery
		`INSERT INTO payload_families (technique_id,name,description,payload,purpose,risk_level) VALUES
		 ('T1016','IP Configuration','Full IP configuration of all adapters',
		  'ipconfig /all','recon','SAFE')
		 ON CONFLICT (technique_id,name) DO NOTHING`,

		`INSERT INTO payload_families (technique_id,name,description,payload,purpose,risk_level) VALUES
		 ('T1016','Routing Table','System routing table',
		  'route print','recon','SAFE')
		 ON CONFLICT (technique_id,name) DO NOTHING`,

		`INSERT INTO payload_families (technique_id,name,description,payload,purpose,risk_level) VALUES
		 ('T1016','DNS Cache','Cached DNS entries',
		  'Get-DnsClientCache | Select-Object Entry,Data,TimeToLive','recon','SAFE')
		 ON CONFLICT (technique_id,name) DO NOTHING`,

		// T1057 — Process Discovery
		`INSERT INTO payload_families (technique_id,name,description,payload,purpose,risk_level) VALUES
		 ('T1057','All Processes','Full process list with owner',
		  'Get-Process | Select-Object Name,Id,CPU,WorkingSet,Path -ErrorAction SilentlyContinue','recon','SAFE')
		 ON CONFLICT (technique_id,name) DO NOTHING`,

		`INSERT INTO payload_families (technique_id,name,description,payload,purpose,risk_level) VALUES
		 ('T1057','Security Products','Identify running security/AV processes',
		  'Get-Process | Where-Object {$_.Name -match "defender|sentinel|crowdstrike|trellix|mcafee|symantec|sophos|cylance"} | Select-Object Name,Id,Path','recon','SAFE')
		 ON CONFLICT (technique_id,name) DO NOTHING`,

		// T1049 — System Network Connections Discovery
		`INSERT INTO payload_families (technique_id,name,description,payload,purpose,risk_level) VALUES
		 ('T1049','Active TCP Connections','All active TCP connections with process IDs',
		  'netstat -ano','recon','SAFE')
		 ON CONFLICT (technique_id,name) DO NOTHING`,

		`INSERT INTO payload_families (technique_id,name,description,payload,purpose,risk_level) VALUES
		 ('T1049','PowerShell TCP View','Active connections via PowerShell (includes process name)',
		  'Get-NetTCPConnection -State Established | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,OwningProcess | Sort-Object OwningProcess','recon','SAFE')
		 ON CONFLICT (technique_id,name) DO NOTHING`,

		// T1033 — System Owner/User Discovery
		`INSERT INTO payload_families (technique_id,name,description,payload,purpose,risk_level) VALUES
		 ('T1033','Current User','Current user identity and privileges',
		  'whoami /all','recon','SAFE')
		 ON CONFLICT (technique_id,name) DO NOTHING`,

		`INSERT INTO payload_families (technique_id,name,description,payload,purpose,risk_level) VALUES
		 ('T1033','Local Users','All local user accounts',
		  'Get-LocalUser | Select-Object Name,Enabled,LastLogon,PasswordRequired','recon','SAFE')
		 ON CONFLICT (technique_id,name) DO NOTHING`,

		`INSERT INTO payload_families (technique_id,name,description,payload,purpose,risk_level) VALUES
		 ('T1033','Local Groups','Local group memberships',
		  'Get-LocalGroup | ForEach-Object {$g=$_.Name; Get-LocalGroupMember $g -ErrorAction SilentlyContinue | Select-Object @{n="Group";e={$g}},Name,ObjectClass}','recon','SAFE')
		 ON CONFLICT (technique_id,name) DO NOTHING`,
	}

	for _, s := range stmts {
		if _, err := pool.Exec(ctx, s); err != nil {
			return fmt.Errorf("schema exec failed:\n%s\nerror: %w", s, err)
		}
	}
	return nil
}
