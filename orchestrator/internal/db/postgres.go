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
	}

	for _, s := range stmts {
		if _, err := pool.Exec(ctx, s); err != nil {
			return fmt.Errorf("schema exec failed:\n%s\nerror: %w", s, err)
		}
	}
	return nil
}
