package legacy

import (
	"context"
	"fmt"
)

// EnsureExerciseSchema creates the exercise engine tables.
// Idempotent — safe to call on every startup.
func EnsureExerciseSchema(ctx context.Context, db DB) error {
	stmts := []string{
		// ── Exercise Templates (built-in + custom plan blueprints) ────────────
		`CREATE TABLE IF NOT EXISTS exercise_templates (
			id             text        PRIMARY KEY,
			name           text        NOT NULL,
			version        int         NOT NULL DEFAULT 1,
			category       text        NOT NULL DEFAULT '',
			description    text        NOT NULL DEFAULT '',
			variables_json jsonb       NOT NULL DEFAULT '[]',
			steps_json     jsonb       NOT NULL DEFAULT '[]',
			built_in       boolean     NOT NULL DEFAULT false,
			author         text        NOT NULL DEFAULT '',
			created_at     timestamptz NOT NULL DEFAULT NOW(),
			updated_at     timestamptz NOT NULL DEFAULT NOW()
		)`,
		`CREATE INDEX IF NOT EXISTS idx_ex_tmpl_category ON exercise_templates(category)`,

		// ── Exercise Plans (reusable DAG templates) ───────────────────────────
		`CREATE TABLE IF NOT EXISTS exercise_plans (
			id             text        PRIMARY KEY DEFAULT gen_random_uuid()::text,
			name           text        NOT NULL,
			description    text        NOT NULL DEFAULT '',
			steps_json     jsonb       NOT NULL DEFAULT '[]',
			variables_json jsonb       NOT NULL DEFAULT '[]',
			template_id    text,
			version        int         NOT NULL DEFAULT 1,
			created_by     text        NOT NULL DEFAULT '',
			created_at     timestamptz NOT NULL DEFAULT NOW(),
			updated_at     timestamptz NOT NULL DEFAULT NOW()
		)`,
		// Backward-compat: add columns to existing tables that predate this migration.
		`ALTER TABLE exercise_plans ADD COLUMN IF NOT EXISTS variables_json jsonb NOT NULL DEFAULT '[]'`,
		`ALTER TABLE exercise_plans ADD COLUMN IF NOT EXISTS template_id    text`,
		`ALTER TABLE exercise_plans ADD COLUMN IF NOT EXISTS version        int NOT NULL DEFAULT 1`,

		// ── Exercise Executions (live instantiation of a plan) ────────────────
		`CREATE TABLE IF NOT EXISTS exercise_executions (
			id             text        PRIMARY KEY DEFAULT gen_random_uuid()::text,
			plan_id        text        NOT NULL REFERENCES exercise_plans(id) ON DELETE RESTRICT,
			name           text        NOT NULL DEFAULT '',
			status         text        NOT NULL DEFAULT 'draft',
			initiated_by   text        NOT NULL DEFAULT '',
			targets_json   jsonb       NOT NULL DEFAULT '[]',
			metadata_json  jsonb       NOT NULL DEFAULT '{}',
			variables_json jsonb       NOT NULL DEFAULT '{}',
			plan_version   int         NOT NULL DEFAULT 1,
			score_json     jsonb,
			started_at     timestamptz,
			completed_at   timestamptz,
			created_at     timestamptz NOT NULL DEFAULT NOW(),
			updated_at    timestamptz NOT NULL DEFAULT NOW()
		)`,
		`CREATE INDEX IF NOT EXISTS idx_ex_exec_plan   ON exercise_executions(plan_id)`,
		`CREATE INDEX IF NOT EXISTS idx_ex_exec_status ON exercise_executions(status)`,
		`ALTER TABLE exercise_executions ADD COLUMN IF NOT EXISTS variables_json jsonb NOT NULL DEFAULT '{}'`,
		`ALTER TABLE exercise_executions ADD COLUMN IF NOT EXISTS plan_version   int NOT NULL DEFAULT 1`,
		// execution_policy_json carries the operator-set ExecutionPolicy (e.g.
		// MaxPrivilege) from CreateExerciseExecution through to the executor's
		// AgentDispatchFn callback when an agent_task step fires.
		`ALTER TABLE exercise_executions ADD COLUMN IF NOT EXISTS execution_policy_json jsonb NOT NULL DEFAULT '{}'`,

		// ── Step Executions (per-node runtime state) ──────────────────────────
		`CREATE TABLE IF NOT EXISTS exercise_step_executions (
			id           text        PRIMARY KEY DEFAULT gen_random_uuid()::text,
			execution_id text        NOT NULL REFERENCES exercise_executions(id) ON DELETE CASCADE,
			step_id      text        NOT NULL,
			step_type    text        NOT NULL DEFAULT '',
			status       text        NOT NULL DEFAULT 'pending',
			attempt      int         NOT NULL DEFAULT 0,
			scheduled_at timestamptz,
			started_at   timestamptz,
			completed_at timestamptz,
			result_json  jsonb       NOT NULL DEFAULT '{}',
			error_msg    text        NOT NULL DEFAULT '',
			created_at   timestamptz NOT NULL DEFAULT NOW(),
			UNIQUE (execution_id, step_id)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_ex_stepex_exec   ON exercise_step_executions(execution_id)`,
		`CREATE INDEX IF NOT EXISTS idx_ex_stepex_status ON exercise_step_executions(execution_id, status)`,

		// ── Evidence (hash-chained, tamper-evident) ───────────────────────────
		`CREATE TABLE IF NOT EXISTS exercise_evidence (
			id                text        PRIMARY KEY DEFAULT gen_random_uuid()::text,
			execution_id      text        NOT NULL REFERENCES exercise_executions(id) ON DELETE CASCADE,
			step_execution_id text,
			seq               bigint      NOT NULL,
			evidence_type     text        NOT NULL,
			actor             text        NOT NULL DEFAULT '',
			source            text        NOT NULL DEFAULT '',
			payload_json      jsonb       NOT NULL DEFAULT '{}',
			sha256            text        NOT NULL,
			prev_hash         text        NOT NULL DEFAULT '',
			signature         text        NOT NULL DEFAULT '',
			retention_policy  text        NOT NULL DEFAULT '90d',
			created_at        timestamptz NOT NULL DEFAULT NOW(),
			UNIQUE (execution_id, seq)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_ex_evidence_exec ON exercise_evidence(execution_id)`,
		`CREATE INDEX IF NOT EXISTS idx_ex_evidence_type ON exercise_evidence(execution_id, evidence_type)`,

		// ── Exercise Events (execution audit trail) ───────────────────────────
		`CREATE TABLE IF NOT EXISTS exercise_events (
			id           text        PRIMARY KEY DEFAULT gen_random_uuid()::text,
			execution_id text        NOT NULL REFERENCES exercise_executions(id) ON DELETE CASCADE,
			step_id      text,
			event_type   text        NOT NULL,
			actor        text        NOT NULL DEFAULT '',
			detail_json  jsonb       NOT NULL DEFAULT '{}',
			ts           timestamptz NOT NULL DEFAULT NOW()
		)`,
		`CREATE INDEX IF NOT EXISTS idx_ex_events_exec ON exercise_events(execution_id)`,
		`CREATE INDEX IF NOT EXISTS idx_ex_events_ts   ON exercise_events(execution_id, ts DESC)`,

		// ── Click/Open Tracking Tokens ────────────────────────────────────────
		`CREATE TABLE IF NOT EXISTS exercise_track_tokens (
			token           text        PRIMARY KEY,
			execution_id    text        NOT NULL,
			step_exec_id    text        NOT NULL,
			target_id       text        NOT NULL DEFAULT '',
			token_type      text        NOT NULL,
			payload_json    jsonb       NOT NULL DEFAULT '{}',
			used_count      int         NOT NULL DEFAULT 0,
			used_at         timestamptz,
			created_at      timestamptz NOT NULL DEFAULT NOW()
		)`,
		`CREATE INDEX IF NOT EXISTS idx_ex_token_exec ON exercise_track_tokens(execution_id)`,
		`CREATE INDEX IF NOT EXISTS idx_ex_token_step ON exercise_track_tokens(step_exec_id)`,

		// ── Inbound webhook calls (/x/hook/{token}) ───────────────────────────
		`CREATE TABLE IF NOT EXISTS exercise_webhook_calls (
			id           text        PRIMARY KEY DEFAULT gen_random_uuid()::text,
			token        text        NOT NULL,
			execution_id text        NOT NULL,
			step_exec_id text        NOT NULL DEFAULT '',
			body         bytea,
			received_at  timestamptz NOT NULL DEFAULT NOW()
		)`,
		`CREATE INDEX IF NOT EXISTS idx_ex_hook_token ON exercise_webhook_calls(token)`,

		// Phase 7 Multi-Tenancy — every table in this file is tenant-owned.
		`ALTER TABLE exercise_events ADD COLUMN IF NOT EXISTS tenant_id text NOT NULL DEFAULT 'default'`,
		`ALTER TABLE exercise_evidence ADD COLUMN IF NOT EXISTS tenant_id text NOT NULL DEFAULT 'default'`,
		`ALTER TABLE exercise_executions ADD COLUMN IF NOT EXISTS tenant_id text NOT NULL DEFAULT 'default'`,
		`ALTER TABLE exercise_plans ADD COLUMN IF NOT EXISTS tenant_id text NOT NULL DEFAULT 'default'`,
		`ALTER TABLE exercise_step_executions ADD COLUMN IF NOT EXISTS tenant_id text NOT NULL DEFAULT 'default'`,
		`ALTER TABLE exercise_templates ADD COLUMN IF NOT EXISTS tenant_id text NOT NULL DEFAULT 'default'`,
		`ALTER TABLE exercise_templates ADD COLUMN IF NOT EXISTS metadata_json jsonb NOT NULL DEFAULT '{}'`,
		`ALTER TABLE exercise_track_tokens ADD COLUMN IF NOT EXISTS tenant_id text NOT NULL DEFAULT 'default'`,
		`ALTER TABLE exercise_webhook_calls ADD COLUMN IF NOT EXISTS tenant_id text NOT NULL DEFAULT 'default'`,
	}
	for _, s := range stmts {
		if _, err := db.Exec(ctx, s); err != nil {
			return fmt.Errorf("exercise schema: %w", err)
		}
	}
	return nil
}
