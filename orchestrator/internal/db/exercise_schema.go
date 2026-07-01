package db

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

// EnsureExerciseSchema creates the exercise engine tables.
// Idempotent — safe to call on every startup.
func EnsureExerciseSchema(ctx context.Context, pool *pgxpool.Pool) error {
	stmts := []string{
		// ── Exercise Plans (reusable DAG templates) ───────────────────────────
		`CREATE TABLE IF NOT EXISTS exercise_plans (
			id          text        PRIMARY KEY DEFAULT gen_random_uuid()::text,
			name        text        NOT NULL,
			description text        NOT NULL DEFAULT '',
			steps_json  jsonb       NOT NULL DEFAULT '[]',
			created_by  text        NOT NULL DEFAULT '',
			created_at  timestamptz NOT NULL DEFAULT NOW(),
			updated_at  timestamptz NOT NULL DEFAULT NOW()
		)`,

		// ── Exercise Executions (live instantiation of a plan) ────────────────
		`CREATE TABLE IF NOT EXISTS exercise_executions (
			id            text        PRIMARY KEY DEFAULT gen_random_uuid()::text,
			plan_id       text        NOT NULL REFERENCES exercise_plans(id) ON DELETE RESTRICT,
			name          text        NOT NULL DEFAULT '',
			status        text        NOT NULL DEFAULT 'draft',
			initiated_by  text        NOT NULL DEFAULT '',
			targets_json  jsonb       NOT NULL DEFAULT '[]',
			metadata_json jsonb       NOT NULL DEFAULT '{}',
			score_json    jsonb,
			started_at    timestamptz,
			completed_at  timestamptz,
			created_at    timestamptz NOT NULL DEFAULT NOW(),
			updated_at    timestamptz NOT NULL DEFAULT NOW()
		)`,
		`CREATE INDEX IF NOT EXISTS idx_ex_exec_plan   ON exercise_executions(plan_id)`,
		`CREATE INDEX IF NOT EXISTS idx_ex_exec_status ON exercise_executions(status)`,

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
	}
	for _, s := range stmts {
		if _, err := pool.Exec(ctx, s); err != nil {
			return fmt.Errorf("exercise schema: %w", err)
		}
	}
	return nil
}
