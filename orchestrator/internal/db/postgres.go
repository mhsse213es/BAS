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
			created_at    timestamptz NOT NULL DEFAULT NOW(),
			last_login    timestamptz
		)`,

		`CREATE TABLE IF NOT EXISTS agents (
			agent_id    text        PRIMARY KEY,
			hostname    text        NOT NULL DEFAULT '',
			ip_address  text        NOT NULL DEFAULT '',
			os_version  text        NOT NULL DEFAULT '',
			username    text        NOT NULL DEFAULT '',
			status      text        NOT NULL DEFAULT 'idle',
			env_label   text        NOT NULL DEFAULT 'Production',
			has_report  boolean     NOT NULL DEFAULT false,
			last_update timestamptz NOT NULL DEFAULT NOW()
		)`,

		`CREATE TABLE IF NOT EXISTS scenario_runs (
			id           text        PRIMARY KEY DEFAULT gen_random_uuid()::text,
			scenario_id  text        NOT NULL,
			agent_id     text        NOT NULL,
			name         text        NOT NULL DEFAULT '',
			status       text        NOT NULL DEFAULT 'running',
			results      jsonb       NOT NULL DEFAULT '[]',
			score        jsonb,
			started_at   timestamptz NOT NULL DEFAULT NOW(),
			completed_at timestamptz,
			CONSTRAINT fk_agent FOREIGN KEY (agent_id) REFERENCES agents(agent_id) ON DELETE CASCADE
		)`,

		`CREATE INDEX IF NOT EXISTS idx_scenario_runs_agent ON scenario_runs(agent_id)`,
		`CREATE INDEX IF NOT EXISTS idx_scenario_runs_scenario ON scenario_runs(scenario_id)`,

		`CREATE TABLE IF NOT EXISTS reports (
			agent_id       text        PRIMARY KEY,
			hostname       text        NOT NULL DEFAULT '',
			ip_address     text        NOT NULL DEFAULT '',
			os_version     text        NOT NULL DEFAULT '',
			username       text        NOT NULL DEFAULT '',
			started_at     timestamptz NOT NULL DEFAULT NOW(),
			status         text        NOT NULL DEFAULT 'Completed',
			env_label      text        NOT NULL DEFAULT 'Production',
			security_tools jsonb       NOT NULL DEFAULT '[]',
			categories     jsonb       NOT NULL DEFAULT '[]',
			score          jsonb,
			last_update    timestamptz NOT NULL DEFAULT NOW()
		)`,
	}

	for _, s := range stmts {
		if _, err := pool.Exec(ctx, s); err != nil {
			return fmt.Errorf("schema exec failed:\n%s\nerror: %w", s, err)
		}
	}
	return nil
}
