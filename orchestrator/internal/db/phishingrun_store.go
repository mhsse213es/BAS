package db

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/phishingrun"
)

// EnsurePhishingRunSchema creates the phishing_runs table -- the real-
// run execution record internal/api's phishing-run executor writes
// to. Mirrors email_gw_runs' column shape, minus the dwell-window
// columns (injected_at/window_start/window_end/verified_at): this
// slice's one registered scenario (PH-DET-002) evaluates
// synchronously, with no real SMTP send or dwell-window wait to
// perform -- see internal/phishingrun's own package comment. No
// tenant_id column: no run-persistence table in this codebase
// (email_gw_runs, cloud_runs) currently scopes rows by Audspect-
// customer tenant, and this table matches that existing precedent
// rather than diverging from it alone.
func EnsurePhishingRunSchema(ctx context.Context, pool *pgxpool.Pool) error {
	_, err := pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS phishing_runs (
			id             text        PRIMARY KEY DEFAULT gen_random_uuid()::text,
			scenario_id    text        NOT NULL,
			status         text        NOT NULL DEFAULT 'pending',
			result         jsonb,
			error          text,
			initiated_by   text,
			started_at     timestamptz NOT NULL DEFAULT NOW(),
			completed_at   timestamptz,
			CONSTRAINT phishing_runs_status_check CHECK (status IN ('pending','running','completed','failed','partial'))
		)`)
	if err != nil {
		return fmt.Errorf("phishing_runs: ensure schema: %w", err)
	}
	if _, err := pool.Exec(ctx, `CREATE INDEX IF NOT EXISTS idx_phishing_runs_status ON phishing_runs (status)`); err != nil {
		return fmt.Errorf("phishing_runs: create status index: %w", err)
	}
	// One dispatch per idempotency key. Ordinary runs carry no key and are not indexed.
	if _, err := pool.Exec(ctx, `CREATE UNIQUE INDEX IF NOT EXISTS idx_phishing_runs_dispatch_key
		ON phishing_runs ((result->'dispatch'->>'idempotencyKey'))
		WHERE result->'dispatch'->>'idempotencyKey' IS NOT NULL`); err != nil {
		return fmt.Errorf("phishing_runs: create dispatch key index: %w", err)
	}
	return nil
}

// InsertPhishingRun writes a new phishing_runs row. The caller
// supplies run.ID and run.Status already set, matching
// InsertEmailGWRun's own convention.
func InsertPhishingRun(ctx context.Context, pool *pgxpool.Pool, run *phishingrun.PhishingRun) error {
	_, err := pool.Exec(ctx, `
		INSERT INTO phishing_runs (id, scenario_id, status, result, error, initiated_by, started_at, completed_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
		run.ID, run.ScenarioID, string(run.Status), run.Result, run.Error, run.InitiatedBy, run.StartedAt, run.CompletedAt)
	if err != nil {
		return fmt.Errorf("phishing_runs: insert %s: %w", run.ID, err)
	}
	return nil
}

const phishingRunColumns = `id, scenario_id, status, result, error, initiated_by, started_at, completed_at`

// scanPhishingRun scans one phishing_runs row, shared by every reader
// below so the column list exists in exactly one place.
func scanPhishingRun(row pgx.Row) (*phishingrun.PhishingRun, error) {
	run := &phishingrun.PhishingRun{}
	var status string
	if err := row.Scan(&run.ID, &run.ScenarioID, &status, &run.Result, &run.Error, &run.InitiatedBy, &run.StartedAt, &run.CompletedAt); err != nil {
		return nil, err
	}
	run.Status = phishingrun.Status(status)
	return run, nil
}

// GetPhishingRun returns one phishing_runs row by id.
func GetPhishingRun(ctx context.Context, pool *pgxpool.Pool, id string) (*phishingrun.PhishingRun, error) {
	row := pool.QueryRow(ctx, `SELECT `+phishingRunColumns+` FROM phishing_runs WHERE id = $1`, id)
	run, err := scanPhishingRun(row)
	if err != nil {
		return nil, fmt.Errorf("phishing_runs: get %s: %w", id, err)
	}
	return run, nil
}

// UpdatePhishingRunStatus transitions a phishing_runs row to a
// terminal status (completed/failed/partial), setting result/error
// and completed_at.
func UpdatePhishingRunStatus(ctx context.Context, pool *pgxpool.Pool, id string, status phishingrun.Status, result json.RawMessage, errMsg string) error {
	_, err := pool.Exec(ctx, `
		UPDATE phishing_runs SET status = $1, result = $2, error = $3, completed_at = NOW()
		WHERE id = $4`,
		string(status), result, errMsg, id)
	if err != nil {
		return fmt.Errorf("phishing_runs: update status for %s: %w", id, err)
	}
	return nil
}

// ListPhishingRuns returns up to limit phishing_runs rows, newest
// started_at first.
func ListPhishingRuns(ctx context.Context, pool *pgxpool.Pool, limit int) ([]*phishingrun.PhishingRun, error) {
	rows, err := pool.Query(ctx, `SELECT `+phishingRunColumns+` FROM phishing_runs ORDER BY started_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("phishing_runs: list: %w", err)
	}
	defer rows.Close()
	var runs []*phishingrun.PhishingRun
	for rows.Next() {
		run, err := scanPhishingRun(rows)
		if err != nil {
			return nil, fmt.Errorf("phishing_runs: list scan: %w", err)
		}
		runs = append(runs, run)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("phishing_runs: list rows: %w", err)
	}
	return runs, nil
}
