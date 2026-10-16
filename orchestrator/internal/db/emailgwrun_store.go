package db

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/emailgwrun"
)

// EnsureEmailGWRunSchema creates the email_gw_runs table -- the
// real-run execution record this package's own executor writes to.
// Mirrors cloud_runs' column shape; see internal/emailgwrun's own
// package comment for why the lifecycle built on top of it differs.
func EnsureEmailGWRunSchema(ctx context.Context, pool *pgxpool.Pool) error {
	_, err := pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS email_gw_runs (
			id                  text        PRIMARY KEY DEFAULT gen_random_uuid()::text,
			scenario_id         text        NOT NULL,
			message_class       text        NOT NULL DEFAULT '',
			status              text        NOT NULL DEFAULT 'pending',
			result              jsonb,
			error               text,
			initiated_by        text,
			sender_payload_hash text        NOT NULL DEFAULT '',
			injected_at         timestamptz,
			window_start        timestamptz,
			window_end          timestamptz,
			verified_at         timestamptz,
			started_at          timestamptz NOT NULL DEFAULT NOW(),
			completed_at        timestamptz,
			CONSTRAINT email_gw_runs_status_check CHECK (status IN ('pending','running','completed','failed','partial'))
		)`)
	if err != nil {
		return fmt.Errorf("email_gw_runs: ensure schema: %w", err)
	}
	_, err = pool.Exec(ctx, `CREATE INDEX IF NOT EXISTS idx_email_gw_runs_status ON email_gw_runs (status)`)
	if err != nil {
		return fmt.Errorf("email_gw_runs: create status index: %w", err)
	}
	return nil
}

// InsertEmailGWRun writes a new email_gw_runs row. The caller
// supplies run.ID and run.Status already set, matching
// InsertCloudRun's own convention.
func InsertEmailGWRun(ctx context.Context, pool *pgxpool.Pool, run *emailgwrun.EmailGWRun) error {
	_, err := pool.Exec(ctx, `
		INSERT INTO email_gw_runs (id, scenario_id, message_class, status, result, error, initiated_by, sender_payload_hash, injected_at, window_start, window_end, verified_at, started_at, completed_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
		run.ID, run.ScenarioID, run.MessageClass, string(run.Status), run.Result, run.Error, run.InitiatedBy,
		run.SenderPayloadHash, run.InjectedAt, run.WindowStart, run.WindowEnd, run.VerifiedAt, run.StartedAt, run.CompletedAt)
	if err != nil {
		return fmt.Errorf("email_gw_runs: insert %s: %w", run.ID, err)
	}
	return nil
}

// scanEmailGWRun scans one email_gw_runs row, shared by every reader
// below so the column list exists in exactly one place.
func scanEmailGWRun(row pgx.Row) (*emailgwrun.EmailGWRun, error) {
	run := &emailgwrun.EmailGWRun{}
	var status string
	if err := row.Scan(&run.ID, &run.ScenarioID, &run.MessageClass, &status, &run.Result, &run.Error, &run.InitiatedBy,
		&run.SenderPayloadHash, &run.InjectedAt, &run.WindowStart, &run.WindowEnd, &run.VerifiedAt, &run.StartedAt, &run.CompletedAt); err != nil {
		return nil, err
	}
	run.Status = emailgwrun.Status(status)
	return run, nil
}

const emailGWRunColumns = `id, scenario_id, message_class, status, result, error, initiated_by, sender_payload_hash, injected_at, window_start, window_end, verified_at, started_at, completed_at`

// GetEmailGWRun returns one email_gw_runs row by id.
func GetEmailGWRun(ctx context.Context, pool *pgxpool.Pool, id string) (*emailgwrun.EmailGWRun, error) {
	row := pool.QueryRow(ctx, `SELECT `+emailGWRunColumns+` FROM email_gw_runs WHERE id = $1`, id)
	run, err := scanEmailGWRun(row)
	if err != nil {
		return nil, fmt.Errorf("email_gw_runs: get %s: %w", id, err)
	}
	return run, nil
}

// UpdateEmailGWRunInjected records a successful injection and
// transitions the row to running -- the point at which the real SMTP
// send has happened and window has been fixed, but verification has
// not run yet.
func UpdateEmailGWRunInjected(ctx context.Context, pool *pgxpool.Pool, id string, senderPayloadHash string, injectedAt, windowStart, windowEnd time.Time) error {
	_, err := pool.Exec(ctx, `
		UPDATE email_gw_runs SET status = $1, sender_payload_hash = $2, injected_at = $3, window_start = $4, window_end = $5
		WHERE id = $6`,
		string(emailgwrun.StatusRunning), senderPayloadHash, injectedAt, windowStart, windowEnd, id)
	if err != nil {
		return fmt.Errorf("email_gw_runs: update injected for %s: %w", id, err)
	}
	return nil
}

// UpdateEmailGWRunStatus transitions an email_gw_runs row to a
// terminal status (completed/failed/partial), setting result/error
// and completed_at. verifiedAt is written only when non-zero -- a
// StatusFailed transition from an injection error has no verification
// to record.
func UpdateEmailGWRunStatus(ctx context.Context, pool *pgxpool.Pool, id string, status emailgwrun.Status, result json.RawMessage, errMsg string, verifiedAt time.Time) error {
	var verifiedAtArg any
	if !verifiedAt.IsZero() {
		verifiedAtArg = verifiedAt
	}
	_, err := pool.Exec(ctx, `
		UPDATE email_gw_runs SET status = $1, result = $2, error = $3, verified_at = COALESCE($4, verified_at), completed_at = NOW()
		WHERE id = $5`,
		string(status), result, errMsg, verifiedAtArg, id)
	if err != nil {
		return fmt.Errorf("email_gw_runs: update status for %s: %w", id, err)
	}
	return nil
}

// ListEmailGWRuns returns up to limit email_gw_runs rows, newest
// started_at first.
func ListEmailGWRuns(ctx context.Context, pool *pgxpool.Pool, limit int) ([]*emailgwrun.EmailGWRun, error) {
	rows, err := pool.Query(ctx, `SELECT `+emailGWRunColumns+` FROM email_gw_runs ORDER BY started_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("email_gw_runs: list: %w", err)
	}
	defer rows.Close()
	var runs []*emailgwrun.EmailGWRun
	for rows.Next() {
		run, err := scanEmailGWRun(rows)
		if err != nil {
			return nil, fmt.Errorf("email_gw_runs: list scan: %w", err)
		}
		runs = append(runs, run)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("email_gw_runs: list rows: %w", err)
	}
	return runs, nil
}

// ListRunningEmailGWRuns returns every row still sitting at
// StatusRunning -- a startup recovery sweep's own input: each one is
// either still legitimately waiting out its window (WindowEnd in the
// future) or was abandoned by a process restart mid-wait (WindowEnd
// already past), and the sweep tells those two cases apart itself
// from WindowEnd, not from anything this function decides.
func ListRunningEmailGWRuns(ctx context.Context, pool *pgxpool.Pool) ([]*emailgwrun.EmailGWRun, error) {
	rows, err := pool.Query(ctx, `SELECT `+emailGWRunColumns+` FROM email_gw_runs WHERE status = $1`, string(emailgwrun.StatusRunning))
	if err != nil {
		return nil, fmt.Errorf("email_gw_runs: list running: %w", err)
	}
	defer rows.Close()
	var runs []*emailgwrun.EmailGWRun
	for rows.Next() {
		run, err := scanEmailGWRun(rows)
		if err != nil {
			return nil, fmt.Errorf("email_gw_runs: list running scan: %w", err)
		}
		runs = append(runs, run)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("email_gw_runs: list running rows: %w", err)
	}
	return runs, nil
}
