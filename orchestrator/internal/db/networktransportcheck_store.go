package db

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/networksecurity"
	"github.com/audspect/bas/internal/networktransport"
)

func EnsureTransportSecurityCheckSchema(ctx context.Context, pool *pgxpool.Pool) error {
	_, err := pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS transport_security_check_runs (
			id               text        PRIMARY KEY DEFAULT gen_random_uuid()::text,
			vantage_point_id text        NOT NULL,
			requested_by     text,
			check_count      int         NOT NULL,
			status           text        NOT NULL,
			started_at       timestamptz NOT NULL DEFAULT NOW(),
			completed_at     timestamptz
		)`)
	if err != nil {
		return fmt.Errorf("transport_security_check_runs: ensure schema: %w", err)
	}
	_, err = pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS transport_security_check_results (
			id           text        PRIMARY KEY DEFAULT gen_random_uuid()::text,
			run_id       text        NOT NULL REFERENCES transport_security_check_runs(id),
			check_type   text        NOT NULL,
			target_host  text        NOT NULL,
			target_port  int         NOT NULL,
			state        text        NOT NULL,
			reason       text,
			observed_at  timestamptz NOT NULL DEFAULT NOW()
		)`)
	if err != nil {
		return fmt.Errorf("transport_security_check_results: ensure schema: %w", err)
	}
	_, err = pool.Exec(ctx, `CREATE INDEX IF NOT EXISTS idx_transport_security_check_results_run ON transport_security_check_results (run_id)`)
	if err != nil {
		return fmt.Errorf("transport_security_check_results: ensure index: %w", err)
	}
	return nil
}

type TransportSecurityCheckRun struct {
	ID             string     `json:"id"`
	VantagePointID string     `json:"vantagePointId"`
	RequestedBy    string     `json:"requestedBy,omitempty"`
	CheckCount     int        `json:"checkCount"`
	Status         string     `json:"status"`
	StartedAt      time.Time  `json:"startedAt"`
	CompletedAt    *time.Time `json:"completedAt,omitempty"`
}

func InsertTransportSecurityCheckRun(ctx context.Context, pool *pgxpool.Pool, run *TransportSecurityCheckRun) error {
	_, err := pool.Exec(ctx,
		`INSERT INTO transport_security_check_runs (id, vantage_point_id, requested_by, check_count, status)
		 VALUES ($1,$2,$3,$4,$5)`,
		run.ID, run.VantagePointID, nullableString(run.RequestedBy), run.CheckCount, run.Status)
	if err != nil {
		return fmt.Errorf("transport_security_check_runs: insert %s: %w", run.ID, err)
	}
	return nil
}

func UpdateTransportSecurityCheckRunStatus(ctx context.Context, pool *pgxpool.Pool, id string, status string) error {
	_, err := pool.Exec(ctx, `UPDATE transport_security_check_runs SET status = $1, completed_at = NOW() WHERE id = $2`, status, id)
	if err != nil {
		return fmt.Errorf("transport_security_check_runs: update status for %s: %w", id, err)
	}
	return nil
}

func scanTransportSecurityCheckRun(row pgx.Row) (*TransportSecurityCheckRun, error) {
	run := &TransportSecurityCheckRun{}
	var requestedBy *string
	if err := row.Scan(&run.ID, &run.VantagePointID, &requestedBy, &run.CheckCount, &run.Status, &run.StartedAt, &run.CompletedAt); err != nil {
		return nil, err
	}
	if requestedBy != nil {
		run.RequestedBy = *requestedBy
	}
	return run, nil
}

func GetTransportSecurityCheckRun(ctx context.Context, pool *pgxpool.Pool, id string) (*TransportSecurityCheckRun, error) {
	row := pool.QueryRow(ctx,
		`SELECT id, vantage_point_id, requested_by, check_count, status, started_at, completed_at
		 FROM transport_security_check_runs WHERE id = $1`, id)
	run, err := scanTransportSecurityCheckRun(row)
	if err != nil {
		return nil, fmt.Errorf("transport_security_check_runs: get %s: %w", id, err)
	}
	return run, nil
}

func ListTransportSecurityCheckRuns(ctx context.Context, pool *pgxpool.Pool, limit int) ([]*TransportSecurityCheckRun, error) {
	rows, err := pool.Query(ctx,
		`SELECT id, vantage_point_id, requested_by, check_count, status, started_at, completed_at
		 FROM transport_security_check_runs ORDER BY started_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("transport_security_check_runs: list: %w", err)
	}
	defer rows.Close()
	var out []*TransportSecurityCheckRun
	for rows.Next() {
		run, err := scanTransportSecurityCheckRun(rows)
		if err != nil {
			return nil, fmt.Errorf("transport_security_check_runs: list scan: %w", err)
		}
		out = append(out, run)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("transport_security_check_runs: list rows: %w", err)
	}
	return out, nil
}

// InsertTransportSecurityCheckResults writes every result for one run in
// a single transaction. checkTypes and results are parallel slices, one
// entry per check, in the same order RunChecks returned them.
func InsertTransportSecurityCheckResults(ctx context.Context, pool *pgxpool.Pool, runID string, checkTypes []networktransport.CheckType, results []networksecurity.SecurityCheckResult) error {
	if len(checkTypes) != len(results) {
		return fmt.Errorf("transport_security_check_results: checkTypes (%d) and results (%d) must be the same length", len(checkTypes), len(results))
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("transport_security_check_results: begin tx: %w", err)
	}
	defer tx.Rollback(ctx)

	for i, r := range results {
		observedAt := r.Provenance.ObservedAt
		if observedAt.IsZero() {
			observedAt = time.Now()
		}
		_, err := tx.Exec(ctx,
			`INSERT INTO transport_security_check_results
			 (run_id, check_type, target_host, target_port, state, reason, observed_at)
			 VALUES ($1,$2,$3,$4,$5,$6,$7)`,
			runID, string(checkTypes[i]), r.Target.Host, r.Target.Port, string(r.State), nullableString(r.Reason), observedAt)
		if err != nil {
			return fmt.Errorf("transport_security_check_results: insert for run %s: %w", runID, err)
		}
	}
	return tx.Commit(ctx)
}

func ListTransportSecurityCheckResultsByRun(ctx context.Context, pool *pgxpool.Pool, runID string) ([]networksecurity.SecurityCheckResult, error) {
	rows, err := pool.Query(ctx,
		`SELECT target_host, target_port, state, reason, observed_at
		 FROM transport_security_check_results WHERE run_id = $1 ORDER BY observed_at ASC`, runID)
	if err != nil {
		return nil, fmt.Errorf("transport_security_check_results: list for run %s: %w", runID, err)
	}
	defer rows.Close()
	var out []networksecurity.SecurityCheckResult
	for rows.Next() {
		var r networksecurity.SecurityCheckResult
		var reason *string
		var state string
		if err := rows.Scan(&r.Target.Host, &r.Target.Port, &state, &reason, &r.Provenance.ObservedAt); err != nil {
			return nil, fmt.Errorf("transport_security_check_results: scan for run %s: %w", runID, err)
		}
		r.State = networksecurity.SecurityState(state)
		if reason != nil {
			r.Reason = *reason
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("transport_security_check_results: rows for run %s: %w", runID, err)
	}
	return out, nil
}
