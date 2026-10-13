package db

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/cloudgraph"
	"github.com/audspect/bas/internal/networkgraph"
)

// EnsureNetworkDiscoverySchema creates the network_discovery_runs and
// network_observations tables.
func EnsureNetworkDiscoverySchema(ctx context.Context, pool *pgxpool.Pool) error {
	_, err := pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS network_discovery_runs (
			id               text        PRIMARY KEY DEFAULT gen_random_uuid()::text,
			vantage_point_id text        NOT NULL,
			requested_by     text,
			target_count     int         NOT NULL,
			status           text        NOT NULL,
			started_at       timestamptz NOT NULL DEFAULT NOW(),
			completed_at     timestamptz
		)`)
	if err != nil {
		return fmt.Errorf("network_discovery_runs: ensure schema: %w", err)
	}
	_, err = pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS network_observations (
			id               text        PRIMARY KEY DEFAULT gen_random_uuid()::text,
			run_id           text        NOT NULL REFERENCES network_discovery_runs(id),
			target_host      text        NOT NULL,
			target_port      int         NOT NULL,
			target_label     text,
			vantage_point_id text        NOT NULL,
			path_state       text        NOT NULL,
			error_detail     text,
			observed_at      timestamptz NOT NULL DEFAULT NOW(),
			confidence       text
		)`)
	if err != nil {
		return fmt.Errorf("network_observations: ensure schema: %w", err)
	}
	_, err = pool.Exec(ctx, `CREATE INDEX IF NOT EXISTS idx_network_observations_run ON network_observations (run_id)`)
	if err != nil {
		return fmt.Errorf("network_observations: ensure index: %w", err)
	}
	return nil
}

// NetworkDiscoveryRun is the persisted record of one discovery run.
type NetworkDiscoveryRun struct {
	ID             string     `json:"id"`
	VantagePointID string     `json:"vantagePointId"`
	RequestedBy    string     `json:"requestedBy,omitempty"`
	TargetCount    int        `json:"targetCount"`
	Status         string     `json:"status"`
	StartedAt      time.Time  `json:"startedAt"`
	CompletedAt    *time.Time `json:"completedAt,omitempty"`
}

// InsertNetworkDiscoveryRun writes a new network_discovery_runs row. The
// caller supplies run.ID already generated.
func InsertNetworkDiscoveryRun(ctx context.Context, pool *pgxpool.Pool, run *NetworkDiscoveryRun) error {
	_, err := pool.Exec(ctx,
		`INSERT INTO network_discovery_runs (id, vantage_point_id, requested_by, target_count, status, completed_at)
		 VALUES ($1,$2,$3,$4,$5,$6)`,
		run.ID, run.VantagePointID, nullableString(run.RequestedBy), run.TargetCount, run.Status, run.CompletedAt)
	if err != nil {
		return fmt.Errorf("network_discovery_runs: insert %s: %w", run.ID, err)
	}
	return nil
}

func nullableString(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func scanNetworkDiscoveryRun(row pgx.Row) (*NetworkDiscoveryRun, error) {
	run := &NetworkDiscoveryRun{}
	var requestedBy *string
	if err := row.Scan(&run.ID, &run.VantagePointID, &requestedBy, &run.TargetCount, &run.Status, &run.StartedAt, &run.CompletedAt); err != nil {
		return nil, err
	}
	if requestedBy != nil {
		run.RequestedBy = *requestedBy
	}
	return run, nil
}

// UpdateNetworkDiscoveryRunStatus transitions a network_discovery_runs
// row's status and sets completed_at to NOW(). Used when a run's
// observations fail to persist after its row has already been inserted --
// mirrors cloud_run's UpdateCloudRunStatus pattern so a reader never sees
// a run claiming "completed"/"partial" with zero backing observations.
func UpdateNetworkDiscoveryRunStatus(ctx context.Context, pool *pgxpool.Pool, id string, status string) error {
	_, err := pool.Exec(ctx, `UPDATE network_discovery_runs SET status = $1, completed_at = NOW() WHERE id = $2`, status, id)
	if err != nil {
		return fmt.Errorf("network_discovery_runs: update status for %s: %w", id, err)
	}
	return nil
}

// GetNetworkDiscoveryRun returns one run by id. A missing id returns an
// error satisfying errors.Is(err, pgx.ErrNoRows).
func GetNetworkDiscoveryRun(ctx context.Context, pool *pgxpool.Pool, id string) (*NetworkDiscoveryRun, error) {
	row := pool.QueryRow(ctx,
		`SELECT id, vantage_point_id, requested_by, target_count, status, started_at, completed_at
		 FROM network_discovery_runs WHERE id = $1`, id)
	run, err := scanNetworkDiscoveryRun(row)
	if err != nil {
		return nil, fmt.Errorf("network_discovery_runs: get %s: %w", id, err)
	}
	return run, nil
}

// ListNetworkDiscoveryRuns returns up to limit rows, newest first. Trusts
// limit as-is -- clamping is the HTTP handler's job.
func ListNetworkDiscoveryRuns(ctx context.Context, pool *pgxpool.Pool, limit int) ([]*NetworkDiscoveryRun, error) {
	rows, err := pool.Query(ctx,
		`SELECT id, vantage_point_id, requested_by, target_count, status, started_at, completed_at
		 FROM network_discovery_runs ORDER BY started_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("network_discovery_runs: list: %w", err)
	}
	defer rows.Close()
	var out []*NetworkDiscoveryRun
	for rows.Next() {
		run, err := scanNetworkDiscoveryRun(rows)
		if err != nil {
			return nil, fmt.Errorf("network_discovery_runs: list scan: %w", err)
		}
		out = append(out, run)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("network_discovery_runs: list rows: %w", err)
	}
	return out, nil
}

// InsertNetworkObservations writes every observation for one run in a
// single transaction -- all or nothing, matching the run's own
// all-targets-persist-together semantics.
func InsertNetworkObservations(ctx context.Context, pool *pgxpool.Pool, runID string, obs []networkgraph.NetworkObservation) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("network_observations: begin tx: %w", err)
	}
	defer tx.Rollback(ctx)

	for _, o := range obs {
		_, err := tx.Exec(ctx,
			`INSERT INTO network_observations
			 (run_id, target_host, target_port, target_label, vantage_point_id, path_state, error_detail, observed_at, confidence)
			 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
			runID, o.Target.Host, o.Target.Port, nullableString(o.Target.Label), o.VantagePointID,
			string(o.State), nullableString(o.ErrorDetail), o.Provenance.ObservedAt, nullableString(o.Provenance.Confidence))
		if err != nil {
			return fmt.Errorf("network_observations: insert for run %s: %w", runID, err)
		}
	}
	return tx.Commit(ctx)
}

// ListNetworkObservationsByRun returns every observation recorded for
// runID, ordered by observed_at (the time each probe actually completed,
// not insertion order, which gen_random_uuid() primary keys don't preserve).
func ListNetworkObservationsByRun(ctx context.Context, pool *pgxpool.Pool, runID string) ([]networkgraph.NetworkObservation, error) {
	rows, err := pool.Query(ctx,
		`SELECT target_host, target_port, target_label, vantage_point_id, path_state, error_detail, observed_at, confidence
		 FROM network_observations WHERE run_id = $1 ORDER BY observed_at ASC`, runID)
	if err != nil {
		return nil, fmt.Errorf("network_observations: list for run %s: %w", runID, err)
	}
	defer rows.Close()
	var out []networkgraph.NetworkObservation
	for rows.Next() {
		var o networkgraph.NetworkObservation
		var label, errDetail, confidence *string
		var state string
		if err := rows.Scan(&o.Target.Host, &o.Target.Port, &label, &o.VantagePointID, &state, &errDetail, &o.Provenance.ObservedAt, &confidence); err != nil {
			return nil, fmt.Errorf("network_observations: scan for run %s: %w", runID, err)
		}
		if label != nil {
			o.Target.Label = *label
		}
		if errDetail != nil {
			o.ErrorDetail = *errDetail
		}
		if confidence != nil {
			o.Provenance.Confidence = *confidence
		}
		o.State = cloudgraph.PathState(state)
		out = append(out, o)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("network_observations: rows for run %s: %w", runID, err)
	}
	return out, nil
}
