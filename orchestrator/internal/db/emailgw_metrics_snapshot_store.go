package db

// Workstream 3 of the EmailGW mastery roadmap: persisted time-series
// snapshots of the Workstream 1 time-based metrics, so a future
// trend view has real history to read even before this initiative
// has meaningful customer run volume. One row per (date, environment)
// pair -- lab and customer snapshots are never merged into one row,
// same discipline as emailgwrun.Environment itself.
import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/emailgwrun"
)

// EmailGWMetricsSnapshotRow is one persisted day's own metrics for
// one environment. Metrics is deliberately the raw marshaled
// api.EmailGWTimeBasedMetrics JSON, not a decoded struct -- internal/db
// cannot import internal/api (internal/api already imports internal/db),
// same reason emailgwrun.EmailGWRun.Result itself stays json.RawMessage.
type EmailGWMetricsSnapshotRow struct {
	ID                      int64                   `json:"id"`
	SnapshotDate            time.Time               `json:"snapshotDate"`
	Environment             emailgwrun.Environment  `json:"environment"`
	MetricDefinitionVersion int                     `json:"metricDefinitionVersion"`
	// HasData mirrors dashboard.Snapshot's own HasAttackPathData
	// convention: true only when the snapshot's own metrics were
	// computed over at least one real run for this environment that
	// day. False is never silently read as "zero/perfect" -- it means
	// there was nothing to compute from.
	HasData   bool            `json:"hasData"`
	Metrics   json.RawMessage `json:"metrics"`
	CreatedAt time.Time       `json:"createdAt"`
}

// EnsureEmailGWMetricsSnapshotSchema creates email_gw_metrics_snapshots.
// Self-contained, like EnsureEmailGWRunSchema/EnsureEmailGWCampaignSchema
// -- this initiative's own tables are never added to the large shared
// migration list in postgres.go.
func EnsureEmailGWMetricsSnapshotSchema(ctx context.Context, pool *pgxpool.Pool) error {
	_, err := pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS email_gw_metrics_snapshots (
			id                         bigserial   PRIMARY KEY,
			snapshot_date              date        NOT NULL,
			environment                text        NOT NULL,
			metric_definition_version  int         NOT NULL,
			has_data                   boolean     NOT NULL DEFAULT false,
			metrics                    jsonb       NOT NULL,
			created_at                 timestamptz NOT NULL DEFAULT NOW(),
			CONSTRAINT email_gw_metrics_snapshots_environment_check CHECK (environment IN ('lab','customer')),
			UNIQUE(snapshot_date, environment)
		)`)
	if err != nil {
		return fmt.Errorf("email_gw_metrics_snapshots: ensure schema: %w", err)
	}
	if _, err := pool.Exec(ctx, `CREATE INDEX IF NOT EXISTS idx_email_gw_metrics_snapshots_date ON email_gw_metrics_snapshots (snapshot_date DESC)`); err != nil {
		return fmt.Errorf("email_gw_metrics_snapshots: create date index: %w", err)
	}
	return nil
}

// UpsertEmailGWMetricsSnapshot writes (or refreshes) one day's own
// snapshot for one environment. Idempotent via
// UNIQUE(snapshot_date, environment) -- a same-day restart just
// refreshes today's row, same convention as dashboard_snapshots'
// own ON CONFLICT upsert.
func UpsertEmailGWMetricsSnapshot(ctx context.Context, pool *pgxpool.Pool, snapshotDate time.Time, environment emailgwrun.Environment, definitionVersion int, hasData bool, metrics json.RawMessage) error {
	_, err := pool.Exec(ctx, `
		INSERT INTO email_gw_metrics_snapshots (snapshot_date, environment, metric_definition_version, has_data, metrics)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (snapshot_date, environment) DO UPDATE SET
			metric_definition_version = EXCLUDED.metric_definition_version,
			has_data                  = EXCLUDED.has_data,
			metrics                   = EXCLUDED.metrics`,
		snapshotDate.UTC().Truncate(24*time.Hour), string(environment), definitionVersion, hasData, metrics)
	if err != nil {
		return fmt.Errorf("email_gw_metrics_snapshots: upsert %s/%s: %w", snapshotDate.Format("2006-01-02"), environment, err)
	}
	return nil
}

func scanEmailGWMetricsSnapshotRow(row pgx.Row) (*EmailGWMetricsSnapshotRow, error) {
	r := &EmailGWMetricsSnapshotRow{}
	var environment string
	if err := row.Scan(&r.ID, &r.SnapshotDate, &environment, &r.MetricDefinitionVersion, &r.HasData, &r.Metrics, &r.CreatedAt); err != nil {
		return nil, err
	}
	r.Environment = emailgwrun.Environment(environment)
	return r, nil
}

// ListEmailGWMetricsSnapshots returns up to limit rows for one
// environment, most recent first -- the real history a future trend
// view reads. Never filters by HasData: an insufficient-data day is
// real history too, not something to hide from a trend line.
func ListEmailGWMetricsSnapshots(ctx context.Context, pool *pgxpool.Pool, environment emailgwrun.Environment, limit int) ([]*EmailGWMetricsSnapshotRow, error) {
	rows, err := pool.Query(ctx, `
		SELECT id, snapshot_date, environment, metric_definition_version, has_data, metrics, created_at
		FROM email_gw_metrics_snapshots
		WHERE environment = $1
		ORDER BY snapshot_date DESC
		LIMIT $2`, string(environment), limit)
	if err != nil {
		return nil, fmt.Errorf("email_gw_metrics_snapshots: list %s: %w", environment, err)
	}
	defer rows.Close()

	var out []*EmailGWMetricsSnapshotRow
	for rows.Next() {
		r, err := scanEmailGWMetricsSnapshotRow(rows)
		if err != nil {
			return nil, fmt.Errorf("email_gw_metrics_snapshots: scan: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// PruneEmailGWMetricsSnapshotsOlderThan deletes every row whose
// snapshot_date is before cutoff, mirroring dashboard_snapshots' own
// 1-year retention pattern (the caller decides the actual cutoff).
func PruneEmailGWMetricsSnapshotsOlderThan(ctx context.Context, pool *pgxpool.Pool, cutoff time.Time) (int64, error) {
	tag, err := pool.Exec(ctx, `DELETE FROM email_gw_metrics_snapshots WHERE snapshot_date < $1`, cutoff.UTC())
	if err != nil {
		return 0, fmt.Errorf("email_gw_metrics_snapshots: prune: %w", err)
	}
	return tag.RowsAffected(), nil
}
