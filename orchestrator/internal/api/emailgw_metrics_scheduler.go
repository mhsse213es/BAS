package api

// Workstream 3's scheduler half: persists today's Workstream 1
// metrics (both environments) once a day, same shape as
// dashboard_scheduler.go's own StartDashboardScheduler -- immediately
// on start, then every 24h, idempotent via
// UNIQUE(snapshot_date, environment) so a same-day restart just
// refreshes today's rows rather than erroring or duplicating.
import (
	"context"
	"encoding/json"
	"log"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/emailgwrun"
)

// EmailGWMetricDefinitionVersion is persisted on every snapshot row.
// Bump this whenever ComputeEmailGWTimeBasedMetrics's own MTTD/MTTR
// semantics change, so a historical snapshot stays interpretable
// against the definition that actually produced it, even after a
// later version changes what the numbers mean.
const EmailGWMetricDefinitionVersion = 1

// emailGWMetricsSnapshotRetention mirrors dashboard_snapshots' own
// 1-year retention window.
const emailGWMetricsSnapshotRetention = 365 * 24 * time.Hour

// StartEmailGWMetricsScheduler snapshots both environments' Workstream
// 1 metrics into email_gw_metrics_snapshots once a day, and prunes
// rows older than a year. Fire-and-forget; stops cleanly on ctx.Done,
// same shutdown contract as StartDashboardScheduler.
func StartEmailGWMetricsScheduler(ctx context.Context, pool *pgxpool.Pool) {
	go func() {
		t := time.NewTicker(24 * time.Hour)
		defer t.Stop()
		snapshotEmailGWMetricsAndPrune(ctx, pool, time.Now().UTC())
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				snapshotEmailGWMetricsAndPrune(ctx, pool, time.Now().UTC())
			}
		}
	}()
	log.Println("[+] EmailGW metrics snapshot scheduler started")
}

// snapshotEmailGWMetricsAndPrune takes now as an explicit parameter
// (unlike dashboard_scheduler's own hardcoded CURRENT_DATE) so a test
// can drive it with a controlled clock instead of waiting on a real
// day boundary -- see this file's own test for why.
func snapshotEmailGWMetricsAndPrune(ctx context.Context, pool *pgxpool.Pool, now time.Time) {
	runs, err := db.ListEmailGWRuns(ctx, pool, 20000)
	if err != nil {
		log.Printf("[emailgw-metrics] snapshot failed to list runs: %v", err)
		return
	}

	for _, environment := range []emailgwrun.Environment{emailgwrun.EnvironmentLab, emailgwrun.EnvironmentCustomer} {
		metrics := ComputeEmailGWTimeBasedMetrics(runs, environment, DefaultEmailGWMinimumSampleSize, now)
		raw, err := json.Marshal(metrics)
		if err != nil {
			log.Printf("[emailgw-metrics] snapshot marshal failed for %s: %v", environment, err)
			continue
		}
		hasData := metrics.RunsConsidered > 0
		if err := db.UpsertEmailGWMetricsSnapshot(ctx, pool, now, environment, EmailGWMetricDefinitionVersion, hasData, raw); err != nil {
			log.Printf("[emailgw-metrics] snapshot upsert failed for %s: %v", environment, err)
		}
	}

	cutoff := now.Add(-emailGWMetricsSnapshotRetention)
	n, err := db.PruneEmailGWMetricsSnapshotsOlderThan(ctx, pool, cutoff)
	if err != nil {
		log.Printf("[emailgw-metrics] prune failed: %v", err)
		return
	}
	if n > 0 {
		log.Printf("[emailgw-metrics] pruned %d snapshot(s) older than %s", n, emailGWMetricsSnapshotRetention)
	}
}
