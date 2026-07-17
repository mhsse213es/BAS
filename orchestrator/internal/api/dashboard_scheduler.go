package api

import (
	"context"
	"log"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/dashboard"
)

// StartDashboardScheduler snapshots fleet-wide risk/exposure/detection-
// coverage scores into dashboard_snapshots once a day (immediately on start,
// then every 24h), and prunes rows older than 1 year. Fire-and-forget, same
// shape as internal/detect.StartRetention. Idempotent via
// dashboard_snapshots' UNIQUE(snapshot_date) + upsert, so a same-day restart
// just refreshes today's row instead of erroring or duplicating — this is
// why there's no separate "has today already run" gate the way the
// attack-path scheduler needs one (that one has a configurable interval and
// an enabled/disabled toggle; this one doesn't).
func StartDashboardScheduler(ctx context.Context, pool *pgxpool.Pool) {
	go func() {
		t := time.NewTicker(24 * time.Hour)
		defer t.Stop()
		snapshotAndPrune(ctx, pool)
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				snapshotAndPrune(ctx, pool)
			}
		}
	}()
	log.Println("[+] Dashboard snapshot scheduler started")
}

func snapshotAndPrune(ctx context.Context, pool *pgxpool.Pool) {
	snap, err := dashboard.Compute(ctx, pool)
	if err != nil {
		log.Printf("[dashboard] snapshot failed: %v", err)
		return
	}
	_, err = pool.Exec(ctx, `
		INSERT INTO dashboard_snapshots (snapshot_date, avg_risk_score, exposure_score, detection_coverage, asset_count)
		VALUES (CURRENT_DATE, $1, $2, $3, $4)
		ON CONFLICT (snapshot_date) DO UPDATE SET
			avg_risk_score     = EXCLUDED.avg_risk_score,
			exposure_score     = EXCLUDED.exposure_score,
			detection_coverage = EXCLUDED.detection_coverage,
			asset_count        = EXCLUDED.asset_count`,
		snap.AvgRiskScore, snap.ExposureScore, snap.DetectionCoverage, snap.AssetCount)
	if err != nil {
		log.Printf("[dashboard] snapshot upsert failed: %v", err)
		return
	}
	ct, err := pool.Exec(ctx, `DELETE FROM dashboard_snapshots WHERE snapshot_date < NOW() - INTERVAL '1 year'`)
	if err == nil {
		if n := ct.RowsAffected(); n > 0 {
			log.Printf("[dashboard] pruned %d snapshot(s) older than 1 year", n)
		}
	}
}
