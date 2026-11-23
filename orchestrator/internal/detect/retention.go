package detect

import (
	"context"
	"log"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/auditretention"
)

// RawRetentionDays is how long raw detection alerts are kept. They are security event logs, so they follow the
// audit retention minimum. Alerts that matched no step exist only in detections_raw, so pruning them earlier
// would lose them before the minimum is reached.
const RawRetentionDays = auditretention.MinimumRetentionDays

// StartRetention prunes raw detection blobs older than RawRetentionDays once a day,
// keeping detection_summary and the per-step results forever. Best-effort; logs and continues on error.
func StartRetention(ctx context.Context, pool *pgxpool.Pool) {
	go func() {
		t := time.NewTicker(24 * time.Hour)
		defer t.Stop()
		prune(ctx, pool)
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				prune(ctx, pool)
			}
		}
	}()
}

func prune(ctx context.Context, pool *pgxpool.Pool) {
	ct, err := pool.Exec(ctx,
		`UPDATE scenario_runs SET detections_raw='[]'
		   WHERE completed_at < NOW() - make_interval(days => $1) AND detections_raw <> '[]'`, RawRetentionDays)
	if err != nil {
		log.Printf("[detect] retention prune failed: %v", err)
		return
	}
	if n := ct.RowsAffected(); n > 0 {
		log.Printf("[detect] pruned raw detections on %d run(s) >30d", n)
	}
}
