package detect

import (
	"context"
	"log"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// StartRetention prunes raw detection blobs older than 30 days once a day,
// keeping detection_summary forever. Best-effort; logs and continues on error.
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
		   WHERE completed_at < NOW() - INTERVAL '30 days' AND detections_raw <> '[]'`)
	if err != nil {
		log.Printf("[detect] retention prune failed: %v", err)
		return
	}
	if n := ct.RowsAffected(); n > 0 {
		log.Printf("[detect] pruned raw detections on %d run(s) >30d", n)
	}
}
