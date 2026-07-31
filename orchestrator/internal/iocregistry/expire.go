package iocregistry

import (
	"context"
	"log"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// DefaultStaleAfter matches internal/detect/retention.go's own precedent for how long
// operational data stays relevant before it's no longer worth surfacing as "current."
const DefaultStaleAfter = 30 * 24 * time.Hour

// StartExpiration prunes stale IOCs once a day, mirroring internal/detect/retention.go's
// exact shape. Best-effort; logs and continues on error.
func StartExpiration(ctx context.Context, pool *pgxpool.Pool, staleAfter time.Duration) {
	go func() {
		t := time.NewTicker(24 * time.Hour)
		defer t.Stop()
		expireStale(ctx, pool, staleAfter)
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				expireStale(ctx, pool, staleAfter)
			}
		}
	}()
}

func expireStale(ctx context.Context, pool *pgxpool.Pool, staleAfter time.Duration) {
	// make_interval(secs => ...) avoids any ambiguity from feeding Go's
	// time.Duration string format ("720h0m0s") into Postgres's interval
	// literal parser -- a plain float8 seconds value has one unambiguous
	// interpretation.
	ct, err := pool.Exec(ctx, `
		UPDATE iocs SET status = $1
		WHERE last_seen < NOW() - make_interval(secs => $2)
		  AND status NOT IN ($1, $3)`,
		string(StatusExpired), staleAfter.Seconds(), string(StatusArchived))
	if err != nil {
		log.Printf("[iocregistry] expiration sweep failed: %v", err)
		return
	}
	if n := ct.RowsAffected(); n > 0 {
		log.Printf("[iocregistry] expired %d stale IOC(s)", n)
	}
}
