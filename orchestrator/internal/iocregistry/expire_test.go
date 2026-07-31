package iocregistry

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func seedIOCWithLastSeen(t *testing.T, pool *pgxpool.Pool, value, status string, lastSeen time.Time) string {
	t.Helper()
	var id string
	if err := pool.QueryRow(context.Background(), `
		INSERT INTO iocs (type, value, source, status, last_seen)
		VALUES ('command_line', $1, 'detection_alert', $2, $3)
		RETURNING id`, value, status, lastSeen).Scan(&id); err != nil {
		t.Fatalf("seed ioc %s: %v", value, err)
	}
	return id
}

func TestExpireStale_TransitionsOldObservedRowsToExpired(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		staleID := seedIOCWithLastSeen(t, pool, "cmd-stale", "observed", time.Now().Add(-60*24*time.Hour))
		freshID := seedIOCWithLastSeen(t, pool, "cmd-fresh", "observed", time.Now())
		archivedID := seedIOCWithLastSeen(t, pool, "cmd-already-archived", "archived", time.Now().Add(-60*24*time.Hour))

		expireStale(context.Background(), pool, 30*24*time.Hour)

		var staleStatus, freshStatus, archivedStatus string
		pool.QueryRow(context.Background(), `SELECT status FROM iocs WHERE id = $1`, staleID).Scan(&staleStatus)
		pool.QueryRow(context.Background(), `SELECT status FROM iocs WHERE id = $1`, freshID).Scan(&freshStatus)
		pool.QueryRow(context.Background(), `SELECT status FROM iocs WHERE id = $1`, archivedID).Scan(&archivedStatus)

		if staleStatus != "expired" {
			t.Errorf("stale IOC status = %q, want expired", staleStatus)
		}
		if freshStatus != "observed" {
			t.Errorf("fresh IOC status = %q, want unchanged observed", freshStatus)
		}
		if archivedStatus != "archived" {
			t.Errorf("already-archived IOC status = %q, want unchanged archived (not re-touched)", archivedStatus)
		}
	})
}
