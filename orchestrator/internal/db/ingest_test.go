package db_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/db"
)

func TestEnsureIngestSchema_CreatesIngestedEventsTableWithUniqueConstraint(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		if err := db.EnsureIngestSchema(ctx, pool); err != nil {
			t.Fatalf("EnsureIngestSchema: %v", err)
		}
		// Idempotent: calling it again must not error.
		if err := db.EnsureIngestSchema(ctx, pool); err != nil {
			t.Fatalf("EnsureIngestSchema (second call): %v", err)
		}

		if _, err := pool.Exec(ctx, `INSERT INTO ingested_events (source, external_event_id, ioc_id) VALUES ('splunk', 'evt-1', NULL)`); err != nil {
			t.Fatalf("first insert: %v", err)
		}
		_, err := pool.Exec(ctx, `INSERT INTO ingested_events (source, external_event_id, ioc_id) VALUES ('splunk', 'evt-1', NULL)`)
		if err == nil {
			t.Fatal("expected a unique-constraint violation on a repeat (source, external_event_id)")
		}
	})
}
