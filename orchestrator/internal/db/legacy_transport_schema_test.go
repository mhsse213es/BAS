package db_test

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestLegacyTransportLog_SchemaExists(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()

		_, err := pool.Exec(ctx,
			`INSERT INTO legacy_transport_log (agent_id, day, last_seen_at, endpoint)
			 VALUES ($1, $2, $3, $4)`,
			"agent-1", time.Now().UTC().Truncate(24*time.Hour), time.Now().UTC(), "/api/heartbeat")
		if err != nil {
			t.Fatalf("insert into legacy_transport_log: %v", err)
		}

		_, err = pool.Exec(ctx,
			`INSERT INTO legacy_transport_unattributed (day, last_seen_at, request_count)
			 VALUES ($1, $2, $3)`,
			time.Now().UTC().Truncate(24*time.Hour), time.Now().UTC(), 1)
		if err != nil {
			t.Fatalf("insert into legacy_transport_unattributed: %v", err)
		}
	})
}

func TestLegacyTransportLog_UniqueConstraintEnforced(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		day := time.Now().UTC().Truncate(24 * time.Hour)

		_, err := pool.Exec(ctx,
			`INSERT INTO legacy_transport_log (agent_id, day, last_seen_at, endpoint) VALUES ($1, $2, $3, $4)`,
			"agent-1", day, time.Now().UTC(), "/api/heartbeat")
		if err != nil {
			t.Fatalf("first insert: %v", err)
		}
		_, err = pool.Exec(ctx,
			`INSERT INTO legacy_transport_log (agent_id, day, last_seen_at, endpoint) VALUES ($1, $2, $3, $4)`,
			"agent-1", day, time.Now().UTC(), "/api/heartbeat")
		if err == nil {
			t.Fatal("expected a second insert for the same (agent_id, day) to violate the UNIQUE constraint, got nil error -- " +
				"Task 2's upsert relies on this constraint existing for ON CONFLICT to have something to conflict on")
		}
	})
}
