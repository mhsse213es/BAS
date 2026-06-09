package db

import (
	"context"
	"os"
	"testing"
)

func TestRunEventsSchemaCreated(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	pool, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer pool.Close()
	if err := EnsureSchema(ctx, pool); err != nil {
		t.Fatalf("ensure 1: %v", err)
	}
	if err := EnsureSchema(ctx, pool); err != nil {
		t.Fatalf("ensure 2 (idempotency): %v", err)
	}
	var n int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM information_schema.tables WHERE table_name = 'run_events'`,
	).Scan(&n); err != nil || n != 1 {
		t.Fatalf("run_events table missing: n=%d err=%v", n, err)
	}
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM information_schema.columns
		 WHERE table_name = 'scenario_runs' AND column_name = 'steps_running'`,
	).Scan(&n); err != nil || n != 1 {
		t.Fatalf("scenario_runs.steps_running missing: n=%d err=%v", n, err)
	}
}
