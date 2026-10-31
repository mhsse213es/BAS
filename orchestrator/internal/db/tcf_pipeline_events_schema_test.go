package db_test

import (
	"context"
	"testing"

	"github.com/audspect/bas/internal/db"
)

func TestEnsureTCFPipelineEventsSchema(t *testing.T) {
	ctx := context.Background()
	pool := sharedDB.Pool

	if err := db.EnsureTCFPipelineEventsSchema(ctx, pool); err != nil {
		t.Fatalf("EnsureTCFPipelineEventsSchema: %v", err)
	}
	// Idempotent -- running it twice must not error.
	if err := db.EnsureTCFPipelineEventsSchema(ctx, pool); err != nil {
		t.Fatalf("EnsureTCFPipelineEventsSchema (second run): %v", err)
	}

	var exists bool
	if err := pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = current_schema() AND table_name = 'tcf_pipeline_events')`).
		Scan(&exists); err != nil {
		t.Fatal(err)
	}
	if !exists {
		t.Fatal("table tcf_pipeline_events was not created")
	}

	ins := func(key string) (int64, error) {
		tag, err := pool.Exec(ctx,
			`INSERT INTO tcf_pipeline_events (event_type, event_time, source_table, source_pk, idempotency_key)
			 VALUES ('threat_observed', now(), 'source_observations', 'obs-1', $1)
			 ON CONFLICT (idempotency_key) DO NOTHING`, key)
		if err != nil {
			return 0, err
		}
		return tag.RowsAffected(), nil
	}
	// (a) a row with a unique idempotency_key inserts.
	if n, err := ins("tpe-schema-k1"); err != nil || n != 1 {
		t.Fatalf("first insert: n=%d err=%v, want 1,nil", n, err)
	}
	// (b) the same idempotency_key with ON CONFLICT DO NOTHING affects 0 rows.
	if n, err := ins("tpe-schema-k1"); err != nil || n != 0 {
		t.Fatalf("duplicate insert: n=%d err=%v, want 0,nil", n, err)
	}
	// (c) an event_type outside the 12-value CHECK is rejected.
	if _, err := pool.Exec(ctx,
		`INSERT INTO tcf_pipeline_events (event_type, event_time, source_table, source_pk, idempotency_key)
		 VALUES ('bogus_type', now(), 't', 'pk', 'tpe-schema-bogus')`); err == nil {
		t.Fatal("event_type outside the CHECK must be rejected")
	}
}
