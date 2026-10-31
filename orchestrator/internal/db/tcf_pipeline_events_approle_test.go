package db_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/db"
)

// Acceptance test 12: the pipeline-event ledger is append-only for the
// application role -- INSERT and SELECT are allowed, UPDATE and DELETE are
// refused (corrections are new rows).
func TestAppRole_PipelineEventsAppendOnly(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		if err := db.EnsureTCFPipelineEventsSchema(ctx, pool); err != nil {
			t.Fatalf("EnsureTCFPipelineEventsSchema: %v", err)
		}
		if err := db.EnsureAppRole(ctx, pool, testAppPassword); err != nil {
			t.Fatalf("EnsureAppRole: %v", err)
		}
		app := appConnectedPool(t, pool)

		if _, err := app.Exec(ctx,
			`INSERT INTO tcf_pipeline_events (event_type, event_time, source_table, source_pk, idempotency_key)
			 VALUES ('threat_observed', now(), 'source_observations', 'obs-approle', 'tpe-approle-k1')`); err != nil {
			t.Fatalf("bas_app INSERT should be allowed: %v", err)
		}
		if _, err := app.Exec(ctx,
			`UPDATE tcf_pipeline_events SET payload = '{"x":1}' WHERE idempotency_key = 'tpe-approle-k1'`); err == nil {
			t.Fatal("bas_app UPDATE on tcf_pipeline_events must be refused")
		}
		if _, err := app.Exec(ctx,
			`DELETE FROM tcf_pipeline_events WHERE idempotency_key = 'tpe-approle-k1'`); err == nil {
			t.Fatal("bas_app DELETE on tcf_pipeline_events must be refused")
		}
	})
}
