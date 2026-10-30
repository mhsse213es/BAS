package db_test

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/db"
)

// SinkEvidenceForStep counts sink tokens issued for one run and technique, and
// how many of those tokens have a receipt. It is scoped to run_id, never a global
// count, so one run's receipts can't satisfy another run's step.
func TestSinkEvidenceForStep_CountsTokensAndReceiptsScopedToRunAndTechnique(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		exp := time.Now().Add(time.Hour)

		seed := func(token, runID, technique string) {
			t.Helper()
			if _, err := pool.Exec(ctx,
				`INSERT INTO dlp_sink_tokens (token, run_id, technique_id, expires_at) VALUES ($1, $2, $3, $4)`,
				token, runID, technique, exp); err != nil {
				t.Fatal(err)
			}
		}
		receive := func(token string) {
			t.Helper()
			if _, err := pool.Exec(ctx, `INSERT INTO dlp_sink_receipts (token) VALUES ($1)`, token); err != nil {
				t.Fatal(err)
			}
		}

		seed("sink-tok-run-a", "sink-run-a", "T1567")
		receive("sink-tok-run-a")
		seed("sink-tok-run-b", "sink-run-b", "T1567") // other run: must not count for run a
		seed("sink-tok-run-a-other", "sink-run-a", "T1048")

		tokens, receipts, err := db.SinkEvidenceForStep(ctx, pool, "sink-run-a", "T1567")
		if err != nil {
			t.Fatal(err)
		}
		if tokens != 1 || receipts != 1 {
			t.Fatalf("run a / T1567: tokens=%d receipts=%d, want 1 and 1", tokens, receipts)
		}

		tokens, receipts, err = db.SinkEvidenceForStep(ctx, pool, "sink-run-b", "T1567")
		if err != nil {
			t.Fatal(err)
		}
		if tokens != 1 || receipts != 0 {
			t.Fatalf("run b / T1567: tokens=%d receipts=%d, want 1 and 0", tokens, receipts)
		}

		tokens, receipts, err = db.SinkEvidenceForStep(ctx, pool, "sink-run-c", "T1567")
		if err != nil {
			t.Fatal(err)
		}
		if tokens != 0 || receipts != 0 {
			t.Fatalf("unknown run: tokens=%d receipts=%d, want 0 and 0", tokens, receipts)
		}
	})
}
