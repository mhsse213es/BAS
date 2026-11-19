package db_test

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/db"
)

// SinkEvidenceForStep counts the sink tokens issued for one run and technique,
// and separately the tokens with a data receipt and with a reachability-probe
// receipt. It is scoped to run_id, so another run's receipts never satisfy
// this step, and a probe is never counted as data.
func TestSinkEvidenceForStep_SplitsDataAndProbeReceiptsScopedToRunAndTechnique(t *testing.T) {
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
		receive := func(token, channel string) {
			t.Helper()
			if _, err := pool.Exec(ctx, `INSERT INTO dlp_sink_receipts (token, channel) VALUES ($1, $2)`, token, channel); err != nil {
				t.Fatal(err)
			}
		}

		// run a: data receipt. run b: probe receipt only. Other technique on run a: must not count.
		seed("sink-tok-run-a", "sink-run-a", "T1567")
		receive("sink-tok-run-a", "https-post")
		seed("sink-tok-run-b", "sink-run-b", "T1567")
		receive("sink-tok-run-b", "reachability")
		seed("sink-tok-run-a-other", "sink-run-a", "T1048")

		tokens, data, probe, err := db.SinkEvidenceForStep(ctx, pool, "sink-run-a", "T1567")
		if err != nil {
			t.Fatal(err)
		}
		if tokens != 1 || data != 1 || probe != 0 {
			t.Fatalf("run a / T1567: tokens=%d data=%d probe=%d, want 1 1 0", tokens, data, probe)
		}

		tokens, data, probe, err = db.SinkEvidenceForStep(ctx, pool, "sink-run-b", "T1567")
		if err != nil {
			t.Fatal(err)
		}
		if tokens != 1 || data != 0 || probe != 1 {
			t.Fatalf("run b / T1567: tokens=%d data=%d probe=%d, want 1 0 1", tokens, data, probe)
		}

		tokens, data, probe, err = db.SinkEvidenceForStep(ctx, pool, "sink-run-c", "T1567")
		if err != nil {
			t.Fatal(err)
		}
		if tokens != 0 || data != 0 || probe != 0 {
			t.Fatalf("unknown run: tokens=%d data=%d probe=%d, want 0 0 0", tokens, data, probe)
		}
	})
}
