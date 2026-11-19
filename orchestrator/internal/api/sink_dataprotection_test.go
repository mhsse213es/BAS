package api

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/rwevidence"
)

// sinkDataProtectionSource backs DataProtection with the DLP sink's own tables.
// A nil pool means no evidence store is configured, so it returns "" and the
// caller records SkipInsufficientEvidence instead of guessing a status.
func TestSinkDataProtectionSource_NilPoolIsNotGuessed(t *testing.T) {
	status, reason, err := sinkDataProtectionSource{pool: nil}.LookupDataProtection(
		context.Background(), rwevidence.AttemptKey{RunID: "r", TechniqueID: "T1567"})
	if err != nil {
		t.Fatal(err)
	}
	if status != "" || reason != "" {
		t.Fatalf("nil pool: got status=%q reason=%q, want both empty", status, reason)
	}
}

func TestSinkDataProtectionSource_ReceiptMeansNotDetected(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		exp := time.Now().Add(time.Hour)
		if _, err := pool.Exec(ctx,
			`INSERT INTO dlp_sink_tokens (token, run_id, technique_id, expires_at) VALUES ($1, $2, $3, $4)`,
			"dp-tok-received", "dp-run-received", "T1567", exp); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO dlp_sink_receipts (token) VALUES ($1)`, "dp-tok-received"); err != nil {
			t.Fatal(err)
		}

		status, _, err := sinkDataProtectionSource{pool: pool}.LookupDataProtection(ctx,
			rwevidence.AttemptKey{RunID: "dp-run-received", TechniqueID: "T1567"})
		if err != nil {
			t.Fatal(err)
		}
		if status != "NotDetected" {
			t.Fatalf("received payload: status=%q, want NotDetected", status)
		}
	})
}

func TestSinkDataProtectionSource_TokenWithoutReceiptIsUnknownNotBlocked(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		if _, err := pool.Exec(ctx,
			`INSERT INTO dlp_sink_tokens (token, run_id, technique_id, expires_at) VALUES ($1, $2, $3, $4)`,
			"dp-tok-silent", "dp-run-silent", "T1567", time.Now().Add(time.Hour)); err != nil {
			t.Fatal(err)
		}

		status, _, err := sinkDataProtectionSource{pool: pool}.LookupDataProtection(ctx,
			rwevidence.AttemptKey{RunID: "dp-run-silent", TechniqueID: "T1567"})
		if err != nil {
			t.Fatal(err)
		}
		if status != "Unknown" {
			t.Fatalf("silent sink: status=%q, want Unknown (no receipt is not proof of a block)", status)
		}
	})
}

// A probe that reached the sink while the payload did not is a block, so the
// adapter reports Detected. This is the only path to a Detected verdict.
func TestSinkDataProtectionSource_ProbeOnlyIsDetected(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		if _, err := pool.Exec(ctx,
			`INSERT INTO dlp_sink_tokens (token, run_id, technique_id, expires_at) VALUES ($1, $2, $3, $4)`,
			"dp-tok-probe", "dp-run-probe", "T1567", time.Now().Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO dlp_sink_receipts (token, channel) VALUES ($1, 'reachability')`, "dp-tok-probe"); err != nil {
			t.Fatal(err)
		}

		status, _, err := sinkDataProtectionSource{pool: pool}.LookupDataProtection(ctx,
			rwevidence.AttemptKey{RunID: "dp-run-probe", TechniqueID: "T1567"})
		if err != nil {
			t.Fatal(err)
		}
		if status != "Detected" {
			t.Fatalf("probe-only: status=%q, want Detected", status)
		}
	})
}
