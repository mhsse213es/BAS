package db_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/db"
)

func TestWriteADControlVerification_RoundTripAndUpsertNoDuplicate(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		runID := "test-run-dcsync"

		d := db.ADControlDecision{
			DRSUAPIResult: "access_denied",
			Corroboration: "unknown",
			Correlated:    true,
			Detail:        "EXEC T1003.006: refused as expected",
		}
		if err := db.WriteADControlVerification(ctx, pool, runID, "dcsync", "T1003.006", "T1003.006:negative", d); err != nil {
			t.Fatalf("first write: %v", err)
		}

		got, found, err := db.LatestADControlVerification(ctx, pool, "dcsync")
		if err != nil {
			t.Fatal(err)
		}
		if !found {
			t.Fatal("expected a stored verification to be found")
		}
		if got.DRSUAPIResult != "access_denied" {
			t.Fatalf("DRSUAPIResult = %q, want access_denied", got.DRSUAPIResult)
		}

		// Retry: same run+action -- must overwrite, not duplicate.
		d2 := db.ADControlDecision{DRSUAPIResult: "succeeded", Correlated: true, Detail: "updated"}
		if err := db.WriteADControlVerification(ctx, pool, runID, "dcsync", "T1003.006", "T1003.006:negative", d2); err != nil {
			t.Fatalf("retry write: %v", err)
		}
		got, found, err = db.LatestADControlVerification(ctx, pool, "dcsync")
		if err != nil {
			t.Fatal(err)
		}
		if !found || got.DRSUAPIResult != "succeeded" {
			t.Fatalf("after retry, got %+v found=%v, want updated row", got, found)
		}
	})
}

func TestLatestADControlVerification_NoRowsIsNotFoundNotError(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		_, found, err := db.LatestADControlVerification(context.Background(), pool, "primitive-with-no-evidence-ever")
		if err != nil {
			t.Fatal(err)
		}
		if found {
			t.Fatal("expected found=false when no verification has ever been written for this primitive")
		}
	})
}
