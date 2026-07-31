package iocregistry

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestImportManual_WritesEntriesWithCustomerOriginAndDraftStatus(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		entries := []ImportEntry{
			{Type: TypeFilename, Value: "customer-known-tool.exe"},
			{Type: TypeMutex, Value: `Global\customer-known-mutex`},
		}
		written, err := ImportManual(context.Background(), pool, entries)
		if err != nil {
			t.Fatalf("ImportManual: %v", err)
		}
		if written != 2 {
			t.Errorf("written = %d, want 2", written)
		}

		var count int
		if err := pool.QueryRow(context.Background(),
			`SELECT COUNT(*) FROM iocs WHERE origin = 'customer' AND status = 'draft'`).Scan(&count); err != nil {
			t.Fatalf("count: %v", err)
		}
		if count != 2 {
			t.Errorf("iocs with origin=customer status=draft = %d, want 2", count)
		}
	})
}

func TestImportManual_DedupesAgainstExistingRow(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		if _, err := upsertIOC(context.Background(), pool, TypeFilename, "already-exists.exe", SourceDetectionAlert, nil); err != nil {
			t.Fatalf("seed existing ioc: %v", err)
		}

		written, err := ImportManual(context.Background(), pool, []ImportEntry{
			{Type: TypeFilename, Value: "already-exists.exe"},
		})
		if err != nil {
			t.Fatalf("ImportManual: %v", err)
		}
		if written != 1 {
			t.Errorf("written = %d, want 1 (upsert still counts as written)", written)
		}

		var count int
		if err := pool.QueryRow(context.Background(),
			`SELECT COUNT(*) FROM iocs WHERE type = 'filename' AND value = 'already-exists.exe'`).Scan(&count); err != nil {
			t.Fatalf("count: %v", err)
		}
		if count != 1 {
			t.Errorf("iocs rows for the same value = %d, want 1 (dedup, no duplicate row)", count)
		}
	})
}
