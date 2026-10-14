package iocregistry

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestRegisterFromExternalIngest_WritesCustomerOriginObservedStatus(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		id, err := RegisterFromExternalIngest(ctx, pool, TypeIP, "203.0.113.9", map[string]any{"ruleTitle": "Suspicious PowerShell"})
		if err != nil {
			t.Fatalf("RegisterFromExternalIngest: %v", err)
		}
		if id == "" {
			t.Fatal("expected a non-empty ioc id")
		}
		var source, origin, status string
		if err := pool.QueryRow(ctx, `SELECT source, origin, status FROM iocs WHERE id = $1`, id).
			Scan(&source, &origin, &status); err != nil {
			t.Fatalf("select: %v", err)
		}
		if source != string(SourceCustomerDetection) || origin != string(OriginCustomer) || status != string(StatusObserved) {
			t.Fatalf("source/origin/status = %q/%q/%q, want %q/%q/%q", source, origin, status, SourceCustomerDetection, OriginCustomer, StatusObserved)
		}
	})
}

func TestRegisterFromExternalIngest_RepeatCallBumpsSightingCount(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		id1, err := RegisterFromExternalIngest(ctx, pool, TypeDomain, "evil.example.test", nil)
		if err != nil {
			t.Fatalf("first call: %v", err)
		}
		id2, err := RegisterFromExternalIngest(ctx, pool, TypeDomain, "evil.example.test", nil)
		if err != nil {
			t.Fatalf("second call: %v", err)
		}
		if id1 != id2 {
			t.Fatalf("ids = %q, %q, want the same row (dedup by type+value)", id1, id2)
		}
		var sightingCount int
		if err := pool.QueryRow(ctx, `SELECT sighting_count FROM iocs WHERE id = $1`, id1).Scan(&sightingCount); err != nil {
			t.Fatalf("select: %v", err)
		}
		if sightingCount != 2 {
			t.Fatalf("sighting_count = %d, want 2", sightingCount)
		}
	})
}
