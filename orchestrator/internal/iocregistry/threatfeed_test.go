package iocregistry

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestRegisterFromThreatFeed_WritesSourceOriginStatus(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		id, err := RegisterFromThreatFeed(ctx, pool, TypeIP, "203.0.113.9", map[string]any{"stixId": "indicator--abc"})
		if err != nil {
			t.Fatalf("RegisterFromThreatFeed: %v", err)
		}
		if id == "" {
			t.Fatal("expected a non-empty ioc id")
		}
		var source, origin, status string
		if err := pool.QueryRow(ctx, `SELECT source, origin, status FROM iocs WHERE id = $1`, id).
			Scan(&source, &origin, &status); err != nil {
			t.Fatalf("query iocs row: %v", err)
		}
		if source != string(SourceThreatFeed) {
			t.Errorf("source = %q, want %q", source, SourceThreatFeed)
		}
		if origin != string(OriginThreatFeed) {
			t.Errorf("origin = %q, want %q", origin, OriginThreatFeed)
		}
		if status != string(StatusReported) {
			t.Errorf("status = %q, want %q", status, StatusReported)
		}
	})
}

func TestRegisterFromThreatFeed_RepeatCallBumpsSightingCount(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		id1, err := RegisterFromThreatFeed(ctx, pool, TypeDomain, "evil.example.com", nil)
		if err != nil {
			t.Fatalf("first RegisterFromThreatFeed: %v", err)
		}
		id2, err := RegisterFromThreatFeed(ctx, pool, TypeDomain, "evil.example.com", nil)
		if err != nil {
			t.Fatalf("second RegisterFromThreatFeed: %v", err)
		}
		if id1 != id2 {
			t.Fatalf("expected same ioc id on repeat, got %q then %q", id1, id2)
		}
		var count int
		if err := pool.QueryRow(ctx, `SELECT sighting_count FROM iocs WHERE id = $1`, id1).Scan(&count); err != nil {
			t.Fatalf("query sighting_count: %v", err)
		}
		if count != 2 {
			t.Errorf("sighting_count = %d, want 2", count)
		}
	})
}
