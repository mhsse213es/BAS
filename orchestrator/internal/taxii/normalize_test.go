package taxii

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestIngest_ProcessesValidIndicator(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		cfg, err := store.Create(ctx, ConnectorConfig{Name: "IngestTest", ServerURL: "https://a.example"})
		if err != nil {
			t.Fatalf("create config: %v", err)
		}
		n := NewNormalizer(pool, store)
		objects := []json.RawMessage{
			json.RawMessage(`{"id":"indicator--1","type":"indicator","modified":"2026-01-01T00:00:00Z","pattern":"[ipv4-addr:value = '203.0.113.9']","pattern_type":"stix"}`),
		}
		sum, err := n.Ingest(ctx, cfg.ID, cfg.Name, objects)
		if err != nil {
			t.Fatalf("Ingest: %v", err)
		}
		if sum.Processed != 1 || sum.Skipped != 0 || sum.Malformed != 0 {
			t.Fatalf("Ingest() summary = %+v", sum)
		}
		var count int
		if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM iocs WHERE type='ip' AND value='203.0.113.9'`).Scan(&count); err != nil {
			t.Fatalf("query iocs: %v", err)
		}
		if count != 1 {
			t.Fatalf("expected exactly 1 ioc row, got %d", count)
		}
	})
}

func TestIngest_SkipsNonIndicatorAndCompositePattern(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		cfg, err := store.Create(ctx, ConnectorConfig{Name: "SkipTest", ServerURL: "https://a.example"})
		if err != nil {
			t.Fatalf("create config: %v", err)
		}
		n := NewNormalizer(pool, store)
		objects := []json.RawMessage{
			json.RawMessage(`{"id":"malware--1","type":"malware","modified":"2026-01-01T00:00:00Z"}`),
			json.RawMessage(`{"id":"indicator--2","type":"indicator","modified":"2026-01-01T00:00:00Z","pattern":"[ipv4-addr:value = '1.2.3.4' AND domain-name:value = 'x.example']","pattern_type":"stix"}`),
		}
		sum, err := n.Ingest(ctx, cfg.ID, cfg.Name, objects)
		if err != nil {
			t.Fatalf("Ingest: %v", err)
		}
		if sum.Skipped != 2 || sum.Processed != 0 {
			t.Fatalf("Ingest() summary = %+v, want Skipped=2 Processed=0", sum)
		}
	})
}

func TestIngest_MalformedJSONCounted(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		cfg, err := store.Create(ctx, ConnectorConfig{Name: "MalformedTest", ServerURL: "https://a.example"})
		if err != nil {
			t.Fatalf("create config: %v", err)
		}
		n := NewNormalizer(pool, store)
		objects := []json.RawMessage{json.RawMessage(`{not valid`)}
		sum, err := n.Ingest(ctx, cfg.ID, cfg.Name, objects)
		if err != nil {
			t.Fatalf("Ingest: %v", err)
		}
		if sum.Malformed != 1 {
			t.Fatalf("Ingest() summary = %+v, want Malformed=1", sum)
		}
	})
}

func TestIngest_IdempotentOnRepeatedIdenticalObject(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		cfg, err := store.Create(ctx, ConnectorConfig{Name: "IdemIngestTest", ServerURL: "https://a.example"})
		if err != nil {
			t.Fatalf("create config: %v", err)
		}
		n := NewNormalizer(pool, store)
		objects := []json.RawMessage{
			json.RawMessage(`{"id":"indicator--dup","type":"indicator","modified":"2026-01-01T00:00:00Z","pattern":"[domain-name:value = 'dup.example.com']","pattern_type":"stix"}`),
		}
		sum1, err := n.Ingest(ctx, cfg.ID, cfg.Name, objects)
		if err != nil {
			t.Fatalf("first Ingest: %v", err)
		}
		if sum1.Processed != 1 {
			t.Fatalf("first Ingest() = %+v, want Processed=1", sum1)
		}
		sum2, err := n.Ingest(ctx, cfg.ID, cfg.Name, objects)
		if err != nil {
			t.Fatalf("second Ingest: %v", err)
		}
		if sum2.Processed != 0 || sum2.Skipped != 0 || sum2.Malformed != 0 {
			t.Fatalf("second Ingest() = %+v, want all zero (already ingested)", sum2)
		}
		var count int
		if err := pool.QueryRow(ctx, `SELECT sighting_count FROM iocs WHERE type='domain' AND value='dup.example.com'`).Scan(&count); err != nil {
			t.Fatalf("query sighting_count: %v", err)
		}
		if count != 1 {
			t.Fatalf("sighting_count = %d, want 1 (second call was a true no-op, not a re-upsert)", count)
		}
	})
}
