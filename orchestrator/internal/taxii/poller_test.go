package taxii

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestPollerSync_DiscoversPollsNormalizesAndRecordsResult(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mux := http.NewServeMux()
		mux.HandleFunc("/taxii2/", func(w http.ResponseWriter, r *http.Request) {
			json.NewEncoder(w).Encode(map[string]any{"default": "http://" + r.Host + "/api1", "api_roots": []string{"http://" + r.Host + "/api1"}})
		})
		mux.HandleFunc("/api1/collections/col-1/objects/", func(w http.ResponseWriter, r *http.Request) {
			json.NewEncoder(w).Encode(map[string]any{
				"more": false, "next": "",
				"objects": []map[string]any{{"id": "indicator--poller-1", "type": "indicator", "modified": "2026-01-01T00:00:00Z", "pattern": "[ipv4-addr:value = '198.51.100.5']", "pattern_type": "stix"}},
			})
		})
		srv := httptest.NewServer(mux)
		defer srv.Close()

		ctx := context.Background()
		store := NewStore(pool)
		cfg, err := store.Create(ctx, ConnectorConfig{Name: "PollerTest", ServerURL: srv.URL, CollectionID: "col-1", Enabled: true})
		if err != nil {
			t.Fatalf("create config: %v", err)
		}
		normalizer := NewNormalizer(pool, store)
		poller := NewPoller(cfg, store, normalizer)

		if err := poller.Sync(ctx); err != nil {
			t.Fatalf("Sync: %v", err)
		}

		got, err := store.Get(ctx, cfg.ID)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if got.LastPollStatus != "ok" || got.LastPollSummary.Processed != 1 || got.LastPollAt == nil {
			t.Fatalf("Get() after Sync = %+v", got)
		}
		var count int
		if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM iocs WHERE type='ip' AND value='198.51.100.5'`).Scan(&count); err != nil {
			t.Fatalf("query iocs: %v", err)
		}
		if count != 1 {
			t.Fatalf("expected 1 ioc row, got %d", count)
		}
	})
}

func TestPollerSync_RecordsErrorOnUnreachableServer(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		cfg, err := store.Create(ctx, ConnectorConfig{Name: "UnreachableTest", ServerURL: "http://127.0.0.1:1", CollectionID: "col-1", Enabled: true})
		if err != nil {
			t.Fatalf("create config: %v", err)
		}
		poller := NewPoller(cfg, store, NewNormalizer(pool, store))
		if err := poller.Sync(ctx); err == nil {
			t.Fatal("expected an error for an unreachable server")
		}
		got, err := store.Get(ctx, cfg.ID)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if got.LastPollStatus != "error" || got.LastError == "" {
			t.Fatalf("Get() after failed Sync = %+v", got)
		}
	})
}
