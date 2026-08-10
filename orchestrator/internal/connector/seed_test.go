package connector

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestSeedFromEnv_WritesRowWhenEmpty(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		err := SeedFromEnv(context.Background(), pool, SeedConfig{
			MISPUrl: "https://misp.example.com", MISPApiKey: "misp-key-1",
		})
		if err != nil {
			t.Fatalf("SeedFromEnv: %v", err)
		}
		var baseURL, apiKey string
		var enabled bool
		if err := pool.QueryRow(context.Background(),
			`SELECT base_url, api_key, enabled FROM threat_intel_config WHERE connector='misp'`,
		).Scan(&baseURL, &apiKey, &enabled); err != nil {
			t.Fatalf("query seeded row: %v", err)
		}
		if baseURL != "https://misp.example.com" || apiKey != "misp-key-1" || !enabled {
			t.Errorf("got baseURL=%q apiKey=%q enabled=%v, want the seeded values with enabled=true", baseURL, apiKey, enabled)
		}
	})
}

func TestSeedFromEnv_DoesNotOverwriteExistingRow(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		if _, err := pool.Exec(context.Background(),
			`INSERT INTO threat_intel_config (connector, base_url, api_key, enabled) VALUES ('misp', 'https://custom.example.com', 'custom-key', true)`,
		); err != nil {
			t.Fatalf("seed existing row: %v", err)
		}
		if err := SeedFromEnv(context.Background(), pool, SeedConfig{
			MISPUrl: "https://misp.example.com", MISPApiKey: "misp-key-1",
		}); err != nil {
			t.Fatalf("SeedFromEnv: %v", err)
		}
		var baseURL string
		if err := pool.QueryRow(context.Background(),
			`SELECT base_url FROM threat_intel_config WHERE connector='misp'`,
		).Scan(&baseURL); err != nil {
			t.Fatalf("query row: %v", err)
		}
		if baseURL != "https://custom.example.com" {
			t.Errorf("baseURL = %q, want unchanged %q — SeedFromEnv must never overwrite an already-configured row", baseURL, "https://custom.example.com")
		}
	})
}

func TestSeedFromEnv_SkipsConnectorWithNoEnvValue(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		if err := SeedFromEnv(context.Background(), pool, SeedConfig{}); err != nil {
			t.Fatalf("SeedFromEnv: %v", err)
		}
		var count int
		if err := pool.QueryRow(context.Background(),
			`SELECT count(*) FROM threat_intel_config`,
		).Scan(&count); err != nil {
			t.Fatalf("count rows: %v", err)
		}
		if count != 0 {
			t.Errorf("row count = %d, want 0 — no env values set means nothing should be seeded", count)
		}
	})
}

func TestSeedFromEnv_OTXHasNoBaseURL(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		if err := SeedFromEnv(context.Background(), pool, SeedConfig{OTXAPIKey: "otx-key-1"}); err != nil {
			t.Fatalf("SeedFromEnv: %v", err)
		}
		var baseURL, apiKey string
		var enabled bool
		if err := pool.QueryRow(context.Background(),
			`SELECT base_url, api_key, enabled FROM threat_intel_config WHERE connector='otx'`,
		).Scan(&baseURL, &apiKey, &enabled); err != nil {
			t.Fatalf("query row: %v", err)
		}
		if baseURL != "" || apiKey != "otx-key-1" || !enabled {
			t.Errorf("got baseURL=%q apiKey=%q enabled=%v, want baseURL empty, apiKey=otx-key-1, enabled=true", baseURL, apiKey, enabled)
		}
	})
}
