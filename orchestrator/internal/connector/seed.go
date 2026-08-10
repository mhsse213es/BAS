package connector

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
)

// SeedConfig carries only the env-sourced values SeedFromEnv needs -- kept
// separate from config.Config so internal/connector doesn't gain a
// dependency on the config package just for this.
type SeedConfig struct {
	MISPUrl       string
	MISPApiKey    string
	OpenCTIUrl    string
	OpenCTIApiKey string
	OTXAPIKey     string
}

// SeedFromEnv writes each connector's env-sourced values into
// threat_intel_config exactly once -- only when that connector's row does
// not exist yet. Once seeded (or once created via the UI), the DB row is
// authoritative and this function never overwrites it again on a later
// boot, so an operator's UI-entered changes always win over a stale .env
// value that happens to still be set in the container's environment.
func SeedFromEnv(ctx context.Context, pool *pgxpool.Pool, cfg SeedConfig) error {
	seeds := []struct {
		connector string
		baseURL   string
		apiKey    string
	}{
		{"misp", cfg.MISPUrl, cfg.MISPApiKey},
		{"opencti", cfg.OpenCTIUrl, cfg.OpenCTIApiKey},
		{"otx", "", cfg.OTXAPIKey},
	}
	for _, s := range seeds {
		if s.apiKey == "" {
			continue // nothing to seed for this connector
		}
		if _, err := pool.Exec(ctx,
			`INSERT INTO threat_intel_config (connector, base_url, api_key, enabled, updated_at)
			 VALUES ($1, $2, $3, true, NOW())
			 ON CONFLICT (connector) DO NOTHING`,
			s.connector, s.baseURL, s.apiKey,
		); err != nil {
			return err
		}
	}
	return nil
}

// LoadSourcesFromDB builds the misp/opencti/otx Sources from whatever is
// currently enabled in threat_intel_config. Called once at startup (after
// SeedFromEnv has had a chance to populate the table) and again, indirectly,
// every time a config save triggers Scheduler.Reconfigure (Task 2) -- this
// is the one place that turns DB rows into live Source objects, so both
// callers stay in sync by construction.
func LoadSourcesFromDB(ctx context.Context, pool *pgxpool.Pool, sectors, regions []string) ([]Source, error) {
	rows, err := pool.Query(ctx, `SELECT connector, base_url, api_key FROM threat_intel_config WHERE enabled = true`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var sources []Source
	for rows.Next() {
		var conn, baseURL, apiKey string
		if err := rows.Scan(&conn, &baseURL, &apiKey); err != nil {
			return nil, err
		}
		switch conn {
		case "misp":
			if baseURL != "" && apiKey != "" {
				sources = append(sources, NewMISPClient(baseURL, apiKey, sectors, regions))
			}
		case "opencti":
			if baseURL != "" && apiKey != "" {
				sources = append(sources, NewOpenCTIClient(baseURL, apiKey, sectors))
			}
		case "otx":
			if apiKey != "" {
				sources = append(sources, NewOTXSource(apiKey))
			}
		}
	}
	return sources, rows.Err()
}
