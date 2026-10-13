package db

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

// EnsureCloudCampaignSchema creates the cloud_campaigns table -- the
// grouping record for a multi-account cloud campaign. Deliberately
// minimal: unlike cloud_runs, there is no scenario/mode/graph column here,
// since every one of those concepts lives per-child-run (cloud_runs),
// not shared across the whole campaign the way one on-prem campaign
// shares one scenario across all its agents.
func EnsureCloudCampaignSchema(ctx context.Context, pool *pgxpool.Pool) error {
	_, err := pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS cloud_campaigns (
			id         text        PRIMARY KEY DEFAULT gen_random_uuid()::text,
			name       text        NOT NULL,
			created_by text,
			created_at timestamptz NOT NULL DEFAULT NOW()
		)`)
	if err != nil {
		return fmt.Errorf("cloud_campaigns: ensure schema: %w", err)
	}
	return nil
}
