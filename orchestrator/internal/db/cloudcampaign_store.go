package db

import (
	"context"
	"fmt"
	"time"

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

// CloudCampaign is the grouping record for a multi-account cloud campaign.
// Deliberately minimal (see EnsureCloudCampaignSchema's own comment) --
// every scenario/graph/account concept lives on the child cloud_runs rows,
// not here.
type CloudCampaign struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	CreatedBy string    `json:"createdBy,omitempty"`
	CreatedAt time.Time `json:"createdAt"`
}

// InsertCloudCampaign writes a new cloud_campaigns row. The caller supplies
// c.ID already generated, matching cloud_runs' own convention of
// generating the ID in Go before insert.
func InsertCloudCampaign(ctx context.Context, pool *pgxpool.Pool, c *CloudCampaign) error {
	_, err := pool.Exec(ctx,
		`INSERT INTO cloud_campaigns (id, name, created_by) VALUES ($1,$2,$3)`,
		c.ID, c.Name, c.CreatedBy)
	if err != nil {
		return fmt.Errorf("cloud_campaigns: insert %s: %w", c.ID, err)
	}
	return nil
}

// GetCloudCampaign returns one cloud_campaigns row by id. A missing id
// returns an error satisfying errors.Is(err, pgx.ErrNoRows), matching
// GetCloudRun's own convention.
func GetCloudCampaign(ctx context.Context, pool *pgxpool.Pool, id string) (*CloudCampaign, error) {
	c := &CloudCampaign{}
	err := pool.QueryRow(ctx,
		`SELECT id, name, COALESCE(created_by, ''), created_at FROM cloud_campaigns WHERE id = $1`, id,
	).Scan(&c.ID, &c.Name, &c.CreatedBy, &c.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("cloud_campaigns: get %s: %w", id, err)
	}
	return c, nil
}

// ListCloudCampaigns returns up to limit cloud_campaigns rows, newest
// created_at first. Trusts its limit argument as-is -- clamping is the
// HTTP handler's job, matching ListCloudRuns' own split between layers.
func ListCloudCampaigns(ctx context.Context, pool *pgxpool.Pool, limit int) ([]*CloudCampaign, error) {
	rows, err := pool.Query(ctx,
		`SELECT id, name, COALESCE(created_by, ''), created_at FROM cloud_campaigns ORDER BY created_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("cloud_campaigns: list: %w", err)
	}
	defer rows.Close()
	var out []*CloudCampaign
	for rows.Next() {
		c := &CloudCampaign{}
		if err := rows.Scan(&c.ID, &c.Name, &c.CreatedBy, &c.CreatedAt); err != nil {
			return nil, fmt.Errorf("cloud_campaigns: list scan: %w", err)
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("cloud_campaigns: list rows: %w", err)
	}
	return out, nil
}
