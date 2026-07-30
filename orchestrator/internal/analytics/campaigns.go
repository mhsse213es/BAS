package analytics

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/campaign"
)

// Campaigns returns every campaign with its live rollup -- a thin pass-
// through to campaign.ListWithRollups, the newly-extracted canonical
// definition (internal/campaign/store.go).
func Campaigns(ctx context.Context, pool *pgxpool.Pool) ([]campaign.Rollup, error) {
	return campaign.ListWithRollups(ctx, pool)
}
