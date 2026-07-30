package analytics

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/detecteffectiveness"
)

// DetectionEffectiveness returns prevented/detectedOnly/missed analytics
// across recent scenario runs -- a thin pass-through to
// detecteffectiveness.Compute, the canonical definition
// (internal/detecteffectiveness/detecteffectiveness.go).
func DetectionEffectiveness(ctx context.Context, pool *pgxpool.Pool, scenarioID, agentID string, limit int) (detecteffectiveness.CoverageAnalytics, error) {
	return detecteffectiveness.Compute(ctx, pool, scenarioID, agentID, limit)
}
