// Package analytics is the canonical facade every dashboard view calls for
// fleet-wide metrics -- Risk, Compliance, Campaigns, Exposure (this
// sub-project), Detection/Threat Intel/Endpoint Posture (later
// sub-projects). Each category's actual computation stays in its own
// existing domain package; this package orchestrates, it does not
// reimplement. See docs/superpowers/specs/2026-07-30-unified-analytics-layer-phase-a-design.md.
package analytics

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
)

// RiskResult is the fleet-wide risk score.
type RiskResult struct {
	FleetAvgScore int `json:"fleetAvgScore"`
}

// FleetRisk returns the fleet-wide average risk score across completed runs
// in the last 30 days -- the sole definition (moved verbatim from
// internal/dashboard's former private avgRiskScore; that function is
// deleted in Task 6, not duplicated).
func FleetRisk(ctx context.Context, pool *pgxpool.Pool) (RiskResult, error) {
	var avg int
	err := pool.QueryRow(ctx, `
		SELECT COALESCE(ROUND(AVG((score->>'riskScore')::numeric)), 0)::int
		FROM scenario_runs
		WHERE completed_at IS NOT NULL
		  AND completed_at > NOW() - INTERVAL '30 days'
		  AND score IS NOT NULL`).Scan(&avg)
	return RiskResult{FleetAvgScore: avg}, err
}
