// Package dashboard is the Phase 6 executive-dashboard aggregator: a thin
// consumer over internal/analytics (Risk, Exposure) reduced to a fleet-wide
// snapshot for a time-series view. It owns no computation and no DB tables
// itself -- internal/api's scheduler persists what Compute returns.
package dashboard

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/analytics"
)

// Snapshot is the fleet-wide posture at the moment Compute was called.
type Snapshot struct {
	AvgRiskScore      int `json:"avgRiskScore"`
	ExposureScore     int `json:"exposureScore"`
	DetectionCoverage int `json:"detectionCoverage"`
	AssetCount        int `json:"assetCount"`
}

// Compute builds today's fleet-wide snapshot. Nil-safe: an empty fleet (no
// runs, no assets) returns a zero-value Snapshot, never an error -- same
// convention as exposure.Build/pathcorrelation.Correlate. Delegates to
// internal/analytics for every value -- this function no longer owns any
// computation itself, matching the "dashboards are pure presentation"
// architecture (docs/superpowers/specs/2026-07-30-unified-analytics-layer-phase-a-design.md).
func Compute(ctx context.Context, pool *pgxpool.Pool) (Snapshot, error) {
	risk, err := analytics.FleetRisk(ctx, pool)
	if err != nil {
		return Snapshot{}, err
	}

	fe, err := analytics.BuildFleetExposure(ctx, pool)
	if err != nil {
		return Snapshot{}, err
	}
	expSummary := fe.AssetExposureSummary()
	corr := fe.Correlation()

	return Snapshot{
		AvgRiskScore:      risk.FleetAvgScore,
		ExposureScore:     expSummary.FleetAvgScore,
		DetectionCoverage: corr.Score,
		AssetCount:        len(expSummary.Assets),
	}, nil
}
