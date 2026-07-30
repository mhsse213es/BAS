package analytics

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/db"
)

// Compliance returns the latest persisted compliance_snapshots rows --
// fleet-wide (the lowest-compliance agent's row per framework, matching
// db.GetFleetComplianceScores' own ORDER BY compliance_pct ASC) when
// agentID is "", or that agent's own per-framework rows otherwise. Thin
// pass-through -- both underlying queries already exist and are already
// what GetComplianceDashboardScores (internal/api/handlers.go:4164) calls
// today; this gives that same logic a name outside internal/api.
func Compliance(ctx context.Context, pool *pgxpool.Pool, agentID string) ([]db.ComplianceSnapshot, error) {
	if agentID != "" {
		return db.GetComplianceScores(ctx, pool, agentID)
	}
	return db.GetFleetComplianceScores(ctx, pool)
}
