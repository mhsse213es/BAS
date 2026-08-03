package api

import (
	"net/http"
)

// GET /api/remediation-reports/summary
// Three independent percentages instead of one blended "remediation
// success" number: Applied and Configuration Verified share a denominator
// (total remediation_requests) since Sub-project 4's Completed status IS
// config-verified; BAS Validated has its own denominator (attempted
// technique_verification_runs only), never inflated by requests that were
// never eligible or never had verification requested.
func (h *Handler) RemediationReportSummary(w http.ResponseWriter, r *http.Request) {
	var totalRequests, completedRequests int
	h.db.QueryRow(r.Context(), `SELECT COUNT(*) FROM remediation_requests`).Scan(&totalRequests)
	h.db.QueryRow(r.Context(), `SELECT COUNT(*) FROM remediation_requests WHERE status='completed'`).Scan(&completedRequests)

	var totalTechRuns, passOrBlockedTechRuns int
	h.db.QueryRow(r.Context(), `SELECT COUNT(*) FROM technique_verification_runs WHERE status IN ('pass','fail','blocked','error','skipped')`).Scan(&totalTechRuns)
	h.db.QueryRow(r.Context(), `SELECT COUNT(*) FROM technique_verification_runs WHERE status IN ('pass','blocked')`).Scan(&passOrBlockedTechRuns)

	appliedPct := pctOf(completedRequests, totalRequests)
	basPct := pctOf(passOrBlockedTechRuns, totalTechRuns)

	respond(w, map[string]any{
		"remediationAppliedPct":    appliedPct,
		"configurationVerifiedPct": appliedPct, // Completed already IS config-verified, Sub-project 4
		"basValidatedPct":          basPct,
	})
}

func pctOf(n, total int) float64 {
	if total == 0 {
		return 0
	}
	return float64(n) / float64(total) * 100
}
