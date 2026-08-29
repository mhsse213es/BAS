package api

import (
	"net/http"
	"time"

	"github.com/audspect/bas/internal/slapolicy"
	"github.com/audspect/bas/internal/slareport"
)

// GetSLAReport returns the fleet-wide SLA compliance report: overall and
// per-severity stats, a monthly trend, and a bounded recently-resolved
// history. GET /api/sla/report
func (h *Handler) GetSLAReport(w http.ResponseWriter, r *http.Request) {
	rows, err := h.db.Query(r.Context(),
		`SELECT severity_at_start, deadline_at, status, resolved_at FROM finding_slas`)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var episodes []slareport.Episode
	for rows.Next() {
		var e slareport.Episode
		if rows.Scan(&e.Severity, &e.DeadlineAt, &e.Status, &e.ResolvedAt) != nil {
			continue
		}
		episodes = append(episodes, e)
	}
	rows.Close()
	report := slareport.ComputeReport(episodes)

	recentRows, err := h.db.Query(r.Context(),
		`SELECT pf.agent_id, pf.check_id, fs.severity_at_start, fs.started_at, fs.resolved_at, fs.deadline_at
		   FROM finding_slas fs
		   JOIN posture_findings pf ON pf.id = fs.posture_finding_id
		  WHERE fs.status = 'resolved'
		  ORDER BY fs.resolved_at DESC LIMIT 50`)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer recentRows.Close()
	recentlyResolved := []map[string]any{}
	for recentRows.Next() {
		var agentID, checkID, severity string
		var startedAt, resolvedAt, deadlineAt time.Time
		if recentRows.Scan(&agentID, &checkID, &severity, &startedAt, &resolvedAt, &deadlineAt) != nil {
			continue
		}
		recentlyResolved = append(recentlyResolved, map[string]any{
			"agentId": agentID, "checkId": checkID, "severity": severity,
			"startedAt": startedAt, "resolvedAt": resolvedAt, "deadlineAt": deadlineAt,
			"onTime": !slapolicy.EvaluateSLABreach(deadlineAt, resolvedAt),
		})
	}

	respond(w, map[string]any{
		"overall":          statsToMap(report.Overall),
		"bySeverity":       severityStatsToMaps(report.BySeverity),
		"monthlyTrend":     monthStatsToMaps(report.MonthlyTrend),
		"recentlyResolved": recentlyResolved,
	})
}

func statsToMap(s slareport.Stats) map[string]any {
	return map[string]any{
		"totalEpisodes": s.TotalEpisodes, "onTime": s.OnTime, "late": s.Late,
		"currentlyOpen": s.CurrentlyOpen, "complianceRate": s.ComplianceRate,
	}
}

func severityStatsToMaps(stats []slareport.Stats) []map[string]any {
	out := make([]map[string]any, 0, len(stats))
	for _, s := range stats {
		m := statsToMap(s)
		m["severity"] = s.Severity
		out = append(out, m)
	}
	return out
}

func monthStatsToMaps(stats []slareport.MonthStats) []map[string]any {
	out := make([]map[string]any, 0, len(stats))
	for _, m := range stats {
		out = append(out, map[string]any{
			"month": m.Month, "resolved": m.Resolved, "onTime": m.OnTime, "complianceRate": m.ComplianceRate,
		})
	}
	return out
}
