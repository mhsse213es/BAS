package api

import (
	"net/http"
	"sort"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/audspect/bas/internal/driftanalytics"
)

// GET /api/agents/{agentId}/checks/{checkId}/drift
// The core per-control view: drift/stability metrics for one control on
// one endpoint, pooled across every remediation request ever made for it.
// No history yet is a normal, common state (e.g. a control that's never
// opted into continuous validation) -- returns 200 with zero-value stats,
// not 404, since there's no authoritative list of valid pairs to 404
// against.
func (h *Handler) GetControlDrift(w http.ResponseWriter, r *http.Request) {
	agentID := chi.URLParam(r, "agentId")
	checkID := chi.URLParam(r, "checkId")
	outcomes, err := h.verificationOutcomesForPair(r.Context(), agentID, checkID)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	stats := driftanalytics.ComputeDriftStats(outcomes)
	respond(w, map[string]any{"driftStats": stats})
}

// checkDriftEntry is one control's drift stats within a per-agent summary.
type checkDriftEntry struct {
	CheckID string
	Stats   driftanalytics.DriftStats
}

// GET /api/agents/{agentId}/drift-summary
// Every control this agent has any verification history for, sorted
// least-stable first, plus an endpoint-level overall stability score
// (mean StabilityPercent across its controls).
func (h *Handler) GetAgentDriftSummary(w http.ResponseWriter, r *http.Request) {
	agentID := chi.URLParam(r, "agentId")
	grouped, err := h.verificationOutcomesByCheckForAgent(r.Context(), agentID)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	entries := make([]checkDriftEntry, 0, len(grouped))
	var stabilitySum float64
	for checkID, outcomes := range grouped {
		stats := driftanalytics.ComputeDriftStats(outcomes)
		entries = append(entries, checkDriftEntry{CheckID: checkID, Stats: stats})
		stabilitySum += stats.StabilityPercent
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Stats.StabilityPercent < entries[j].Stats.StabilityPercent })

	overall := 0.0
	if len(entries) > 0 {
		overall = stabilitySum / float64(len(entries))
	}
	respond(w, map[string]any{"overallStabilityPercent": overall, "checks": entries})
}

// controlDriftEntry is one control's drift stats within the fleet-wide report.
type controlDriftEntry struct {
	AgentID string
	CheckID string
	Stats   driftanalytics.DriftStats
}

// monthlyDriftBucket is the drift-event count for one calendar month.
type monthlyDriftBucket struct {
	Month      string // "2006-01" format
	DriftCount int
}

// GET /api/drift-reports/summary
// Fleet-wide: top-drifting controls, controls that never drifted, controls
// currently drifting within the last 7 days, and a monthly drift-event
// trend. Naming matches Sub-project 5's existing
// GET /api/remediation-reports/summary precedent.
func (h *Handler) GetFleetDriftReport(w http.ResponseWriter, r *http.Request) {
	grouped, err := h.verificationOutcomesByPairFleetWide(r.Context())
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	all := make([]controlDriftEntry, 0, len(grouped))
	monthCounts := map[string]int{}
	for key, outcomes := range grouped {
		stats := driftanalytics.ComputeDriftStats(outcomes)
		all = append(all, controlDriftEntry{AgentID: key.AgentID, CheckID: key.CheckID, Stats: stats})
		for _, ev := range stats.DriftEvents {
			monthCounts[ev.Format("2006-01")]++
		}
	}

	topDrifting := make([]controlDriftEntry, 0)
	neverDrifted := make([]controlDriftEntry, 0)
	driftingWithin7Days := make([]controlDriftEntry, 0)
	now := time.Now().UTC()
	for _, e := range all {
		if e.Stats.DriftCount > 0 {
			topDrifting = append(topDrifting, e)
		}
		if e.Stats.DriftCount == 0 && e.Stats.TotalRuns > 1 {
			neverDrifted = append(neverDrifted, e)
		}
		if e.Stats.CurrentStreakResult == "fail" && e.Stats.CurrentStreakStartedAt != nil && now.Sub(*e.Stats.CurrentStreakStartedAt) <= 7*24*time.Hour {
			driftingWithin7Days = append(driftingWithin7Days, e)
		}
	}
	sort.Slice(topDrifting, func(i, j int) bool { return topDrifting[i].Stats.DriftCount > topDrifting[j].Stats.DriftCount })

	months := make([]monthlyDriftBucket, 0, len(monthCounts))
	for m, c := range monthCounts {
		months = append(months, monthlyDriftBucket{Month: m, DriftCount: c})
	}
	sort.Slice(months, func(i, j int) bool { return months[i].Month < months[j].Month })

	respond(w, map[string]any{
		"topDrifting":         topDrifting,
		"neverDrifted":        neverDrifted,
		"driftingWithin7Days": driftingWithin7Days,
		"monthlyTrend":        months,
	})
}
