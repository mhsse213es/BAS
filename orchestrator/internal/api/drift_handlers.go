package api

import (
	"net/http"
	"sort"

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
