package api

import (
	"encoding/json"
	"net/http"

	"github.com/audspect/bas/internal/reporting"
)

// GET /api/ti/readiness?agentId=&runId=
// Returns per-ATT&CK-group readiness scores derived from the most recent
// (or specified) run's TechniqueMatrix. No external API required — uses the
// bundled MITRE ATT&CK STIX enrichment. Groups with <3 tested techniques
// are excluded. Results sorted worst prevention readiness first.
func (h *Handler) GetTIReadiness(w http.ResponseWriter, r *http.Request) {
	if h.reportingEngine == nil {
		http.Error(w, "reporting engine not available", http.StatusServiceUnavailable)
		return
	}

	runID := r.URL.Query().Get("runId")
	agentID := r.URL.Query().Get("agentId")

	var matrix []reporting.TechniqueRow

	switch {
	case runID != "":
		rep, err := h.reportingEngine.BuildFromRun(r.Context(), runID, "")
		if err != nil {
			http.Error(w, "run not found", http.StatusNotFound)
			return
		}
		matrix = rep.TechniqueMatrix
	case agentID != "":
		rep, err := h.reportingEngine.Build(r.Context(), agentID, "")
		if err != nil {
			http.Error(w, "agent not found or no runs", http.StatusNotFound)
			return
		}
		matrix = rep.TechniqueMatrix
	default:
		http.Error(w, "agentId or runId required", http.StatusBadRequest)
		return
	}

	scores := reporting.BuildReadinessScores(matrix)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"scores": scores,
		"total":  len(scores),
	})
}
