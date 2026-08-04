package api

import (
	"net/http"

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
