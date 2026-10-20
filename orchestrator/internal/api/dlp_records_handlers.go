package api

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/audspect/bas/internal/verifysync"
)

// ListRunDLPRecords returns the dlpreport records persisted for one run's DLP
// evaluations: one entry per (step, DLP expectation), in step order.
// GET /api/scenarios/runs/{runId}/dlp-records
func (h *Handler) ListRunDLPRecords(w http.ResponseWriter, r *http.Request) {
	if h.db == nil {
		jsonError(w, "database unavailable", http.StatusServiceUnavailable)
		return
	}
	runID := chi.URLParam(r, "runId")
	if _, ok := h.runScenario(r.Context(), runID); !ok {
		jsonError(w, "run or scenario not found", http.StatusNotFound)
		return
	}
	entries, err := verifysync.DLPRecordsForRun(r.Context(), h.db, runID)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jsonOK(w, entries)
}
