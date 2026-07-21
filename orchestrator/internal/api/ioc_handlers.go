package api

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/audspect/bas/internal/db"
)

// GetRunIOCs returns the indicators extracted from a run's results.
// GET /api/scenarios/runs/{runId}/iocs?type={ip|domain|url|hash|cve}&search={substring}
func (h *Handler) GetRunIOCs(w http.ResponseWriter, r *http.Request) {
	runID := chi.URLParam(r, "runId")
	typeFilter := r.URL.Query().Get("type")
	search := r.URL.Query().Get("search")

	indicators, err := db.GetRunIOCs(r.Context(), h.db, runID, typeFilter, search)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respond(w, indicators)
}
