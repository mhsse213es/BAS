package api

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/rwefficacy"
)

// GetRansomwareEfficacy returns the run-level ransomware efficacy statement:
// per-dimension status (proven / partial / unproven / gap / not_applicable),
// per-attempt worst-case verdicts, and an overall that is never "evidenced"
// unless detection, containment and recovery are each fully proven.
func (h *Handler) GetRansomwareEfficacy(w http.ResponseWriter, r *http.Request) {
	runID := chi.URLParam(r, "runId")
	rows, err := db.RWCapabilityAttempts(r.Context(), h.db, runID)
	if err != nil {
		jsonError(w, "db error", http.StatusInternalServerError)
		return
	}
	jsonOK(w, rwefficacy.Build(rows))
}
