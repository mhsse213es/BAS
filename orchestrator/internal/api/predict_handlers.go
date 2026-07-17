package api

import (
	"net/http"

	"github.com/audspect/bas/internal/predict"
)

// GetPredictRisk returns the fleet risk-score forecast and open-finding
// exposure windows — Phase 6. Read-only (Viewer+). A young or empty fleet
// returns a well-formed Prediction whose sub-structs report their own
// insufficiency, never an error.
// GET /api/predict/risk
func (h *Handler) GetPredictRisk(w http.ResponseWriter, r *http.Request) {
	p, err := predict.Build(r.Context(), h.db)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respond(w, p)
}
