package api

import (
	"net/http"

	"github.com/audspect/bas/internal/analytics"
)

// GET /api/analytics/iocs — IOC registry dashboard: most-detected,
// highest-bypass-rate, frequently-reused, longest-surviving. Viewer+.
func (h *Handler) GetIOCAnalytics(w http.ResponseWriter, r *http.Request) {
	result, err := analytics.IOCAnalytics(r.Context(), h.db, 10)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respond(w, result)
}
