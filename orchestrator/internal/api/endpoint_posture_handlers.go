package api

import (
	"net/http"

	"github.com/audspect/bas/internal/analytics"
)

// GET /api/analytics/endpoint-posture — fleet-wide endpoint health: agent
// connectivity/lifecycle/binary-trust state plus current EPP isolation
// exposure. Viewer+.
func (h *Handler) GetEndpointPosture(w http.ResponseWriter, r *http.Request) {
	result, err := analytics.EndpointPosture(r.Context(), h.db)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respond(w, result)
}
