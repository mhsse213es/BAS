package api

import (
	"net/http"
	"strconv"

	"github.com/audspect/bas/internal/controlhealth"
)

// GetControlHealthSummary returns every control category's computed health,
// fleet-wide. Read-only (Viewer+), matching /api/compliance/frameworks and
// /api/attackpath/correlation's access convention.
// GET /api/controlhealth/summary?windowDays=30
func (h *Handler) GetControlHealthSummary(w http.ResponseWriter, r *http.Request) {
	if h.controlHealthMapper == nil {
		jsonError(w, "control health mapper not loaded", http.StatusServiceUnavailable)
		return
	}
	windowDays := 30
	if v := r.URL.Query().Get("windowDays"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			windowDays = n
		}
	}
	categories, err := controlhealth.ComputeSummary(r.Context(), h.db, h.controlHealthMapper, windowDays)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respond(w, map[string]any{"categories": categories})
}
