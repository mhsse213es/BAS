package api

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/audspect/bas/internal/iocregistry"
)

// POST /api/iocs/{id}/suppress -- {"suppressed": true, "reason": "known lab tool"}.
// Admin-only (CanManageIOCs).
func (h *Handler) SetIOCSuppressed(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var body struct {
		Suppressed bool   `json:"suppressed"`
		Reason     string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	if err := iocregistry.SetSuppressed(r.Context(), h.db, id, body.Suppressed, body.Reason); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respond(w, map[string]any{"id": id, "suppressed": body.Suppressed, "reason": body.Reason})
}
