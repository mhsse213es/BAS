package api

import (
	"encoding/json"
	"net/http"

	"github.com/audspect/bas/internal/iocregistry"
)

// POST /api/iocs/import -- {"entries":[{"type":"filename","value":"..."}]}. Admin-only
// (CanManageIOCs). Writes each entry as Origin=customer, Status=draft.
func (h *Handler) ImportIOCs(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Entries []iocregistry.ImportEntry `json:"entries"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	written, err := iocregistry.ImportManual(r.Context(), h.db, body.Entries)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respond(w, map[string]any{"written": written})
}
