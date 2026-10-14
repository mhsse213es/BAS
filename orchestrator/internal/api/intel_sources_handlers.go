package api

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/audspect/bas/internal/evidence"
)

// SetSourceTrust -- POST /api/intel/sources/{id}/trust
// {trustState: trusted|untrusted, reason}. Admin-only, audited (spec §5.1).
func (h *Handler) SetSourceTrust(w http.ResponseWriter, r *http.Request) {
	if h.db == nil {
		jsonError(w, "database unavailable", http.StatusServiceUnavailable)
		return
	}
	var req struct {
		TrustState string `json:"trustState"`
		Reason     string `json:"reason"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&req); err != nil {
		jsonError(w, "body must be {trustState, reason}", http.StatusBadRequest)
		return
	}
	if req.TrustState != "trusted" && req.TrustState != "untrusted" {
		jsonError(w, `trustState must be "trusted" or "untrusted"`, http.StatusBadRequest)
		return
	}
	if req.Reason == "" {
		jsonError(w, "reason is required", http.StatusBadRequest)
		return
	}
	id := chi.URLParam(r, "id")
	store := evidence.NewStore(h.db)
	if err := store.SetTrust(r.Context(), id, evidence.TrustState(req.TrustState), actorFor(r), req.Reason); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.auditLog(r, "intel.source.set_trust", id, map[string]any{
		"trustState": req.TrustState, "reason": req.Reason}, "ok")
	respond(w, map[string]any{"sourceId": id, "trustState": req.TrustState})
}
