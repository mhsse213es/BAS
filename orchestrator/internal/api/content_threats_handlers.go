package api

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"github.com/audspect/bas/internal/contentregistry"
)

// LinkContentThreat -- POST /api/content/{contentId}/versions/{n}/threats
// {threatId, reason}. Admin-only, audited (spec §9.3).
func (h *Handler) LinkContentThreat(w http.ResponseWriter, r *http.Request) {
	reg, ok := h.registry(w)
	if !ok {
		return
	}
	version, err := strconv.Atoi(chi.URLParam(r, "n"))
	if err != nil {
		jsonError(w, "version must be an integer", http.StatusBadRequest)
		return
	}
	var req struct {
		ThreatID string `json:"threatId"`
		Reason   string `json:"reason"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&req); err != nil || req.ThreatID == "" || req.Reason == "" {
		jsonError(w, "body must be {threatId, reason}", http.StatusBadRequest)
		return
	}
	contentID := chi.URLParam(r, "contentId")
	err = reg.LinkThreat(r.Context(), contentID, version, req.ThreatID, actorFor(r), req.Reason)
	switch {
	case err == contentregistry.ErrVersionNotFound:
		jsonError(w, "content version not found", http.StatusNotFound)
		return
	case err == contentregistry.ErrThreatNotFound:
		jsonError(w, "threat not found", http.StatusNotFound)
		return
	case err != nil:
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.auditLog(r, "content_registry.link_threat", contentID, map[string]any{
		"version": version, "threatId": req.ThreatID, "reason": req.Reason}, "ok")
	respond(w, map[string]any{"contentId": contentID, "version": version, "threatId": req.ThreatID})
}
