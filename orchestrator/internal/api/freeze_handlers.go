package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/jobs"
)

// POST /api/agents/{agentId}/maintenance-freezes
// Admin-only: a freeze can silently block every remediation tier including
// ones an Analyst is normally allowed to run, making it a stronger action
// than executing a single remediation.
func (h *Handler) CreateAgentFreeze(w http.ResponseWriter, r *http.Request) {
	agentID := chi.URLParam(r, "agentId")
	var req struct {
		FromAt string `json:"fromAt"`
		ToAt   string `json:"toAt"`
		Reason string `json:"reason"`
	}
	if json.NewDecoder(r.Body).Decode(&req) != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	from, err := time.Parse(time.RFC3339, req.FromAt)
	if err != nil {
		jsonError(w, "fromAt must be RFC3339", http.StatusBadRequest)
		return
	}
	to, err := time.Parse(time.RFC3339, req.ToAt)
	if err != nil {
		jsonError(w, "toAt must be RFC3339", http.StatusBadRequest)
		return
	}
	if !to.After(from) {
		jsonError(w, "toAt must be after fromAt", http.StatusBadRequest)
		return
	}
	if h.jobsStore == nil {
		jsonError(w, "job engine not loaded", http.StatusServiceUnavailable)
		return
	}
	claims, _ := auth.ClaimsFrom(r.Context())
	actorID := ""
	if claims != nil {
		actorID = claims.UserID
	}
	f, err := h.jobsStore.CreateFreeze(r.Context(), jobs.AgentFreeze{
		AgentID: agentID, FromAt: from, ToAt: to, Reason: req.Reason, CreatedBy: actorID,
	})
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.auditLog(r, "jobs.freeze.create", f.ID, map[string]any{"agentId": agentID, "fromAt": req.FromAt, "toAt": req.ToAt}, "created")
	respond(w, map[string]any{"freezeId": f.ID})
}

// GET /api/agents/{agentId}/maintenance-freezes
func (h *Handler) ListAgentFreezes(w http.ResponseWriter, r *http.Request) {
	agentID := chi.URLParam(r, "agentId")
	if h.jobsStore == nil {
		jsonError(w, "job engine not loaded", http.StatusServiceUnavailable)
		return
	}
	freezes, err := h.jobsStore.ListFreezesForAgent(r.Context(), agentID)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respond(w, map[string]any{"freezes": freezes})
}

// DELETE /api/maintenance-freezes/{freezeId}
// Admin-only, same reasoning as create.
func (h *Handler) DeleteAgentFreeze(w http.ResponseWriter, r *http.Request) {
	freezeID := chi.URLParam(r, "freezeId")
	if h.jobsStore == nil {
		jsonError(w, "job engine not loaded", http.StatusServiceUnavailable)
		return
	}
	if err := h.jobsStore.DeleteFreeze(r.Context(), freezeID); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.auditLog(r, "jobs.freeze.delete", freezeID, nil, "deleted")
	respond(w, map[string]any{"freezeId": freezeID, "deleted": true})
}
