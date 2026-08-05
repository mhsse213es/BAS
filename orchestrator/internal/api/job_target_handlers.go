package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"

	"github.com/audspect/bas/internal/notifications"
)

// AssignJobTarget assigns or clears a JobTarget's owner. An empty ownerId
// clears ownership; assigning a non-empty owner emits a Phase 7
// EventTargetAssigned notification so the new owner is alerted.
// POST /api/job-targets/{targetId}/assign  body: {ownerId}
func (h *Handler) AssignJobTarget(w http.ResponseWriter, r *http.Request) {
	if h.jobsStore == nil {
		jsonError(w, "job engine not loaded", http.StatusServiceUnavailable)
		return
	}
	targetID := chi.URLParam(r, "targetId")
	var req struct {
		OwnerID string `json:"ownerId"`
	}
	if json.NewDecoder(r.Body).Decode(&req) != nil {
		jsonError(w, "invalid body", http.StatusBadRequest)
		return
	}
	target, err := h.jobsStore.SetTargetOwner(r.Context(), targetID, req.OwnerID)
	if errors.Is(err, pgx.ErrNoRows) {
		jsonError(w, "job target not found", http.StatusNotFound)
		return
	}
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if req.OwnerID != "" && h.notifications != nil {
		h.notifications.Emit(r.Context(), notifications.Event{
			Type: notifications.EventTargetAssigned, JobID: target.JobID, TargetID: target.ID, AgentID: target.AgentID,
			Severity: notifications.SeverityInfo, Message: "assigned to " + req.OwnerID,
			Metadata: map[string]any{"ownerId": req.OwnerID},
		})
	}
	h.auditLog(r, "jobs.target_assigned", targetID, map[string]any{"ownerId": req.OwnerID}, "ok")
	respond(w, map[string]any{"target": target})
}

// GetJobTargetsByOwner lists every JobTarget assigned to ownerId, across
// every job, most-recently-assigned first. Optional state query param
// narrows to one TargetState value.
// GET /api/job-targets?ownerId=X&state=Y
func (h *Handler) GetJobTargetsByOwner(w http.ResponseWriter, r *http.Request) {
	if h.jobsStore == nil {
		jsonError(w, "job engine not loaded", http.StatusServiceUnavailable)
		return
	}
	ownerID := r.URL.Query().Get("ownerId")
	if ownerID == "" {
		jsonError(w, "ownerId is required", http.StatusBadRequest)
		return
	}
	state := r.URL.Query().Get("state")
	targets, err := h.jobsStore.ListTargetsByOwner(r.Context(), ownerID, state)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respond(w, map[string]any{"targets": targets})
}
