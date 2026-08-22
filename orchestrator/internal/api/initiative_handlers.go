package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/initiatives"
)

// CreateInitiative creates a new Initiative in the active state.
// POST /api/initiatives  body: {name, description}
func (h *Handler) CreateInitiative(w http.ResponseWriter, r *http.Request) {
	if h.initiativesStore == nil {
		jsonError(w, "initiative layer not loaded", http.StatusServiceUnavailable)
		return
	}
	var req struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	if json.NewDecoder(r.Body).Decode(&req) != nil || req.Name == "" {
		jsonError(w, "name is required", http.StatusBadRequest)
		return
	}
	claims, _ := auth.ClaimsFrom(r.Context())
	actorID := ""
	if claims != nil {
		actorID = claims.UserID
	}
	it, err := h.initiativesStore.Create(r.Context(), req.Name, req.Description, actorID)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respond(w, map[string]any{"initiative": it})
}

// ListInitiatives lists every Initiative, optionally filtered by state.
// GET /api/initiatives?state=active|closed|archived
func (h *Handler) ListInitiatives(w http.ResponseWriter, r *http.Request) {
	if h.initiativesStore == nil {
		jsonError(w, "initiative layer not loaded", http.StatusServiceUnavailable)
		return
	}
	state := r.URL.Query().Get("state")
	list, err := h.initiativesStore.List(r.Context(), state)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respond(w, map[string]any{"initiatives": list})
}

// GetInitiative returns one Initiative plus its derived Progress and a
// lightweight list of member jobs (no target-level nesting).
// GET /api/initiatives/{initiativeId}
func (h *Handler) GetInitiative(w http.ResponseWriter, r *http.Request) {
	if h.initiativesStore == nil || h.jobsStore == nil {
		jsonError(w, "initiative layer not loaded", http.StatusServiceUnavailable)
		return
	}
	id := chi.URLParam(r, "initiativeId")
	it, err := h.initiativesStore.Get(r.Context(), id)
	if err != nil {
		jsonError(w, "initiative not found", http.StatusNotFound)
		return
	}
	progress, err := h.initiativesStore.ComputeProgress(r.Context(), id)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	rows, err := h.db.Query(r.Context(),
		`SELECT id, type, state, created_at, completed_at FROM jobs WHERE initiative_id=$1 ORDER BY created_at`, id)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	type jobSummary struct {
		ID          string     `json:"id"`
		Type        string     `json:"type"`
		State       string     `json:"state"`
		CreatedAt   time.Time  `json:"createdAt"`
		CompletedAt *time.Time `json:"completedAt,omitempty"`
	}
	var jobSummaries []jobSummary
	for rows.Next() {
		var js jobSummary
		if err := rows.Scan(&js.ID, &js.Type, &js.State, &js.CreatedAt, &js.CompletedAt); err != nil {
			jsonError(w, err.Error(), http.StatusInternalServerError)
			return
		}
		jobSummaries = append(jobSummaries, js)
	}
	respond(w, map[string]any{"initiative": it, "progress": progress, "jobs": jobSummaries})
}

// CloseInitiative moves an Initiative from active to closed.
// POST /api/initiatives/{initiativeId}/close
func (h *Handler) CloseInitiative(w http.ResponseWriter, r *http.Request) {
	if h.initiativesStore == nil {
		jsonError(w, "initiative layer not loaded", http.StatusServiceUnavailable)
		return
	}
	id := chi.URLParam(r, "initiativeId")
	it, err := h.initiativesStore.Close(r.Context(), id)
	if errors.Is(err, initiatives.ErrInvalidTransition) {
		jsonError(w, "initiative is not active", http.StatusConflict)
		return
	}
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.auditLog(r, "initiatives.closed", id, map[string]any{}, "ok")
	respond(w, map[string]any{"initiative": it})
}

// ArchiveInitiative moves an Initiative from closed to archived.
// POST /api/initiatives/{initiativeId}/archive
func (h *Handler) ArchiveInitiative(w http.ResponseWriter, r *http.Request) {
	if h.initiativesStore == nil {
		jsonError(w, "initiative layer not loaded", http.StatusServiceUnavailable)
		return
	}
	id := chi.URLParam(r, "initiativeId")
	it, err := h.initiativesStore.Archive(r.Context(), id)
	if errors.Is(err, initiatives.ErrInvalidTransition) {
		jsonError(w, "initiative is not closed", http.StatusConflict)
		return
	}
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.auditLog(r, "initiatives.archived", id, map[string]any{}, "ok")
	respond(w, map[string]any{"initiative": it})
}

// SetJobInitiative assigns, reassigns, or clears (initiativeId: "") a
// job's initiative membership. Assigning to a non-active initiative is
// rejected; detaching is always allowed regardless of the initiative's
// current state.
// PATCH /api/jobs/{jobId}/initiative  body: {initiativeId}
func (h *Handler) SetJobInitiative(w http.ResponseWriter, r *http.Request) {
	if h.initiativesStore == nil || h.jobsStore == nil {
		jsonError(w, "initiative layer not loaded", http.StatusServiceUnavailable)
		return
	}
	jobID := chi.URLParam(r, "jobId")
	var req struct {
		InitiativeID string `json:"initiativeId"`
	}
	if json.NewDecoder(r.Body).Decode(&req) != nil {
		jsonError(w, "invalid body", http.StatusBadRequest)
		return
	}

	previous, err := h.jobsStore.Get(r.Context(), jobID)
	if err != nil {
		jsonError(w, "job not found", http.StatusNotFound)
		return
	}

	if req.InitiativeID != "" {
		target, err := h.initiativesStore.Get(r.Context(), req.InitiativeID)
		if err != nil {
			jsonError(w, "initiative not found", http.StatusNotFound)
			return
		}
		if target.State != initiatives.StateActive {
			jsonError(w, "initiative is "+target.State+", not active", http.StatusConflict)
			return
		}
	}

	job, err := h.jobsStore.SetJobInitiative(r.Context(), jobID, req.InitiativeID)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if req.InitiativeID == "" {
		h.auditLog(r, "initiatives.job_detached", previous.InitiativeID, map[string]any{"jobId": jobID}, "ok")
	} else {
		h.auditLog(r, "initiatives.job_assigned", req.InitiativeID,
			map[string]any{"jobId": jobID, "previousInitiativeId": previous.InitiativeID}, "ok")
	}
	respond(w, map[string]any{"job": job})
}

// DeleteInitiative permanently removes an archived Initiative with no
// jobs still attached. Requires CanApproveRemediation (Admin-only) --
// unlike the other 5 Initiative endpoints, this one is genuinely
// destructive, matching the higher tier this codebase already uses for
// other destructive/high-trust actions (maintenance-freeze delete,
// notification-webhook write).
// DELETE /api/initiatives/{initiativeId}
func (h *Handler) DeleteInitiative(w http.ResponseWriter, r *http.Request) {
	if h.initiativesStore == nil {
		jsonError(w, "initiative layer not loaded", http.StatusServiceUnavailable)
		return
	}
	id := chi.URLParam(r, "initiativeId")
	err := h.initiativesStore.Delete(r.Context(), id)
	if errors.Is(err, initiatives.ErrHasJobs) {
		jsonError(w, "detach all jobs before deleting this initiative", http.StatusConflict)
		return
	}
	if errors.Is(err, initiatives.ErrInvalidTransition) {
		jsonError(w, "initiative is not archived", http.StatusConflict)
		return
	}
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.auditLog(r, "initiatives.deleted", id, map[string]any{}, "ok")
	respond(w, map[string]any{"deleted": true})
}
