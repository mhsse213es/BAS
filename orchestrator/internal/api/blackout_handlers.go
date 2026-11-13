package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/jobs"
)

// Change-freeze (blackout) windows for scheduled assessments.
//
//	GET    /api/scheduled-blackouts        list every window
//	POST   /api/scheduled-blackouts        create one (kind "once" or "daily"; see jobs.ValidateBlackout)
//	DELETE /api/scheduled-blackouts/{id}   remove one

type blackoutRequest struct {
	Name      string     `json:"name"`
	Kind      string     `json:"kind"`
	StartsAt  *time.Time `json:"startsAt,omitempty"`
	EndsAt    *time.Time `json:"endsAt,omitempty"`
	TimeFrom  string     `json:"timeFrom,omitempty"`
	TimeTo    string     `json:"timeTo,omitempty"`
	Timezone  string     `json:"timezone,omitempty"`
	ValidFrom string     `json:"validFrom,omitempty"`
	ValidTo   string     `json:"validTo,omitempty"`
}

// ListScheduledBlackouts answers GET /api/scheduled-blackouts.
func (h *Handler) ListScheduledBlackouts(w http.ResponseWriter, r *http.Request) {
	if h.jobsStore == nil {
		jsonError(w, "scheduler not available", http.StatusServiceUnavailable)
		return
	}
	windows, err := h.jobsStore.ListBlackouts(r.Context())
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respond(w, map[string]any{"blackouts": windows})
}

// CreateScheduledBlackout answers POST /api/scheduled-blackouts.
func (h *Handler) CreateScheduledBlackout(w http.ResponseWriter, r *http.Request) {
	if h.jobsStore == nil {
		jsonError(w, "scheduler not available", http.StatusServiceUnavailable)
		return
	}
	var req blackoutRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	actor := ""
	if claims, _ := auth.ClaimsFrom(r.Context()); claims != nil {
		actor = claims.UserID
	}
	created, err := h.jobsStore.CreateBlackout(r.Context(), jobs.Blackout{
		Name: req.Name, Kind: req.Kind, StartsAt: req.StartsAt, EndsAt: req.EndsAt,
		TimeFrom: req.TimeFrom, TimeTo: req.TimeTo, Timezone: req.Timezone,
		ValidFrom: req.ValidFrom, ValidTo: req.ValidTo, CreatedBy: actor,
	})
	if err != nil {
		if errors.Is(err, jobs.ErrInvalidBlackout) {
			jsonError(w, err.Error(), http.StatusBadRequest)
			return
		}
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.auditLog(r, "scheduled_blackout.create", created.ID, map[string]any{"name": created.Name, "kind": created.Kind}, "ok")
	w.WriteHeader(http.StatusCreated)
	respond(w, created)
}

// DeleteScheduledBlackout answers DELETE /api/scheduled-blackouts/{id}.
func (h *Handler) DeleteScheduledBlackout(w http.ResponseWriter, r *http.Request) {
	if h.jobsStore == nil {
		jsonError(w, "scheduler not available", http.StatusServiceUnavailable)
		return
	}
	id := chi.URLParam(r, "id")
	found, err := h.jobsStore.DeleteBlackout(r.Context(), id)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !found {
		jsonError(w, "blackout window not found", http.StatusNotFound)
		return
	}
	h.auditLog(r, "scheduled_blackout.delete", id, nil, "ok")
	respond(w, map[string]any{"id": id, "deleted": true})
}
