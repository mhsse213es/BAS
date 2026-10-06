package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"github.com/audspect/bas/internal/threatidentity"
)

// ListActorResolutions — GET /api/intel/actor-resolutions?status=unresolved&limit=100
// (TCF Phase 2 spec §3.4).
func (h *Handler) ListActorResolutions(w http.ResponseWriter, r *http.Request) {
	if h.db == nil {
		jsonError(w, "database unavailable", http.StatusServiceUnavailable)
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	items, err := threatidentity.NewStore(h.db).ListCandidates(r.Context(), r.URL.Query().Get("status"), limit)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respond(w, map[string]any{"items": items})
}

// DecideActorResolution — POST /api/intel/actor-resolutions/{id}
// {action: link|new|dismiss, actorId?, decisionReason}. Terminal; audited.
func (h *Handler) DecideActorResolution(w http.ResponseWriter, r *http.Request) {
	if h.db == nil {
		jsonError(w, "database unavailable", http.StatusServiceUnavailable)
		return
	}
	var req struct {
		Action         string `json:"action"`
		ActorID        string `json:"actorId"`
		DecisionReason string `json:"decisionReason"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&req); err != nil {
		jsonError(w, "body must be {action, actorId?, decisionReason}", http.StatusBadRequest)
		return
	}
	id := chi.URLParam(r, "id")
	c, err := threatidentity.NewStore(h.db).Decide(r.Context(), id, threatidentity.Action(req.Action), req.ActorID,
		req.DecisionReason, actorFor(r))
	switch {
	case errors.Is(err, threatidentity.ErrBadDecision):
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	case errors.Is(err, threatidentity.ErrCandidateNotFound):
		jsonError(w, err.Error(), http.StatusNotFound)
		return
	case errors.Is(err, threatidentity.ErrAlreadyDecided), errors.Is(err, threatidentity.ErrNameTaken):
		jsonError(w, err.Error(), http.StatusConflict)
		return
	case errors.Is(err, threatidentity.ErrActorNotFound):
		jsonError(w, err.Error(), http.StatusUnprocessableEntity)
		return
	case err != nil:
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.auditLog(r, "intel.actor_resolution.decide", id, map[string]any{
		"action": req.Action, "actorId": c.DecidedActorID, "reason": req.DecisionReason}, "ok")
	respond(w, c)
}
