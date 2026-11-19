package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/audspect/bas/internal/advisory"
	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/contentregistry"
	"github.com/go-chi/chi/v5"
)

// WithAdvisoryStore attaches the advisory relevance store to the handler.
func (h *Handler) WithAdvisoryStore(s *advisory.Store) *Handler {
	h.advisories = s
	return h
}

type advisoryDecisionBody struct {
	Decision   string `json:"decision"`
	ReasonCode string `json:"reasonCode"`
	Note       string `json:"note"`
}

// DecideAdvisory records the first relevance decision for an advisory.
// POST /api/advisories/{id}/decision. The route requires
// advisory:relevance:decide. The decider is the authenticated user, never a
// value from the request body.
func (h *Handler) DecideAdvisory(w http.ResponseWriter, r *http.Request) {
	h.advisoryDecide(w, r, false)
}

// ReverseAdvisoryDecision records a superseding decision. The prior decision
// is kept. POST /api/advisories/{id}/reverse.
func (h *Handler) ReverseAdvisoryDecision(w http.ResponseWriter, r *http.Request) {
	h.advisoryDecide(w, r, true)
}

func (h *Handler) advisoryDecide(w http.ResponseWriter, r *http.Request, reverse bool) {
	if h.advisories == nil {
		jsonError(w, "advisory store unavailable", http.StatusServiceUnavailable)
		return
	}
	claims, ok := auth.ClaimsFrom(r.Context())
	if !ok || claims == nil || claims.UserID == "" {
		jsonError(w, "authentication required", http.StatusUnauthorized)
		return
	}
	var body advisoryDecisionBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	id := chi.URLParam(r, "id")
	if strings.TrimSpace(id) == "" {
		jsonError(w, "advisory id required", http.StatusBadRequest)
		return
	}
	code := contentregistry.ExclusionReason(body.ReasonCode)
	decidedBy := "user:" + claims.UserID

	var err error
	if reverse {
		err = h.advisories.Reverse(r.Context(), id, decidedBy, body.Decision, code, body.Note)
	} else {
		err = h.advisories.Decide(r.Context(), id, decidedBy, body.Decision, code, body.Note)
	}
	switch {
	case err == nil:
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"advisoryId": id, "decision": body.Decision, "decidedBy": decidedBy,
		})
	case errors.Is(err, advisory.ErrInvalidDecision):
		jsonError(w, err.Error(), http.StatusBadRequest)
	case errors.Is(err, advisory.ErrAlreadyDecided), errors.Is(err, advisory.ErrNoDecision):
		jsonError(w, err.Error(), http.StatusConflict)
	default:
		jsonError(w, "could not record decision", http.StatusInternalServerError)
	}
}
