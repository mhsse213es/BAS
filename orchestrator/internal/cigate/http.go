package cigate

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/audspect/bas/internal/auth"
)

type ctxCIKey struct{}

// Verifier checks a presented CI token. Store.Verify satisfies it.
type Verifier func(ctx context.Context, token string) (TokenInfo, error)

// Auth accepts only CI tokens on the routes it guards. A user session JWT is refused here on purpose, so a CI pipeline
// never gets the access of a user.
func Auth(verify Verifier) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h := r.Header.Get("Authorization")
			tok := strings.TrimPrefix(h, "Bearer ")
			if !strings.HasPrefix(h, "Bearer ") || !IsCIToken(tok) {
				writeErr(w, http.StatusUnauthorized, "a CI token is required")
				return
			}
			info, err := verify(r.Context(), tok)
			if err != nil {
				writeErr(w, http.StatusUnauthorized, "invalid or revoked CI token")
				return
			}
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxCIKey{}, info)))
		})
	}
}

// AuditFunc records one audit event. The API supplies it so cigate does not depend on the API package. actor is
// the audit actor id ("" means: take it from the request's user session).
type AuditFunc func(r *http.Request, actor, action, resource string, detail map[string]any, outcome string)

// Handler serves the CI routes and the token management routes.
type Handler struct {
	svc   *Service
	store *Store
	audit AuditFunc
}

func NewHandler(svc *Service, store *Store) *Handler { return &Handler{svc: svc, store: store} }

// SetAudit wires audit logging. Without it the handlers still work and record nothing.
func (h *Handler) SetAudit(f AuditFunc) { h.audit = f }

func (h *Handler) record(r *http.Request, actor, action, resource string, detail map[string]any, outcome string) {
	if h.audit != nil {
		h.audit(r, actor, action, resource, detail, outcome)
	}
}

// ciActor is the audit actor for a request that cleared CI auth: the token, never a user.
func ciActor(r *http.Request) (actor, tokenName string) {
	if t, ok := r.Context().Value(ctxCIKey{}).(TokenInfo); ok {
		return "ci:" + t.ID, t.Name
	}
	return "ci:unknown", ""
}

// Verify checks a presented CI token against the store. It is the Verifier the API wires into the CI routes.
func (h *Handler) Verify(ctx context.Context, token string) (TokenInfo, error) {
	return h.store.Verify(ctx, token)
}

const maxStartBody = 4 << 10

// StartValidation handles POST /api/ci/validations {"contentId": "..."}. 202 with a run id on success.
func (h *Handler) StartValidation(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ContentID string `json:"contentId"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxStartBody)).Decode(&body); err != nil || body.ContentID == "" {
		writeErr(w, http.StatusBadRequest, `body must be {"contentId": "<registered content id>"}`)
		return
	}
	runID, err := h.svc.Start(r.Context(), body.ContentID)
	var refused *RefusedError
	actor, tokenName := ciActor(r)
	detail := map[string]any{"contentId": body.ContentID, "token": tokenName}
	switch {
	case err == nil:
		detail["runId"] = runID
		h.record(r, actor, "ci.validation_started", runID, detail, "ok")
		writeJSON(w, http.StatusAccepted, map[string]string{
			"runId":     runID,
			"statusUrl": "/api/ci/validations/" + runID,
		})
	case errors.Is(err, ErrNoLab):
		writeErr(w, http.StatusServiceUnavailable, err.Error())
	case errors.Is(err, ErrUnknownContent):
		writeErr(w, http.StatusNotFound, err.Error())
	case errors.As(err, &refused):
		detail["reason"] = refused.Reason
		h.record(r, actor, "ci.validation_refused", body.ContentID, detail, "refused")
		writeJSON(w, http.StatusConflict, map[string]string{"error": "validation refused, retry later", "reason": refused.Reason})
	default:
		writeErr(w, http.StatusInternalServerError, "validation could not be started")
	}
}

// GetValidation handles GET /api/ci/validations/{runId}.
func (h *Handler) GetValidation(w http.ResponseWriter, r *http.Request) {
	st, err := h.svc.Status(r.Context(), chi.URLParam(r, "runId"))
	switch {
	case err == nil:
		writeJSON(w, http.StatusOK, st)
	case errors.Is(err, ErrNoRun):
		writeErr(w, http.StatusNotFound, err.Error())
	default:
		writeErr(w, http.StatusInternalServerError, "status could not be read")
	}
}

// ListTokens handles GET /api/ci-tokens. Secrets are never returned.
func (h *Handler) ListTokens(w http.ResponseWriter, r *http.Request) {
	list, err := h.store.List(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "tokens could not be listed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"tokens": list})
}

// CreateToken handles POST /api/ci-tokens {"name": "..."}. The token is returned once, here, and never again.
func (h *Handler) CreateToken(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxStartBody)).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "body must be JSON with a name")
		return
	}
	name := strings.TrimSpace(body.Name)
	if name == "" || len(name) > 80 {
		writeErr(w, http.StatusBadRequest, "name must be 1 to 80 characters")
		return
	}
	actor := ""
	if c, ok := auth.ClaimsFrom(r.Context()); ok {
		actor = c.UserID
	}
	token, info, err := h.store.Create(r.Context(), name, actor)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "token could not be created")
		return
	}
	h.record(r, "", "ci.token_created", info.ID, map[string]any{"name": info.Name}, "ok")
	writeJSON(w, http.StatusCreated, map[string]any{"token": token, "info": info})
}

// RevokeToken handles DELETE /api/ci-tokens/{id}.
func (h *Handler) RevokeToken(w http.ResponseWriter, r *http.Request) {
	err := h.store.Revoke(r.Context(), chi.URLParam(r, "id"))
	switch {
	case err == nil:
		h.record(r, "", "ci.token_revoked", chi.URLParam(r, "id"), nil, "ok")
		writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
	case errors.Is(err, ErrNoToken):
		writeErr(w, http.StatusNotFound, "no active token with that id")
	default:
		writeErr(w, http.StatusInternalServerError, "token could not be revoked")
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}
