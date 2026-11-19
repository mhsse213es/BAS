package api

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/cigate"
)

// SetCIGate wires the CI validation gate (REQ-057) once the lab and registry exist at startup.
func (h *Handler) SetCIGate(c *cigate.Handler) {
	if c != nil {
		c.SetAudit(func(r *http.Request, actor, action, resource string, detail map[string]any, outcome string) {
			if actor == "" {
				h.auditLog(r, action, resource, detail, outcome)
				return
			}
			h.auditLogAs(r, actor, action, resource, detail, outcome)
		})
	}
	h.ci = c
}

// ciRoute resolves the CI gate per request, so routes registered before startup finishes still answer, with 503 until
// the gate is wired.
func (h *Handler) ciRoute(pick func(*cigate.Handler) http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if h.ci == nil {
			jsonError(w, "CI validation is not configured", http.StatusServiceUnavailable)
			return
		}
		pick(h.ci)(w, r)
	}
}

// registerCIValidationRoutes mounts the CI routes outside the user-session group. A CI token opens these and only these.
func (h *Handler) registerCIValidationRoutes(r chi.Router) {
	r.Group(func(r chi.Router) {
		r.Use(func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				if h.ci == nil {
					jsonError(w, "CI validation is not configured", http.StatusServiceUnavailable)
					return
				}
				cigate.Auth(h.ci.Verify)(next).ServeHTTP(w, req)
			})
		})
		r.Post("/api/ci/validations", h.ciRoute(func(c *cigate.Handler) http.HandlerFunc { return c.StartValidation }))
		r.Get("/api/ci/validations/{runId}", h.ciRoute(func(c *cigate.Handler) http.HandlerFunc { return c.GetValidation }))
	})
}

// registerCITokenRoutes mounts token management. Call it inside the user-session group: only an admin with the
// permission can issue or revoke a CI token.
func (h *Handler) registerCITokenRoutes(r chi.Router) {
	perm := auth.RequirePermission(auth.CanManageCITokens)
	r.With(perm).Get("/api/ci-tokens", h.ciRoute(func(c *cigate.Handler) http.HandlerFunc { return c.ListTokens }))
	r.With(perm).Post("/api/ci-tokens", h.ciRoute(func(c *cigate.Handler) http.HandlerFunc { return c.CreateToken }))
	r.With(perm).Delete("/api/ci-tokens/{id}", h.ciRoute(func(c *cigate.Handler) http.HandlerFunc { return c.RevokeToken }))
}
