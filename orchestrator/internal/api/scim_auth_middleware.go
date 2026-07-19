package api

import (
	"context"
	"net/http"
	"strings"
)

type ctxSCIMTenantKey struct{}

// scimAuth authenticates a SCIM request by its per-tenant bearer token,
// entirely outside the JWT/RBAC system — there is no user identity or
// role here, only a resolved tenant. A missing token, an unrecognized
// token, or a token belonging to a disabled config are all treated
// identically: 401, fail closed.
func (h *Handler) scimAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authz := r.Header.Get("Authorization")
		token := strings.TrimPrefix(authz, "Bearer ")
		if token == "" || !strings.HasPrefix(authz, "Bearer ") {
			scimErrorResponse(w, "missing or invalid bearer token", http.StatusUnauthorized)
			return
		}
		var tenantID string
		var enabled bool
		err := h.db.QueryRow(r.Context(),
			`SELECT tenant_id, enabled FROM scim_configs WHERE token_hash = $1`, hashSCIMToken(token),
		).Scan(&tenantID, &enabled)
		if err != nil || !enabled {
			scimErrorResponse(w, "invalid or disabled token", http.StatusUnauthorized)
			return
		}
		ctx := context.WithValue(r.Context(), ctxSCIMTenantKey{}, tenantID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// scimTenantFrom retrieves the tenant resolved by scimAuth.
func scimTenantFrom(ctx context.Context) (string, bool) {
	tid, ok := ctx.Value(ctxSCIMTenantKey{}).(string)
	return tid, ok
}
