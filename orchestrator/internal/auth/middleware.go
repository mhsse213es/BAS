package auth

import (
	"context"
	"net/http"
	"strings"
)

type ctxClaimsKey struct{}

// Middleware validates the JWT on every request.
// Accepts the token from (in priority order):
//  1. HttpOnly cookie "bas_token" (browser sessions)
//  2. Authorization: Bearer <token> header (API / CLI clients)
func Middleware(secret string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tokenStr := tokenFromRequest(r)
			if tokenStr == "" {
				http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
				return
			}
			claims, err := ValidateToken(tokenStr, secret)
			if err != nil {
				http.Error(w, `{"error":"invalid token"}`, http.StatusUnauthorized)
				return
			}
			ctx := context.WithValue(r.Context(), ctxClaimsKey{}, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// TokenFromRequest extracts the JWT from cookie or Bearer header.
// Exported so WebSocket handlers can reuse it during the upgrade handshake.
func TokenFromRequest(r *http.Request) string {
	return tokenFromRequest(r)
}

func tokenFromRequest(r *http.Request) string {
	if cookie, err := r.Cookie("bas_token"); err == nil && cookie.Value != "" {
		return cookie.Value
	}
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		return strings.TrimPrefix(h, "Bearer ")
	}
	return ""
}

// RequirePlatformAdmin rejects requests from users who are not
// platform-admins. Platform-admin is an orthogonal flag (which tenant, or
// none) checked independently of role/permission — not a fourth RBAC tier.
func RequirePlatformAdmin() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, ok := ClaimsFrom(r.Context())
			if !ok || !claims.IsPlatformAdmin {
				http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// ClaimsFrom retrieves the validated JWT claims from a request context.
func ClaimsFrom(ctx context.Context) (*Claims, bool) {
	c, ok := ctx.Value(ctxClaimsKey{}).(*Claims)
	return c, ok
}

// ContextWithClaims returns a context carrying claims, retrievable via
// ClaimsFrom. Exported for tests that call a handler directly, bypassing
// Middleware's normal request-scoped context injection.
func ContextWithClaims(ctx context.Context, claims *Claims) context.Context {
	return context.WithValue(ctx, ctxClaimsKey{}, claims)
}
