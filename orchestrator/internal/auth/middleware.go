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

// RequireRole rejects requests from users whose role is not in the allowed list.
func RequireRole(roles ...Role) func(http.Handler) http.Handler {
	allowed := make(map[Role]bool, len(roles))
	for _, r := range roles {
		allowed[r] = true
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, ok := ClaimsFrom(r.Context())
			if !ok || !allowed[claims.Role] {
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
