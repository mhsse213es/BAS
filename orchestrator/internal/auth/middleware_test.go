package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func nextThatRecordsClaims(t *testing.T, got **Claims) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, ok := ClaimsFrom(r.Context())
		if !ok {
			t.Error("next handler: expected claims in context, found none")
			return
		}
		*got = c
		w.WriteHeader(http.StatusOK)
	}
}

func TestMiddleware_NoToken(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	Middleware("secret")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next handler must not be called without a token")
	})).ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestMiddleware_CookieToken(t *testing.T) {
	tok, _ := GenerateToken("u1", RoleAnalyst, "secret", time.Hour)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "bas_token", Value: tok})
	var got *Claims
	rec := httptest.NewRecorder()
	Middleware("secret")(nextThatRecordsClaims(t, &got)).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got == nil || got.UserID != "u1" {
		t.Fatalf("claims = %+v", got)
	}
}

func TestMiddleware_BearerHeaderToken(t *testing.T) {
	tok, _ := GenerateToken("u2", RoleViewer, "secret", time.Hour)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	var got *Claims
	rec := httptest.NewRecorder()
	Middleware("secret")(nextThatRecordsClaims(t, &got)).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got == nil || got.UserID != "u2" {
		t.Fatalf("claims = %+v", got)
	}
}

func TestMiddleware_CookieTakesPriorityOverHeader(t *testing.T) {
	cookieTok, _ := GenerateToken("cookie-user", RoleAdmin, "secret", time.Hour)
	headerTok, _ := GenerateToken("header-user", RoleAdmin, "secret", time.Hour)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "bas_token", Value: cookieTok})
	req.Header.Set("Authorization", "Bearer "+headerTok)

	if got := TokenFromRequest(req); got != cookieTok {
		t.Fatalf("TokenFromRequest returned the header token, not the cookie token")
	}

	var got *Claims
	rec := httptest.NewRecorder()
	Middleware("secret")(nextThatRecordsClaims(t, &got)).ServeHTTP(rec, req)
	if got == nil || got.UserID != "cookie-user" {
		t.Fatalf("claims = %+v, want UserID=cookie-user (cookie must win)", got)
	}
}

func TestMiddleware_InvalidToken(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer not-a-real-token")
	rec := httptest.NewRecorder()
	Middleware("secret")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next handler must not be called with an invalid token")
	})).ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestRequireRole_AllowedRolePasses(t *testing.T) {
	tok, _ := GenerateToken("u1", RoleAdmin, "secret", time.Hour)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	called := false
	handler := Middleware("secret")(RequireRole(RoleAdmin, RoleAnalyst)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if !called || rec.Code != http.StatusOK {
		t.Fatalf("called=%v status=%d, want called=true status=200", called, rec.Code)
	}
}

func TestRequirePlatformAdmin_PlatformAdminPasses(t *testing.T) {
	tok, _ := GenerateTenantToken("pa-1", RoleAdmin, nil, true, "secret", time.Hour)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	called := false
	handler := Middleware("secret")(RequirePlatformAdmin()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if !called || rec.Code != http.StatusOK {
		t.Fatalf("called=%v status=%d, want called=true status=200", called, rec.Code)
	}
}

func TestRequirePlatformAdmin_TenantAdminForbidden(t *testing.T) {
	tenantID := "acme"
	tok, _ := GenerateTenantToken("ta-1", RoleAdmin, &tenantID, false, "secret", time.Hour)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	handler := Middleware("secret")(RequirePlatformAdmin()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next handler must not be called for a non-platform-admin, even with RoleAdmin")
	})))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
}

func TestRequireRole_DisallowedRoleForbidden(t *testing.T) {
	tok, _ := GenerateToken("u1", RoleViewer, "secret", time.Hour)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	handler := Middleware("secret")(RequireRole(RoleAdmin)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next handler must not be called for a disallowed role")
	})))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
}

func TestRequireRole_NoClaimsInContext_DenyByDefault(t *testing.T) {
	// RequireRole invoked directly, bypassing Middleware — simulates a
	// misconfigured route with no auth middleware in front of it. Must
	// deny, not panic.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	handler := RequireRole(RoleAdmin, RoleAnalyst, RoleViewer)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next handler must not be called with no claims in context")
	}))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (deny-by-default)", rec.Code)
	}
}

func TestClaimsFrom_Absent(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if _, ok := ClaimsFrom(req.Context()); ok {
		t.Fatal("expected ok=false for a context with no claims")
	}
}

// TestAuthorizationPrecedence pins the full authn-then-authz decision chain
// as an explicit invariant: anything that fails authentication returns 401
// and never reaches the role check; anything that authenticates but fails
// authorization returns 403.
func TestAuthorizationPrecedence(t *testing.T) {
	validAdmin, _ := GenerateToken("admin-1", RoleAdmin, "secret", time.Hour)
	validViewer, _ := GenerateToken("viewer-1", RoleViewer, "secret", time.Hour)
	expired, _ := GenerateToken("expired-1", RoleAdmin, "secret", -time.Hour)

	cases := []struct {
		name       string
		bearer     string // "" means no Authorization header at all
		wantStatus int
	}{
		{"anonymous — no token", "", http.StatusUnauthorized},
		{"malformed JWT", "not-a-jwt", http.StatusUnauthorized},
		{"expired JWT", expired, http.StatusUnauthorized},
		{"authenticated but wrong role", validViewer, http.StatusForbidden},
		{"authenticated, correct role", validAdmin, http.StatusOK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if tc.bearer != "" {
				req.Header.Set("Authorization", "Bearer "+tc.bearer)
			}
			handler := Middleware("secret")(RequireRole(RoleAdmin)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			})))
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d", rec.Code, tc.wantStatus)
			}
		})
	}
}
