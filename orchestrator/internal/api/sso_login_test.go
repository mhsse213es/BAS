package api

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/auth"
)

// fakeOIDCProvider spins up a minimal local OIDC discovery + JWKS + token
// endpoint set, so the SSO login flow can be tested without a real IdP.
// Duplicated from internal/oidcauth's own test-only fake provider — Go test
// helpers in _test.go files aren't importable across packages, and this is
// the only cross-package test fixture the SSO slice needs, so a second
// small copy here is simpler than restructuring either package's tests.
type fakeOIDCProvider struct {
	server   *httptest.Server
	key      *rsa.PrivateKey
	email    string
	clientID string
}

func newFakeOIDCProvider(t *testing.T, clientID, email string) *fakeOIDCProvider {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	f := &fakeOIDCProvider{key: key, email: email, clientID: clientID}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", f.discovery)
	mux.HandleFunc("/jwks", f.jwks)
	mux.HandleFunc("/token", f.token)
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {})
	f.server = httptest.NewServer(mux)
	t.Cleanup(f.server.Close)
	return f
}

func (f *fakeOIDCProvider) discovery(w http.ResponseWriter, r *http.Request) {
	_ = json.NewEncoder(w).Encode(map[string]any{
		"issuer":                                f.server.URL,
		"authorization_endpoint":                f.server.URL + "/authorize",
		"token_endpoint":                        f.server.URL + "/token",
		"jwks_uri":                              f.server.URL + "/jwks",
		"id_token_signing_alg_values_supported": []string{"RS256"},
	})
}

func (f *fakeOIDCProvider) jwks(w http.ResponseWriter, r *http.Request) {
	pub := f.key.PublicKey
	_ = json.NewEncoder(w).Encode(map[string]any{
		"keys": []map[string]any{{
			"kty": "RSA",
			"kid": "test-key",
			"use": "sig",
			"alg": "RS256",
			"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
		}},
	})
}

func (f *fakeOIDCProvider) token(w http.ResponseWriter, r *http.Request) {
	claims := jwt.MapClaims{
		"iss":   f.server.URL,
		"sub":   "test-subject",
		"aud":   f.clientID,
		"email": f.email,
		"exp":   time.Now().Add(time.Hour).Unix(),
		"iat":   time.Now().Unix(),
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = "test-key"
	signed, err := tok.SignedString(f.key)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"access_token": "test-access-token",
		"id_token":     signed,
		"token_type":   "Bearer",
	})
}

func TestInitiateSSOLogin_UnknownTenantSlug404(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := ssoHandler(t, pool)
		req := httptest.NewRequest(http.MethodGet, "/login/no-such-tenant/sso", nil)
		req = withURLParam(req, "tenantSlug", "no-such-tenant")
		rec := httptest.NewRecorder()
		h.InitiateSSOLogin(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", rec.Code)
		}
	})
}

func TestInitiateSSOLogin_DisabledConfig404(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := ssoHandler(t, pool)
		if _, err := pool.Exec(t.Context(),
			`INSERT INTO sso_configs (tenant_id, issuer_url, client_id, client_secret, enabled) VALUES ('default','https://idp.example.com','c1','s1', false)`,
		); err != nil {
			t.Fatalf("seed: %v", err)
		}
		req := httptest.NewRequest(http.MethodGet, "/login/default/sso", nil)
		req = withURLParam(req, "tenantSlug", "default")
		rec := httptest.NewRecorder()
		h.InitiateSSOLogin(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404 (config disabled)", rec.Code)
		}
	})
}

func TestSSOCallback_JITProvisionsNewUserWithTenantDefaultRole(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		fake := newFakeOIDCProvider(t, "c1", "newhire@example.com")
		if _, err := pool.Exec(t.Context(),
			`INSERT INTO sso_configs (tenant_id, issuer_url, client_id, client_secret, default_role, enabled) VALUES ('default',$1,'c1','s1','analyst',true)`,
			fake.server.URL,
		); err != nil {
			t.Fatalf("seed: %v", err)
		}
		h := ssoHandler(t, pool)

		verifier := "test-verifier"
		state, err := auth.GenerateSSOState("default", verifier, testJWTSecret, 10*time.Minute)
		if err != nil {
			t.Fatalf("GenerateSSOState: %v", err)
		}
		req := httptest.NewRequest(http.MethodGet, "/api/auth/sso/callback?state="+state+"&code=any-code", nil)
		rec := httptest.NewRecorder()
		h.SSOCallback(rec, req)
		if rec.Code != http.StatusFound {
			t.Fatalf("SSOCallback status = %d, body=%s", rec.Code, rec.Body.String())
		}

		var role, authSource string
		var tenantID *string
		err = pool.QueryRow(t.Context(), `SELECT role, auth_source, tenant_id FROM users WHERE username = 'newhire@example.com'`).
			Scan(&role, &authSource, &tenantID)
		if err != nil {
			t.Fatalf("JIT-provisioned user not found: %v", err)
		}
		if role != "analyst" || authSource != "sso" || tenantID == nil || *tenantID != "default" {
			t.Errorf("role=%q authSource=%q tenantID=%v, want analyst/sso/default", role, authSource, tenantID)
		}

		var cookieSet bool
		for _, c := range rec.Result().Cookies() {
			if c.Name == "bas_token" && c.Value != "" {
				cookieSet = true
			}
		}
		if !cookieSet {
			t.Error("bas_token cookie was not set on successful SSO login")
		}
	})
}

func TestSSOCallback_LinksExistingUserByEmail(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		fake := newFakeOIDCProvider(t, "c1", "existing@example.com")
		if _, err := pool.Exec(t.Context(),
			`INSERT INTO sso_configs (tenant_id, issuer_url, client_id, client_secret, default_role, enabled) VALUES ('default',$1,'c1','s1','viewer',true)`,
			fake.server.URL,
		); err != nil {
			t.Fatalf("seed config: %v", err)
		}
		existingID := seedUser(t, pool, "existing@example.com", "some-local-password", "admin", true)
		h := ssoHandler(t, pool)

		verifier := "test-verifier"
		state, err := auth.GenerateSSOState("default", verifier, testJWTSecret, 10*time.Minute)
		if err != nil {
			t.Fatalf("GenerateSSOState: %v", err)
		}
		req := httptest.NewRequest(http.MethodGet, "/api/auth/sso/callback?state="+state+"&code=any-code", nil)
		rec := httptest.NewRecorder()
		h.SSOCallback(rec, req)
		if rec.Code != http.StatusFound {
			t.Fatalf("SSOCallback status = %d, body=%s", rec.Code, rec.Body.String())
		}

		var n int
		pool.QueryRow(t.Context(), `SELECT COUNT(*) FROM users WHERE username = 'existing@example.com'`).Scan(&n)
		if n != 1 {
			t.Fatalf("expected exactly 1 user row (linked, not duplicated), got %d", n)
		}
		var role string
		pool.QueryRow(t.Context(), `SELECT role FROM users WHERE id = $1`, existingID).Scan(&role)
		if role != "admin" {
			t.Errorf("linked user's role changed to %q, want unchanged admin", role)
		}
	})
}

func TestSSOCallback_WrongOrExpiredStateRejected(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := ssoHandler(t, pool)
		expired, err := auth.GenerateSSOState("default", "v", testJWTSecret, -time.Minute)
		if err != nil {
			t.Fatalf("GenerateSSOState: %v", err)
		}
		req := httptest.NewRequest(http.MethodGet, "/api/auth/sso/callback?state="+expired+"&code=any-code", nil)
		rec := httptest.NewRecorder()
		h.SSOCallback(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expired-state status = %d, want 400", rec.Code)
		}
	})
}
