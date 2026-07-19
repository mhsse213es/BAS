package api

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/oidcauth"
)

// ssoRedirectURL derives this server's externally-reachable callback URL
// from the incoming request — no separate config surface needed. Honors
// X-Forwarded-Proto for deployments behind a reverse proxy.
func ssoRedirectURL(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}
	return scheme + "://" + r.Host + "/api/auth/sso/callback"
}

// InitiateSSOLogin redirects the browser to the tenant's IdP to start an
// OIDC Authorization Code + PKCE flow.
// GET /login/{tenantSlug}/sso
func (h *Handler) InitiateSSOLogin(w http.ResponseWriter, r *http.Request) {
	slug := chi.URLParam(r, "tenantSlug")
	var tenantID, issuerURL, clientID, clientSecret string
	var enabled bool
	err := h.db.QueryRow(r.Context(),
		`SELECT t.id, c.issuer_url, c.client_id, c.client_secret, c.enabled
		   FROM tenants t JOIN sso_configs c ON c.tenant_id = t.id
		  WHERE t.slug = $1`, slug,
	).Scan(&tenantID, &issuerURL, &clientID, &clientSecret, &enabled)
	if err != nil || !enabled {
		jsonError(w, "SSO is not configured for this organization", http.StatusNotFound)
		return
	}
	provider, err := oidcauth.NewProvider(r.Context(), issuerURL, clientID, clientSecret, ssoRedirectURL(r))
	if err != nil {
		jsonError(w, "SSO provider unavailable", http.StatusServiceUnavailable)
		return
	}
	verifier, challenge, err := oidcauth.GeneratePKCE()
	if err != nil {
		jsonError(w, "internal error", http.StatusInternalServerError)
		return
	}
	state, err := auth.GenerateSSOState(tenantID, verifier, h.secret, 10*time.Minute)
	if err != nil {
		jsonError(w, "internal error", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, provider.AuthCodeURL(state, challenge), http.StatusFound)
}

// SSOCallback completes the OIDC Authorization Code flow: validates state,
// exchanges the code, resolves or JIT-provisions the user, and mints the
// same tenant-aware JWT Login does.
// GET /api/auth/sso/callback
func (h *Handler) SSOCallback(w http.ResponseWriter, r *http.Request) {
	stateTok := r.URL.Query().Get("state")
	code := r.URL.Query().Get("code")
	if stateTok == "" || code == "" {
		jsonError(w, "missing state or code", http.StatusBadRequest)
		return
	}
	state, err := auth.ValidateSSOState(stateTok, h.secret)
	if err != nil {
		jsonError(w, "invalid or expired login attempt", http.StatusBadRequest)
		return
	}

	var issuerURL, clientID, clientSecret, defaultRole string
	var enabled bool
	err = h.db.QueryRow(r.Context(),
		`SELECT issuer_url, client_id, client_secret, default_role, enabled
		   FROM sso_configs WHERE tenant_id = $1`, state.TenantID,
	).Scan(&issuerURL, &clientID, &clientSecret, &defaultRole, &enabled)
	if err != nil || !enabled {
		jsonError(w, "SSO is not configured for this organization", http.StatusNotFound)
		return
	}

	provider, err := oidcauth.NewProvider(r.Context(), issuerURL, clientID, clientSecret, ssoRedirectURL(r))
	if err != nil {
		jsonError(w, "SSO provider unavailable", http.StatusServiceUnavailable)
		return
	}
	email, err := provider.Exchange(r.Context(), code, state.CodeVerifier)
	if err != nil {
		h.auditLogAs(r, "", "user.sso_login", "", map[string]any{"tenantId": state.TenantID, "reason": "token exchange failed"}, "fail")
		jsonError(w, "SSO login failed", http.StatusUnauthorized)
		return
	}

	var userID, role string
	var isActive bool
	err = h.db.QueryRow(r.Context(),
		`SELECT id, role, is_active FROM users WHERE username = $1 AND tenant_id = $2`,
		email, state.TenantID,
	).Scan(&userID, &role, &isActive)
	if err != nil {
		placeholder, hErr := auth.HashPassword(randomSSOPlaceholder())
		if hErr != nil {
			jsonError(w, "internal error", http.StatusInternalServerError)
			return
		}
		role = defaultRole
		isActive = true
		insErr := h.db.QueryRow(r.Context(),
			`INSERT INTO users (username, password_hash, role, tenant_id, auth_source)
			 VALUES ($1,$2,$3,$4,'sso') RETURNING id`,
			email, placeholder, role, state.TenantID,
		).Scan(&userID)
		if insErr != nil {
			jsonError(w, insErr.Error(), http.StatusInternalServerError)
			return
		}
		h.auditLogAs(r, userID, "user.sso_provisioned", userID, map[string]any{"username": email, "tenantId": state.TenantID, "role": role}, "ok")
	}
	if !isActive {
		h.auditLogAs(r, userID, "user.login", userID, map[string]any{"username": email, "reason": "account disabled"}, "fail")
		jsonError(w, "account is disabled — contact your administrator", http.StatusForbidden)
		return
	}

	tenantID := state.TenantID
	token, err := auth.GenerateTenantToken(userID, auth.Role(role), &tenantID, false, h.secret, 24*time.Hour)
	if err != nil {
		jsonError(w, "token generation failed", http.StatusInternalServerError)
		return
	}
	_, _ = h.db.Exec(r.Context(), `UPDATE users SET last_login = NOW() WHERE id = $1`, userID)

	http.SetCookie(w, &http.Cookie{
		Name:     "bas_token",
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   secureCookies(),
		SameSite: http.SameSiteStrictMode,
		MaxAge:   86400,
	})
	h.auditLogAs(r, userID, "user.sso_login", userID, map[string]any{"username": email}, "ok")
	http.Redirect(w, r, "/", http.StatusFound)
}
