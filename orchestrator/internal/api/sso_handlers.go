package api

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/oidcauth"
)

// SSOConfig is one row from sso_configs, with client_secret masked — it is
// never returned in cleartext once saved.
type SSOConfig struct {
	ID          string `json:"id"`
	TenantID    string `json:"tenantId"`
	IssuerURL   string `json:"issuerUrl"`
	ClientID    string `json:"clientId"`
	DefaultRole string `json:"defaultRole"`
	Enabled     bool   `json:"enabled"`
	CreatedAt   string `json:"createdAt"`
}

var validSSORoles = map[string]bool{"viewer": true, "analyst": true, "admin": true}

// effectiveCallerTenantID resolves which tenant's SSO config the caller may
// act on: a tenant user always acts on their own tenant; a platform-admin
// (who belongs to no tenant) must specify one explicitly via ?tenantId=.
func (h *Handler) effectiveCallerTenantID(r *http.Request) (string, bool) {
	claims, ok := auth.ClaimsFrom(r.Context())
	if !ok {
		return "", false
	}
	if claims.IsPlatformAdmin {
		tid := r.URL.Query().Get("tenantId")
		return tid, tid != ""
	}
	if claims.TenantID == nil {
		return "", false
	}
	return *claims.TenantID, true
}

// GetSSOConfig returns the caller's tenant's SSO config (secret masked).
// GET /api/sso/config
func (h *Handler) GetSSOConfig(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := h.effectiveCallerTenantID(r)
	if !ok {
		jsonError(w, "no tenant context", http.StatusForbidden)
		return
	}
	var cfg SSOConfig
	err := h.db.QueryRow(r.Context(),
		`SELECT id, tenant_id, issuer_url, client_id, default_role, enabled,
		        to_char(created_at, 'YYYY-MM-DD"T"HH24:MI:SS"Z"')
		   FROM sso_configs WHERE tenant_id = $1`, tenantID,
	).Scan(&cfg.ID, &cfg.TenantID, &cfg.IssuerURL, &cfg.ClientID, &cfg.DefaultRole, &cfg.Enabled, &cfg.CreatedAt)
	if err != nil {
		jsonError(w, "no SSO config for this tenant", http.StatusNotFound)
		return
	}
	respond(w, cfg)
}

// CreateSSOConfig creates the caller's tenant's SSO config.
// POST /api/sso/config
func (h *Handler) CreateSSOConfig(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := h.effectiveCallerTenantID(r)
	if !ok {
		jsonError(w, "no tenant context", http.StatusForbidden)
		return
	}
	var req struct {
		IssuerURL    string `json:"issuerUrl"`
		ClientID     string `json:"clientId"`
		ClientSecret string `json:"clientSecret"`
		DefaultRole  string `json:"defaultRole"`
		Enabled      bool   `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.IssuerURL == "" || req.ClientID == "" || req.ClientSecret == "" {
		jsonError(w, "issuerUrl, clientId and clientSecret are required", http.StatusBadRequest)
		return
	}
	if req.DefaultRole == "" {
		req.DefaultRole = "viewer"
	}
	if !validSSORoles[req.DefaultRole] {
		jsonError(w, "defaultRole must be viewer, analyst, or admin", http.StatusBadRequest)
		return
	}
	var id string
	err := h.db.QueryRow(r.Context(),
		`INSERT INTO sso_configs (tenant_id, issuer_url, client_id, client_secret, default_role, enabled)
		 VALUES ($1,$2,$3,$4,$5,$6) RETURNING id`,
		tenantID, req.IssuerURL, req.ClientID, req.ClientSecret, req.DefaultRole, req.Enabled,
	).Scan(&id)
	if err != nil {
		if strings.Contains(err.Error(), "unique") {
			jsonError(w, "this tenant already has an SSO config", http.StatusConflict)
			return
		}
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.auditLog(r, "sso.config_created", id, map[string]any{"tenantId": tenantID, "issuerUrl": req.IssuerURL}, "ok")
	respond(w, map[string]any{"id": id})
}

// UpdateSSOConfig updates the caller's tenant's SSO config. A "***"
// clientSecret preserves the existing value.
// PUT /api/sso/config/{id}
func (h *Handler) UpdateSSOConfig(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := h.effectiveCallerTenantID(r)
	if !ok {
		jsonError(w, "no tenant context", http.StatusForbidden)
		return
	}
	id := chi.URLParam(r, "id")
	var req struct {
		IssuerURL    string `json:"issuerUrl"`
		ClientID     string `json:"clientId"`
		ClientSecret string `json:"clientSecret"`
		DefaultRole  string `json:"defaultRole"`
		Enabled      bool   `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid body", http.StatusBadRequest)
		return
	}
	if req.ClientSecret == "***" {
		var existing string
		h.db.QueryRow(r.Context(), `SELECT client_secret FROM sso_configs WHERE id=$1 AND tenant_id=$2`, id, tenantID).Scan(&existing)
		req.ClientSecret = existing
	}
	if req.DefaultRole != "" && !validSSORoles[req.DefaultRole] {
		jsonError(w, "defaultRole must be viewer, analyst, or admin", http.StatusBadRequest)
		return
	}
	ct, err := h.db.Exec(r.Context(),
		`UPDATE sso_configs SET issuer_url=$1, client_id=$2, client_secret=$3, default_role=$4, enabled=$5, updated_at=NOW()
		  WHERE id=$6 AND tenant_id=$7`,
		req.IssuerURL, req.ClientID, req.ClientSecret, req.DefaultRole, req.Enabled, id, tenantID)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if ct.RowsAffected() == 0 {
		jsonError(w, "SSO config not found", http.StatusNotFound)
		return
	}
	h.auditLog(r, "sso.config_updated", id, nil, "ok")
	respond(w, map[string]any{"status": "ok"})
}

// DeleteSSOConfig deletes the caller's tenant's SSO config. Existing
// SSO-provisioned users are unaffected — their auth_source='sso' blocks
// password login regardless of whether a config still exists; deleting the
// config just stops new SSO logins.
// DELETE /api/sso/config/{id}
func (h *Handler) DeleteSSOConfig(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := h.effectiveCallerTenantID(r)
	if !ok {
		jsonError(w, "no tenant context", http.StatusForbidden)
		return
	}
	id := chi.URLParam(r, "id")
	ct, err := h.db.Exec(r.Context(), `DELETE FROM sso_configs WHERE id=$1 AND tenant_id=$2`, id, tenantID)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if ct.RowsAffected() == 0 {
		jsonError(w, "SSO config not found", http.StatusNotFound)
		return
	}
	h.auditLog(r, "sso.config_deleted", id, nil, "ok")
	respond(w, map[string]any{"status": "ok"})
}

// TestSSOConfig round-trips OIDC discovery against the configured issuer,
// without performing a full login.
// POST /api/sso/config/{id}/test
func (h *Handler) TestSSOConfig(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := h.effectiveCallerTenantID(r)
	if !ok {
		jsonError(w, "no tenant context", http.StatusForbidden)
		return
	}
	id := chi.URLParam(r, "id")
	var issuerURL, clientID, clientSecret string
	err := h.db.QueryRow(r.Context(),
		`SELECT issuer_url, client_id, client_secret FROM sso_configs WHERE id=$1 AND tenant_id=$2`, id, tenantID,
	).Scan(&issuerURL, &clientID, &clientSecret)
	if err != nil {
		jsonError(w, "SSO config not found", http.StatusNotFound)
		return
	}
	if _, err := oidcauth.NewProvider(r.Context(), issuerURL, clientID, clientSecret, ""); err != nil {
		respond(w, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	respond(w, map[string]any{"ok": true})
}

// randomSSOPlaceholder returns a cryptographically random string, used as
// the throwaway password_hash input for a JIT-provisioned SSO user (never
// actually used for verification — auth_source='sso' blocks password login
// outright, this is belt-and-suspenders for the NOT NULL column).
func randomSSOPlaceholder() string {
	buf := make([]byte, 32)
	_, _ = rand.Read(buf)
	return base64.RawURLEncoding.EncodeToString(buf)
}
