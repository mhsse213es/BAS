package api

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
)

// SCIMConfigResponse is the admin-facing view of a scim_configs row. The
// token itself is never included here — GetSCIMConfig only reports that a
// config exists. The cleartext token is returned exactly once, from
// Create/Rotate, and never again.
type SCIMConfigResponse struct {
	ID          string `json:"id"`
	TenantID    string `json:"tenantId"`
	DefaultRole string `json:"defaultRole"`
	Enabled     bool   `json:"enabled"`
	CreatedAt   string `json:"createdAt"`
}

// GetSCIMConfig returns the caller's tenant's SCIM config, without the token.
// GET /api/scim/config
func (h *Handler) GetSCIMConfig(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := h.effectiveCallerTenantID(r)
	if !ok {
		jsonError(w, "no tenant context", http.StatusForbidden)
		return
	}
	var cfg SCIMConfigResponse
	err := h.db.QueryRow(r.Context(),
		`SELECT id, tenant_id, default_role, enabled,
		        to_char(created_at, 'YYYY-MM-DD"T"HH24:MI:SS"Z"')
		   FROM scim_configs WHERE tenant_id = $1`, tenantID,
	).Scan(&cfg.ID, &cfg.TenantID, &cfg.DefaultRole, &cfg.Enabled, &cfg.CreatedAt)
	if err != nil {
		jsonError(w, "no SCIM config for this tenant", http.StatusNotFound)
		return
	}
	respond(w, cfg)
}

// CreateSCIMConfig creates the caller's tenant's SCIM config and returns
// the bearer token in cleartext — the only time it is ever returned.
// POST /api/scim/config
func (h *Handler) CreateSCIMConfig(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := h.effectiveCallerTenantID(r)
	if !ok {
		jsonError(w, "no tenant context", http.StatusForbidden)
		return
	}
	var req struct {
		DefaultRole string `json:"defaultRole"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	if req.DefaultRole == "" {
		req.DefaultRole = "viewer"
	}
	if !validSSORoles[req.DefaultRole] {
		jsonError(w, "defaultRole must be viewer, analyst, or admin", http.StatusBadRequest)
		return
	}
	token, err := generateSCIMToken()
	if err != nil {
		jsonError(w, "internal error", http.StatusInternalServerError)
		return
	}
	var id string
	err = h.db.QueryRow(r.Context(),
		`INSERT INTO scim_configs (tenant_id, token_hash, default_role) VALUES ($1,$2,$3) RETURNING id`,
		tenantID, hashSCIMToken(token), req.DefaultRole,
	).Scan(&id)
	if err != nil {
		if strings.Contains(err.Error(), "unique") {
			jsonError(w, "this tenant already has a SCIM config", http.StatusConflict)
			return
		}
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.auditLog(r, "scim.config_created", id, map[string]any{"tenantId": tenantID}, "ok")
	respond(w, map[string]any{"id": id, "token": token})
}

// UpdateSCIMConfig changes the caller's tenant's SCIM config's defaultRole
// and enabled flag. Does not change the token — use RotateSCIMConfig for
// that. Callers must always send both fields; enabled has no "unchanged"
// sentinel (matches UpdateSSOConfig's own convention).
// PUT /api/scim/config/{id}
func (h *Handler) UpdateSCIMConfig(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := h.effectiveCallerTenantID(r)
	if !ok {
		jsonError(w, "no tenant context", http.StatusForbidden)
		return
	}
	id := chi.URLParam(r, "id")
	var req struct {
		DefaultRole string `json:"defaultRole"`
		Enabled     bool   `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid body", http.StatusBadRequest)
		return
	}
	if req.DefaultRole != "" && !validSSORoles[req.DefaultRole] {
		jsonError(w, "defaultRole must be viewer, analyst, or admin", http.StatusBadRequest)
		return
	}
	ct, err := h.db.Exec(r.Context(),
		`UPDATE scim_configs SET default_role=COALESCE(NULLIF($1,''), default_role), enabled=$2, updated_at=NOW()
		  WHERE id=$3 AND tenant_id=$4`,
		req.DefaultRole, req.Enabled, id, tenantID)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if ct.RowsAffected() == 0 {
		jsonError(w, "SCIM config not found", http.StatusNotFound)
		return
	}
	h.auditLog(r, "scim.config_updated", id, nil, "ok")
	respond(w, map[string]any{"status": "ok"})
}

// RotateSCIMConfig issues a fresh token for the caller's tenant's SCIM
// config, invalidating the old one immediately (its hash is overwritten,
// so any SCIM request presenting it 401s from then on). Returns the new
// token in cleartext — the only time it is ever returned.
// POST /api/scim/config/{id}/rotate
func (h *Handler) RotateSCIMConfig(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := h.effectiveCallerTenantID(r)
	if !ok {
		jsonError(w, "no tenant context", http.StatusForbidden)
		return
	}
	id := chi.URLParam(r, "id")
	token, err := generateSCIMToken()
	if err != nil {
		jsonError(w, "internal error", http.StatusInternalServerError)
		return
	}
	ct, err := h.db.Exec(r.Context(),
		`UPDATE scim_configs SET token_hash=$1, updated_at=NOW() WHERE id=$2 AND tenant_id=$3`,
		hashSCIMToken(token), id, tenantID)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if ct.RowsAffected() == 0 {
		jsonError(w, "SCIM config not found", http.StatusNotFound)
		return
	}
	h.auditLog(r, "scim.config_rotated", id, nil, "ok")
	respond(w, map[string]any{"token": token})
}

// DeleteSCIMConfig deletes the caller's tenant's SCIM config, immediately
// invalidating its token — any further SCIM request 401s. Existing
// SCIM-provisioned users are unaffected.
// DELETE /api/scim/config/{id}
func (h *Handler) DeleteSCIMConfig(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := h.effectiveCallerTenantID(r)
	if !ok {
		jsonError(w, "no tenant context", http.StatusForbidden)
		return
	}
	id := chi.URLParam(r, "id")
	ct, err := h.db.Exec(r.Context(), `DELETE FROM scim_configs WHERE id=$1 AND tenant_id=$2`, id, tenantID)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if ct.RowsAffected() == 0 {
		jsonError(w, "SCIM config not found", http.StatusNotFound)
		return
	}
	h.auditLog(r, "scim.config_deleted", id, nil, "ok")
	respond(w, map[string]any{"status": "ok"})
}
