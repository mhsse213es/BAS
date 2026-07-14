package api

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/audspect/bas/internal/detectverify"
)

// ── Detection Connector Config CRUD (Admin only) ───────────────────────────

// ListDetectionConnectors lists all detection verification connector configs.
// GET /api/detectverify/configs
func (h *Handler) ListDetectionConnectors(w http.ResponseWriter, r *http.Request) {
	rows, err := h.db.Query(r.Context(),
		`SELECT id, name, provider, enabled, auto_verify, tenant_id, workspace_id,
		        verify_delay_seconds, created_at, updated_at
		   FROM detection_connectors ORDER BY created_at ASC`)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	type row struct {
		ID                 string    `json:"id"`
		Name               string    `json:"name"`
		Provider           string    `json:"provider"`
		Enabled            bool      `json:"enabled"`
		AutoVerify         bool      `json:"autoVerify"`
		TenantID           string    `json:"tenantId"`
		WorkspaceID        string    `json:"workspaceId"`
		VerifyDelaySeconds int       `json:"verifyDelaySeconds"`
		CreatedAt          time.Time `json:"createdAt"`
		UpdatedAt          time.Time `json:"updatedAt"`
	}
	var out []row
	for rows.Next() {
		var rv row
		if err := rows.Scan(&rv.ID, &rv.Name, &rv.Provider, &rv.Enabled, &rv.AutoVerify,
			&rv.TenantID, &rv.WorkspaceID, &rv.VerifyDelaySeconds, &rv.CreatedAt, &rv.UpdatedAt); err != nil {
			continue
		}
		out = append(out, rv)
	}
	if out == nil {
		out = []row{}
	}
	respond(w, out)
}

// CreateDetectionConnector creates a new detection verification connector config.
// POST /api/detectverify/configs
func (h *Handler) CreateDetectionConnector(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name               string `json:"name"`
		Provider           string `json:"provider"`
		Enabled            bool   `json:"enabled"`
		AutoVerify         bool   `json:"autoVerify"`
		TenantID           string `json:"tenantId"`
		ClientID           string `json:"clientId"`
		ClientSecret       string `json:"clientSecret"`
		WorkspaceID        string `json:"workspaceId"`
		VerifyDelaySeconds int    `json:"verifyDelaySeconds"`
	}
	if json.NewDecoder(r.Body).Decode(&req) != nil || req.Name == "" || req.Provider == "" {
		jsonError(w, "name and provider are required", http.StatusBadRequest)
		return
	}
	validProviders := map[string]bool{"microsoft_sentinel": true, "microsoft_defender": true}
	if !validProviders[req.Provider] {
		jsonError(w, "provider must be microsoft_sentinel | microsoft_defender", http.StatusBadRequest)
		return
	}
	if req.VerifyDelaySeconds <= 0 {
		req.VerifyDelaySeconds = 120
	}
	var id string
	err := h.db.QueryRow(r.Context(),
		`INSERT INTO detection_connectors
		 (name, provider, enabled, auto_verify, tenant_id, client_id, client_secret, workspace_id, verify_delay_seconds)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING id`,
		req.Name, req.Provider, req.Enabled, req.AutoVerify,
		req.TenantID, req.ClientID, req.ClientSecret, req.WorkspaceID, req.VerifyDelaySeconds,
	).Scan(&id)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.auditLog(r, "detectverify.config_created", id, map[string]any{"provider": req.Provider, "name": req.Name}, "ok")
	respond(w, map[string]any{"id": id})
}

// UpdateDetectionConnector updates a detection verification connector config.
// PUT /api/detectverify/configs/{id}
func (h *Handler) UpdateDetectionConnector(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var req struct {
		Name               string `json:"name"`
		Enabled            bool   `json:"enabled"`
		AutoVerify         bool   `json:"autoVerify"`
		TenantID           string `json:"tenantId"`
		ClientID           string `json:"clientId"`
		ClientSecret       string `json:"clientSecret"`
		WorkspaceID        string `json:"workspaceId"`
		VerifyDelaySeconds int    `json:"verifyDelaySeconds"`
	}
	if json.NewDecoder(r.Body).Decode(&req) != nil {
		jsonError(w, "invalid body", http.StatusBadRequest)
		return
	}
	// Preserve masked sensitive values (UI returns "***" for secrets it can't show).
	var existingSecret string
	h.db.QueryRow(r.Context(), `SELECT client_secret FROM detection_connectors WHERE id=$1`, id).Scan(&existingSecret)
	if req.ClientSecret == "***" {
		req.ClientSecret = existingSecret
	}
	if req.VerifyDelaySeconds <= 0 {
		req.VerifyDelaySeconds = 120
	}
	ct, err := h.db.Exec(r.Context(),
		`UPDATE detection_connectors SET name=$1, enabled=$2, auto_verify=$3, tenant_id=$4,
		        client_id=$5, client_secret=$6, workspace_id=$7, verify_delay_seconds=$8, updated_at=NOW()
		  WHERE id=$9`,
		req.Name, req.Enabled, req.AutoVerify, req.TenantID,
		req.ClientID, req.ClientSecret, req.WorkspaceID, req.VerifyDelaySeconds, id)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if ct.RowsAffected() == 0 {
		jsonError(w, "connector not found", http.StatusNotFound)
		return
	}
	h.auditLog(r, "detectverify.config_updated", id, nil, "ok")
	respond(w, map[string]any{"status": "ok"})
}

// DeleteDetectionConnector deletes a detection verification connector config.
// DELETE /api/detectverify/configs/{id}
func (h *Handler) DeleteDetectionConnector(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	ct, err := h.db.Exec(r.Context(), `DELETE FROM detection_connectors WHERE id=$1`, id)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if ct.RowsAffected() == 0 {
		jsonError(w, "connector not found", http.StatusNotFound)
		return
	}
	h.auditLog(r, "detectverify.config_deleted", id, nil, "ok")
	respond(w, map[string]any{"status": "ok"})
}

// TestDetectionConnector tests connectivity for a saved detection connector.
// POST /api/detectverify/configs/{id}/test
func (h *Handler) TestDetectionConnector(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	cfg, err := h.loadDetectionConnector(r.Context(), id)
	if err != nil {
		jsonError(w, err.Error(), http.StatusNotFound)
		return
	}
	conn, err := h.buildDetectConnector(*cfg)
	if err != nil {
		respond(w, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	if err := conn.TestConnection(r.Context()); err != nil {
		respond(w, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	respond(w, map[string]any{"ok": true})
}

// ── Internal helpers ──────────────────────────────────────────────────────────

func (h *Handler) loadDetectionConnector(ctx context.Context, id string) (*detectverify.Config, error) {
	var cfg detectverify.Config
	err := h.db.QueryRow(ctx,
		`SELECT id, name, provider, enabled, auto_verify, tenant_id, client_id, client_secret,
		        workspace_id, verify_delay_seconds
		   FROM detection_connectors WHERE id=$1`, id,
	).Scan(&cfg.ID, &cfg.Name, &cfg.Provider, &cfg.Enabled, &cfg.AutoVerify,
		&cfg.TenantID, &cfg.ClientID, &cfg.ClientSecret, &cfg.WorkspaceID, &cfg.VerifyDelaySeconds)
	if err != nil {
		return nil, err
	}
	return &cfg, nil
}

// buildDetectConnector builds a live connector for cfg, honoring a test
// override on h.detectVerifyConnector when set.
func (h *Handler) buildDetectConnector(cfg detectverify.Config) (detectverify.Connector, error) {
	if h.detectVerifyConnector != nil {
		return h.detectVerifyConnector(cfg)
	}
	return detectverify.NewConnector(cfg)
}
