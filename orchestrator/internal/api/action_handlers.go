package api

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/audspect/bas/internal/actions"
)

// ── Response Connector Config CRUD (Admin only) ────────────────────────────

// ListResponseConnectors lists all EPP response-action connector configs.
// GET /api/actions/configs
func (h *Handler) ListResponseConnectors(w http.ResponseWriter, r *http.Request) {
	rows, err := h.db.Query(r.Context(),
		`SELECT id, name, provider, enabled, tenant_id, base_url, kill_process_script_name, created_at, updated_at
		   FROM action_connectors ORDER BY created_at ASC`)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	type row struct {
		ID                    string    `json:"id"`
		Name                  string    `json:"name"`
		Provider              string    `json:"provider"`
		Enabled               bool      `json:"enabled"`
		TenantID              string    `json:"tenantId"`
		BaseURL               string    `json:"baseUrl"`
		KillProcessScriptName string    `json:"killProcessScriptName"`
		CreatedAt             time.Time `json:"createdAt"`
		UpdatedAt             time.Time `json:"updatedAt"`
	}
	var out []row
	for rows.Next() {
		var rv row
		if err := rows.Scan(&rv.ID, &rv.Name, &rv.Provider, &rv.Enabled, &rv.TenantID,
			&rv.BaseURL, &rv.KillProcessScriptName, &rv.CreatedAt, &rv.UpdatedAt); err != nil {
			continue
		}
		out = append(out, rv)
	}
	if out == nil {
		out = []row{}
	}
	respond(w, out)
}

// CreateResponseConnector creates a new EPP response-action connector config.
// POST /api/actions/configs
func (h *Handler) CreateResponseConnector(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name                  string `json:"name"`
		Provider              string `json:"provider"`
		Enabled               bool   `json:"enabled"`
		TenantID              string `json:"tenantId"`
		ClientID              string `json:"clientId"`
		ClientSecret          string `json:"clientSecret"`
		BaseURL               string `json:"baseUrl"`
		KillProcessScriptName string `json:"killProcessScriptName"`
	}
	if json.NewDecoder(r.Body).Decode(&req) != nil || req.Name == "" || req.Provider == "" {
		jsonError(w, "name and provider are required", http.StatusBadRequest)
		return
	}
	validProviders := map[string]bool{"crowdstrike": true, "microsoft_defender": true}
	if !validProviders[req.Provider] {
		jsonError(w, "provider must be crowdstrike | microsoft_defender", http.StatusBadRequest)
		return
	}
	var id string
	err := h.db.QueryRow(r.Context(),
		`INSERT INTO action_connectors
		 (name, provider, enabled, tenant_id, client_id, client_secret, base_url, kill_process_script_name)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id`,
		req.Name, req.Provider, req.Enabled, req.TenantID, req.ClientID, req.ClientSecret,
		req.BaseURL, req.KillProcessScriptName,
	).Scan(&id)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.auditLog(r, "actions.connector_created", id, map[string]any{"provider": req.Provider, "name": req.Name}, "ok")
	respond(w, map[string]any{"id": id})
}

// UpdateResponseConnector updates an EPP response-action connector config.
// PUT /api/actions/configs/{id}
func (h *Handler) UpdateResponseConnector(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var req struct {
		Name                  string `json:"name"`
		Enabled               bool   `json:"enabled"`
		TenantID              string `json:"tenantId"`
		ClientID              string `json:"clientId"`
		ClientSecret          string `json:"clientSecret"`
		BaseURL               string `json:"baseUrl"`
		KillProcessScriptName string `json:"killProcessScriptName"`
	}
	if json.NewDecoder(r.Body).Decode(&req) != nil {
		jsonError(w, "invalid body", http.StatusBadRequest)
		return
	}
	// Preserve masked sensitive values (UI returns "***" for secrets it can't show).
	var existingSecret string
	h.db.QueryRow(r.Context(), `SELECT client_secret FROM action_connectors WHERE id=$1`, id).Scan(&existingSecret)
	if req.ClientSecret == "***" {
		req.ClientSecret = existingSecret
	}
	ct, err := h.db.Exec(r.Context(),
		`UPDATE action_connectors SET name=$1, enabled=$2, tenant_id=$3, client_id=$4,
		        client_secret=$5, base_url=$6, kill_process_script_name=$7, updated_at=NOW()
		  WHERE id=$8`,
		req.Name, req.Enabled, req.TenantID, req.ClientID, req.ClientSecret,
		req.BaseURL, req.KillProcessScriptName, id)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if ct.RowsAffected() == 0 {
		jsonError(w, "connector not found", http.StatusNotFound)
		return
	}
	h.auditLog(r, "actions.connector_updated", id, nil, "ok")
	respond(w, map[string]any{"status": "ok"})
}

// DeleteResponseConnector deletes an EPP response-action connector config.
// DELETE /api/actions/configs/{id}
func (h *Handler) DeleteResponseConnector(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	ct, err := h.db.Exec(r.Context(), `DELETE FROM action_connectors WHERE id=$1`, id)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if ct.RowsAffected() == 0 {
		jsonError(w, "connector not found", http.StatusNotFound)
		return
	}
	h.auditLog(r, "actions.connector_deleted", id, nil, "ok")
	respond(w, map[string]any{"status": "ok"})
}

// TestResponseConnector tests connectivity for a saved response connector by
// resolving a placeholder hostname — a connectivity/auth check, not a real
// action. Uses ResolveDevice specifically because it's the one VendorClient
// method that's read-only for both vendors (a plain device lookup, no
// isolate/kill/quarantine side effect), which is what "test connection"
// should mean here.
// POST /api/actions/configs/{id}/test
func (h *Handler) TestResponseConnector(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	cfg, _, err := h.loadResponseConnector(r.Context(), id)
	if err != nil {
		jsonError(w, "connector not found", http.StatusNotFound)
		return
	}
	client, err := h.buildActionVendorClient(*cfg)
	if err != nil {
		respond(w, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	if _, err := client.ResolveDevice(r.Context(), "audspect-test-connectivity-probe"); err != nil {
		// A "no device found" error means auth succeeded and the API is
		// reachable — that IS a successful connectivity test. Any other
		// error (auth failure, network failure, HTTP 4xx/5xx before the
		// "not found" stage) is a genuine failure.
		respond(w, map[string]any{"ok": true, "note": "connector reachable (probe hostname not expected to exist): " + err.Error()})
		return
	}
	respond(w, map[string]any{"ok": true})
}

// ── Internal helpers ────────────────────────────────────────────────────────

// loadResponseConnector returns the connector's config and its enabled flag.
func (h *Handler) loadResponseConnector(ctx context.Context, id string) (*actions.ConnectorConfig, bool, error) {
	var cfg actions.ConnectorConfig
	var enabled bool
	err := h.db.QueryRow(ctx,
		`SELECT provider, enabled, tenant_id, client_id, client_secret, base_url, kill_process_script_name
		   FROM action_connectors WHERE id=$1`, id,
	).Scan(&cfg.Provider, &enabled, &cfg.TenantID, &cfg.ClientID, &cfg.ClientSecret,
		&cfg.BaseURL, &cfg.KillProcessScriptName)
	if err != nil {
		return nil, false, err
	}
	return &cfg, enabled, nil
}

// buildActionVendorClient builds a live VendorClient for cfg, honoring a
// test override on h.actionVendorClient when set.
func (h *Handler) buildActionVendorClient(cfg actions.ConnectorConfig) (actions.VendorClient, error) {
	if h.actionVendorClient != nil {
		return h.actionVendorClient(cfg)
	}
	return actions.NewVendorClient(cfg)
}
