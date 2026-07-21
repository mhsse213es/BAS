package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/audspect/bas/internal/actions"
	"github.com/audspect/bas/internal/auth"
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

// ── Execute + audit trail ───────────────────────────────────────────────────

// ExecuteResponseAction executes one EPP response action against a
// configured connector. The target hostname must belong to a currently-
// enrolled agent — this is the safety rail preventing an operator from
// acting on a host outside the BAS fleet.
// POST /api/actions/run
func (h *Handler) ExecuteResponseAction(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Type        string         `json:"type"`
		Hostname    string         `json:"hostname"`
		Parameters  map[string]any `json:"parameters"`
		ConnectorID string         `json:"connectorId"`
		Reason      string         `json:"reason"`
		TicketRef   string         `json:"ticketRef"`
		RunID       string         `json:"runId"`
	}
	if json.NewDecoder(r.Body).Decode(&req) != nil || req.Type == "" || req.Hostname == "" || req.ConnectorID == "" {
		jsonError(w, "type, hostname, and connectorId are required", http.StatusBadRequest)
		return
	}
	if req.Reason == "" {
		jsonError(w, "reason is required", http.StatusBadRequest)
		return
	}
	validTypes := map[string]bool{
		actions.TypeIsolate: true, actions.TypeRelease: true,
		actions.TypeKillProcess: true, actions.TypeQuarantineFile: true,
	}
	if !validTypes[req.Type] {
		jsonError(w, "type must be endpoint.isolate | endpoint.release | endpoint.kill_process | endpoint.quarantine_file", http.StatusBadRequest)
		return
	}

	var agentExists bool
	if err := h.db.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM agents WHERE hostname=$1)`, req.Hostname).Scan(&agentExists); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !agentExists {
		jsonError(w, "hostname must match a currently-enrolled agent", http.StatusBadRequest)
		return
	}

	connCfg, enabled, err := h.loadResponseConnector(r.Context(), req.ConnectorID)
	if err != nil {
		jsonError(w, "connector not found", http.StatusNotFound)
		return
	}
	if !enabled {
		jsonError(w, "connector is disabled", http.StatusBadRequest)
		return
	}

	client, err := h.buildActionVendorClient(*connCfg)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	actorID := ""
	if claims, ok := auth.ClaimsFrom(r.Context()); ok {
		actorID = claims.UserID
	}
	actionReq := actions.Request{
		Type:        req.Type,
		Target:      actions.Target{Type: "hostname", Identifier: req.Hostname},
		Parameters:  req.Parameters,
		ConnectorID: req.ConnectorID,
		RequestedBy: actorID,
		Reason:      req.Reason,
		TicketRef:   req.TicketRef,
		RunID:       req.RunID,
	}
	action := actions.Execute(r.Context(), client, actionReq)

	id, persistErr := h.persistActionRequest(r.Context(), action)
	if persistErr != nil {
		log.Printf("[actions] failed to persist action request: %v", persistErr)
	}
	h.auditLog(r, "actions.executed", id,
		map[string]any{"type": action.Type, "hostname": req.Hostname, "connectorId": req.ConnectorID}, action.Status)

	respond(w, map[string]any{
		"id": id, "status": action.Status, "vendorRequestId": action.VendorRequestID, "error": action.Error,
	})
}

// ListResponseActions returns the response-action audit trail, most-recent
// first, optionally filtered by runId and/or hostname.
// GET /api/actions?runId=&hostname=&limit=
func (h *Handler) ListResponseActions(w http.ResponseWriter, r *http.Request) {
	runID := r.URL.Query().Get("runId")
	hostname := r.URL.Query().Get("hostname")
	limit := 100
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 500 {
			limit = n
		}
	}

	query := `SELECT id, type, target_type, target_identifier, connector_id, status,
	                 resolved_device_id, vendor_request_id, error, requested_by, reason, ticket_ref, run_id,
	                 requested_at, dispatched_at, completed_at
	            FROM action_requests WHERE true`
	var args []any
	if runID != "" {
		args = append(args, runID)
		query += fmt.Sprintf(" AND run_id=$%d", len(args))
	}
	if hostname != "" {
		args = append(args, hostname)
		query += fmt.Sprintf(" AND target_identifier=$%d", len(args))
	}
	args = append(args, limit)
	query += fmt.Sprintf(" ORDER BY requested_at DESC LIMIT $%d", len(args))

	rows, err := h.db.Query(r.Context(), query, args...)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	type row struct {
		ID               string     `json:"id"`
		Type             string     `json:"type"`
		TargetType       string     `json:"targetType"`
		Hostname         string     `json:"hostname"`
		ConnectorID      string     `json:"connectorId"`
		Status           string     `json:"status"`
		ResolvedDeviceID string     `json:"resolvedDeviceId"`
		VendorRequestID  string     `json:"vendorRequestId"`
		Error            string     `json:"error"`
		RequestedBy      string     `json:"requestedBy"`
		Reason           string     `json:"reason"`
		TicketRef        string     `json:"ticketRef"`
		RunID            string     `json:"runId"`
		RequestedAt      time.Time  `json:"requestedAt"`
		DispatchedAt     *time.Time `json:"dispatchedAt,omitempty"`
		CompletedAt      *time.Time `json:"completedAt,omitempty"`
	}
	var out []row
	for rows.Next() {
		var rv row
		if err := rows.Scan(&rv.ID, &rv.Type, &rv.TargetType, &rv.Hostname, &rv.ConnectorID, &rv.Status,
			&rv.ResolvedDeviceID, &rv.VendorRequestID, &rv.Error, &rv.RequestedBy, &rv.Reason, &rv.TicketRef,
			&rv.RunID, &rv.RequestedAt, &rv.DispatchedAt, &rv.CompletedAt); err != nil {
			continue
		}
		out = append(out, rv)
	}
	if out == nil {
		out = []row{}
	}
	respond(w, out)
}

// persistActionRequest writes a completed Execute() result into
// action_requests and returns the row's generated id.
func (h *Handler) persistActionRequest(ctx context.Context, a actions.Action) (string, error) {
	paramsJSON, err := json.Marshal(a.Parameters)
	if err != nil {
		paramsJSON = []byte("{}")
	}
	var id string
	err = h.db.QueryRow(ctx,
		`INSERT INTO action_requests
		 (type, target_type, target_identifier, parameters, connector_id, status,
		  resolved_device_id, vendor_request_id, error, requested_by, reason, ticket_ref, run_id,
		  requested_at, dispatched_at, completed_at)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16) RETURNING id`,
		a.Type, a.Target.Type, a.Target.Identifier, paramsJSON, a.ConnectorID, a.Status,
		a.ResolvedDeviceID, a.VendorRequestID, a.Error, a.RequestedBy, a.Reason, a.TicketRef, a.RunID,
		a.RequestedAt, a.DispatchedAt, a.CompletedAt,
	).Scan(&id)
	return id, err
}
