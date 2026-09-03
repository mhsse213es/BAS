package api

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/audspect/bas/internal/detectverify"
	"github.com/audspect/bas/internal/models"
)

// ── Detection Connector Config CRUD (Admin only) ───────────────────────────

// ListDetectionConnectors lists all detection verification connector configs.
// GET /api/detectverify/configs
func (h *Handler) ListDetectionConnectors(w http.ResponseWriter, r *http.Request) {
	rows, err := h.db.Query(r.Context(),
		`SELECT id, name, provider, enabled, auto_verify, azure_tenant_id, workspace_id, base_url,
		        insecure_tls, verify_delay_seconds, created_at, updated_at
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
		BaseURL            string    `json:"baseUrl"`
		InsecureTLS        bool      `json:"insecureTls"`
		VerifyDelaySeconds int       `json:"verifyDelaySeconds"`
		CreatedAt          time.Time `json:"createdAt"`
		UpdatedAt          time.Time `json:"updatedAt"`
	}
	var out []row
	for rows.Next() {
		var rv row
		if err := rows.Scan(&rv.ID, &rv.Name, &rv.Provider, &rv.Enabled, &rv.AutoVerify,
			&rv.TenantID, &rv.WorkspaceID, &rv.BaseURL, &rv.InsecureTLS, &rv.VerifyDelaySeconds, &rv.CreatedAt, &rv.UpdatedAt); err != nil {
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
		BaseURL            string `json:"baseUrl"`
		APIToken           string `json:"apiToken"`
		InsecureTLS        bool   `json:"insecureTls"`
		VerifyDelaySeconds int    `json:"verifyDelaySeconds"`
	}
	if json.NewDecoder(r.Body).Decode(&req) != nil || req.Name == "" || req.Provider == "" {
		jsonError(w, "name and provider are required", http.StatusBadRequest)
		return
	}
	validProviders := map[string]bool{
		"microsoft_sentinel": true, "microsoft_defender": true, "splunk": true, "qradar": true, "crowdstrike": true, "trellix": true,
	}
	if !validProviders[req.Provider] {
		jsonError(w, "provider must be microsoft_sentinel | microsoft_defender | splunk | qradar | crowdstrike | trellix", http.StatusBadRequest)
		return
	}
	if req.VerifyDelaySeconds <= 0 {
		req.VerifyDelaySeconds = 120
	}
	var id string
	err := h.db.QueryRow(r.Context(),
		`INSERT INTO detection_connectors
		 (name, provider, enabled, auto_verify, azure_tenant_id, client_id, client_secret, workspace_id, base_url, api_token, insecure_tls, verify_delay_seconds)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) RETURNING id`,
		req.Name, req.Provider, req.Enabled, req.AutoVerify,
		req.TenantID, req.ClientID, req.ClientSecret, req.WorkspaceID, req.BaseURL, req.APIToken, req.InsecureTLS, req.VerifyDelaySeconds,
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
		BaseURL            string `json:"baseUrl"`
		APIToken           string `json:"apiToken"`
		InsecureTLS        bool   `json:"insecureTls"`
		VerifyDelaySeconds int    `json:"verifyDelaySeconds"`
	}
	if json.NewDecoder(r.Body).Decode(&req) != nil {
		jsonError(w, "invalid body", http.StatusBadRequest)
		return
	}
	// Preserve masked sensitive values (UI returns "***" for secrets it can't show).
	var existingSecret, existingToken string
	h.db.QueryRow(r.Context(), `SELECT client_secret, api_token FROM detection_connectors WHERE id=$1`, id).
		Scan(&existingSecret, &existingToken)
	if req.ClientSecret == "***" {
		req.ClientSecret = existingSecret
	}
	if req.APIToken == "***" {
		req.APIToken = existingToken
	}
	if req.VerifyDelaySeconds <= 0 {
		req.VerifyDelaySeconds = 120
	}
	ct, err := h.db.Exec(r.Context(),
		`UPDATE detection_connectors SET name=$1, enabled=$2, auto_verify=$3, azure_tenant_id=$4,
		        client_id=$5, client_secret=$6, workspace_id=$7, base_url=$8, api_token=$9,
		        insecure_tls=$10, verify_delay_seconds=$11, updated_at=NOW()
		  WHERE id=$12`,
		req.Name, req.Enabled, req.AutoVerify, req.TenantID,
		req.ClientID, req.ClientSecret, req.WorkspaceID, req.BaseURL, req.APIToken,
		req.InsecureTLS, req.VerifyDelaySeconds, id)
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
		`SELECT id, name, provider, enabled, auto_verify, azure_tenant_id, client_id, client_secret,
		        workspace_id, base_url, api_token, insecure_tls, verify_delay_seconds
		   FROM detection_connectors WHERE id=$1`, id,
	).Scan(&cfg.ID, &cfg.Name, &cfg.Provider, &cfg.Enabled, &cfg.AutoVerify,
		&cfg.TenantID, &cfg.ClientID, &cfg.ClientSecret, &cfg.WorkspaceID,
		&cfg.BaseURL, &cfg.APIToken, &cfg.InsecureTLS, &cfg.VerifyDelaySeconds)
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

// ── Correlation / Trigger ───────────────────────────────────────────────────

// TriggerDetectionVerification manually runs API detection verification for a
// completed run against every enabled connector.
// POST /api/detectverify/run/{runId}
func (h *Handler) TriggerDetectionVerification(w http.ResponseWriter, r *http.Request) {
	runID := chi.URLParam(r, "runId")
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		h.runDetectionVerification(ctx, runID)
	}()
	h.auditLog(r, "detectverify.triggered", runID, nil, "ok")
	respond(w, map[string]any{"status": "verifying", "runId": runID,
		"message": "Detection verification started — results will appear in the run report shortly"})
}

// AutoVerifyDetection is called from SubmitScenarioResult when a run
// completes. Fires one independent, delayed verification pass per enabled
// connector with auto_verify=true — mirrors AutoCorrelateSIEM's per-config
// dispatch exactly. Each goroutine sleeps its own verify_delay_seconds before
// querying, to absorb SIEM/XDR ingestion lag.
func (h *Handler) AutoVerifyDetection(runID string) {
	rows, err := h.db.Query(context.Background(),
		`SELECT id, verify_delay_seconds FROM detection_connectors
		  WHERE enabled=true AND auto_verify=true ORDER BY created_at ASC`)
	if err != nil || rows == nil {
		return
	}
	type target struct {
		id    string
		delay int
	}
	var targets []target
	for rows.Next() {
		var t target
		if err := rows.Scan(&t.id, &t.delay); err != nil {
			continue
		}
		targets = append(targets, t)
	}
	rows.Close()

	for _, t := range targets {
		go func() {
			if t.delay > 0 {
				time.Sleep(time.Duration(t.delay) * time.Second)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			h.runDetectionVerificationForConnector(ctx, runID, t.id)
		}()
	}
}

// loadRunForVerification loads the scenario ID, host name/IP, and stored
// results for a run — the same data AutoCorrelateSIEM's call site already
// reads for SIEM correlation, plus the scenario ID VerifyRun needs to resolve
// expectations.
func (h *Handler) loadRunForVerification(ctx context.Context, runID string) (scenarioID, agentHost, agentIP string, results []models.SimulationResult, err error) {
	var resultsRaw []byte
	err = h.db.QueryRow(ctx,
		`SELECT sr.scenario_id, COALESCE(a.hostname,''), COALESCE(a.ip_address,''), sr.results
		   FROM scenario_runs sr
		   LEFT JOIN agents a ON a.agent_id = sr.agent_id
		  WHERE sr.id = $1`, runID,
	).Scan(&scenarioID, &agentHost, &agentIP, &resultsRaw)
	if err != nil {
		return "", "", "", nil, err
	}
	_ = json.Unmarshal(resultsRaw, &results)
	return scenarioID, agentHost, agentIP, results, nil
}

// runDetectionVerification checks a run against every enabled connector.
// Used by the manual trigger endpoint.
func (h *Handler) runDetectionVerification(ctx context.Context, runID string) {
	if h.verification == nil {
		return
	}
	scenarioID, host, ip, results, err := h.loadRunForVerification(ctx, runID)
	if err != nil {
		log.Printf("[detectverify] load run %s: %v", runID, err)
		return
	}
	connectors, err := h.enabledDetectionConnectors(ctx)
	if err != nil || len(connectors) == 0 {
		return
	}
	summary := detectverify.VerifyRun(ctx, detectverify.VerifyRunParams{
		RunID: runID, ScenarioID: scenarioID, HostName: host, HostIP: ip,
		Results: results, Scenarios: h.engine, Store: h.verification, Connectors: connectors,
	})
	log.Printf("[detectverify] run %s: checked=%d attested=%d errors=%d",
		runID, summary.Checked, summary.Attested, summary.Errors)
}

// runDetectionVerificationForConnector checks a run against exactly one
// connector. Used by the auto-verify path so each connector gets its own
// independently-timed delay.
func (h *Handler) runDetectionVerificationForConnector(ctx context.Context, runID, connectorID string) {
	if h.verification == nil {
		return
	}
	scenarioID, host, ip, results, err := h.loadRunForVerification(ctx, runID)
	if err != nil {
		log.Printf("[detectverify] load run %s: %v", runID, err)
		return
	}
	cfg, err := h.loadDetectionConnector(ctx, connectorID)
	if err != nil {
		return
	}
	conn, err := h.buildDetectConnector(*cfg)
	if err != nil {
		log.Printf("[detectverify] build connector %s: %v", connectorID, err)
		return
	}
	summary := detectverify.VerifyRun(ctx, detectverify.VerifyRunParams{
		RunID: runID, ScenarioID: scenarioID, HostName: host, HostIP: ip,
		Results: results, Scenarios: h.engine, Store: h.verification,
		Connectors: map[string]detectverify.Connector{cfg.Provider: conn},
	})
	log.Printf("[detectverify] run %s connector %s: checked=%d attested=%d errors=%d",
		runID, connectorID, summary.Checked, summary.Attested, summary.Errors)
}

// enabledDetectionConnectors builds a live Connector for every enabled
// detection_connectors row, keyed by provider.
func (h *Handler) enabledDetectionConnectors(ctx context.Context) (map[string]detectverify.Connector, error) {
	rows, err := h.db.Query(ctx, `SELECT id FROM detection_connectors WHERE enabled=true ORDER BY created_at ASC`)
	if err != nil {
		return nil, err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			continue
		}
		ids = append(ids, id)
	}
	rows.Close()

	out := map[string]detectverify.Connector{}
	for _, id := range ids {
		cfg, err := h.loadDetectionConnector(ctx, id)
		if err != nil {
			continue
		}
		conn, err := h.buildDetectConnector(*cfg)
		if err != nil {
			log.Printf("[detectverify] build connector %s: %v", id, err)
			continue
		}
		out[cfg.Provider] = conn
	}
	return out, nil
}
