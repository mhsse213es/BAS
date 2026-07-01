package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/audspect/bas/internal/models"
	"github.com/audspect/bas/internal/siem"
)

// ── SIEM Config CRUD (Admin only) ─────────────────────────────────────────────

// ListSIEMConfigs lists all SIEM connector configs.
// GET /api/siem/configs
func (h *Handler) ListSIEMConfigs(w http.ResponseWriter, r *http.Request) {
	rows, err := h.db.Query(r.Context(),
		`SELECT id, name, provider, enabled, console_url, insecure_skip_verify,
		        auto_correlate, created_at, updated_at
		   FROM siem_configs ORDER BY created_at ASC`)
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
		ConsoleURL         string    `json:"consoleUrl"`
		InsecureSkipVerify bool      `json:"insecureSkipVerify"`
		AutoCorrelate      bool      `json:"autoCorrelate"`
		CreatedAt          time.Time `json:"createdAt"`
		UpdatedAt          time.Time `json:"updatedAt"`
	}
	var out []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.ID, &r.Name, &r.Provider, &r.Enabled, &r.ConsoleURL,
			&r.InsecureSkipVerify, &r.AutoCorrelate, &r.CreatedAt, &r.UpdatedAt); err != nil {
			continue
		}
		out = append(out, r)
	}
	if out == nil {
		out = []row{}
	}
	respond(w, out)
}

// CreateSIEMConfig creates a new SIEM connector config.
// POST /api/siem/configs
func (h *Handler) CreateSIEMConfig(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name               string `json:"name"`
		Provider           string `json:"provider"`
		Enabled            bool   `json:"enabled"`
		ConsoleURL         string `json:"consoleUrl"`
		Token              string `json:"token"`
		Username           string `json:"username"`
		Password           string `json:"password"`
		TenantID           string `json:"tenantId"`
		WorkspaceID        string `json:"workspaceId"`
		ClientID           string `json:"clientId"`
		ClientSecret       string `json:"clientSecret"`
		InsecureSkipVerify bool   `json:"insecureSkipVerify"`
		AutoCorrelate      bool   `json:"autoCorrelate"`
	}
	if json.NewDecoder(r.Body).Decode(&req) != nil || req.Name == "" || req.Provider == "" {
		jsonError(w, "name and provider are required", http.StatusBadRequest)
		return
	}
	validProviders := map[string]bool{"qradar": true, "splunk": true, "wazuh": true, "sentinel": true}
	if !validProviders[req.Provider] {
		jsonError(w, "provider must be qradar | splunk | wazuh | sentinel", http.StatusBadRequest)
		return
	}
	var id string
	err := h.db.QueryRow(r.Context(),
		`INSERT INTO siem_configs
		 (name, provider, enabled, console_url, token, username, password,
		  tenant_id, workspace_id, client_id, client_secret, insecure_skip_verify, auto_correlate)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) RETURNING id`,
		req.Name, req.Provider, req.Enabled, req.ConsoleURL,
		req.Token, req.Username, req.Password,
		req.TenantID, req.WorkspaceID, req.ClientID, req.ClientSecret,
		req.InsecureSkipVerify, req.AutoCorrelate,
	).Scan(&id)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.auditLog(r, "siem.config_created", id, map[string]any{"provider": req.Provider, "name": req.Name}, "ok")
	respond(w, map[string]any{"id": id})
}

// UpdateSIEMConfig updates a SIEM connector config.
// PUT /api/siem/configs/{id}
func (h *Handler) UpdateSIEMConfig(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var req struct {
		Name               string `json:"name"`
		Enabled            bool   `json:"enabled"`
		ConsoleURL         string `json:"consoleUrl"`
		Token              string `json:"token"`
		Username           string `json:"username"`
		Password           string `json:"password"`
		InsecureSkipVerify bool   `json:"insecureSkipVerify"`
		AutoCorrelate      bool   `json:"autoCorrelate"`
	}
	if json.NewDecoder(r.Body).Decode(&req) != nil {
		jsonError(w, "invalid body", http.StatusBadRequest)
		return
	}
	// Preserve masked sensitive values (UI returns "***" for secrets it can't show).
	var existing struct{ Token, Username, Password string }
	h.db.QueryRow(r.Context(), `SELECT token, username, password FROM siem_configs WHERE id=$1`, id).
		Scan(&existing.Token, &existing.Username, &existing.Password)
	if req.Token == "***" {
		req.Token = existing.Token
	}
	if req.Password == "***" {
		req.Password = existing.Password
	}
	ct, err := h.db.Exec(r.Context(),
		`UPDATE siem_configs SET name=$1, enabled=$2, console_url=$3, token=$4, username=$5,
		        password=$6, insecure_skip_verify=$7, auto_correlate=$8, updated_at=NOW()
		  WHERE id=$9`,
		req.Name, req.Enabled, req.ConsoleURL, req.Token, req.Username,
		req.Password, req.InsecureSkipVerify, req.AutoCorrelate, id)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if ct.RowsAffected() == 0 {
		jsonError(w, "config not found", http.StatusNotFound)
		return
	}
	h.auditLog(r, "siem.config_updated", id, nil, "ok")
	respond(w, map[string]any{"status": "ok"})
}

// DeleteSIEMConfig deletes a SIEM connector config.
// DELETE /api/siem/configs/{id}
func (h *Handler) DeleteSIEMConfig(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	ct, err := h.db.Exec(r.Context(), `DELETE FROM siem_configs WHERE id=$1`, id)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if ct.RowsAffected() == 0 {
		jsonError(w, "config not found", http.StatusNotFound)
		return
	}
	h.auditLog(r, "siem.config_deleted", id, nil, "ok")
	respond(w, map[string]any{"status": "ok"})
}

// TestSIEMConfig tests connectivity for a saved SIEM connector.
// POST /api/siem/configs/{id}/test
func (h *Handler) TestSIEMConfig(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	cfg, err := h.loadSIEMConfig(r.Context(), id)
	if err != nil {
		jsonError(w, err.Error(), http.StatusNotFound)
		return
	}
	if err := siem.TestConnectivity(r.Context(), *cfg); err != nil {
		respond(w, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	respond(w, map[string]any{"ok": true})
}

// ── Correlation ────────────────────────────────────────────────────────────────

// TriggerSIEMCorrelation manually triggers SIEM correlation for a completed run.
// POST /api/siem/correlate/{runId}
func (h *Handler) TriggerSIEMCorrelation(w http.ResponseWriter, r *http.Request) {
	runID := chi.URLParam(r, "runId")
	var req struct {
		ConfigID string `json:"configId"` // optional — uses first enabled config if omitted
	}
	_ = json.NewDecoder(r.Body).Decode(&req)

	// Resolve config to use.
	var cfgID string
	if req.ConfigID != "" {
		cfgID = req.ConfigID
	} else {
		h.db.QueryRow(r.Context(),
			`SELECT id FROM siem_configs WHERE enabled=true ORDER BY created_at ASC LIMIT 1`).Scan(&cfgID)
	}
	if cfgID == "" {
		jsonError(w, "no SIEM config available — configure one in Administration → SIEM", http.StatusServiceUnavailable)
		return
	}
	cfg, err := h.loadSIEMConfig(r.Context(), cfgID)
	if err != nil {
		jsonError(w, err.Error(), http.StatusNotFound)
		return
	}

	// Load run metadata.
	var agentID, agentIP string
	var startedAt, completedAt time.Time
	var resultsRaw []byte
	err = h.db.QueryRow(r.Context(),
		`SELECT sr.agent_id, COALESCE(a.ip_address,''), sr.started_at,
		        COALESCE(sr.completed_at, NOW()), sr.results
		   FROM scenario_runs sr
		   LEFT JOIN agents a ON a.agent_id = sr.agent_id
		  WHERE sr.id = $1`, runID,
	).Scan(&agentID, &agentIP, &startedAt, &completedAt, &resultsRaw)
	if err != nil {
		jsonError(w, "run not found", http.StatusNotFound)
		return
	}
	var results []models.SimulationResult
	_ = json.Unmarshal(resultsRaw, &results)

	// Dispatch correlation in background so the HTTP response is immediate.
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		if err := h.runSIEMCorrelation(ctx, *cfg, runID, agentID, agentIP, startedAt, completedAt, results); err != nil {
			log.Printf("[siem] manual correlation run %s: %v", runID, err)
		}
	}()

	h.auditLog(r, "siem.correlate_triggered", runID, map[string]any{"configId": cfgID}, "ok")
	respond(w, map[string]any{"status": "correlating", "runId": runID, "configId": cfgID,
		"message": "SIEM correlation started — results will appear in the run report within ~30 seconds"})
}

// GetSIEMCorrelations returns all stored SIEM correlation results for a run.
// GET /api/siem/correlations/{runId}
func (h *Handler) GetSIEMCorrelations(w http.ResponseWriter, r *http.Request) {
	runID := chi.URLParam(r, "runId")
	rows, err := h.db.Query(r.Context(),
		`SELECT id, run_id, config_id, agent_id, agent_ip, provider,
		        window_start, window_end, total_alerts,
		        detected, undetected, not_executed,
		        detection_rate, undetected_rate, report_json, correlated_at
		   FROM siem_correlations WHERE run_id=$1 ORDER BY correlated_at DESC`, runID)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	type row struct {
		ID             string          `json:"id"`
		RunID          string          `json:"runId"`
		ConfigID       string          `json:"configId"`
		AgentID        string          `json:"agentId"`
		AgentIP        string          `json:"agentIp"`
		Provider       string          `json:"provider"`
		WindowStart    time.Time       `json:"windowStart"`
		WindowEnd      time.Time       `json:"windowEnd"`
		TotalAlerts    int             `json:"totalAlerts"`
		Detected       int             `json:"detected"`
		Undetected     int             `json:"undetected"`
		NotExecuted    int             `json:"notExecuted"`
		DetectionRate  int             `json:"detectionRate"`
		UndetectedRate int             `json:"undetectedRate"`
		Report         json.RawMessage `json:"report"`
		CorrelatedAt   time.Time       `json:"correlatedAt"`
	}
	var out []row
	for rows.Next() {
		var rv row
		if err := rows.Scan(&rv.ID, &rv.RunID, &rv.ConfigID, &rv.AgentID, &rv.AgentIP,
			&rv.Provider, &rv.WindowStart, &rv.WindowEnd, &rv.TotalAlerts,
			&rv.Detected, &rv.Undetected, &rv.NotExecuted,
			&rv.DetectionRate, &rv.UndetectedRate, &rv.Report, &rv.CorrelatedAt); err != nil {
			continue
		}
		out = append(out, rv)
	}
	if out == nil {
		out = []row{}
	}
	respond(w, out)
}

// ── Internal helpers ──────────────────────────────────────────────────────────

func (h *Handler) loadSIEMConfig(ctx context.Context, id string) (*siem.Config, error) {
	var cfg siem.Config
	var providerStr string
	err := h.db.QueryRow(ctx,
		`SELECT id, name, provider, enabled, console_url, token, username, password,
		        tenant_id, workspace_id, client_id, client_secret, insecure_skip_verify, created_at, updated_at
		   FROM siem_configs WHERE id=$1`, id,
	).Scan(&cfg.ID, &cfg.Name, &providerStr, &cfg.Enabled, &cfg.ConsoleURL,
		&cfg.Token, &cfg.Username, &cfg.Password,
		&cfg.TenantID, &cfg.WorkspaceID, &cfg.ClientID, &cfg.ClientSecret,
		&cfg.InsecureSkipVerify, &cfg.CreatedAt, &cfg.UpdatedAt)
	if err != nil {
		return nil, err
	}
	cfg.Provider = siem.Provider(providerStr)
	return &cfg, nil
}

// runSIEMCorrelation is the shared core called by both auto-correlation (after
// run completion) and the manual trigger endpoint.
func (h *Handler) runSIEMCorrelation(
	ctx context.Context,
	cfg siem.Config,
	runID, agentID, agentIP string,
	runStart, runEnd time.Time,
	results []models.SimulationResult,
) error {
	report, err := siem.Correlate(ctx, cfg, runID, agentID, agentIP, runStart, runEnd, results)
	if err != nil {
		return err
	}

	reportJSON, _ := json.Marshal(report)
	_, err = h.db.Exec(ctx,
		`INSERT INTO siem_correlations
		 (run_id, config_id, agent_id, agent_ip, provider, window_start, window_end,
		  total_alerts, detected, undetected, not_executed, detection_rate, undetected_rate, report_json)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
		 ON CONFLICT (run_id, config_id) DO UPDATE SET
		   total_alerts=$8, detected=$9, undetected=$10, not_executed=$11,
		   detection_rate=$12, undetected_rate=$13, report_json=$14,
		   correlated_at=NOW()`,
		runID, cfg.ID, agentID, agentIP, string(cfg.Provider),
		report.WindowStart, report.WindowEnd,
		report.TotalAlerts, report.Detected, report.Undetected, report.NotExecuted,
		report.DetectionRate, report.UndetectedRate, reportJSON,
	)
	if err != nil {
		return fmt.Errorf("persist siem correlation: %w", err)
	}

	// Broadcast to dashboard so the run detail view auto-refreshes.
	h.hub.BroadcastBrowsers(models.WSMessage{
		Type:    "siem_correlation_complete",
		AgentID: agentID,
		Data: map[string]any{
			"runId":         runID,
			"provider":      string(cfg.Provider),
			"detectionRate": report.DetectionRate,
			"detected":      report.Detected,
			"undetected":    report.Undetected,
			"totalAlerts":   report.TotalAlerts,
		},
	})

	log.Printf("[siem] run %s correlated: %d alerts, %d detected, %d undetected (rate %d%%)",
		runID, report.TotalAlerts, report.Detected, report.Undetected, report.DetectionRate)
	return nil
}

// AutoCorrelateSIEM is called from SubmitScenarioResult when a run completes.
// Checks if any SIEM configs have auto_correlate=true; if so, fires correlation
// in a goroutine so it never blocks the agent's result submission response.
func (h *Handler) AutoCorrelateSIEM(runID, agentID, agentIP string, runStart, runEnd time.Time, results []models.SimulationResult) {
	rows, err := h.db.Query(context.Background(),
		`SELECT id FROM siem_configs WHERE enabled=true AND auto_correlate=true ORDER BY created_at ASC`)
	if err != nil || rows == nil {
		return
	}
	var ids []string
	for rows.Next() {
		var id string
		rows.Scan(&id)
		ids = append(ids, id)
	}
	rows.Close()

	for _, cfgID := range ids {
		cfgID := cfgID
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			cfg, err := h.loadSIEMConfig(ctx, cfgID)
			if err != nil {
				log.Printf("[siem] auto-correlate load config %s: %v", cfgID, err)
				return
			}
			if err := h.runSIEMCorrelation(ctx, *cfg, runID, agentID, agentIP, runStart, runEnd, results); err != nil {
				log.Printf("[siem] auto-correlate run %s config %s: %v", runID, cfgID, err)
			}
		}()
	}
}
