package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/ticketing"
)

// ── Config CRUD (Admin only) ─────────────────────────────────────────────────

// ListTicketingConfigs lists all ITSM connector configs.
// GET /api/ticketing/configs
func (h *Handler) ListTicketingConfigs(w http.ResponseWriter, r *http.Request) {
	if h.ticketing == nil {
		respond(w, []any{})
		return
	}
	respond(w, h.ticketing.ActiveConfigs())
}

// CreateTicketingConfig creates a new ITSM connector config.
// POST /api/ticketing/configs  body: {name, provider, enabled, autoCreate, autoUpdate, autoClose, settings}
func (h *Handler) CreateTicketingConfig(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name       string            `json:"name"`
		Provider   string            `json:"provider"`
		Enabled    bool              `json:"enabled"`
		AutoCreate string            `json:"autoCreate"`
		AutoUpdate bool              `json:"autoUpdate"`
		AutoClose  bool              `json:"autoClose"`
		Settings   map[string]string `json:"settings"`
	}
	if json.NewDecoder(r.Body).Decode(&req) != nil {
		jsonError(w, "invalid body", http.StatusBadRequest)
		return
	}
	validProviders := map[string]bool{"servicenow": true, "jira": true, "webhook": true}
	if !validProviders[req.Provider] {
		jsonError(w, "provider must be servicenow | jira | webhook", http.StatusBadRequest)
		return
	}
	validAC := map[string]bool{"off": true, "critical": true, "critical_high": true, "all": true}
	if req.AutoCreate == "" {
		req.AutoCreate = "off"
	}
	if !validAC[req.AutoCreate] {
		jsonError(w, "autoCreate must be off | critical | critical_high | all", http.StatusBadRequest)
		return
	}

	settingsJSON, _ := json.Marshal(req.Settings)
	var id string
	err := h.db.QueryRow(r.Context(),
		`INSERT INTO ticketing_configs (name, provider, enabled, auto_create, auto_update, auto_close, settings)
		 VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING id`,
		req.Name, req.Provider, req.Enabled, req.AutoCreate, req.AutoUpdate, req.AutoClose, settingsJSON,
	).Scan(&id)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if h.ticketing != nil {
		_ = h.ticketing.Reload(r.Context())
	}
	by := "unknown"
	if c, ok := auth.ClaimsFrom(r.Context()); ok && c != nil {
		by = c.UserID
	}
	h.auditLog(r, "ticketing.config_created", id, map[string]any{"provider": req.Provider, "name": req.Name}, "ok")
	_ = by
	respond(w, map[string]any{"id": id})
}

// UpdateTicketingConfig updates a connector config.
// PUT /api/ticketing/configs/{id}
func (h *Handler) UpdateTicketingConfig(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var req struct {
		Name       string            `json:"name"`
		Enabled    bool              `json:"enabled"`
		AutoCreate string            `json:"autoCreate"`
		AutoUpdate bool              `json:"autoUpdate"`
		AutoClose  bool              `json:"autoClose"`
		Settings   map[string]string `json:"settings"`
	}
	if json.NewDecoder(r.Body).Decode(&req) != nil {
		jsonError(w, "invalid body", http.StatusBadRequest)
		return
	}
	if req.AutoCreate == "" {
		req.AutoCreate = "off"
	}
	// Preserve existing sensitive values that the UI returns as "***" (masked).
	var existingRaw []byte
	_ = h.db.QueryRow(r.Context(), `SELECT settings FROM ticketing_configs WHERE id=$1`, id).Scan(&existingRaw)
	var existingSettings map[string]string
	_ = json.Unmarshal(existingRaw, &existingSettings)
	if req.Settings == nil {
		req.Settings = map[string]string{}
	}
	for k, v := range req.Settings {
		if v == "***" {
			if old, ok := existingSettings[k]; ok {
				req.Settings[k] = old
			}
		}
	}
	settingsJSON, _ := json.Marshal(req.Settings)
	ct, err := h.db.Exec(r.Context(),
		`UPDATE ticketing_configs SET name=$1, enabled=$2, auto_create=$3, auto_update=$4,
		        auto_close=$5, settings=$6, updated_at=NOW() WHERE id=$7`,
		req.Name, req.Enabled, req.AutoCreate, req.AutoUpdate, req.AutoClose, settingsJSON, id)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if ct.RowsAffected() == 0 {
		jsonError(w, "config not found", http.StatusNotFound)
		return
	}
	if h.ticketing != nil {
		_ = h.ticketing.Reload(r.Context())
	}
	h.auditLog(r, "ticketing.config_updated", id, nil, "ok")
	respond(w, map[string]any{"status": "ok"})
}

// DeleteTicketingConfig deletes a connector config.
// DELETE /api/ticketing/configs/{id}
func (h *Handler) DeleteTicketingConfig(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	ct, err := h.db.Exec(r.Context(), `DELETE FROM ticketing_configs WHERE id=$1`, id)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if ct.RowsAffected() == 0 {
		jsonError(w, "config not found", http.StatusNotFound)
		return
	}
	if h.ticketing != nil {
		_ = h.ticketing.Reload(r.Context())
	}
	h.auditLog(r, "ticketing.config_deleted", id, nil, "ok")
	respond(w, map[string]any{"status": "ok"})
}

// TestTicketingConfig tests connectivity for a saved connector.
// POST /api/ticketing/configs/{id}/test
func (h *Handler) TestTicketingConfig(w http.ResponseWriter, r *http.Request) {
	if h.ticketing == nil {
		jsonError(w, "ticketing not configured", http.StatusServiceUnavailable)
		return
	}
	id := chi.URLParam(r, "id")
	if err := h.ticketing.TestConnector(r.Context(), id); err != nil {
		respond(w, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	respond(w, map[string]any{"ok": true})
}

// ProbeTicketingConfig tests connectivity from inline (unsaved) settings.
// POST /api/ticketing/probe  body: {provider, settings}
// Lets the UI test credentials from the form without saving first.
func (h *Handler) ProbeTicketingConfig(w http.ResponseWriter, r *http.Request) {
	if h.ticketing == nil {
		jsonError(w, "ticketing not configured", http.StatusServiceUnavailable)
		return
	}
	var req struct {
		Provider string            `json:"provider"`
		Settings map[string]string `json:"settings"`
	}
	if json.NewDecoder(r.Body).Decode(&req) != nil || req.Provider == "" {
		jsonError(w, "provider is required", http.StatusBadRequest)
		return
	}
	if req.Settings == nil {
		req.Settings = map[string]string{}
	}
	if err := h.ticketing.ProbeConnector(r.Context(), req.Provider, req.Settings); err != nil {
		respond(w, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	respond(w, map[string]any{"ok": true})
}

// ProbeListProjects returns the project list from inline (unsaved) credentials.
// POST /api/ticketing/probe/projects  body: {provider, settings}
func (h *Handler) ProbeListProjects(w http.ResponseWriter, r *http.Request) {
	if h.ticketing == nil {
		jsonError(w, "ticketing not configured", http.StatusServiceUnavailable)
		return
	}
	var req struct {
		Provider string            `json:"provider"`
		Settings map[string]string `json:"settings"`
	}
	if json.NewDecoder(r.Body).Decode(&req) != nil || req.Provider == "" {
		jsonError(w, "provider is required", http.StatusBadRequest)
		return
	}
	if req.Settings == nil {
		req.Settings = map[string]string{}
	}
	projects, err := h.ticketing.ProbeListProjects(r.Context(), req.Provider, req.Settings)
	if err != nil {
		respond(w, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	respond(w, map[string]any{"ok": true, "projects": projects})
}

// ── Candidates + Push (Analyst+) ─────────────────────────────────────────────

// ListTicketCandidates returns open/triaged findings not yet in any active ticket.
// GET /api/ticketing/candidates
func (h *Handler) ListTicketCandidates(w http.ResponseWriter, r *http.Request) {
	if h.ticketing == nil {
		respond(w, []any{})
		return
	}
	candidates, err := h.ticketing.Candidates(r.Context())
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if candidates == nil {
		candidates = []map[string]any{}
	}
	respond(w, candidates)
}

// PushFindingToITSM manually pushes a finding to an ITSM connector.
// POST /api/ticketing/push
// body: {findingId, configId, recordType}
func (h *Handler) PushFindingToITSM(w http.ResponseWriter, r *http.Request) {
	if h.ticketing == nil {
		jsonError(w, "no ITSM connectors configured", http.StatusServiceUnavailable)
		return
	}
	var req struct {
		FindingID  string `json:"findingId"`
		ConfigID   string `json:"configId"`
		RecordType string `json:"recordType"`
	}
	if json.NewDecoder(r.Body).Decode(&req) != nil || req.FindingID == "" || req.ConfigID == "" {
		jsonError(w, "findingId and configId are required", http.StatusBadRequest)
		return
	}
	rt := ticketing.RecordType(req.RecordType)
	if rt == "" {
		rt = ticketing.RecordIncident
	}
	if !ticketing.ValidRecordType(rt) {
		jsonError(w, "invalid recordType", http.StatusBadRequest)
		return
	}
	ref, err := h.ticketing.PushFinding(r.Context(), req.ConfigID, req.FindingID, rt)
	if err != nil {
		jsonError(w, err.Error(), http.StatusBadGateway)
		return
	}
	h.auditLog(r, "ticketing.pushed", req.FindingID,
		map[string]any{"configId": req.ConfigID, "ticketId": ref.TicketID, "recordType": string(rt)}, "ok")
	respond(w, map[string]any{"ticketId": ref.TicketID, "ticketUrl": ref.TicketURL})
}

// BulkPushToITSM pushes multiple findings to one connector.
// POST /api/ticketing/push/bulk
// body: {findingIds: [...], configId, recordType}
func (h *Handler) BulkPushToITSM(w http.ResponseWriter, r *http.Request) {
	if h.ticketing == nil {
		jsonError(w, "no ITSM connectors configured", http.StatusServiceUnavailable)
		return
	}
	var req struct {
		FindingIDs []string `json:"findingIds"`
		ConfigID   string   `json:"configId"`
		RecordType string   `json:"recordType"`
	}
	if json.NewDecoder(r.Body).Decode(&req) != nil || len(req.FindingIDs) == 0 || req.ConfigID == "" {
		jsonError(w, "findingIds and configId are required", http.StatusBadRequest)
		return
	}
	rt := ticketing.RecordType(req.RecordType)
	if rt == "" {
		rt = ticketing.RecordIncident
	}
	if !ticketing.ValidRecordType(rt) {
		jsonError(w, "invalid recordType", http.StatusBadRequest)
		return
	}
	type result struct {
		FindingID string `json:"findingId"`
		TicketID  string `json:"ticketId,omitempty"`
		TicketURL string `json:"ticketUrl,omitempty"`
		Error     string `json:"error,omitempty"`
	}
	results := make([]result, 0, len(req.FindingIDs))
	for _, fid := range req.FindingIDs {
		ref, err := h.ticketing.PushFinding(r.Context(), req.ConfigID, fid, rt)
		if err != nil {
			results = append(results, result{FindingID: fid, Error: err.Error()})
		} else {
			results = append(results, result{FindingID: fid, TicketID: ref.TicketID, TicketURL: ref.TicketURL})
		}
	}
	h.auditLog(r, "ticketing.bulk_pushed", "",
		map[string]any{"configId": req.ConfigID, "count": len(req.FindingIDs)}, "ok")
	respond(w, results)
}

// ── Finding ticket lookup (Analyst+) ─────────────────────────────────────────

// GetFindingTickets returns ITSM tickets for a specific finding.
// GET /api/findings/{id}/tickets
func (h *Handler) GetFindingTickets(w http.ResponseWriter, r *http.Request) {
	findingID := chi.URLParam(r, "id")
	if h.ticketing == nil {
		respond(w, []any{})
		return
	}
	tickets, err := h.ticketing.ListTicketsForFinding(r.Context(), findingID)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if tickets == nil {
		tickets = []map[string]any{}
	}
	respond(w, tickets)
}

// ── Manual sync (Admin only) ──────────────────────────────────────────────────

// TriggerTicketingSync kicks off an immediate status-sync cycle.
// POST /api/ticketing/sync
func (h *Handler) TriggerTicketingSync(w http.ResponseWriter, r *http.Request) {
	if h.ticketing == nil {
		jsonError(w, "ticketing not configured", http.StatusServiceUnavailable)
		return
	}
	h.ticketing.SyncNow(r.Context())
	h.auditLog(r, "ticketing.sync_triggered", "", nil, "ok")
	respond(w, map[string]any{"status": "sync started"})
}

// ── Inbound webhook from ITSM (no JWT auth — HMAC verified in manager) ───────

// ReceiveTicketingWebhook accepts push notifications from ServiceNow/Jira.
// POST /api/ticketing/webhook/{configId}
// When an external ticket is resolved, sets revalidation_required on the
// corresponding finding_ticket row so the next BAS run can confirm it.
func (h *Handler) ReceiveTicketingWebhook(w http.ResponseWriter, r *http.Request) {
	configID := chi.URLParam(r, "configId")

	var payload struct {
		TicketID string `json:"ticketId"`
		State    string `json:"state"`   // resolved | reopened | updated
		Number   string `json:"number"`  // ServiceNow record number
		Key      string `json:"key"`     // Jira issue key
	}
	if json.NewDecoder(r.Body).Decode(&payload) != nil {
		w.WriteHeader(http.StatusOK) // don't reveal parse errors to external systems
		return
	}

	ticketID := payload.TicketID
	if ticketID == "" {
		ticketID = payload.Key // Jira
	}
	if ticketID == "" || configID == "" {
		w.WriteHeader(http.StatusOK)
		return
	}

	ctx := r.Context()
	switch payload.State {
	case "resolved", "closed":
		h.db.Exec(ctx,
			`UPDATE finding_tickets SET status='resolved', revalidation_required=true, last_synced_at=NOW()
			  WHERE ticket_id=$1 AND config_id=$2`, ticketID, configID)
	case "reopened", "open":
		h.db.Exec(ctx,
			`UPDATE finding_tickets SET status='open', revalidation_required=false, last_synced_at=NOW()
			  WHERE ticket_id=$1 AND config_id=$2`, ticketID, configID)
	}
	w.WriteHeader(http.StatusOK)
}

// ── Revalidation status helper ────────────────────────────────────────────────

// TicketingSummary returns dashboard-level ticket stats (open/resolved/revalidation + per-provider).
// GET /api/ticketing/summary
func (h *Handler) TicketingSummary(w http.ResponseWriter, r *http.Request) {
	if h.ticketing == nil {
		respond(w, map[string]any{"openTickets": 0, "resolvedTickets": 0, "pendingRevalidation": 0, "byProvider": []any{}})
		return
	}
	summary, err := h.ticketing.Summary(r.Context())
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respond(w, summary)
}

// revalidationStatus returns pending-revalidation count for the dashboard.
// Findings where an ITSM ticket was resolved but BAS hasn't re-confirmed yet.
func (h *Handler) RevalidationStatus(w http.ResponseWriter, r *http.Request) {
	var count int
	h.db.QueryRow(r.Context(),
		`SELECT COUNT(*) FROM finding_tickets WHERE revalidation_required=true AND status='resolved'`,
	).Scan(&count)
	respond(w, map[string]any{"pendingRevalidation": count, "checkedAt": time.Now()})
}
