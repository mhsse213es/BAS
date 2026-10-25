package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/killchain"
)

// hostEventMaxBatch bounds one batch. The agent caps its collection to the same
// order of magnitude, so a larger batch means something is wrong.
const hostEventMaxBatch = 5000

// allowedHostEventIDs are the only Security events the orchestrator accepts.
var allowedHostEventIDs = map[int]bool{4688: true, 4624: true, 4648: true}

// SubmitRunHostEvents stores an agent's Security events for a run and its audit
// state. Agent-authed. The batch must come from the agent that ran the scenario,
// and it may only carry the required event IDs. Re-delivery replaces the run's
// events.
// POST /api/scenarios/runs/{runId}/host-events
func (h *Handler) SubmitRunHostEvents(w http.ResponseWriter, r *http.Request) {
	if !h.validateAgentAuth(r) {
		jsonError(w, "unauthorized — check AGENT_SECRET", http.StatusUnauthorized)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 8<<20)
	var body struct {
		AgentID string `json:"agentId"`
		Events  []struct {
			RecordID    uint64    `json:"recordId"`
			EventID     int       `json:"eventId"`
			Host        string    `json:"host"`
			Time        time.Time `json:"ts"`
			Subject     string    `json:"subject"`
			NewProcess  string    `json:"newProcess"`
			CommandLine string    `json:"commandLine"`
			LogonType   int       `json:"logonType"`
			TargetUser  string    `json:"targetUser"`
		} `json:"events"`
		Audit struct {
			ProcessCreation string `json:"processCreation"`
			Logon           string `json:"logon"`
			CommandLine     string `json:"commandLine"`
		} `json:"audit"`
		WindowFrom time.Time `json:"windowFrom"`
		WindowTo   time.Time `json:"windowTo"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, "invalid host events payload", http.StatusBadRequest)
		return
	}
	if !agentMatchesCertificate(w, r, body.AgentID) {
		return
	}
	store := h.killChainStore()
	if store == nil {
		jsonError(w, "database not configured", http.StatusServiceUnavailable)
		return
	}
	if len(body.Events) > hostEventMaxBatch {
		jsonError(w, fmt.Sprintf("batch exceeds %d events", hostEventMaxBatch), http.StatusBadRequest)
		return
	}
	events := make([]killchain.HostEvent, 0, len(body.Events))
	for _, e := range body.Events {
		if !allowedHostEventIDs[e.EventID] {
			jsonError(w, fmt.Sprintf("event id %d is outside the required set", e.EventID), http.StatusBadRequest)
			return
		}
		events = append(events, killchain.HostEvent{
			RecordID: e.RecordID, EventID: e.EventID, Host: e.Host, Time: e.Time,
			Subject: e.Subject, NewProcess: e.NewProcess, CommandLine: e.CommandLine,
			LogonType: e.LogonType, TargetUser: e.TargetUser,
		})
	}

	runID := chi.URLParam(r, "runId")
	var runAgent string
	if err := h.db.QueryRow(r.Context(), `SELECT agent_id FROM scenario_runs WHERE id = $1`, runID).Scan(&runAgent); err != nil {
		jsonError(w, "run not found", http.StatusNotFound)
		return
	}
	if body.AgentID == "" || body.AgentID != runAgent {
		jsonError(w, "host events must come from the agent that ran this scenario", http.StatusForbidden)
		return
	}

	audit := killchain.AuditState{
		ProcessCreation: normalizeAuditSetting(body.Audit.ProcessCreation),
		Logon:           normalizeAuditSetting(body.Audit.Logon),
		CommandLine:     normalizeAuditSetting(body.Audit.CommandLine),
	}
	win := db.HostEventWindow{From: body.WindowFrom, To: body.WindowTo}
	if err := store.PutHostEvents(r.Context(), runID, events, audit, win); err != nil {
		jsonError(w, "could not store host events", http.StatusInternalServerError)
		return
	}
	h.auditLog(r, "killchain.host_events.submit", runID, map[string]any{"events": len(events)}, "success")
	w.WriteHeader(http.StatusCreated)
	jsonOK(w, map[string]any{"runId": runID, "stored": len(events)})
}

// normalizeAuditSetting keeps only the two known settings. Anything else is
// unknown, which is never read as disabled.
func normalizeAuditSetting(s string) killchain.AuditSetting {
	switch s {
	case string(killchain.AuditEnabled), string(killchain.AuditDisabled):
		return killchain.AuditSetting(s)
	default:
		return killchain.AuditUnknown
	}
}
