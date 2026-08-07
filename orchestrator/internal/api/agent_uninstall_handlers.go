package api

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/models"
)

// POST /api/agents/{agentId}/uninstall — dispatches a real uninstall order
// to a connected agent and marks the record 'uninstalling' until the
// endpoint confirms success or failure via UninstallAgentResult below.
// Unlike RemoveAgent (Force Remove), this requires a live connection and
// never silently claims the endpoint is gone. Admin-only; the route group
// enforces the permission check.
func (h *Handler) UninstallAgent(w http.ResponseWriter, r *http.Request) {
	agentID := chi.URLParam(r, "agentId")
	var body struct {
		Reason string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || strings.TrimSpace(body.Reason) == "" {
		jsonError(w, "reason is required", http.StatusBadRequest)
		return
	}

	var priorState string
	if err := h.db.QueryRow(r.Context(),
		`SELECT COALESCE(state, 'active') FROM agents WHERE agent_id = $1`, agentID,
	).Scan(&priorState); err != nil {
		jsonError(w, "agent not found", http.StatusNotFound)
		return
	}

	sent := h.hub.SendToAgent(agentID, models.WSMessage{
		Type:    models.MsgCommandUninstallAgent,
		AgentID: agentID,
		Data:    map[string]string{"reason": body.Reason},
	})
	if !sent {
		jsonError(w, "agent not connected — cannot verify uninstall. Retry once it reconnects, or use Force Remove for a permanently unavailable device.", http.StatusServiceUnavailable)
		return
	}

	actorID := ""
	if claims, ok := auth.ClaimsFrom(r.Context()); ok {
		actorID = claims.UserID
	}
	_, err := h.db.Exec(r.Context(),
		`UPDATE agents SET state = 'uninstalling', uninstall_requested_by = $1, uninstall_requested_at = NOW(),
		        uninstall_reason = $2, uninstall_prior_state = $3, uninstall_error = NULL, uninstall_error_at = NULL
		 WHERE agent_id = $4`,
		actorID, body.Reason, priorState, agentID)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	h.auditLog(r, "agent.uninstall", agentID, map[string]any{"reason": body.Reason}, "ok")
	h.hub.BroadcastBrowsers(models.WSMessage{Type: models.MsgAgentUpdate, AgentID: agentID})
	respond(w, map[string]any{"agentId": agentID, "status": "uninstall_dispatched"})
}

// POST /api/agents/{agentId}/uninstall-result — the agent's own report of
// whether command_uninstall_agent actually succeeded on the endpoint.
// Agent-token authenticated (same as UnenrollAgent), not a user JWT -- there
// is no admin session at this point. Applied whenever it arrives, no matter
// how long dispatch was ago (idempotent, at-least-once delivery -- matches
// UnenrollAgent's own convention).
func (h *Handler) UninstallAgentResult(w http.ResponseWriter, r *http.Request) {
	if !h.validateAgentAuth(r) {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	agentID := chi.URLParam(r, "agentId")
	var body struct {
		Success bool   `json:"success"`
		Error   string `json:"error"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, "invalid JSON body", http.StatusBadRequest)
		return
	}

	var err error
	if body.Success {
		_, err = h.db.Exec(r.Context(),
			`UPDATE agents SET state = 'uninstalled', uninstall_error = NULL, uninstall_error_at = NULL WHERE agent_id = $1`,
			agentID)
	} else {
		_, err = h.db.Exec(r.Context(),
			`UPDATE agents SET state = COALESCE(uninstall_prior_state, 'active'), uninstall_error = $1, uninstall_error_at = NOW()
			 WHERE agent_id = $2`,
			body.Error, agentID)
	}
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	h.auditLogAs(r, "agent:"+agentID, "agent.uninstall_result", agentID,
		map[string]any{"success": body.Success, "error": body.Error}, "ok")
	h.hub.BroadcastBrowsers(models.WSMessage{Type: models.MsgAgentUpdate, AgentID: agentID})
	respond(w, map[string]any{"agentId": agentID, "success": body.Success})
}
