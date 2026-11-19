package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
)

const (
	reinstallDefaultHours = 24
	reinstallMaxHours     = 72
)

// POST /api/agents/{agentId}/allow-reinstall -- an administrator approves ONE fresh install for a host the
// server still shows as live (for example its agent broke and lost its keys). While the approval is open, a
// bootstrap with the shared secret may replace that host's certificates; EnrollCSR clears the approval when it
// is used, so it works once, for this host only, and then expires on its own. Without it the secret alone
// cannot replace a live host (audit F-03). Admin-only; the route group enforces the permission.
func (h *Handler) AllowAgentReinstall(w http.ResponseWriter, r *http.Request) {
	agentID := chi.URLParam(r, "agentId")
	var body struct {
		Reason string `json:"reason"`
		Hours  *int   `json:"hours"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || strings.TrimSpace(body.Reason) == "" {
		jsonError(w, "reason is required", http.StatusBadRequest)
		return
	}
	hours := reinstallDefaultHours
	if body.Hours != nil {
		hours = *body.Hours
		if hours < 1 || hours > reinstallMaxHours {
			jsonError(w, "hours must be between 1 and 72", http.StatusBadRequest)
			return
		}
	}

	var state string
	if err := h.db.QueryRow(r.Context(), `SELECT COALESCE(state, 'active') FROM agents WHERE agent_id = $1`, agentID).Scan(&state); err != nil {
		jsonError(w, "agent not found", http.StatusNotFound)
		return
	}
	if state == AgentStateRevoked {
		jsonError(w, "this agent has been revoked — reinstate it before approving a reinstall", http.StatusConflict)
		return
	}

	var until time.Time
	if err := h.db.QueryRow(r.Context(),
		`UPDATE agents SET reinstall_allowed_until = NOW() + make_interval(hours => $2) WHERE agent_id = $1 RETURNING reinstall_allowed_until`,
		agentID, hours).Scan(&until); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.auditLog(r, "agent.allow_reinstall", agentID, map[string]any{"reason": strings.TrimSpace(body.Reason), "until": until}, "ok")
	respond(w, map[string]any{"agentId": agentID, "reinstallAllowedUntil": until})
}
