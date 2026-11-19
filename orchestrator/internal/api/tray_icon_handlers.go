package api

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/models"
)

// Tray-icon visibility. The Windows agent shows a notification-area icon so the person at the endpoint can see
// that the agent is installed. An administrator can hide it for the whole fleet (a default) or for one agent
// (an override). The effective value reaches each agent in every heartbeat response as policy.hideTrayIcon:
//
//	override (agents.tray_hidden, NULL = none)  >  fleet default (fleet_settings 'tray_icon')  >  visible
//
// Hiding the icon removes the endpoint user's local view of the agent, so every change is audited. The override
// lives in its own column, not policy_json, because re-enrolling an agent rewrites policy_json.

// fleetTrayIconKey is the fleet_settings row holding the fleet-wide default ({"hidden": bool}).
const fleetTrayIconKey = "tray_icon"

// effectiveTrayHidden resolves the value an agent is told: its own override if set, else the fleet default.
func effectiveTrayHidden(override *bool, fleetDefault bool) bool {
	if override != nil {
		return *override
	}
	return fleetDefault
}

// PUT /api/agents/{agentId}/tray-icon   body {"hidden": true|false|null}
// true hides this agent's tray icon, false forces it visible, null clears the override so the agent follows the
// fleet default again. Admin-only (route group).
func (h *Handler) SetAgentTrayIcon(w http.ResponseWriter, r *http.Request) {
	agentID := chi.URLParam(r, "agentId")
	var raw map[string]json.RawMessage
	if err := json.NewDecoder(r.Body).Decode(&raw); err != nil {
		jsonError(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	field, present := raw["hidden"]
	if !present {
		jsonError(w, `"hidden" is required: true, false or null`, http.StatusBadRequest)
		return
	}
	var override *bool
	if string(field) != "null" {
		var b bool
		if err := json.Unmarshal(field, &b); err != nil {
			jsonError(w, `"hidden" must be true, false or null`, http.StatusBadRequest)
			return
		}
		override = &b
	}
	tag, err := h.db.Exec(r.Context(), `UPDATE agents SET tray_hidden = $1 WHERE agent_id = $2`, override, agentID)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if tag.RowsAffected() == 0 {
		jsonError(w, "agent not found", http.StatusNotFound)
		return
	}
	h.auditLog(r, "agent.tray_icon", agentID, map[string]any{"hidden": override}, "ok")
	h.hub.BroadcastBrowsers(models.WSMessage{Type: models.MsgAgentUpdate, AgentID: agentID})
	respond(w, map[string]any{"agentId": agentID, "hidden": override})
}

// PUT /api/fleet/tray-icon   body {"hidden": true|false}
// Sets the default for every agent without its own override. Admin-only (route group).
func (h *Handler) SetFleetTrayIcon(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Hidden *bool `json:"hidden"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Hidden == nil {
		jsonError(w, `"hidden" is required: true or false`, http.StatusBadRequest)
		return
	}
	actorID := ""
	if claims, ok := auth.ClaimsFrom(r.Context()); ok {
		actorID = claims.UserID
	}
	value, _ := json.Marshal(map[string]bool{"hidden": *body.Hidden})
	if _, err := h.db.Exec(r.Context(), `
		INSERT INTO fleet_settings (key, value, updated_by, updated_at) VALUES ($1, $2, $3, NOW())
		ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_by = EXCLUDED.updated_by, updated_at = NOW()`,
		fleetTrayIconKey, value, actorID); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.auditLog(r, "fleet.tray_icon", "fleet", map[string]any{"hidden": *body.Hidden}, "ok")
	h.hub.BroadcastBrowsers(models.WSMessage{Type: models.MsgAgentUpdate})
	respond(w, map[string]any{"hidden": *body.Hidden})
}

// GET /api/fleet/tray-icon   -> {"hidden": bool}. Any signed-in user; the console uses it to label its control.
func (h *Handler) GetFleetTrayIcon(w http.ResponseWriter, r *http.Request) {
	var hidden bool
	if err := h.db.QueryRow(r.Context(), `
		SELECT COALESCE((SELECT (value->>'hidden')::boolean FROM fleet_settings WHERE key = $1), false)`,
		fleetTrayIconKey).Scan(&hidden); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respond(w, map[string]any{"hidden": hidden})
}
