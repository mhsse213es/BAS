package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/audspect/bas/internal/models"
)

// AgentStateRevoked is the agents.state of an agent whose certificates were revoked on purpose.
const AgentStateRevoked = "revoked"

// POST /api/agents/{agentId}/revoke -- revokes every certificate of one agent and blocks it, without
// touching the deployment CA or any other agent. Takes effect at the next TLS handshake and
// immediately drops the agent's live connection. Admin-only; the route group enforces the permission.
func (h *Handler) RevokeAgent(w http.ResponseWriter, r *http.Request) {
	agentID := chi.URLParam(r, "agentId")
	var body struct {
		Reason string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || strings.TrimSpace(body.Reason) == "" {
		jsonError(w, "reason is required", http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	tx, err := h.db.Begin(ctx)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer tx.Rollback(ctx)

	// Same per-agent lock as EnrollCSR, so a concurrent enrolment cannot slip a new certificate in.
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('agent_certificates:' || $1, 0))`, agentID); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	tag, err := tx.Exec(ctx, `UPDATE agents SET state = $2 WHERE agent_id = $1`, agentID, AgentStateRevoked)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if tag.RowsAffected() == 0 {
		jsonError(w, "agent not found", http.StatusNotFound)
		return
	}
	certs, err := tx.Exec(ctx,
		`UPDATE agent_certificates SET revoked = true, revoked_at = NOW() WHERE agent_id = $1 AND revoked = false`, agentID)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	dropped := h.hub.DisconnectAgent(agentID)
	h.auditLog(r, "agent.revoke", agentID,
		map[string]any{"reason": body.Reason, "certificatesRevoked": certs.RowsAffected(), "connectionDropped": dropped}, "ok")
	h.hub.BroadcastBrowsers(models.WSMessage{Type: models.MsgAgentUpdate, AgentID: agentID})
	respond(w, map[string]any{"agentId": agentID, "state": AgentStateRevoked, "certificatesRevoked": certs.RowsAffected()})
}

// POST /api/agents/{agentId}/reinstate -- lets a revoked agent enrol again. Its old certificates stay
// revoked; the agent must enrol afresh (reinstall, or reset its enrolment). Admin-only.
func (h *Handler) ReinstateAgent(w http.ResponseWriter, r *http.Request) {
	agentID := chi.URLParam(r, "agentId")
	var body struct {
		Reason string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || strings.TrimSpace(body.Reason) == "" {
		jsonError(w, "reason is required", http.StatusBadRequest)
		return
	}
	tag, err := h.db.Exec(r.Context(),
		`UPDATE agents SET state = 'active' WHERE agent_id = $1 AND state = $2`, agentID, AgentStateRevoked)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if tag.RowsAffected() == 0 {
		jsonError(w, "agent is not revoked", http.StatusConflict)
		return
	}
	h.auditLog(r, "agent.reinstate", agentID, map[string]any{"reason": body.Reason}, "ok")
	h.hub.BroadcastBrowsers(models.WSMessage{Type: models.MsgAgentUpdate, AgentID: agentID})
	respond(w, map[string]string{"agentId": agentID, "state": "active"})
}

// AgentCertRevoked is the pki.RevocationCheck for the agent listener: true when this serial was
// revoked, or when the agent itself is revoked (whatever certificate it presents). A database error
// is returned so the caller refuses the connection.
func (h *Handler) AgentCertRevoked(ctx context.Context, serial, agentID string) (bool, error) {
	var revoked bool
	err := h.db.QueryRow(ctx, `
		SELECT EXISTS (SELECT 1 FROM agent_certificates WHERE serial_number = $1 AND revoked = true)
		    OR EXISTS (SELECT 1 FROM agents WHERE agent_id = $2 AND state = $3)`,
		serial, agentID, AgentStateRevoked).Scan(&revoked)
	return revoked, err
}
