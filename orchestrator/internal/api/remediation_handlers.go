package api

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/remediation"
)

// POST /api/agents/{agentId}/remediations
func (h *Handler) ExecuteRemediation(w http.ResponseWriter, r *http.Request) {
	agentID := chi.URLParam(r, "agentId")
	var req struct {
		RemediationID        string `json:"remediationId"`
		Reason               string `json:"reason"`
		ContinuousValidation bool   `json:"continuousValidation"`
	}
	if json.NewDecoder(r.Body).Decode(&req) != nil || req.RemediationID == "" {
		jsonError(w, "remediationId is required", http.StatusBadRequest)
		return
	}
	if req.Reason == "" {
		jsonError(w, "reason is required", http.StatusBadRequest)
		return
	}
	if h.remediationCatalog == nil {
		jsonError(w, "remediation catalog not loaded", http.StatusServiceUnavailable)
		return
	}
	entry, ok := h.remediationCatalog.ByID(req.RemediationID)
	if !ok {
		jsonError(w, "unknown remediationId", http.StatusNotFound)
		return
	}
	if entry.Tier == remediation.TierManualGuidance {
		jsonError(w, "this remediation is manual guidance only -- no automatic execution", http.StatusUnprocessableEntity)
		return
	}

	claims, _ := auth.ClaimsFrom(r.Context())
	if entry.Tier == remediation.TierConfirmRequired && (claims == nil || !auth.HasPermission(claims.Role, auth.CanApproveRemediation)) {
		jsonError(w, "this remediation requires an Administrator", http.StatusForbidden)
		return
	}

	var agentExists bool
	var agentOS string
	h.db.QueryRow(r.Context(), `SELECT true, COALESCE(os_version,'') FROM agents WHERE agent_id=$1`, agentID).Scan(&agentExists, &agentOS)
	if !agentExists {
		jsonError(w, "agent not found", http.StatusNotFound)
		return
	}
	if !remediation.OSSupported(agentOS, entry) {
		jsonError(w, "remediation not supported on this endpoint's OS", http.StatusUnprocessableEntity)
		return
	}

	allResults := h.aggregateAgentResults(r.Context(), agentID)
	if latestCheckIsPassing(allResults, entry.CheckID) {
		jsonError(w, "already compliant -- nothing to fix", http.StatusConflict)
		return
	}

	actorID := ""
	if claims != nil {
		actorID = claims.UserID
	}
	approvedBy := ""
	if entry.Tier == remediation.TierConfirmRequired {
		approvedBy = actorID
	}
	requestID := newID()
	if _, err := h.db.Exec(r.Context(),
		`INSERT INTO remediation_requests (id, remediation_id, agent_id, check_id, tier, status, requested_by, approved_by, reason, rollback_available, continuous_validation)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
		requestID, entry.ID, agentID, entry.CheckID, int(entry.Tier), remediation.StatusRequested, actorID, approvedBy, req.Reason, entry.SupportsRollback, req.ContinuousValidation,
	); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	timeoutSec := entry.EstimatedTimeSec * 2
	if timeoutSec == 0 {
		timeoutSec = 60
	}
	runID, sent, err := h.dispatchRemediationStep(r.Context(), agentID, "remediation-fix", entry.ID, entry.Command, entry.Executor, timeoutSec)
	if err != nil {
		h.db.Exec(r.Context(), `UPDATE remediation_requests SET status=$1, error=$2 WHERE id=$3`, remediation.StatusFailed, err.Error(), requestID)
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !sent {
		h.db.Exec(r.Context(), `UPDATE remediation_requests SET status=$1, error='agent not connected' WHERE id=$2`, remediation.StatusFailed, requestID)
		h.auditLog(r, "remediation.execute", requestID, map[string]any{"remediationId": entry.ID, "agentId": agentID}, "failed")
		respond(w, map[string]string{"requestId": requestID, "status": remediation.StatusFailed})
		return
	}
	h.db.Exec(r.Context(),
		`UPDATE remediation_requests SET status=$1, fix_run_id=$2, dispatched_at=NOW() WHERE id=$3`,
		remediation.StatusDispatched, runID, requestID)
	h.auditLog(r, "remediation.execute", requestID, map[string]any{"remediationId": entry.ID, "agentId": agentID, "tier": int(entry.Tier)}, "dispatched")
	respond(w, map[string]string{"requestId": requestID, "status": remediation.StatusDispatched})
}
