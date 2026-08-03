package api

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/audspect/bas/internal/remediation"
)

// POST /api/remediation-requests/{requestId}/rollback
// Always requires CanApproveRemediation at the route level (routes.go),
// regardless of the original fix's own tier -- reversing a security
// control is inherently risk-increasing.
func (h *Handler) RollbackRemediation(w http.ResponseWriter, r *http.Request) {
	requestID := chi.URLParam(r, "requestId")
	req, err := h.scanRemediationRequest(r.Context(), requestID)
	if err != nil {
		jsonError(w, "remediation request not found", http.StatusNotFound)
		return
	}
	if req.Status != remediation.StatusCompleted {
		jsonError(w, "can only roll back a completed remediation", http.StatusConflict)
		return
	}
	if !req.RollbackAvailable {
		jsonError(w, "this remediation does not support rollback", http.StatusUnprocessableEntity)
		return
	}
	if req.RollbackStatus != "" {
		jsonError(w, "a rollback has already been requested for this remediation", http.StatusConflict)
		return
	}
	if h.remediationCatalog == nil {
		jsonError(w, "remediation catalog not loaded", http.StatusServiceUnavailable)
		return
	}
	entry, ok := h.remediationCatalog.ByID(req.RemediationID)
	if !ok || entry.RollbackCommand == "" {
		jsonError(w, "rollback command not found in catalog", http.StatusUnprocessableEntity)
		return
	}
	timeoutSec := entry.EstimatedTimeSec * 2
	if timeoutSec == 0 {
		timeoutSec = 60
	}
	runID, sent, dispatchErr := h.dispatchRemediationStep(r.Context(), req.AgentID, "remediation-rollback", entry.ID, entry.RollbackCommand, entry.Executor, timeoutSec)
	if dispatchErr != nil || !sent {
		jsonError(w, "could not dispatch rollback -- agent may be offline", http.StatusServiceUnavailable)
		return
	}
	h.db.Exec(r.Context(),
		`UPDATE remediation_requests SET rollback_status='requested', rollback_run_id=$1 WHERE id=$2`, runID, requestID)
	h.auditLog(r, "remediation.rollback_requested", requestID, map[string]any{"remediationId": entry.ID, "agentId": req.AgentID}, "requested")
	respond(w, map[string]string{"requestId": requestID, "rollbackStatus": "requested"})
}
