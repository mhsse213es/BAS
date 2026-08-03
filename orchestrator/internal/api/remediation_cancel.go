package api

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/remediation"
)

// POST /api/remediation-requests/{requestId}/cancel
func (h *Handler) CancelRemediation(w http.ResponseWriter, r *http.Request) {
	requestID := chi.URLParam(r, "requestId")
	req, err := h.scanRemediationRequest(r.Context(), requestID)
	if err != nil {
		jsonError(w, "remediation request not found", http.StatusNotFound)
		return
	}
	if req.Tier == remediation.TierConfirmRequired {
		claims, _ := auth.ClaimsFrom(r.Context())
		if claims == nil || !auth.HasPermission(claims.Role, auth.CanApproveRemediation) {
			jsonError(w, "this remediation requires an Administrator to cancel", http.StatusForbidden)
			return
		}
	}
	runID := req.VerifyRunID
	if runID == "" {
		runID = req.FixRunID
	}
	if runID == "" {
		jsonError(w, "nothing in flight to cancel", http.StatusConflict)
		return
	}
	if _, _, cancelErr := h.cancelScenarioRun(r.Context(), runID); cancelErr != nil && cancelErr != errRunNotRunning {
		jsonError(w, cancelErr.Error(), http.StatusInternalServerError)
		return
	}
	h.db.Exec(r.Context(), `UPDATE remediation_requests SET status=$1 WHERE id=$2`, remediation.StatusCancelled, requestID)
	h.auditLog(r, "remediation.cancel", requestID, map[string]any{"remediationId": req.RemediationID, "agentId": req.AgentID}, "ok")
	respond(w, map[string]string{"requestId": requestID, "status": remediation.StatusCancelled})
}
