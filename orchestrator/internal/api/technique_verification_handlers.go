package api

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/audspect/bas/internal/auth"
)

// POST /api/remediation-requests/{requestId}/verify-technique
// Requires CanRunScenario (Analyst+Admin) -- reused, not a new permission:
// this endpoint mechanically IS "run an ART technique against an agent",
// the exact action CanRunScenario already gates everywhere else.
func (h *Handler) VerifyTechnique(w http.ResponseWriter, r *http.Request) {
	requestID := chi.URLParam(r, "requestId")
	req, err := h.scanRemediationRequest(r.Context(), requestID)
	if err != nil {
		jsonError(w, "remediation request not found", http.StatusNotFound)
		return
	}
	if req.Status != "completed" {
		jsonError(w, "can only verify a technique after the remediation is completed", http.StatusConflict)
		return
	}
	if !h.EligibleForBASVerification(req.CheckID) {
		jsonError(w, "this check has no mapped ATT&CK technique -- not eligible for BAS verification", http.StatusUnprocessableEntity)
		return
	}
	var alreadyExists bool
	h.db.QueryRow(r.Context(),
		`SELECT EXISTS(SELECT 1 FROM technique_verification_runs WHERE request_id=$1)`, requestID,
	).Scan(&alreadyExists)
	if alreadyExists {
		jsonError(w, "a technique verification has already been requested for this remediation", http.StatusConflict)
		return
	}

	step, _ := h.findStepByCheckID(req.CheckID)

	actorID := ""
	if claims, ok := auth.ClaimsFrom(r.Context()); ok && claims != nil {
		actorID = claims.UserID
	}
	techVerifyID := newID()
	if _, err := h.db.Exec(r.Context(),
		`INSERT INTO technique_verification_runs (id, request_id, agent_id, check_id, technique_id, status, requested_by)
		 VALUES ($1,$2,$3,$4,$5,'requested',$6)`,
		techVerifyID, requestID, req.AgentID, req.CheckID, step.TechniqueID, actorID,
	); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	runID, sent, err := h.dispatchTechniqueVerification(r.Context(), req.AgentID, step.TechniqueID)
	if err != nil {
		h.db.Exec(r.Context(), `UPDATE technique_verification_runs SET status='error', reason=$1 WHERE id=$2`, err.Error(), techVerifyID)
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !sent {
		h.db.Exec(r.Context(), `UPDATE technique_verification_runs SET status='error', reason='agent not connected' WHERE id=$1`, techVerifyID)
		h.auditLog(r, "remediation.verify_technique", techVerifyID, map[string]any{"requestId": requestID, "techniqueId": step.TechniqueID}, "failed")
		respond(w, map[string]string{"techniqueVerificationId": techVerifyID, "status": "error"})
		return
	}
	h.db.Exec(r.Context(),
		`UPDATE technique_verification_runs SET status='dispatched', run_id=$1, dispatched_at=NOW() WHERE id=$2`,
		runID, techVerifyID)
	h.auditLog(r, "remediation.verify_technique", techVerifyID, map[string]any{"requestId": requestID, "techniqueId": step.TechniqueID}, "dispatched")
	respond(w, map[string]string{"techniqueVerificationId": techVerifyID, "status": "dispatched"})
}
