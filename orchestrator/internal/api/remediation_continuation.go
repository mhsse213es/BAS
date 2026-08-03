package api

import (
	"net/http"

	"github.com/audspect/bas/internal/models"
	"github.com/audspect/bas/internal/remediation"
)

// continueRemediationFromResult checks whether runID matches an open
// remediation_requests row's fix_run_id/verify_run_id, and if so advances
// that row's state machine. Called synchronously at the end of
// SubmitScenarioResult -- purely additive, a no-op for the vast majority
// of runs with no matching row. Every remediation dispatch (fix, verify)
// is a synthetic 1-step scenario, so simResults has exactly one element on
// success; an empty slice is treated as a failure.
func (h *Handler) continueRemediationFromResult(r *http.Request, runID string, simResults []models.SimulationResult) {
	passed := len(simResults) > 0 && simResults[0].Result == models.ResultPass

	var id string
	if err := h.db.QueryRow(r.Context(),
		`SELECT id FROM remediation_requests WHERE fix_run_id = $1 AND status = 'dispatched'`, runID,
	).Scan(&id); err == nil {
		h.handleRemediationFixResult(r, id, passed)
		return
	}
	if err := h.db.QueryRow(r.Context(),
		`SELECT id FROM remediation_requests WHERE verify_run_id = $1 AND status = 'verifying'`, runID,
	).Scan(&id); err == nil {
		h.handleRemediationVerifyResult(r, id, passed)
	}
}

// handleRemediationFixResult advances a remediation from "dispatched" once
// its fix command's result arrives: on success, dispatches the
// verification check as a second synthetic scenario; on failure, the
// remediation ends here (StatusFailed) -- verification never runs against
// a fix that didn't even execute cleanly.
func (h *Handler) handleRemediationFixResult(r *http.Request, requestID string, passed bool) {
	ctx := r.Context()
	var remediationID, agentID, requestedBy string
	if err := h.db.QueryRow(ctx,
		`SELECT remediation_id, agent_id, requested_by FROM remediation_requests WHERE id=$1`, requestID,
	).Scan(&remediationID, &agentID, &requestedBy); err != nil {
		return
	}
	if !passed {
		h.db.Exec(ctx,
			`UPDATE remediation_requests SET status=$1, error='fix command failed', execution_completed_at=NOW() WHERE id=$2`,
			remediation.StatusFailed, requestID)
		h.auditLogAs(r, requestedBy, "remediation.fix_failed", requestID,
			map[string]any{"remediationId": remediationID, "agentId": agentID}, "failed")
		return
	}
	h.db.Exec(ctx, `UPDATE remediation_requests SET execution_completed_at=NOW() WHERE id=$1`, requestID)

	if h.remediationCatalog == nil {
		h.db.Exec(ctx, `UPDATE remediation_requests SET status=$1, error='remediation catalog not loaded' WHERE id=$2`,
			remediation.StatusFailed, requestID)
		return
	}
	entry, ok := h.remediationCatalog.ByID(remediationID)
	if !ok {
		h.db.Exec(ctx, `UPDATE remediation_requests SET status=$1, error='remediation catalog entry no longer exists' WHERE id=$2`,
			remediation.StatusFailed, requestID)
		return
	}
	verificationCheckID := entry.VerificationCheckID
	if verificationCheckID == "" {
		verificationCheckID = entry.CheckID
	}
	step, found := h.findStepByCheckID(verificationCheckID)
	if !found {
		h.db.Exec(ctx, `UPDATE remediation_requests SET status=$1, error='verification check not found in scenario library' WHERE id=$2`,
			remediation.StatusFailed, requestID)
		return
	}
	timeoutSec := step.TimeoutSec
	if timeoutSec == 0 {
		timeoutSec = 30
	}
	verifyRunID, sent, err := h.dispatchRemediationStep(ctx, agentID, "remediation-verify", remediationID, step.Command, step.Executor, timeoutSec)
	if err != nil || !sent {
		diag := "could not dispatch verification"
		if err != nil {
			diag += ": " + err.Error()
		} else {
			diag += ": sent=false"
		}
		h.db.Exec(ctx, `UPDATE remediation_requests SET status=$1, error=$2 WHERE id=$3`,
			remediation.StatusFailed, diag, requestID)
		return
	}
	h.db.Exec(ctx,
		`UPDATE remediation_requests SET status=$1, verify_run_id=$2 WHERE id=$3`,
		remediation.StatusVerifying, verifyRunID, requestID)
}

// handleRemediationVerifyResult resolves a remediation once its
// verification check's result arrives: PASS means the fix actually took
// effect (StatusCompleted); FAIL means the command exited cleanly but the
// endpoint's compliance state didn't change (StatusVerificationFailed) --
// evidence-based, not exit-code-based.
func (h *Handler) handleRemediationVerifyResult(r *http.Request, requestID string, passed bool) {
	ctx := r.Context()
	var remediationID, agentID, requestedBy string
	h.db.QueryRow(ctx, `SELECT remediation_id, agent_id, requested_by FROM remediation_requests WHERE id=$1`, requestID).
		Scan(&remediationID, &agentID, &requestedBy)

	status := remediation.StatusCompleted
	outcome := "completed"
	if !passed {
		status = remediation.StatusVerificationFailed
		outcome = "verification_failed"
	}
	h.db.Exec(ctx,
		`UPDATE remediation_requests SET status=$1, verification_completed_at=NOW(), completed_at=NOW() WHERE id=$2`,
		status, requestID)
	h.auditLogAs(r, requestedBy, "remediation."+status, requestID,
		map[string]any{"remediationId": remediationID, "agentId": agentID}, outcome)
}
