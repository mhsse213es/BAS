package api

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

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
		return
	}
	if err := h.db.QueryRow(r.Context(),
		`SELECT id FROM remediation_requests WHERE rollback_run_id = $1 AND rollback_status = 'requested'`, runID,
	).Scan(&id); err == nil {
		h.handleRemediationRollbackResult(r, id, passed)
		return
	}
	if err := h.db.QueryRow(r.Context(),
		`SELECT id FROM remediation_requests WHERE rollback_verify_run_id = $1 AND rollback_status = 'requested'`, runID,
	).Scan(&id); err == nil {
		h.handleRemediationRollbackVerifyResult(r, id, passed)
		return
	}
	if err := h.db.QueryRow(r.Context(),
		`SELECT id FROM technique_verification_runs WHERE run_id = $1 AND status = 'dispatched'`, runID,
	).Scan(&id); err == nil {
		h.handleTechniqueVerificationResult(r, id, simResults)
	}
}

// handleTechniqueVerificationResult writes the technique run's result
// directly onto technique_verification_runs.status -- models.CheckResult's
// own value (pass/fail/blocked/error/skipped), no new taxonomy. reason is
// copied verbatim from the result's Details field.
func (h *Handler) handleTechniqueVerificationResult(r *http.Request, techVerifyID string, simResults []models.SimulationResult) {
	ctx := r.Context()
	status := string(models.ResultError)
	reason := "agent reported no result"
	if len(simResults) > 0 {
		status = string(simResults[0].Result)
		reason = simResults[0].Details
	}
	h.db.Exec(ctx,
		`UPDATE technique_verification_runs SET status=$1, reason=$2, completed_at=NOW() WHERE id=$3`,
		status, reason, techVerifyID)

	var requestID, checkID, techniqueID, requestedBy string
	h.db.QueryRow(ctx, `SELECT request_id, check_id, technique_id, requested_by FROM technique_verification_runs WHERE id=$1`, techVerifyID).
		Scan(&requestID, &checkID, &techniqueID, &requestedBy)
	h.auditLogAs(r, requestedBy, "remediation.technique_verification_"+status, techVerifyID,
		map[string]any{"requestId": requestID, "checkId": checkID, "techniqueId": techniqueID}, status)
}

// handleRemediationRollbackResult mirrors handleRemediationFixResult for
// the rollback path: on success, re-runs verification to confirm the
// control is actually back in its pre-fix state; on failure, the rollback
// stops here.
func (h *Handler) handleRemediationRollbackResult(r *http.Request, requestID string, passed bool) {
	ctx := r.Context()
	var remediationID, agentID, requestedBy string
	h.db.QueryRow(ctx, `SELECT remediation_id, agent_id, requested_by FROM remediation_requests WHERE id=$1`, requestID).
		Scan(&remediationID, &agentID, &requestedBy)

	if !passed {
		h.db.Exec(ctx, `UPDATE remediation_requests SET rollback_status='failed' WHERE id=$1`, requestID)
		h.auditLogAs(r, requestedBy, "remediation.rollback_failed", requestID,
			map[string]any{"remediationId": remediationID, "agentId": agentID}, "failed")
		return
	}

	if h.remediationCatalog == nil {
		h.db.Exec(ctx, `UPDATE remediation_requests SET rollback_status='failed' WHERE id=$1`, requestID)
		return
	}
	entry, ok := h.remediationCatalog.ByID(remediationID)
	if !ok {
		h.db.Exec(ctx, `UPDATE remediation_requests SET rollback_status='failed' WHERE id=$1`, requestID)
		return
	}
	verificationCheckID := entry.VerificationCheckID
	if verificationCheckID == "" {
		verificationCheckID = entry.CheckID
	}
	step, found := h.findStepByCheckID(verificationCheckID)
	if !found {
		h.db.Exec(ctx, `UPDATE remediation_requests SET rollback_status='failed' WHERE id=$1`, requestID)
		return
	}
	timeoutSec := step.TimeoutSec
	if timeoutSec == 0 {
		timeoutSec = 30
	}
	verifyRunID, sent, err := h.dispatchRemediationStep(ctx, agentID, "remediation-rollback-verify", remediationID, step.Command, step.Executor, timeoutSec)
	if err != nil || !sent {
		h.db.Exec(ctx, `UPDATE remediation_requests SET rollback_status='failed' WHERE id=$1`, requestID)
		return
	}
	h.db.Exec(ctx, `UPDATE remediation_requests SET rollback_verify_run_id=$1 WHERE id=$2`, verifyRunID, requestID)
}

// handleRemediationRollbackVerifyResult: passed==true means the finding's
// check STILL PASSES after the rollback command ran -- the rollback did
// NOT take effect. passed==false means the check now fails again,
// confirming the rollback worked (the control reverted to its pre-fix
// state).
func (h *Handler) handleRemediationRollbackVerifyResult(r *http.Request, requestID string, passed bool) {
	ctx := r.Context()
	var remediationID, agentID, requestedBy string
	h.db.QueryRow(ctx, `SELECT remediation_id, agent_id, requested_by FROM remediation_requests WHERE id=$1`, requestID).
		Scan(&remediationID, &agentID, &requestedBy)

	status := "completed"
	outcome := "ok"
	if passed {
		status = "failed"
		outcome = "rollback ran but the control is still active -- verify manually"
	}
	h.db.Exec(ctx, `UPDATE remediation_requests SET rollback_status=$1 WHERE id=$2`, status, requestID)
	h.auditLogAs(r, requestedBy, "remediation.rollback_"+status, requestID,
		map[string]any{"remediationId": remediationID, "agentId": agentID}, outcome)
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
	var remediationID, agentID, requestedBy, checkID string
	var continuousValidation bool
	h.db.QueryRow(ctx, `SELECT remediation_id, agent_id, requested_by, check_id, continuous_validation FROM remediation_requests WHERE id=$1`, requestID).
		Scan(&remediationID, &agentID, &requestedBy, &checkID, &continuousValidation)

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

	if passed && continuousValidation && h.jobsStore != nil && h.EligibleForBASVerification(checkID) {
		h.scheduleRevalidationChain(ctx, requestID, agentID, checkID, requestedBy)
	}
}

// scheduleRevalidationChain creates the three bas_revalidation Jobs
// (T+24h/T+7d/T+30d) for one just-verified remediation. Each is a
// singleton-target Job -- a revalidation is inherently one endpoint
// re-checking one control, not a fleet-wide batch.
func (h *Handler) scheduleRevalidationChain(ctx context.Context, requestID, agentID, checkID, requestedBy string) {
	step, found := h.findStepByCheckID(checkID)
	if !found {
		return
	}
	payload, err := json.Marshal(basRevalidationPayload{
		RequestID: requestID, AgentID: agentID, CheckID: checkID, TechniqueID: step.TechniqueID,
	})
	if err != nil {
		return
	}
	now := time.Now().UTC()
	for _, delay := range []time.Duration{24 * time.Hour, 7 * 24 * time.Hour, 30 * 24 * time.Hour} {
		at := now.Add(delay)
		h.jobsStore.CreateBatchScheduled(ctx, "bas_revalidation", payload, requestedBy, []string{agentID}, &at)
	}
}
