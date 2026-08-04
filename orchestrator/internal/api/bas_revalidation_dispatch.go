package api

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/audspect/bas/internal/jobs"
	"github.com/audspect/bas/internal/models"
)

// basRevalidationPayload is the Job.Payload shape for Type="bas_revalidation".
// Self-contained -- no re-lookup of remediation_requests needed at dispatch
// time, since a bas_revalidation Job is created with everything it needs
// (see handleRemediationVerifyResult's trigger logic).
type basRevalidationPayload struct {
	RequestID   string `json:"requestId"`
	AgentID     string `json:"agentId"`
	CheckID     string `json:"checkId"`
	TechniqueID string `json:"techniqueId"`
}

// dispatchBasRevalidationTarget is Sub-project 5's VerifyTechnique dispatch
// body, extracted and reused: it inserts a technique_verification_runs row
// and calls the unchanged dispatchTechniqueVerification. Because it writes
// run_id onto that row exactly as VerifyTechnique already does,
// continueRemediationFromResult's existing technique_verification_runs
// branch picks up the eventual scenario result with no new code -- this
// function deliberately does NOT call VerifyTechnique's per-request_id
// uniqueness guard (that guard lives in VerifyTechnique's own handler body,
// not the schema), so multiple rows correctly accumulate per request over
// the three revalidation cycles.
func (h *Handler) dispatchBasRevalidationTarget(ctx context.Context, job jobs.Job, target jobs.JobTarget) (refID string, err error) {
	var payload basRevalidationPayload
	if err := json.Unmarshal(job.Payload, &payload); err != nil {
		return "", err
	}

	techVerifyID := newID()
	if _, err := h.db.Exec(ctx,
		`INSERT INTO technique_verification_runs (id, request_id, agent_id, check_id, technique_id, status, requested_by)
		 VALUES ($1,$2,$3,$4,$5,'requested',$6)`,
		techVerifyID, payload.RequestID, target.AgentID, payload.CheckID, payload.TechniqueID, job.CreatedBy,
	); err != nil {
		return "", err
	}

	runID, sent, err := h.dispatchTechniqueVerification(ctx, target.AgentID, payload.TechniqueID)
	if err != nil {
		h.db.Exec(ctx, `UPDATE technique_verification_runs SET status='error', reason=$1 WHERE id=$2`, err.Error(), techVerifyID)
		return "", err
	}
	if !sent {
		h.db.Exec(ctx, `UPDATE technique_verification_runs SET status='error', reason='agent not connected' WHERE id=$1`, techVerifyID)
		return "", errors.New("agent not connected")
	}
	h.db.Exec(ctx,
		`UPDATE technique_verification_runs SET status='dispatched', run_id=$1, dispatched_at=NOW() WHERE id=$2`,
		runID, techVerifyID)
	return techVerifyID, nil
}

// basRevalidationTargetStatus polls the technique_verification_runs row
// (refID = its own id, the value dispatchBasRevalidationTarget returned as
// refID -- not run_id). models.ResultBlocked counts as job-target success
// alongside models.ResultPass -- it means the security control prevented
// the technique from running, matching the "pass, blocked" success bucket
// used consistently everywhere else in this codebase (models/score.go,
// campaign, compliance, detecteffectiveness, reporting). error/skipped are
// the only terminal-but-failed outcomes.
func (h *Handler) basRevalidationTargetStatus(ctx context.Context, jobType, refID string) (state string, errText string, terminal bool) {
	var status, reason string
	if err := h.db.QueryRow(ctx, `SELECT status, reason FROM technique_verification_runs WHERE id=$1`, refID).Scan(&status, &reason); err != nil {
		return jobs.TargetStateFailed, "technique verification run not found: " + err.Error(), true
	}
	switch status {
	case string(models.ResultPass), string(models.ResultBlocked):
		return jobs.TargetStateCompleted, "", true
	case string(models.ResultFail), string(models.ResultError), string(models.ResultSkipped):
		return jobs.TargetStateFailed, reason, true
	default: // "requested", "dispatched"
		return jobs.TargetStateDispatched, "", false
	}
}
