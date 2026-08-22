package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/audspect/bas/internal/initiatives"
	"github.com/audspect/bas/internal/jobs"
	"github.com/audspect/bas/internal/remediation"
)

// batchRemediationPayload is the Job.Payload shape for Type="batch_remediation".
type batchRemediationPayload struct {
	RemediationID        string `json:"remediationId"`
	Reason               string `json:"reason"`
	ContinuousValidation bool   `json:"continuousValidation"`
}

// dispatchBatchRemediationTarget is injected into jobs.Dispatcher via
// SetDispatch (see WithJobsDispatcher below). It performs the exact same
// pre-flight + dispatch steps as Sub-project 4's ExecuteRemediation -- the
// permission/Tier-4/catalog-existence checks already happened once, at
// job-creation time (CreateBatchRemediationJob), not per-target here.
func (h *Handler) dispatchBatchRemediationTarget(ctx context.Context, job jobs.Job, target jobs.JobTarget) (refID string, err error) {
	var payload batchRemediationPayload
	if err := json.Unmarshal(job.Payload, &payload); err != nil {
		return "", err
	}
	if h.remediationCatalog == nil {
		return "", errors.New("remediation catalog not loaded")
	}
	entry, ok := h.remediationCatalog.ByID(payload.RemediationID)
	if !ok {
		return "", errors.New("unknown remediationId")
	}

	var agentOS string
	h.db.QueryRow(ctx, `SELECT COALESCE(os_version,'') FROM agents WHERE agent_id=$1`, target.AgentID).Scan(&agentOS)
	if !remediation.OSSupported(agentOS, entry) {
		return "", errors.New("remediation not supported on this endpoint's OS")
	}

	requestID := newID()
	allResults := h.aggregateAgentResults(ctx, target.AgentID)
	if latestCheckIsPassing(allResults, entry.CheckID) {
		if _, err := h.db.Exec(ctx,
			`INSERT INTO remediation_requests (id, remediation_id, agent_id, check_id, tier, status, requested_by, reason, rollback_available, continuous_validation, completed_at)
			 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,NOW())`,
			requestID, entry.ID, target.AgentID, entry.CheckID, int(entry.Tier), remediation.StatusCompleted, job.CreatedBy, payload.Reason, entry.SupportsRollback, payload.ContinuousValidation,
		); err != nil {
			return "", err
		}
		return requestID, nil
	}

	if _, err := h.db.Exec(ctx,
		`INSERT INTO remediation_requests (id, remediation_id, agent_id, check_id, tier, status, requested_by, reason, rollback_available, continuous_validation)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
		requestID, entry.ID, target.AgentID, entry.CheckID, int(entry.Tier), remediation.StatusRequested, job.CreatedBy, payload.Reason, entry.SupportsRollback, payload.ContinuousValidation,
	); err != nil {
		return "", err
	}

	timeoutSec := entry.EstimatedTimeSec * 2
	if timeoutSec == 0 {
		timeoutSec = 60
	}
	runID, sent, dispatchErr := h.dispatchRemediationStep(ctx, target.AgentID, "remediation-fix", entry.ID, entry.Command, entry.Executor, timeoutSec)
	if dispatchErr != nil {
		h.db.Exec(ctx, `UPDATE remediation_requests SET status=$1, error=$2 WHERE id=$3`, remediation.StatusFailed, dispatchErr.Error(), requestID)
		return "", dispatchErr
	}
	if !sent {
		h.db.Exec(ctx, `UPDATE remediation_requests SET status=$1, error='agent not connected' WHERE id=$2`, remediation.StatusFailed, requestID)
		return "", errors.New("agent not connected")
	}
	h.db.Exec(ctx,
		`UPDATE remediation_requests SET status=$1, fix_run_id=$2, dispatched_at=NOW() WHERE id=$3`,
		remediation.StatusDispatched, runID, requestID)
	return requestID, nil
}

// batchRemediationTargetStatus is injected into jobs.Dispatcher via
// SetStatus. It polls the remediation_requests row created for this target
// (refID) and reports whether that row has reached a terminal state.
func (h *Handler) batchRemediationTargetStatus(ctx context.Context, jobType, refID string) (state string, errText string, terminal bool) {
	var status, errCol string
	if err := h.db.QueryRow(ctx, `SELECT status, error FROM remediation_requests WHERE id=$1`, refID).Scan(&status, &errCol); err != nil {
		return jobs.TargetStateFailed, "remediation request not found: " + err.Error(), true
	}
	switch status {
	case remediation.StatusCompleted:
		return jobs.TargetStateCompleted, "", true
	case remediation.StatusFailed, remediation.StatusVerificationFailed, remediation.StatusTimedOut, remediation.StatusCancelled:
		return jobs.TargetStateFailed, errCol, true
	default: // requested, dispatched, running, verifying
		return jobs.TargetStateDispatched, "", false
	}
}

// dispatchJobTarget routes to the correct dispatch function for job.Type.
// internal/jobs.Dispatcher knows nothing about what any job type actually
// does -- this switch is the one place that knowledge lives.
func (h *Handler) dispatchJobTarget(ctx context.Context, job jobs.Job, target jobs.JobTarget) (refID string, err error) {
	switch job.Type {
	case "batch_remediation":
		return h.dispatchBatchRemediationTarget(ctx, job, target)
	case "bas_revalidation":
		return h.dispatchBasRevalidationTarget(ctx, job, target)
	case "scheduled_assessment":
		return h.dispatchScheduledAssessmentTarget(ctx, job, target)
	default:
		return "", fmt.Errorf("unknown job type %q", job.Type)
	}
}

// statusForJobTarget mirrors dispatchJobTarget's routing for status polling.
func (h *Handler) statusForJobTarget(ctx context.Context, jobType, refID string) (state string, errText string, terminal bool) {
	switch jobType {
	case "batch_remediation":
		return h.batchRemediationTargetStatus(ctx, jobType, refID)
	case "bas_revalidation":
		return h.basRevalidationTargetStatus(ctx, jobType, refID)
	case "scheduled_assessment":
		return h.scheduledAssessmentTargetStatus(ctx, jobType, refID)
	default:
		return jobs.TargetStateFailed, "unknown job type", true
	}
}

// WithJobsDispatcher wires the Fleet Job Engine's dispatch/status routing
// into dispatcher, and stores store for the HTTP handlers in
// job_handlers.go. Mirrors WithVexSweep's exact shape.
func (h *Handler) WithJobsDispatcher(store *jobs.Store, dispatcher *jobs.Dispatcher) *Handler {
	h.jobsStore = store
	dispatcher.SetDispatch(h.dispatchJobTarget)
	dispatcher.SetStatus(h.statusForJobTarget)
	dispatcher.SetNotify(h.dispatchJobNotify)
	return h
}

// WithInitiatives wires the Initiative layer's store into the handler.
func (h *Handler) WithInitiatives(store *initiatives.Store) *Handler {
	h.initiativesStore = store
	return h
}
