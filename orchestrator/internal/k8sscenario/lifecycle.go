package k8sscenario

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// DefaultMaxRun is the longest a live run may execute on the server, measured from the start of the engine's run. A
// run that reaches it is stopped and rolled back exactly as a cancelled run is.
const DefaultMaxRun = 10 * time.Minute

// rollbackBudget bounds rollback and its verification. Rollback runs on a context that cancellation cannot end, so it
// needs its own limit.
const rollbackBudget = 2 * time.Minute

// StateCancelled: the run was stopped (cancelled, time limit, or the kill switch) and the rollback was verified. It is
// not a claim that the action completed.
const StateCancelled State = "CANCELLED"

// Audit event types for the lifecycle beyond the engine's own run events.
const (
	EventCancelRequested  = "k8s.scenario.cancel_requested"
	EventApproved         = "k8s.scenario.approved"
	EventControlledSwitch = "k8s.controlled.switch"
)

// Reasons a run is stopped. They are recorded in the outcome so the audit trail says why.
var (
	ErrCancelledByOperator  = errors.New("cancelled by the requester")
	ErrRunTimeLimit         = errors.New("run exceeded the server time limit")
	ErrControlledDisabled   = errors.New("controlled execution is disabled")
	ErrAuthorizationChanged = errors.New("customer authorization changed or was revoked since the run was planned")
)

// activeRun is a live run the engine is executing, so it can be stopped.
type activeRun struct {
	cancel     func(error)
	controlled bool
}

// track gives a live run its own context: stopped by Cancel, CancelControlled, or the time limit. The returned func
// must be called when the run has finished.
func (e *Engine) track(ctx context.Context, req RunRequest) (context.Context, func()) {
	limit := e.cfg.MaxRunDuration
	if limit <= 0 {
		limit = DefaultMaxRun
	}
	base, cancelCause := context.WithCancelCause(ctx)
	runCtx, cancelTimeout := context.WithTimeoutCause(base, limit, ErrRunTimeLimit)
	e.mu.Lock()
	e.active[req.RunID] = activeRun{cancel: func(err error) { cancelCause(err) }, controlled: ActionProfile(req.ActionID) == ProfileControlled}
	e.mu.Unlock()
	return runCtx, func() {
		e.mu.Lock()
		delete(e.active, req.RunID)
		e.mu.Unlock()
		cancelTimeout()
		cancelCause(nil)
	}
}

// Cancel stops a running live run. Further writes stop, and the engine rolls back and verifies the restore before it
// reports the outcome. It reports false when no such run is executing.
func (e *Engine) Cancel(runID string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	a, ok := e.active[runID]
	if ok {
		a.cancel(ErrCancelledByOperator)
	}
	return ok
}

// CancelControlled stops every executing Controlled run. The kill switch calls it when the switch is turned off. It
// returns how many runs it stopped.
func (e *Engine) CancelControlled() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	n := 0
	for _, a := range e.active {
		if a.controlled {
			a.cancel(ErrControlledDisabled)
			n++
		}
	}
	return n
}

// gate is the Controlled check. It fails closed when no gate is configured.
func (e *Engine) gate(ctx context.Context, req RunRequest) error {
	if e.cfg.ControlledGate == nil {
		return ErrControlledDisabled
	}
	return e.cfg.ControlledGate(ctx, req)
}

// CheckControlled runs the same gate for callers that plan a run, so planning and execution agree.
func (e *Engine) CheckControlled(ctx context.Context, req RunRequest) error {
	return e.gate(ctx, req)
}

// NewControlledGate builds the gate for Controlled work. It denies unless the global switch is on, and the cluster has
// an active authorization for this exact action and namespace, and that record is still the one the run was planned
// under. It is checked at planning, before the run starts, and again immediately before the first write.
func NewControlledGate(enabled func(ctx context.Context) (bool, error),
	records func(ctx context.Context, clusterID string) ([]CustomerAuthorization, error),
	now func() time.Time) func(context.Context, RunRequest) error {
	return func(ctx context.Context, req RunRequest) error {
		on, err := enabled(ctx)
		if err != nil {
			return fmt.Errorf("kill switch unreadable: %w", err)
		}
		if !on {
			return ErrControlledDisabled
		}
		if req.ClusterID == "" {
			return ErrAuthorizationDenied
		}
		recs, err := records(ctx, req.ClusterID)
		if err != nil {
			return fmt.Errorf("authorization unreadable: %w", err)
		}
		rec, err := MatchCustomerAuthorization(recs, req.ClusterID, req.ActionID, req.Namespace, now())
		if err != nil {
			return err
		}
		if rec.ID != req.AuthorizationID || rec.CustomerRef != req.CustomerRef {
			return ErrAuthorizationChanged
		}
		return nil
	}
}

// ApprovalEvent is the audit record for an approval. It holds who approved, for which customer, cluster, authorization,
// scenario and namespaces, the exact parameters, and the approval's time and expiry.
func ApprovalEvent(a Approval, params map[string]string) Event {
	p, _ := json.Marshal(params)
	return Event{
		Type:  EventApproved,
		RunID: a.RunID,
		Fields: map[string]string{
			"requester":       a.RequesterID,
			"approver":        a.ApproverID,
			"approvalId":      a.ID,
			"clusterId":       a.ClusterID,
			"authorizationId": a.AuthorizationID,
			"customerRef":     a.CustomerRef,
			"cluster":         a.Cluster,
			"namespace":       a.Namespace,
			"action":          a.ActionID,
			"paramsHash":      a.ParamsHash,
			"params":          string(p),
			"approvedAt":      a.ApprovedAt.UTC().Format(time.RFC3339),
			"expiresAt":       a.ExpiresAt.UTC().Format(time.RFC3339),
		},
	}
}

// CancelRequestEvent records that a requester asked to stop a run. The outcome records what then happened.
func CancelRequestEvent(runID, actor, clusterID, clusterName, namespace, action string) Event {
	return Event{
		Type:  EventCancelRequested,
		RunID: runID,
		Fields: map[string]string{
			"requester": actor,
			"clusterId": clusterID,
			"cluster":   clusterName,
			"namespace": namespace,
			"action":    action,
		},
	}
}

// ControlledSwitchEvent records a change to the global Controlled switch.
func ControlledSwitchEvent(enabled bool, actor string, at time.Time) Event {
	return Event{
		Type: EventControlledSwitch,
		Fields: map[string]string{
			"enabled":   fmt.Sprint(enabled),
			"requester": actor,
			"changedAt": at.UTC().Format(time.RFC3339),
		},
	}
}
