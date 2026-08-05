package jobs

import (
	"context"
	"log"
	"time"
)

// DispatchFn performs one target's actual execution (e.g. creating a
// remediation_requests row and dispatching it to the agent) and returns a
// RefID to poll for that target's outcome via StatusFn, or an error if
// dispatch itself failed.
type DispatchFn func(ctx context.Context, job Job, target JobTarget) (refID string, err error)

// StatusFn resolves a dispatched target's current state by interpreting
// whatever RefID points at. terminal=false means still in progress -- Tick
// leaves the target alone and checks again next tick.
type StatusFn func(ctx context.Context, jobType, refID string) (state string, errText string, terminal bool)

// jobDispatchBatchSize caps how many pending targets Tick dispatches in a
// single call, mirroring internal/api/revalidation.go's revalidationBatchSize
// reasoning -- a 200-target job shouldn't flood the WS hub and every agent's
// local queue in one pass.
const jobDispatchBatchSize = 20

type Dispatcher struct {
	store    *Store
	dispatch DispatchFn
	status   StatusFn
	notify   NotifyFn
}

func NewDispatcher(store *Store) *Dispatcher {
	return &Dispatcher{store: store}
}

func (d *Dispatcher) SetDispatch(fn DispatchFn) { d.dispatch = fn }
func (d *Dispatcher) SetStatus(fn StatusFn)     { d.status = fn }

// Tick advances every active job by (1) resolving any in-flight targets
// that have reached a terminal state, (2) dispatching up to
// jobDispatchBatchSize still-pending targets, then (3) recomputing and
// persisting the aggregate state of every job touched in this tick.
func (d *Dispatcher) Tick(ctx context.Context) error {
	d.spawnDueSchedules(ctx)

	jobCache := map[string]Job{}
	jobOf := func(jobID string) (Job, error) {
		if j, ok := jobCache[jobID]; ok {
			return j, nil
		}
		j, err := d.store.Get(ctx, jobID)
		if err == nil {
			jobCache[jobID] = j
		}
		return j, err
	}

	touchedJobs := map[string]bool{}

	inFlight, err := d.store.ListActiveDispatchedTargets(ctx)
	if err != nil {
		return err
	}
	for _, t := range inFlight {
		job, err := jobOf(t.JobID)
		if err != nil {
			continue
		}
		state, errText, terminal := d.status(ctx, job.Type, t.RefID)
		if !terminal {
			continue
		}
		if err := d.store.MarkTargetTerminal(ctx, t.ID, state, errText); err != nil {
			continue
		}
		if state == TargetStateFailed && d.notify != nil {
			d.notify(ctx, NotifyEvent{
				Type: notifyTypeTargetFailed, JobID: t.JobID, TargetID: t.ID, AgentID: t.AgentID,
				Severity: notifySeverityError, Message: errText,
			})
		}
		touchedJobs[t.JobID] = true
	}

	deferred, err := d.store.ListDeferredTargets(ctx)
	if err != nil {
		return err
	}
	for _, t := range deferred {
		frozen, _, ferr := d.store.IsAgentFrozen(ctx, t.AgentID)
		if ferr != nil || frozen {
			continue
		}
		if err := d.store.MarkTargetPending(ctx, t.ID); err != nil {
			continue
		}
		touchedJobs[t.JobID] = true
	}

	pending, err := d.store.ListPendingTargetsAcrossActiveJobs(ctx, jobDispatchBatchSize)
	if err != nil {
		return err
	}
	for _, t := range pending {
		job, err := jobOf(t.JobID)
		if err != nil {
			continue
		}
		if frozen, reason, ferr := d.store.IsAgentFrozen(ctx, t.AgentID); ferr == nil && frozen {
			d.store.MarkTargetDeferred(ctx, t.ID, reason)
			if d.notify != nil {
				d.notify(ctx, NotifyEvent{
					Type: notifyTypeTargetDeferred, JobID: t.JobID, TargetID: t.ID, AgentID: t.AgentID,
					Severity: notifySeverityWarning, Message: reason,
				})
			}
			touchedJobs[t.JobID] = true
			continue
		}
		refID, dispatchErr := d.dispatch(ctx, job, t)
		if dispatchErr != nil {
			d.store.MarkTargetTerminal(ctx, t.ID, TargetStateFailed, dispatchErr.Error())
			if d.notify != nil {
				d.notify(ctx, NotifyEvent{
					Type: notifyTypeTargetFailed, JobID: t.JobID, TargetID: t.ID, AgentID: t.AgentID,
					Severity: notifySeverityError, Message: dispatchErr.Error(),
				})
			}
		} else {
			d.store.MarkTargetDispatched(ctx, t.ID, refID)
		}
		touchedJobs[t.JobID] = true
	}

	for jobID := range touchedJobs {
		targets, err := d.store.ListTargets(ctx, jobID)
		if err != nil {
			continue
		}
		job, err := jobOf(jobID)
		if err != nil {
			continue
		}
		newState := AggregateState(job.State, targets)
		if newState != job.State {
			if err := d.store.SetJobState(ctx, jobID, newState); err == nil {
				updated := job
				updated.State = newState
				jobCache[jobID] = updated
				if d.notify != nil {
					if evtType, sev, ok := classifyJobTransition(newState); ok {
						d.notify(ctx, NotifyEvent{Type: evtType, JobID: jobID, Severity: sev})
					}
				}
			}
		}
	}
	return nil
}

// spawnDueSchedules checks every enabled Schedule for a new weekly
// occurrence and spawns a fresh one-shot Job for it, unless the previous
// spawn from this schedule is still non-terminal (skip + log; the schedule
// tries again next occurrence).
func (d *Dispatcher) spawnDueSchedules(ctx context.Context) {
	schedules, err := d.store.ListEnabledSchedules(ctx)
	if err != nil {
		return
	}
	for _, sch := range schedules {
		occurrence, ok := nextOccurrenceSince(sch, time.Now().UTC())
		if !ok {
			continue // no new occurrence since sch.LastOccurrenceAt -- the common case
		}
		if sch.LastSpawnedJobID != "" {
			if job, err := d.store.Get(ctx, sch.LastSpawnedJobID); err == nil && !IsTerminalJobState(job.State) {
				log.Printf("[jobs] schedule %s: skipping occurrence %v -- previous spawn %s still active", sch.ID, occurrence, sch.LastSpawnedJobID)
				d.store.MarkScheduleOccurrenceHandled(ctx, sch.ID, occurrence, "")
				continue
			}
		}
		newJob, err := d.store.CreateBatch(ctx, sch.Type, sch.Payload, sch.CreatedBy, sch.AgentIDs)
		if err != nil {
			log.Printf("[jobs] schedule %s: spawn failed: %v -- will retry next tick", sch.ID, err)
			continue
		}
		d.store.MarkScheduleOccurrenceHandled(ctx, sch.ID, occurrence, newJob.ID)
		log.Printf("[jobs] schedule %s: spawned job %s for occurrence %v", sch.ID, newJob.ID, occurrence)
	}
}
