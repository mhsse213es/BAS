package jobs

import "context"

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
		refID, dispatchErr := d.dispatch(ctx, job, t)
		if dispatchErr != nil {
			d.store.MarkTargetTerminal(ctx, t.ID, TargetStateFailed, dispatchErr.Error())
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
			}
		}
	}
	return nil
}
