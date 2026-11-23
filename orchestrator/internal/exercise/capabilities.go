package exercise

import (
	"context"
	"sync"
	"time"
)

// Channel capabilities beyond Send. A channel declares only the ones it has; asking for one it lacks is not
// a fake success. One-way channels (chat webhooks, SMS) have no status and cannot be unsent, so they implement
// none of these. Tickets can report status and be closed.

// TicketStatusReader reads a ticket's status ("open", "in_progress", "resolved") from its connector.
type TicketStatusReader interface {
	TicketStatus(ctx context.Context, connectorID, ticketID string) (string, error)
}

// TicketCloser resolves an exercise ticket with a note that says it was a drill.
type TicketCloser interface {
	CloseExerciseTicket(ctx context.Context, connectorID, ticketID, note string) error
}

// inflightSends tracks cancel handles for sends that are running right now, per execution and step, so that
// AbortExecution can really stop them. The zero value is ready to use.
type inflightSends struct {
	mu     sync.Mutex
	byExec map[string]map[string]context.CancelFunc
}

// beginSend returns a context for one step's external send and a func to call when it finishes. The context is
// cancelled by cancelInflight (abort), not by the request that started the step.
func (e *Executor) beginSend(execID, stepID string) (context.Context, func()) {
	ctx, cancel := context.WithCancel(context.Background())
	e.inflight.mu.Lock()
	if e.inflight.byExec == nil {
		e.inflight.byExec = map[string]map[string]context.CancelFunc{}
	}
	if e.inflight.byExec[execID] == nil {
		e.inflight.byExec[execID] = map[string]context.CancelFunc{}
	}
	e.inflight.byExec[execID][stepID] = cancel
	e.inflight.mu.Unlock()
	return ctx, func() {
		e.inflight.mu.Lock()
		delete(e.inflight.byExec[execID], stepID)
		if len(e.inflight.byExec[execID]) == 0 {
			delete(e.inflight.byExec, execID)
		}
		e.inflight.mu.Unlock()
		cancel()
	}
}

// cancelInflight cancels every send running for the execution and returns the step ids it cancelled.
func (e *Executor) cancelInflight(execID string) []string {
	e.inflight.mu.Lock()
	defer e.inflight.mu.Unlock()
	var ids []string
	for stepID, cancel := range e.inflight.byExec[execID] {
		cancel()
		ids = append(ids, stepID)
	}
	return ids
}

// Cleanup states recorded in a ticket step's result, so a later pass never closes the same ticket twice.
const (
	cleanupDone    = "done"
	cleanupSkipped = "skipped"
)

// cleanupExecution undoes what an execution left in external systems: it closes the drill tickets its ticket
// steps opened, unless the step says keep_open. It runs when an exercise completes or is aborted, is safe to
// run more than once, and never fails the caller: a failure is recorded as cleanup_failed evidence and the
// ticket stays eligible for a later pass.
func (e *Executor) cleanupExecution(ctx context.Context, ex *Execution) {
	plan, err := e.store.GetPlan(ctx, ex.PlanID)
	if err != nil {
		return
	}
	stepExecs, err := e.store.ListStepExecutions(ctx, ex.ID)
	if err != nil {
		return
	}
	byID := make(map[string]*StepExecution, len(stepExecs))
	for i := range stepExecs {
		byID[stepExecs[i].StepID] = &stepExecs[i]
	}
	for i := range plan.Steps {
		ps := &plan.Steps[i]
		if ps.Type != StepTypeTicket || ps.Config.Ticket == nil {
			continue
		}
		se := byID[ps.ID]
		if se == nil || se.Status != StepCompleted {
			continue
		}
		if st, _ := se.Result["cleanup"].(string); st == cleanupDone || st == cleanupSkipped {
			continue
		}
		ticketID, _ := se.Result["ticket_id"].(string)
		connectorID, _ := se.Result["connector_id"].(string)
		if ticketID == "" {
			continue
		}
		payload := map[string]any{"step_id": ps.ID, "connector_id": connectorID, "ticket_id": ticketID}
		mark := func(state string) {
			_ = e.store.SetStepResult(ctx, ex.ID, ps.ID, mergeMaps(se.Result, map[string]any{"cleanup": state, "cleanup_at": time.Now().UTC().Format(time.RFC3339)}))
		}

		if ps.Config.Ticket.KeepOpen {
			payload["reason"] = "keep_open"
			mark(cleanupSkipped)
			_, _ = e.evidence.Append(ctx, ex.ID, se.ID, "cleanup_skipped", "system", "ticket_cleanup", payload)
			_ = e.store.RecordEvent(ctx, ex.ID, ps.ID, "cleanup_skipped", "system", payload)
			continue
		}
		closer, ok := e.tickets.(TicketCloser)
		if !ok {
			payload["error"] = "ticketing cannot close exercise tickets"
			_, _ = e.evidence.Append(ctx, ex.ID, se.ID, "cleanup_failed", "system", "ticket_cleanup", payload)
			continue
		}
		note := "Exercise ended; closing this drill ticket (Audspect BAS exercise " + ex.ID + ")."
		if err := closer.CloseExerciseTicket(ctx, connectorID, ticketID, note); err != nil {
			payload["error"] = err.Error()
			_, _ = e.evidence.Append(ctx, ex.ID, se.ID, "cleanup_failed", "system", "ticket_cleanup", payload)
			_ = e.store.RecordEvent(ctx, ex.ID, ps.ID, "cleanup_failed", "system", payload)
			continue
		}
		mark(cleanupDone)
		_, _ = e.evidence.Append(ctx, ex.ID, se.ID, "cleanup_done", "system", "ticket_cleanup", payload)
		_ = e.store.RecordEvent(ctx, ex.ID, ps.ID, "cleanup_done", "system", payload)
	}
}
