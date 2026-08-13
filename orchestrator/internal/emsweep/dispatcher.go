package emsweep

import (
	"context"
	"log"
	"time"
)

// DispatchFn dispatches one EM layer (a plain scenario) to an agent.
// Injected after construction (SetDispatch) to avoid an
// internal/emsweep -> internal/api import cycle -- the same pattern
// internal/vexsweep.DispatchFn and internal/exercise.Executor already use.
type DispatchFn func(ctx context.Context, sweepID, agentID, scenarioID string) (scenarioRunID string, err error)

// StatusFn reports a scenario_run's current status ("running"/"completed"/
// "failed"/"partial"), read directly from scenario_runs -- no callback into
// internal/api needed, since it's a plain read of a table emsweep can query
// itself. Mirrors vexsweep.VariantRunStatusFn.
type StatusFn func(ctx context.Context, scenarioRunID string) (status string, err error)

// CancelFn cancels an in-flight scenario_run -- injected after construction
// (SetCancel), same import-cycle-avoidance pattern as DispatchFn.
// Production wiring points this at the exact same Handler.cancelScenarioRun
// vexsweep's CancelFn uses -- no new cancellation logic, just reused.
type CancelFn func(ctx context.Context, scenarioRunID string) (agentID, status string, err error)

// defaultStuckThreshold mirrors vexsweep's: how long a layer can sit with
// no progress before the Dispatcher treats it as genuinely hung and
// force-cancels it. See internal/vexsweep/dispatcher.go's identical
// constant for the full rationale (a real ART/Custom check can hang
// unattended the same way an ART atomic can).
const defaultStuckThreshold = 3 * time.Minute

type Dispatcher struct {
	store    *Store
	status   StatusFn
	dispatch DispatchFn
	cancel   CancelFn

	stuckThreshold time.Duration
	// cancelTriggeredForRun tracks scenario_run_ids a stuck-cancel has
	// already been triggered for, so advance() doesn't re-trigger it every
	// 5s tick while the cancel's own grace period is still resolving.
	cancelTriggeredForRun map[string]bool
}

func NewDispatcher(store *Store, status StatusFn) *Dispatcher {
	return &Dispatcher{
		store: store, status: status,
		stuckThreshold:        defaultStuckThreshold,
		cancelTriggeredForRun: make(map[string]bool),
	}
}

func (d *Dispatcher) SetDispatch(fn DispatchFn) { d.dispatch = fn }
func (d *Dispatcher) SetCancel(fn CancelFn)     { d.cancel = fn }

// Tick advances every running sweep by at most one step. Exported so tests
// can call it directly without a real ticker; production wiring calls it
// from an exercise.PollScheduler tick callback.
func (d *Dispatcher) Tick(ctx context.Context) error {
	sweeps, err := d.store.ListRunning(ctx)
	if err != nil {
		return err
	}
	for _, sw := range sweeps {
		d.advance(ctx, sw)
	}
	return nil
}

func (d *Dispatcher) advance(ctx context.Context, sw Sweep) {
	if sw.CurrentScenarioRunID != "" {
		status, err := d.status(ctx, sw.CurrentScenarioRunID)
		if err != nil {
			log.Printf("[emsweep] status check failed for sweep %s run %s: %v", sw.ID, sw.CurrentScenarioRunID, err)
			// A persistent status-check failure must not permanently block
			// stuck-recovery -- see internal/vexsweep/dispatcher.go's
			// identical fix.
			d.maybeForceCancelStuck(ctx, sw)
			return
		}
		if status == "running" {
			d.maybeForceCancelStuck(ctx, sw)
			return // nothing to do this tick
		}
		delete(d.cancelTriggeredForRun, sw.CurrentScenarioRunID)
		// Layer finished (completed/failed/partial) -- credit it and advance.
		d.dispatchNext(ctx, sw, 1)
		return
	}
	// No layer in flight yet -- this is the sweep's very first tick.
	d.dispatchNext(ctx, sw, 0)
}

// maybeForceCancelStuck triggers a cancel for the current layer once it has
// exceeded stuckThreshold with no progress. Triggers at most once per
// scenario_run. Sets the dedup flag ONLY after a successful cancel call --
// see internal/vexsweep/dispatcher.go's identical fix: a failed cancel
// attempt (e.g. transient WS-send error) must retry on the next tick, not
// be abandoned forever.
func (d *Dispatcher) maybeForceCancelStuck(ctx context.Context, sw Sweep) {
	if d.cancel == nil || sw.CurrentScenarioRunID == "" || sw.CurrentLayerStartedAt == nil {
		return
	}
	if time.Since(*sw.CurrentLayerStartedAt) <= d.stuckThreshold {
		return
	}
	if d.cancelTriggeredForRun[sw.CurrentScenarioRunID] {
		return
	}

	layer := ""
	if sw.CurrentIndex >= 0 && sw.CurrentIndex < len(sw.Layers) {
		layer = sw.Layers[sw.CurrentIndex]
	}
	if _, _, err := d.cancel(ctx, sw.CurrentScenarioRunID); err != nil {
		log.Printf("[emsweep] force-cancel stuck layer %s for sweep %s (run %s): %v -- will retry next tick", layer, sw.ID, sw.CurrentScenarioRunID, err)
		return
	}
	d.cancelTriggeredForRun[sw.CurrentScenarioRunID] = true
	log.Printf("[emsweep] layer %s for sweep %s exceeded stuck threshold (%s) -- force-cancel triggered", layer, sw.ID, d.stuckThreshold)
}

func (d *Dispatcher) dispatchNext(ctx context.Context, sw Sweep, justFinishedCount int) {
	nextIdx := sw.CurrentIndex
	if sw.CurrentScenarioRunID != "" {
		nextIdx = sw.CurrentIndex + 1
	}
	if nextIdx >= len(sw.Layers) {
		if err := d.store.AdvanceToNext(ctx, sw.ID, justFinishedCount, nextIdx, ""); err != nil {
			log.Printf("[emsweep] complete sweep %s: %v", sw.ID, err)
		}
		return
	}

	scenarioRunID, err := d.dispatch(ctx, sw.ID, sw.AgentID, sw.Layers[nextIdx])
	if err != nil {
		// Deliberately does not fall through to the next layer -- a
		// silently-skipped layer in a security-validation sweep is worse
		// than a sweep that stops and says why. Matches vexsweep's identical
		// choice.
		if merr := d.store.MarkFailed(ctx, sw.ID, err.Error()); merr != nil {
			log.Printf("[emsweep] mark sweep %s failed: %v", sw.ID, merr)
		}
		return
	}
	if err := d.store.AdvanceToNext(ctx, sw.ID, justFinishedCount, nextIdx, scenarioRunID); err != nil {
		log.Printf("[emsweep] advance sweep %s: %v", sw.ID, err)
	}
}
