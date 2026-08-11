package vexsweep

import (
	"context"
	"log"
)

// DispatchFn dispatches one technique's variants to an agent. Injected
// after construction (SetDispatch) to avoid an internal/vexsweep ->
// internal/api import cycle -- the same pattern internal/exercise.Executor
// already uses for its AgentDispatchFn.
type DispatchFn func(ctx context.Context, sweepID, agentID, techniqueID, mode string, includeAdvanced bool) (scenarioRunID, variantRunID string, totalVariants int, err error)

// VariantRunStatusFn reports a variant run's current status
// ("running"/"completed"/"failed"/"partial"), read directly from
// variant_runs/scenario_runs -- no callback into internal/api needed for
// this half, since it's a plain read of tables vexsweep can query itself.
type VariantRunStatusFn func(ctx context.Context, variantRunID string) (status string, err error)

type Dispatcher struct {
	store    *Store
	status   VariantRunStatusFn
	dispatch DispatchFn
}

func NewDispatcher(store *Store, status VariantRunStatusFn) *Dispatcher {
	return &Dispatcher{store: store, status: status}
}

func (d *Dispatcher) SetDispatch(fn DispatchFn) { d.dispatch = fn }

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
	if sw.CurrentVariantRunID != "" {
		status, err := d.status(ctx, sw.CurrentVariantRunID)
		if err != nil {
			log.Printf("[vexsweep] status check failed for sweep %s variant_run %s: %v", sw.ID, sw.CurrentVariantRunID, err)
			return
		}
		if status == "running" {
			return // nothing to do this tick
		}
		// Technique finished (completed/failed/partial) -- credit its variants.
		d.dispatchNext(ctx, sw, sw.TechniqueVariantCounts[sw.CurrentIndex])
		return
	}
	// No technique in flight yet -- this is the sweep's very first tick.
	d.dispatchNext(ctx, sw, 0)
}

func (d *Dispatcher) dispatchNext(ctx context.Context, sw Sweep, justFinishedCount int) {
	nextIdx := sw.CurrentIndex
	if sw.CurrentVariantRunID != "" {
		nextIdx = sw.CurrentIndex + 1
	}
	if nextIdx >= len(sw.Techniques) {
		if err := d.store.AdvanceToNext(ctx, sw.ID, justFinishedCount, nextIdx, "", ""); err != nil {
			log.Printf("[vexsweep] complete sweep %s: %v", sw.ID, err)
		}
		return
	}

	scenarioRunID, variantRunID, _, err := d.dispatch(ctx, sw.ID, sw.AgentID, sw.Techniques[nextIdx], sw.Mode, sw.IncludeAdvanced)
	if err != nil {
		// Deliberately does not fall through to the next technique -- a
		// silently-skipped technique in a security-validation sweep is
		// worse than a sweep that stops and says why. See design spec
		// Architecture §2.
		if merr := d.store.MarkFailed(ctx, sw.ID, err.Error()); merr != nil {
			log.Printf("[vexsweep] mark sweep %s failed: %v", sw.ID, merr)
		}
		return
	}
	if err := d.store.AdvanceToNext(ctx, sw.ID, justFinishedCount, nextIdx, variantRunID, scenarioRunID); err != nil {
		log.Printf("[vexsweep] advance sweep %s: %v", sw.ID, err)
	}
}
