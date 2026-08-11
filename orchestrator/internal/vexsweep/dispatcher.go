package vexsweep

import (
	"context"
	"log"
	"time"
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

// CancelFn cancels an in-flight scenario_run -- injected after
// construction (SetCancel), same import-cycle-avoidance pattern as
// DispatchFn. Production wiring points this directly at
// Handler.cancelScenarioRun, reusing its existing agent-notify + grace-
// period + variant_runs-sync behavior rather than duplicating any of it
// here (see internal/api/handlers.go).
type CancelFn func(ctx context.Context, scenarioRunID string) (agentID, status string, err error)

// defaultStuckThreshold is how long a technique can sit with no progress
// (variant_runs.status still "running") before the Dispatcher treats it as
// genuinely hung and force-cancels it, freeing the sweep to move on. This
// is a backstop against real ART content that never completes unattended
// (e.g. an atomic test that launches a bare GUI executable with nothing to
// auto-exit) -- kept short deliberately, per user preference, at the cost
// of some risk: a technique with many variants and evasion delays
// (sleep_jitter/delay add real seconds per variant) can legitimately take
// a few minutes, so a long-but-genuinely-progressing technique could be
// force-cancelled too. Tune here if that starts happening in practice.
const defaultStuckThreshold = 3 * time.Minute

type Dispatcher struct {
	store    *Store
	status   VariantRunStatusFn
	dispatch DispatchFn
	cancel   CancelFn

	stuckThreshold time.Duration
	// cancelTriggeredForRun tracks scenario_run_ids a stuck-cancel has
	// already been triggered for, so advance() doesn't re-trigger it every
	// 5s tick while the cancel's own grace period is still resolving.
	cancelTriggeredForRun map[string]bool
}

func NewDispatcher(store *Store, status VariantRunStatusFn) *Dispatcher {
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
	if sw.CurrentVariantRunID != "" {
		status, err := d.status(ctx, sw.CurrentVariantRunID)
		if err != nil {
			log.Printf("[vexsweep] status check failed for sweep %s variant_run %s: %v", sw.ID, sw.CurrentVariantRunID, err)
			return
		}
		if status == "running" {
			d.maybeForceCancelStuck(ctx, sw)
			return // nothing to do this tick
		}
		delete(d.cancelTriggeredForRun, sw.CurrentScenarioRunID)
		// Technique finished (completed/failed/partial) -- credit its variants.
		d.dispatchNext(ctx, sw, sw.TechniqueVariantCounts[sw.CurrentIndex])
		return
	}
	// No technique in flight yet -- this is the sweep's very first tick.
	d.dispatchNext(ctx, sw, 0)
}

// maybeForceCancelStuck triggers a cancel for the current technique once it
// has exceeded stuckThreshold with no progress. Triggers at most once per
// scenario_run -- cancelling is itself asynchronous (the injected
// CancelFn's own grace period), so re-triggering it every tick until that
// resolves would just spam redundant cancel messages/goroutines. Once the
// cancel resolves, the next tick's normal status check naturally advances
// the sweep via the existing dispatchNext path -- no special-casing needed
// there.
func (d *Dispatcher) maybeForceCancelStuck(ctx context.Context, sw Sweep) {
	if d.cancel == nil || sw.CurrentScenarioRunID == "" || sw.CurrentTechniqueStartedAt == nil {
		return
	}
	if time.Since(*sw.CurrentTechniqueStartedAt) <= d.stuckThreshold {
		return
	}
	if d.cancelTriggeredForRun[sw.CurrentScenarioRunID] {
		return
	}
	d.cancelTriggeredForRun[sw.CurrentScenarioRunID] = true

	technique := ""
	if sw.CurrentIndex >= 0 && sw.CurrentIndex < len(sw.Techniques) {
		technique = sw.Techniques[sw.CurrentIndex]
	}
	if _, _, err := d.cancel(ctx, sw.CurrentScenarioRunID); err != nil {
		log.Printf("[vexsweep] force-cancel stuck technique %s for sweep %s (run %s): %v", technique, sw.ID, sw.CurrentScenarioRunID, err)
		return
	}
	log.Printf("[vexsweep] technique %s for sweep %s exceeded stuck threshold (%s) -- force-cancel triggered", technique, sw.ID, d.stuckThreshold)
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
