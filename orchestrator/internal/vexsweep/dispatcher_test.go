package vexsweep

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestDispatcher_Tick_DispatchesFirstTechniqueForNewSweep(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		sw, err := store.Create(ctx, Sweep{
			AgentID: "agent-tick-1", Mode: "sequential",
			Techniques: []string{"T1059.001", "T1059.003"}, TechniqueVariantCounts: []int{33, 12}, TotalVariants: 45,
		})
		if err != nil {
			t.Fatalf("Create: %v", err)
		}

		var dispatchedTechniques []string
		d := NewDispatcher(store, func(ctx context.Context, variantRunID string) (string, error) {
			return "running", nil // nothing has "completed" yet in this test
		})
		d.SetDispatch(func(ctx context.Context, sweepID, agentID, techniqueID, baseType, mode string, includeAdvanced bool, techniqueIndex, totalTechniques int) (string, string, int, error) {
			dispatchedTechniques = append(dispatchedTechniques, techniqueID)
			return "sr-1", "vr-1", 33, nil
		})

		if err := d.Tick(ctx); err != nil {
			t.Fatalf("Tick: %v", err)
		}
		if len(dispatchedTechniques) != 1 || dispatchedTechniques[0] != "T1059.001" {
			t.Fatalf("dispatchedTechniques = %v, want [T1059.001]", dispatchedTechniques)
		}
		got, _ := store.Get(ctx, sw.ID)
		if got.CurrentVariantRunID != "vr-1" || got.CurrentScenarioRunID != "sr-1" {
			t.Fatalf("after first tick: %+v, want CurrentVariantRunID=vr-1 CurrentScenarioRunID=sr-1", got)
		}
	})
}

func TestDispatcher_Tick_AdvancesWhenCurrentTechniqueFinishes(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		sw, err := store.Create(ctx, Sweep{
			AgentID: "agent-tick-2", Mode: "sequential",
			Techniques: []string{"T1059.001", "T1059.003"}, TechniqueVariantCounts: []int{33, 12}, TotalVariants: 45,
		})
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		if err := store.AdvanceToNext(ctx, sw.ID, 0, 0, "vr-1", "sr-1"); err != nil {
			// Simulate: dispatcher already dispatched technique 1 (index 0)
			// on a prior tick -- nextIndex=0 since this was the sweep's
			// first-ever dispatch, index unchanged from its starting value.
			t.Fatalf("seed AdvanceToNext: %v", err)
		}

		var dispatchedTechniques []string
		d := NewDispatcher(store, func(ctx context.Context, variantRunID string) (string, error) {
			if variantRunID == "vr-1" {
				return "completed", nil
			}
			return "running", nil
		})
		d.SetDispatch(func(ctx context.Context, sweepID, agentID, techniqueID, baseType, mode string, includeAdvanced bool, techniqueIndex, totalTechniques int) (string, string, int, error) {
			dispatchedTechniques = append(dispatchedTechniques, techniqueID)
			return "sr-2", "vr-2", 12, nil
		})

		if err := d.Tick(ctx); err != nil {
			t.Fatalf("Tick: %v", err)
		}
		if len(dispatchedTechniques) != 1 || dispatchedTechniques[0] != "T1059.003" {
			t.Fatalf("dispatchedTechniques = %v, want [T1059.003]", dispatchedTechniques)
		}
		got, _ := store.Get(ctx, sw.ID)
		if got.CompletedVariants != 33 || got.CurrentIndex != 1 {
			t.Fatalf("after advancing: %+v, want CompletedVariants=33 CurrentIndex=1", got)
		}
	})
}

func TestDispatcher_Tick_CompletesSweepAfterLastTechnique(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		sw, err := store.Create(ctx, Sweep{
			AgentID: "agent-tick-3", Mode: "sequential",
			Techniques: []string{"T1059.001"}, TechniqueVariantCounts: []int{33}, TotalVariants: 33,
		})
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		if err := store.AdvanceToNext(ctx, sw.ID, 0, 0, "vr-1", "sr-1"); err != nil {
			t.Fatalf("seed AdvanceToNext: %v", err)
		}

		d := NewDispatcher(store, func(ctx context.Context, variantRunID string) (string, error) {
			return "completed", nil
		})
		d.SetDispatch(func(ctx context.Context, sweepID, agentID, techniqueID, baseType, mode string, includeAdvanced bool, techniqueIndex, totalTechniques int) (string, string, int, error) {
			t.Fatal("dispatch should not be called -- no techniques remain after the last one")
			return "", "", 0, nil
		})

		if err := d.Tick(ctx); err != nil {
			t.Fatalf("Tick: %v", err)
		}
		got, _ := store.Get(ctx, sw.ID)
		if got.Status != "completed" || got.CompletedVariants != 33 {
			t.Fatalf("after last tick: %+v, want Status=completed CompletedVariants=33", got)
		}
	})
}

func TestDispatcher_Tick_MarksFailedOnDispatchError(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		sw, err := store.Create(ctx, Sweep{
			AgentID: "agent-tick-4", Mode: "sequential",
			Techniques: []string{"T1059.001", "T1059.003"}, TechniqueVariantCounts: []int{33, 12}, TotalVariants: 45,
		})
		if err != nil {
			t.Fatalf("Create: %v", err)
		}

		d := NewDispatcher(store, func(ctx context.Context, variantRunID string) (string, error) {
			return "running", nil
		})
		d.SetDispatch(func(ctx context.Context, sweepID, agentID, techniqueID, baseType, mode string, includeAdvanced bool, techniqueIndex, totalTechniques int) (string, string, int, error) {
			return "", "", 0, errors.New("agent not connected")
		})

		if err := d.Tick(ctx); err != nil {
			t.Fatalf("Tick itself should not error (failure is recorded on the sweep, not returned): %v", err)
		}
		got, _ := store.Get(ctx, sw.ID)
		if got.Status != "failed" || got.Error != "agent not connected" {
			t.Fatalf("after dispatch error: %+v, want Status=failed Error=%q", got, "agent not connected")
		}
	})
}

// TestDispatcher_Tick_ForceCancelsStuckTechniqueAfterThreshold is the
// regression test for a real, repeatedly-observed bug: some ART atomic
// tests (e.g. T1072's Radmin/PDQ Deploy tests, which launch a bare GUI
// executable with nothing to auto-exit) never complete on an unattended
// agent. Nothing in this pipeline had any ceiling on how long it waits for
// such a technique -- the sweep just sat "Running" forever until a human
// noticed and manually stopped it. Once a technique exceeds stuckThreshold
// with no progress, the Dispatcher must trigger the injected CancelFn.
func TestDispatcher_Tick_ForceCancelsStuckTechniqueAfterThreshold(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		sw, err := store.Create(ctx, Sweep{
			AgentID: "agent-stuck-1", Mode: "sequential",
			Techniques: []string{"T1072"}, TechniqueVariantCounts: []int{10}, TotalVariants: 10,
		})
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		if err := store.AdvanceToNext(ctx, sw.ID, 0, 0, "vr-stuck-1", "sr-stuck-1"); err != nil {
			t.Fatalf("seed AdvanceToNext: %v", err)
		}

		var cancelledRunIDs []string
		d := NewDispatcher(store, func(ctx context.Context, variantRunID string) (string, error) {
			return "running", nil // never finishes -- simulates a truly hung technique
		})
		d.SetDispatch(func(ctx context.Context, sweepID, agentID, techniqueID, baseType, mode string, includeAdvanced bool, techniqueIndex, totalTechniques int) (string, string, int, error) {
			t.Fatal("dispatch should not be called -- the current technique never leaves running in this test")
			return "", "", 0, nil
		})
		d.stuckThreshold = time.Millisecond
		d.SetCancel(func(ctx context.Context, scenarioRunID string) (string, string, error) {
			cancelledRunIDs = append(cancelledRunIDs, scenarioRunID)
			return "agent-stuck-1", "cancelling", nil
		})

		time.Sleep(5 * time.Millisecond) // let current_technique_started_at fall behind stuckThreshold

		if err := d.Tick(ctx); err != nil {
			t.Fatalf("Tick: %v", err)
		}
		if len(cancelledRunIDs) != 1 || cancelledRunIDs[0] != "sr-stuck-1" {
			t.Fatalf("cancelledRunIDs = %v, want exactly [sr-stuck-1]", cancelledRunIDs)
		}
	})
}

func TestDispatcher_Tick_DoesNotForceCancelBeforeThreshold(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		sw, err := store.Create(ctx, Sweep{
			AgentID: "agent-stuck-2", Mode: "sequential",
			Techniques: []string{"T1072"}, TechniqueVariantCounts: []int{10}, TotalVariants: 10,
		})
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		if err := store.AdvanceToNext(ctx, sw.ID, 0, 0, "vr-stuck-2", "sr-stuck-2"); err != nil {
			t.Fatalf("seed AdvanceToNext: %v", err)
		}

		cancelCalled := false
		d := NewDispatcher(store, func(ctx context.Context, variantRunID string) (string, error) {
			return "running", nil
		})
		d.SetDispatch(func(ctx context.Context, sweepID, agentID, techniqueID, baseType, mode string, includeAdvanced bool, techniqueIndex, totalTechniques int) (string, string, int, error) {
			t.Fatal("dispatch should not be called")
			return "", "", 0, nil
		})
		d.stuckThreshold = time.Hour // technique just started -- nowhere near stuck yet
		d.SetCancel(func(ctx context.Context, scenarioRunID string) (string, string, error) {
			cancelCalled = true
			return "", "", nil
		})

		if err := d.Tick(ctx); err != nil {
			t.Fatalf("Tick: %v", err)
		}
		if cancelCalled {
			t.Fatal("cancel should not be triggered before stuckThreshold elapses")
		}
	})
}

// TestDispatcher_Tick_DoesNotReTriggerCancelOnSubsequentTicks proves the
// dedup guard: cancelling is itself asynchronous (the injected CancelFn's
// own grace period), so re-triggering it every 5s tick while waiting for
// that to resolve would spam redundant cancel messages and goroutines.
func TestDispatcher_Tick_DoesNotReTriggerCancelOnSubsequentTicks(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		sw, err := store.Create(ctx, Sweep{
			AgentID: "agent-stuck-3", Mode: "sequential",
			Techniques: []string{"T1072"}, TechniqueVariantCounts: []int{10}, TotalVariants: 10,
		})
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		if err := store.AdvanceToNext(ctx, sw.ID, 0, 0, "vr-stuck-3", "sr-stuck-3"); err != nil {
			t.Fatalf("seed AdvanceToNext: %v", err)
		}

		cancelCount := 0
		d := NewDispatcher(store, func(ctx context.Context, variantRunID string) (string, error) {
			return "running", nil // still stuck across every tick in this test
		})
		d.SetDispatch(func(ctx context.Context, sweepID, agentID, techniqueID, baseType, mode string, includeAdvanced bool, techniqueIndex, totalTechniques int) (string, string, int, error) {
			t.Fatal("dispatch should not be called")
			return "", "", 0, nil
		})
		d.stuckThreshold = time.Millisecond
		d.SetCancel(func(ctx context.Context, scenarioRunID string) (string, string, error) {
			cancelCount++
			return "agent-stuck-3", "cancelling", nil
		})

		time.Sleep(5 * time.Millisecond)

		for i := 0; i < 3; i++ {
			if err := d.Tick(ctx); err != nil {
				t.Fatalf("Tick %d: %v", i, err)
			}
		}
		if cancelCount != 1 {
			t.Fatalf("cancel triggered %d times across 3 ticks, want exactly 1 (must not spam re-trigger while the cancel's own grace period resolves)", cancelCount)
		}
	})
}

// TestDispatcher_Tick_RetriesStuckCancelAfterFailedAttempt is the regression
// test for a real bug found while investigating a Full Sweep that stayed
// stuck on T1072 well past stuckThreshold + cancelGracePeriod: the dispatcher
// marked cancelTriggeredForRun BEFORE calling CancelFn, so a single failed
// cancel attempt (e.g. a transient scenario_runs/variant_runs status desync)
// permanently disabled all further recovery attempts for that technique --
// the sweep was then stuck forever, with zero retries, no matter how long a
// human waited. A failed cancel attempt must be retried on a later tick.
func TestDispatcher_Tick_RetriesStuckCancelAfterFailedAttempt(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		sw, err := store.Create(ctx, Sweep{
			AgentID: "agent-stuck-retry-1", Mode: "sequential",
			Techniques: []string{"T1072"}, TechniqueVariantCounts: []int{10}, TotalVariants: 10,
		})
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		if err := store.AdvanceToNext(ctx, sw.ID, 0, 0, "vr-stuck-retry-1", "sr-stuck-retry-1"); err != nil {
			t.Fatalf("seed AdvanceToNext: %v", err)
		}

		cancelAttempts := 0
		d := NewDispatcher(store, func(ctx context.Context, variantRunID string) (string, error) {
			return "running", nil // still stuck across every tick in this test
		})
		d.SetDispatch(func(ctx context.Context, sweepID, agentID, techniqueID, baseType, mode string, includeAdvanced bool, techniqueIndex, totalTechniques int) (string, string, int, error) {
			t.Fatal("dispatch should not be called")
			return "", "", 0, nil
		})
		d.stuckThreshold = time.Millisecond
		d.SetCancel(func(ctx context.Context, scenarioRunID string) (string, string, error) {
			cancelAttempts++
			if cancelAttempts == 1 {
				return "", "", errors.New("simulated transient cancel failure")
			}
			return "agent-stuck-retry-1", "cancelling", nil
		})

		time.Sleep(5 * time.Millisecond)

		if err := d.Tick(ctx); err != nil {
			t.Fatalf("Tick 1: %v", err)
		}
		if err := d.Tick(ctx); err != nil {
			t.Fatalf("Tick 2: %v", err)
		}
		if cancelAttempts != 2 {
			t.Fatalf("cancelAttempts = %d, want 2 (the first failed attempt must not permanently block a retry)", cancelAttempts)
		}
	})
}

// TestDispatcher_Tick_ForceCancelsStuckTechniqueEvenIfStatusCheckErrors is
// the regression test for the other half of the same bug class: advance()
// returned immediately on any status-check error, before maybeForceCancelStuck
// ever ran -- so a persistently-erroring status lookup (e.g. a bad/missing
// variant_run row) silently disabled stuck-recovery forever too, with no log
// signal beyond the one status-check-failed line repeating every tick.
func TestDispatcher_Tick_ForceCancelsStuckTechniqueEvenIfStatusCheckErrors(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		sw, err := store.Create(ctx, Sweep{
			AgentID: "agent-stuck-statuserr-1", Mode: "sequential",
			Techniques: []string{"T1072"}, TechniqueVariantCounts: []int{10}, TotalVariants: 10,
		})
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		if err := store.AdvanceToNext(ctx, sw.ID, 0, 0, "vr-stuck-statuserr-1", "sr-stuck-statuserr-1"); err != nil {
			t.Fatalf("seed AdvanceToNext: %v", err)
		}

		var cancelledRunIDs []string
		d := NewDispatcher(store, func(ctx context.Context, variantRunID string) (string, error) {
			return "", errors.New("simulated persistent status-check failure")
		})
		d.SetDispatch(func(ctx context.Context, sweepID, agentID, techniqueID, baseType, mode string, includeAdvanced bool, techniqueIndex, totalTechniques int) (string, string, int, error) {
			t.Fatal("dispatch should not be called")
			return "", "", 0, nil
		})
		d.stuckThreshold = time.Millisecond
		d.SetCancel(func(ctx context.Context, scenarioRunID string) (string, string, error) {
			cancelledRunIDs = append(cancelledRunIDs, scenarioRunID)
			return "agent-stuck-statuserr-1", "cancelling", nil
		})

		time.Sleep(5 * time.Millisecond)

		if err := d.Tick(ctx); err != nil {
			t.Fatalf("Tick: %v", err)
		}
		if len(cancelledRunIDs) != 1 || cancelledRunIDs[0] != "sr-stuck-statuserr-1" {
			t.Fatalf("cancelledRunIDs = %v, want exactly [sr-stuck-statuserr-1] (a persistent status-check error must still allow stuck-recovery to fire)", cancelledRunIDs)
		}
	})
}

func TestDispatcher_Tick_IgnoresStoppedAndFailedSweeps(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		sw, err := store.Create(ctx, Sweep{
			AgentID: "agent-tick-5", Mode: "sequential",
			Techniques: []string{"T1059.001"}, TechniqueVariantCounts: []int{33}, TotalVariants: 33,
		})
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		if err := store.MarkStopped(ctx, sw.ID); err != nil {
			t.Fatalf("MarkStopped: %v", err)
		}

		d := NewDispatcher(store, func(ctx context.Context, variantRunID string) (string, error) {
			t.Fatal("status check should not be called for a stopped sweep")
			return "", nil
		})
		d.SetDispatch(func(ctx context.Context, sweepID, agentID, techniqueID, baseType, mode string, includeAdvanced bool, techniqueIndex, totalTechniques int) (string, string, int, error) {
			t.Fatal("dispatch should not be called for a stopped sweep")
			return "", "", 0, nil
		})

		if err := d.Tick(ctx); err != nil {
			t.Fatalf("Tick: %v", err)
		}
	})
}
