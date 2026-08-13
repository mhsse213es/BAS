package emsweep

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestDispatcher_Tick_DispatchesFirstLayerForNewSweep(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		sw, err := store.Create(ctx, Sweep{
			AgentID: "agent-tick-1", Layers: []string{"em-01", "em-02"}, TotalLayers: 2,
		})
		if err != nil {
			t.Fatalf("Create: %v", err)
		}

		var dispatchedLayers []string
		d := NewDispatcher(store, func(ctx context.Context, scenarioRunID string) (string, error) {
			return "running", nil // nothing has "completed" yet in this test
		})
		d.SetDispatch(func(ctx context.Context, sweepID, agentID, scenarioID string) (string, error) {
			dispatchedLayers = append(dispatchedLayers, scenarioID)
			return "sr-1", nil
		})

		if err := d.Tick(ctx); err != nil {
			t.Fatalf("Tick: %v", err)
		}
		if len(dispatchedLayers) != 1 || dispatchedLayers[0] != "em-01" {
			t.Fatalf("dispatchedLayers = %v, want [em-01]", dispatchedLayers)
		}
		got, _ := store.Get(ctx, sw.ID)
		if got.CurrentScenarioRunID != "sr-1" {
			t.Fatalf("after first tick: %+v, want CurrentScenarioRunID=sr-1", got)
		}
	})
}

func TestDispatcher_Tick_AdvancesWhenCurrentLayerFinishes(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		sw, err := store.Create(ctx, Sweep{
			AgentID: "agent-tick-2", Layers: []string{"em-01", "em-02"}, TotalLayers: 2,
		})
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		if err := store.AdvanceToNext(ctx, sw.ID, 0, 0, "sr-1"); err != nil {
			// Simulate: dispatcher already dispatched layer 1 (index 0) on a
			// prior tick -- nextIndex=0 since this was the sweep's
			// first-ever dispatch, index unchanged from its starting value.
			t.Fatalf("seed AdvanceToNext: %v", err)
		}

		var dispatchedLayers []string
		d := NewDispatcher(store, func(ctx context.Context, scenarioRunID string) (string, error) {
			if scenarioRunID == "sr-1" {
				return "completed", nil
			}
			return "running", nil
		})
		d.SetDispatch(func(ctx context.Context, sweepID, agentID, scenarioID string) (string, error) {
			dispatchedLayers = append(dispatchedLayers, scenarioID)
			return "sr-2", nil
		})

		if err := d.Tick(ctx); err != nil {
			t.Fatalf("Tick: %v", err)
		}
		if len(dispatchedLayers) != 1 || dispatchedLayers[0] != "em-02" {
			t.Fatalf("dispatchedLayers = %v, want [em-02]", dispatchedLayers)
		}
		got, _ := store.Get(ctx, sw.ID)
		if got.CompletedLayers != 1 || got.CurrentIndex != 1 {
			t.Fatalf("after advancing: %+v, want CompletedLayers=1 CurrentIndex=1", got)
		}
	})
}

func TestDispatcher_Tick_CompletesSweepAfterLastLayer(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		sw, err := store.Create(ctx, Sweep{
			AgentID: "agent-tick-3", Layers: []string{"em-01"}, TotalLayers: 1,
		})
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		if err := store.AdvanceToNext(ctx, sw.ID, 0, 0, "sr-1"); err != nil {
			t.Fatalf("seed AdvanceToNext: %v", err)
		}

		d := NewDispatcher(store, func(ctx context.Context, scenarioRunID string) (string, error) {
			return "completed", nil
		})
		d.SetDispatch(func(ctx context.Context, sweepID, agentID, scenarioID string) (string, error) {
			t.Fatal("dispatch should not be called -- no layers remain after the last one")
			return "", nil
		})

		if err := d.Tick(ctx); err != nil {
			t.Fatalf("Tick: %v", err)
		}
		got, _ := store.Get(ctx, sw.ID)
		if got.Status != "completed" || got.CompletedLayers != 1 {
			t.Fatalf("after last tick: %+v, want Status=completed CompletedLayers=1", got)
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
			AgentID: "agent-tick-4", Layers: []string{"em-01", "em-02"}, TotalLayers: 2,
		})
		if err != nil {
			t.Fatalf("Create: %v", err)
		}

		d := NewDispatcher(store, func(ctx context.Context, scenarioRunID string) (string, error) {
			return "running", nil
		})
		d.SetDispatch(func(ctx context.Context, sweepID, agentID, scenarioID string) (string, error) {
			return "", errors.New("agent not connected")
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

// TestDispatcher_Tick_ForceCancelsStuckLayerAfterThreshold is the regression
// test for the same bug class vexsweep's identical test guards against: some
// EM layer checks (real ART/Custom checks -- memory attacks, credential
// theft, etc.) can hang unattended on an agent just like an ART atomic can.
// Once a layer exceeds stuckThreshold with no progress, the Dispatcher must
// trigger the injected CancelFn.
func TestDispatcher_Tick_ForceCancelsStuckLayerAfterThreshold(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		sw, err := store.Create(ctx, Sweep{
			AgentID: "agent-stuck-1", Layers: []string{"em-03-memory-attacks"}, TotalLayers: 1,
		})
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		if err := store.AdvanceToNext(ctx, sw.ID, 0, 0, "sr-stuck-1"); err != nil {
			t.Fatalf("seed AdvanceToNext: %v", err)
		}

		var cancelledRunIDs []string
		d := NewDispatcher(store, func(ctx context.Context, scenarioRunID string) (string, error) {
			return "running", nil // never finishes -- simulates a truly hung layer
		})
		d.SetDispatch(func(ctx context.Context, sweepID, agentID, scenarioID string) (string, error) {
			t.Fatal("dispatch should not be called -- the current layer never leaves running in this test")
			return "", nil
		})
		d.stuckThreshold = time.Millisecond
		d.SetCancel(func(ctx context.Context, scenarioRunID string) (string, string, error) {
			cancelledRunIDs = append(cancelledRunIDs, scenarioRunID)
			return "agent-stuck-1", "cancelling", nil
		})

		time.Sleep(5 * time.Millisecond) // let current_layer_started_at fall behind stuckThreshold

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
			AgentID: "agent-stuck-2", Layers: []string{"em-03-memory-attacks"}, TotalLayers: 1,
		})
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		if err := store.AdvanceToNext(ctx, sw.ID, 0, 0, "sr-stuck-2"); err != nil {
			t.Fatalf("seed AdvanceToNext: %v", err)
		}

		cancelCalled := false
		d := NewDispatcher(store, func(ctx context.Context, scenarioRunID string) (string, error) {
			return "running", nil
		})
		d.SetDispatch(func(ctx context.Context, sweepID, agentID, scenarioID string) (string, error) {
			t.Fatal("dispatch should not be called")
			return "", nil
		})
		d.stuckThreshold = time.Hour // layer just started -- nowhere near stuck yet
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
			AgentID: "agent-stuck-3", Layers: []string{"em-03-memory-attacks"}, TotalLayers: 1,
		})
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		if err := store.AdvanceToNext(ctx, sw.ID, 0, 0, "sr-stuck-3"); err != nil {
			t.Fatalf("seed AdvanceToNext: %v", err)
		}

		cancelCount := 0
		d := NewDispatcher(store, func(ctx context.Context, scenarioRunID string) (string, error) {
			return "running", nil // still stuck across every tick in this test
		})
		d.SetDispatch(func(ctx context.Context, sweepID, agentID, scenarioID string) (string, error) {
			t.Fatal("dispatch should not be called")
			return "", nil
		})
		d.stuckThreshold = time.Millisecond
		d.SetCancel(func(ctx context.Context, scenarioRunID string) (string, string, error) {
			cancelCount++
			return "agent-stuck-3", "cancelling", nil
		})

		time.Sleep(5 * time.Millisecond)

		for i := range 3 {
			if err := d.Tick(ctx); err != nil {
				t.Fatalf("Tick %d: %v", i, err)
			}
		}
		if cancelCount != 1 {
			t.Fatalf("cancel triggered %d times across 3 ticks, want exactly 1 (must not spam re-trigger while the cancel's own grace period resolves)", cancelCount)
		}
	})
}

// TestDispatcher_Tick_RetriesStuckCancelAfterFailedAttempt proves the
// dedup flag is only set AFTER a successful cancel call, mirroring the exact
// bug this session found and fixed in internal/vexsweep/dispatcher.go: a
// single failed cancel attempt must not permanently disable all further
// recovery attempts for that layer.
func TestDispatcher_Tick_RetriesStuckCancelAfterFailedAttempt(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		sw, err := store.Create(ctx, Sweep{
			AgentID: "agent-stuck-retry-1", Layers: []string{"em-03-memory-attacks"}, TotalLayers: 1,
		})
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		if err := store.AdvanceToNext(ctx, sw.ID, 0, 0, "sr-stuck-retry-1"); err != nil {
			t.Fatalf("seed AdvanceToNext: %v", err)
		}

		cancelAttempts := 0
		d := NewDispatcher(store, func(ctx context.Context, scenarioRunID string) (string, error) {
			return "running", nil // still stuck across every tick in this test
		})
		d.SetDispatch(func(ctx context.Context, sweepID, agentID, scenarioID string) (string, error) {
			t.Fatal("dispatch should not be called")
			return "", nil
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

// TestDispatcher_Tick_ForceCancelsStuckLayerEvenIfStatusCheckErrors proves
// the other half of the same fix: a persistently-erroring status lookup
// must not silently disable stuck-recovery forever.
func TestDispatcher_Tick_ForceCancelsStuckLayerEvenIfStatusCheckErrors(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		sw, err := store.Create(ctx, Sweep{
			AgentID: "agent-stuck-statuserr-1", Layers: []string{"em-03-memory-attacks"}, TotalLayers: 1,
		})
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		if err := store.AdvanceToNext(ctx, sw.ID, 0, 0, "sr-stuck-statuserr-1"); err != nil {
			t.Fatalf("seed AdvanceToNext: %v", err)
		}

		var cancelledRunIDs []string
		d := NewDispatcher(store, func(ctx context.Context, scenarioRunID string) (string, error) {
			return "", errors.New("simulated persistent status-check failure")
		})
		d.SetDispatch(func(ctx context.Context, sweepID, agentID, scenarioID string) (string, error) {
			t.Fatal("dispatch should not be called")
			return "", nil
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
			AgentID: "agent-tick-5", Layers: []string{"em-01"}, TotalLayers: 1,
		})
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		if err := store.MarkStopped(ctx, sw.ID); err != nil {
			t.Fatalf("MarkStopped: %v", err)
		}

		d := NewDispatcher(store, func(ctx context.Context, scenarioRunID string) (string, error) {
			t.Fatal("status check should not be called for a stopped sweep")
			return "", nil
		})
		d.SetDispatch(func(ctx context.Context, sweepID, agentID, scenarioID string) (string, error) {
			t.Fatal("dispatch should not be called for a stopped sweep")
			return "", nil
		})

		if err := d.Tick(ctx); err != nil {
			t.Fatalf("Tick: %v", err)
		}
	})
}
