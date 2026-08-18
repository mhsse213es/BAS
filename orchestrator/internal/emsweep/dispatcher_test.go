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
		d.SetDispatch(func(ctx context.Context, sweepID, agentID, scenarioID string, layerIndex, totalLayers int) (string, error) {
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
		d.SetDispatch(func(ctx context.Context, sweepID, agentID, scenarioID string, layerIndex, totalLayers int) (string, error) {
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
		d.SetDispatch(func(ctx context.Context, sweepID, agentID, scenarioID string, layerIndex, totalLayers int) (string, error) {
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
		d.SetDispatch(func(ctx context.Context, sweepID, agentID, scenarioID string, layerIndex, totalLayers int) (string, error) {
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
		d.SetDispatch(func(ctx context.Context, sweepID, agentID, scenarioID string, layerIndex, totalLayers int) (string, error) {
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
		d.SetDispatch(func(ctx context.Context, sweepID, agentID, scenarioID string, layerIndex, totalLayers int) (string, error) {
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
		d.SetDispatch(func(ctx context.Context, sweepID, agentID, scenarioID string, layerIndex, totalLayers int) (string, error) {
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
		d.SetDispatch(func(ctx context.Context, sweepID, agentID, scenarioID string, layerIndex, totalLayers int) (string, error) {
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
		d.SetDispatch(func(ctx context.Context, sweepID, agentID, scenarioID string, layerIndex, totalLayers int) (string, error) {
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
		d.SetDispatch(func(ctx context.Context, sweepID, agentID, scenarioID string, layerIndex, totalLayers int) (string, error) {
			t.Fatal("dispatch should not be called for a stopped sweep")
			return "", nil
		})

		if err := d.Tick(ctx); err != nil {
			t.Fatalf("Tick: %v", err)
		}
	})
}

// TestDispatcher_Tick_PausesOnDisconnectAndCancelsInFlightRun is the
// regression test for the actual bug reported: an agent that disconnects
// mid-layer used to sit "running" for a full 3 minutes, then get force-
// cancelled and the WHOLE SWEEP marked failed on the next dispatch attempt
// (since the agent was still offline) -- typically well before the user
// could reconnect. The Dispatcher must instead detect the disconnect
// immediately (via ConnectedFn) and pause, not fail.
func TestDispatcher_Tick_PausesOnDisconnectAndCancelsInFlightRun(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		sw, err := store.Create(ctx, Sweep{
			AgentID: "agent-disc-1", Layers: []string{"em-01", "em-02"}, TotalLayers: 2,
		})
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		if err := store.AdvanceToNext(ctx, sw.ID, 0, 0, "sr-disc-1"); err != nil {
			t.Fatalf("seed AdvanceToNext: %v", err)
		}

		var cancelledRunIDs []string
		d := NewDispatcher(store, func(ctx context.Context, scenarioRunID string) (string, error) {
			return "running", nil // the layer never gets a chance to finish -- agent went offline
		})
		d.SetDispatch(func(ctx context.Context, sweepID, agentID, scenarioID string, layerIndex, totalLayers int) (string, error) {
			t.Fatal("dispatch should not be called -- the sweep must pause, not advance")
			return "", nil
		})
		d.SetCancel(func(ctx context.Context, scenarioRunID string) (string, string, error) {
			cancelledRunIDs = append(cancelledRunIDs, scenarioRunID)
			return "agent-disc-1", "partial", nil
		})
		d.SetConnected(func(agentID string) bool { return false }) // agent is offline

		if err := d.Tick(ctx); err != nil {
			t.Fatalf("Tick: %v", err)
		}
		got, _ := store.Get(ctx, sw.ID)
		if got.Status != "agent_disconnected" {
			t.Fatalf("Status = %q, want agent_disconnected", got.Status)
		}
		if got.DisconnectedAt == nil {
			t.Fatal("DisconnectedAt should be set")
		}
		if len(cancelledRunIDs) != 1 || cancelledRunIDs[0] != "sr-disc-1" {
			t.Fatalf("cancelledRunIDs = %v, want exactly [sr-disc-1] (the in-flight layer must be cancelled, not left dangling)", cancelledRunIDs)
		}
		if got.CurrentIndex != 0 {
			t.Fatalf("CurrentIndex = %d, want 0 (the interrupted layer, unchanged, ready to re-dispatch on reconnect)", got.CurrentIndex)
		}
	})
}

// TestDispatcher_Tick_WaitsIndefinitelyWhileDisconnected proves the
// no-timeout decision: unlike the connected-but-stuck path, a disconnected
// sweep never force-advances or fails on its own, no matter how much time
// passes -- it just waits for reconnect or an explicit Stop.
func TestDispatcher_Tick_WaitsIndefinitelyWhileDisconnected(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		sw, err := store.Create(ctx, Sweep{
			AgentID: "agent-disc-2", Layers: []string{"em-01"}, TotalLayers: 1,
		})
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		if err := store.MarkDisconnected(ctx, sw.ID, 0); err != nil {
			t.Fatalf("MarkDisconnected: %v", err)
		}

		d := NewDispatcher(store, func(ctx context.Context, scenarioRunID string) (string, error) {
			t.Fatal("status should not be checked -- no run is in flight while disconnected")
			return "", nil
		})
		d.SetDispatch(func(ctx context.Context, sweepID, agentID, scenarioID string, layerIndex, totalLayers int) (string, error) {
			t.Fatal("dispatch should not be called -- agent is still offline")
			return "", nil
		})
		d.SetCancel(func(ctx context.Context, scenarioRunID string) (string, string, error) {
			t.Fatal("cancel should not be called -- nothing is in flight while disconnected")
			return "", "", nil
		})
		d.stuckThreshold = time.Millisecond // would force-fail almost instantly if the old timer still applied here
		d.SetConnected(func(agentID string) bool { return false })

		time.Sleep(5 * time.Millisecond)

		for i := 0; i < 3; i++ {
			if err := d.Tick(ctx); err != nil {
				t.Fatalf("Tick %d: %v", i, err)
			}
		}
		got, _ := store.Get(ctx, sw.ID)
		if got.Status != "agent_disconnected" {
			t.Fatalf("Status = %q after 3 ticks while still offline, want agent_disconnected (must not time out)", got.Status)
		}
	})
}

// TestDispatcher_Tick_ResumesInterruptedLayerOnReconnect proves the resume
// behavior the user explicitly asked for: the interrupted layer is
// re-dispatched from scratch, not skipped, once the agent reconnects.
func TestDispatcher_Tick_ResumesInterruptedLayerOnReconnect(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		sw, err := store.Create(ctx, Sweep{
			AgentID: "agent-disc-3", Layers: []string{"em-01", "em-02"}, TotalLayers: 2,
		})
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		if err := store.MarkDisconnected(ctx, sw.ID, 1); err != nil { // was mid-layer 1 (0-indexed second layer) when it disconnected
			t.Fatalf("MarkDisconnected: %v", err)
		}

		var dispatchedLayers []string
		d := NewDispatcher(store, func(ctx context.Context, scenarioRunID string) (string, error) {
			t.Fatal("status should not be checked this tick -- no run was in flight before resuming")
			return "", nil
		})
		d.SetDispatch(func(ctx context.Context, sweepID, agentID, scenarioID string, layerIndex, totalLayers int) (string, error) {
			dispatchedLayers = append(dispatchedLayers, scenarioID)
			if layerIndex != 1 {
				t.Fatalf("layerIndex = %d, want 1 (the interrupted layer)", layerIndex)
			}
			return "sr-resumed", nil
		})
		d.SetConnected(func(agentID string) bool { return true }) // agent is back

		if err := d.Tick(ctx); err != nil {
			t.Fatalf("Tick: %v", err)
		}
		if len(dispatchedLayers) != 1 || dispatchedLayers[0] != "em-02" {
			t.Fatalf("dispatchedLayers = %v, want [em-02] (the interrupted layer, re-dispatched from scratch)", dispatchedLayers)
		}
		got, _ := store.Get(ctx, sw.ID)
		if got.Status != "running" {
			t.Fatalf("Status = %q, want running", got.Status)
		}
		if got.DisconnectedAt != nil {
			t.Fatal("DisconnectedAt should be cleared")
		}
		if got.CurrentScenarioRunID != "sr-resumed" {
			t.Fatalf("CurrentScenarioRunID = %q, want sr-resumed", got.CurrentScenarioRunID)
		}
		if got.CurrentIndex != 1 {
			t.Fatalf("CurrentIndex = %d, want unchanged at 1", got.CurrentIndex)
		}
	})
}

// TestDispatcher_Tick_ExistingBehaviorUnaffectedWhenConnectedFnNotSet proves
// backward compatibility: every dispatcher_test.go test written before this
// change never calls SetConnected, so d.connected stays nil. Those tests
// must keep passing unmodified -- a nil ConnectedFn must mean "connectivity
// awareness is off", not "treat every agent as disconnected".
func TestDispatcher_Tick_ExistingBehaviorUnaffectedWhenConnectedFnNotSet(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		if _, err := store.Create(ctx, Sweep{
			AgentID: "agent-no-connected-fn", Layers: []string{"em-01"}, TotalLayers: 1,
		}); err != nil {
			t.Fatalf("Create: %v", err)
		}

		var dispatchedLayers []string
		d := NewDispatcher(store, func(ctx context.Context, scenarioRunID string) (string, error) {
			return "running", nil
		})
		d.SetDispatch(func(ctx context.Context, sweepID, agentID, scenarioID string, layerIndex, totalLayers int) (string, error) {
			dispatchedLayers = append(dispatchedLayers, scenarioID)
			return "sr-1", nil
		})
		// Deliberately no SetConnected call.

		if err := d.Tick(ctx); err != nil {
			t.Fatalf("Tick: %v", err)
		}
		if len(dispatchedLayers) != 1 {
			t.Fatalf("dispatchedLayers = %v, want exactly 1 dispatch (nil ConnectedFn must not block normal dispatch)", dispatchedLayers)
		}
	})
}

// TestDispatcher_Tick_PausesInsteadOfFailingOnOfflineRaceDuringDispatch
// covers the narrow race window: ConnectedFn said the agent was reachable,
// but the dispatch call itself still failed because the agent dropped in
// between. dispatchNext must special-case ErrAgentOffline into a pause
// (same as a proactively-detected disconnect), not the ordinary
// MarkFailed/hard-fail path every other dispatch error still takes.
func TestDispatcher_Tick_PausesInsteadOfFailingOnOfflineRaceDuringDispatch(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		sw, err := store.Create(ctx, Sweep{
			AgentID: "agent-race-1", Layers: []string{"em-01"}, TotalLayers: 1,
		})
		if err != nil {
			t.Fatalf("Create: %v", err)
		}

		d := NewDispatcher(store, func(ctx context.Context, scenarioRunID string) (string, error) {
			return "running", nil
		})
		d.SetDispatch(func(ctx context.Context, sweepID, agentID, scenarioID string, layerIndex, totalLayers int) (string, error) {
			return "", ErrAgentOffline
		})
		d.SetConnected(func(agentID string) bool { return true }) // said reachable, but dispatch itself then fails

		if err := d.Tick(ctx); err != nil {
			t.Fatalf("Tick: %v", err)
		}
		got, _ := store.Get(ctx, sw.ID)
		if got.Status != "agent_disconnected" {
			t.Fatalf("Status = %q, want agent_disconnected (not failed)", got.Status)
		}
		if got.CurrentIndex != 0 {
			t.Fatalf("CurrentIndex = %d, want 0 (the layer the failed dispatch was trying to reach)", got.CurrentIndex)
		}
	})
}
