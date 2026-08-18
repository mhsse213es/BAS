package emsweep

import (
	"context"
	"errors"
	"flag"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/testutil"
)

var sharedDB *testutil.TestDB

func TestMain(m *testing.M) {
	flag.Parse()
	if testing.Short() {
		os.Exit(m.Run())
	}
	sharedDB = testutil.MustSharedTestDB()
	code := m.Run()
	sharedDB.Cleanup()
	os.Exit(code)
}

func TestCreate_PersistsAndGetRoundTrips(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		created, err := store.Create(ctx, Sweep{
			AgentID: "agent-1", Layers: []string{"em-01", "em-02", "em-03"}, TotalLayers: 3, CreatedBy: "user-1",
		})
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		if created.ID == "" {
			t.Fatal("Create() returned empty ID")
		}
		if created.Status != "running" {
			t.Errorf("Status = %q, want %q (default)", created.Status, "running")
		}

		got, err := store.Get(ctx, created.ID)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if len(got.Layers) != 3 || got.Layers[0] != "em-01" || got.Layers[2] != "em-03" {
			t.Errorf("Layers = %v, want [em-01 em-02 em-03]", got.Layers)
		}
		if got.TotalLayers != 3 {
			t.Errorf("TotalLayers = %d, want 3", got.TotalLayers)
		}
		if got.AgentID != "agent-1" || got.CreatedBy != "user-1" {
			t.Errorf("round-trip mismatch: %+v", got)
		}
	})
}

func TestCreate_RejectsSecondRunningSweepSameAgent(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		base := Sweep{AgentID: "agent-conflict", Layers: []string{"em-01"}, TotalLayers: 1}

		if _, err := store.Create(ctx, base); err != nil {
			t.Fatalf("first Create: %v", err)
		}
		_, err := store.Create(ctx, base)
		if !errors.Is(err, ErrAgentAlreadySweeping) {
			t.Fatalf("second Create() err = %v, want ErrAgentAlreadySweeping", err)
		}
	})
}

func TestCreate_AllowsConcurrentSweepsDifferentAgents(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		if _, err := store.Create(ctx, Sweep{AgentID: "agent-a", Layers: []string{"em-01"}, TotalLayers: 1}); err != nil {
			t.Fatalf("Create agent-a: %v", err)
		}
		if _, err := store.Create(ctx, Sweep{AgentID: "agent-b", Layers: []string{"em-01"}, TotalLayers: 1}); err != nil {
			t.Fatalf("Create agent-b: %v", err)
		}
		running, err := store.ListRunning(ctx)
		if err != nil {
			t.Fatalf("ListRunning: %v", err)
		}
		if len(running) != 2 {
			t.Fatalf("ListRunning() = %+v, want 2 sweeps (one per agent)", running)
		}
	})
}

func TestGetActiveForAgent_FoundAndNotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		_, found, err := store.GetActiveForAgent(ctx, "agent-never-swept")
		if err != nil {
			t.Fatalf("GetActiveForAgent (not found): %v", err)
		}
		if found {
			t.Fatal("expected found=false for an agent with no sweep")
		}
		created, err := store.Create(ctx, Sweep{AgentID: "agent-active", Layers: []string{"em-01"}, TotalLayers: 1})
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		got, found, err := store.GetActiveForAgent(ctx, "agent-active")
		if err != nil {
			t.Fatalf("GetActiveForAgent (found): %v", err)
		}
		if !found || got.ID != created.ID {
			t.Fatalf("GetActiveForAgent = (%+v, %v), want the created sweep", got, found)
		}
	})
}

// TestAdvanceToNext_StampsAndClearsCurrentLayerStartedAt proves the column
// Dispatcher's stuck-layer detection relies on is actually written: set to
// ~now when a layer is dispatched, cleared to NULL once the sweep completes
// (no "current layer" left to time out). Mirrors vexsweep's identical test.
func TestAdvanceToNext_StampsAndClearsCurrentLayerStartedAt(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		sw, err := store.Create(ctx, Sweep{AgentID: "agent-started-at", Layers: []string{"em-01"}, TotalLayers: 1})
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		if got, _ := store.Get(ctx, sw.ID); got.CurrentLayerStartedAt != nil {
			t.Fatalf("newly-created sweep should have no current layer yet, got CurrentLayerStartedAt=%v", got.CurrentLayerStartedAt)
		}

		if err := store.AdvanceToNext(ctx, sw.ID, 0, 0, "sr-started-at"); err != nil {
			t.Fatalf("AdvanceToNext (dispatch): %v", err)
		}
		mid, _ := store.Get(ctx, sw.ID)
		if mid.CurrentLayerStartedAt == nil {
			t.Fatal("CurrentLayerStartedAt should be set once a layer is dispatched")
		}
		if time.Since(*mid.CurrentLayerStartedAt) > 5*time.Second {
			t.Fatalf("CurrentLayerStartedAt = %v, want ~now", *mid.CurrentLayerStartedAt)
		}

		if err := store.AdvanceToNext(ctx, sw.ID, 1, 1, ""); err != nil {
			t.Fatalf("AdvanceToNext (complete): %v", err)
		}
		final, _ := store.Get(ctx, sw.ID)
		if final.CurrentLayerStartedAt != nil {
			t.Fatalf("CurrentLayerStartedAt should be cleared once the sweep completes, got %v", final.CurrentLayerStartedAt)
		}
	})
}

// TestAdvanceToNext_CreditsAndAdvancesThenCompletes proves the
// justCompleted-credit/advance/complete lifecycle: the very first dispatch
// (layer 0) credits 0 (nothing has finished yet), advancing past a finished
// layer credits 1 (every EM layer is worth exactly 1, unlike vexsweep's
// variable variant-count credit), and reaching the end marks the sweep
// completed.
func TestAdvanceToNext_CreditsAndAdvancesThenCompletes(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		sw, err := store.Create(ctx, Sweep{AgentID: "agent-advance", Layers: []string{"em-01", "em-02"}, TotalLayers: 2})
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		// First dispatch: layer 0, nothing completed yet.
		if err := store.AdvanceToNext(ctx, sw.ID, 0, 0, "run-em-01"); err != nil {
			t.Fatalf("AdvanceToNext (first dispatch): %v", err)
		}
		got, _ := store.Get(ctx, sw.ID)
		if got.CompletedLayers != 0 || got.CurrentIndex != 0 || got.CurrentScenarioRunID != "run-em-01" {
			t.Fatalf("after first dispatch: %+v", got)
		}
		// Advance to layer 1, crediting layer 0 as finished.
		if err := store.AdvanceToNext(ctx, sw.ID, 1, 1, "run-em-02"); err != nil {
			t.Fatalf("AdvanceToNext (advance): %v", err)
		}
		got, _ = store.Get(ctx, sw.ID)
		if got.CompletedLayers != 1 || got.CurrentIndex != 1 || got.CurrentScenarioRunID != "run-em-02" || got.Status != "running" {
			t.Fatalf("after advance: %+v", got)
		}
		// Complete: credit layer 1, nextScenarioRunID == "" means no more layers.
		if err := store.AdvanceToNext(ctx, sw.ID, 1, 2, ""); err != nil {
			t.Fatalf("AdvanceToNext (complete): %v", err)
		}
		got, _ = store.Get(ctx, sw.ID)
		if got.CompletedLayers != 2 || got.Status != "completed" || got.CurrentScenarioRunID != "" || got.CompletedAt == nil {
			t.Fatalf("after completing advance: %+v", got)
		}
	})
}

func TestGetActiveForAgent_TreatsDisconnectedAsActive(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		sw, err := store.Create(ctx, Sweep{AgentID: "agent-disc-active", Layers: []string{"em-01"}, TotalLayers: 1})
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		if err := store.MarkDisconnected(ctx, sw.ID, 0); err != nil {
			t.Fatalf("MarkDisconnected: %v", err)
		}
		got, found, err := store.GetActiveForAgent(ctx, "agent-disc-active")
		if err != nil {
			t.Fatalf("GetActiveForAgent: %v", err)
		}
		if !found || got.ID != sw.ID {
			t.Fatalf("GetActiveForAgent = (%+v, %v), want the disconnected sweep to still count as active", got, found)
		}
	})
}

func TestListActionable_IncludesRunningAndDisconnectedOnly(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		running, err := store.Create(ctx, Sweep{AgentID: "agent-actionable-running", Layers: []string{"em-01"}, TotalLayers: 1})
		if err != nil {
			t.Fatalf("Create running: %v", err)
		}
		disconnected, err := store.Create(ctx, Sweep{AgentID: "agent-actionable-disc", Layers: []string{"em-01"}, TotalLayers: 1})
		if err != nil {
			t.Fatalf("Create disconnected: %v", err)
		}
		if err := store.MarkDisconnected(ctx, disconnected.ID, 0); err != nil {
			t.Fatalf("MarkDisconnected: %v", err)
		}
		stopped, err := store.Create(ctx, Sweep{AgentID: "agent-actionable-stopped", Layers: []string{"em-01"}, TotalLayers: 1})
		if err != nil {
			t.Fatalf("Create stopped: %v", err)
		}
		if err := store.MarkStopped(ctx, stopped.ID); err != nil {
			t.Fatalf("MarkStopped: %v", err)
		}

		got, err := store.ListActionable(ctx)
		if err != nil {
			t.Fatalf("ListActionable: %v", err)
		}
		ids := map[string]bool{}
		for _, sw := range got {
			ids[sw.ID] = true
		}
		if !ids[running.ID] || !ids[disconnected.ID] {
			t.Fatalf("ListActionable() = %+v, want both the running and disconnected sweeps", got)
		}
		if ids[stopped.ID] {
			t.Fatalf("ListActionable() included a stopped sweep: %+v", got)
		}
	})
}

// TestMarkDisconnected_SetsStatusAndClearsCurrentRun proves the pause
// transition: status flips, disconnected_at is stamped, and the current run
// pointer clears since whatever was in flight has already been separately
// resolved by the caller (or never existed, in the dispatchNext race case).
// pendingIndex names the layer to re-dispatch on reconnect.
func TestMarkDisconnected_SetsStatusAndClearsCurrentRun(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		sw, err := store.Create(ctx, Sweep{AgentID: "agent-mark-disc", Layers: []string{"em-01", "em-02"}, TotalLayers: 2})
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		if err := store.AdvanceToNext(ctx, sw.ID, 0, 0, "sr-mark-disc"); err != nil {
			t.Fatalf("seed AdvanceToNext: %v", err)
		}

		if err := store.MarkDisconnected(ctx, sw.ID, 0); err != nil {
			t.Fatalf("MarkDisconnected: %v", err)
		}
		got, _ := store.Get(ctx, sw.ID)
		if got.Status != "agent_disconnected" {
			t.Fatalf("Status = %q, want agent_disconnected", got.Status)
		}
		if got.DisconnectedAt == nil {
			t.Fatal("DisconnectedAt should be set")
		}
		if got.CurrentScenarioRunID != "" {
			t.Fatalf("CurrentScenarioRunID = %q, want cleared", got.CurrentScenarioRunID)
		}
		if got.CurrentLayerStartedAt != nil {
			t.Fatal("CurrentLayerStartedAt should be cleared")
		}
		if got.CurrentIndex != 0 {
			t.Fatalf("CurrentIndex = %d, want 0 (pendingIndex)", got.CurrentIndex)
		}
	})
}

// TestResume_ClearsDisconnectedAtAndSetsNewRun proves the un-pause
// transition: status flips back, disconnected_at clears, and the new run
// (from re-dispatching the pending layer) becomes current.
func TestResume_ClearsDisconnectedAtAndSetsNewRun(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		sw, err := store.Create(ctx, Sweep{AgentID: "agent-resume", Layers: []string{"em-01"}, TotalLayers: 1})
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		if err := store.MarkDisconnected(ctx, sw.ID, 0); err != nil {
			t.Fatalf("MarkDisconnected: %v", err)
		}

		if err := store.Resume(ctx, sw.ID, "sr-resumed"); err != nil {
			t.Fatalf("Resume: %v", err)
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
		if got.CurrentLayerStartedAt == nil {
			t.Fatal("CurrentLayerStartedAt should be set")
		}
	})
}

func TestMarkStopped_And_MarkFailed(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		sw1, err := store.Create(ctx, Sweep{AgentID: "agent-stop", Layers: []string{"em-01"}, TotalLayers: 1})
		if err != nil {
			t.Fatalf("Create sw1: %v", err)
		}
		if err := store.MarkStopped(ctx, sw1.ID); err != nil {
			t.Fatalf("MarkStopped: %v", err)
		}
		got1, _ := store.Get(ctx, sw1.ID)
		if got1.Status != "stopped" {
			t.Fatalf("Status = %q, want stopped", got1.Status)
		}

		sw2, err := store.Create(ctx, Sweep{AgentID: "agent-fail", Layers: []string{"em-01"}, TotalLayers: 1})
		if err != nil {
			t.Fatalf("Create sw2: %v", err)
		}
		if err := store.MarkFailed(ctx, sw2.ID, "layer dispatch exploded"); err != nil {
			t.Fatalf("MarkFailed: %v", err)
		}
		got2, _ := store.Get(ctx, sw2.ID)
		if got2.Status != "failed" || got2.Error != "layer dispatch exploded" {
			t.Fatalf("after MarkFailed: %+v", got2)
		}
	})
}
