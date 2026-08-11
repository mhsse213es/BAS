package vexsweep

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

// TestAdvanceToNext_StampsAndClearsCurrentTechniqueStartedAt proves the
// column Dispatcher's stuck-technique detection relies on is actually
// written: set to ~now when a technique is dispatched, cleared to NULL once
// the sweep completes (no "current technique" left to time out).
func TestAdvanceToNext_StampsAndClearsCurrentTechniqueStartedAt(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		sw, err := store.Create(ctx, Sweep{
			AgentID: "agent-started-at", Mode: "sequential",
			Techniques: []string{"T1072"}, TechniqueVariantCounts: []int{10}, TotalVariants: 10,
		})
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		if got, _ := store.Get(ctx, sw.ID); got.CurrentTechniqueStartedAt != nil {
			t.Fatalf("newly-created sweep should have no current technique yet, got CurrentTechniqueStartedAt=%v", got.CurrentTechniqueStartedAt)
		}

		if err := store.AdvanceToNext(ctx, sw.ID, 0, 0, "vr-started-at", "sr-started-at"); err != nil {
			t.Fatalf("AdvanceToNext (dispatch): %v", err)
		}
		mid, _ := store.Get(ctx, sw.ID)
		if mid.CurrentTechniqueStartedAt == nil {
			t.Fatal("CurrentTechniqueStartedAt should be set once a technique is dispatched")
		}
		if time.Since(*mid.CurrentTechniqueStartedAt) > 5*time.Second {
			t.Fatalf("CurrentTechniqueStartedAt = %v, want ~now", *mid.CurrentTechniqueStartedAt)
		}

		if err := store.AdvanceToNext(ctx, sw.ID, 10, 1, "", ""); err != nil {
			t.Fatalf("AdvanceToNext (complete): %v", err)
		}
		final, _ := store.Get(ctx, sw.ID)
		if final.CurrentTechniqueStartedAt != nil {
			t.Fatalf("CurrentTechniqueStartedAt should be cleared once the sweep completes, got %v", final.CurrentTechniqueStartedAt)
		}
	})
}

func TestCreate_PersistsAndGetRoundTrips(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		created, err := store.Create(ctx, Sweep{
			AgentID:                "agent-1",
			Mode:                   "sequential",
			Techniques:             []string{"T1059.001", "T1059.003"},
			TechniqueVariantCounts: []int{33, 12},
			TotalVariants:          45,
			CreatedBy:              "user-1",
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
		if len(got.Techniques) != 2 || got.Techniques[0] != "T1059.001" || got.Techniques[1] != "T1059.003" {
			t.Errorf("Techniques = %v, want [T1059.001 T1059.003]", got.Techniques)
		}
		if len(got.TechniqueVariantCounts) != 2 || got.TechniqueVariantCounts[0] != 33 || got.TechniqueVariantCounts[1] != 12 {
			t.Errorf("TechniqueVariantCounts = %v, want [33 12]", got.TechniqueVariantCounts)
		}
		if got.TotalVariants != 45 {
			t.Errorf("TotalVariants = %d, want 45", got.TotalVariants)
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
		base := Sweep{AgentID: "agent-conflict", Mode: "sequential", Techniques: []string{"T1059.001"}, TechniqueVariantCounts: []int{1}, TotalVariants: 1}

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
		if _, err := store.Create(ctx, Sweep{AgentID: "agent-a", Mode: "sequential", Techniques: []string{"T1059.001"}, TechniqueVariantCounts: []int{1}, TotalVariants: 1}); err != nil {
			t.Fatalf("Create agent-a: %v", err)
		}
		if _, err := store.Create(ctx, Sweep{AgentID: "agent-b", Mode: "sequential", Techniques: []string{"T1059.001"}, TechniqueVariantCounts: []int{1}, TotalVariants: 1}); err != nil {
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
		created, err := store.Create(ctx, Sweep{AgentID: "agent-active", Mode: "sequential", Techniques: []string{"T1059.001"}, TechniqueVariantCounts: []int{1}, TotalVariants: 1})
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		got, found, err := store.GetActiveForAgent(ctx, "agent-active")
		if err != nil {
			t.Fatalf("GetActiveForAgent: %v", err)
		}
		if !found || got.ID != created.ID {
			t.Fatalf("GetActiveForAgent(agent-active) = %+v, found=%v, want ID=%s found=true", got, found, created.ID)
		}
		_, found, err = store.GetActiveForAgent(ctx, "agent-with-no-sweep")
		if err != nil {
			t.Fatalf("GetActiveForAgent: %v", err)
		}
		if found {
			t.Fatal("GetActiveForAgent(agent-with-no-sweep) found=true, want false")
		}
	})
}

func TestAdvanceToNext_CreditsAndAdvancesThenCompletes(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		created, err := store.Create(ctx, Sweep{
			AgentID: "agent-advance", Mode: "sequential",
			Techniques: []string{"T1059.001", "T1059.003"}, TechniqueVariantCounts: []int{33, 12}, TotalVariants: 45,
		})
		if err != nil {
			t.Fatalf("Create: %v", err)
		}

		// First technique finishes -- advance to the second.
		if err := store.AdvanceToNext(ctx, created.ID, 33, 1, "vr-2", "sr-2"); err != nil {
			t.Fatalf("AdvanceToNext (1st): %v", err)
		}
		mid, err := store.Get(ctx, created.ID)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if mid.CurrentIndex != 1 || mid.CompletedVariants != 33 || mid.CurrentVariantRunID != "vr-2" || mid.Status != "running" {
			t.Fatalf("mid-sweep state = %+v, want CurrentIndex=1 CompletedVariants=33 CurrentVariantRunID=vr-2 Status=running", mid)
		}

		// Second (last) technique finishes -- sweep completes.
		if err := store.AdvanceToNext(ctx, created.ID, 12, 2, "", ""); err != nil {
			t.Fatalf("AdvanceToNext (2nd): %v", err)
		}
		final, err := store.Get(ctx, created.ID)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if final.Status != "completed" || final.CompletedVariants != 45 || final.CompletedAt == nil {
			t.Fatalf("final state = %+v, want Status=completed CompletedVariants=45 CompletedAt set", final)
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

		stopped, err := store.Create(ctx, Sweep{AgentID: "agent-stop", Mode: "sequential", Techniques: []string{"T1059.001"}, TechniqueVariantCounts: []int{1}, TotalVariants: 1})
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		if err := store.MarkStopped(ctx, stopped.ID); err != nil {
			t.Fatalf("MarkStopped: %v", err)
		}
		got, _ := store.Get(ctx, stopped.ID)
		if got.Status != "stopped" || got.CompletedAt == nil {
			t.Fatalf("after MarkStopped: %+v, want Status=stopped CompletedAt set", got)
		}

		failed, err := store.Create(ctx, Sweep{AgentID: "agent-fail", Mode: "sequential", Techniques: []string{"T1059.001"}, TechniqueVariantCounts: []int{1}, TotalVariants: 1})
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		if err := store.MarkFailed(ctx, failed.ID, "agent went offline"); err != nil {
			t.Fatalf("MarkFailed: %v", err)
		}
		got, _ = store.Get(ctx, failed.ID)
		if got.Status != "failed" || got.Error != "agent went offline" {
			t.Fatalf("after MarkFailed: %+v, want Status=failed Error=%q", got, "agent went offline")
		}
	})
}
