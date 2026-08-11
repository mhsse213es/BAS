package vexsweep

import (
	"context"
	"errors"
	"testing"

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
		d.SetDispatch(func(ctx context.Context, sweepID, agentID, techniqueID, mode string, includeAdvanced bool) (string, string, int, error) {
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
		d.SetDispatch(func(ctx context.Context, sweepID, agentID, techniqueID, mode string, includeAdvanced bool) (string, string, int, error) {
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
		d.SetDispatch(func(ctx context.Context, sweepID, agentID, techniqueID, mode string, includeAdvanced bool) (string, string, int, error) {
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
		d.SetDispatch(func(ctx context.Context, sweepID, agentID, techniqueID, mode string, includeAdvanced bool) (string, string, int, error) {
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
		d.SetDispatch(func(ctx context.Context, sweepID, agentID, techniqueID, mode string, includeAdvanced bool) (string, string, int, error) {
			t.Fatal("dispatch should not be called for a stopped sweep")
			return "", "", 0, nil
		})

		if err := d.Tick(ctx); err != nil {
			t.Fatalf("Tick: %v", err)
		}
	})
}
