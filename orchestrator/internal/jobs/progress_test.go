package jobs

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestComputeProgress_CountsEveryTargetState(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		payload, _ := json.Marshal(map[string]string{"remediationId": "enable_windows_firewall", "reason": "test"})

		job, err := store.CreateBatch(ctx, "batch_remediation", payload, "user-1",
			[]string{"pg-a1", "pg-a2", "pg-a3", "pg-a4", "pg-a5", "pg-a6"})
		if err != nil {
			t.Fatalf("CreateBatch: %v", err)
		}
		targets, err := store.ListTargets(ctx, job.ID)
		if err != nil {
			t.Fatalf("ListTargets: %v", err)
		}
		if len(targets) != 6 {
			t.Fatalf("got %d targets, want 6", len(targets))
		}

		// targets[0] stays pending.
		if err := store.MarkTargetDispatched(ctx, targets[1].ID, "ref-1"); err != nil {
			t.Fatalf("MarkTargetDispatched: %v", err)
		}
		if err := store.MarkTargetTerminal(ctx, targets[2].ID, TargetStateCompleted, ""); err != nil {
			t.Fatalf("MarkTargetTerminal(completed): %v", err)
		}
		if err := store.MarkTargetTerminal(ctx, targets[3].ID, TargetStateFailed, "boom"); err != nil {
			t.Fatalf("MarkTargetTerminal(failed): %v", err)
		}
		if err := store.MarkTargetTerminal(ctx, targets[4].ID, TargetStateCancelled, ""); err != nil {
			t.Fatalf("MarkTargetTerminal(cancelled): %v", err)
		}
		if err := store.MarkTargetDeferred(ctx, targets[5].ID, "frozen"); err != nil {
			t.Fatalf("MarkTargetDeferred: %v", err)
		}

		progress, err := store.ComputeProgress(ctx, job.ID)
		if err != nil {
			t.Fatalf("ComputeProgress: %v", err)
		}
		want := JobProgress{Total: 6, Pending: 1, Dispatched: 1, Completed: 1, Failed: 1, Cancelled: 1, Deferred: 1, PercentComplete: 50}
		if progress != want {
			t.Errorf("progress = %+v, want %+v", progress, want)
		}
	})
}

func TestComputeProgress_AllFailed_Is100PercentComplete(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		payload, _ := json.Marshal(map[string]string{"remediationId": "enable_windows_firewall", "reason": "test"})

		job, err := store.CreateBatch(ctx, "batch_remediation", payload, "user-1", []string{"pg-b1", "pg-b2"})
		if err != nil {
			t.Fatalf("CreateBatch: %v", err)
		}
		targets, err := store.ListTargets(ctx, job.ID)
		if err != nil {
			t.Fatalf("ListTargets: %v", err)
		}
		for _, tg := range targets {
			if err := store.MarkTargetTerminal(ctx, tg.ID, TargetStateFailed, "boom"); err != nil {
				t.Fatalf("MarkTargetTerminal: %v", err)
			}
		}

		progress, err := store.ComputeProgress(ctx, job.ID)
		if err != nil {
			t.Fatalf("ComputeProgress: %v", err)
		}
		if progress.PercentComplete != 100 {
			t.Errorf("PercentComplete = %v, want 100 (fully terminal, even though every target failed)", progress.PercentComplete)
		}
	})
}

func TestComputeProgress_NoSuchJob_ReturnsZeroValue(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		store := NewStore(pool)
		progress, err := store.ComputeProgress(context.Background(), "no-such-job-id")
		if err != nil {
			t.Fatalf("ComputeProgress: %v", err)
		}
		if progress.Total != 0 || progress.PercentComplete != 0 {
			t.Errorf("progress = %+v, want all-zero for a job with no targets", progress)
		}
	})
}
