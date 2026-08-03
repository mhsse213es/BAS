package jobs

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestTick_DispatchesPendingTargetsUpToCap(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		payload, _ := json.Marshal(map[string]string{"remediationId": "enable_windows_firewall", "reason": "test"})
		agentIDs := make([]string, 0, jobDispatchBatchSize+5)
		for i := 0; i < jobDispatchBatchSize+5; i++ {
			agentIDs = append(agentIDs, "cap-agent-"+string(rune('a'+i)))
		}
		job, err := store.CreateBatch(ctx, "batch_remediation", payload, "user-1", agentIDs)
		if err != nil {
			t.Fatalf("CreateBatch: %v", err)
		}

		var dispatchedCount int
		d := NewDispatcher(store)
		d.SetDispatch(func(ctx context.Context, j Job, target JobTarget) (string, error) {
			dispatchedCount++
			return "ref-" + target.AgentID, nil
		})
		d.SetStatus(func(ctx context.Context, jobType, refID string) (string, string, bool) {
			return TargetStateDispatched, "", false
		})

		if err := d.Tick(ctx); err != nil {
			t.Fatalf("Tick: %v", err)
		}
		if dispatchedCount != jobDispatchBatchSize {
			t.Fatalf("dispatchedCount = %d, want %d (the per-tick cap)", dispatchedCount, jobDispatchBatchSize)
		}
		gotJob, err := store.Get(ctx, job.ID)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if gotJob.State != JobStateRunning {
			t.Errorf("job State = %q, want running (some targets dispatched, some still pending)", gotJob.State)
		}
	})
}

func TestTick_ResolvesTerminalTargetsAndAggregatesJobState(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		payload, _ := json.Marshal(map[string]string{"remediationId": "enable_windows_firewall", "reason": "test"})
		job, err := store.CreateBatch(ctx, "batch_remediation", payload, "user-1", []string{"agent-done"})
		if err != nil {
			t.Fatalf("CreateBatch: %v", err)
		}
		targets, _ := store.ListTargets(ctx, job.ID)
		if err := store.MarkTargetDispatched(ctx, targets[0].ID, "ref-done"); err != nil {
			t.Fatalf("MarkTargetDispatched: %v", err)
		}

		d := NewDispatcher(store)
		d.SetDispatch(func(ctx context.Context, j Job, target JobTarget) (string, error) {
			t.Fatal("dispatch should not be called -- the only target is already dispatched")
			return "", nil
		})
		d.SetStatus(func(ctx context.Context, jobType, refID string) (string, string, bool) {
			if refID == "ref-done" {
				return TargetStateCompleted, "", true
			}
			return TargetStateDispatched, "", false
		})

		if err := d.Tick(ctx); err != nil {
			t.Fatalf("Tick: %v", err)
		}
		gotJob, err := store.Get(ctx, job.ID)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if gotJob.State != JobStateCompleted || gotJob.CompletedAt == nil {
			t.Fatalf("job = %+v, want State=completed CompletedAt set", gotJob)
		}
	})
}

func TestTick_DispatchErrorMarksTargetFailedWithoutAborting(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		payload, _ := json.Marshal(map[string]string{"remediationId": "enable_windows_firewall", "reason": "test"})
		job, err := store.CreateBatch(ctx, "batch_remediation", payload, "user-1", []string{"agent-offline"})
		if err != nil {
			t.Fatalf("CreateBatch: %v", err)
		}

		d := NewDispatcher(store)
		d.SetDispatch(func(ctx context.Context, j Job, target JobTarget) (string, error) {
			return "", errors.New("agent not connected")
		})
		d.SetStatus(func(ctx context.Context, jobType, refID string) (string, string, bool) {
			t.Fatal("status should not be called -- nothing was dispatched")
			return "", "", false
		})

		if err := d.Tick(ctx); err != nil {
			t.Fatalf("Tick itself should not error (failure is recorded on the target, not returned): %v", err)
		}
		targets, err := store.ListTargets(ctx, job.ID)
		if err != nil {
			t.Fatalf("ListTargets: %v", err)
		}
		if targets[0].State != TargetStateFailed || targets[0].Error != "agent not connected" {
			t.Fatalf("target = %+v, want State=failed Error='agent not connected'", targets[0])
		}
		gotJob, err := store.Get(ctx, job.ID)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if gotJob.State != JobStateFailed {
			t.Errorf("job State = %q, want failed (its only target failed)", gotJob.State)
		}
	})
}

func TestTick_CancelledJobIsNeverTouched(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		payload, _ := json.Marshal(map[string]string{"remediationId": "enable_windows_firewall", "reason": "test"})
		job, err := store.CreateBatch(ctx, "batch_remediation", payload, "user-1", []string{"agent-c1", "agent-c2"})
		if err != nil {
			t.Fatalf("CreateBatch: %v", err)
		}
		if _, err := store.CancelJob(ctx, job.ID); err != nil {
			t.Fatalf("CancelJob: %v", err)
		}

		d := NewDispatcher(store)
		d.SetDispatch(func(ctx context.Context, j Job, target JobTarget) (string, error) {
			t.Fatal("dispatch should not be called for a cancelled job")
			return "", nil
		})
		d.SetStatus(func(ctx context.Context, jobType, refID string) (string, string, bool) {
			t.Fatal("status should not be called for a cancelled job")
			return "", "", false
		})

		if err := d.Tick(ctx); err != nil {
			t.Fatalf("Tick: %v", err)
		}
	})
}
