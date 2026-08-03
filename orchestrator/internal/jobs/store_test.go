package jobs

import (
	"context"
	"encoding/json"
	"flag"
	"os"
	"testing"

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

func TestCreateBatch_CreatesJobPlusOneTargetPerAgent(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		payload, _ := json.Marshal(map[string]string{"remediationId": "enable_windows_firewall", "reason": "test"})

		job, err := store.CreateBatch(ctx, "batch_remediation", payload, "user-1", []string{"agent-a", "agent-b", "agent-c"})
		if err != nil {
			t.Fatalf("CreateBatch: %v", err)
		}
		if job.ID == "" || job.State != JobStateRequested || job.Type != "batch_remediation" {
			t.Fatalf("job = %+v, want non-empty ID, State=requested, Type=batch_remediation", job)
		}

		targets, err := store.ListTargets(ctx, job.ID)
		if err != nil {
			t.Fatalf("ListTargets: %v", err)
		}
		if len(targets) != 3 {
			t.Fatalf("ListTargets() = %d rows, want 3", len(targets))
		}
		for _, tg := range targets {
			if tg.State != TargetStatePending {
				t.Errorf("target %s State = %q, want pending", tg.AgentID, tg.State)
			}
		}
	})
}

func TestListPendingTargetsAcrossActiveJobs_RespectsLimitAndOrder(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		payload, _ := json.Marshal(map[string]string{"remediationId": "enable_windows_firewall", "reason": "test"})
		job, err := store.CreateBatch(ctx, "batch_remediation", payload, "user-1", []string{"a1", "a2", "a3", "a4", "a5"})
		if err != nil {
			t.Fatalf("CreateBatch: %v", err)
		}

		got, err := store.ListPendingTargetsAcrossActiveJobs(ctx, 3)
		if err != nil {
			t.Fatalf("ListPendingTargetsAcrossActiveJobs: %v", err)
		}
		if len(got) != 3 {
			t.Fatalf("ListPendingTargetsAcrossActiveJobs(limit=3) = %d rows, want 3 (out of 5 pending)", len(got))
		}
		for _, tg := range got {
			if tg.JobID != job.ID {
				t.Errorf("target JobID = %q, want %q", tg.JobID, job.ID)
			}
		}
	})
}

func TestMarkTargetDispatchedThenTerminal_UpdatesState(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		payload, _ := json.Marshal(map[string]string{"remediationId": "enable_windows_firewall", "reason": "test"})
		job, err := store.CreateBatch(ctx, "batch_remediation", payload, "user-1", []string{"agent-x"})
		if err != nil {
			t.Fatalf("CreateBatch: %v", err)
		}
		targets, _ := store.ListTargets(ctx, job.ID)
		target := targets[0]

		if err := store.MarkTargetDispatched(ctx, target.ID, "ref-123"); err != nil {
			t.Fatalf("MarkTargetDispatched: %v", err)
		}
		dispatched, err := store.ListActiveDispatchedTargets(ctx)
		if err != nil {
			t.Fatalf("ListActiveDispatchedTargets: %v", err)
		}
		found := false
		for _, tg := range dispatched {
			if tg.ID == target.ID && tg.RefID == "ref-123" {
				found = true
			}
		}
		if !found {
			t.Fatalf("ListActiveDispatchedTargets() = %+v, want target %s with RefID=ref-123", dispatched, target.ID)
		}

		if err := store.MarkTargetTerminal(ctx, target.ID, TargetStateFailed, "agent not connected"); err != nil {
			t.Fatalf("MarkTargetTerminal: %v", err)
		}
		final, err := store.ListTargets(ctx, job.ID)
		if err != nil {
			t.Fatalf("ListTargets: %v", err)
		}
		if final[0].State != TargetStateFailed || final[0].Error != "agent not connected" || final[0].CompletedAt == nil {
			t.Fatalf("final target = %+v, want State=failed Error='agent not connected' CompletedAt set", final[0])
		}
		stillDispatched, err := store.ListActiveDispatchedTargets(ctx)
		if err != nil {
			t.Fatalf("ListActiveDispatchedTargets: %v", err)
		}
		for _, tg := range stillDispatched {
			if tg.ID == target.ID {
				t.Fatalf("target %s still shows up as dispatched after being marked terminal", target.ID)
			}
		}
	})
}

func TestSetJobState_TerminalStateStampsCompletedAt(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		payload, _ := json.Marshal(map[string]string{"remediationId": "enable_windows_firewall", "reason": "test"})
		job, err := store.CreateBatch(ctx, "batch_remediation", payload, "user-1", []string{"agent-y"})
		if err != nil {
			t.Fatalf("CreateBatch: %v", err)
		}

		if err := store.SetJobState(ctx, job.ID, JobStateRunning); err != nil {
			t.Fatalf("SetJobState(running): %v", err)
		}
		mid, err := store.Get(ctx, job.ID)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if mid.State != JobStateRunning || mid.StartedAt == nil || mid.CompletedAt != nil {
			t.Fatalf("mid state = %+v, want State=running StartedAt set CompletedAt nil", mid)
		}

		if err := store.SetJobState(ctx, job.ID, JobStateCompleted); err != nil {
			t.Fatalf("SetJobState(completed): %v", err)
		}
		final, err := store.Get(ctx, job.ID)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if final.State != JobStateCompleted || final.CompletedAt == nil {
			t.Fatalf("final state = %+v, want State=completed CompletedAt set", final)
		}
	})
}

func TestCancelJob_CancelsPendingLeavesDispatchedAlone(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		payload, _ := json.Marshal(map[string]string{"remediationId": "enable_windows_firewall", "reason": "test"})
		job, err := store.CreateBatch(ctx, "batch_remediation", payload, "user-1", []string{"agent-p", "agent-d"})
		if err != nil {
			t.Fatalf("CreateBatch: %v", err)
		}
		targets, _ := store.ListTargets(ctx, job.ID)
		var dispatchedID string
		for _, tg := range targets {
			if tg.AgentID == "agent-d" {
				dispatchedID = tg.ID
			}
		}
		if err := store.MarkTargetDispatched(ctx, dispatchedID, "ref-d"); err != nil {
			t.Fatalf("MarkTargetDispatched: %v", err)
		}

		cancelled, err := store.CancelJob(ctx, job.ID)
		if err != nil {
			t.Fatalf("CancelJob: %v", err)
		}
		if cancelled != 1 {
			t.Fatalf("CancelJob() cancelled = %d, want 1 (only the still-pending target)", cancelled)
		}

		final, err := store.ListTargets(ctx, job.ID)
		if err != nil {
			t.Fatalf("ListTargets: %v", err)
		}
		for _, tg := range final {
			switch tg.AgentID {
			case "agent-p":
				if tg.State != TargetStateCancelled {
					t.Errorf("agent-p State = %q, want cancelled", tg.State)
				}
			case "agent-d":
				if tg.State != TargetStateDispatched {
					t.Errorf("agent-d State = %q, want dispatched (already in flight, untouched)", tg.State)
				}
			}
		}
		gotJob, err := store.Get(ctx, job.ID)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if gotJob.State != JobStateCancelled {
			t.Errorf("job State = %q, want cancelled", gotJob.State)
		}
	})
}
