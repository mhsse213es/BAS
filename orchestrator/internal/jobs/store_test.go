package jobs

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
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

func TestCreateBatchScheduled_FutureScheduledAt_TargetsNotDispatchable(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		// Truncated to microsecond precision -- Postgres timestamptz only
		// stores microseconds, so a nanosecond-precision time.Now() value
		// would never round-trip .Equal() otherwise.
		future := time.Now().UTC().Add(24 * time.Hour).Truncate(time.Microsecond)
		payload, _ := json.Marshal(map[string]string{"remediationId": "enable_windows_firewall", "reason": "test"})

		job, err := store.CreateBatchScheduled(ctx, "batch_remediation", payload, "user-1", []string{"agent-future"}, &future)
		if err != nil {
			t.Fatalf("CreateBatchScheduled: %v", err)
		}
		if job.ScheduledAt == nil || !job.ScheduledAt.Equal(future) {
			t.Fatalf("job.ScheduledAt = %v, want %v", job.ScheduledAt, future)
		}

		pending, err := store.ListPendingTargetsAcrossActiveJobs(ctx, 20)
		if err != nil {
			t.Fatalf("ListPendingTargetsAcrossActiveJobs: %v", err)
		}
		for _, tg := range pending {
			if tg.JobID == job.ID {
				t.Fatalf("target for future-scheduled job %s appeared in the dispatchable pending list", job.ID)
			}
		}
	})
}

func TestCreateBatchScheduled_PastScheduledAt_TargetsDispatchable(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		past := time.Now().UTC().Add(-1 * time.Hour)
		payload, _ := json.Marshal(map[string]string{"remediationId": "enable_windows_firewall", "reason": "test"})

		job, err := store.CreateBatchScheduled(ctx, "batch_remediation", payload, "user-1", []string{"agent-past"}, &past)
		if err != nil {
			t.Fatalf("CreateBatchScheduled: %v", err)
		}

		pending, err := store.ListPendingTargetsAcrossActiveJobs(ctx, 20)
		if err != nil {
			t.Fatalf("ListPendingTargetsAcrossActiveJobs: %v", err)
		}
		found := false
		for _, tg := range pending {
			if tg.JobID == job.ID {
				found = true
			}
		}
		if !found {
			t.Fatalf("target for past-scheduled job %s did not appear in the dispatchable pending list", job.ID)
		}
	})
}

func TestCreateBatch_NilScheduledAt_UnchangedBehavior(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		payload, _ := json.Marshal(map[string]string{"remediationId": "enable_windows_firewall", "reason": "test"})

		job, err := store.CreateBatch(ctx, "batch_remediation", payload, "user-1", []string{"agent-now"})
		if err != nil {
			t.Fatalf("CreateBatch: %v", err)
		}
		if job.ScheduledAt != nil {
			t.Fatalf("job.ScheduledAt = %v, want nil (CreateBatch's existing immediate-dispatch behavior)", job.ScheduledAt)
		}
	})
}

func TestMarkTargetDeferredThenPending_UpdatesState(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		payload, _ := json.Marshal(map[string]string{"remediationId": "enable_windows_firewall", "reason": "test"})
		job, err := store.CreateBatch(ctx, "batch_remediation", payload, "user-1", []string{"agent-defer"})
		if err != nil {
			t.Fatalf("CreateBatch: %v", err)
		}
		targets, _ := store.ListTargets(ctx, job.ID)
		target := targets[0]

		if err := store.MarkTargetDeferred(ctx, target.ID, "frozen: Q3 audit"); err != nil {
			t.Fatalf("MarkTargetDeferred: %v", err)
		}
		deferred, err := store.ListDeferredTargets(ctx)
		if err != nil {
			t.Fatalf("ListDeferredTargets: %v", err)
		}
		found := false
		for _, tg := range deferred {
			if tg.ID == target.ID && tg.Error == "frozen: Q3 audit" {
				found = true
			}
		}
		if !found {
			t.Fatalf("ListDeferredTargets() = %+v, want target %s with Error='frozen: Q3 audit'", deferred, target.ID)
		}

		if err := store.MarkTargetPending(ctx, target.ID); err != nil {
			t.Fatalf("MarkTargetPending: %v", err)
		}
		pending, err := store.ListPendingTargetsAcrossActiveJobs(ctx, 20)
		if err != nil {
			t.Fatalf("ListPendingTargetsAcrossActiveJobs: %v", err)
		}
		found = false
		for _, tg := range pending {
			if tg.ID == target.ID {
				found = true
			}
		}
		if !found {
			t.Fatal("target did not return to the pending list after MarkTargetPending")
		}
	})
}

func TestJobTarget_OwnershipColumnsScanCorrectly(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		payload, _ := json.Marshal(map[string]string{"remediationId": "enable_windows_firewall", "reason": "test"})
		job, err := store.CreateBatch(ctx, "batch_remediation", payload, "user-1", []string{"agent-own-1"})
		if err != nil {
			t.Fatalf("CreateBatch: %v", err)
		}
		targets, err := store.ListTargets(ctx, job.ID)
		if err != nil {
			t.Fatalf("ListTargets: %v", err)
		}
		if targets[0].OwnerID != "" || targets[0].AssignedAt != nil {
			t.Fatalf("new target = %+v, want unassigned by default (OwnerID=\"\", AssignedAt=nil)", targets[0])
		}

		mustExecJobsNotif(t, pool, `UPDATE job_targets SET owner_id=$1, assigned_at=NOW() WHERE id=$2`, "user-42", targets[0].ID)

		got, err := store.ListTargets(ctx, job.ID)
		if err != nil {
			t.Fatalf("ListTargets after raw update: %v", err)
		}
		if got[0].OwnerID != "user-42" || got[0].AssignedAt == nil {
			t.Fatalf("got = %+v, want OwnerID=user-42 AssignedAt set", got[0])
		}
	})
}

func TestSetTargetOwner_AssignsThenClears(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		payload, _ := json.Marshal(map[string]string{"remediationId": "enable_windows_firewall", "reason": "test"})
		job, err := store.CreateBatch(ctx, "batch_remediation", payload, "user-1", []string{"agent-so-1"})
		if err != nil {
			t.Fatalf("CreateBatch: %v", err)
		}
		targets, err := store.ListTargets(ctx, job.ID)
		if err != nil {
			t.Fatalf("ListTargets: %v", err)
		}

		assigned, err := store.SetTargetOwner(ctx, targets[0].ID, "user-7")
		if err != nil {
			t.Fatalf("SetTargetOwner (assign): %v", err)
		}
		if assigned.OwnerID != "user-7" || assigned.AssignedAt == nil {
			t.Fatalf("assigned = %+v, want OwnerID=user-7 AssignedAt set", assigned)
		}

		cleared, err := store.SetTargetOwner(ctx, targets[0].ID, "")
		if err != nil {
			t.Fatalf("SetTargetOwner (clear): %v", err)
		}
		if cleared.OwnerID != "" || cleared.AssignedAt != nil {
			t.Fatalf("cleared = %+v, want OwnerID=\"\" AssignedAt=nil", cleared)
		}
	})
}

func TestSetTargetOwner_NoSuchTarget_ReturnsErrNoRows(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		store := NewStore(pool)
		_, err := store.SetTargetOwner(context.Background(), "no-such-target-id", "user-1")
		if !errors.Is(err, pgx.ErrNoRows) {
			t.Fatalf("err = %v, want pgx.ErrNoRows", err)
		}
	})
}

func TestListTargetsByOwner_ReturnsOnlyThatOwnerAcrossJobs(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		payload, _ := json.Marshal(map[string]string{"remediationId": "enable_windows_firewall", "reason": "test"})
		jobA, err := store.CreateBatch(ctx, "batch_remediation", payload, "user-1", []string{"agent-lto-a"})
		if err != nil {
			t.Fatalf("CreateBatch A: %v", err)
		}
		jobB, err := store.CreateBatch(ctx, "batch_remediation", payload, "user-1", []string{"agent-lto-b"})
		if err != nil {
			t.Fatalf("CreateBatch B: %v", err)
		}
		targetsA, _ := store.ListTargets(ctx, jobA.ID)
		targetsB, _ := store.ListTargets(ctx, jobB.ID)

		if _, err := store.SetTargetOwner(ctx, targetsA[0].ID, "owner-x"); err != nil {
			t.Fatalf("SetTargetOwner A: %v", err)
		}
		if _, err := store.SetTargetOwner(ctx, targetsB[0].ID, "owner-x"); err != nil {
			t.Fatalf("SetTargetOwner B: %v", err)
		}

		got, err := store.ListTargetsByOwner(ctx, "owner-x", "")
		if err != nil {
			t.Fatalf("ListTargetsByOwner: %v", err)
		}
		if len(got) != 2 {
			t.Fatalf("got %d targets, want 2 (one from each job)", len(got))
		}
	})
}

func TestListTargetsByOwner_StateFilterNarrows(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		payload, _ := json.Marshal(map[string]string{"remediationId": "enable_windows_firewall", "reason": "test"})
		job, err := store.CreateBatch(ctx, "batch_remediation", payload, "user-1", []string{"agent-sfn-1", "agent-sfn-2"})
		if err != nil {
			t.Fatalf("CreateBatch: %v", err)
		}
		targets, _ := store.ListTargets(ctx, job.ID)
		store.SetTargetOwner(ctx, targets[0].ID, "owner-y")
		store.SetTargetOwner(ctx, targets[1].ID, "owner-y")
		if err := store.MarkTargetTerminal(ctx, targets[1].ID, TargetStateFailed, "boom"); err != nil {
			t.Fatalf("MarkTargetTerminal: %v", err)
		}

		got, err := store.ListTargetsByOwner(ctx, "owner-y", TargetStateFailed)
		if err != nil {
			t.Fatalf("ListTargetsByOwner: %v", err)
		}
		if len(got) != 1 || got[0].ID != targets[1].ID {
			t.Fatalf("got %+v, want exactly the failed target", got)
		}
	})
}

func TestListTargetsByOwner_NoAssignments_ReturnsEmptySlice(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		store := NewStore(pool)
		got, err := store.ListTargetsByOwner(context.Background(), "nobody-owns-anything", "")
		if err != nil {
			t.Fatalf("ListTargetsByOwner: %v", err)
		}
		if len(got) != 0 {
			t.Fatalf("got %+v, want empty", got)
		}
	})
}
