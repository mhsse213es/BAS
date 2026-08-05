package jobs

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

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

func TestTick_NotifiesTargetFailedAndJobFailed(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		payload, _ := json.Marshal(map[string]string{"remediationId": "enable_windows_firewall", "reason": "test"})
		job, err := store.CreateBatch(ctx, "batch_remediation", payload, "user-1", []string{"agent-notif-fail"})
		if err != nil {
			t.Fatalf("CreateBatch: %v", err)
		}

		var events []NotifyEvent
		d := NewDispatcher(store)
		d.SetDispatch(func(ctx context.Context, j Job, target JobTarget) (string, error) {
			return "", errors.New("agent not connected")
		})
		d.SetStatus(func(ctx context.Context, jobType, refID string) (string, string, bool) {
			t.Fatal("status should not be called -- nothing was dispatched")
			return "", "", false
		})
		d.SetNotify(func(ctx context.Context, evt NotifyEvent) {
			events = append(events, evt)
		})

		if err := d.Tick(ctx); err != nil {
			t.Fatalf("Tick: %v", err)
		}

		if len(events) != 2 {
			t.Fatalf("got %d notify events, want 2 (target_failed + job_failed): %+v", len(events), events)
		}
		if events[0].Type != notifyTypeTargetFailed || events[0].JobID != job.ID || events[0].Message != "agent not connected" {
			t.Errorf("events[0] = %+v, want target_failed for job %s", events[0], job.ID)
		}
		if events[1].Type != notifyTypeJobFailed || events[1].JobID != job.ID {
			t.Errorf("events[1] = %+v, want job_failed for job %s", events[1], job.ID)
		}
	})
}

func TestTick_NotifiesTargetDeferred(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		mustExecJobsNotif(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('agent-notif-freeze', 'AGENT-NOTIF-FREEZE')`)
		store := NewStore(pool)
		payload, _ := json.Marshal(map[string]string{"remediationId": "enable_windows_firewall", "reason": "test"})
		job, err := store.CreateBatch(ctx, "batch_remediation", payload, "user-1", []string{"agent-notif-freeze"})
		if err != nil {
			t.Fatalf("CreateBatch: %v", err)
		}
		_, err = store.CreateFreeze(ctx, AgentFreeze{
			AgentID: "agent-notif-freeze", FromAt: time.Now().UTC().Add(-time.Hour), ToAt: time.Now().UTC().Add(time.Hour),
			Reason: "maintenance", CreatedBy: "admin-1",
		})
		if err != nil {
			t.Fatalf("CreateFreeze: %v", err)
		}

		var events []NotifyEvent
		d := NewDispatcher(store)
		d.SetDispatch(func(ctx context.Context, j Job, target JobTarget) (string, error) {
			t.Fatal("dispatch should not be called -- the agent is frozen")
			return "", nil
		})
		d.SetStatus(func(ctx context.Context, jobType, refID string) (string, string, bool) { return "", "", false })
		d.SetNotify(func(ctx context.Context, evt NotifyEvent) {
			events = append(events, evt)
		})

		if err := d.Tick(ctx); err != nil {
			t.Fatalf("Tick: %v", err)
		}
		// The job's only target going Deferred also flips the job's aggregate
		// state from Requested to Running (Deferred counts as
		// dispatchedOrTerminal in AggregateState -- see internal/jobs/state.go),
		// so both target_deferred and job_started fire in the same tick.
		if len(events) != 2 {
			t.Fatalf("got %d notify events, want 2 (target_deferred + job_started): %+v", len(events), events)
		}
		if events[0].Type != notifyTypeTargetDeferred || events[0].JobID != job.ID {
			t.Errorf("events[0] = %+v, want target_deferred for job %s", events[0], job.ID)
		}
		if events[1].Type != notifyTypeJobStarted || events[1].JobID != job.ID {
			t.Errorf("events[1] = %+v, want job_started for job %s", events[1], job.ID)
		}
	})
}

func mustExecJobsNotif(t *testing.T, pool *pgxpool.Pool, sql string, args ...any) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), sql, args...); err != nil {
		t.Fatalf("mustExecJobsNotif: %v\nsql: %s", err, sql)
	}
}

func TestTick_SpawnsDueSchedule(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		payload, _ := json.Marshal(map[string]string{"remediationId": "enable_windows_firewall", "reason": "weekly"})
		// A schedule whose weekly slot is definitely in the past relative to
		// "now" and has never been checked (LastOccurrenceAt nil) -- today's
		// weekday at 00:00 UTC is always at or before "now" for any test run.
		sch, err := store.CreateSchedule(ctx, Schedule{
			Type: "batch_remediation", Payload: payload, AgentIDs: []string{"sched-agent-1"},
			DayOfWeek: int(time.Now().UTC().Weekday()), TimeOfDay: "00:00", Timezone: "UTC", Enabled: true, CreatedBy: "user-1",
		})
		if err != nil {
			t.Fatalf("CreateSchedule: %v", err)
		}

		d := NewDispatcher(store)
		d.SetDispatch(func(ctx context.Context, j Job, target JobTarget) (string, error) { return "ref-" + target.AgentID, nil })
		d.SetStatus(func(ctx context.Context, jobType, refID string) (string, string, bool) { return TargetStateDispatched, "", false })

		if err := d.Tick(ctx); err != nil {
			t.Fatalf("Tick: %v", err)
		}
		got, err := store.GetSchedule(ctx, sch.ID)
		if err != nil {
			t.Fatalf("GetSchedule: %v", err)
		}
		if got.LastSpawnedJobID == "" {
			t.Fatal("schedule was not spawned -- LastSpawnedJobID is empty")
		}
		spawned, err := store.Get(ctx, got.LastSpawnedJobID)
		if err != nil {
			t.Fatalf("Get(spawned job): %v", err)
		}
		targets, err := store.ListTargets(ctx, spawned.ID)
		if err != nil {
			t.Fatalf("ListTargets: %v", err)
		}
		if len(targets) != 1 || targets[0].AgentID != "sched-agent-1" {
			t.Fatalf("spawned job's targets = %+v, want 1 target for sched-agent-1", targets)
		}
	})
}

func TestTick_SkipsScheduleWhenPreviousSpawnStillActive(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		payload, _ := json.Marshal(map[string]string{"remediationId": "enable_windows_firewall", "reason": "weekly"})
		stillRunning, err := store.CreateBatch(ctx, "batch_remediation", payload, "user-1", []string{"prev-run-agent"})
		if err != nil {
			t.Fatalf("CreateBatch (previous run): %v", err)
		}
		if err := store.SetJobState(ctx, stillRunning.ID, JobStateRunning); err != nil {
			t.Fatalf("SetJobState: %v", err)
		}

		sch, err := store.CreateSchedule(ctx, Schedule{
			Type: "batch_remediation", Payload: payload, AgentIDs: []string{"sched-agent-2"},
			DayOfWeek: int(time.Now().UTC().Weekday()), TimeOfDay: "00:00", Timezone: "UTC", Enabled: true, CreatedBy: "user-1",
		})
		if err != nil {
			t.Fatalf("CreateSchedule: %v", err)
		}
		if err := store.MarkScheduleOccurrenceHandled(ctx, sch.ID, time.Now().UTC().Add(-1*time.Hour), stillRunning.ID); err != nil {
			t.Fatalf("MarkScheduleOccurrenceHandled: %v", err)
		}

		d := NewDispatcher(store)
		d.SetDispatch(func(ctx context.Context, j Job, target JobTarget) (string, error) { return "ref-" + target.AgentID, nil })
		d.SetStatus(func(ctx context.Context, jobType, refID string) (string, string, bool) { return TargetStateDispatched, "", false })

		if err := d.Tick(ctx); err != nil {
			t.Fatalf("Tick: %v", err)
		}
		got, err := store.GetSchedule(ctx, sch.ID)
		if err != nil {
			t.Fatalf("GetSchedule: %v", err)
		}
		if got.LastSpawnedJobID != stillRunning.ID {
			t.Errorf("LastSpawnedJobID = %q, want %q (unchanged -- previous run still active, this occurrence skipped)", got.LastSpawnedJobID, stillRunning.ID)
		}
	})
}

func TestTick_DisabledScheduleNeverSpawns(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		payload, _ := json.Marshal(map[string]string{"remediationId": "enable_windows_firewall", "reason": "weekly"})
		sch, err := store.CreateSchedule(ctx, Schedule{
			Type: "batch_remediation", Payload: payload, AgentIDs: []string{"sched-agent-3"},
			DayOfWeek: int(time.Now().UTC().Weekday()), TimeOfDay: "00:00", Timezone: "UTC", Enabled: true, CreatedBy: "user-1",
		})
		if err != nil {
			t.Fatalf("CreateSchedule: %v", err)
		}
		if err := store.DisableSchedule(ctx, sch.ID); err != nil {
			t.Fatalf("DisableSchedule: %v", err)
		}

		d := NewDispatcher(store)
		d.SetDispatch(func(ctx context.Context, j Job, target JobTarget) (string, error) {
			t.Fatal("dispatch should not be called -- schedule's own target list should never have been spawned")
			return "", nil
		})
		d.SetStatus(func(ctx context.Context, jobType, refID string) (string, string, bool) { return TargetStateDispatched, "", false })

		if err := d.Tick(ctx); err != nil {
			t.Fatalf("Tick: %v", err)
		}
		got, err := store.GetSchedule(ctx, sch.ID)
		if err != nil {
			t.Fatalf("GetSchedule: %v", err)
		}
		if got.LastSpawnedJobID != "" {
			t.Errorf("LastSpawnedJobID = %q, want empty -- disabled schedule must never spawn", got.LastSpawnedJobID)
		}
	})
}

func TestTick_FrozenTargetDeferredInsteadOfDispatched(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		if _, err := store.CreateFreeze(ctx, AgentFreeze{
			AgentID: "frozen-agent-1", FromAt: time.Now().UTC().Add(-1 * time.Hour), ToAt: time.Now().UTC().Add(1 * time.Hour), Reason: "change freeze",
		}); err != nil {
			t.Fatalf("CreateFreeze: %v", err)
		}
		payload, _ := json.Marshal(map[string]string{"remediationId": "enable_windows_firewall", "reason": "test"})
		job, err := store.CreateBatch(ctx, "batch_remediation", payload, "user-1", []string{"frozen-agent-1"})
		if err != nil {
			t.Fatalf("CreateBatch: %v", err)
		}

		d := NewDispatcher(store)
		d.SetDispatch(func(ctx context.Context, j Job, target JobTarget) (string, error) {
			t.Fatal("dispatch should not be called for a frozen agent")
			return "", nil
		})
		d.SetStatus(func(ctx context.Context, jobType, refID string) (string, string, bool) { return TargetStateDispatched, "", false })

		if err := d.Tick(ctx); err != nil {
			t.Fatalf("Tick: %v", err)
		}
		targets, err := store.ListTargets(ctx, job.ID)
		if err != nil {
			t.Fatalf("ListTargets: %v", err)
		}
		if targets[0].State != TargetStateDeferred || targets[0].Error != "change freeze" {
			t.Fatalf("target = %+v, want State=deferred Error='change freeze'", targets[0])
		}
		gotJob, err := store.Get(ctx, job.ID)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if gotJob.State != JobStateRunning {
			t.Errorf("job State = %q, want running (deferred target keeps it open)", gotJob.State)
		}
	})
}

func TestTick_DeferredTargetResumesOnceFreezeExpires(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		if _, err := store.CreateFreeze(ctx, AgentFreeze{
			AgentID: "frozen-agent-2", FromAt: time.Now().UTC().Add(-2 * time.Hour), ToAt: time.Now().UTC().Add(-1 * time.Hour), Reason: "already expired",
		}); err != nil {
			t.Fatalf("CreateFreeze: %v", err)
		}
		payload, _ := json.Marshal(map[string]string{"remediationId": "enable_windows_firewall", "reason": "test"})
		job, err := store.CreateBatch(ctx, "batch_remediation", payload, "user-1", []string{"frozen-agent-2"})
		if err != nil {
			t.Fatalf("CreateBatch: %v", err)
		}
		targets, _ := store.ListTargets(ctx, job.ID)
		if err := store.MarkTargetDeferred(ctx, targets[0].ID, "was frozen"); err != nil {
			t.Fatalf("MarkTargetDeferred: %v", err)
		}

		var dispatched bool
		d := NewDispatcher(store)
		d.SetDispatch(func(ctx context.Context, j Job, target JobTarget) (string, error) {
			dispatched = true
			return "ref-resumed", nil
		})
		d.SetStatus(func(ctx context.Context, jobType, refID string) (string, string, bool) { return TargetStateDispatched, "", false })

		if err := d.Tick(ctx); err != nil {
			t.Fatalf("Tick: %v", err)
		}
		if !dispatched {
			t.Fatal("target was not dispatched after its freeze expired")
		}
	})
}
