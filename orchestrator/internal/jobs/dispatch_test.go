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

		var metricsEvents []MetricsEvent
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
		d.SetMetrics(func(evt MetricsEvent) {
			metricsEvents = append(metricsEvents, evt)
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
		if len(metricsEvents) != 1 {
			t.Fatalf("got %d metrics events, want 1 (job_completed): %+v", len(metricsEvents), metricsEvents)
		}
		if metricsEvents[0].Type != MetricsEventJobCompleted || metricsEvents[0].JobType != "batch_remediation" {
			t.Errorf("metricsEvents[0] = %+v, want job_completed for type batch_remediation", metricsEvents[0])
		}
		if !metricsEvents[0].HasDuration || metricsEvents[0].DurationSecs < 0 {
			t.Errorf("metricsEvents[0] = %+v, want HasDuration=true and DurationSecs >= 0", metricsEvents[0])
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
		var metricsEvents []MetricsEvent
		d := NewDispatcher(store)
		d.SetDispatch(func(ctx context.Context, j Job, target JobTarget) (string, error) {
			t.Fatal("dispatch should not be called -- the agent is frozen")
			return "", nil
		})
		d.SetStatus(func(ctx context.Context, jobType, refID string) (string, string, bool) { return "", "", false })
		d.SetNotify(func(ctx context.Context, evt NotifyEvent) {
			events = append(events, evt)
		})
		d.SetMetrics(func(evt MetricsEvent) {
			metricsEvents = append(metricsEvents, evt)
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
		if len(metricsEvents) != 1 {
			t.Fatalf("got %d metrics events, want 1 (job_started): %+v", len(metricsEvents), metricsEvents)
		}
		if metricsEvents[0].Type != MetricsEventJobStarted || metricsEvents[0].JobType != "batch_remediation" {
			t.Errorf("metricsEvents[0] = %+v, want job_started for type batch_remediation", metricsEvents[0])
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
		// A schedule whose weekly slot is at least an hour in the past
		// relative to "now" (comfortably beyond scheduleJitterWindow) and
		// has never been checked (LastOccurrenceAt nil) -- guaranteed due
		// regardless of when this test runs or which way a schedule's ID
		// happens to jitter.
		ref := time.Now().UTC().Add(-1 * time.Hour)
		sch, err := store.CreateSchedule(ctx, Schedule{
			Type: "batch_remediation", Payload: payload, AgentIDs: []string{"sched-agent-1"},
			DayOfWeek: int(ref.Weekday()), TimeOfDay: ref.Format("15:04"), Timezone: "UTC", Enabled: true, CreatedBy: "user-1",
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

func TestTick_SpawnsDueSchedule_AssignsSpawnedJobToInitiative(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		var initiativeID string
		if err := pool.QueryRow(ctx,
			`INSERT INTO initiatives (name, description, state, created_by) VALUES ('Q3 Hardening', '', 'active', 'user-1') RETURNING id`,
		).Scan(&initiativeID); err != nil {
			t.Fatalf("seed initiative: %v", err)
		}

		payload, _ := json.Marshal(map[string]string{"remediationId": "enable_windows_firewall", "reason": "weekly"})
		// A schedule whose weekly slot is at least an hour in the past
		// relative to "now" (comfortably beyond scheduleJitterWindow) and
		// has never been checked (LastOccurrenceAt nil) -- guaranteed due
		// regardless of when this test runs or which way a schedule's ID
		// happens to jitter.
		ref := time.Now().UTC().Add(-1 * time.Hour)
		sch, err := store.CreateSchedule(ctx, Schedule{
			Type: "batch_remediation", Payload: payload, AgentIDs: []string{"sched-agent-init-1"},
			DayOfWeek: int(ref.Weekday()), TimeOfDay: ref.Format("15:04"), Timezone: "UTC", Enabled: true, CreatedBy: "user-1",
			InitiativeID: initiativeID,
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
		if spawned.InitiativeID != initiativeID {
			t.Errorf("spawned.InitiativeID = %q, want %q -- schedule's InitiativeID should auto-assign the spawned job", spawned.InitiativeID, initiativeID)
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

		// A schedule whose weekly slot is at least an hour in the past
		// relative to "now" (comfortably beyond scheduleJitterWindow) and
		// has never been checked (LastOccurrenceAt nil) -- guaranteed due
		// regardless of when this test runs or which way a schedule's ID
		// happens to jitter.
		ref := time.Now().UTC().Add(-1 * time.Hour)
		sch, err := store.CreateSchedule(ctx, Schedule{
			Type: "batch_remediation", Payload: payload, AgentIDs: []string{"sched-agent-2"},
			DayOfWeek: int(ref.Weekday()), TimeOfDay: ref.Format("15:04"), Timezone: "UTC", Enabled: true, CreatedBy: "user-1",
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
		// A schedule whose weekly slot is at least an hour in the past
		// relative to "now" (comfortably beyond scheduleJitterWindow) and
		// has never been checked (LastOccurrenceAt nil) -- guaranteed due
		// regardless of when this test runs or which way a schedule's ID
		// happens to jitter.
		ref := time.Now().UTC().Add(-1 * time.Hour)
		sch, err := store.CreateSchedule(ctx, Schedule{
			Type: "batch_remediation", Payload: payload, AgentIDs: []string{"sched-agent-3"},
			DayOfWeek: int(ref.Weekday()), TimeOfDay: ref.Format("15:04"), Timezone: "UTC", Enabled: true, CreatedBy: "user-1",
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

func TestSpawnDueSchedules_ResolvesGroupMembershipLive(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		var groupID int64
		if err := pool.QueryRow(context.Background(),
			`INSERT INTO agent_groups (name) VALUES ('Live-Res-Group') RETURNING id`).Scan(&groupID); err != nil {
			t.Fatalf("insert group: %v", err)
		}
		mustExecJobsNotif(t, pool, `INSERT INTO agents (agent_id, hostname, group_id) VALUES ('live-res-a1', 'A1', $1)`, groupID)

		store := NewStore(pool)
		dispatcher := NewDispatcher(store)
		dispatcher.SetDispatch(func(ctx context.Context, job Job, target JobTarget) (string, error) { return "ref-" + target.ID, nil })
		dispatcher.SetStatus(func(ctx context.Context, jobType, refID string) (string, string, bool) { return TargetStateCompleted, "", true })

		past := time.Now().Add(-time.Hour).UTC()
		sch, err := store.CreateSchedule(context.Background(), Schedule{
			Type: "scheduled_assessment", Payload: json.RawMessage(`{}`), GroupIDs: []int64{groupID},
			RecurrenceType: "once", RunAt: &past, Enabled: true,
		})
		if err != nil {
			t.Fatalf("CreateSchedule: %v", err)
		}

		if err := dispatcher.Tick(context.Background()); err != nil {
			t.Fatalf("Tick: %v", err)
		}

		got, err := store.GetSchedule(context.Background(), sch.ID)
		if err != nil {
			t.Fatalf("GetSchedule: %v", err)
		}
		if got.LastSpawnedJobID == "" {
			t.Fatal("schedule did not spawn a job")
		}
		targets, err := store.ListTargets(context.Background(), got.LastSpawnedJobID)
		if err != nil {
			t.Fatalf("ListTargets: %v", err)
		}
		if len(targets) != 1 || targets[0].AgentID != "live-res-a1" {
			t.Errorf("targets = %v, want exactly [live-res-a1]", targets)
		}
	})
}

func TestTick_RespectsPerJobConcurrencyLimit(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		store := NewStore(pool)
		dispatcher := NewDispatcher(store)

		var dispatchCount int
		dispatcher.SetDispatch(func(ctx context.Context, job Job, target JobTarget) (string, error) {
			dispatchCount++
			return "ref-" + target.ID, nil
		})
		// Every dispatched target stays non-terminal ("dispatched") for the
		// whole test -- this is what makes the concurrency limit observable:
		// if it weren't enforced, all 5 targets would dispatch on tick 1.
		dispatcher.SetStatus(func(ctx context.Context, jobType, refID string) (string, string, bool) {
			return TargetStateDispatched, "", false
		})

		agentIDs := []string{"cc-a1", "cc-a2", "cc-a3", "cc-a4", "cc-a5"}
		for _, id := range agentIDs {
			mustExecJobsNotif(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ($1, $1) ON CONFLICT (agent_id) DO NOTHING`, id)
		}
		job, err := store.CreateBatchWithConcurrency(context.Background(), "scheduled_assessment", json.RawMessage(`{}`), "tester", agentIDs, nil, 2)
		if err != nil {
			t.Fatalf("CreateBatchWithConcurrency: %v", err)
		}

		if err := dispatcher.Tick(context.Background()); err != nil {
			t.Fatalf("Tick: %v", err)
		}
		if dispatchCount != 2 {
			t.Fatalf("after 1 tick: dispatchCount = %d, want 2 (concurrency limit)", dispatchCount)
		}

		// A second tick must NOT dispatch more -- the 2 already in flight
		// never resolve (status always returns terminal=false), so the
		// limit should still be hit.
		if err := dispatcher.Tick(context.Background()); err != nil {
			t.Fatalf("Tick 2: %v", err)
		}
		if dispatchCount != 2 {
			t.Fatalf("after 2 ticks: dispatchCount = %d, want still 2", dispatchCount)
		}
		_ = job
	})
}
