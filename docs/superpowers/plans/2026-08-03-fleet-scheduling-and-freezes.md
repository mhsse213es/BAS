# Fleet Scheduling & Maintenance Freezes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add one-shot/recurring job scheduling (`Job.ScheduledAt` + `job_schedules`) and per-agent maintenance freezes (`agent_maintenance_freezes` + `TargetStateDeferred`) to the Fleet Job Engine built in Sub-project 6.

**Architecture:** Both extensions are generic infrastructure living entirely in `internal/jobs` (never `internal/remediation`/`internal/api`-specific). `Job.ScheduledAt` gates `Dispatcher.Tick()`'s existing pending-dispatch query; `job_schedules` is a recurring template above `Job` that calls the existing `Store.CreateBatch`-family method to spawn one-shot jobs; `agent_maintenance_freezes` is checked at dispatch time via a new `TargetStateDeferred` target state that auto-resumes once the freeze lifts.

**Tech Stack:** Go, PostgreSQL (`pgx/v5`), `chi` router, Go stdlib `time.LoadLocation` for IANA timezone handling (no new dependency).

## Global Constraints

- Direct-to-`main` repo convention — no branches/PRs; every task commits and pushes straight to `main`.
- TDD throughout: write failing test → verify it fails → implement → verify it passes → commit → push.
- `internal/jobs` never imports `internal/remediation` or `internal/api`.
- `Store.CreateBatch`'s existing signature and every existing call site stay unchanged — new scheduling capability is added via a new `CreateBatchScheduled` method that `CreateBatch` delegates to with `scheduledAt=nil`.
- Freeze creation/deletion requires `auth.CanApproveRemediation` (Admin-only); everything else reuses `auth.CanExecuteRemediation`, matching Sub-project 6's existing routes.
- Recurrence is day-of-week + time-of-day + IANA timezone only (no cron). Freeze windows are one-shot absolute ranges only (no recurrence).
- Every DB-backed test in this codebase follows `sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {...})` and starts with `if testing.Short() { t.Skip(...) }`.

---

### Task 1: `Job.ScheduledAt` + `CreateBatchScheduled` + dispatch gating

**Files:**
- Modify: `orchestrator/internal/db/postgres.go` (append `ALTER TABLE jobs ADD COLUMN IF NOT EXISTS scheduled_at timestamptz` right after `job_targets`' indexes)
- Modify: `orchestrator/internal/jobs/types.go` (`Job.ScheduledAt *time.Time`)
- Modify: `orchestrator/internal/jobs/store.go` (`CreateBatchScheduled`, `CreateBatch` becomes a delegator, `Get` scans `scheduled_at`, `ListPendingTargetsAcrossActiveJobs` filters on it)
- Test: `orchestrator/internal/jobs/store_test.go`

**Interfaces:**
- Consumes: existing `Job`, `JobTarget`, `Store` (Sub-project 6).
- Produces: `(s *Store) CreateBatchScheduled(ctx, jobType string, payload json.RawMessage, createdBy string, agentIDs []string, scheduledAt *time.Time) (Job, error)` — Task 4's `spawnDueSchedules` and Task 7's API handler both call this.

- [ ] **Step 1: Write the failing tests**

Append to `orchestrator/internal/jobs/store_test.go`:

```go
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
```

Add `"time"` to `store_test.go`'s import block if not already present.

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/jobs/... -run "TestCreateBatchScheduled|TestCreateBatch_NilScheduledAt" -v`
Expected: FAIL — `store.CreateBatchScheduled` undefined; `job.ScheduledAt` undefined (compile error).

- [ ] **Step 3: Add the schema column**

In `orchestrator/internal/db/postgres.go`, right after `idx_job_targets_state`:

```go
		`ALTER TABLE jobs ADD COLUMN IF NOT EXISTS scheduled_at timestamptz`,
```

- [ ] **Step 4: Add `ScheduledAt` to the `Job` struct**

In `orchestrator/internal/jobs/types.go`, add to `Job`:

```go
	ScheduledAt *time.Time // nil = dispatch immediately; non-nil = don't dispatch before this
```

- [ ] **Step 5: Update `store.go`**

Replace the existing `CreateBatch` and `Get` functions, and modify `ListPendingTargetsAcrossActiveJobs`:

```go
// CreateBatch creates a Job plus one JobTarget per agentID, dispatching
// immediately (ScheduledAt=nil). Delegates to CreateBatchScheduled so
// every existing call site's behavior is unchanged.
func (s *Store) CreateBatch(ctx context.Context, jobType string, payload json.RawMessage, createdBy string, agentIDs []string) (Job, error) {
	return s.CreateBatchScheduled(ctx, jobType, payload, createdBy, agentIDs, nil)
}

// CreateBatchScheduled is CreateBatch with an optional future dispatch time.
// A single transaction so a job never exists with a partial target list.
func (s *Store) CreateBatchScheduled(ctx context.Context, jobType string, payload json.RawMessage, createdBy string, agentIDs []string, scheduledAt *time.Time) (Job, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Job{}, err
	}
	defer tx.Rollback(ctx)

	var jobID string
	if err := tx.QueryRow(ctx,
		`INSERT INTO jobs (type, state, payload, created_by, scheduled_at) VALUES ($1,$2,$3,$4,$5) RETURNING id`,
		jobType, JobStateRequested, []byte(payload), createdBy, scheduledAt,
	).Scan(&jobID); err != nil {
		return Job{}, err
	}
	for _, agentID := range agentIDs {
		if _, err := tx.Exec(ctx,
			`INSERT INTO job_targets (job_id, agent_id, state) VALUES ($1,$2,$3)`,
			jobID, agentID, TargetStatePending,
		); err != nil {
			return Job{}, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return Job{}, err
	}
	return s.Get(ctx, jobID)
}

func (s *Store) Get(ctx context.Context, id string) (Job, error) {
	var j Job
	err := s.pool.QueryRow(ctx,
		`SELECT id, type, state, payload, created_by, created_at, started_at, completed_at, scheduled_at FROM jobs WHERE id=$1`, id,
	).Scan(&j.ID, &j.Type, &j.State, &j.Payload, &j.CreatedBy, &j.CreatedAt, &j.StartedAt, &j.CompletedAt, &j.ScheduledAt)
	return j, err
}
```

In `ListPendingTargetsAcrossActiveJobs`, add the `scheduled_at` filter to the `WHERE` clause:

```go
func (s *Store) ListPendingTargetsAcrossActiveJobs(ctx context.Context, limit int) ([]JobTarget, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT `+jobTargetColumnsQualified()+`
		   FROM job_targets jt JOIN jobs j ON j.id = jt.job_id
		  WHERE jt.state = $1 AND j.state IN ($2,$3)
		    AND (j.scheduled_at IS NULL OR j.scheduled_at <= NOW())
		  ORDER BY jt.created_at, jt.id
		  LIMIT $4`,
		TargetStatePending, JobStateRequested, JobStateRunning, limit)
	if err != nil {
		return nil, err
	}
	return scanJobTargets(rows)
}
```

Add `"time"` to `store.go`'s import block.

- [ ] **Step 6: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/jobs/... -v`
Expected: PASS for every test in the package (all Sub-project 6 tests plus the 3 new ones).

- [ ] **Step 7: Full build check**

Run: `cd orchestrator && go build ./...`
Expected: succeeds cleanly.

- [ ] **Step 8: Commit**

```bash
git add orchestrator/internal/db/postgres.go orchestrator/internal/jobs/types.go orchestrator/internal/jobs/store.go orchestrator/internal/jobs/store_test.go
git commit -m "feat(jobs): add Job.ScheduledAt and CreateBatchScheduled -- gate dispatch on a future time"
git push
```

---

### Task 2: `IsTerminalJobState` + `Schedule` type + `nextOccurrenceSince` (pure logic)

**Files:**
- Modify: `orchestrator/internal/jobs/state.go` (`IsTerminalJobState`)
- Modify: `orchestrator/internal/jobs/store.go` (`SetJobState` uses the new helper instead of its own inline check)
- Create: `orchestrator/internal/jobs/schedule.go` (`Schedule` type + `nextOccurrenceSince` + `parseTimeOfDay`, pure functions only -- no DB yet)
- Test: `orchestrator/internal/jobs/schedule_test.go`

**Interfaces:**
- Produces: `IsTerminalJobState(state string) bool`; `Schedule` struct; `nextOccurrenceSince(sch Schedule, now time.Time) (occurrence time.Time, ok bool)`. Task 3's `Store` CRUD methods and Task 4's `spawnDueSchedules` both consume all three.

- [ ] **Step 1: Write the failing tests**

```go
// orchestrator/internal/jobs/schedule_test.go
package jobs

import (
	"testing"
	"time"
)

func TestIsTerminalJobState(t *testing.T) {
	cases := map[string]bool{
		JobStateRequested: false,
		JobStateRunning:   false,
		JobStateCompleted: true,
		JobStatePartial:   true,
		JobStateFailed:    true,
		JobStateCancelled: true,
	}
	for state, want := range cases {
		if got := IsTerminalJobState(state); got != want {
			t.Errorf("IsTerminalJobState(%q) = %v, want %v", state, got, want)
		}
	}
}

func TestNextOccurrenceSince_FirstOccurrenceEverChecked(t *testing.T) {
	// A Friday 23:00 UTC schedule, never checked before (LastOccurrenceAt
	// nil), evaluated on the following Monday -- should find last Friday's
	// occurrence.
	sch := Schedule{DayOfWeek: 5, TimeOfDay: "23:00", Timezone: "UTC"} // 5 = Friday
	now := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)              // a Monday
	occurrence, ok := nextOccurrenceSince(sch, now)
	if !ok {
		t.Fatal("nextOccurrenceSince() ok = false, want true (first-ever check should find last Friday)")
	}
	want := time.Date(2026, 8, 7, 23, 0, 0, 0, time.UTC) // the preceding Friday
	if !occurrence.Equal(want) {
		t.Errorf("occurrence = %v, want %v", occurrence, want)
	}
}

func TestNextOccurrenceSince_AlreadyHandled_ReturnsNotOK(t *testing.T) {
	sch := Schedule{DayOfWeek: 5, TimeOfDay: "23:00", Timezone: "UTC"}
	already := time.Date(2026, 8, 7, 23, 0, 0, 0, time.UTC)
	sch.LastOccurrenceAt = &already
	now := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC) // still the same week, no new Friday yet
	_, ok := nextOccurrenceSince(sch, now)
	if ok {
		t.Error("nextOccurrenceSince() ok = true, want false -- this occurrence was already handled")
	}
}

func TestNextOccurrenceSince_TimeOfDayNotYetReachedToday(t *testing.T) {
	sch := Schedule{DayOfWeek: 1, TimeOfDay: "23:00", Timezone: "UTC"} // 1 = Monday
	now := time.Date(2026, 8, 10, 10, 0, 0, 0, time.UTC)              // Monday, 10:00 -- before 23:00
	_, ok := nextOccurrenceSince(sch, now)
	if ok {
		t.Error("nextOccurrenceSince() ok = true, want false -- today's occurrence time hasn't arrived yet")
	}
}

func TestNextOccurrenceSince_TimezoneConversion(t *testing.T) {
	// Friday 23:00 IST (Asia/Kolkata, UTC+5:30) is Friday 17:30 UTC.
	sch := Schedule{DayOfWeek: 5, TimeOfDay: "23:00", Timezone: "Asia/Kolkata"}
	now := time.Date(2026, 8, 7, 18, 0, 0, 0, time.UTC) // just after 17:30 UTC on that Friday
	occurrence, ok := nextOccurrenceSince(sch, now)
	if !ok {
		t.Fatal("nextOccurrenceSince() ok = false, want true")
	}
	want := time.Date(2026, 8, 7, 17, 30, 0, 0, time.UTC)
	if !occurrence.Equal(want) {
		t.Errorf("occurrence = %v, want %v (UTC equivalent of Friday 23:00 IST)", occurrence, want)
	}
}

func TestNextOccurrenceSince_InvalidTimezone_ReturnsNotOK(t *testing.T) {
	sch := Schedule{DayOfWeek: 5, TimeOfDay: "23:00", Timezone: "Not/A_Real_Zone"}
	_, ok := nextOccurrenceSince(sch, time.Now().UTC())
	if ok {
		t.Error("nextOccurrenceSince() ok = true, want false for an invalid timezone")
	}
}

func TestNextOccurrenceSince_InvalidTimeOfDay_ReturnsNotOK(t *testing.T) {
	sch := Schedule{DayOfWeek: 5, TimeOfDay: "not-a-time", Timezone: "UTC"}
	_, ok := nextOccurrenceSince(sch, time.Now().UTC())
	if ok {
		t.Error("nextOccurrenceSince() ok = true, want false for an invalid time-of-day")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/jobs/... -run "TestIsTerminalJobState|TestNextOccurrenceSince" -v`
Expected: FAIL — `IsTerminalJobState`/`Schedule`/`nextOccurrenceSince` undefined (compile error).

- [ ] **Step 3: Add `IsTerminalJobState` to `state.go`**

Append to `orchestrator/internal/jobs/state.go`:

```go
// IsTerminalJobState reports whether state is one Tick() will never advance
// further -- used by spawnDueSchedules to decide whether a schedule's
// previous spawned job is still active.
func IsTerminalJobState(state string) bool {
	return state == JobStateCompleted || state == JobStatePartial || state == JobStateFailed || state == JobStateCancelled
}
```

- [ ] **Step 4: Refactor `SetJobState` in `store.go` to use it**

Replace `SetJobState`'s body:

```go
func (s *Store) SetJobState(ctx context.Context, jobID, state string) error {
	if IsTerminalJobState(state) {
		_, err := s.pool.Exec(ctx,
			`UPDATE jobs SET state=$1, started_at=COALESCE(started_at, NOW()), completed_at=NOW() WHERE id=$2`,
			state, jobID)
		return err
	}
	_, err := s.pool.Exec(ctx,
		`UPDATE jobs SET state=$1, started_at=COALESCE(started_at, NOW()) WHERE id=$2`,
		state, jobID)
	return err
}
```

- [ ] **Step 5: Write `schedule.go`**

```go
// orchestrator/internal/jobs/schedule.go
package jobs

import (
	"encoding/json"
	"strconv"
	"strings"
	"time"
)

// Schedule is a recurring template that spawns a fresh one-shot Job each
// weekly occurrence. It is not itself a Job -- it outlives any single
// spawned run.
type Schedule struct {
	ID                string
	Type              string
	Payload           json.RawMessage
	AgentIDs          []string
	DayOfWeek         int    // 0=Sunday .. 6=Saturday
	TimeOfDay         string // "23:00", 24h HH:MM
	Timezone          string // IANA name, e.g. "Asia/Kolkata"
	Enabled           bool
	CreatedBy         string
	CreatedAt         time.Time
	LastOccurrenceAt  *time.Time
	LastSpawnedJobID  string
}

// parseTimeOfDay parses "HH:MM" (24h) into hour/minute, rejecting anything
// else so an invalid schedule can never silently compute a wrong time.
func parseTimeOfDay(s string) (hour, minute int, err error) {
	parts := strings.Split(s, ":")
	if len(parts) != 2 {
		return 0, 0, errInvalidTimeOfDay
	}
	hour, err = strconv.Atoi(parts[0])
	if err != nil || hour < 0 || hour > 23 {
		return 0, 0, errInvalidTimeOfDay
	}
	minute, err = strconv.Atoi(parts[1])
	if err != nil || minute < 0 || minute > 59 {
		return 0, 0, errInvalidTimeOfDay
	}
	return hour, minute, nil
}

var errInvalidTimeOfDay = &timeOfDayError{}

type timeOfDayError struct{}

func (*timeOfDayError) Error() string { return "invalid time-of-day, want HH:MM" }

// nextOccurrenceSince finds the most recent past occurrence of sch's weekly
// (DayOfWeek, TimeOfDay) slot in sch.Timezone, and reports whether it is
// newer than sch.LastOccurrenceAt. ok=false is the common case (nothing new
// since the last check).
func nextOccurrenceSince(sch Schedule, now time.Time) (occurrence time.Time, ok bool) {
	loc, err := time.LoadLocation(sch.Timezone)
	if err != nil {
		return time.Time{}, false
	}
	hh, mm, err := parseTimeOfDay(sch.TimeOfDay)
	if err != nil {
		return time.Time{}, false
	}
	nowLocal := now.In(loc)
	for daysBack := 0; daysBack < 7; daysBack++ {
		candidate := time.Date(nowLocal.Year(), nowLocal.Month(), nowLocal.Day()-daysBack, hh, mm, 0, 0, loc)
		if int(candidate.Weekday()) != sch.DayOfWeek || candidate.After(now) {
			continue
		}
		if sch.LastOccurrenceAt != nil && !candidate.After(*sch.LastOccurrenceAt) {
			return time.Time{}, false
		}
		return candidate.UTC(), true
	}
	return time.Time{}, false
}
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/jobs/... -v`
Expected: PASS for every test in the package.

- [ ] **Step 7: Full build check**

Run: `cd orchestrator && go build ./...`
Expected: succeeds cleanly.

- [ ] **Step 8: Commit**

```bash
git add orchestrator/internal/jobs/state.go orchestrator/internal/jobs/store.go orchestrator/internal/jobs/schedule.go orchestrator/internal/jobs/schedule_test.go
git commit -m "feat(jobs): add IsTerminalJobState and Schedule recurrence math (nextOccurrenceSince)"
git push
```

---

### Task 3: `job_schedules` schema + `Store` CRUD

**Files:**
- Modify: `orchestrator/internal/db/postgres.go` (append `job_schedules` table + index)
- Modify: `orchestrator/internal/jobs/schedule.go` (add `Store` methods)
- Test: `orchestrator/internal/jobs/schedule_test.go` (append DB-backed tests)

**Interfaces:**
- Consumes: `Schedule` (Task 2), `Store` (Sub-project 6/Task 1).
- Produces: `(s *Store) CreateSchedule(ctx, sch Schedule) (Schedule, error)`; `(s *Store) GetSchedule(ctx, id string) (Schedule, error)`; `(s *Store) ListEnabledSchedules(ctx) ([]Schedule, error)`; `(s *Store) ListSchedules(ctx) ([]Schedule, error)`; `(s *Store) DisableSchedule(ctx, id string) error`; `(s *Store) MarkScheduleOccurrenceHandled(ctx, id string, occurrence time.Time, spawnedJobID string) error` -- Task 4's `spawnDueSchedules` and Task 8's API handlers consume all of these.

- [ ] **Step 1: Write the failing tests**

Append to `orchestrator/internal/jobs/schedule_test.go`:

```go
func TestCreateSchedule_PersistsAndRoundTrips(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		payload, _ := json.Marshal(map[string]string{"remediationId": "enable_windows_firewall", "reason": "weekly hardening"})

		created, err := store.CreateSchedule(ctx, Schedule{
			Type: "batch_remediation", Payload: payload, AgentIDs: []string{"a1", "a2"},
			DayOfWeek: 5, TimeOfDay: "23:00", Timezone: "Asia/Kolkata", Enabled: true, CreatedBy: "user-1",
		})
		if err != nil {
			t.Fatalf("CreateSchedule: %v", err)
		}
		if created.ID == "" || !created.Enabled || created.LastSpawnedJobID != "" {
			t.Fatalf("created = %+v, want non-empty ID, Enabled=true, LastSpawnedJobID=''", created)
		}

		got, err := store.GetSchedule(ctx, created.ID)
		if err != nil {
			t.Fatalf("GetSchedule: %v", err)
		}
		if len(got.AgentIDs) != 2 || got.AgentIDs[0] != "a1" || got.DayOfWeek != 5 || got.TimeOfDay != "23:00" || got.Timezone != "Asia/Kolkata" {
			t.Errorf("got = %+v, want AgentIDs=[a1 a2] DayOfWeek=5 TimeOfDay=23:00 Timezone=Asia/Kolkata", got)
		}
	})
}

func TestListEnabledSchedules_ExcludesDisabled(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		payload, _ := json.Marshal(map[string]string{"remediationId": "enable_windows_firewall", "reason": "test"})

		enabled, err := store.CreateSchedule(ctx, Schedule{
			Type: "batch_remediation", Payload: payload, AgentIDs: []string{"a1"},
			DayOfWeek: 5, TimeOfDay: "23:00", Timezone: "UTC", Enabled: true, CreatedBy: "user-1",
		})
		if err != nil {
			t.Fatalf("CreateSchedule (enabled): %v", err)
		}
		disabled, err := store.CreateSchedule(ctx, Schedule{
			Type: "batch_remediation", Payload: payload, AgentIDs: []string{"a2"},
			DayOfWeek: 5, TimeOfDay: "23:00", Timezone: "UTC", Enabled: true, CreatedBy: "user-1",
		})
		if err != nil {
			t.Fatalf("CreateSchedule (to-be-disabled): %v", err)
		}
		if err := store.DisableSchedule(ctx, disabled.ID); err != nil {
			t.Fatalf("DisableSchedule: %v", err)
		}

		got, err := store.ListEnabledSchedules(ctx)
		if err != nil {
			t.Fatalf("ListEnabledSchedules: %v", err)
		}
		var sawEnabled, sawDisabled bool
		for _, sch := range got {
			if sch.ID == enabled.ID {
				sawEnabled = true
			}
			if sch.ID == disabled.ID {
				sawDisabled = true
			}
		}
		if !sawEnabled || sawDisabled {
			t.Errorf("ListEnabledSchedules() sawEnabled=%v sawDisabled=%v, want true/false", sawEnabled, sawDisabled)
		}
	})
}

func TestMarkScheduleOccurrenceHandled_UpdatesBothFields(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		payload, _ := json.Marshal(map[string]string{"remediationId": "enable_windows_firewall", "reason": "test"})
		sch, err := store.CreateSchedule(ctx, Schedule{
			Type: "batch_remediation", Payload: payload, AgentIDs: []string{"a1"},
			DayOfWeek: 5, TimeOfDay: "23:00", Timezone: "UTC", Enabled: true, CreatedBy: "user-1",
		})
		if err != nil {
			t.Fatalf("CreateSchedule: %v", err)
		}
		occurrence := time.Date(2026, 8, 7, 23, 0, 0, 0, time.UTC)

		if err := store.MarkScheduleOccurrenceHandled(ctx, sch.ID, occurrence, "spawned-job-1"); err != nil {
			t.Fatalf("MarkScheduleOccurrenceHandled: %v", err)
		}
		got, err := store.GetSchedule(ctx, sch.ID)
		if err != nil {
			t.Fatalf("GetSchedule: %v", err)
		}
		if got.LastOccurrenceAt == nil || !got.LastOccurrenceAt.Equal(occurrence) || got.LastSpawnedJobID != "spawned-job-1" {
			t.Fatalf("got = %+v, want LastOccurrenceAt=%v LastSpawnedJobID=spawned-job-1", got, occurrence)
		}
	})
}
```

Add `"context"` and `"github.com/jackc/pgx/v5/pgxpool"` to `schedule_test.go`'s import block.

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/jobs/... -run "TestCreateSchedule|TestListEnabledSchedules|TestMarkScheduleOccurrenceHandled" -v`
Expected: FAIL — `store.CreateSchedule` undefined (compile error); `job_schedules` table doesn't exist.

- [ ] **Step 3: Add the schema**

In `orchestrator/internal/db/postgres.go`, right after the `scheduled_at` column addition from Task 1:

```go
		// job_schedules: recurring template that spawns a fresh one-shot Job
		// each occurrence. See
		// docs/superpowers/specs/2026-08-03-fleet-scheduling-and-freezes-design.md.
		`CREATE TABLE IF NOT EXISTS job_schedules (
			id                  text        PRIMARY KEY DEFAULT gen_random_uuid()::text,
			type                text        NOT NULL,
			payload             jsonb       NOT NULL DEFAULT '{}',
			agent_ids           jsonb       NOT NULL,
			day_of_week         int         NOT NULL,
			time_of_day         text        NOT NULL,
			timezone            text        NOT NULL DEFAULT 'UTC',
			enabled             boolean     NOT NULL DEFAULT true,
			created_by          text        NOT NULL DEFAULT '',
			created_at          timestamptz NOT NULL DEFAULT NOW(),
			last_occurrence_at  timestamptz,
			last_spawned_job_id text        NOT NULL DEFAULT ''
		)`,
		`CREATE INDEX IF NOT EXISTS idx_job_schedules_enabled ON job_schedules (enabled) WHERE enabled = true`,
```

- [ ] **Step 4: Add `Store` methods to `schedule.go`**

Append to `orchestrator/internal/jobs/schedule.go`:

```go
const scheduleColumns = `id, type, payload, agent_ids, day_of_week, time_of_day, timezone, enabled, created_by, created_at, last_occurrence_at, last_spawned_job_id`

func scanSchedule(row interface {
	Scan(dest ...any) error
}) (Schedule, error) {
	var sch Schedule
	var agentIDsRaw []byte
	err := row.Scan(&sch.ID, &sch.Type, &sch.Payload, &agentIDsRaw, &sch.DayOfWeek, &sch.TimeOfDay,
		&sch.Timezone, &sch.Enabled, &sch.CreatedBy, &sch.CreatedAt, &sch.LastOccurrenceAt, &sch.LastSpawnedJobID)
	if err != nil {
		return Schedule{}, err
	}
	if err := json.Unmarshal(agentIDsRaw, &sch.AgentIDs); err != nil {
		return Schedule{}, err
	}
	return sch, nil
}

func (s *Store) CreateSchedule(ctx context.Context, sch Schedule) (Schedule, error) {
	agentIDsJSON, err := json.Marshal(sch.AgentIDs)
	if err != nil {
		return Schedule{}, err
	}
	var id string
	if err := s.pool.QueryRow(ctx,
		`INSERT INTO job_schedules (type, payload, agent_ids, day_of_week, time_of_day, timezone, enabled, created_by)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id`,
		sch.Type, []byte(sch.Payload), agentIDsJSON, sch.DayOfWeek, sch.TimeOfDay, sch.Timezone, sch.Enabled, sch.CreatedBy,
	).Scan(&id); err != nil {
		return Schedule{}, err
	}
	return s.GetSchedule(ctx, id)
}

func (s *Store) GetSchedule(ctx context.Context, id string) (Schedule, error) {
	row := s.pool.QueryRow(ctx, `SELECT `+scheduleColumns+` FROM job_schedules WHERE id=$1`, id)
	return scanSchedule(row)
}

func (s *Store) ListEnabledSchedules(ctx context.Context) ([]Schedule, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+scheduleColumns+` FROM job_schedules WHERE enabled = true`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Schedule
	for rows.Next() {
		sch, err := scanSchedule(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, sch)
	}
	return out, rows.Err()
}

func (s *Store) ListSchedules(ctx context.Context) ([]Schedule, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+scheduleColumns+` FROM job_schedules ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Schedule
	for rows.Next() {
		sch, err := scanSchedule(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, sch)
	}
	return out, rows.Err()
}

func (s *Store) DisableSchedule(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, `UPDATE job_schedules SET enabled=false WHERE id=$1`, id)
	return err
}

func (s *Store) MarkScheduleOccurrenceHandled(ctx context.Context, id string, occurrence time.Time, spawnedJobID string) error {
	if spawnedJobID == "" {
		_, err := s.pool.Exec(ctx, `UPDATE job_schedules SET last_occurrence_at=$1 WHERE id=$2`, occurrence, id)
		return err
	}
	_, err := s.pool.Exec(ctx,
		`UPDATE job_schedules SET last_occurrence_at=$1, last_spawned_job_id=$2 WHERE id=$3`,
		occurrence, spawnedJobID, id)
	return err
}
```

Add `"context"` to `schedule.go`'s import block.

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/jobs/... -v`
Expected: PASS for every test in the package.

- [ ] **Step 6: Full build check**

Run: `cd orchestrator && go build ./...`
Expected: succeeds cleanly.

- [ ] **Step 7: Commit**

```bash
git add orchestrator/internal/db/postgres.go orchestrator/internal/jobs/schedule.go orchestrator/internal/jobs/schedule_test.go
git commit -m "feat(jobs): add job_schedules schema and Store CRUD"
git push
```

---

### Task 4: `spawnDueSchedules` wired into `Tick()`

**Files:**
- Modify: `orchestrator/internal/jobs/dispatch.go`
- Test: `orchestrator/internal/jobs/dispatch_test.go`

**Interfaces:**
- Consumes: `Schedule`, `nextOccurrenceSince`, `IsTerminalJobState`, `Store.ListEnabledSchedules`/`.CreateBatch`/`.MarkScheduleOccurrenceHandled`/`.Get` (Tasks 2-3).
- Produces: `(d *Dispatcher) spawnDueSchedules(ctx context.Context)` -- called at the start of `Tick()`.

- [ ] **Step 1: Write the failing tests**

Append to `orchestrator/internal/jobs/dispatch_test.go`:

```go
func TestTick_SpawnsDueSchedule(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		payload, _ := json.Marshal(map[string]string{"remediationId": "enable_windows_firewall", "reason": "weekly"})
		// A schedule whose weekly slot is definitely in the past relative to
		// "now" and has never been checked (LastOccurrenceAt nil) -- Monday
		// 00:00 UTC is always at or before "now" for any test run.
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
```

Add `"time"` to `dispatch_test.go`'s import block.

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/jobs/... -run TestTick_.*Schedule -v`
Expected: FAIL — the tests compile (spawnDueSchedules isn't called yet) but `LastSpawnedJobID` stays empty in all cases, including the first test which expects a spawn.

- [ ] **Step 3: Add `spawnDueSchedules` and wire it into `Tick`**

In `orchestrator/internal/jobs/dispatch.go`, add the new method and call it first inside `Tick`:

```go
func (d *Dispatcher) Tick(ctx context.Context) error {
	d.spawnDueSchedules(ctx)

	jobCache := map[string]Job{}
	// ...rest of Tick unchanged...
```

Append the new method:

```go
// spawnDueSchedules checks every enabled Schedule for a new weekly
// occurrence and spawns a fresh one-shot Job for it, unless the previous
// spawn from this schedule is still non-terminal (skip + log; the schedule
// tries again next occurrence).
func (d *Dispatcher) spawnDueSchedules(ctx context.Context) {
	schedules, err := d.store.ListEnabledSchedules(ctx)
	if err != nil {
		return
	}
	for _, sch := range schedules {
		occurrence, ok := nextOccurrenceSince(sch, time.Now().UTC())
		if !ok {
			continue
		}
		if sch.LastSpawnedJobID != "" {
			if job, err := d.store.Get(ctx, sch.LastSpawnedJobID); err == nil && !IsTerminalJobState(job.State) {
				log.Printf("[jobs] schedule %s: skipping occurrence %v -- previous spawn %s still active", sch.ID, occurrence, sch.LastSpawnedJobID)
				d.store.MarkScheduleOccurrenceHandled(ctx, sch.ID, occurrence, "")
				continue
			}
		}
		newJob, err := d.store.CreateBatch(ctx, sch.Type, sch.Payload, sch.CreatedBy, sch.AgentIDs)
		if err != nil {
			log.Printf("[jobs] schedule %s: spawn failed: %v -- will retry next tick", sch.ID, err)
			continue
		}
		d.store.MarkScheduleOccurrenceHandled(ctx, sch.ID, occurrence, newJob.ID)
		log.Printf("[jobs] schedule %s: spawned job %s for occurrence %v", sch.ID, newJob.ID, occurrence)
	}
}
```

Add `"log"` and `"time"` to `dispatch.go`'s import block.

**Note on Step 3's skip path:** `MarkScheduleOccurrenceHandled(ctx, sch.ID, occurrence, "")` passes an empty `spawnedJobID`, which (per Task 3's implementation) leaves `last_spawned_job_id` untouched and only advances `last_occurrence_at` -- confirmed by `TestTick_SkipsScheduleWhenPreviousSpawnStillActive` asserting `LastSpawnedJobID` stays equal to the original still-running job's ID.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/jobs/... -v`
Expected: PASS for every test in the package.

- [ ] **Step 5: Full build check**

Run: `cd orchestrator && go build ./...`
Expected: succeeds cleanly.

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/jobs/dispatch.go orchestrator/internal/jobs/dispatch_test.go
git commit -m "feat(jobs): wire spawnDueSchedules into Tick() -- recurring schedules spawn one-shot jobs"
git push
```

---

### Task 5: `agent_maintenance_freezes` schema + `Store` CRUD + `IsAgentFrozen`

**Files:**
- Modify: `orchestrator/internal/db/postgres.go` (append `agent_maintenance_freezes` table + indexes)
- Create: `orchestrator/internal/jobs/freeze.go`
- Test: `orchestrator/internal/jobs/freeze_test.go`

**Interfaces:**
- Produces: `AgentFreeze` struct; `(s *Store) CreateFreeze(ctx, f AgentFreeze) (AgentFreeze, error)`; `(s *Store) ListFreezesForAgent(ctx, agentID string) ([]AgentFreeze, error)`; `(s *Store) DeleteFreeze(ctx, id string) error`; `(s *Store) IsAgentFrozen(ctx, agentID string) (frozen bool, reason string, err error)` -- Task 6's `Tick()` extension and Task 9's API handlers consume all of these.

- [ ] **Step 1: Write the failing tests**

```go
// orchestrator/internal/jobs/freeze_test.go
package jobs

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestCreateFreeze_PersistsAndRoundTrips(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		from := time.Now().UTC()
		to := from.Add(48 * time.Hour)

		created, err := store.CreateFreeze(ctx, AgentFreeze{
			AgentID: "freeze-agent-1", FromAt: from, ToAt: to, Reason: "Q3 audit change-freeze", CreatedBy: "admin-1",
		})
		if err != nil {
			t.Fatalf("CreateFreeze: %v", err)
		}
		if created.ID == "" || created.Reason != "Q3 audit change-freeze" {
			t.Fatalf("created = %+v, want non-empty ID and the given reason", created)
		}

		got, err := store.ListFreezesForAgent(ctx, "freeze-agent-1")
		if err != nil {
			t.Fatalf("ListFreezesForAgent: %v", err)
		}
		if len(got) != 1 || got[0].ID != created.ID {
			t.Fatalf("ListFreezesForAgent() = %+v, want 1 row matching %s", got, created.ID)
		}
	})
}

func TestIsAgentFrozen_ActiveWindowReturnsTrue(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		from := time.Now().UTC().Add(-1 * time.Hour)
		to := time.Now().UTC().Add(1 * time.Hour)
		if _, err := store.CreateFreeze(ctx, AgentFreeze{AgentID: "freeze-agent-2", FromAt: from, ToAt: to, Reason: "maintenance"}); err != nil {
			t.Fatalf("CreateFreeze: %v", err)
		}

		frozen, reason, err := store.IsAgentFrozen(ctx, "freeze-agent-2")
		if err != nil {
			t.Fatalf("IsAgentFrozen: %v", err)
		}
		if !frozen || reason != "maintenance" {
			t.Errorf("frozen=%v reason=%q, want true/maintenance", frozen, reason)
		}
	})
}

func TestIsAgentFrozen_ExpiredWindowReturnsFalse(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		from := time.Now().UTC().Add(-48 * time.Hour)
		to := time.Now().UTC().Add(-24 * time.Hour)
		if _, err := store.CreateFreeze(ctx, AgentFreeze{AgentID: "freeze-agent-3", FromAt: from, ToAt: to, Reason: "past freeze"}); err != nil {
			t.Fatalf("CreateFreeze: %v", err)
		}

		frozen, _, err := store.IsAgentFrozen(ctx, "freeze-agent-3")
		if err != nil {
			t.Fatalf("IsAgentFrozen: %v", err)
		}
		if frozen {
			t.Error("frozen = true, want false -- the freeze window already ended")
		}
	})
}

func TestIsAgentFrozen_NoFreezeReturnsFalse(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		store := NewStore(pool)
		frozen, _, err := store.IsAgentFrozen(context.Background(), "freeze-agent-never-frozen")
		if err != nil {
			t.Fatalf("IsAgentFrozen: %v", err)
		}
		if frozen {
			t.Error("frozen = true, want false -- this agent has no freeze rows at all")
		}
	})
}

func TestDeleteFreeze_LiftsItEarly(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		from := time.Now().UTC().Add(-1 * time.Hour)
		to := time.Now().UTC().Add(1 * time.Hour)
		created, err := store.CreateFreeze(ctx, AgentFreeze{AgentID: "freeze-agent-4", FromAt: from, ToAt: to, Reason: "will be lifted"})
		if err != nil {
			t.Fatalf("CreateFreeze: %v", err)
		}

		if err := store.DeleteFreeze(ctx, created.ID); err != nil {
			t.Fatalf("DeleteFreeze: %v", err)
		}
		frozen, _, err := store.IsAgentFrozen(ctx, "freeze-agent-4")
		if err != nil {
			t.Fatalf("IsAgentFrozen: %v", err)
		}
		if frozen {
			t.Error("frozen = true, want false -- the freeze was deleted")
		}
	})
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/jobs/... -run "TestCreateFreeze|TestIsAgentFrozen|TestDeleteFreeze" -v`
Expected: FAIL — `AgentFreeze`/`store.CreateFreeze` undefined (compile error).

- [ ] **Step 3: Add the schema**

In `orchestrator/internal/db/postgres.go`, right after `job_schedules`' index:

```go
		// agent_maintenance_freezes: one-shot absolute freeze window per agent,
		// checked at dispatch time by Dispatcher.Tick.
		`CREATE TABLE IF NOT EXISTS agent_maintenance_freezes (
			id         text        PRIMARY KEY DEFAULT gen_random_uuid()::text,
			agent_id   text        NOT NULL,
			from_at    timestamptz NOT NULL,
			to_at      timestamptz NOT NULL,
			reason     text        NOT NULL DEFAULT '',
			created_by text        NOT NULL DEFAULT '',
			created_at timestamptz NOT NULL DEFAULT NOW()
		)`,
		`CREATE INDEX IF NOT EXISTS idx_agent_maintenance_freezes_agent_id ON agent_maintenance_freezes (agent_id)`,
```

- [ ] **Step 4: Write `freeze.go`**

```go
// orchestrator/internal/jobs/freeze.go
package jobs

import (
	"context"
	"time"
)

// AgentFreeze is a one-shot absolute freeze window for one agent -- while
// active, Dispatcher.Tick defers rather than dispatches any pending target
// for this agent.
type AgentFreeze struct {
	ID        string
	AgentID   string
	FromAt    time.Time
	ToAt      time.Time
	Reason    string
	CreatedBy string
	CreatedAt time.Time
}

func (s *Store) CreateFreeze(ctx context.Context, f AgentFreeze) (AgentFreeze, error) {
	var id string
	if err := s.pool.QueryRow(ctx,
		`INSERT INTO agent_maintenance_freezes (agent_id, from_at, to_at, reason, created_by)
		 VALUES ($1,$2,$3,$4,$5) RETURNING id`,
		f.AgentID, f.FromAt, f.ToAt, f.Reason, f.CreatedBy,
	).Scan(&id); err != nil {
		return AgentFreeze{}, err
	}
	return s.getFreeze(ctx, id)
}

func (s *Store) getFreeze(ctx context.Context, id string) (AgentFreeze, error) {
	var f AgentFreeze
	err := s.pool.QueryRow(ctx,
		`SELECT id, agent_id, from_at, to_at, reason, created_by, created_at FROM agent_maintenance_freezes WHERE id=$1`, id,
	).Scan(&f.ID, &f.AgentID, &f.FromAt, &f.ToAt, &f.Reason, &f.CreatedBy, &f.CreatedAt)
	return f, err
}

func (s *Store) ListFreezesForAgent(ctx context.Context, agentID string) ([]AgentFreeze, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, agent_id, from_at, to_at, reason, created_by, created_at
		   FROM agent_maintenance_freezes WHERE agent_id=$1 ORDER BY from_at DESC`, agentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AgentFreeze
	for rows.Next() {
		var f AgentFreeze
		if err := rows.Scan(&f.ID, &f.AgentID, &f.FromAt, &f.ToAt, &f.Reason, &f.CreatedBy, &f.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

func (s *Store) DeleteFreeze(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM agent_maintenance_freezes WHERE id=$1`, id)
	return err
}

// IsAgentFrozen reports whether agentID has a currently-active freeze
// window. Overlapping freezes for the same agent are allowed at creation --
// this only cares whether any one of them is active right now, taking the
// most recently created if several overlap.
func (s *Store) IsAgentFrozen(ctx context.Context, agentID string) (frozen bool, reason string, err error) {
	err = s.pool.QueryRow(ctx,
		`SELECT reason FROM agent_maintenance_freezes
		  WHERE agent_id=$1 AND from_at <= NOW() AND to_at >= NOW()
		  ORDER BY created_at DESC LIMIT 1`, agentID,
	).Scan(&reason)
	if err != nil {
		return false, "", nil // no rows is the common, non-error case
	}
	return true, reason, nil
}
```

**Note on Step 4:** `IsAgentFrozen` deliberately swallows `pgx.ErrNoRows` (and any other scan error) into `frozen=false, err=nil` -- a missing freeze row is the overwhelmingly common case on every dispatch check, not an error condition. This mirrors how `Get`-style lookups elsewhere in this codebase (e.g. `remediation_dispatch.go`'s `findStepByCheckID`) return an ok-bool rather than propagating "not found" as an error.

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/jobs/... -v`
Expected: PASS for every test in the package.

- [ ] **Step 6: Full build check**

Run: `cd orchestrator && go build ./...`
Expected: succeeds cleanly.

- [ ] **Step 7: Commit**

```bash
git add orchestrator/internal/db/postgres.go orchestrator/internal/jobs/freeze.go orchestrator/internal/jobs/freeze_test.go
git commit -m "feat(jobs): add agent_maintenance_freezes schema, Store CRUD, and IsAgentFrozen"
git push
```

---

### Task 6: `TargetStateDeferred` + `AggregateState` + freeze-aware `Tick()`

**Files:**
- Modify: `orchestrator/internal/jobs/types.go` (`TargetStateDeferred` constant)
- Modify: `orchestrator/internal/jobs/state.go` (`AggregateState` handles the new state)
- Modify: `orchestrator/internal/jobs/store.go` (`ListDeferredTargets`, `MarkTargetDeferred`, `MarkTargetPending`)
- Modify: `orchestrator/internal/jobs/dispatch.go` (`Tick`'s phase 2 resume-check + phase 3 freeze-check)
- Test: `orchestrator/internal/jobs/state_test.go`, `orchestrator/internal/jobs/store_test.go`, `orchestrator/internal/jobs/dispatch_test.go`

**Interfaces:**
- Consumes: `Store.IsAgentFrozen` (Task 5).
- Produces: `TargetStateDeferred` constant; `(s *Store) ListDeferredTargets(ctx) ([]JobTarget, error)`; `(s *Store) MarkTargetDeferred(ctx, targetID, reason string) error`; `(s *Store) MarkTargetPending(ctx, targetID string) error`.

- [ ] **Step 1: Write the failing tests**

Append to `orchestrator/internal/jobs/state_test.go`:

```go
func TestAggregateState_DeferredTargetKeepsJobRunning(t *testing.T) {
	targets := []JobTarget{{State: TargetStateCompleted}, {State: TargetStateDeferred}}
	got := AggregateState(JobStateRunning, targets)
	if got != JobStateRunning {
		t.Errorf("AggregateState() = %q, want %q (a deferred target is never terminal)", got, JobStateRunning)
	}
}

func TestAggregateState_AllDeferredIsRunningNotRequested(t *testing.T) {
	targets := []JobTarget{{State: TargetStateDeferred}, {State: TargetStateDeferred}}
	got := AggregateState(JobStateRequested, targets)
	if got != JobStateRunning {
		t.Errorf("AggregateState() = %q, want %q", got, JobStateRunning)
	}
}
```

Append to `orchestrator/internal/jobs/store_test.go`:

```go
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
```

Append to `orchestrator/internal/jobs/dispatch_test.go`:

```go
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/jobs/... -run "TestAggregateState_.*Deferred|TestMarkTargetDeferred|TestTick_Frozen|TestTick_Deferred" -v`
Expected: FAIL — `TargetStateDeferred`/`store.MarkTargetDeferred`/`store.ListDeferredTargets`/`store.MarkTargetPending` undefined (compile error).

- [ ] **Step 3: Add `TargetStateDeferred`**

In `orchestrator/internal/jobs/types.go`, add to the target-state const block:

```go
	TargetStateDeferred = "deferred" // frozen at dispatch time; non-terminal, auto-resumes when the freeze lifts
```

- [ ] **Step 4: Update `AggregateState`**

In `orchestrator/internal/jobs/state.go`, add a case to the `switch`:

```go
		case TargetStateDeferred:
			dispatchedOrTerminal++
```

(placed alongside the existing `case TargetStateDispatched:` -- deferred counts toward "job still running," never toward `terminal`/`completed`.)

- [ ] **Step 5: Add `Store` methods**

Append to `orchestrator/internal/jobs/store.go`:

```go
func (s *Store) ListDeferredTargets(ctx context.Context) ([]JobTarget, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT `+jobTargetColumnsQualified()+`
		   FROM job_targets jt JOIN jobs j ON j.id = jt.job_id
		  WHERE jt.state = $1 AND j.state IN ($2,$3)`,
		TargetStateDeferred, JobStateRequested, JobStateRunning)
	if err != nil {
		return nil, err
	}
	return scanJobTargets(rows)
}

func (s *Store) MarkTargetDeferred(ctx context.Context, targetID, reason string) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE job_targets SET state=$1, error=$2 WHERE id=$3`,
		TargetStateDeferred, reason, targetID)
	return err
}

func (s *Store) MarkTargetPending(ctx context.Context, targetID string) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE job_targets SET state=$1, error='' WHERE id=$2`,
		TargetStatePending, targetID)
	return err
}
```

- [ ] **Step 6: Wire freeze-check and resume into `Tick`**

In `orchestrator/internal/jobs/dispatch.go`, insert a new phase between the existing "resolve terminal in-flight targets" loop and the "dispatch pending targets" loop:

```go
	deferred, err := d.store.ListDeferredTargets(ctx)
	if err != nil {
		return err
	}
	for _, t := range deferred {
		frozen, _, ferr := d.store.IsAgentFrozen(ctx, t.AgentID)
		if ferr != nil || frozen {
			continue
		}
		if err := d.store.MarkTargetPending(ctx, t.ID); err != nil {
			continue
		}
		touchedJobs[t.JobID] = true
	}
```

Then, inside the existing pending-dispatch loop, check the freeze before calling `d.dispatch`:

```go
	for _, t := range pending {
		job, err := jobOf(t.JobID)
		if err != nil {
			continue
		}
		if frozen, reason, ferr := d.store.IsAgentFrozen(ctx, t.AgentID); ferr == nil && frozen {
			d.store.MarkTargetDeferred(ctx, t.ID, reason)
			touchedJobs[t.JobID] = true
			continue
		}
		refID, dispatchErr := d.dispatch(ctx, job, t)
		if dispatchErr != nil {
			d.store.MarkTargetTerminal(ctx, t.ID, TargetStateFailed, dispatchErr.Error())
		} else {
			d.store.MarkTargetDispatched(ctx, t.ID, refID)
		}
		touchedJobs[t.JobID] = true
	}
```

- [ ] **Step 7: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/jobs/... -v`
Expected: PASS for every test in the package.

- [ ] **Step 8: Full build check**

Run: `cd orchestrator && go build ./...`
Expected: succeeds cleanly.

- [ ] **Step 9: Commit**

```bash
git add orchestrator/internal/jobs/types.go orchestrator/internal/jobs/state.go orchestrator/internal/jobs/store.go orchestrator/internal/jobs/dispatch.go orchestrator/internal/jobs/state_test.go orchestrator/internal/jobs/store_test.go orchestrator/internal/jobs/dispatch_test.go
git commit -m "feat(jobs): add TargetStateDeferred -- frozen targets defer at dispatch time and auto-resume"
git push
```

---

### Task 7: `scheduledAt` on `POST /api/jobs/batch-remediation`

**Files:**
- Modify: `orchestrator/internal/api/job_handlers.go`
- Test: `orchestrator/internal/api/job_handlers_test.go`

**Interfaces:**
- Consumes: `jobsStore.CreateBatchScheduled` (Task 1).

- [ ] **Step 1: Write the failing test**

Append to `orchestrator/internal/api/job_handlers_test.go`:

```go
func TestCreateBatchRemediationJob_ScheduledAt_SetsJobScheduledAt(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('jbs-a1', 'JBS-A1')`)
		cat, err := remediation.NewCatalog()
		if err != nil {
			t.Fatalf("NewCatalog: %v", err)
		}
		jobsStore := jobs.NewStore(pool)
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "").
			WithRemediationCatalog(cat).
			WithJobsDispatcher(jobsStore, jobs.NewDispatcher(jobsStore))

		future := time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339)
		body, _ := json.Marshal(map[string]any{
			"remediationId": "enable_windows_firewall",
			"reason":        "scheduled batch",
			"agentIds":      []string{"jbs-a1"},
			"scheduledAt":   future,
		})
		req := httptest.NewRequest(http.MethodPost, "/x", bytes.NewReader(body))
		req = req.WithContext(auth.ContextWithClaims(req.Context(), &auth.Claims{UserID: "user-1", Role: auth.RoleAnalyst}))
		w := httptest.NewRecorder()
		h.CreateBatchRemediationJob(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
		}
		var resp struct {
			JobID string `json:"jobId"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		got, err := jobsStore.Get(context.Background(), resp.JobID)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if got.ScheduledAt == nil {
			t.Fatal("job.ScheduledAt is nil, want the requested future time")
		}
	})
}

func TestCreateBatchRemediationJob_InvalidScheduledAt_BadRequest(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('jbs-a2', 'JBS-A2')`)
		cat, err := remediation.NewCatalog()
		if err != nil {
			t.Fatalf("NewCatalog: %v", err)
		}
		jobsStore := jobs.NewStore(pool)
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "").
			WithRemediationCatalog(cat).
			WithJobsDispatcher(jobsStore, jobs.NewDispatcher(jobsStore))

		body, _ := json.Marshal(map[string]any{
			"remediationId": "enable_windows_firewall",
			"reason":        "test",
			"agentIds":      []string{"jbs-a2"},
			"scheduledAt":   "not-a-timestamp",
		})
		req := httptest.NewRequest(http.MethodPost, "/x", bytes.NewReader(body))
		req = req.WithContext(auth.ContextWithClaims(req.Context(), &auth.Claims{UserID: "user-1", Role: auth.RoleAnalyst}))
		w := httptest.NewRecorder()
		h.CreateBatchRemediationJob(w, req)
		if w.Code != http.StatusBadRequest {
			t.Errorf("status = %d, want 400 for an unparseable scheduledAt", w.Code)
		}
	})
}
```

Add `"time"` to `job_handlers_test.go`'s import block if not already present.

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/api/... -run "TestCreateBatchRemediationJob_.*ScheduledAt" -v`
Expected: FAIL — the request succeeds but `job.ScheduledAt` stays nil (the field is silently ignored today), and the invalid-input case doesn't 400.

- [ ] **Step 3: Update `CreateBatchRemediationJob`**

In `orchestrator/internal/api/job_handlers.go`, add `ScheduledAt` to the request struct and parse it:

```go
	var req struct {
		RemediationID string   `json:"remediationId"`
		Reason        string   `json:"reason"`
		AgentIDs      []string `json:"agentIds"`
		ScheduledAt   string   `json:"scheduledAt"`
	}
```

Add parsing right after the existing `agentIds` empty-check, before the catalog lookup:

```go
	var scheduledAt *time.Time
	if req.ScheduledAt != "" {
		t, err := time.Parse(time.RFC3339, req.ScheduledAt)
		if err != nil {
			jsonError(w, "scheduledAt must be RFC3339", http.StatusBadRequest)
			return
		}
		scheduledAt = &t
	}
```

Replace the `CreateBatch` call with `CreateBatchScheduled`:

```go
	job, err := h.jobsStore.CreateBatchScheduled(r.Context(), "batch_remediation", payload, actorID, req.AgentIDs, scheduledAt)
```

Add `"time"` to `job_handlers.go`'s import block.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/api/... -run TestCreateBatchRemediationJob -v`
Expected: PASS for every `TestCreateBatchRemediationJob*` test, including Sub-project 6's original 4 (unchanged behavior when `scheduledAt` is omitted).

- [ ] **Step 5: Full build check**

Run: `cd orchestrator && go build ./...`
Expected: succeeds cleanly.

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/api/job_handlers.go orchestrator/internal/api/job_handlers_test.go
git commit -m "feat(api): add optional scheduledAt to POST /api/jobs/batch-remediation"
git push
```

---

### Task 8: `job-schedules` API (create, list, cancel)

**Files:**
- Create: `orchestrator/internal/api/schedule_handlers.go`
- Modify: `orchestrator/internal/api/routes.go`
- Modify: `orchestrator/internal/api/rbac_matrix_test.go`
- Test: `orchestrator/internal/api/schedule_handlers_test.go`

**Interfaces:**
- Consumes: `h.jobsStore.CreateSchedule`/`.ListSchedules`/`.DisableSchedule`/`.GetSchedule` (Task 3); the same catalog/tier/permission logic as `CreateBatchRemediationJob` (Sub-project 6/Task 7).
- Produces: `(h *Handler) CreateJobSchedule`, `(h *Handler) ListJobSchedules`, `(h *Handler) CancelJobSchedule`.

- [ ] **Step 1: Write the failing tests**

```go
// orchestrator/internal/api/schedule_handlers_test.go
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/jobs"
	"github.com/audspect/bas/internal/remediation"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

func TestCreateJobSchedule_CreatesEnabledSchedule(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		cat, err := remediation.NewCatalog()
		if err != nil {
			t.Fatalf("NewCatalog: %v", err)
		}
		jobsStore := jobs.NewStore(pool)
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "").
			WithRemediationCatalog(cat).
			WithJobsDispatcher(jobsStore, jobs.NewDispatcher(jobsStore))

		body, _ := json.Marshal(map[string]any{
			"remediationId": "enable_windows_firewall",
			"reason":        "weekly hardening",
			"agentIds":      []string{"sch-a1", "sch-a2"},
			"dayOfWeek":     5,
			"timeOfDay":     "23:00",
			"timezone":      "Asia/Kolkata",
		})
		req := httptest.NewRequest(http.MethodPost, "/x", bytes.NewReader(body))
		req = req.WithContext(auth.ContextWithClaims(req.Context(), &auth.Claims{UserID: "user-1", Role: auth.RoleAnalyst}))
		w := httptest.NewRecorder()
		h.CreateJobSchedule(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
		}
		var resp struct {
			ScheduleID string `json:"scheduleId"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		got, err := jobsStore.GetSchedule(context.Background(), resp.ScheduleID)
		if err != nil {
			t.Fatalf("GetSchedule: %v", err)
		}
		if !got.Enabled || got.DayOfWeek != 5 || got.TimeOfDay != "23:00" || got.Timezone != "Asia/Kolkata" || len(got.AgentIDs) != 2 {
			t.Errorf("got = %+v, want Enabled=true DayOfWeek=5 TimeOfDay=23:00 Timezone=Asia/Kolkata 2 AgentIDs", got)
		}
	})
}

func TestCreateJobSchedule_Tier2WithoutApprovePermission_Forbidden(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		cat, err := remediation.NewCatalog()
		if err != nil {
			t.Fatalf("NewCatalog: %v", err)
		}
		jobsStore := jobs.NewStore(pool)
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "").
			WithRemediationCatalog(cat).
			WithJobsDispatcher(jobsStore, jobs.NewDispatcher(jobsStore))

		body, _ := json.Marshal(map[string]any{
			"remediationId": "disable_windows_smbv1", // Tier 2
			"reason":        "test",
			"agentIds":      []string{"sch-a3"},
			"dayOfWeek":     5,
			"timeOfDay":     "23:00",
			"timezone":      "UTC",
		})
		req := httptest.NewRequest(http.MethodPost, "/x", bytes.NewReader(body))
		req = req.WithContext(auth.ContextWithClaims(req.Context(), &auth.Claims{UserID: "user-1", Role: auth.RoleAnalyst}))
		w := httptest.NewRecorder()
		h.CreateJobSchedule(w, req)
		if w.Code != http.StatusForbidden {
			t.Errorf("status = %d, want 403", w.Code)
		}
	})
}

func TestCreateJobSchedule_InvalidTimezone_BadRequest(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		cat, err := remediation.NewCatalog()
		if err != nil {
			t.Fatalf("NewCatalog: %v", err)
		}
		jobsStore := jobs.NewStore(pool)
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "").
			WithRemediationCatalog(cat).
			WithJobsDispatcher(jobsStore, jobs.NewDispatcher(jobsStore))

		body, _ := json.Marshal(map[string]any{
			"remediationId": "enable_windows_firewall",
			"reason":        "test",
			"agentIds":      []string{"sch-a4"},
			"dayOfWeek":     5,
			"timeOfDay":     "23:00",
			"timezone":      "Not/A_Real_Zone",
		})
		req := httptest.NewRequest(http.MethodPost, "/x", bytes.NewReader(body))
		req = req.WithContext(auth.ContextWithClaims(req.Context(), &auth.Claims{UserID: "user-1", Role: auth.RoleAnalyst}))
		w := httptest.NewRecorder()
		h.CreateJobSchedule(w, req)
		if w.Code != http.StatusBadRequest {
			t.Errorf("status = %d, want 400 for an invalid timezone", w.Code)
		}
	})
}

func TestListJobSchedules_ReturnsCreatedSchedule(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		jobsStore := jobs.NewStore(pool)
		payload, _ := json.Marshal(map[string]string{"remediationId": "enable_windows_firewall", "reason": "test"})
		created, err := jobsStore.CreateSchedule(context.Background(), jobs.Schedule{
			Type: "batch_remediation", Payload: payload, AgentIDs: []string{"a1"},
			DayOfWeek: 5, TimeOfDay: "23:00", Timezone: "UTC", Enabled: true, CreatedBy: "user-1",
		})
		if err != nil {
			t.Fatalf("CreateSchedule: %v", err)
		}

		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "").
			WithJobsDispatcher(jobsStore, jobs.NewDispatcher(jobsStore))
		req := httptest.NewRequest(http.MethodGet, "/x", nil)
		w := httptest.NewRecorder()
		h.ListJobSchedules(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
		}
		var resp struct {
			Schedules []jobs.Schedule `json:"schedules"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		found := false
		for _, sch := range resp.Schedules {
			if sch.ID == created.ID {
				found = true
			}
		}
		if !found {
			t.Errorf("ListJobSchedules() did not include %s", created.ID)
		}
	})
}

func TestCancelJobSchedule_Disables(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		jobsStore := jobs.NewStore(pool)
		payload, _ := json.Marshal(map[string]string{"remediationId": "enable_windows_firewall", "reason": "test"})
		created, err := jobsStore.CreateSchedule(context.Background(), jobs.Schedule{
			Type: "batch_remediation", Payload: payload, AgentIDs: []string{"a1"},
			DayOfWeek: 5, TimeOfDay: "23:00", Timezone: "UTC", Enabled: true, CreatedBy: "user-1",
		})
		if err != nil {
			t.Fatalf("CreateSchedule: %v", err)
		}

		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "").
			WithJobsDispatcher(jobsStore, jobs.NewDispatcher(jobsStore))
		req := withURLParam(httptest.NewRequest(http.MethodPost, "/x", nil), "scheduleId", created.ID)
		w := httptest.NewRecorder()
		h.CancelJobSchedule(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
		}
		got, err := jobsStore.GetSchedule(context.Background(), created.ID)
		if err != nil {
			t.Fatalf("GetSchedule: %v", err)
		}
		if got.Enabled {
			t.Error("Enabled = true, want false after cancel")
		}
	})
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/api/... -run "TestCreateJobSchedule|TestListJobSchedules|TestCancelJobSchedule" -v`
Expected: FAIL — `h.CreateJobSchedule`/`h.ListJobSchedules`/`h.CancelJobSchedule` undefined (compile error).

- [ ] **Step 3: Write `schedule_handlers.go`**

```go
// orchestrator/internal/api/schedule_handlers.go
package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/jobs"
	"github.com/audspect/bas/internal/remediation"
)

// POST /api/job-schedules
// Same tier-gated permission logic as CreateBatchRemediationJob -- a
// schedule is "create this batch job, but recurring."
func (h *Handler) CreateJobSchedule(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RemediationID string   `json:"remediationId"`
		Reason        string   `json:"reason"`
		AgentIDs      []string `json:"agentIds"`
		DayOfWeek     int      `json:"dayOfWeek"`
		TimeOfDay     string   `json:"timeOfDay"`
		Timezone      string   `json:"timezone"`
	}
	if json.NewDecoder(r.Body).Decode(&req) != nil || req.RemediationID == "" {
		jsonError(w, "remediationId is required", http.StatusBadRequest)
		return
	}
	if req.Reason == "" {
		jsonError(w, "reason is required", http.StatusBadRequest)
		return
	}
	if len(req.AgentIDs) == 0 {
		jsonError(w, "agentIds must contain at least one agent", http.StatusBadRequest)
		return
	}
	if req.DayOfWeek < 0 || req.DayOfWeek > 6 {
		jsonError(w, "dayOfWeek must be 0-6", http.StatusBadRequest)
		return
	}
	if _, _, err := parseTimeOfDayForAPI(req.TimeOfDay); err != nil {
		jsonError(w, "timeOfDay must be HH:MM (24h)", http.StatusBadRequest)
		return
	}
	tz := req.Timezone
	if tz == "" {
		tz = "UTC"
	}
	if _, err := time.LoadLocation(tz); err != nil {
		jsonError(w, "timezone is not a valid IANA name", http.StatusBadRequest)
		return
	}
	if h.remediationCatalog == nil {
		jsonError(w, "remediation catalog not loaded", http.StatusServiceUnavailable)
		return
	}
	entry, ok := h.remediationCatalog.ByID(req.RemediationID)
	if !ok {
		jsonError(w, "unknown remediationId", http.StatusNotFound)
		return
	}
	if entry.Tier == remediation.TierManualGuidance {
		jsonError(w, "this remediation is manual guidance only -- no automatic execution", http.StatusUnprocessableEntity)
		return
	}
	claims, _ := auth.ClaimsFrom(r.Context())
	if entry.Tier == remediation.TierConfirmRequired && (claims == nil || !auth.HasPermission(claims.Role, auth.CanApproveRemediation)) {
		jsonError(w, "this remediation requires an Administrator", http.StatusForbidden)
		return
	}
	if h.jobsStore == nil {
		jsonError(w, "job engine not loaded", http.StatusServiceUnavailable)
		return
	}

	actorID := ""
	if claims != nil {
		actorID = claims.UserID
	}
	payload, err := json.Marshal(map[string]string{"remediationId": entry.ID, "reason": req.Reason})
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	sch, err := h.jobsStore.CreateSchedule(r.Context(), jobs.Schedule{
		Type: "batch_remediation", Payload: payload, AgentIDs: req.AgentIDs,
		DayOfWeek: req.DayOfWeek, TimeOfDay: req.TimeOfDay, Timezone: tz, Enabled: true, CreatedBy: actorID,
	})
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.auditLog(r, "jobs.schedule.create", sch.ID,
		map[string]any{"remediationId": entry.ID, "agentCount": len(req.AgentIDs), "dayOfWeek": req.DayOfWeek, "timeOfDay": req.TimeOfDay, "timezone": tz}, "created")
	respond(w, map[string]any{"scheduleId": sch.ID})
}

// GET /api/job-schedules
func (h *Handler) ListJobSchedules(w http.ResponseWriter, r *http.Request) {
	if h.jobsStore == nil {
		jsonError(w, "job engine not loaded", http.StatusServiceUnavailable)
		return
	}
	schedules, err := h.jobsStore.ListSchedules(r.Context())
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respond(w, map[string]any{"schedules": schedules})
}

// POST /api/job-schedules/{scheduleId}/cancel
func (h *Handler) CancelJobSchedule(w http.ResponseWriter, r *http.Request) {
	scheduleID := chi.URLParam(r, "scheduleId")
	if h.jobsStore == nil {
		jsonError(w, "job engine not loaded", http.StatusServiceUnavailable)
		return
	}
	if _, err := h.jobsStore.GetSchedule(r.Context(), scheduleID); err != nil {
		jsonError(w, "schedule not found", http.StatusNotFound)
		return
	}
	if err := h.jobsStore.DisableSchedule(r.Context(), scheduleID); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.auditLog(r, "jobs.schedule.cancel", scheduleID, nil, "cancelled")
	respond(w, map[string]any{"scheduleId": scheduleID, "enabled": false})
}

// parseTimeOfDayForAPI validates "HH:MM" without importing internal/jobs'
// unexported parseTimeOfDay -- kept deliberately tiny and duplicated rather
// than exporting a package-internal helper solely for this one call site.
func parseTimeOfDayForAPI(s string) (hour, minute int, err error) {
	var h2, m2 int
	n, scanErr := fmt.Sscanf(s, "%d:%d", &h2, &m2)
	if scanErr != nil || n != 2 || h2 < 0 || h2 > 23 || m2 < 0 || m2 > 59 {
		return 0, 0, fmt.Errorf("invalid time-of-day %q", s)
	}
	return h2, m2, nil
}
```

Add `"fmt"` to `schedule_handlers.go`'s import block.

- [ ] **Step 4: Register the routes**

In `orchestrator/internal/api/routes.go`, right after the `POST /api/jobs/{jobId}/cancel` route:

```go
		r.With(auth.RequirePermission(auth.CanExecuteRemediation)).Post("/api/job-schedules", h.CreateJobSchedule)
		r.With(auth.RequirePermission(auth.CanExecuteRemediation)).Get("/api/job-schedules", h.ListJobSchedules)
		r.With(auth.RequirePermission(auth.CanExecuteRemediation)).Post("/api/job-schedules/{scheduleId}/cancel", h.CancelJobSchedule)
```

- [ ] **Step 5: Add the rows to the RBAC route matrix**

In `orchestrator/internal/api/rbac_matrix_test.go`, right after the `POST /api/jobs/{jobId}/cancel` row:

```go
	{http.MethodPost, "/api/job-schedules", tierPermission, auth.CanExecuteRemediation},
	{http.MethodGet, "/api/job-schedules", tierPermission, auth.CanExecuteRemediation},
	{http.MethodPost, "/api/job-schedules/{scheduleId}/cancel", tierPermission, auth.CanExecuteRemediation},
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/api/... -run "TestCreateJobSchedule|TestListJobSchedules|TestCancelJobSchedule|TestRBACMatrix" -v`
Expected: PASS for all 5 new tests plus `TestRBACMatrix_NoDrift`/`TestRBACMatrix_MethodConfusion`.

- [ ] **Step 7: Full build check**

Run: `cd orchestrator && go build ./...`
Expected: succeeds cleanly.

- [ ] **Step 8: Commit**

```bash
git add orchestrator/internal/api/schedule_handlers.go orchestrator/internal/api/schedule_handlers_test.go orchestrator/internal/api/routes.go orchestrator/internal/api/rbac_matrix_test.go
git commit -m "feat(api): add job-schedules CRUD (create/list/cancel)"
git push
```

---

### Task 9: `maintenance-freezes` API (create, list, delete)

**Files:**
- Create: `orchestrator/internal/api/freeze_handlers.go`
- Modify: `orchestrator/internal/api/routes.go`
- Modify: `orchestrator/internal/api/rbac_matrix_test.go`
- Test: `orchestrator/internal/api/freeze_handlers_test.go`

**Interfaces:**
- Consumes: `h.jobsStore.CreateFreeze`/`.ListFreezesForAgent`/`.DeleteFreeze` (Task 5).
- Produces: `(h *Handler) CreateAgentFreeze`, `(h *Handler) ListAgentFreezes`, `(h *Handler) DeleteAgentFreeze`.

- [ ] **Step 1: Write the failing tests**

```go
// orchestrator/internal/api/freeze_handlers_test.go
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/jobs"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

func TestCreateAgentFreeze_AdminCreates(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		jobsStore := jobs.NewStore(pool)
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "").
			WithJobsDispatcher(jobsStore, jobs.NewDispatcher(jobsStore))

		from := time.Now().UTC()
		to := from.Add(48 * time.Hour)
		body, _ := json.Marshal(map[string]any{
			"fromAt": from.Format(time.RFC3339),
			"toAt":   to.Format(time.RFC3339),
			"reason": "Q3 audit change-freeze",
		})
		req := withURLParam(httptest.NewRequest(http.MethodPost, "/x", bytes.NewReader(body)), "agentId", "freeze-h-a1")
		req = req.WithContext(auth.ContextWithClaims(req.Context(), &auth.Claims{UserID: "admin-1", Role: auth.RoleAdmin}))
		w := httptest.NewRecorder()
		h.CreateAgentFreeze(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
		}

		frozen, reason, err := jobsStore.IsAgentFrozen(context.Background(), "freeze-h-a1")
		if err != nil {
			t.Fatalf("IsAgentFrozen: %v", err)
		}
		if !frozen || reason != "Q3 audit change-freeze" {
			t.Errorf("frozen=%v reason=%q, want true/'Q3 audit change-freeze'", frozen, reason)
		}
	})
}

func TestCreateAgentFreeze_AnalystForbidden(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		jobsStore := jobs.NewStore(pool)
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "").
			WithJobsDispatcher(jobsStore, jobs.NewDispatcher(jobsStore))

		from := time.Now().UTC()
		to := from.Add(1 * time.Hour)
		body, _ := json.Marshal(map[string]any{"fromAt": from.Format(time.RFC3339), "toAt": to.Format(time.RFC3339), "reason": "test"})
		req := withURLParam(httptest.NewRequest(http.MethodPost, "/x", bytes.NewReader(body)), "agentId", "freeze-h-a2")
		req = req.WithContext(auth.ContextWithClaims(req.Context(), &auth.Claims{UserID: "user-1", Role: auth.RoleAnalyst}))
		w := httptest.NewRecorder()
		h.CreateAgentFreeze(w, req)
		if w.Code != http.StatusForbidden {
			t.Errorf("status = %d, want 403 (freeze creation is Admin-only)", w.Code)
		}
	})
}

func TestCreateAgentFreeze_ToBeforeFrom_BadRequest(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		jobsStore := jobs.NewStore(pool)
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "").
			WithJobsDispatcher(jobsStore, jobs.NewDispatcher(jobsStore))

		from := time.Now().UTC()
		to := from.Add(-1 * time.Hour) // before from
		body, _ := json.Marshal(map[string]any{"fromAt": from.Format(time.RFC3339), "toAt": to.Format(time.RFC3339), "reason": "test"})
		req := withURLParam(httptest.NewRequest(http.MethodPost, "/x", bytes.NewReader(body)), "agentId", "freeze-h-a3")
		req = req.WithContext(auth.ContextWithClaims(req.Context(), &auth.Claims{UserID: "admin-1", Role: auth.RoleAdmin}))
		w := httptest.NewRecorder()
		h.CreateAgentFreeze(w, req)
		if w.Code != http.StatusBadRequest {
			t.Errorf("status = %d, want 400 (toAt before fromAt)", w.Code)
		}
	})
}

func TestListAgentFreezes_ReturnsCreated(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		jobsStore := jobs.NewStore(pool)
		created, err := jobsStore.CreateFreeze(context.Background(), jobs.AgentFreeze{
			AgentID: "freeze-h-a4", FromAt: time.Now().UTC(), ToAt: time.Now().UTC().Add(1 * time.Hour), Reason: "test",
		})
		if err != nil {
			t.Fatalf("CreateFreeze: %v", err)
		}

		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "").
			WithJobsDispatcher(jobsStore, jobs.NewDispatcher(jobsStore))
		req := withURLParam(httptest.NewRequest(http.MethodGet, "/x", nil), "agentId", "freeze-h-a4")
		w := httptest.NewRecorder()
		h.ListAgentFreezes(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
		}
		var resp struct {
			Freezes []jobs.AgentFreeze `json:"freezes"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if len(resp.Freezes) != 1 || resp.Freezes[0].ID != created.ID {
			t.Errorf("resp.Freezes = %+v, want 1 row matching %s", resp.Freezes, created.ID)
		}
	})
}

func TestDeleteAgentFreeze_AdminLiftsEarly(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		jobsStore := jobs.NewStore(pool)
		created, err := jobsStore.CreateFreeze(context.Background(), jobs.AgentFreeze{
			AgentID: "freeze-h-a5", FromAt: time.Now().UTC(), ToAt: time.Now().UTC().Add(1 * time.Hour), Reason: "test",
		})
		if err != nil {
			t.Fatalf("CreateFreeze: %v", err)
		}

		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "").
			WithJobsDispatcher(jobsStore, jobs.NewDispatcher(jobsStore))
		req := withURLParam(httptest.NewRequest(http.MethodDelete, "/x", nil), "freezeId", created.ID)
		req = req.WithContext(auth.ContextWithClaims(req.Context(), &auth.Claims{UserID: "admin-1", Role: auth.RoleAdmin}))
		w := httptest.NewRecorder()
		h.DeleteAgentFreeze(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
		}
		frozen, _, err := jobsStore.IsAgentFrozen(context.Background(), "freeze-h-a5")
		if err != nil {
			t.Fatalf("IsAgentFrozen: %v", err)
		}
		if frozen {
			t.Error("frozen = true, want false after DELETE")
		}
	})
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/api/... -run "TestCreateAgentFreeze|TestListAgentFreezes|TestDeleteAgentFreeze" -v`
Expected: FAIL — `h.CreateAgentFreeze`/`h.ListAgentFreezes`/`h.DeleteAgentFreeze` undefined (compile error).

- [ ] **Step 3: Write `freeze_handlers.go`**

```go
// orchestrator/internal/api/freeze_handlers.go
package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/jobs"
)

// POST /api/agents/{agentId}/maintenance-freezes
// Admin-only: a freeze can silently block every remediation tier including
// ones an Analyst is normally allowed to run, making it a stronger action
// than executing a single remediation.
func (h *Handler) CreateAgentFreeze(w http.ResponseWriter, r *http.Request) {
	agentID := chi.URLParam(r, "agentId")
	var req struct {
		FromAt string `json:"fromAt"`
		ToAt   string `json:"toAt"`
		Reason string `json:"reason"`
	}
	if json.NewDecoder(r.Body).Decode(&req) != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	from, err := time.Parse(time.RFC3339, req.FromAt)
	if err != nil {
		jsonError(w, "fromAt must be RFC3339", http.StatusBadRequest)
		return
	}
	to, err := time.Parse(time.RFC3339, req.ToAt)
	if err != nil {
		jsonError(w, "toAt must be RFC3339", http.StatusBadRequest)
		return
	}
	if !to.After(from) {
		jsonError(w, "toAt must be after fromAt", http.StatusBadRequest)
		return
	}
	if h.jobsStore == nil {
		jsonError(w, "job engine not loaded", http.StatusServiceUnavailable)
		return
	}
	claims, _ := auth.ClaimsFrom(r.Context())
	actorID := ""
	if claims != nil {
		actorID = claims.UserID
	}
	f, err := h.jobsStore.CreateFreeze(r.Context(), jobs.AgentFreeze{
		AgentID: agentID, FromAt: from, ToAt: to, Reason: req.Reason, CreatedBy: actorID,
	})
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.auditLog(r, "jobs.freeze.create", f.ID, map[string]any{"agentId": agentID, "fromAt": req.FromAt, "toAt": req.ToAt}, "created")
	respond(w, map[string]any{"freezeId": f.ID})
}

// GET /api/agents/{agentId}/maintenance-freezes
func (h *Handler) ListAgentFreezes(w http.ResponseWriter, r *http.Request) {
	agentID := chi.URLParam(r, "agentId")
	if h.jobsStore == nil {
		jsonError(w, "job engine not loaded", http.StatusServiceUnavailable)
		return
	}
	freezes, err := h.jobsStore.ListFreezesForAgent(r.Context(), agentID)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respond(w, map[string]any{"freezes": freezes})
}

// DELETE /api/maintenance-freezes/{freezeId}
// Admin-only, same reasoning as create.
func (h *Handler) DeleteAgentFreeze(w http.ResponseWriter, r *http.Request) {
	freezeID := chi.URLParam(r, "freezeId")
	if h.jobsStore == nil {
		jsonError(w, "job engine not loaded", http.StatusServiceUnavailable)
		return
	}
	if err := h.jobsStore.DeleteFreeze(r.Context(), freezeID); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.auditLog(r, "jobs.freeze.delete", freezeID, nil, "deleted")
	respond(w, map[string]any{"freezeId": freezeID, "deleted": true})
}
```

- [ ] **Step 4: Register the routes**

In `orchestrator/internal/api/routes.go`, right after the `job-schedules` routes:

```go
		r.With(auth.RequirePermission(auth.CanApproveRemediation)).Post("/api/agents/{agentId}/maintenance-freezes", h.CreateAgentFreeze)
		r.With(auth.RequirePermission(auth.CanExecuteRemediation)).Get("/api/agents/{agentId}/maintenance-freezes", h.ListAgentFreezes)
		r.With(auth.RequirePermission(auth.CanApproveRemediation)).Delete("/api/maintenance-freezes/{freezeId}", h.DeleteAgentFreeze)
```

- [ ] **Step 5: Add the rows to the RBAC route matrix**

In `orchestrator/internal/api/rbac_matrix_test.go`, right after the `job-schedules` rows:

```go
	{http.MethodPost, "/api/agents/{agentId}/maintenance-freezes", tierPermission, auth.CanApproveRemediation},
	{http.MethodGet, "/api/agents/{agentId}/maintenance-freezes", tierPermission, auth.CanExecuteRemediation},
	{http.MethodDelete, "/api/maintenance-freezes/{freezeId}", tierPermission, auth.CanApproveRemediation},
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/api/... -run "TestCreateAgentFreeze|TestListAgentFreezes|TestDeleteAgentFreeze|TestRBACMatrix" -v`
Expected: PASS for all 5 new tests plus `TestRBACMatrix_NoDrift`/`TestRBACMatrix_MethodConfusion`.

- [ ] **Step 7: Full build check**

Run: `cd orchestrator && go build ./...`
Expected: succeeds cleanly.

- [ ] **Step 8: Commit**

```bash
git add orchestrator/internal/api/freeze_handlers.go orchestrator/internal/api/freeze_handlers_test.go orchestrator/internal/api/routes.go orchestrator/internal/api/rbac_matrix_test.go
git commit -m "feat(api): add maintenance-freezes CRUD (create/list/delete)"
git push
```

---

### Task 10: Full verification pass

**Files:** none (verification only).

- [ ] **Step 1: Confirm Docker is available**

```bash
docker info >/dev/null 2>&1 && echo "docker running" || echo "docker not running"
```

- [ ] **Step 2: Full build**

Run: `cd orchestrator && go build ./...`
Expected: succeeds cleanly.

- [ ] **Step 3: Full test suite for every touched package**

Run: `cd orchestrator && go test ./internal/jobs/... ./internal/api/... ./internal/remediation/... ./internal/auth/... -v 2>&1 | grep -E "^ok|^FAIL|^---"`
Expected: `ok` for all four packages, zero `FAIL`/`--- FAIL` lines. (`internal/remediation`/`internal/auth` are a regression check -- this plan never modifies either.)

- [ ] **Step 4: Confirm the RBAC route matrix has zero drift**

Run: `cd orchestrator && go test ./internal/api/... -run TestRBACMatrix_NoDrift -v`
Expected: PASS.

- [ ] **Step 5: No commit needed** (verification-only task).

---

## Self-Review Notes

- **Spec coverage**: §3 (architecture, generic infrastructure in `internal/jobs`) → Tasks 1-6. §4 (data model: `Job.ScheduledAt`, `job_schedules`, `agent_maintenance_freezes`, `TargetStateDeferred`) → Tasks 1, 3, 5, 6. §5 (dispatch-loop mechanics: `Tick`'s new phases, `spawnDueSchedules`, `nextOccurrenceSince`, `IsTerminalJobState`, `IsAgentFrozen`) → Tasks 2, 4, 5, 6. §6 (API surface, all 6 new/modified routes with their exact permissions) → Tasks 7, 8, 9. §7 (error handling: invalid schedule input rejected at creation, spawn-failure retry, skip-and-log overlap, freeze reason surfaced on the deferred target, no same-tick double-dispatch race) → covered by Task 8's validation, Task 4's retry-on-failure behavior, and Task 6's phase-ordering (resume before dispatch). §8 (testing) → every task's own tests plus Task 10's full-suite run. §9 (explicitly deferred: cron, recurring freezes, group freezing, hard-exclude, notifications) → no task builds any of that, correctly.
- **Placeholder scan**: found and fixed one during drafting -- Task 8 Step 3's `parseTimeOfDayForAPI` initially referenced a nonexistent `fmtSscanTimeOfDay` helper and `errBadTimeOfDay` sentinel; rewritten in place as a single, real `fmt.Sscanf`-based implementation.
- **Type consistency checked**: `CreateBatchScheduled`, `Schedule`, `AgentFreeze`, `IsTerminalJobState`, `nextOccurrenceSince`, `TargetStateDeferred`, `ListDeferredTargets`/`MarkTargetDeferred`/`MarkTargetPending`, `IsAgentFrozen`, and every `Store` schedule/freeze CRUD method match verbatim between their defining task and every consuming task (Tasks 4/6 consuming Tasks 2/3/5; Tasks 7/8/9 consuming Tasks 1/3/5).
- **No temporary build breaks**: task order is `ScheduledAt`+dispatch-gating → pure recurrence math → schedule schema/CRUD → schedule spawning wired into `Tick` → freeze schema/CRUD → freeze-aware `Tick` phases → API surface (scheduledAt param, then schedules CRUD, then freezes CRUD) → full verification, so every dependency exists before its first consumer; `go build ./...` stays green after every task.
