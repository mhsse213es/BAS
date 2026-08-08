# Scheduled Assessments Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let operators schedule recurring BAS scenario runs (posture or telemetry mode, never lab) against agent groups or explicit agents, built as a new job type on the existing Fleet Job Engine rather than a second scheduling system.

**Architecture:** Extends `internal/jobs`' existing `Schedule`/`Job` model (additive columns only — every existing `batch_remediation` schedule keeps working unmigrated) with recurrence types, live group-based targeting, and a per-schedule concurrency limit. A new `scheduled_assessment` job type dispatches through the exact per-agent path `RunScenario` already uses (`h.dispatchRun`), so nothing about scenario execution itself changes. Telemetry-mode schedules require a one-time, Admin-only, auditable standing authorization captured at creation; schedules are immutable — changing anything means cancel-and-recreate, which is always re-authorized by construction.

**Tech Stack:** Go, PostgreSQL (pgxpool), chi router — matches the existing orchestrator stack exactly, no new dependencies.

## Global Constraints

- Backend/API only — no UI page this sub-project (job-schedules has no dashboard UI today at all; a Scheduled Assessments page is an explicit, separate follow-on).
- Lab mode is permanently excluded from scheduling — not V1-deferred, never.
- No PUT/edit endpoint anywhere — schedules are immutable by design.
- No cron recurrence, no max-targets-per-run cap, no cooldown-between-runs (all explicitly deferred per the spec).
- Every new DB column on `job_schedules`/`jobs` must be additive (`ALTER TABLE ... ADD COLUMN IF NOT EXISTS`) so existing rows and the existing `CreateJobSchedule`/`batch_remediation` path are completely unaffected.
- Full spec at `docs/superpowers/specs/2026-08-08-scheduled-assessments-design.md` — read it if anything below is ambiguous.

---

### Task 1: Schema migration + Schedule/Job struct extensions

**Files:**
- Modify: `orchestrator/internal/db/postgres.go` (inside `EnsureSchema`, right after the existing `job_schedules` block, currently ending around line 1305 with `idx_job_schedules_enabled`)
- Modify: `orchestrator/internal/jobs/types.go` (`Schedule` and `Job` structs)
- Modify: `orchestrator/internal/jobs/schedule.go` (`scheduleColumns`, `scanSchedule`, `CreateSchedule`)
- Modify: `orchestrator/internal/jobs/store.go` (`Get`, and `CreateBatchScheduled` → new `CreateBatchWithConcurrency`)
- Test: `orchestrator/internal/jobs/schedule_test.go` (existing file — add to it)

**Interfaces:**
- Produces: `jobs.Schedule` gains `RecurrenceType string`, `RunAt *time.Time`, `DayOfMonth int`, `EndDate *time.Time`, `ConcurrencyLimit int`, `GroupIDs []int64`, `Mode string`, `ApprovedBy string`, `ApprovedAt *time.Time`, `ApprovalVersion int`, `Reason string`. `jobs.Job` gains `ConcurrencyLimit int`. `Store.CreateBatchWithConcurrency(ctx, jobType string, payload json.RawMessage, createdBy string, agentIDs []string, scheduledAt *time.Time, concurrencyLimit int) (Job, error)` — the new real implementation; `CreateBatchScheduled` becomes a thin wrapper calling it with `concurrencyLimit=0`, and `CreateBatch` is untouched (still wraps `CreateBatchScheduled`).
- Later tasks consume: Task 2 reads `Schedule.RecurrenceType`/`RunAt`/`DayOfMonth`/`EndDate`. Task 3 reads/writes `Schedule.GroupIDs`. Task 4 reads `Job.ConcurrencyLimit` and calls `CreateBatchWithConcurrency`. Task 6 sets all the new `Schedule` fields at creation time.

- [ ] **Step 1: Add the new columns to `EnsureSchema`**

In `orchestrator/internal/db/postgres.go`, find the existing block:
```go
`CREATE INDEX IF NOT EXISTS idx_job_schedules_enabled ON job_schedules (enabled) WHERE enabled = true`,
```
Immediately after it, add:
```go
// Scheduled Assessments extensions to job_schedules/jobs -- all additive,
// existing batch_remediation schedule rows are unaffected (new columns
// default to their zero value; recurrence_type='' aliases to the existing
// weekly behavior, see nextOccurrenceSince). See
// docs/superpowers/specs/2026-08-08-scheduled-assessments-design.md.
`ALTER TABLE job_schedules ADD COLUMN IF NOT EXISTS recurrence_type text NOT NULL DEFAULT ''`,
`ALTER TABLE job_schedules ADD COLUMN IF NOT EXISTS run_at timestamptz`,
`ALTER TABLE job_schedules ADD COLUMN IF NOT EXISTS day_of_month int NOT NULL DEFAULT 0`,
`ALTER TABLE job_schedules ADD COLUMN IF NOT EXISTS end_date timestamptz`,
`ALTER TABLE job_schedules ADD COLUMN IF NOT EXISTS concurrency_limit int NOT NULL DEFAULT 0`,
`ALTER TABLE job_schedules ADD COLUMN IF NOT EXISTS group_ids jsonb NOT NULL DEFAULT '[]'`,
`ALTER TABLE job_schedules ADD COLUMN IF NOT EXISTS mode text NOT NULL DEFAULT ''`,
`ALTER TABLE job_schedules ADD COLUMN IF NOT EXISTS approved_by text NOT NULL DEFAULT ''`,
`ALTER TABLE job_schedules ADD COLUMN IF NOT EXISTS approved_at timestamptz`,
`ALTER TABLE job_schedules ADD COLUMN IF NOT EXISTS approval_version int NOT NULL DEFAULT 0`,
`ALTER TABLE job_schedules ADD COLUMN IF NOT EXISTS reason text NOT NULL DEFAULT ''`,
`ALTER TABLE jobs ADD COLUMN IF NOT EXISTS concurrency_limit int NOT NULL DEFAULT 0`,
```

- [ ] **Step 2: Extend the `Schedule` and `Job` structs**

In `orchestrator/internal/jobs/types.go`, replace:
```go
// Job is one logical fleet-wide operation -- e.g. "apply remediation X to
// these N agents".
type Job struct {
	ID          string
	Type        string
	State       string
	Payload     json.RawMessage // type-specific, e.g. {"remediationId":"...","reason":"..."}
	CreatedBy   string
	CreatedAt   time.Time
	StartedAt   *time.Time
	CompletedAt *time.Time
	ScheduledAt *time.Time // nil = dispatch immediately; non-nil = don't dispatch before this
}
```
with:
```go
// Job is one logical fleet-wide operation -- e.g. "apply remediation X to
// these N agents".
type Job struct {
	ID               string
	Type             string
	State            string
	Payload          json.RawMessage // type-specific, e.g. {"remediationId":"...","reason":"..."}
	CreatedBy        string
	CreatedAt        time.Time
	StartedAt        *time.Time
	CompletedAt      *time.Time
	ScheduledAt      *time.Time // nil = dispatch immediately; non-nil = don't dispatch before this
	ConcurrencyLimit int        // 0 = unlimited; caps how many of this job's targets Tick() dispatches simultaneously
}
```

In the same file, find `Schedule` (in `schedule.go`, not `types.go` -- see next step) -- skip, `Schedule` lives in `schedule.go`.

- [ ] **Step 3: Extend the `Schedule` struct and its column list/scan/insert**

In `orchestrator/internal/jobs/schedule.go`, replace:
```go
// Schedule is a recurring template that spawns a fresh one-shot Job each
// weekly occurrence. It is not itself a Job -- it outlives any single
// spawned run.
type Schedule struct {
	ID               string
	Type             string
	Payload          json.RawMessage
	AgentIDs         []string
	DayOfWeek        int    // 0=Sunday .. 6=Saturday
	TimeOfDay        string // "23:00", 24h HH:MM
	Timezone         string // IANA name, e.g. "Asia/Kolkata"
	Enabled          bool
	CreatedBy        string
	CreatedAt        time.Time
	LastOccurrenceAt *time.Time
	LastSpawnedJobID string
}
```
with:
```go
// Schedule is a recurring template that spawns a fresh one-shot Job each
// occurrence. It is not itself a Job -- it outlives any single spawned run.
type Schedule struct {
	ID               string
	Type             string
	Payload          json.RawMessage
	AgentIDs         []string
	DayOfWeek        int    // 0=Sunday .. 6=Saturday -- used when RecurrenceType is "" (alias for "weekly") or "weekly"
	TimeOfDay        string // "23:00", 24h HH:MM -- used by every RecurrenceType except "once"
	Timezone         string // IANA name, e.g. "Asia/Kolkata"
	Enabled          bool
	CreatedBy        string
	CreatedAt        time.Time
	LastOccurrenceAt *time.Time
	LastSpawnedJobID string

	// RecurrenceType is "" (alias for "weekly", the original behavior) |
	// "once" | "daily" | "weekly" | "monthly". See nextOccurrenceSince.
	RecurrenceType string
	RunAt          *time.Time // for RecurrenceType=="once": the single absolute fire time
	DayOfMonth     int        // for RecurrenceType=="monthly": 1-28
	EndDate        *time.Time // nil = no end; no spawns once now is after this

	// ConcurrencyLimit is copied onto every Job this schedule spawns (see
	// Store.CreateBatchWithConcurrency).
	ConcurrencyLimit int

	// GroupIDs are agent_groups.id values -- resolved recursively (a group
	// and all its descendants) fresh at every spawn, unioned with AgentIDs.
	// See Store.ResolveGroupAgentIDs.
	GroupIDs []int64

	// Mode/ApprovedBy/ApprovedAt/ApprovalVersion/Reason are the Scheduled
	// Execution Authorization for scheduled_assessment schedules ("" for
	// other schedule types like batch_remediation). Mode is "posture" (no
	// authorization needed) or "telemetry" (requires the four fields below,
	// captured once at creation -- schedules are immutable, so this can
	// never go stale).
	Mode            string
	ApprovedBy      string
	ApprovedAt      *time.Time
	ApprovalVersion int
	Reason          string
}
```

Replace:
```go
const scheduleColumns = `id, type, payload, agent_ids, day_of_week, time_of_day, timezone, enabled, created_by, created_at, last_occurrence_at, last_spawned_job_id`
```
with:
```go
const scheduleColumns = `id, type, payload, agent_ids, day_of_week, time_of_day, timezone, enabled, created_by, created_at, last_occurrence_at, last_spawned_job_id, recurrence_type, run_at, day_of_month, end_date, concurrency_limit, group_ids, mode, approved_by, approved_at, approval_version, reason`
```

Replace:
```go
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
```
with:
```go
func scanSchedule(row interface {
	Scan(dest ...any) error
}) (Schedule, error) {
	var sch Schedule
	var agentIDsRaw, groupIDsRaw []byte
	err := row.Scan(&sch.ID, &sch.Type, &sch.Payload, &agentIDsRaw, &sch.DayOfWeek, &sch.TimeOfDay,
		&sch.Timezone, &sch.Enabled, &sch.CreatedBy, &sch.CreatedAt, &sch.LastOccurrenceAt, &sch.LastSpawnedJobID,
		&sch.RecurrenceType, &sch.RunAt, &sch.DayOfMonth, &sch.EndDate, &sch.ConcurrencyLimit, &groupIDsRaw,
		&sch.Mode, &sch.ApprovedBy, &sch.ApprovedAt, &sch.ApprovalVersion, &sch.Reason)
	if err != nil {
		return Schedule{}, err
	}
	if err := json.Unmarshal(agentIDsRaw, &sch.AgentIDs); err != nil {
		return Schedule{}, err
	}
	if err := json.Unmarshal(groupIDsRaw, &sch.GroupIDs); err != nil {
		return Schedule{}, err
	}
	return sch, nil
}
```

Replace:
```go
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
```
with:
```go
func (s *Store) CreateSchedule(ctx context.Context, sch Schedule) (Schedule, error) {
	agentIDsJSON, err := json.Marshal(sch.AgentIDs)
	if err != nil {
		return Schedule{}, err
	}
	groupIDsJSON, err := json.Marshal(sch.GroupIDs)
	if err != nil {
		return Schedule{}, err
	}
	var id string
	if err := s.pool.QueryRow(ctx,
		`INSERT INTO job_schedules (type, payload, agent_ids, day_of_week, time_of_day, timezone, enabled, created_by,
		    recurrence_type, run_at, day_of_month, end_date, concurrency_limit, group_ids, mode, approved_by, approved_at, approval_version, reason)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19) RETURNING id`,
		sch.Type, []byte(sch.Payload), agentIDsJSON, sch.DayOfWeek, sch.TimeOfDay, sch.Timezone, sch.Enabled, sch.CreatedBy,
		sch.RecurrenceType, sch.RunAt, sch.DayOfMonth, sch.EndDate, sch.ConcurrencyLimit, groupIDsJSON,
		sch.Mode, sch.ApprovedBy, sch.ApprovedAt, sch.ApprovalVersion, sch.Reason,
	).Scan(&id); err != nil {
		return Schedule{}, err
	}
	return s.GetSchedule(ctx, id)
}
```

- [ ] **Step 4: `Store.Get` reads the new `Job.ConcurrencyLimit` column, and `CreateBatchScheduled` gains a concurrency-aware sibling**

In `orchestrator/internal/jobs/store.go`, replace:
```go
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
with:
```go
func (s *Store) CreateBatch(ctx context.Context, jobType string, payload json.RawMessage, createdBy string, agentIDs []string) (Job, error) {
	return s.CreateBatchScheduled(ctx, jobType, payload, createdBy, agentIDs, nil)
}

// CreateBatchScheduled is CreateBatch with an optional future dispatch time.
func (s *Store) CreateBatchScheduled(ctx context.Context, jobType string, payload json.RawMessage, createdBy string, agentIDs []string, scheduledAt *time.Time) (Job, error) {
	return s.CreateBatchWithConcurrency(ctx, jobType, payload, createdBy, agentIDs, scheduledAt, 0)
}

// CreateBatchWithConcurrency is CreateBatchScheduled plus an optional
// per-job concurrency limit (0 = unlimited), read by Dispatcher.Tick's
// pending-dispatch loop to throttle how many of this job's targets run
// simultaneously. A single transaction so a job never exists with a
// partial target list.
func (s *Store) CreateBatchWithConcurrency(ctx context.Context, jobType string, payload json.RawMessage, createdBy string, agentIDs []string, scheduledAt *time.Time, concurrencyLimit int) (Job, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Job{}, err
	}
	defer tx.Rollback(ctx)

	var jobID string
	if err := tx.QueryRow(ctx,
		`INSERT INTO jobs (type, state, payload, created_by, scheduled_at, concurrency_limit) VALUES ($1,$2,$3,$4,$5,$6) RETURNING id`,
		jobType, JobStateRequested, []byte(payload), createdBy, scheduledAt, concurrencyLimit,
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
		`SELECT id, type, state, payload, created_by, created_at, started_at, completed_at, scheduled_at, concurrency_limit FROM jobs WHERE id=$1`, id,
	).Scan(&j.ID, &j.Type, &j.State, &j.Payload, &j.CreatedBy, &j.CreatedAt, &j.StartedAt, &j.CompletedAt, &j.ScheduledAt, &j.ConcurrencyLimit)
	return j, err
}
```

- [ ] **Step 5: Write a failing test for the round-trip**

In `orchestrator/internal/jobs/schedule_test.go` (append to the existing file):
```go
func TestCreateSchedule_RoundTripsScheduledAssessmentFields(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		store := NewStore(pool)
		runAt := time.Now().Add(48 * time.Hour).UTC().Truncate(time.Microsecond)
		created, err := store.CreateSchedule(context.Background(), Schedule{
			Type: "scheduled_assessment", Payload: json.RawMessage(`{}`), AgentIDs: []string{"sa-1"},
			GroupIDs: []int64{7, 8}, RecurrenceType: "once", RunAt: &runAt, Enabled: true,
			ConcurrencyLimit: 5, Mode: "telemetry", ApprovedBy: "admin-1", ApprovalVersion: 1, Reason: "test",
		})
		if err != nil {
			t.Fatalf("CreateSchedule: %v", err)
		}
		got, err := store.GetSchedule(context.Background(), created.ID)
		if err != nil {
			t.Fatalf("GetSchedule: %v", err)
		}
		if got.RecurrenceType != "once" || got.RunAt == nil || !got.RunAt.Equal(runAt) {
			t.Errorf("recurrence fields: got RecurrenceType=%q RunAt=%v, want once/%v", got.RecurrenceType, got.RunAt, runAt)
		}
		if len(got.GroupIDs) != 2 || got.GroupIDs[0] != 7 || got.GroupIDs[1] != 8 {
			t.Errorf("GroupIDs = %v, want [7 8]", got.GroupIDs)
		}
		if got.ConcurrencyLimit != 5 || got.Mode != "telemetry" || got.ApprovedBy != "admin-1" || got.ApprovalVersion != 1 || got.Reason != "test" {
			t.Errorf("got = %+v, want ConcurrencyLimit=5 Mode=telemetry ApprovedBy=admin-1 ApprovalVersion=1 Reason=test", got)
		}
	})
}
```

Note: `sharedDB` is this package's existing shared test-DB handle (used by every other test in this file) -- if `schedule_test.go` doesn't already import `"encoding/json"`/`"time"`/`"github.com/jackc/pgx/v5/pgxpool"`, add them.

- [ ] **Step 6: Run it to verify it fails first**

```bash
cd orchestrator
go test ./internal/jobs/... -run TestCreateSchedule_RoundTripsScheduledAssessmentFields -v
```
Expected: FAIL (compile error — the new struct fields don't exist yet if you run this before Steps 1-4, or a scan/column-count mismatch if the DB migration hasn't run). If you followed steps in order, Steps 1-4 already exist, so this actually verifies the happy path — that's fine, TDD's "see it fail first" is most valuable for genuinely new behavior; here Step 6 doubles as your first real verification. If it fails for an unexpected reason (not a missing-migration/missing-field reason), stop and investigate before continuing.

- [ ] **Step 7: Run the full `internal/jobs` package test suite**

```bash
go test ./internal/jobs/... -v
```
Expected: PASS, including every pre-existing test (confirms the new columns/struct fields didn't break anything already there).

- [ ] **Step 8: Commit**

```bash
git add internal/db/postgres.go internal/jobs/types.go internal/jobs/schedule.go internal/jobs/store.go internal/jobs/schedule_test.go
git commit -m "feat(jobs): extend Schedule/Job with Scheduled Assessments fields"
```

---

### Task 2: Recurrence engine — once/daily/weekly/monthly

**Files:**
- Modify: `orchestrator/internal/jobs/schedule.go` (`nextOccurrenceSince`)
- Test: `orchestrator/internal/jobs/schedule_test.go`

**Interfaces:**
- Consumes: `Schedule.RecurrenceType`/`RunAt`/`DayOfMonth`/`EndDate` (Task 1).
- Produces: `nextOccurrenceSince(sch Schedule, now time.Time) (occurrence time.Time, ok bool)` — same signature as before, now handling 5 cases (`""`, `"once"`, `"daily"`, `"weekly"`, `"monthly"`). Task 3's `spawnDueSchedules` calls this unchanged.

- [ ] **Step 1: Write failing tests for each new recurrence type**

Append to `orchestrator/internal/jobs/schedule_test.go` (these are pure functions, no DB needed — no `testing.Short()` skip):
```go
func TestNextOccurrenceSince_Once(t *testing.T) {
	loc, _ := time.LoadLocation("UTC")
	runAt := time.Date(2026, 8, 10, 2, 0, 0, 0, loc)
	sch := Schedule{RecurrenceType: "once", RunAt: &runAt, Timezone: "UTC", TimeOfDay: "00:00"}

	// Before RunAt: no occurrence yet.
	before := time.Date(2026, 8, 9, 0, 0, 0, 0, loc)
	if _, ok := nextOccurrenceSince(sch, before); ok {
		t.Error("before RunAt: got ok=true, want false")
	}

	// After RunAt, never spawned: fires exactly once.
	after := time.Date(2026, 8, 11, 0, 0, 0, 0, loc)
	occ, ok := nextOccurrenceSince(sch, after)
	if !ok || !occ.Equal(runAt) {
		t.Errorf("first check after RunAt: got occ=%v ok=%v, want %v/true", occ, ok, runAt)
	}

	// After it already spawned once: never fires again, regardless of now.
	spawned := runAt
	sch.LastOccurrenceAt = &spawned
	if _, ok := nextOccurrenceSince(sch, after.Add(24*time.Hour)); ok {
		t.Error("after already spawned: got ok=true, want false (once-only)")
	}
}

func TestNextOccurrenceSince_Daily(t *testing.T) {
	loc, _ := time.LoadLocation("UTC")
	sch := Schedule{RecurrenceType: "daily", TimeOfDay: "14:00", Timezone: "UTC"}

	now := time.Date(2026, 8, 10, 14, 5, 0, 0, loc) // 5 min past today's slot
	occ, ok := nextOccurrenceSince(sch, now)
	want := time.Date(2026, 8, 10, 14, 0, 0, 0, loc)
	if !ok || !occ.Equal(want) {
		t.Errorf("got occ=%v ok=%v, want %v/true", occ, ok, want)
	}

	// Already spawned today: no new occurrence until tomorrow.
	sch.LastOccurrenceAt = &occ
	if _, ok := nextOccurrenceSince(sch, now); ok {
		t.Error("same-day recheck after spawn: got ok=true, want false")
	}
	tomorrow := now.Add(24 * time.Hour)
	occ2, ok := nextOccurrenceSince(sch, tomorrow)
	wantTomorrow := time.Date(2026, 8, 11, 14, 0, 0, 0, loc)
	if !ok || !occ2.Equal(wantTomorrow) {
		t.Errorf("next day: got occ=%v ok=%v, want %v/true", occ2, ok, wantTomorrow)
	}
}

func TestNextOccurrenceSince_Weekly_EmptyRecurrenceTypeAliasesToWeekly(t *testing.T) {
	loc, _ := time.LoadLocation("UTC")
	// RecurrenceType left "" -- matches every pre-existing batch_remediation
	// schedule row, which must keep behaving exactly as before this change.
	sch := Schedule{RecurrenceType: "", DayOfWeek: 1, TimeOfDay: "09:00", Timezone: "UTC"} // Monday
	now := time.Date(2026, 8, 11, 9, 30, 0, 0, loc)                                        // a Tuesday, 9:30
	occ, ok := nextOccurrenceSince(sch, now)
	want := time.Date(2026, 8, 10, 9, 0, 0, 0, loc) // the Monday before
	if !ok || !occ.Equal(want) {
		t.Errorf("got occ=%v ok=%v, want %v/true", occ, ok, want)
	}
}

func TestNextOccurrenceSince_Monthly(t *testing.T) {
	loc, _ := time.LoadLocation("UTC")
	sch := Schedule{RecurrenceType: "monthly", DayOfMonth: 1, TimeOfDay: "03:00", Timezone: "UTC"}
	now := time.Date(2026, 8, 5, 0, 0, 0, 0, loc) // Aug 5, after Aug 1's slot
	occ, ok := nextOccurrenceSince(sch, now)
	want := time.Date(2026, 8, 1, 3, 0, 0, 0, loc)
	if !ok || !occ.Equal(want) {
		t.Errorf("got occ=%v ok=%v, want %v/true", occ, ok, want)
	}
}

func TestNextOccurrenceSince_EndDate_StopsSpawning(t *testing.T) {
	loc, _ := time.LoadLocation("UTC")
	ended := time.Date(2026, 8, 1, 0, 0, 0, 0, loc)
	sch := Schedule{RecurrenceType: "daily", TimeOfDay: "09:00", Timezone: "UTC", EndDate: &ended}
	now := time.Date(2026, 8, 10, 9, 30, 0, 0, loc) // well after EndDate
	if _, ok := nextOccurrenceSince(sch, now); ok {
		t.Error("after EndDate: got ok=true, want false")
	}
}
```

- [ ] **Step 2: Run to verify the new-type tests fail (weekly/empty-alias should already pass)**

```bash
go test ./internal/jobs/... -run TestNextOccurrenceSince -v
```
Expected: `TestNextOccurrenceSince_Once`, `_Daily`, `_Monthly`, `_EndDate_StopsSpawning` FAIL (RecurrenceType-based branches don't exist yet); `_Weekly_EmptyRecurrenceTypeAliasesToWeekly` PASSES already (it exercises the pre-existing behavior).

- [ ] **Step 3: Rewrite `nextOccurrenceSince`**

Replace the existing function in `orchestrator/internal/jobs/schedule.go`:
```go
// nextOccurrenceSince finds the most recent past occurrence of sch's
// recurrence slot in sch.Timezone, and reports whether it is newer than
// sch.LastOccurrenceAt. ok=false is the common case (nothing new since the
// last check). RecurrenceType=="" aliases to "weekly" so every schedule row
// created before this field existed keeps behaving identically.
func nextOccurrenceSince(sch Schedule, now time.Time) (occurrence time.Time, ok bool) {
	if sch.EndDate != nil && now.After(*sch.EndDate) {
		return time.Time{}, false
	}
	loc, err := time.LoadLocation(sch.Timezone)
	if err != nil {
		return time.Time{}, false
	}

	recType := sch.RecurrenceType
	if recType == "" {
		recType = "weekly"
	}

	switch recType {
	case "once":
		return nextOccurrenceOnce(sch, now, loc)
	case "daily":
		return nextOccurrenceDaily(sch, now, loc)
	case "weekly":
		return nextOccurrenceWeekly(sch, now, loc)
	case "monthly":
		return nextOccurrenceMonthly(sch, now, loc)
	default:
		return time.Time{}, false
	}
}

func nextOccurrenceOnce(sch Schedule, now time.Time, loc *time.Location) (time.Time, bool) {
	if sch.RunAt == nil || sch.LastOccurrenceAt != nil {
		return time.Time{}, false // no target time, or already spawned its one occurrence ever
	}
	candidate := sch.RunAt.In(loc)
	if candidate.After(now) {
		return time.Time{}, false
	}
	return candidate.UTC(), true
}

func nextOccurrenceDaily(sch Schedule, now time.Time, loc *time.Location) (time.Time, bool) {
	hh, mm, err := parseTimeOfDay(sch.TimeOfDay)
	if err != nil {
		return time.Time{}, false
	}
	nowLocal := now.In(loc)
	for daysBack := 0; daysBack < 2; daysBack++ {
		candidate := time.Date(nowLocal.Year(), nowLocal.Month(), nowLocal.Day()-daysBack, hh, mm, 0, 0, loc)
		if candidate.After(now) {
			continue
		}
		if sch.LastOccurrenceAt != nil && !candidate.After(*sch.LastOccurrenceAt) {
			return time.Time{}, false
		}
		return candidate.UTC(), true
	}
	return time.Time{}, false
}

func nextOccurrenceWeekly(sch Schedule, now time.Time, loc *time.Location) (time.Time, bool) {
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

func nextOccurrenceMonthly(sch Schedule, now time.Time, loc *time.Location) (time.Time, bool) {
	hh, mm, err := parseTimeOfDay(sch.TimeOfDay)
	if err != nil {
		return time.Time{}, false
	}
	nowLocal := now.In(loc)
	for monthsBack := 0; monthsBack < 2; monthsBack++ {
		// time.Date normalizes an out-of-range day (e.g. day 31 in a
		// 30-day month) by rolling into the next month -- the Day()
		// check below rejects that roll-over instead of misfiring in the
		// wrong month.
		candidate := time.Date(nowLocal.Year(), nowLocal.Month()-time.Month(monthsBack), sch.DayOfMonth, hh, mm, 0, 0, loc)
		if candidate.Day() != sch.DayOfMonth || candidate.After(now) {
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

- [ ] **Step 4: Run the tests again to verify they pass**

```bash
go test ./internal/jobs/... -run TestNextOccurrenceSince -v
```
Expected: all 5 PASS.

- [ ] **Step 5: Run the full `internal/jobs` suite**

```bash
go test ./internal/jobs/... -v
```
Expected: PASS, including `spawnDueSchedules`-adjacent tests in `dispatch_test.go` (they use weekly/empty `RecurrenceType`, unaffected).

- [ ] **Step 6: Commit**

```bash
git add internal/jobs/schedule.go internal/jobs/schedule_test.go
git commit -m "feat(jobs): once/daily/weekly/monthly recurrence for job schedules"
```

---

### Task 3: Live group-based target resolution

**Files:**
- Create: `orchestrator/internal/jobs/groups.go`
- Modify: `orchestrator/internal/jobs/dispatch.go` (`spawnDueSchedules`)
- Test: `orchestrator/internal/jobs/groups_test.go`

**Interfaces:**
- Consumes: `Schedule.GroupIDs []int64` (Task 1), the existing `agent_groups`/`agents` tables (schema already exists, from the Agent Group Hierarchy sub-project — not touched here).
- Produces: `Store.ResolveGroupAgentIDs(ctx context.Context, groupIDs []int64) ([]string, error)` — every distinct `agent_id` belonging to any of `groupIDs` or their descendant groups. `spawnDueSchedules` now unions this with `Schedule.AgentIDs` before spawning.

- [ ] **Step 1: Write the failing test**

Create `orchestrator/internal/jobs/groups_test.go`:
```go
package jobs

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestResolveGroupAgentIDs_RecursesIntoDescendantGroups(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		var parentID, childID int64
		if err := pool.QueryRow(context.Background(),
			`INSERT INTO agent_groups (name) VALUES ('Finance') RETURNING id`).Scan(&parentID); err != nil {
			t.Fatalf("insert parent group: %v", err)
		}
		if err := pool.QueryRow(context.Background(),
			`INSERT INTO agent_groups (name, parent_id) VALUES ('Finance-Servers', $1) RETURNING id`, parentID).Scan(&childID); err != nil {
			t.Fatalf("insert child group: %v", err)
		}
		mustExecJobs(t, pool, `INSERT INTO agents (agent_id, hostname, group_id) VALUES ('grp-direct', 'DIRECT-HOST', $1)`, parentID)
		mustExecJobs(t, pool, `INSERT INTO agents (agent_id, hostname, group_id) VALUES ('grp-nested', 'NESTED-HOST', $1)`, childID)
		mustExecJobs(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('grp-outside', 'OUTSIDE-HOST')`)

		store := NewStore(pool)
		got, err := store.ResolveGroupAgentIDs(context.Background(), []int64{parentID})
		if err != nil {
			t.Fatalf("ResolveGroupAgentIDs: %v", err)
		}
		want := map[string]bool{"grp-direct": true, "grp-nested": true}
		if len(got) != 2 {
			t.Fatalf("got %v, want exactly grp-direct and grp-nested", got)
		}
		for _, id := range got {
			if !want[id] {
				t.Errorf("unexpected agent %q in result", id)
			}
		}
	})
}

func TestResolveGroupAgentIDs_EmptyInput(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		store := NewStore(pool)
		got, err := store.ResolveGroupAgentIDs(context.Background(), nil)
		if err != nil {
			t.Fatalf("ResolveGroupAgentIDs: %v", err)
		}
		if len(got) != 0 {
			t.Errorf("got %v, want empty", got)
		}
	})
}

// mustExecJobs mirrors this package's other tests' pattern for one-off
// fixture inserts (parameterized, unlike the api package's mustExecAPI).
func mustExecJobs(t *testing.T, pool *pgxpool.Pool, sql string, args ...any) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), sql, args...); err != nil {
		t.Fatalf("exec %q: %v", sql, err)
	}
}
```

If `internal/jobs`'s existing tests already define a `mustExecJobs`-shaped helper (or a differently-named equivalent) in another `_test.go` file in this package, reuse that one instead of defining a second copy — check with:
```bash
grep -rn "func mustExec" orchestrator/internal/jobs/
```

- [ ] **Step 2: Run to verify it fails**

```bash
go test ./internal/jobs/... -run TestResolveGroupAgentIDs -v
```
Expected: FAIL — `store.ResolveGroupAgentIDs` doesn't exist yet (compile error).

- [ ] **Step 3: Implement `ResolveGroupAgentIDs`**

Create `orchestrator/internal/jobs/groups.go`:
```go
package jobs

import "context"

// ResolveGroupAgentIDs returns every distinct agent_id belonging to any of
// groupIDs or their descendant groups -- the same recursive membership rule
// GET /api/agents?groupId= already applies (selecting a parent group
// surfaces agents in its children too). Called fresh at every schedule
// spawn (see spawnDueSchedules), never cached, so group-membership changes
// are picked up automatically without editing the schedule. Empty input
// returns an empty, non-nil slice.
func (s *Store) ResolveGroupAgentIDs(ctx context.Context, groupIDs []int64) ([]string, error) {
	if len(groupIDs) == 0 {
		return []string{}, nil
	}
	rows, err := s.pool.Query(ctx,
		`WITH RECURSIVE descendants(id) AS (
			SELECT id FROM agent_groups WHERE id = ANY($1)
			UNION ALL
			SELECT gr.id FROM agent_groups gr JOIN descendants d ON gr.parent_id = d.id
		)
		SELECT DISTINCT agent_id FROM agents WHERE group_id IN (SELECT id FROM descendants)`,
		groupIDs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var agentID string
		if err := rows.Scan(&agentID); err != nil {
			return nil, err
		}
		out = append(out, agentID)
	}
	return out, rows.Err()
}
```

- [ ] **Step 4: Run to verify it passes**

```bash
go test ./internal/jobs/... -run TestResolveGroupAgentIDs -v
```
Expected: PASS.

- [ ] **Step 5: Wire group resolution into `spawnDueSchedules`**

In `orchestrator/internal/jobs/dispatch.go`, replace:
```go
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
with:
```go
		agentIDs := sch.AgentIDs
		if len(sch.GroupIDs) > 0 {
			groupAgentIDs, gerr := d.store.ResolveGroupAgentIDs(ctx, sch.GroupIDs)
			if gerr != nil {
				log.Printf("[jobs] schedule %s: group resolution failed: %v -- will retry next tick", sch.ID, gerr)
				continue
			}
			agentIDs = unionAgentIDs(sch.AgentIDs, groupAgentIDs)
		}
		if len(agentIDs) == 0 {
			log.Printf("[jobs] schedule %s: resolved to zero targets -- skipping occurrence %v", sch.ID, occurrence)
			d.store.MarkScheduleOccurrenceHandled(ctx, sch.ID, occurrence, "")
			continue
		}

		newJob, err := d.store.CreateBatchWithConcurrency(ctx, sch.Type, sch.Payload, sch.CreatedBy, agentIDs, nil, sch.ConcurrencyLimit)
		if err != nil {
			log.Printf("[jobs] schedule %s: spawn failed: %v -- will retry next tick", sch.ID, err)
			continue
		}
		d.store.MarkScheduleOccurrenceHandled(ctx, sch.ID, occurrence, newJob.ID)
		log.Printf("[jobs] schedule %s: spawned job %s for occurrence %v", sch.ID, newJob.ID, occurrence)
	}
}

// unionAgentIDs merges two agent-ID lists, deduping (an agent could be both
// explicitly listed and a member of a targeted group).
func unionAgentIDs(a, b []string) []string {
	seen := make(map[string]bool, len(a)+len(b))
	out := make([]string, 0, len(a)+len(b))
	for _, id := range a {
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	for _, id := range b {
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	return out
}
```

- [ ] **Step 6: Write a failing test for live resolution in `spawnDueSchedules`**

In `orchestrator/internal/jobs/dispatch_test.go` (existing file — check its exact test-setup pattern first, e.g. how it constructs a `Dispatcher`/`Store` and calls `Tick`, then match it):
```go
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
		mustExecJobs(t, pool, `INSERT INTO agents (agent_id, hostname, group_id) VALUES ('live-res-a1', 'A1', $1)`, groupID)

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
```

Check `orchestrator/internal/jobs/dispatch_test.go`'s existing imports/helpers before adding this — if `ListTargets` has a different name or `Dispatcher.SetDispatch`/`SetStatus` differ, match what's actually there rather than this draft.

- [ ] **Step 7: Run it, verify it fails first if you haven't done Step 5 yet, then passes after**

```bash
go test ./internal/jobs/... -run TestSpawnDueSchedules_ResolvesGroupMembershipLive -v
```
Expected: PASS (Step 5 already wired the resolution in).

- [ ] **Step 8: Run the full `internal/jobs` suite**

```bash
go test ./internal/jobs/... -v
```
Expected: PASS.

- [ ] **Step 9: Commit**

```bash
git add internal/jobs/groups.go internal/jobs/groups_test.go internal/jobs/dispatch.go internal/jobs/dispatch_test.go
git commit -m "feat(jobs): live group-based target resolution for job schedules"
```

---

### Task 4: Per-schedule concurrency limit in `Tick()`

**Files:**
- Modify: `orchestrator/internal/jobs/dispatch.go` (`Tick`)
- Test: `orchestrator/internal/jobs/dispatch_test.go`

**Interfaces:**
- Consumes: `Job.ConcurrencyLimit` (Task 1), `Store.ListActiveDispatchedTargets`/`ListPendingTargetsAcrossActiveJobs` (existing, unchanged signatures).
- Produces: no new exported interface — this changes `Tick`'s internal dispatch-selection behavior only. A `Job` with `ConcurrencyLimit=0` behaves exactly as before (unlimited).

- [ ] **Step 1: Write the failing test**

Append to `orchestrator/internal/jobs/dispatch_test.go`:
```go
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
			mustExecJobs(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ($1, $1) ON CONFLICT (agent_id) DO NOTHING`, id)
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
```

Check the exact fixture-insert pattern used elsewhere in `dispatch_test.go` for seeding agents (the `ON CONFLICT` clause above is defensive against a shared-agent-ID collision across tests in the same container — match whatever convention the file already uses).

- [ ] **Step 2: Run to verify it fails**

```bash
go test ./internal/jobs/... -run TestTick_RespectsPerJobConcurrencyLimit -v
```
Expected: FAIL — `dispatchCount` reaches 5, not 2 (no throttling yet).

- [ ] **Step 3: Implement the throttle in `Tick`**

In `orchestrator/internal/jobs/dispatch.go`, the current pending-dispatch section reads:
```go
	inFlight, err := d.store.ListActiveDispatchedTargets(ctx)
	if err != nil {
		return err
	}
	for _, t := range inFlight {
		job, err := jobOf(t.JobID)
		if err != nil {
			continue
		}
		state, errText, terminal := d.status(ctx, job.Type, t.RefID)
		if !terminal {
			continue
		}
		if err := d.store.MarkTargetTerminal(ctx, t.ID, state, errText); err != nil {
			continue
		}
		if state == TargetStateFailed && d.notify != nil {
			d.notify(ctx, NotifyEvent{
				Type: notifyTypeTargetFailed, JobID: t.JobID, TargetID: t.ID, AgentID: t.AgentID,
				Severity: notifySeverityError, Message: errText,
			})
		}
		touchedJobs[t.JobID] = true
	}
```
Replace it with (adds an in-flight-per-job counter, decremented as targets resolve):
```go
	inFlight, err := d.store.ListActiveDispatchedTargets(ctx)
	if err != nil {
		return err
	}
	inFlightByJob := map[string]int{}
	for _, t := range inFlight {
		inFlightByJob[t.JobID]++
	}
	for _, t := range inFlight {
		job, err := jobOf(t.JobID)
		if err != nil {
			continue
		}
		state, errText, terminal := d.status(ctx, job.Type, t.RefID)
		if !terminal {
			continue
		}
		if err := d.store.MarkTargetTerminal(ctx, t.ID, state, errText); err != nil {
			continue
		}
		inFlightByJob[t.JobID]-- // resolved -- frees a concurrency slot
		if state == TargetStateFailed && d.notify != nil {
			d.notify(ctx, NotifyEvent{
				Type: notifyTypeTargetFailed, JobID: t.JobID, TargetID: t.ID, AgentID: t.AgentID,
				Severity: notifySeverityError, Message: errText,
			})
		}
		touchedJobs[t.JobID] = true
	}
```

Then, still in `Tick`, the pending-target loop currently reads:
```go
	pending, err := d.store.ListPendingTargetsAcrossActiveJobs(ctx, jobDispatchBatchSize)
	if err != nil {
		return err
	}
	for _, t := range pending {
		job, err := jobOf(t.JobID)
		if err != nil {
			continue
		}
		if frozen, reason, ferr := d.store.IsAgentFrozen(ctx, t.AgentID); ferr == nil && frozen {
			d.store.MarkTargetDeferred(ctx, t.ID, reason)
			if d.notify != nil {
				d.notify(ctx, NotifyEvent{
					Type: notifyTypeTargetDeferred, JobID: t.JobID, TargetID: t.ID, AgentID: t.AgentID,
					Severity: notifySeverityWarning, Message: reason,
				})
			}
			touchedJobs[t.JobID] = true
			continue
		}
		refID, dispatchErr := d.dispatch(ctx, job, t)
		if dispatchErr != nil {
			d.store.MarkTargetTerminal(ctx, t.ID, TargetStateFailed, dispatchErr.Error())
			if d.notify != nil {
				d.notify(ctx, NotifyEvent{
					Type: notifyTypeTargetFailed, JobID: t.JobID, TargetID: t.ID, AgentID: t.AgentID,
					Severity: notifySeverityError, Message: dispatchErr.Error(),
				})
			}
		} else {
			d.store.MarkTargetDispatched(ctx, t.ID, refID)
		}
		touchedJobs[t.JobID] = true
	}
```
Replace it with (adds the concurrency check right after the job lookup, and increments the counter on a successful dispatch so later targets of the same job in the same tick see the updated count):
```go
	pending, err := d.store.ListPendingTargetsAcrossActiveJobs(ctx, jobDispatchBatchSize)
	if err != nil {
		return err
	}
	for _, t := range pending {
		job, err := jobOf(t.JobID)
		if err != nil {
			continue
		}
		if job.ConcurrencyLimit > 0 && inFlightByJob[job.ID] >= job.ConcurrencyLimit {
			continue // at this job's concurrency cap this tick -- stays pending, retried next tick
		}
		if frozen, reason, ferr := d.store.IsAgentFrozen(ctx, t.AgentID); ferr == nil && frozen {
			d.store.MarkTargetDeferred(ctx, t.ID, reason)
			if d.notify != nil {
				d.notify(ctx, NotifyEvent{
					Type: notifyTypeTargetDeferred, JobID: t.JobID, TargetID: t.ID, AgentID: t.AgentID,
					Severity: notifySeverityWarning, Message: reason,
				})
			}
			touchedJobs[t.JobID] = true
			continue
		}
		refID, dispatchErr := d.dispatch(ctx, job, t)
		if dispatchErr != nil {
			d.store.MarkTargetTerminal(ctx, t.ID, TargetStateFailed, dispatchErr.Error())
			if d.notify != nil {
				d.notify(ctx, NotifyEvent{
					Type: notifyTypeTargetFailed, JobID: t.JobID, TargetID: t.ID, AgentID: t.AgentID,
					Severity: notifySeverityError, Message: dispatchErr.Error(),
				})
			}
		} else {
			d.store.MarkTargetDispatched(ctx, t.ID, refID)
			inFlightByJob[job.ID]++ // just went in flight -- counts against this same job's later targets this tick
		}
		touchedJobs[t.JobID] = true
	}
```

- [ ] **Step 4: Run to verify it passes**

```bash
go test ./internal/jobs/... -run TestTick_RespectsPerJobConcurrencyLimit -v
```
Expected: PASS.

- [ ] **Step 5: Run the full `internal/jobs` suite**

```bash
go test ./internal/jobs/... -v
```
Expected: PASS, including every pre-existing `Tick`-related test (jobs with `ConcurrencyLimit=0` are completely unaffected by this change).

- [ ] **Step 6: Commit**

```bash
git add internal/jobs/dispatch.go internal/jobs/dispatch_test.go
git commit -m "feat(jobs): per-job concurrency limit in Tick's dispatch loop"
```

---

### Task 5: `scheduled_assessment` job type — dispatch and status

**Files:**
- Create: `orchestrator/internal/api/scheduled_assessment_dispatch.go`
- Modify: `orchestrator/internal/api/job_dispatch.go` (`dispatchJobTarget`, `statusForJobTarget` switches)
- Test: `orchestrator/internal/api/scheduled_assessment_dispatch_test.go`

**Interfaces:**
- Consumes: `h.engine.Get(id) (*scenario.Scenario, bool)`, `h.dispatchRun(ctx, sc *scenario.Scenario, agentID string, o dispatchOpts) (runID, skipReason string, err error)` (both existing, unchanged — `dispatchRun` is `handlers.go`'s shared per-agent dispatch core, already used by both `RunScenario` and campaign fan-out), `withinWindow(spec string, now time.Time) (bool, error)` (existing, `handlers.go:2704`).
- Produces: `scheduledAssessmentPayload{ScenarioID, Mode, Techniques, Steps}` (the `Job.Payload` shape for `Type="scheduled_assessment"`) — Task 6's create-schedule handler builds this. `dispatchJobTarget`/`statusForJobTarget` gain a `"scheduled_assessment"` case.

- [ ] **Step 1: Write the failing test**

Create `orchestrator/internal/api/scheduled_assessment_dispatch_test.go`:
```go
package api

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/jobs"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

func TestDispatchScheduledAssessmentTarget_PostureMode_CreatesScenarioRun(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname, os_version) VALUES ('sa-disp-1', 'SA-DISP-HOST', 'windows')`)

		eng := scenario.NewEngine(t.TempDir())
		registerFixtureScenario(t, eng, "fixture-check")
		h := New(pool, ws.NewHub(), eng, "")

		payload, _ := json.Marshal(scheduledAssessmentPayload{ScenarioID: "fixture-scenario", Mode: "posture"})
		job := jobs.Job{ID: "job-1", Type: "scheduled_assessment", CreatedBy: "sched-1", Payload: payload}
		target := jobs.JobTarget{ID: "target-1", JobID: "job-1", AgentID: "sa-disp-1"}

		runID, err := h.dispatchScheduledAssessmentTarget(context.Background(), job, target)
		if err != nil {
			t.Fatalf("dispatchScheduledAssessmentTarget: %v", err)
		}
		if runID == "" {
			t.Fatal("got empty runID")
		}

		var scenarioID, agentID, status string
		if err := pool.QueryRow(context.Background(),
			`SELECT scenario_id, agent_id, status FROM scenario_runs WHERE id=$1`, runID,
		).Scan(&scenarioID, &agentID, &status); err != nil {
			t.Fatalf("query scenario_runs: %v", err)
		}
		if scenarioID != "fixture-scenario" || agentID != "sa-disp-1" {
			t.Errorf("scenario_runs row: scenarioId=%q agentId=%q, want fixture-scenario/sa-disp-1", scenarioID, agentID)
		}

		state, _, terminal := h.scheduledAssessmentTargetStatus(context.Background(), "scheduled_assessment", runID)
		if terminal {
			t.Errorf("status: terminal = true immediately after dispatch, want false (run just started)")
		}
		if state != jobs.TargetStateDispatched {
			t.Errorf("status: state = %q, want %q", state, jobs.TargetStateDispatched)
		}
	})
}

func TestDispatchScheduledAssessmentTarget_UnknownScenario_Errors(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		payload, _ := json.Marshal(scheduledAssessmentPayload{ScenarioID: "does-not-exist", Mode: "posture"})
		job := jobs.Job{ID: "job-2", Type: "scheduled_assessment", Payload: payload}
		target := jobs.JobTarget{ID: "target-2", JobID: "job-2", AgentID: "no-such-agent"}

		if _, err := h.dispatchScheduledAssessmentTarget(context.Background(), job, target); err == nil {
			t.Error("got nil error for an unknown scenarioId, want an error")
		}
	})
}
```

`registerFixtureScenario` is the existing helper in `internal/api/remediation_continuation_test.go` (same package, no import needed) — it registers a `LocalCheck: true` scenario, which is the posture-mode path `dispatchRun` takes (no live/OS-compat complications for this first test).

- [ ] **Step 2: Run to verify it fails**

```bash
cd orchestrator
go test ./internal/api/... -run TestDispatchScheduledAssessmentTarget -v
```
Expected: FAIL — compile error, `dispatchScheduledAssessmentTarget`/`scheduledAssessmentTargetStatus`/`scheduledAssessmentPayload` don't exist yet.

- [ ] **Step 3: Implement the dispatch and status functions**

Create `orchestrator/internal/api/scheduled_assessment_dispatch.go`:
```go
package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/audspect/bas/internal/jobs"
)

// scheduledAssessmentPayload is the Job.Payload shape for
// Type="scheduled_assessment". Mode is always "posture" or "telemetry" --
// lab mode is rejected at schedule-creation time (see
// CreateScheduledAssessment), so it can never reach this dispatch function.
type scheduledAssessmentPayload struct {
	ScenarioID string   `json:"scenarioId"`
	Mode       string   `json:"mode"`
	Techniques []string `json:"techniques,omitempty"`
	Steps      []int    `json:"steps,omitempty"`
}

// dispatchScheduledAssessmentTarget is injected into jobs.Dispatcher via
// SetDispatch (see WithJobsDispatcher). It reuses dispatchRun -- the exact
// per-agent dispatch core RunScenario and campaign fan-out already share --
// so a scheduled assessment's actual execution is indistinguishable from an
// interactive run. The one guard dispatchRun does NOT itself apply (it's
// only checked in RunScenario, its HTTP caller) is the scenario's live
// execution-window policy; replicated here so telemetry-mode scheduled runs
// respect it exactly like an interactive telemetry run would.
func (h *Handler) dispatchScheduledAssessmentTarget(ctx context.Context, job jobs.Job, target jobs.JobTarget) (refID string, err error) {
	var payload scheduledAssessmentPayload
	if err := json.Unmarshal(job.Payload, &payload); err != nil {
		return "", err
	}
	sc, ok := h.engine.Get(payload.ScenarioID)
	if !ok {
		return "", errors.New("scenario not found")
	}

	live := payload.Mode == "telemetry"
	if live && sc.LivePolicy != nil && sc.LivePolicy.ExecutionWindow != "" {
		within, werr := withinWindow(sc.LivePolicy.ExecutionWindow, time.Now())
		if werr != nil {
			return "", fmt.Errorf("invalid execution_window in scenario policy: %w", werr)
		}
		if !within {
			return "", errors.New("outside the approved execution window for live execution")
		}
	}

	createdBy := job.CreatedBy
	runID, skip, dispatchErr := h.dispatchRun(ctx, sc, target.AgentID, dispatchOpts{
		Mode: payload.Mode, ConfirmLive: live, Techniques: payload.Techniques, Steps: payload.Steps,
		InitiatedBy: &createdBy, RunLabel: "Scheduled: " + sc.Name,
	})
	if dispatchErr != nil {
		return "", dispatchErr
	}
	if skip != "" {
		return "", errors.New(skip)
	}
	return runID, nil
}

// scheduledAssessmentTargetStatus is injected into jobs.Dispatcher via
// SetStatus. It polls the scenario_runs row created for this target
// (refID) -- same poll-by-refID shape as batchRemediationTargetStatus.
func (h *Handler) scheduledAssessmentTargetStatus(ctx context.Context, jobType, refID string) (state string, errText string, terminal bool) {
	var status string
	if err := h.db.QueryRow(ctx, `SELECT status FROM scenario_runs WHERE id=$1`, refID).Scan(&status); err != nil {
		return jobs.TargetStateFailed, "scenario run not found: " + err.Error(), true
	}
	switch status {
	case "completed":
		return jobs.TargetStateCompleted, "", true
	case "failed", "partial":
		return jobs.TargetStateFailed, "", true
	default: // "running"
		return jobs.TargetStateDispatched, "", false
	}
}
```

- [ ] **Step 4: Register the new job type in the dispatch/status switches**

In `orchestrator/internal/api/job_dispatch.go`, replace:
```go
func (h *Handler) dispatchJobTarget(ctx context.Context, job jobs.Job, target jobs.JobTarget) (refID string, err error) {
	switch job.Type {
	case "batch_remediation":
		return h.dispatchBatchRemediationTarget(ctx, job, target)
	case "bas_revalidation":
		return h.dispatchBasRevalidationTarget(ctx, job, target)
	default:
		return "", fmt.Errorf("unknown job type %q", job.Type)
	}
}

// statusForJobTarget mirrors dispatchJobTarget's routing for status polling.
func (h *Handler) statusForJobTarget(ctx context.Context, jobType, refID string) (state string, errText string, terminal bool) {
	switch jobType {
	case "batch_remediation":
		return h.batchRemediationTargetStatus(ctx, jobType, refID)
	case "bas_revalidation":
		return h.basRevalidationTargetStatus(ctx, jobType, refID)
	default:
		return jobs.TargetStateFailed, "unknown job type", true
	}
}
```
with:
```go
func (h *Handler) dispatchJobTarget(ctx context.Context, job jobs.Job, target jobs.JobTarget) (refID string, err error) {
	switch job.Type {
	case "batch_remediation":
		return h.dispatchBatchRemediationTarget(ctx, job, target)
	case "bas_revalidation":
		return h.dispatchBasRevalidationTarget(ctx, job, target)
	case "scheduled_assessment":
		return h.dispatchScheduledAssessmentTarget(ctx, job, target)
	default:
		return "", fmt.Errorf("unknown job type %q", job.Type)
	}
}

// statusForJobTarget mirrors dispatchJobTarget's routing for status polling.
func (h *Handler) statusForJobTarget(ctx context.Context, jobType, refID string) (state string, errText string, terminal bool) {
	switch jobType {
	case "batch_remediation":
		return h.batchRemediationTargetStatus(ctx, jobType, refID)
	case "bas_revalidation":
		return h.basRevalidationTargetStatus(ctx, jobType, refID)
	case "scheduled_assessment":
		return h.scheduledAssessmentTargetStatus(ctx, jobType, refID)
	default:
		return jobs.TargetStateFailed, "unknown job type", true
	}
}
```

- [ ] **Step 5: Run the tests to verify they pass**

```bash
go test ./internal/api/... -run TestDispatchScheduledAssessmentTarget -v
```
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/api/scheduled_assessment_dispatch.go internal/api/scheduled_assessment_dispatch_test.go internal/api/job_dispatch.go
git commit -m "feat(api): scheduled_assessment job type, dispatching through the existing per-agent run path"
```

---

### Task 6: API endpoints, routes, RBAC matrix, full verification

**Files:**
- Create: `orchestrator/internal/api/scheduled_assessment_handlers.go`
- Modify: `orchestrator/internal/api/routes.go`
- Modify: `orchestrator/internal/api/rbac_matrix_test.go`
- Test: `orchestrator/internal/api/scheduled_assessment_handlers_test.go`

**Interfaces:**
- Consumes: `jobs.Schedule` (all fields, Task 1), `h.engine.Get`, `h.jobsStore` (existing `Handler` field), `auth.ClaimsFrom`/`auth.HasPermission`/`auth.CanExecuteRemediation`/`auth.CanApproveRemediation` (all existing), `parseTimeOfDayForAPI` (existing, `schedule_handlers.go`), `scheduledAssessmentPayload` (Task 5).
- Produces: `Handler.CreateScheduledAssessment`, `Handler.ListScheduledAssessments`, `Handler.CancelScheduledAssessment` — the 3 route handlers.

- [ ] **Step 1: Write the failing tests**

Create `orchestrator/internal/api/scheduled_assessment_handlers_test.go`:
```go
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
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

func TestCreateScheduledAssessment_Posture_AnalystAllowed(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		eng := scenario.NewEngine(t.TempDir())
		registerFixtureScenario(t, eng, "fixture-check")
		jobsStore := jobs.NewStore(pool)
		h := New(pool, ws.NewHub(), eng, "").WithJobsDispatcher(jobsStore, jobs.NewDispatcher(jobsStore))

		body, _ := json.Marshal(map[string]any{
			"scenarioId": "fixture-scenario", "mode": "posture", "agentIds": []string{"sa-h1"},
			"recurrenceType": "weekly", "dayOfWeek": 1, "timeOfDay": "02:00", "timezone": "UTC",
		})
		req := httptest.NewRequest(http.MethodPost, "/x", bytes.NewReader(body))
		req = req.WithContext(auth.ContextWithClaims(req.Context(), &auth.Claims{UserID: "analyst-1", Role: auth.RoleAnalyst}))
		w := httptest.NewRecorder()
		h.CreateScheduledAssessment(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
		}
		var resp struct {
			ScheduleID string `json:"scheduleId"`
		}
		json.Unmarshal(w.Body.Bytes(), &resp)
		got, err := jobsStore.GetSchedule(context.Background(), resp.ScheduleID)
		if err != nil {
			t.Fatalf("GetSchedule: %v", err)
		}
		if got.Mode != "posture" || got.ApprovedBy != "" || got.ApprovalVersion != 0 {
			t.Errorf("posture schedule should have no authorization captured, got Mode=%q ApprovedBy=%q ApprovalVersion=%d", got.Mode, got.ApprovedBy, got.ApprovalVersion)
		}
	})
}

func TestCreateScheduledAssessment_Telemetry_AnalystForbidden(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		eng := scenario.NewEngine(t.TempDir())
		registerFixtureScenario(t, eng, "fixture-check")
		jobsStore := jobs.NewStore(pool)
		h := New(pool, ws.NewHub(), eng, "").WithJobsDispatcher(jobsStore, jobs.NewDispatcher(jobsStore))

		body, _ := json.Marshal(map[string]any{
			"scenarioId": "fixture-scenario", "mode": "telemetry", "agentIds": []string{"sa-h2"},
			"recurrenceType": "daily", "timeOfDay": "02:00", "timezone": "UTC", "reason": "test",
		})
		req := httptest.NewRequest(http.MethodPost, "/x", bytes.NewReader(body))
		req = req.WithContext(auth.ContextWithClaims(req.Context(), &auth.Claims{UserID: "analyst-1", Role: auth.RoleAnalyst}))
		w := httptest.NewRecorder()
		h.CreateScheduledAssessment(w, req)
		if w.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403, body = %s", w.Code, w.Body.String())
		}
	})
}

func TestCreateScheduledAssessment_Telemetry_AdminWithReason_CapturesAuthorization(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		eng := scenario.NewEngine(t.TempDir())
		registerFixtureScenario(t, eng, "fixture-check")
		jobsStore := jobs.NewStore(pool)
		h := New(pool, ws.NewHub(), eng, "").WithJobsDispatcher(jobsStore, jobs.NewDispatcher(jobsStore))

		body, _ := json.Marshal(map[string]any{
			"scenarioId": "fixture-scenario", "mode": "telemetry", "agentIds": []string{"sa-h3"},
			"recurrenceType": "daily", "timeOfDay": "02:00", "timezone": "UTC",
			"reason": "quarterly detection validation, approved by CISO",
		})
		req := httptest.NewRequest(http.MethodPost, "/x", bytes.NewReader(body))
		req = req.WithContext(auth.ContextWithClaims(req.Context(), &auth.Claims{UserID: "admin-1", Role: auth.RoleAdmin}))
		w := httptest.NewRecorder()
		h.CreateScheduledAssessment(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
		}
		var resp struct {
			ScheduleID string `json:"scheduleId"`
		}
		json.Unmarshal(w.Body.Bytes(), &resp)
		got, err := jobsStore.GetSchedule(context.Background(), resp.ScheduleID)
		if err != nil {
			t.Fatalf("GetSchedule: %v", err)
		}
		if got.ApprovedBy != "admin-1" || got.ApprovalVersion != 1 || got.ApprovedAt == nil || got.Reason == "" {
			t.Errorf("got = %+v, want ApprovedBy=admin-1 ApprovalVersion=1 ApprovedAt=non-nil Reason=non-empty", got)
		}
	})
}

func TestCreateScheduledAssessment_TelemetryWithoutReason_BadRequest(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		eng := scenario.NewEngine(t.TempDir())
		registerFixtureScenario(t, eng, "fixture-check")
		jobsStore := jobs.NewStore(pool)
		h := New(pool, ws.NewHub(), eng, "").WithJobsDispatcher(jobsStore, jobs.NewDispatcher(jobsStore))

		body, _ := json.Marshal(map[string]any{
			"scenarioId": "fixture-scenario", "mode": "telemetry", "agentIds": []string{"sa-h4"},
			"recurrenceType": "daily", "timeOfDay": "02:00", "timezone": "UTC",
		})
		req := httptest.NewRequest(http.MethodPost, "/x", bytes.NewReader(body))
		req = req.WithContext(auth.ContextWithClaims(req.Context(), &auth.Claims{UserID: "admin-1", Role: auth.RoleAdmin}))
		w := httptest.NewRecorder()
		h.CreateScheduledAssessment(w, req)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400, body = %s", w.Code, w.Body.String())
		}
	})
}

func TestCreateScheduledAssessment_LabMode_Rejected(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		eng := scenario.NewEngine(t.TempDir())
		registerFixtureScenario(t, eng, "fixture-check")
		jobsStore := jobs.NewStore(pool)
		h := New(pool, ws.NewHub(), eng, "").WithJobsDispatcher(jobsStore, jobs.NewDispatcher(jobsStore))

		body, _ := json.Marshal(map[string]any{
			"scenarioId": "fixture-scenario", "mode": "lab", "agentIds": []string{"sa-h5"},
			"recurrenceType": "daily", "timeOfDay": "02:00", "timezone": "UTC",
		})
		req := httptest.NewRequest(http.MethodPost, "/x", bytes.NewReader(body))
		req = req.WithContext(auth.ContextWithClaims(req.Context(), &auth.Claims{UserID: "admin-1", Role: auth.RoleAdmin}))
		w := httptest.NewRecorder()
		h.CreateScheduledAssessment(w, req)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400 (lab mode must never be schedulable), body = %s", w.Code, w.Body.String())
		}
	})
}

func TestListScheduledAssessments_OnlyReturnsScheduledAssessmentType(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		jobsStore := jobs.NewStore(pool)
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "").WithJobsDispatcher(jobsStore, jobs.NewDispatcher(jobsStore))

		if _, err := jobsStore.CreateSchedule(context.Background(), jobs.Schedule{
			Type: "batch_remediation", Payload: json.RawMessage(`{}`), AgentIDs: []string{"x"},
			DayOfWeek: 1, TimeOfDay: "02:00", Timezone: "UTC", Enabled: true,
		}); err != nil {
			t.Fatalf("seed batch_remediation schedule: %v", err)
		}
		if _, err := jobsStore.CreateSchedule(context.Background(), jobs.Schedule{
			Type: "scheduled_assessment", Payload: json.RawMessage(`{}`), AgentIDs: []string{"y"},
			RecurrenceType: "daily", TimeOfDay: "02:00", Timezone: "UTC", Enabled: true, Mode: "posture",
		}); err != nil {
			t.Fatalf("seed scheduled_assessment schedule: %v", err)
		}

		req := httptest.NewRequest(http.MethodGet, "/x", nil)
		w := httptest.NewRecorder()
		h.ListScheduledAssessments(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
		}
		var resp struct {
			Schedules []jobs.Schedule `json:"schedules"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		for _, sch := range resp.Schedules {
			if sch.Type != "scheduled_assessment" {
				t.Errorf("got a %q schedule in the list, want only scheduled_assessment", sch.Type)
			}
		}
		if len(resp.Schedules) < 1 {
			t.Error("expected at least the one scheduled_assessment schedule seeded above")
		}
	})
}

func TestCancelScheduledAssessment_Disables(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		jobsStore := jobs.NewStore(pool)
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "").WithJobsDispatcher(jobsStore, jobs.NewDispatcher(jobsStore))

		sch, err := jobsStore.CreateSchedule(context.Background(), jobs.Schedule{
			Type: "scheduled_assessment", Payload: json.RawMessage(`{}`), AgentIDs: []string{"z"},
			RecurrenceType: "daily", TimeOfDay: "02:00", Timezone: "UTC", Enabled: true, Mode: "posture",
		})
		if err != nil {
			t.Fatalf("CreateSchedule: %v", err)
		}

		req := httptest.NewRequest(http.MethodPost, "/x", nil)
		req = withURLParam(req, "id", sch.ID)
		w := httptest.NewRecorder()
		h.CancelScheduledAssessment(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
		}
		got, err := jobsStore.GetSchedule(context.Background(), sch.ID)
		if err != nil {
			t.Fatalf("GetSchedule: %v", err)
		}
		if got.Enabled {
			t.Error("schedule still enabled after cancel")
		}
	})
}
```

Check `withURLParam`'s exact signature in this package (used elsewhere for chi URL params in direct-handler tests, e.g. `freeze_handlers_test.go`) before relying on it as written above.

- [ ] **Step 2: Run to verify they fail**

```bash
go test ./internal/api/... -run TestCreateScheduledAssessment -run TestListScheduledAssessments -run TestCancelScheduledAssessment -v
```
Expected: FAIL — compile error, the 3 handlers don't exist yet.

- [ ] **Step 3: Implement the 3 handlers**

Create `orchestrator/internal/api/scheduled_assessment_handlers.go`:
```go
package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/jobs"
)

// POST /api/scheduled-assessments
// Mode-conditional permission: posture needs CanExecuteRemediation (the
// same tier as batch remediation); telemetry needs CanApproveRemediation
// (Admin-only) PLUS a non-empty reason -- together these ARE the Scheduled
// Execution Authorization (see the design spec's "Execution mode and
// authorization" section). Lab mode is rejected outright: it can never be
// scheduled. Schedules are immutable -- there is no update endpoint;
// changing anything means cancelling this one and creating a new one,
// which is always freshly authorized by construction.
func (h *Handler) CreateScheduledAssessment(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ScenarioID       string     `json:"scenarioId"`
		Mode             string     `json:"mode"`
		Techniques       []string   `json:"techniques"`
		Steps            []int      `json:"steps"`
		AgentIDs         []string   `json:"agentIds"`
		GroupIDs         []int64    `json:"groupIds"`
		RecurrenceType   string     `json:"recurrenceType"`
		RunAt            *time.Time `json:"runAt"`
		DayOfWeek        int        `json:"dayOfWeek"`
		DayOfMonth       int        `json:"dayOfMonth"`
		TimeOfDay        string     `json:"timeOfDay"`
		Timezone         string     `json:"timezone"`
		EndDate          *time.Time `json:"endDate"`
		ConcurrencyLimit int        `json:"concurrencyLimit"`
		Reason           string     `json:"reason"`
	}
	if json.NewDecoder(r.Body).Decode(&req) != nil || req.ScenarioID == "" {
		jsonError(w, "scenarioId is required", http.StatusBadRequest)
		return
	}
	if req.Mode != "posture" && req.Mode != "telemetry" {
		jsonError(w, "mode must be posture or telemetry -- lab mode cannot be scheduled", http.StatusBadRequest)
		return
	}
	if len(req.AgentIDs) == 0 && len(req.GroupIDs) == 0 {
		jsonError(w, "at least one agentId or groupId is required", http.StatusBadRequest)
		return
	}
	switch req.RecurrenceType {
	case "once":
		if req.RunAt == nil {
			jsonError(w, "runAt is required for a once schedule", http.StatusBadRequest)
			return
		}
	case "daily":
		if _, _, err := parseTimeOfDayForAPI(req.TimeOfDay); err != nil {
			jsonError(w, "timeOfDay must be HH:MM (24h)", http.StatusBadRequest)
			return
		}
	case "weekly":
		if req.DayOfWeek < 0 || req.DayOfWeek > 6 {
			jsonError(w, "dayOfWeek must be 0-6", http.StatusBadRequest)
			return
		}
		if _, _, err := parseTimeOfDayForAPI(req.TimeOfDay); err != nil {
			jsonError(w, "timeOfDay must be HH:MM (24h)", http.StatusBadRequest)
			return
		}
	case "monthly":
		if req.DayOfMonth < 1 || req.DayOfMonth > 28 {
			jsonError(w, "dayOfMonth must be 1-28 (29-31 excluded -- not every month has them)", http.StatusBadRequest)
			return
		}
		if _, _, err := parseTimeOfDayForAPI(req.TimeOfDay); err != nil {
			jsonError(w, "timeOfDay must be HH:MM (24h)", http.StatusBadRequest)
			return
		}
	default:
		jsonError(w, "recurrenceType must be once, daily, weekly, or monthly", http.StatusBadRequest)
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
	if h.engine == nil {
		jsonError(w, "scenario engine not loaded", http.StatusServiceUnavailable)
		return
	}
	if _, ok := h.engine.Get(req.ScenarioID); !ok {
		jsonError(w, "scenario not found", http.StatusNotFound)
		return
	}
	if h.jobsStore == nil {
		jsonError(w, "job engine not loaded", http.StatusServiceUnavailable)
		return
	}

	claims, _ := auth.ClaimsFrom(r.Context())
	var approvedBy string
	var approvedAt *time.Time
	approvalVersion := 0
	if req.Mode == "telemetry" {
		if claims == nil || !auth.HasPermission(claims.Role, auth.CanApproveRemediation) {
			jsonError(w, "scheduling a telemetry-mode assessment requires an Administrator's standing authorization", http.StatusForbidden)
			return
		}
		if req.Reason == "" {
			jsonError(w, "reason is required to authorize a telemetry-mode schedule", http.StatusBadRequest)
			return
		}
		now := time.Now()
		approvedAt = &now
		approvalVersion = 1
		approvedBy = claims.UserID
	}

	actorID := ""
	if claims != nil {
		actorID = claims.UserID
	}

	payload, err := json.Marshal(scheduledAssessmentPayload{
		ScenarioID: req.ScenarioID, Mode: req.Mode, Techniques: req.Techniques, Steps: req.Steps,
	})
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	sch, err := h.jobsStore.CreateSchedule(r.Context(), jobs.Schedule{
		Type: "scheduled_assessment", Payload: payload, AgentIDs: req.AgentIDs, GroupIDs: req.GroupIDs,
		RecurrenceType: req.RecurrenceType, RunAt: req.RunAt, DayOfWeek: req.DayOfWeek, DayOfMonth: req.DayOfMonth,
		TimeOfDay: req.TimeOfDay, Timezone: tz, EndDate: req.EndDate, ConcurrencyLimit: req.ConcurrencyLimit,
		Enabled: true, CreatedBy: actorID, Mode: req.Mode, ApprovedBy: approvedBy, ApprovedAt: approvedAt,
		ApprovalVersion: approvalVersion, Reason: req.Reason,
	})
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.auditLog(r, "jobs.schedule.create", sch.ID, map[string]any{
		"scenarioId": req.ScenarioID, "mode": req.Mode, "recurrenceType": req.RecurrenceType,
		"agentCount": len(req.AgentIDs), "groupCount": len(req.GroupIDs), "approvedBy": approvedBy,
	}, "created")
	respond(w, map[string]any{"scheduleId": sch.ID})
}

// GET /api/scheduled-assessments
func (h *Handler) ListScheduledAssessments(w http.ResponseWriter, r *http.Request) {
	if h.jobsStore == nil {
		jsonError(w, "job engine not loaded", http.StatusServiceUnavailable)
		return
	}
	all, err := h.jobsStore.ListSchedules(r.Context())
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	out := make([]jobs.Schedule, 0, len(all))
	for _, sch := range all {
		if sch.Type == "scheduled_assessment" {
			out = append(out, sch)
		}
	}
	respond(w, map[string]any{"schedules": out})
}

// POST /api/scheduled-assessments/{id}/cancel
func (h *Handler) CancelScheduledAssessment(w http.ResponseWriter, r *http.Request) {
	scheduleID := chi.URLParam(r, "id")
	if h.jobsStore == nil {
		jsonError(w, "job engine not loaded", http.StatusServiceUnavailable)
		return
	}
	sch, err := h.jobsStore.GetSchedule(r.Context(), scheduleID)
	if err != nil {
		jsonError(w, "schedule not found", http.StatusNotFound)
		return
	}
	if sch.Type != "scheduled_assessment" {
		jsonError(w, "not a scheduled assessment", http.StatusNotFound)
		return
	}
	if err := h.jobsStore.DisableSchedule(r.Context(), scheduleID); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.auditLog(r, "jobs.schedule.cancel", scheduleID, nil, "cancelled")
	respond(w, map[string]any{"scheduleId": scheduleID, "enabled": false})
}
```

- [ ] **Step 4: Register the 3 routes**

In `orchestrator/internal/api/routes.go`, find:
```go
		r.With(auth.RequirePermission(auth.CanExecuteRemediation)).Post("/api/job-schedules/{scheduleId}/cancel", h.CancelJobSchedule)
```
Immediately after it, add:
```go
		r.With(auth.RequirePermission(auth.CanExecuteRemediation)).Post("/api/scheduled-assessments", h.CreateScheduledAssessment)
		r.With(auth.RequirePermission(auth.CanExecuteRemediation)).Get("/api/scheduled-assessments", h.ListScheduledAssessments)
		r.With(auth.RequirePermission(auth.CanExecuteRemediation)).Post("/api/scheduled-assessments/{id}/cancel", h.CancelScheduledAssessment)
```
(Router-level permission is the base `CanExecuteRemediation` tier for all three — the stricter Admin-only + reason check for telemetry mode happens inside `CreateScheduledAssessment` itself, exactly mirroring how `CreateJobSchedule` already does its Tier2 check internally rather than at the router.)

- [ ] **Step 5: Add the 3 routes to the RBAC matrix test**

In `orchestrator/internal/api/rbac_matrix_test.go`, find:
```go
	{http.MethodPost, "/api/job-schedules/{scheduleId}/cancel", tierPermission, auth.CanExecuteRemediation},
```
Immediately after it, add:
```go
	{http.MethodPost, "/api/scheduled-assessments", tierPermission, auth.CanExecuteRemediation},
	{http.MethodGet, "/api/scheduled-assessments", tierPermission, auth.CanExecuteRemediation},
	{http.MethodPost, "/api/scheduled-assessments/{id}/cancel", tierPermission, auth.CanExecuteRemediation},
```

- [ ] **Step 6: Run the new tests to verify they pass**

```bash
go test ./internal/api/... -run TestCreateScheduledAssessment -run TestListScheduledAssessments -run TestCancelScheduledAssessment -v
```
Expected: PASS, all 7.

- [ ] **Step 7: Run the RBAC matrix test**

```bash
go test ./internal/api/... -run TestRBACMatrix_AuthorizationBoundary -v
```
Expected: PASS.

- [ ] **Step 8: Run the full `internal/api` and `internal/jobs` suites**

```bash
go test ./internal/api/... -v
go test ./internal/jobs/... -v
```
Expected: PASS. If `internal/api` shows an isolated failure unrelated to this change (a known class of Docker/testcontainer contention noise documented repeatedly in this initiative's history — see the Endpoint Health & Remediation memory's "Recurring gotchas" section), re-run that specific failing test alone to confirm it's not a real regression before treating the task as done.

- [ ] **Step 9: Full workspace verification**

```bash
cd orchestrator
go build ./...
go vet ./...
go test ./...
```
Expected: clean build, no new vet issues, full suite green (module-wide, catching anything Task 1-6 might have missed in a package not touched directly, e.g. a shared test helper).

- [ ] **Step 10: Commit**

```bash
git add internal/api/scheduled_assessment_handlers.go internal/api/scheduled_assessment_handlers_test.go internal/api/routes.go internal/api/rbac_matrix_test.go
git commit -m "feat(api): Scheduled Assessments endpoints (create/list/cancel)"
git push
```

---

## Self-Review Notes

- **Spec coverage:** Every spec section maps to a task — "Data model changes" → Task 1; "Recurrence" → Task 2; "Targets: live group resolution" → Task 3; "Concurrency" → Task 4; "New job type" → Task 5; "Execution mode and authorization" + "API surface" → Task 6. "Guardrails" table items marked Reused required no task (nothing to build); items marked New/deferred are covered (concurrency in Task 4; max-targets/cooldown explicitly not built, matching Non-goals). "Assessment/Profile" (reuse existing Scenario) required no task — it's the absence of a new entity, exercised implicitly by every test that calls `h.engine.Get`.
- **Placeholder scan:** No TBD/TODO. Every step shows exact before/after code or a runnable command with its expected result.
- **Type consistency:** `scheduledAssessmentPayload{ScenarioID, Mode, Techniques, Steps}` (Task 5) matches exactly what Task 6's `CreateScheduledAssessment` marshals. `Store.CreateBatchWithConcurrency`'s signature (Task 1) matches its two call sites: `CreateBatchScheduled`'s wrapper (Task 1) and `spawnDueSchedules` (Task 3). `jobs.TargetStateDispatched`/`TargetStateCompleted`/`TargetStateFailed` (existing constants) are used identically in Task 5's status function and Task 4's concurrency test. `Schedule.GroupIDs []int64` (Task 1) matches `ResolveGroupAgentIDs(ctx, groupIDs []int64)`'s parameter type (Task 3) and the API request's `GroupIDs []int64` field (Task 6).
- **Scope check:** 6 tasks, each with an independently testable deliverable, matching the granularity of prior sub-projects in this initiative (e.g. Sub-project 7 bundled two related phases; this bundles data-model, recurrence, targeting, concurrency, dispatch, and API — each genuinely separable but all needed for one working feature). Not split further since Tasks 2-5 each depend on Task 1's struct fields existing, and Task 6 depends on all of them.
