# Scheduled Assessment Jitter Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give each recurring `Schedule` a small, stable, deterministic per-schedule time offset so schedules that share a common nominal `TimeOfDay` don't all become due in the same 5-second `Dispatcher.Tick`.

**Architecture:** A pure function `jitterOffset(scheduleID string, window time.Duration) time.Duration` derives a stable offset in `[-window, +window]` from an FNV-1a hash of the schedule's own `ID` -- no new storage, no migration, restart-stable by construction. It is applied inside `nextOccurrenceDaily`/`nextOccurrenceWeekly`/`nextOccurrenceMonthly` (never `nextOccurrenceOnce`) after the nominal candidate's weekday/day-of-month validity is checked, but before the due-check and dedup-check use it.

**Tech Stack:** Go, standard library only (`hash/fnv`, `time`). No new dependencies.

**Spec:** `docs/superpowers/specs/2026-09-07-scheduled-assessment-jitter-design.md`

## Global Constraints

- **No DB migration.** The jitter offset is derived from the existing `Schedule.ID` field at read time -- nothing new is persisted. Do not add a column, do not touch `orchestrator/internal/db` migrations.
- **`scheduleJitterWindow = 2 * time.Minute`** -- exact value, copied verbatim from the spec. Do not make this configurable in this pass.
- **`nextOccurrenceOnce` is never touched.** One-shot schedules always fire at their exact `RunAt`, unaffected by jitter.
- **Single orchestrator process per deployment** (confirmed via `packaging/compose/docker-compose*.yml` -- no `replicas:` anywhere). No locking or leader-election work is in scope.
- **No new API or UI surface.** Observability for this feature is a log-line change only, in `orchestrator/internal/jobs/dispatch.go`.
- **No worktree** -- this session works directly on `main`, matching this project's established pattern for this entire initiative.

---

## Task 1: `jitterOffset` core function

**Files:**
- Modify: `orchestrator/internal/jobs/schedule.go` (add `hash/fnv` import, add `scheduleJitterWindow` const and `jitterOffset` func, placed after `parseTimeOfDay` and before `nextOccurrenceSince`)
- Create: `orchestrator/internal/jobs/jitter_test.go`

**Interfaces:**
- Produces: `const scheduleJitterWindow = 2 * time.Minute` and `func jitterOffset(scheduleID string, window time.Duration) time.Duration`, both package-private in `package jobs` -- Task 2 and Task 3 call these directly (same package, no import needed).

- [ ] **Step 1: Write the failing tests**

Create `orchestrator/internal/jobs/jitter_test.go`:

```go
package jobs

import (
	"testing"
	"time"
)

func TestJitterOffset_Deterministic(t *testing.T) {
	first := jitterOffset("sched-a", scheduleJitterWindow)
	second := jitterOffset("sched-a", scheduleJitterWindow)
	if first != second {
		t.Errorf("jitterOffset() = %v then %v, want identical results for the same ID", first, second)
	}
}

func TestJitterOffset_WithinBounds(t *testing.T) {
	ids := []string{"sched-a", "sched-b", "sched-c", "sched-d", "sched-e", "sched-f", "sched-g", "sched-h", "sched-i", "sched-j"}
	for _, id := range ids {
		off := jitterOffset(id, scheduleJitterWindow)
		if off < -scheduleJitterWindow || off > scheduleJitterWindow {
			t.Errorf("jitterOffset(%q) = %v, want within [%v, %v]", id, off, -scheduleJitterWindow, scheduleJitterWindow)
		}
	}
}

func TestJitterOffset_PinnedValues(t *testing.T) {
	cases := []struct {
		id   string
		want time.Duration
	}{
		{"sched-a", 13504439675 * time.Nanosecond},
		{"sched-c", -25518816738 * time.Nanosecond},
	}
	for _, c := range cases {
		got := jitterOffset(c.id, scheduleJitterWindow)
		if got != c.want {
			t.Errorf("jitterOffset(%q) = %v, want %v -- if this legitimately changed, the derivation algorithm changed and every schedule's fire time silently shifted", c.id, got, c.want)
		}
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/jobs/... -run TestJitterOffset -v`
Expected: FAIL with `undefined: jitterOffset` / `undefined: scheduleJitterWindow` (compile error, not a test failure -- `jitterOffset` doesn't exist yet)

- [ ] **Step 3: Implement `jitterOffset`**

In `orchestrator/internal/jobs/schedule.go`, add `"hash/fnv"` to the import block (alphabetically, between `"errors"` and `"strconv"`):

```go
import (
	"context"
	"encoding/json"
	"errors"
	"hash/fnv"
	"strconv"
	"strings"
	"time"
)
```

Then add this block after `parseTimeOfDay`'s closing brace and before `nextOccurrenceSince`:

```go
// scheduleJitterWindow bounds how far a schedule's effective trigger time
// can drift from its nominal TimeOfDay -- small enough to stay well within
// user expectations of "9am daily", large enough to break up clusters of
// schedules sharing a common nominal time. See
// docs/superpowers/specs/2026-09-07-scheduled-assessment-jitter-design.md.
const scheduleJitterWindow = 2 * time.Minute

// jitterOffset derives a stable per-schedule offset in [-window, +window],
// deterministic from the schedule's own ID -- same offset every time this
// process (or any future process) computes it, no stored state, no
// reconciliation needed across restarts. Production schedules always have
// a real DB-assigned id (Store.CreateSchedule's `RETURNING id`); an empty
// ID is purely a test-fixture artifact, never a real production value.
func jitterOffset(scheduleID string, window time.Duration) time.Duration {
	h := fnv.New64a()
	h.Write([]byte(scheduleID))
	span := int64(2*window) + 1
	return time.Duration(int64(h.Sum64()%uint64(span))) - window
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/jobs/... -run TestJitterOffset -v`
Expected: PASS (all three: `TestJitterOffset_Deterministic`, `TestJitterOffset_WithinBounds`, `TestJitterOffset_PinnedValues`)

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/jobs/schedule.go orchestrator/internal/jobs/jitter_test.go
git commit -m "feat(orchestrator): add deterministic per-schedule jitter offset

Pure jitterOffset(scheduleID, window) derives a stable offset in
[-window, +window] from an FNV-1a hash of the schedule's ID -- no
storage, restart-stable by construction. Not yet wired into due-time
computation (Task 2).

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

## Task 2: Wire jitter into due-time computation

**Files:**
- Modify: `orchestrator/internal/jobs/schedule.go:126-185` (`nextOccurrenceDaily`, `nextOccurrenceWeekly`, `nextOccurrenceMonthly`)
- Modify: `orchestrator/internal/jobs/schedule_test.go` (update 6 existing fixtures, add 5 new tests)

**Interfaces:**
- Consumes: `scheduleJitterWindow` and `jitterOffset(scheduleID string, window time.Duration) time.Duration` from Task 1 (same package).
- Produces: `nextOccurrenceDaily`/`Weekly`/`Monthly` now return the *jittered* occurrence, not the nominal one. `nextOccurrenceSince`'s exported behavior for callers (Task 3, `dispatch.go`) is otherwise unchanged -- same signature, same semantics, just a shifted return value for daily/weekly/monthly.

- [ ] **Step 1: Update the existing exact-equality tests first (still red until Step 3)**

In `orchestrator/internal/jobs/schedule_test.go`, apply these five changes. Each adds `.Add(jitterOffset(sch.ID, scheduleJitterWindow))` onto an existing `want`/`already` value -- every one of these fixtures uses `Schedule{}`'s zero-value `ID` (`""`), so it's the same fixed addend in every case.

`TestNextOccurrenceSince_FirstOccurrenceEverChecked`:
```go
	want := time.Date(2026, 8, 7, 23, 0, 0, 0, time.UTC).Add(jitterOffset(sch.ID, scheduleJitterWindow)) // the preceding Friday, jittered
```

`TestNextOccurrenceSince_AlreadyHandled_ReturnsNotOK`:
```go
	already := time.Date(2026, 8, 7, 23, 0, 0, 0, time.UTC).Add(jitterOffset(sch.ID, scheduleJitterWindow))
```
(`sch` isn't declared yet at this point in the function -- move the `sch := Schedule{...}` line above `already`'s computation if it isn't already; check the current file, since `sch.ID` must be in scope. The full corrected function:)
```go
func TestNextOccurrenceSince_AlreadyHandled_ReturnsNotOK(t *testing.T) {
	sch := Schedule{DayOfWeek: 5, TimeOfDay: "23:00", Timezone: "UTC"}
	already := time.Date(2026, 8, 7, 23, 0, 0, 0, time.UTC).Add(jitterOffset(sch.ID, scheduleJitterWindow))
	sch.LastOccurrenceAt = &already
	now := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC) // still the same week, no new Friday yet
	_, ok := nextOccurrenceSince(sch, now)
	if ok {
		t.Error("nextOccurrenceSince() ok = true, want false -- this occurrence was already handled")
	}
}
```

`TestNextOccurrenceSince_TimezoneConversion`:
```go
	want := time.Date(2026, 8, 7, 17, 30, 0, 0, time.UTC).Add(jitterOffset(sch.ID, scheduleJitterWindow))
```

`TestNextOccurrenceSince_Daily` (compute `offset` once and reuse for both assertions):
```go
func TestNextOccurrenceSince_Daily(t *testing.T) {
	loc, _ := time.LoadLocation("UTC")
	sch := Schedule{RecurrenceType: "daily", TimeOfDay: "14:00", Timezone: "UTC"}
	offset := jitterOffset(sch.ID, scheduleJitterWindow)

	now := time.Date(2026, 8, 10, 14, 5, 0, 0, loc)
	occ, ok := nextOccurrenceSince(sch, now)
	want := time.Date(2026, 8, 10, 14, 0, 0, 0, loc).Add(offset)
	if !ok || !occ.Equal(want) {
		t.Errorf("got occ=%v ok=%v, want %v/true", occ, ok, want)
	}

	sch.LastOccurrenceAt = &occ
	if _, ok := nextOccurrenceSince(sch, now); ok {
		t.Error("same-day recheck after spawn: got ok=true, want false")
	}
	tomorrow := now.Add(24 * time.Hour)
	occ2, ok := nextOccurrenceSince(sch, tomorrow)
	wantTomorrow := time.Date(2026, 8, 11, 14, 0, 0, 0, loc).Add(offset)
	if !ok || !occ2.Equal(wantTomorrow) {
		t.Errorf("next day: got occ=%v ok=%v, want %v/true", occ2, ok, wantTomorrow)
	}
}
```

`TestNextOccurrenceSince_Weekly_EmptyRecurrenceTypeAliasesToWeekly`:
```go
	want := time.Date(2026, 8, 10, 9, 0, 0, 0, loc).Add(jitterOffset(sch.ID, scheduleJitterWindow)) // the Monday before, jittered
```

`TestNextOccurrenceSince_Monthly`:
```go
	want := time.Date(2026, 8, 1, 3, 0, 0, 0, loc).Add(jitterOffset(sch.ID, scheduleJitterWindow))
```

`TestNextOccurrenceSince_TimeOfDayNotYetReachedToday` and `TestNextOccurrenceSince_EndDate_StopsSpawning` need **no changes** -- both assert `ok == false` with margins (13 hours; well past `EndDate`) far larger than the 2-minute jitter window.

- [ ] **Step 2: Run tests to verify the updated ones still fail (jitter not wired yet)**

Run: `cd orchestrator && go test ./internal/jobs/... -run TestNextOccurrenceSince -v`
Expected: FAIL on the 5 tests just updated (their new `want` values include a jitter offset that the production code doesn't apply yet) -- `TestNextOccurrenceSince_TimeOfDayNotYetReachedToday` and `_EndDate_StopsSpawning` still PASS (unchanged).

- [ ] **Step 3: Wire jitter into `nextOccurrenceDaily`**

Replace the full function body in `schedule.go`:

```go
func nextOccurrenceDaily(sch Schedule, now time.Time, loc *time.Location) (time.Time, bool) {
	hh, mm, err := parseTimeOfDay(sch.TimeOfDay)
	if err != nil {
		return time.Time{}, false
	}
	nowLocal := now.In(loc)
	for daysBack := 0; daysBack < 2; daysBack++ {
		candidate := time.Date(nowLocal.Year(), nowLocal.Month(), nowLocal.Day()-daysBack, hh, mm, 0, 0, loc)
		jittered := candidate.Add(jitterOffset(sch.ID, scheduleJitterWindow))
		if jittered.After(now) {
			continue
		}
		if sch.LastOccurrenceAt != nil && !jittered.After(*sch.LastOccurrenceAt) {
			return time.Time{}, false
		}
		return jittered.UTC(), true
	}
	return time.Time{}, false
}
```

- [ ] **Step 4: Wire jitter into `nextOccurrenceWeekly`**

```go
func nextOccurrenceWeekly(sch Schedule, now time.Time, loc *time.Location) (time.Time, bool) {
	hh, mm, err := parseTimeOfDay(sch.TimeOfDay)
	if err != nil {
		return time.Time{}, false
	}
	nowLocal := now.In(loc)
	for daysBack := 0; daysBack < 7; daysBack++ {
		candidate := time.Date(nowLocal.Year(), nowLocal.Month(), nowLocal.Day()-daysBack, hh, mm, 0, 0, loc)
		if int(candidate.Weekday()) != sch.DayOfWeek {
			continue
		}
		jittered := candidate.Add(jitterOffset(sch.ID, scheduleJitterWindow))
		if jittered.After(now) {
			continue
		}
		if sch.LastOccurrenceAt != nil && !jittered.After(*sch.LastOccurrenceAt) {
			return time.Time{}, false
		}
		return jittered.UTC(), true
	}
	return time.Time{}, false
}
```

Note the weekday check stays against the *nominal* `candidate`, split out from the due-check so jitter never changes which day is valid, only when a valid day fires.

- [ ] **Step 5: Wire jitter into `nextOccurrenceMonthly`**

```go
func nextOccurrenceMonthly(sch Schedule, now time.Time, loc *time.Location) (time.Time, bool) {
	hh, mm, err := parseTimeOfDay(sch.TimeOfDay)
	if err != nil {
		return time.Time{}, false
	}
	nowLocal := now.In(loc)
	for monthsBack := 0; monthsBack < 2; monthsBack++ {
		// time.Date normalizes an out-of-range day (e.g. day 31 in a
		// 30-day month) by rolling into the next month -- the Day() check
		// below rejects that roll-over instead of misfiring in the wrong
		// month.
		candidate := time.Date(nowLocal.Year(), nowLocal.Month()-time.Month(monthsBack), sch.DayOfMonth, hh, mm, 0, 0, loc)
		if candidate.Day() != sch.DayOfMonth {
			continue
		}
		jittered := candidate.Add(jitterOffset(sch.ID, scheduleJitterWindow))
		if jittered.After(now) {
			continue
		}
		if sch.LastOccurrenceAt != nil && !jittered.After(*sch.LastOccurrenceAt) {
			return time.Time{}, false
		}
		return jittered.UTC(), true
	}
	return time.Time{}, false
}
```

- [ ] **Step 6: Run tests to verify the updated existing tests now pass**

Run: `cd orchestrator && go test ./internal/jobs/... -run TestNextOccurrenceSince -v`
Expected: PASS (all of them, including the 5 updated in Step 1)

- [ ] **Step 7: Add new jitter-specific tests**

Append to `orchestrator/internal/jobs/schedule_test.go`:

```go
func TestNextOccurrenceDaily_JitterShiftsOccurrence(t *testing.T) {
	loc, _ := time.LoadLocation("UTC")
	now := time.Date(2026, 8, 10, 14, 5, 0, 0, loc)

	// "test-schedule-1" has a positive jitterOffset (~+34.5s).
	positive := Schedule{ID: "test-schedule-1", RecurrenceType: "daily", TimeOfDay: "14:00", Timezone: "UTC"}
	if off := jitterOffset(positive.ID, scheduleJitterWindow); off <= 0 {
		t.Fatalf("test fixture assumption broken: jitterOffset(%q) = %v, want > 0 -- pick a different ID", positive.ID, off)
	}
	occ, ok := nextOccurrenceSince(positive, now)
	want := time.Date(2026, 8, 10, 14, 0, 0, 0, loc).Add(jitterOffset(positive.ID, scheduleJitterWindow))
	if !ok || !occ.Equal(want) {
		t.Errorf("positive-offset ID: got occ=%v ok=%v, want %v/true", occ, ok, want)
	}

	// "test-schedule-2" has a negative jitterOffset (~-66s).
	negative := Schedule{ID: "test-schedule-2", RecurrenceType: "daily", TimeOfDay: "14:00", Timezone: "UTC"}
	if off := jitterOffset(negative.ID, scheduleJitterWindow); off >= 0 {
		t.Fatalf("test fixture assumption broken: jitterOffset(%q) = %v, want < 0 -- pick a different ID", negative.ID, off)
	}
	occ2, ok := nextOccurrenceSince(negative, now)
	want2 := time.Date(2026, 8, 10, 14, 0, 0, 0, loc).Add(jitterOffset(negative.ID, scheduleJitterWindow))
	if !ok || !occ2.Equal(want2) {
		t.Errorf("negative-offset ID: got occ=%v ok=%v, want %v/true", occ2, ok, want2)
	}
}

func TestNextOccurrenceDaily_JitterCrossesDayBoundary(t *testing.T) {
	loc, _ := time.LoadLocation("UTC")
	sch := Schedule{ID: "sched-g", RecurrenceType: "daily", TimeOfDay: "00:01", Timezone: "UTC"}
	offset := jitterOffset(sch.ID, scheduleJitterWindow)
	if offset >= -60*time.Second {
		t.Fatalf("test fixture assumption broken: jitterOffset(%q) = %v, want <= -60s to cross the day boundary from 00:01 -- pick a different ID", sch.ID, offset)
	}

	now := time.Date(2026, 8, 10, 1, 0, 0, 0, loc) // well after midnight
	occ, ok := nextOccurrenceSince(sch, now)
	want := time.Date(2026, 8, 10, 0, 1, 0, 0, loc).Add(offset)
	if !ok || !occ.Equal(want) {
		t.Errorf("got occ=%v ok=%v, want %v/true", occ, ok, want)
	}
	if occ.UTC().Day() != 9 {
		t.Errorf("occurrence lands on day %d, want day 9 (the prior calendar day) -- jitter should have pushed a 00:01 nominal time backward across midnight", occ.UTC().Day())
	}
}

func TestNextOccurrenceOnce_JitterDoesNotApply(t *testing.T) {
	runAt := time.Date(2026, 8, 10, 9, 0, 0, 0, time.UTC)
	sch := Schedule{ID: "sched-d", RecurrenceType: "once", RunAt: &runAt, Timezone: "UTC", TimeOfDay: "00:00"}
	if off := jitterOffset(sch.ID, scheduleJitterWindow); off == 0 {
		t.Fatalf("test fixture assumption broken: jitterOffset(%q) = 0, want nonzero -- pick a different ID", sch.ID)
	}
	now := runAt.Add(time.Hour)
	occurrence, ok := nextOccurrenceSince(sch, now)
	if !ok {
		t.Fatal("nextOccurrenceSince() ok = false, want true")
	}
	if !occurrence.Equal(runAt) {
		t.Errorf("occurrence = %v, want %v (exact RunAt, unaffected by jitter)", occurrence, runAt)
	}
}

func TestNextOccurrenceWeekly_JitterShiftsOccurrence(t *testing.T) {
	loc, _ := time.LoadLocation("UTC")
	sch := Schedule{ID: "sched-b", RecurrenceType: "weekly", DayOfWeek: 1, TimeOfDay: "09:00", Timezone: "UTC"} // Monday
	if off := jitterOffset(sch.ID, scheduleJitterWindow); off <= 0 {
		t.Fatalf("test fixture assumption broken: jitterOffset(%q) = %v, want > 0 -- pick a different ID", sch.ID, off)
	}
	now := time.Date(2026, 8, 11, 9, 30, 0, 0, loc) // a Tuesday, 9:30
	occ, ok := nextOccurrenceSince(sch, now)
	want := time.Date(2026, 8, 10, 9, 0, 0, 0, loc).Add(jitterOffset(sch.ID, scheduleJitterWindow)) // the Monday before, jittered
	if !ok || !occ.Equal(want) {
		t.Errorf("got occ=%v ok=%v, want %v/true", occ, ok, want)
	}
}

func TestNextOccurrenceMonthly_JitterShiftsOccurrence(t *testing.T) {
	loc, _ := time.LoadLocation("UTC")
	sch := Schedule{ID: "sched-e", RecurrenceType: "monthly", DayOfMonth: 1, TimeOfDay: "03:00", Timezone: "UTC"}
	if off := jitterOffset(sch.ID, scheduleJitterWindow); off >= 0 {
		t.Fatalf("test fixture assumption broken: jitterOffset(%q) = %v, want < 0 -- pick a different ID", sch.ID, off)
	}
	now := time.Date(2026, 8, 5, 0, 0, 0, 0, loc) // Aug 5, after Aug 1's slot
	occ, ok := nextOccurrenceSince(sch, now)
	want := time.Date(2026, 8, 1, 3, 0, 0, 0, loc).Add(jitterOffset(sch.ID, scheduleJitterWindow))
	if !ok || !occ.Equal(want) {
		t.Errorf("got occ=%v ok=%v, want %v/true", occ, ok, want)
	}
}
```

- [ ] **Step 8: Run the full package test suite**

Run: `cd orchestrator && go test ./internal/jobs/... -v 2>&1 | tail -100`
Expected: PASS -- every test in the `jobs` package, including `dispatch_test.go`'s integration tests (unaffected per the spec's analysis: they use real wall-clock `now()` with `TimeOfDay: "00:00"`, hours-old candidates stay due regardless of a ±2min shift).

- [ ] **Step 9: Commit**

```bash
git add orchestrator/internal/jobs/schedule.go orchestrator/internal/jobs/schedule_test.go
git commit -m "feat(orchestrator): apply schedule jitter to daily/weekly/monthly due-time

nextOccurrenceDaily/Weekly/Monthly now return the jittered occurrence
(nominal TimeOfDay shifted by jitterOffset(sch.ID, scheduleJitterWindow))
instead of the exact nominal time, so schedules sharing a common
TimeOfDay stop all becoming due in the same 5s Dispatcher.Tick.
nextOccurrenceOnce is untouched -- one-shot schedules still fire at
their exact RunAt.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

## Task 3: Observability -- show nominal vs. jittered time in the spawn log line

**Files:**
- Modify: `orchestrator/internal/jobs/dispatch.go:249-250` (inside `spawnDueSchedules`)

**Interfaces:**
- Consumes: `scheduleJitterWindow` and `jitterOffset` from Task 1, same package, no import needed (this deliberately avoids changing `nextOccurrenceSince`'s two-value signature, which every one of the ~13 tests in `schedule_test.go` destructures as `occurrence, ok := nextOccurrenceSince(...)` -- adding a third return value there would force every one of those call sites to change for a log-line-only feature. Recomputing `jitterOffset(sch.ID, scheduleJitterWindow)` a second time here is cheap and pure, and keeps `nextOccurrenceSince`'s public shape untouched.)

- [ ] **Step 1: Update the log line**

In `orchestrator/internal/jobs/dispatch.go`, find:

```go
		d.store.MarkScheduleOccurrenceHandled(ctx, sch.ID, occurrence, newJob.ID)
		log.Printf("[jobs] schedule %s: spawned job %s for occurrence %v", sch.ID, newJob.ID, occurrence)
```

Replace with:

```go
		d.store.MarkScheduleOccurrenceHandled(ctx, sch.ID, occurrence, newJob.ID)
		offset := jitterOffset(sch.ID, scheduleJitterWindow)
		nominal := occurrence.Add(-offset)
		log.Printf("[jobs] schedule %s: spawned job %s for occurrence %v (nominal %v, jitter %v)",
			sch.ID, newJob.ID, occurrence, nominal, offset)
```

Note: for a `once` schedule, `occurrence` equals the exact `RunAt` and `offset` will still be `jitterOffset(sch.ID, scheduleJitterWindow)`'s real (nonzero, in general) value even though it was never applied to the occurrence itself -- this makes the log line's `nominal` field slightly misleading for `once` schedules (it back-computes a "nominal" that doesn't correspond to anything real for that recurrence type). Since `once` schedules aren't the case this log format is trying to clarify (jitter never applies to them), this is acceptable: the log line's purpose is spotting jitter on recurring schedules, and a reader can already tell a schedule is `once`-type from its row in the schedules table if this ever causes confusion. Do not add a `RecurrenceType` branch here -- that would be complexity earning its keep for a log cosmetic that doesn't affect correctness.

- [ ] **Step 2: Build and run the full jobs package test suite**

Run: `cd orchestrator && go build ./... && go test ./internal/jobs/... -v 2>&1 | tail -100`
Expected: builds clean; all tests PASS (no test asserts on log output, matching this codebase's existing convention of not unit-testing `log.Printf` format strings)

- [ ] **Step 3: Manually verify the log format**

Run: `cd orchestrator && go test ./internal/jobs/... -run TestDispatcher_SpawnsScheduledJob -v -args -test.v 2>&1 | grep -i "spawned job"` (adjust the `-run` pattern to whatever `dispatch_test.go` test actually exercises `spawnDueSchedules` end-to-end with a real schedule spawn -- check the file for the exact test name first, e.g. via `grep -n "func Test" orchestrator/internal/jobs/dispatch_test.go`)
Expected: a log line matching `[jobs] schedule <id>: spawned job <job-id> for occurrence <time> (nominal <time>, jitter <duration>)`

- [ ] **Step 4: Commit**

```bash
git add orchestrator/internal/jobs/dispatch.go
git commit -m "feat(orchestrator): log nominal vs. jittered time on schedule spawn

Lets an operator grep logs to confirm jitter is spreading schedule
spawns, without any new API/UI surface (none exists today for this --
next-occurrence was never exposed outside Dispatcher.Tick before this).

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

## Final Verification

- [ ] Run the complete orchestrator test suite: `cd orchestrator && go build ./... && go test ./... -p 1 2>&1 | tail -100` -- expect all packages `ok`, none broken by this change (only `internal/jobs` was touched).
- [ ] Confirm no DB migration was added: `git diff main --stat` (or `git log --stat` on the three commits above) should show only `orchestrator/internal/jobs/schedule.go`, `orchestrator/internal/jobs/schedule_test.go`, `orchestrator/internal/jobs/jitter_test.go`, `orchestrator/internal/jobs/dispatch.go` -- no `orchestrator/internal/db/**` file touched.
- [ ] Confirm `nextOccurrenceOnce` in `schedule.go` still contains no call to `jitterOffset` (grep: `grep -n "jitterOffset" orchestrator/internal/jobs/schedule.go` should show it only inside `nextOccurrenceDaily`/`Weekly`/`Monthly`, never inside `nextOccurrenceOnce`).
