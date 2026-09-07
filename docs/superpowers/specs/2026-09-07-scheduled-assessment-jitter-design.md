# Scheduled Assessment Jitter — Design

## Problem

`orchestrator/internal/jobs/dispatch.go`'s `Dispatcher.Tick` runs every 5s
(`jobsScheduler := exercise.NewPollScheduler(5 * time.Second)`,
`cmd/server/main.go:553`) and calls `spawnDueSchedules`, which checks every
enabled `Schedule` and, for any whose nominal `TimeOfDay` has just passed,
spawns a fresh `Job` **synchronously, in the same for-loop, in the same
tick** (`schedule.go`'s `nextOccurrenceSince` -> `dispatch.go`'s
`CreateBatchWithConcurrency`, one DB transaction per due schedule).

Schedules commonly cluster on round nominal times (many users default to
"09:00" or "00:00"). When several schedules share a nominal `TimeOfDay`,
they all become due in the same 5s tick and spawn back-to-back. This is
not a literal flood against agents — `Tick`'s separate
`ListPendingTargetsAcrossActiveJobs(ctx, jobDispatchBatchSize=20)` already
caps *all* agent-facing dispatch to 20 targets/5s fleet-wide, regardless
of how many schedules just fired. What isn't protected is fairness: all
those schedules' newly-created targets now compete for that same shared
20-per-5s budget, so a schedule that loses that race can see its actual
execution start meaningfully delayed relative to its nominal time, purely
because another schedule happened to share the same clock reading.

## Goal

Spread each schedule's *effective* trigger moment by a small, stable
per-schedule offset, so schedules sharing a common nominal `TimeOfDay`
don't all become due in the same tick — while preserving user-configured
schedule semantics ("9am daily" still means approximately 9am, every day,
consistently).

## Scope

**In scope:** cross-schedule jitter on `daily`, `weekly`, and `monthly`
recurring schedules' due-time computation.

**Explicitly out of scope (non-goals, with reasoning):**

- **`RecurrenceType == "once"` schedules are never jittered.** A user who
  picked a single absolute `RunAt` timestamp for a one-time run means
  that exact moment; jittering it would silently violate an explicit,
  non-recurring commitment. `once` schedules are also unlikely to cluster
  with others in the way that motivates this feature in the first place.
- **Intra-schedule target spread is not new work.** The other half of
  "spread" — a single schedule whose `GroupIDs` resolve to many agents —
  is already adequately handled by existing mechanisms: `Tick`'s global
  `jobDispatchBatchSize=20`/5s cap throttles all dispatch fleet-wide
  regardless of schedule count, and `Schedule.ConcurrencyLimit` (already
  copied onto every spawned `Job`) lets a schedule's own author cap how
  many of *its* targets run concurrently. A schedule resolving to 500
  agents already dispatches at roughly 4/sec via existing code. No new
  mechanism is added here; if a real gap surfaces later it gets its own
  pass.
- **Multi-instance / leader-election correctness is not addressed.**
  Checked `packaging/compose/docker-compose*.yml` — no `replicas:` in any
  compose file. This is a single orchestrator process per on-prem
  deployment, not an HA/multi-replica setup. `spawnDueSchedules` already
  runs on a single ticker goroutine per process with no concurrent callers
  within a process, so no new locking is needed for the deployment model
  that actually exists.
- **No new API/UI surface.** There is no existing "next scheduled run"
  display anywhere today (checked `wwwroot/index.html` and
  `scheduled_assessment_handlers.go`) — it's computed fresh inside
  `Dispatcher.Tick` and never exposed. Observability for this feature is
  a log line only (see below); an API/UI surface for a predicted next-fire
  time is a reasonable follow-up but is its own pass.
- **No DB migration.** The jitter offset is derived deterministically from
  the existing `Schedule.ID`, not stored — see below.

## Design

### Deriving the offset

```go
// scheduleJitterWindow bounds how far a schedule's effective trigger time
// can drift from its nominal TimeOfDay -- small enough to stay well within
// user expectations of "9am daily", large enough to break up clusters of
// schedules sharing a common nominal time.
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

Choosing a deterministic hash over a persisted offset column was an
explicit trade-off: zero schema/migration cost, and restart-stability
falls out for free (a pure function of an already-stable ID has nothing
to reconcile). The cost — not independently visible without recomputing
it — is accepted because observability for this feature is a log line
(see below), not an API field.

Because the offset is a fixed function of `ID` alone (not recomputed
per-occurrence), the *same* schedule always jitters the *same* direction
and amount on every occurrence — "9am daily" consistently becomes,
say, "9:01:23 daily," not a different offset each day. This is what
"stable across restarts" means in practice, and it is also what avoids
the failure mode explicitly ruled out during design: recomputing a fresh
random offset on every restart (or every tick) would risk reshuffling a
fleet's workload and accidentally recreating the exact burst this feature
exists to prevent.

### Where it's applied

Inside `nextOccurrenceDaily`, `nextOccurrenceWeekly`, and
`nextOccurrenceMonthly` (never `nextOccurrenceOnce`):

1. Compute the nominal candidate exactly as today (`time.Date(...)` in the
   schedule's timezone).
2. **Weekly/monthly only:** validate `candidate.Weekday() != sch.DayOfWeek`
   / `candidate.Day() != sch.DayOfMonth` against the **nominal** candidate,
   unchanged from today. Jitter shifts *when* a valid day fires, never
   *which* day is valid.
3. Compute `jittered := candidate.Add(jitterOffset(sch.ID,
   scheduleJitterWindow))`.
4. Use `jittered` (not `candidate`) for the `After(now)` due-check, the
   `LastOccurrenceAt` dedup check, and the final returned `occurrence`
   value (what `MarkScheduleOccurrenceHandled` persists).

A small consequence worth naming explicitly: a schedule with `TimeOfDay`
near midnight and a negative offset can have its effective instant land on
the *prior* calendar day (e.g. `TimeOfDay: "00:01"` with a -90s offset
effectively fires at `23:59:30` the day before). This is intended
behavior of a ±2min window and requires no special-casing — the existing
backward-search loops in `nextOccurrenceDaily`/`Weekly`/`Monthly`
(`daysBack`/`monthsBack`) already tolerate small offsets from the nominal
calendar boundary; ±2min is far smaller than the day/week/month windows
those loops already search.

### Observability

Extend the existing spawn log line in `dispatch.go`'s `spawnDueSchedules`
(currently `"[jobs] schedule %s: spawned job %s for occurrence %v"`) to
also show the nominal time alongside the effective (jittered) occurrence,
so an operator can grep logs to confirm spreading is happening without any
new API surface.

## Existing-test impact

Checked `orchestrator/internal/jobs/schedule_test.go` and
`dispatch_test.go` directly.

**`dispatch_test.go`'s integration tests are unaffected.** They use real
wall-clock `time.Now()` with `TimeOfDay: "00:00"` and only assert whether
a job spawned, not exact timestamps — a candidate hours in the past stays
due regardless of a ±2min jitter shift.

**`schedule_test.go`'s exact-equality unit tests need updating** — every
current fixture uses `Schedule{}` with `ID` unset (`""`), and several
assert `occurrence` equals a hardcoded exact `time.Date(...)`:
`TestNextOccurrenceSince_FirstOccurrenceEverChecked`,
`_TimezoneConversion`, `_Daily`,
`_Weekly_EmptyRecurrenceTypeAliasesToWeekly`, `_Monthly`. Since
`jitterOffset("")` is one fixed value, every one of these `want`/
`wantTomorrow` computations needs `.Add(jitterOffset(sch.ID,
scheduleJitterWindow))`.

`TestNextOccurrenceSince_AlreadyHandled_ReturnsNotOK` needs more than
that: it sets `LastOccurrenceAt` directly to the *nominal* time, but
production always stores the *jittered* value there (via
`MarkScheduleOccurrenceHandled`). The fixture's `already` value must be
set to the jittered time too, or the dedup check's correctness would
depend on the accidental sign of `jitterOffset("")` rather than being
genuinely exercised.

## Testing strategy

**New pure-function tests** for `jitterOffset`:
- Determinism: same ID -> same offset across repeated calls (no hidden
  state, no `rand` — this is what "stable across restarts" reduces to,
  provable without simulating an actual restart).
- Bounds: offset always in `[-scheduleJitterWindow, scheduleJitterWindow]`
  across a spread of sample IDs.
- Two literal IDs with hardcoded expected offsets, pinning the algorithm
  so a future accidental change to the derivation doesn't silently shift
  every schedule's fire time without a failing test.

**Extended `nextOccurrence{Daily,Weekly,Monthly}` tests**, using explicit
non-empty `Schedule.ID` values:
- One schedule ID (found by calling the real `jitterOffset` function in
  test setup, not guessed) that produces a positive offset, and one that
  produces a negative offset — confirms `occurrence` shifts by exactly
  that amount in both directions.
- A day-boundary case: `TimeOfDay: "00:01"` paired with an ID whose
  offset (again computed via the real function) is negative enough to
  cross into the prior calendar day — confirms due-check and dedup logic
  use the jittered instant correctly regardless of which calendar day it
  nominally lands on.
- `nextOccurrenceOnce`: one added assertion that a schedule ID with a
  known nonzero `jitterOffset` still returns the exact `RunAt` unchanged —
  turns the "once is excluded" design decision into a regression guard.

**Existing-test updates** (mechanical, per "Existing-test impact" above).

**No dedicated test for the log line format change**, consistent with
this codebase's existing convention (no other `log.Printf` call in
`dispatch.go` is unit-tested for exact format).

Nothing here requires sleep-based tests: `nextOccurrenceSince` already
takes `now` as a parameter, and `jitterOffset` takes no time input at
all — both fully deterministic under test as written today.

## Success criteria

1. Two schedules with the same `daily`/`weekly`/`monthly` `TimeOfDay`
   produce different `occurrence` values (assuming their IDs hash to
   different offsets) via `nextOccurrenceSince`.
2. Calling `jitterOffset` twice for the same ID (simulating two separate
   process lifetimes) returns the identical value both times.
3. A `once` schedule's returned `occurrence` equals its exact `RunAt`,
   unaffected by jitter, regardless of its ID's `jitterOffset`.
4. All existing `schedule_test.go` and `dispatch_test.go` tests pass
   (with the named exact-equality fixtures updated per "Existing-test
   impact," not loosened to tolerance-based assertions).
5. The `spawnDueSchedules` log line shows both the nominal and effective
   (jittered) time for a spawned occurrence.
