# Drift & Stability Analytics (Phase 6) — Design

## 1. Problem statement

`technique_verification_runs` (Sub-project 5) already stores every technique-verification result, and Sub-project 8's 24h/7d/30d revalidation chain now generates enough of them per control to matter — but the only existing consumer, `techniqueVerificationFindings`, always collapses history down to the single latest result per `check_id`. There is no way today to answer the questions a security team actually cares about: does this control stay fixed once remediated, or does it drift back within days? Which controls on this endpoint are chronically unstable vs. rock-solid after one fix? How does the fleet's overall control stability trend month over month? Phase 6 answers these by computing derived stability analytics from the existing data — no new history storage, since the history already exists.

## 2. Scope

**In scope:**
- A pure, DB-free computation core (`internal/driftanalytics`) that takes an ordered PASS/FAIL sequence and derives drift/stability metrics.
- A precise, explicit definition of "drift": a PASS→FAIL transition, never a bare FAIL (see §4).
- Sequences pooled per `(agent_id, check_id)` **across every `request_id`** ever created for that pair — not scoped to a single revalidation chain (see §3 for why).
- Three new read-only endpoints: per-control drift stats, per-endpoint drift summary, fleet-wide drift report.

**Explicitly out of scope, deferred:**
- Drift heatmap grouped by control category (Security Configuration/Identity/Compliance/etc.) — no `check_id → category` lookup function exists today (category assignment is done ad hoc, inline, per category-specific function in `endpointrisk_aggregations.go`); building one is a separate, unscoped effort. The fleet report groups by `check_id` directly instead.
- Any notification/alerting on drift events (Phase 7).
- Any frontend/UI — backend/API only, consistent with every prior sub-project in this initiative.
- Any new database table — `technique_verification_runs` is the sole source of truth; everything else is computed on read.

## 3. Architecture

**Sequence scope.** A drift/stability computation for one control is keyed by `(agent_id, check_id)` and pools **every** `technique_verification_runs` row ever written for that pair, regardless of which `request_id` (i.e. which separate remediation attempt) produced it. This is a deliberate, confirmed choice: a single Sub-project 8 revalidation chain only ever produces up to ~4 rows within a 30-day window, and by construction every row in that chain starts from a PASS (the chain is only created after `handleRemediationVerifyResult`'s success branch) — so a chain-scoped sequence can never show a control that passed in January, drifted in April, and got fixed again in September across three unrelated remediation attempts. Pooling by `(agent_id, check_id)` is the only scope that produces a real long-term stability signal.

**Drift definition.** Drift is a **PASS→FAIL transition** in the ordered sequence, nothing else:

| Sequence | Drift count | Why |
|---|---|---|
| `FAIL, FAIL, FAIL, FAIL` | 0 | Never fixed — no PASS to drift *from*. |
| `PASS, PASS, PASS, PASS` | 0 | Never drifted. |
| `FAIL, PASS, FAIL` | 1 | One relapse after the first fix. |
| `FAIL, PASS, PASS, PASS, FAIL` | 1 | Held for 3 checks, then relapsed. |

**Outcome normalization.** `models.ResultPass` and `models.ResultBlocked` both normalize to a binary `PASS` — this matches the `case ResultPass, ResultBlocked:` convention used consistently everywhere else in this codebase (`models/score.go`, `campaign`, `compliance`, `detecteffectiveness`, `reporting`; `ResultBlocked` means the control prevented the technique from running, a security win). `models.ResultFail` normalizes to `FAIL`. `models.ResultError` and `models.ResultSkipped` rows are dropped from the sequence entirely before computation — not counted as PASS, FAIL, or a streak-breaker — matching the codebase's existing "excluded from score" treatment of those two statuses (they answer "did the BAS hit a problem," never "did the control hold").

**Computation is a pure function**, not SQL aggregation. `internal/driftanalytics.ComputeDriftStats(runs []VerificationOutcome) DriftStats` takes an already-normalized, already-ordered binary sequence and derives every metric via a single linear walk — no database access inside the function, fully unit-testable with hand-built sequences. This mirrors two existing precedents in this codebase: `models.ComputeScore` (compute-on-read from raw results, never pre-materialized) and Sub-project 6's `jobs.AggregateState` (a pure function with its own DB-free unit tests). Endpoint- and fleet-level aggregates are built by calling `ComputeDriftStats` once per `(agent_id, check_id)` pair present in the data and combining the results in Go — there is no separate SQL aggregation path duplicating the per-pair algorithm.

## 4. Data model

No new tables. `internal/driftanalytics` introduces two plain Go types with no persistence of their own:

```go
// internal/driftanalytics/driftanalytics.go
package driftanalytics

import "time"

// VerificationOutcome is one already-normalized, binary result in a
// control's ordered history. Callers build this slice from
// technique_verification_runs, mapping ResultPass/ResultBlocked -> "pass",
// ResultFail -> "fail", and dropping ResultError/ResultSkipped rows before
// calling ComputeDriftStats.
type VerificationOutcome struct {
	Result string // "pass" or "fail" -- never any other value
	At     time.Time
}

// DriftStats is the full set of derived stability metrics for one
// (agent_id, check_id) pair's pooled history.
type DriftStats struct {
	TotalRuns             int
	PassCount             int
	FailCount             int
	StabilityPercent      float64 // PassCount / TotalRuns * 100; 0 if TotalRuns == 0
	DriftCount            int     // count of PASS -> FAIL transitions
	LongestPassStreak     int
	LongestFailStreak     int
	CurrentStreakResult    string // "pass" or "fail"; "" if TotalRuns == 0
	CurrentStreakLength    int
	CurrentStreakStartedAt *time.Time // when the current (still-open) streak began
	AverageDaysUntilDrift  float64    // mean duration (days) of every PASS-streak that ended in a drift; 0 if DriftCount == 0
	FirstVerifiedAt        *time.Time
	LastVerifiedAt         *time.Time
}
```

The source query building `[]VerificationOutcome` for one pair, run by the handler layer (not inside `internal/driftanalytics`, which stays DB-free):

```sql
SELECT status, completed_at FROM technique_verification_runs
WHERE agent_id = $1 AND check_id = $2
  AND completed_at IS NOT NULL
  AND status IN ('pass', 'blocked', 'fail')
ORDER BY completed_at ASC
```

`status IN ('pass','blocked','fail')` does the error/skipped exclusion directly in SQL rather than filtering in Go after the fact.

## 5. Computation algorithm

```go
// internal/driftanalytics/driftanalytics.go
func ComputeDriftStats(runs []VerificationOutcome) DriftStats {
	var s DriftStats
	s.TotalRuns = len(runs)
	if s.TotalRuns == 0 {
		return s
	}
	s.FirstVerifiedAt = &runs[0].At
	s.LastVerifiedAt = &runs[len(runs)-1].At

	streakResult := runs[0].Result
	streakStart := runs[0].At
	streakLen := 0
	var driftDurationsDays []float64

	flushStreak := func() {
		if streakResult == "pass" && streakLen > s.LongestPassStreak {
			s.LongestPassStreak = streakLen
		}
		if streakResult == "fail" && streakLen > s.LongestFailStreak {
			s.LongestFailStreak = streakLen
		}
	}

	for i, r := range runs {
		if r.Result == "pass" {
			s.PassCount++
		} else {
			s.FailCount++
		}

		if i > 0 && runs[i-1].Result != r.Result {
			if runs[i-1].Result == "pass" && r.Result == "fail" {
				s.DriftCount++
				driftDurationsDays = append(driftDurationsDays, r.At.Sub(streakStart).Hours()/24)
			}
			flushStreak()
			streakResult = r.Result
			streakStart = r.At
			streakLen = 0
		}
		streakLen++
	}
	flushStreak() // close out the final (current) streak

	s.CurrentStreakResult = streakResult
	s.CurrentStreakLength = streakLen
	s.CurrentStreakStartedAt = &streakStart
	s.StabilityPercent = float64(s.PassCount) / float64(s.TotalRuns) * 100
	if len(driftDurationsDays) > 0 {
		var sum float64
		for _, d := range driftDurationsDays {
			sum += d
		}
		s.AverageDaysUntilDrift = sum / float64(len(driftDurationsDays))
	}
	return s
}
```

Walking through the spec's own canonical example, `FAIL, PASS, PASS, PASS, FAIL` (5 runs, indices 0-4): `PassCount=3, FailCount=2`, the FAIL→PASS transition at i=1 is not a drift (wrong direction), the PASS→FAIL transition at i=4 is 1 drift with duration = `runs[4].At - runs[1].At` (the streak that started at the first PASS), `LongestPassStreak=3`, `LongestFailStreak=1`, `CurrentStreakResult="fail"`, `CurrentStreakLength=1`, `StabilityPercent=60`.

## 6. API surface

- **`GET /api/agents/{agentId}/checks/{checkId}/drift`** — runs the source query for this one `(agentId, checkId)` pair, calls `ComputeDriftStats`, returns the `DriftStats` directly. The core per-control view.
- **`GET /api/agents/{agentId}/drift-summary`** — enumerates every distinct `check_id` this agent has any `technique_verification_runs` row for, computes `DriftStats` per check, returns them sorted by `StabilityPercent` ascending (most-unstable first) plus an endpoint-level `overallStabilityPercent` (mean `StabilityPercent` across all this agent's controls).
- **`GET /api/drift-reports/summary`** — fleet-wide: enumerates every distinct `(agent_id, check_id)` pair with any row, computes `DriftStats` for each, and returns: top-drifting controls (sorted by `DriftCount` descending), controls that never drifted (`DriftCount == 0 && TotalRuns > 1`), controls currently drifting within the last 7 days (`CurrentStreakResult == "fail" && time.Since(*CurrentStreakStartedAt) <= 7*24*time.Hour` — directly from the new `CurrentStreakStartedAt` field, no re-walk of the raw sequence needed), and a monthly drift trend (count of drift-transition events bucketed by the month of the FAIL that caused each one). Naming matches Sub-project 5's existing `GET /api/remediation-reports/summary` precedent.

All three reuse `auth.CanExecuteRemediation` (read-level) — matches every other read endpoint across this initiative, no new permission.

## 7. Error handling

- **No verification history at all for a pair** (`TotalRuns == 0`) — `ComputeDriftStats` returns a zero-value `DriftStats` (all counts 0, `StabilityPercent 0`, `CurrentStreakResult ""`, both `*VerifiedAt` fields `nil`); the per-control endpoint still returns 200 with this zero-value payload rather than 404, since "no data yet" is a valid, common state (e.g. a control that has never opted into continuous validation).
- **Exactly one run** — no transition is possible, so `DriftCount = 0`; `LongestPassStreak`/`LongestFailStreak` reflect the single run's result; `CurrentStreakLength = 1`.
- **All error/skipped rows for a pair** (e.g. every dispatch hit an agent-not-connected or BAS-execution problem) — the SQL filter excludes them all, so the sequence passed to `ComputeDriftStats` is empty and this collapses to the "no verification history" case above, not a distinct error path.
- **Unknown `agentId`/`checkId` combination** with zero rows — same zero-value response as "no history," not a 404; there's no authoritative list of valid `(agentId, checkId)` pairs to validate against (a check_id only "exists" by virtue of a scenario step referencing it, which can change over time).

## 8. Testing

- **`ComputeDriftStats`**: pure unit tests, no DB, table-driven over the canonical sequences from §3's table plus: empty sequence, single-run sequence, a sequence with multiple drift events (verifying `AverageDaysUntilDrift` averages correctly across more than one relapse), and a sequence ending mid-fail-streak vs. mid-pass-streak (verifying `CurrentStreakResult`/`CurrentStreakLength`/`CurrentStreakStartedAt`).
- **Source-query normalization**: a DB-backed test seeding rows with `status` values across all 5 `models.CheckResult` values for one `(agent_id, check_id)` pair, asserting the returned `[]VerificationOutcome` contains exactly the pass/blocked/fail rows (blocked normalized to `"pass"`) in `completed_at` order, with error/skipped silently absent.
- **API handlers**: DB-backed tests for all three endpoints — the per-control endpoint against a seeded multi-drift sequence; the per-endpoint summary against multiple checks with differing stability; the fleet summary against multiple agents, verifying the "never drifted" and "drifted within 7 days" buckets and the monthly trend grouping. RBAC matrix rows for all three new routes.

## 9. Explicitly deferred

Category-based heatmap grouping is deferred pending a real `check_id → category` lookup being built for its own reasons elsewhere (not invented here solely for this report). Drift-event notifications are Phase 7. Any UI is out of scope for every sub-project in this initiative to date. `DriftStats` and `VerificationOutcome` have no structural blocker to either being added later.
