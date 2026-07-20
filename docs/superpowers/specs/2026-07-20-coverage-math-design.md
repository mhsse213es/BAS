# Coverage Math (Scenario vs. Eligible Coverage) — Design

## Context

Reports today show techniques as PASS/FAIL/ERROR/SKIPPED counts, but nothing tells an operator what fraction of a scenario's steps were actually attemptable under the run's execution policy. A 40-step scenario constrained to `MaxPrivilege: user` that eligibly runs 26 steps — all of which succeed — currently has no way to be distinguished, in a report, from a broken run that only managed to execute 26 of 40 steps due to a real problem. Both would just show "26 executed." This plan closes that gap with two coverage ratios: **Scenario Coverage** (executed ÷ everything the scenario defines) and **Eligible Coverage** (executed ÷ what was actually attemptable after policy filtering) — so a deliberately constrained run reads as complete, not broken.

## Definitions

- **Total**: base-technique count right after `scenario.BuildSteps` resolves the run's configuration (`internal/api/handlers.go:1076`) — reflects any operator-selected technique/step subset for that specific run, but is captured *before* the lab-only fidelity drop (`handlers.go:1086-1104`) and *before* the MaxPrivilege filter (`handlers.go:1111-1148`). Nothing persists this number today.
- **Eligible**: base-technique count after *both* of those filters run, but *before* variant expansion (`handlers.go:1150-1160`). Also not persisted today — the lab-only drop and policy-skip counts are only logged/reflected indirectly (via `policy_skipped_results`'s array length), never stored as a single "what's left" number.
- **Executed**: distinct base techniques with at least one settled result (Pass/Fail/Error/Skipped-non-policy) in the run's persisted `results`. Computed at report time, not persisted — reuses the same `Technique.ID` grouping key `groupResultsByTechnique` (`internal/reporting/engine.go:1931`) already uses to collapse repeated/variant results for the same technique into one entry, so variant-expanded steps (which multiply one base technique into several dispatched steps, each producing its own result) correctly collapse back to a single "this technique was executed" count instead of over-counting.

**Scope boundary:** all three numbers are base-technique counts. Variant expansion (encoding × privilege × exec-context multiplication) is deliberately excluded from this feature's arithmetic — it already has its own dedicated "Variant Coverage Analysis" report section with its own counts. Mixing the two would make this feature's numbers read confusingly (e.g. "260/260" instead of "26/26" on a 10×-variant-expanded run) and duplicate an existing report section's job.

## Architecture

### 1. Capture at dispatch time (`internal/api/handlers.go`)

Two new integer columns on `scenario_runs`: `steps_total_base int NOT NULL DEFAULT 0` and `steps_eligible_base int NOT NULL DEFAULT 0`. `dispatchRun` captures and persists both once, mirroring the exact precedent `policy_skipped_results` already established (write once at dispatch, read at report time — no retroactive backfill for historical runs, same as that column):

- `steps_total_base` = `len(steps)` immediately after `BuildSteps` returns.
- `steps_eligible_base` = `len(steps)` immediately after the MaxPrivilege filter block completes (i.e., after both the lab-only drop and the policy filter have run), still before variant expansion.

Both writes happen via the same `h.db.Exec` pattern already used for `policy_skipped_results` and `step_meta` in this function — no new persistence mechanism, just two more columns following the identical write pattern.

### 2. Compute "Executed" and the two ratios at report time (`internal/reporting`)

The reporting engine's existing `scenario_runs` SELECT queries (the ones that already populate `FullReport` fields like `PrivilegeSummary`'s inputs, at the same three call sites in `engine.go` — single-agent, scoped, and campaign report) are extended with the two new columns, stored directly on `FullReport`. A new report-time function then combines those two stored counts with `Executed` — derived from `results` using the existing `Technique.ID`-based grouping already proven by `groupResultsByTechnique` — into a small struct with both raw counts and their percentages. It's wired into `deriveExecutive` (`internal/reporting/insights.go:426`) exactly the way `SkipBreakdown` was: that function already runs once per report (single-agent, scoped, and campaign all call it) and already receives `results` as a parameter, so it's the same single integration point already proven for this pattern — it just also needs the two new `FullReport` fields to already be set by the time it runs, same as every other field `deriveExecutive` reads.

### 3. Report placement (`internal/reporting/html.go`)

Extends the **same "Execution Summary" section** built in the SkipReason reporting work (your own framing put these together):

```
Execution Summary

Executed:               26
Succeeded:               24
Failed:                   2
Skipped (Policy):        14
Skipped (Content):        0
Skipped (Platform):       0

Scenario Coverage:   26/40
Eligible Coverage:   26/26 (100%)
```

## Non-goals (explicitly deferred)

- Variant-expanded step counts — the existing Variant Coverage Analysis section already owns that.
- Retroactive backfill of `steps_total_base`/`steps_eligible_base` for historical runs — like `policy_skipped_results`, these are dispatch-time-only captures. Both columns default to `0` for rows that predate this change, meaning old runs will render `0/0` (both ratios computed as 0-over-0) until re-run — the report layer must treat a `0/0` denominator as "coverage data not available for this run," not "0% coverage."
- Any change to `ComputeScore` / `models.Score` — coverage is a descriptive completeness metric, not a security score input.
- No separate design needed for campaign-level aggregation — it falls out of the existing pattern automatically. `BuildFromCampaign` (`engine.go:1712`) already loops per child `scenario_runs` row and pools every child's `results` into one `allResults` slice before calling `deriveExecutive` — the whole Execution Summary section (Executed/Succeeded/Failed/Skipped) is already a campaign-wide aggregate, not per-run, whenever it's built this way. `steps_total_base`/`steps_eligible_base` follow the identical shape: add both columns to that same per-row `SELECT`, sum them in the same loop that already accumulates `allResults`, and the two new coverage ratios are campaign-wide aggregates for free, consistent with every other number already in that section.

## Testing approach

Unit tests for the dispatch-time capture (extending the existing `TestRunScenarioIntegration_MaxPrivilegeFiltersStep`-style integration tests to assert the two new columns land correctly for a mixed eligible/policy-filtered run), and for the report-time ratio computation (table-driven, covering: no filtering at all, lab-only-only filtering, policy-only filtering, both filters combined, and a run where dispatched-but-never-returned steps make Executed < Eligible). An HTML-rendering test confirms the two new Execution Summary rows render the right numbers, following the same pattern used for the SkipReason breakdown's rendering test.
