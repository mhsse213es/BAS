# SkipReason Reporting Breakdown — Design

## Context

The MaxPrivilege execution policy and its campaign-wide propagation (both 2026-07-20) introduced `models.SimulationResult.SkipReason` and its first value, `SkipReasonPolicyPrivilege`. But reports today lump every `Result=Skipped` entry into one undifferentiated `Reliability.Skipped` count (`internal/reporting/insights.go:buildReliability`), regardless of *why* a step was skipped. A run where 14 steps were deliberately excluded by an operator's privilege policy reads identically, in the report, to a run where 14 steps failed to execute because ART payload content was missing from the server — even though one is an intentional, policy-driven exclusion and the other is a content gap worth fixing.

This plan gives skips a proper cause taxonomy and a dedicated report section, so a constrained run reads as "compliant with policy," not "incomplete."

## What already exists vs. what's missing

Every non-policy skip in this codebase originates from one of six self-authored `"SKIP: ..."` marker messages, all constructed by our own server code (never third-party program output):

| Source | File | Message |
|---|---|---|
| ART missing payload | `internal/scenario/art.go:505-507` | "requires external payload(s) not available on server..." |
| ART technique not in local store (with OS) | `internal/scenario/builder.go:157` | "ART technique %s not in local store for %s" |
| ART technique not in local store (no OS) | `internal/scenario/builder.go:159` | "ART technique %s not in local store" |
| Malformed step, no command | `internal/scenario/builder.go:171` | "No command defined for step '%s'" |
| Caldera not configured | `internal/scenario/builder.go:255` | "Caldera not configured — set CALDERA_URL to enable ability %s" |
| Caldera ability not found | `internal/scenario/builder.go:269` | "Caldera ability %s not found" |

All six already produce `Result=Skipped` via `classifyExecution`'s `"SKIP:"` marker detection (`internal/scenario/outcome.go:162-164`), but none of them populate `SkipReason` — only the policy-privilege path (synthesized directly in `internal/api/handlers.go`) sets it today. `Interpret` (`internal/scenario/interpreter.go`) has no wiring to set `SkipReason` for any of the marker-based skips.

**Naming note:** the ERROR taxonomy already has an `ErrMissingPrerequisite` reason (`internal/scenario/outcome.go:31`) for a *different* outcome class entirely (a BAS execution problem, not a skip). This plan's bucket names avoid that word to prevent confusion between the two taxonomies.

## Goal

Every skip carries a `SkipReason` bucketed into one of three report-facing categories — **Policy**, **Content**, **Platform** — and reports show a dedicated Execution Summary breaking those out, with an executive-narrative sentence when policy skips are present.

## Architecture

### 1. Skip classification (`internal/models`, `internal/scenario`)

Two new plain-string constants, alongside the existing `SkipReasonPolicyPrivilege`, in `internal/models/schema.go`:

```go
// SkipReasonMissingContent marks a skip caused by content unavailable on the
// server (e.g. an ART atomic test's required payload was never staged).
const SkipReasonMissingContent = "missing-content"

// SkipReasonPlatformUnavailable marks a skip caused by an environment/tooling
// gap: the technique isn't available for the target OS, Caldera isn't
// configured, a referenced Caldera ability doesn't exist, or a step has no
// executable command at all.
const SkipReasonPlatformUnavailable = "platform-unavailable"
```

A new function in `internal/scenario/outcome.go`, styled exactly like the existing `classifyExecutionError`:

```go
func classifySkipReason(detail string) string
```

It pattern-matches the free-text after `"SKIP:"` (already extracted by `classifyExecution` into its returned `detail`) against the six known message shapes above, returning `models.SkipReasonMissingContent` or `models.SkipReasonPlatformUnavailable`. Because every one of those six messages is authored by our own code — not unpredictable third-party output — this is a small, fully-enumerable vocabulary, not a fragile heuristic; the same style of matching already works safely for `classifyExecutionError`.

`interpretART`, `interpretCaldera`, and `interpretCustom` (`internal/scenario/interpreter.go`) are extended to also return a skip reason when `OutcomeSkipped`/a `"skip:"` prefix is detected, and `Interpret` sets it on the returned `models.SimulationResult.SkipReason`. The existing policy-privilege path (`synthesizePolicySkipResult` in `internal/api/handlers.go`) is untouched — it already sets `SkipReason` directly and bypasses marker-text classification entirely.

Note: `synthesizePolicySkipResult` constructs its own `"SKIP: requires %s privilege, execution policy caps at %s"` marker text (`handlers.go:901`) and passes it through `scenario.Interpret` (`handlers.go:903`) before explicitly overwriting `sim.SkipReason = models.SkipReasonPolicyPrivilege` immediately afterward (`handlers.go:904`). That marker text is **not** one of the six shapes `classifySkipReason` needs to recognize — if it falls through to the empty/unclassified case inside `Interpret`, that's fine, since the explicit overwrite on the very next line always wins. Do not add a seventh case for it.

### 2. Reporting (`internal/reporting`)

A new fixed-field struct in `engine.go`, styled exactly like the existing `PrivilegeSummary` (explicit JSON tags — required for garble safety per this codebase's established `html/template` rendering approach, not a `map[string]int`):

```go
// SkipBreakdown counts Result=Skipped entries by SkipReason across a report's
// results, so a policy-constrained run reads as "compliant," not "incomplete."
type SkipBreakdown struct {
	Policy   int `json:"policy"`
	Content  int `json:"content"`
	Platform int `json:"platform"`
}
```

A new `buildSkipBreakdown(results []models.SimulationResult) SkipBreakdown` counts `Result=Skipped` entries by `SkipReason`, unrecognized/empty reasons falling into `Platform` (the closest fit — an unclassified skip is still an environment gap, not a policy decision). Wired into `Report` at the same three call sites `PrivilegeSummary` already uses (single-agent report, scoped report, campaign report — `engine.go` lines ~1291, ~1566, ~1753), so every report type gets it for free, identically to how `PrivilegeSummary` already works.

### 3. New "Execution Summary" HTML section (`internal/reporting/html.go`)

A new section placed near the top of the report (before "Top Risk Drivers"), showing:

```
Execution Summary

Executed:               {{.summary.passedTechniques + .summary.failedTechniques}}
Succeeded:               {{.summary.passedTechniques}}
Failed:                  {{.summary.failedTechniques}}

Skipped (Policy):        {{.skipBreakdown.policy}}
Skipped (Content):       {{.skipBreakdown.content}}
Skipped (Platform):      {{.skipBreakdown.platform}}
```

`Executed`/`Succeeded`/`Failed` reuse the already-existing `ExecutiveSummary.PassedTechniques`/`.FailedTechniques` fields (no duplication). The existing "Simulation Reliability" table (Attempted/Valid/Errored/Skipped, `html.go:1257-1265`) is untouched — it answers a different question (how much to trust the data), not "what happened and why."

### 4. Executive narrative (`internal/reporting/insights.go`)

`buildExecutiveConclusion` gains one more sentence, appended only when `SkipBreakdown.Policy > 0`:

> "14 techniques requiring administrative privileges were intentionally excluded by the execution policy."

Content and Platform skips get no narrative sentence — they show in the Execution Summary table, but they're environment facts, not an operator decision worth narrating. The count uses a plain `%d` numeral, matching every other count in this function (e.g. `"%d unprevented techniques executed without any detection alert"`) — the function never spells out numbers.

## Non-goals (explicitly deferred)

- Coverage math (eligible-vs-total step counts) — separate, already-scoped follow-up.
- Any change to `ComputeScore` / `models.Score` — skips are already correctly excluded from scoring; this plan only adds descriptive breakdown, not a scoring change.
- Any change to the existing "Simulation Reliability" table.
- Retroactive reclassification of already-persisted `SimulationResult` rows — `SkipReason` classification happens at `Interpret` time (when a result is first produced), not as a backfill migration on historical data. Old runs' skips will show as `Platform` (the empty-reason fallback) in reports generated after this change, not retroactively reclassified.

## Testing approach

Unit tests for `classifySkipReason` (table-driven, one case per known message shape, matching `classifyExecutionError`'s existing test style) and for `buildSkipBreakdown` (a handful of `SimulationResult`s with each `SkipReason` value, assert correct bucket counts including the empty-reason-falls-to-Platform case). An HTML-rendering test confirming the Execution Summary section renders the right numbers for a report with a mix of all three skip types, following the existing `html_test.go`/`html_robustness_test.go` patterns.
