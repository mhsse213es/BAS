# Actor Coverage Breakdown — Design

**Status:** Approved 2026-08-11
**Scope:** New section on the existing Threat Prioritization actor detail view. No new tab, no new engine, no new fleet-wide dashboard tile — a pure read-path addition over data that already exists.

## Problem

The user's original feedback distinguished "Threat Prioritization" (ranking actors by composite score, which `internal/threatpriority` already does) from a separate question: for a given actor, what is our concrete coverage posture against their techniques, broken down clearly enough to see *where* the gaps are?

Investigating before designing anything turned up two things:

1. **Naming collision.** "Exposure" already means two unrelated things in this codebase: `internal/analytics.FleetExposure`/`ExposureSummary` (asset/attack-path-centric, per-endpoint `ExposureScore` + `CriticalityRisk`) and `internal/predict`'s `ExposureWindows` (open-finding staleness). The existing code even flags this explicitly in a comment: *"unrelated to the graph/asset-based exposure above — a 3rd, distinct 'exposure' concept."* A new actor/technique concept called "Threat Exposure" would be a fourth, unrelated meaning. This view is named **Actor Coverage Breakdown** instead — it names what it actually is, with no collision anywhere in the codebase.
2. **Most of the underlying data already exists**, just not assembled per-technique:
   - "Relevant" — `threatpriority.RelevanceFactor` (sector/region overlap, binary) already scores this, folded into the composite.
   - "Has content" — `coverage.BuildSimulationIndex`/`BuildProfileIndex`/`BuildComplianceIndex` already exist, but `ThreatPriorityActorDetail` (`internal/api/threatpriority_handlers.go:42-74`) only uses them to build a flat `UncoveredTechniques []string` — a technique either has *some* content or it's in that list. Nothing distinguishes *what kind* of content, or separates "has content" from "has been run."
   - "Tested" / "Detected" — `threatpriority.LoadPreventionVerdicts` (real `scenario_runs` outcomes) and `LoadValidationVerdicts` (real `verification_history` outcomes) already exist and are already exported specifically for outside consumers (`internal/correlation` already uses them this way). They're computed inside `Engine.buildSharedIndexes` and folded into aggregate `PreventionSuccessFactor`/`ValidationSuccessFactor` scores and a `ValidatedCount` — but never surfaced per-technique.
   - "Gap" — `UncoveredTechniques` only captures "zero content at all." It does not distinguish "has content but was never run" from "was run but never detected" — both are real gaps today, with different remediations, and both currently vanish into the same undifferentiated non-list (a technique with content but no verdict simply doesn't appear in `UncoveredTechniques`, and its more specific gap state is invisible).

## Goal

Give the actor detail view a per-technique breakdown table: for each technique in the actor's roster, show whether it has content, and — if it does — whether it's been tested (prevention verdict) and/or detected (detection verdict), using data the engine already computes. Make the "has content but never run" and "run but not detected" gap states visible, where today they're both invisible.

## Non-goals

- **No new fleet-wide dashboard tile.** A rollup like "X% of top-actor techniques have zero test coverage" is a reasonable follow-on, but out of scope here — this project is the per-actor detail table only.
- **No new scoring engine or new composite factor.** This is a read-path addition. `internal/threatpriority`'s scoring, weights, and composite calculation are untouched.
- **No change to `UncoveredTechniques`.** It stays exactly as-is for backward compatibility; the new breakdown is additive on the same response.
- **No change to `internal/analytics`'s existing "exposure" concepts**, and no reuse of the word "exposure" anywhere in this project's naming (types, JSON fields, UI labels) — the whole point is avoiding the collision.

## Design

### Data model

```go
// TechniqueCoverage is one technique's coverage-breakdown row for a given
// actor -- what content exists for it, and what real outcomes (if any)
// have been recorded.
type TechniqueCoverage struct {
	TechniqueID       string `json:"techniqueId"`
	TechniqueName     string `json:"techniqueName,omitempty"`
	HasSimulation     bool   `json:"hasSimulation"`
	HasDetection      bool   `json:"hasDetection"`
	HasCompliance     bool   `json:"hasCompliance"`
	PreventionVerdict string `json:"preventionVerdict,omitempty"` // scenario_runs result, e.g. "pass"/"fail" -- "" if never run
	DetectionVerdict  string `json:"detectionVerdict,omitempty"`  // verification_history result, "Detected"/"NotDetected" -- "" if never verified
	Status            string `json:"status"` // "gap-no-content" | "untested" | "has-outcomes"
}
```

`Status` is derived, in this priority order, so the UI can render a single clear label per row without re-deriving the logic client-side:

1. **`gap-no-content`** — none of `HasSimulation`/`HasDetection`/`HasCompliance` are true.
2. **`untested`** — has content, but both `PreventionVerdict` and `DetectionVerdict` are empty (no `scenario_runs` result and no `verification_history` result exist for this technique fleet-wide).
3. **`has-outcomes`** — has content and at least one of `PreventionVerdict`/`DetectionVerdict` is set. Prevention and Detection are independent and both shown when present — they answer different questions (did a control block it vs. did the stack alert on it), and a technique can have one without the other.

### Backend

New function in `internal/api/threatpriority_handlers.go` (same file `UncoveredTechniques` is already built in, since it consumes the same three coverage indexes):

```go
// buildTechniqueCoverage computes the per-technique coverage-breakdown row
// for each of an actor's techniques, using the same coverage indexes
// UncoveredTechniques already relies on, plus real prevention/detection
// verdicts (threatpriority.LoadPreventionVerdicts/LoadValidationVerdicts,
// already exported for exactly this kind of external read). Pure function
// -- no new DB queries beyond the two verdict loads, no scoring changes.
func buildTechniqueCoverage(
	techIDs []string,
	sim, detect, compliant map[string]bool,
	prevention, validation map[string]threatpriority.VerdictEntry,
) []TechniqueCoverage
```

`ThreatPriorityActorDetail` calls `threatpriority.LoadPreventionVerdicts(ctx, h.db)` / `LoadValidationVerdicts(ctx, h.db)` (both already public, already used this way by `internal/correlation`) alongside the existing `coverage.Build*Index` calls, then calls `buildTechniqueCoverage` and adds the result to the response:

```go
type threatPriorityActorDetail struct {
	threatpriority.ActorPriority
	History             []threatpriority.ActorPriorityHistory `json:"history"`
	UncoveredTechniques []string                              `json:"uncoveredTechniques"`
	TechniqueCoverage   []TechniqueCoverage                    `json:"techniqueCoverage"`
}
```

Technique names come from `attackdata.Lookup(id)` (already the standard way technique names are resolved elsewhere), best-effort — an unrecognized ID just leaves `TechniqueName` empty rather than erroring.

### Frontend

A new table section in `renderThreatPriorityDetail` (`orchestrator/wwwroot/index.html`), placed after the existing Factors section and before History: one row per `TechniqueCoverage` entry — Technique ID/Name, small icons or badges for Simulation/Detection/Compliance content, then Prevention and Detection verdict cells (blank/dash when not yet tested). Reuses existing badge/tag CSS classes already used elsewhere in this view (`tool-tag`, `tiny muted`) rather than introducing new styling.

## Testing

- `buildTechniqueCoverage`: pure function, fully unit-testable without a DB —
  1. A technique with no content in any index → `gap-no-content`.
  2. A technique with content but no verdicts in either map → `untested`.
  3. A technique with a prevention verdict only → `has-outcomes`, `DetectionVerdict` empty.
  4. A technique with a detection verdict only → `has-outcomes`, `PreventionVerdict` empty.
  5. A technique with both → `has-outcomes`, both verdicts populated.
- `ThreatPriorityActorDetail` handler: extend existing test coverage to confirm `TechniqueCoverage` is present and non-nil in the response, and that `UncoveredTechniques` is unchanged (regression — proves this is additive).

## Relationship to prior work

This is the "other" project from the user's original architecture-feedback document, deferred until after the two actor-identity-resolution projects (alias-aware `MergeActors`, commit `3e6d5e8`; canonical MITRE Group-ID layer, commits `f0c8405`..`9266b48`) shipped. It does not depend on either — it reads `ThreatActor`/`ActorPriority` data as already produced by those projects, unmodified.
