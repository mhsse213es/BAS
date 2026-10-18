# dlpcorrelate Campaign 06 (Business Continuity vs. Data Protection) — Design Spec

## Intent

Closes `dlp.txt` §3C's Campaign 06:

> **Business continuity versus data protection.** Test legitimate business workflows alongside prohibited disclosure cases → verify authorized collaboration succeeds → verify restricted actions remain blocked → measure false positives and operational friction. Prevents a misleading maturity score based solely on aggressive blocking.

## Why this reuses Campaign 03's scenario-differentiation shape directly

Campaign 03's own spec (`2026-10-18-dlpcorrelate-campaign03-design.md`) named this exact reuse as a future opportunity: "a future Campaign 06 wrapper... not built in this slice." Re-reading Campaign 06's text confirms the fit is exact, not approximate: "legitimate business workflows" are cases where `ExpectedToSucceed: true`, "prohibited disclosure cases" are cases where `ExpectedToSucceed: false`, "verify authorized collaboration succeeds" is `OverBlocking` detection (a legitimate case wrongly blocked), "verify restricted actions remain blocked" is `UnderBlocking` detection (a prohibited case wrongly let through), and "measure false positives and operational friction" is exactly what `OverBlocking`'s existing `Reason` string already reports (count of legitimate cases wrongly blocked). No new aggregate type, no new verdict vocabulary — this is `scenariodifferentiation.go`'s `ScenarioCase`/`DifferentiationVerdict`/`EvaluateScenarioDifferentiation` consumed as-is.

## Why this campaign's wrapper signature differs from Campaign 03's

Campaign 03's own wrapper, `Campaign03EmailPolicyAndExceptionFailure(normalDelivery, justifiedOverride, unauthorizedSharing ScenarioCase)`, takes exactly 3 fixed, individually-named cases because its own `dlp.txt` text names 3 specific scenarios. Campaign 06's text instead speaks in the plural throughout ("workflows", "cases") with no fixed count — it describes a *category* of legitimate workflows tested alongside a *category* of prohibited cases, not 3 named roles. `Campaign06BusinessContinuityVersusDataProtection` therefore takes two slices, `legitimate []ScenarioCase` and `prohibited []ScenarioCase`, rather than 3 fixed parameters.

## A new, Campaign-06-specific correctness check

Because the caller supplies which bucket (`legitimate` vs. `prohibited`) each case belongs to as well as that case's own `ExpectedToSucceed` field, the two could be authored inconsistently — a case placed in `legitimate` with `ExpectedToSucceed: false` set on it (or vice versa) would be a scenario-authoring mistake, not a real DLP finding, and should not be silently passed through to `EvaluateScenarioDifferentiation` as if it were a genuine under/over-blocking result. `Campaign06BusinessContinuityVersusDataProtection` validates this consistency before delegating, returning an error (never a fabricated verdict) when a case's `ExpectedToSucceed` contradicts the bucket it was placed in. Campaign 03's 3-fixed-param wrapper has no equivalent check because its own call sites fix each case's `ExpectedToSucceed` inline at the call — Campaign 06's slice-based signature doesn't have that same syntactic guarantee, so the check is added here specifically.

## What already exists and is reused, unmodified

- `internal/dlpcorrelate/scenariodifferentiation.go`'s `ScenarioCase`/`DifferentiationVerdict`/`ScenarioDifferentiationResult`/`EvaluateScenarioDifferentiation` (Campaign 03's own core) — reused as-is, zero changes.

## Goals

1. `Campaign06BusinessContinuityVersusDataProtection(legitimate, prohibited []ScenarioCase) (ScenarioDifferentiationResult, error)` — validates bucket/`ExpectedToSucceed` consistency (returns an error naming the offending case's `Label` on mismatch), concatenates `legitimate` and `prohibited` into one slice, and delegates to the existing `EvaluateScenarioDifferentiation`.

## Non-goals

- No new verdict type, no new `ScenarioCase` field — Campaign 03's existing vocabulary covers this campaign's text exactly.
- No new scenario YAML, no wiring into the real run/report pipeline.
- No change to `scenariodifferentiation.go` itself.

## Anti-goals

- Must not duplicate `EvaluateScenarioDifferentiation`'s classification logic under a new name — this wrapper only validates inputs and delegates.
- Must not silently accept a case whose `ExpectedToSucceed` contradicts its bucket — that is a scenario-authoring bug and must surface as an error, not get folded into the differentiation verdict as if it were real evidence.

## What's left to the builder

- Exact error message text for the bucket-consistency check.
- Empty-slice handling for either bucket: delegate to `EvaluateScenarioDifferentiation`'s own existing empty-input handling (it already returns an error on a fully empty input; a single non-empty bucket is a valid, if one-sided, differentiation test).
