# WAF BAS Mastery Phase 3: Configuration and Policy-Gap Testing — Design Spec

## 1. Goal

Phase 3 is the third slice of the WAF BAS Mastery roadmap (`waf.txt` §3, Phase 3: "Configuration and policy-gap testing — find weak modes, exclusions, overly broad exceptions, missing coverage, priority conflicts, and unprotected routes"). It builds the layer that drives Phase 2's attack catalog (`internal/wafcatalog`, merged, `77a2df3c`) through Phase 1's already-built, not-yet-used two-leg policy-gap comparison (`wafval.Pair`/`wafval.EvaluatePolicyGap`, merged in Phase 1 but never called by anything outside `wafval`'s own unit tests until now).

Phase 1's own spec deferred exactly this: "the full attack-payload library (Phase 2) and all later roadmap phases," naming the policy-gap pair machinery's real consumer as future work. Phase 2's own spec made the division of labor explicit: `policy_misconfig` vectors stay single-leg; "supplying both legs of an actual baseline/weakened comparison is Phase 3's job, not this phase's." This spec is that job.

Same discipline as Phases 1-2: fixture-backed only. Nothing here claims a real WAF's policy was actually weakened — these are catalog-driven claims about configuration *correctness*, proven against fixture evidence.

## 2. Scope Boundary

| Component | Phase 3 decision |
|---|---|
| Policy-gap scenarios | Build: versioned, catalog-referencing, vendor-neutral |
| Evaluation logic | Reuse `wafval.Pair`/`EvaluatePolicyGap` and `wafval.EvaluateClaim` entirely — no new verdict logic |
| Weakness types covered | Detection-only mode, exclusion rules, overly broad exceptions, priority conflicts (paired); unprotected routes, missing coverage (single-leg) |
| Seed breadth | One scenario per weakness type (6 total) — proving the model, not exhaustive breadth |
| Validation | Fixture-backed only |
| Real execution | Out of scope — same deferral as Phases 1-2 |

## 3. Package and Dependency Direction

New package `internal/wafpolicygap`, depending one-way on both `internal/wafcatalog` (for `AttackVector`, `AudspectWAFAttackCatalog`) and `internal/wafval` (for `Pair`, `EvaluatePolicyGap`, `EvaluateClaim`, `Result`, `CollectionResult`, `CorrelationKey`, `Verdict`). Neither `wafval` nor `wafcatalog` ever imports `wafpolicygap` — the chain stays strictly one-way: `wafval` ← `wafcatalog` ← `wafpolicygap`.

## 4. Two Scenario Shapes

Not every named weakness type in `waf.txt` is a "baseline vs weakened" comparison. Detection-only mode, exclusion rules, overly broad exceptions, and priority conflicts all describe a policy that *used to* block something and was changed — a genuine two-leg comparison, which is exactly what `wafval.Pair`/`EvaluatePolicyGap` already models. Unprotected routes and missing coverage describe the *absence* of protection from the start — there is no "baseline" leg where it was ever covered; forcing these into the pair model would require a fabricated baseline that never existed. These resolve as a direct `wafval.EvaluateClaim` call instead, where a `Missed`/`Inconclusive` verdict against fixture evidence showing no WAF coverage *is* the finding.

```go
package wafpolicygap

// WeaknessType is one of the six configuration-gap categories waf.txt names.
type WeaknessType string

const (
	WeaknessDetectionOnlyMode     WeaknessType = "detection_only_mode"
	WeaknessExclusionRule         WeaknessType = "exclusion_rule"
	WeaknessOverlyBroadException  WeaknessType = "overly_broad_exception"
	WeaknessPriorityConflict      WeaknessType = "priority_conflict"
	WeaknessUnprotectedRoute      WeaknessType = "unprotected_route"
	WeaknessMissingCoverage       WeaknessType = "missing_coverage"
)

// IsPaired reports whether w is evaluated as a baseline-vs-weakened pair
// (via wafval.Pair/EvaluatePolicyGap) or as a single-leg coverage-absence
// check (via a direct wafval.EvaluateClaim call).
func (w WeaknessType) IsPaired() bool {
	switch w {
	case WeaknessDetectionOnlyMode, WeaknessExclusionRule, WeaknessOverlyBroadException, WeaknessPriorityConflict:
		return true
	default:
		return false
	}
}
```

## 5. The Scenario Entry Model

```go
// PolicyGapScenario declares one configuration-gap claim against a specific,
// real AttackVector from internal/wafcatalog. BaselinePolicyDescription
// describes the declared/expected policy state; WeakenedPolicyDescription
// describes the actual gap -- for a paired scenario, the weakening applied;
// for a single-leg scenario, what's actually missing.
type PolicyGapScenario struct {
	ID                        string
	Weakness                  WeaknessType
	AttackVectorID            string // must reference a real wafcatalog.AttackVector.ID
	BaselinePolicyDescription string
	WeakenedPolicyDescription string
	Provenance                string
}
```

`NewPolicyGapScenario(id string, weakness WeaknessType, attackVectorID string, baselineDesc, weakenedDesc, provenance string) (PolicyGapScenario, error)` validates at construction: `id`/`baselineDesc`/`weakenedDesc`/`provenance` non-empty; `weakness` is one of the six known constants; `attackVectorID` is non-empty **and references a real ID in `wafcatalog.AudspectWAFAttackCatalog()`** — the same cross-package construction-time validation `webgwefficacy.NewIndustryProfile` already uses against `AudspectWebGWCoverageReport()`. A scenario naming a fictional or retired vector ID is rejected, never silently carried.

## 6. Evaluation

Two functions, one per shape — a scenario's own `Weakness.IsPaired()` tells the caller which one applies; calling the wrong one for a scenario's shape is a caller error, returned not panicked.

```go
// EvaluatePairedScenario drives scenario's referenced vector's malicious leg
// through baseline and weakened evidence, then wafval.EvaluatePolicyGap.
// Returns an error if scenario.Weakness is not a paired weakness, or if
// vector.ID does not match scenario.AttackVectorID.
func EvaluatePairedScenario(
	scenario PolicyGapScenario,
	vector wafcatalog.AttackVector,
	policyBasis string,
	baselineEvidence []wafval.CollectionResult,
	baselineKey wafval.CorrelationKey,
	weakenedEvidence []wafval.CollectionResult,
	weakenedKey wafval.CorrelationKey,
	policyDifferentiationConfirmed bool,
) (wafval.Verdict, string, error)

// EvaluateCoverageGapScenario drives scenario's referenced vector's
// malicious leg through a single evidence set via wafval.EvaluateClaim,
// returning the raw Result for a single-leg weakness. Returns an error if
// scenario.Weakness is paired, or if vector.ID does not match
// scenario.AttackVectorID.
func EvaluateCoverageGapScenario(
	scenario PolicyGapScenario,
	vector wafcatalog.AttackVector,
	policyBasis string,
	evidence []wafval.CollectionResult,
	key wafval.CorrelationKey,
) (wafval.Result, error)
```

Neither function computes a verdict of its own — `EvaluatePairedScenario` calls `vector.Expectations(policyBasis)`'s malicious leg through `wafval.EvaluateClaim` twice (baseline, weakened), builds a `wafval.Pair`, and returns whatever `wafval.EvaluatePolicyGap` derives. `EvaluateCoverageGapScenario` calls the same malicious-leg `Expectation` through `wafval.EvaluateClaim` once. `wafpolicygap` is purely orchestration, same discipline as `wafcatalog`'s own "the catalog never derives a verdict itself."

## 7. Catalog-Wide Validation

```go
// ValidatePolicyGapCatalog rejects a catalog containing two scenarios with
// the same ID.
func ValidatePolicyGapCatalog(scenarios []PolicyGapScenario) error
```

## 8. Seed Scenario Catalog

One scenario per weakness type — six total, each referencing a real `wafcatalog` vector, proving the model rather than claiming exhaustive breadth (same honesty Phases 1-2 held about their own minimal/non-exhaustive slices):

| ID | Weakness | References | Why this vector |
|---|---|---|---|
| `GAP-001` | `detection_only_mode` | `POLICY-001` | Already built in Phase 2 specifically to probe detection-only misconfiguration |
| `GAP-002` | `exclusion_rule` | `SQLI-001` | A targeted per-rule exclusion added for this specific SQLi signature |
| `GAP-003` | `overly_broad_exception` | `POLICY-002` | Already built in Phase 2 specifically to probe an overly broad legacy-path exception |
| `GAP-004` | `priority_conflict` | `XSS-001` | A lower-priority allow-rule evaluated before the higher-priority block-rule for this signature |
| `GAP-005` | `unprotected_route` | `SSRF-001` | A route the WAF was never configured to sit in front of at all |
| `GAP-006` | `missing_coverage` | `API-001` | A newly added API route the policy was never updated to cover |

`AudspectWAFPolicyGapCatalog() ([]PolicyGapScenario, error)` builds these six via `NewPolicyGapScenario`, validated via `ValidatePolicyGapCatalog` before returning.

## 9. Testing Approach

Fixture-backed, same style as `wafcatalog`/`wafval`: hand-built `[]wafval.CollectionResult` per leg, feeding real catalog vectors through the two evaluation functions, asserting the derived verdict/reason. No real HTTP, no ModSecurity.

## 10. Acceptance Gate

1. `NewPolicyGapScenario` rejects an empty `ID`/`baselineDesc`/`weakenedDesc`/`provenance`, an unknown `Weakness`, and an `AttackVectorID` that does not exist in `wafcatalog.AudspectWAFAttackCatalog()`.
2. `ValidatePolicyGapCatalog` rejects two scenarios sharing the same `ID`.
3. `EvaluatePairedScenario` called with a single-leg (`IsPaired() == false`) scenario returns an error.
4. `EvaluateCoverageGapScenario` called with a paired (`IsPaired() == true`) scenario returns an error.
5. Either evaluation function called with a `vector.ID` that does not match `scenario.AttackVectorID` returns an error.
6. `EvaluatePairedScenario` against `GAP-001` (`POLICY-001`): baseline evidence shows blocked, weakened evidence shows allowed+undetected, `policyDifferentiationConfirmed=true` → `VerdictMissed`, with a policy-attribution reason (not a bare failed-prevention report).
7. `EvaluatePairedScenario` against the same scenario with `policyDifferentiationConfirmed=false` → `VerdictInconclusive`, even though the two legs' responses differ.
8. `EvaluateCoverageGapScenario` against `GAP-005` (`SSRF-001`) with evidence showing the request reached the origin with no WAF-engine coverage at all → `VerdictInconclusive` with insufficient completeness — the real finding being "this route has no WAF evidence to assess," not a false "missed."
9. `AudspectWAFPolicyGapCatalog()` returns exactly 6 scenarios, one per `WeaknessType`, passes `ValidatePolicyGapCatalog`, and every `AttackVectorID` it references resolves in `wafcatalog.AudspectWAFAttackCatalog()`.

## 11. Explicitly Deferred

- Real execution against a live WAF to actually weaken a policy and observe the gap.
- Expanding the seed scenario catalog beyond one example per weakness type.
- Any new wafval verdict logic — this phase adds zero behavior to `wafval` itself, only new callers of what Phase 1 already built.
