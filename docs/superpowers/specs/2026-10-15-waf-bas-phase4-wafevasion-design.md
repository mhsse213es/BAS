# WAF BAS Mastery Phase 4: Protocol, Parser and Evasion Testing — `internal/wafevasion` Design

**Status:** Approved for implementation under the user's standing authorization to complete all WAF BAS Mastery phases autonomously ("fix any critical or important findings then move to the next phase without approval start spec plan and native" / "keep going until all phases are done"). Condensed self-directed brainstorm — no interactive Q&A round; design decisions below are this session's own reasoned choices, made explicit for review.

## 1. Scope (from `waf.txt`)

> Phase 4 — Protocol, parser and evasion testing
> Validate encoding, normalization, content types, HTTP discrepancies, multipart uploads, and request-boundary behavior.

Phase 4 asks a different question than Phase 3. Phase 3 asked "did a *configuration* weakening cause a request the WAF used to block to get through?" Phase 4 asks "does re-expressing the *same* malicious payload through a different wire-level encoding cause the WAF to fail to recognize it, even though the policy never changed and the origin application still treats the re-expressed request as the identical attack?" That is a parser/normalization gap, not a policy gap, and it needs its own evaluation rule.

## 2. Package and dependency shape

New package `internal/wafevasion`, depending one-way on `internal/wafval` and `internal/wafcatalog` (both already merged):

```
wafval ← wafcatalog ← wafevasion
```

`wafevasion` does **not** depend on `internal/wafpolicygap` (Phase 3) — the two phases are independent consumers of the same two lower layers, not a chain. Neither `wafval` nor `wafcatalog` ever imports `wafevasion`. Fixture-backed only; no real HTTP, no real WAF/browser normalization behavior in this phase — real execution against a live WAF/browser to actually prove origin-equivalence is explicitly deferred (§11).

## 3. Why this isn't `wafval.Pair`/`EvaluatePolicyGap` again

Phase 3's `wafpolicygap` reused `wafval.Pair` and `wafval.EvaluatePolicyGap` unchanged because the two-leg comparison Phase 3 needed — a baseline leg and a weakened leg, with an explicit "the weakening was actually in force" confirmation flag — was *exactly* what Phase 1 had already built, under an attribution story ("is the gap attributable to the confirmed policy change?") that fit precisely.

Phase 4's two-leg comparison is also baseline-vs-other, but the *attribution story* is different: it's not "was the policy different between legs" (the policy never changes here), it's "does the origin application genuinely treat the evasive-encoded leg as the same attack as the canonical leg." `wafval.Pair`'s field is literally named `PolicyDifferentiationConfirmed` — reusing it here and setting it to mean something else would be a semantic lie baked into a shared type's field name. So Phase 4 defines its own pair-shaped comparison and its own decision rule, `EvaluateEvasionGap`, living entirely in `wafevasion` — never in `wafval`. This mirrors how `wafval.EvaluatePolicyGap` itself was domain logic built for Phase 1's specific need, not a generic primitive; Phase 4 is simply the next domain-specific rule built the same way, on the same `wafval.EvaluateClaim`/`Result` foundation.

## 4. Core types

```go
// EvasionTechnique is one of the six protocol/parser evasion categories
// waf.txt names, each a distinct way a malicious payload can be
// re-expressed at the wire level without changing what the origin
// application ultimately executes.
type EvasionTechnique string

const (
    EvasionEncodingObfuscation          EvasionTechnique = "encoding_obfuscation"
    EvasionNormalizationMismatch        EvasionTechnique = "normalization_mismatch"
    EvasionContentTypeConfusion         EvasionTechnique = "content_type_confusion"
    EvasionHTTPDiscrepancy              EvasionTechnique = "http_discrepancy"
    EvasionMultipartBoundaryManipulation EvasionTechnique = "multipart_boundary_manipulation"
    EvasionRequestBoundaryAbuse         EvasionTechnique = "request_boundary_abuse"
)
```

These map 1:1 onto waf.txt's six named items: encoding → `EvasionEncodingObfuscation`; normalization → `EvasionNormalizationMismatch`; content types → `EvasionContentTypeConfusion`; HTTP discrepancies → `EvasionHTTPDiscrepancy`; multipart uploads → `EvasionMultipartBoundaryManipulation`; request-boundary behavior → `EvasionRequestBoundaryAbuse`. Unlike Phase 3's `WeaknessType`, there is no paired/single-leg split here — every evasion technique is inherently a two-leg comparison (canonical payload vs. evasive-encoded payload against the same policy), so there is exactly one evaluation function (§6), not two.

```go
// EvasionScenario declares one evasion-technique claim against a specific,
// real AttackVector from internal/wafcatalog. OriginEquivalenceRationale is
// mandatory and distinct from the two payload descriptions: it is the
// documented reason the evasive encoding is expected to decode to the
// identical attack at the origin, the thing that makes a divergence in WAF
// behavior attributable to the technique rather than to a different attack.
type EvasionScenario struct {
    ID                          string
    Technique                   EvasionTechnique
    AttackVectorID              string
    CanonicalPayloadDescription string
    EvasivePayloadDescription   string
    OriginEquivalenceRationale  string
    Provenance                  string
}
```

`NewEvasionScenario(id, technique, attackVectorID, canonicalDesc, evasiveDesc, originEquivalenceRationale, provenance) (EvasionScenario, error)` validates at construction, mirroring `wafpolicygap.NewPolicyGapScenario`'s pattern exactly: every string field non-empty, `technique` one of the six constants, and `attackVectorID` cross-referenced against a real ID in `wafcatalog.AudspectWAFAttackCatalog()` — a fictional or retired vector ID is rejected here, never silently carried to evaluation time.

## 5. Catalog-wide validation

`ValidateEvasionCatalog(scenarios []EvasionScenario) error` rejects a catalog containing two scenarios with the same ID — the same single-purpose duplicate-ID guard as `wafcatalog.ValidateCatalog` and `wafpolicygap.ValidatePolicyGapCatalog`.

## 6. Evaluation

```go
func EvaluateEvasionGap(
    scenario EvasionScenario,
    vector wafcatalog.AttackVector,
    policyBasis string,
    canonicalEvidence []wafval.CollectionResult,
    canonicalKey wafval.CorrelationKey,
    evasiveEvidence []wafval.CollectionResult,
    evasiveKey wafval.CorrelationKey,
    originEquivalenceConfirmed bool,
) (wafval.Verdict, string, error)
```

Behavior:

1. If `vector.ID != scenario.AttackVectorID`, return an error (caller passed the wrong vector for this scenario — the same vector-match guard `wafpolicygap`'s two evaluation functions use).
2. Otherwise, take `vector.Expectations(policyBasis)[0].Expectation` (the malicious leg — always present per `wafcatalog.AttackVector.Expectations`'s contract) and call `wafval.EvaluateClaim` once per leg, producing `canonical wafval.Result` and `evasive wafval.Result`.
3. Apply the decision rule below, which lives entirely in this package and touches no `wafval` source file:

```go
func trustworthyBlocked(r wafval.Result) bool {
    return r.Verdict == wafval.VerdictBlocked &&
        (r.Confidence == wafval.ConfidenceHigh || r.Confidence == wafval.ConfidenceMedium)
}

func decideEvasionGap(canonical, evasive wafval.Result, originEquivalenceConfirmed bool) (wafval.Verdict, string) {
    if !originEquivalenceConfirmed {
        return wafval.VerdictInconclusive, "origin-equivalence of the evasive encoding not confirmed; differing responses not attributable to the evasion technique"
    }
    if !trustworthyBlocked(canonical) {
        return wafval.VerdictInconclusive, "canonical baseline did not establish a reliable block; evasive-leg behavior cannot be attributed to the evasion technique"
    }
    switch evasive.Verdict {
    case wafval.VerdictMissed:
        return wafval.VerdictMissed, "evasion bypass confirmed: canonical payload blocked, evasive-encoded equivalent neither detected nor blocked"
    case wafval.VerdictDetectedButAllowed:
        return wafval.VerdictDetectedButAllowed, "evasion-driven enforcement gap: evasive encoding still detected but not blocked"
    case wafval.VerdictBlocked:
        return wafval.VerdictBlocked, "no evasion gap demonstrated: evasive-encoded variant still blocked"
    default:
        return wafval.VerdictInconclusive, "evasive-leg outcome not attributable to the evasion technique"
    }
}
```

This is a deliberate structural echo of `wafval.EvaluatePolicyGap` (same shape: confirmation gate, then baseline-reliability gate, then a switch on the other leg's verdict) — consistent reasoning applied to a different attribution story, not a copy-paste of policy semantics. `trustworthyBlocked` is redefined locally because `wafval`'s own `trustworthyBlocked`/`confRank` helpers are unexported; redefining the two-line equivalent here is simpler and clearer than exporting internal ranking machinery from `wafval` for one caller.

A canonical leg that was never reliably blocked to begin with (e.g. the WAF didn't catch the attack even in its plain form) makes the evasion comparison moot — that is a Phase 2 coverage gap, not a Phase 4 finding — so it resolves to `Inconclusive`, never a false "no gap" or a false "bypass".

## 7. Seed catalog

`AudspectWAFEvasionCatalog() ([]EvasionScenario, error)` returns exactly 6 scenarios, one per `EvasionTechnique`, each referencing a real, already-existing Phase 2 vector ID:

| ID | Technique | AttackVectorID | Canonical / evasive sketch |
|----|-----------|-----------------|------------------------------|
| EVADE-001 | encoding_obfuscation | SQLI-002 | plain SQLi payload vs. double-URL-encoded equivalent |
| EVADE-002 | normalization_mismatch | PATHTRAV-001 | plain `../` traversal vs. Unicode/overlong-encoded path segments that normalize to the same traversal |
| EVADE-003 | content_type_confusion | FILEUP-001 | upload declared with its real executable content-type vs. a mislabeled benign-looking content-type for the same bytes |
| EVADE-004 | http_discrepancy | HTTPPARSE-002 | canonical direct TRACE request vs. the identical administrative operation via an `X-HTTP-Method-Override: TRACE` header on an outer POST, which the origin resolves to the same handler |
| EVADE-005 | multipart_boundary_manipulation | FILEUP-002 | canonical multipart boundary vs. a boundary string crafted to be parsed differently by the WAF than by the origin |
| EVADE-006 | request_boundary_abuse | HTTPPARSE-001 | canonical `Content-Length` request vs. a `Transfer-Encoding`/`Content-Length`-conflicting framing the origin still resolves to the same body |

All 6 `AttackVectorID`s are confirmed to exist in `wafcatalog.AudspectWAFAttackCatalog()`'s real 26-entry seed (`SQLI-002`, `PATHTRAV-001`, `FILEUP-001`, `HTTPPARSE-002`, `FILEUP-002`, `HTTPPARSE-001`). `HTTPPARSE-001`'s real payload is itself a Content-Length/Transfer-Encoding conflict (CL.TE request smuggling), which is exactly `EVADE-006`'s `request_boundary_abuse` story — not a generic header-discrepancy story — so it is bound to `EVADE-006`. `HTTPPARSE-002`'s real payload is HTTP verb tampering, an `http_discrepancy` story, so it is bound to `EVADE-004`. (This corrects an earlier draft of this table that had the two IDs swapped relative to their own narratives — caught in Phase 4's final review and fixed in both the spec and `catalog.go` together.)

## 8. Acceptance gate

1. `NewEvasionScenario` rejects: empty ID, unknown `Technique`, empty `AttackVectorID`, an `AttackVectorID` that does not exist in `wafcatalog.AudspectWAFAttackCatalog()`, empty `CanonicalPayloadDescription`, empty `EvasivePayloadDescription`, empty `OriginEquivalenceRationale`, empty `Provenance`.
2. `ValidateEvasionCatalog` rejects a catalog with two scenarios sharing an ID.
3. `EvaluateEvasionGap` returns an error when `vector.ID != scenario.AttackVectorID`.
4. With `originEquivalenceConfirmed = false`, `EvaluateEvasionGap` returns `Inconclusive` even when the canonical and evasive legs' fixture evidence visibly differ (canonical blocked, evasive allowed+undetected).
5. With `originEquivalenceConfirmed = true` and a canonical leg that was never reliably blocked (e.g. canonical itself allowed/undetected), `EvaluateEvasionGap` returns `Inconclusive`, not a false bypass claim.
6. With `originEquivalenceConfirmed = true`, a trustworthy-blocked canonical leg, and an evasive leg that is missed, `EvaluateEvasionGap` returns `VerdictMissed` with a non-empty evasion-attributed reason (EVADE-001 end-to-end).
7. `AudspectWAFEvasionCatalog` returns exactly 6 scenarios, one per distinct `EvasionTechnique`, all of whose `AttackVectorID`s resolve against the real catalog (guaranteed transitively by `NewEvasionScenario`'s construction-time cross-check).

## 9. Explicitly deferred

- Real execution against a live WAF and a real origin application to actually produce and verify matched canonical/evasive request pairs, and to establish true origin-equivalence rather than asserting it via `OriginEquivalenceRationale`.
- Expanding the seed catalog beyond one example per technique.
- Any new `wafval` verdict logic or type changes — this phase's decision rule lives entirely in `wafevasion`, built from `wafval.EvaluateClaim`'s existing output, exactly as `wafval.EvaluatePolicyGap` was itself domain logic built for Phase 1's specific need rather than a change to `wafval`'s evidence/correlation core.
- A single-leg ("coverage absence") evaluation path analogous to Phase 3's `EvaluateCoverageGapScenario` — every evasion technique is inherently a two-leg canonical-vs-evasive comparison, so no such path is needed in this phase.
