# dlppolicy — DLP-POL: Policy integrity and scope

## Intent and why

DLP Mastery's five completed priorities (`dlpprofile`, `dlpfixture`, the `dlp.go` evidence extension, the NOT_TESTED resolver, the Purview/Trellix connector clients) all test **channel exfiltration behavior**: can synthetic sensitive data leave through channel X, and was it blocked. None of them test whether the **DLP policy itself is configured correctly** — the right data in scope, the right precedence when rules overlap, the right mode (enforce vs audit-only), the right rollout to every site/OU/tenant. dlp.txt names this gap explicitly as its own scenario family, **DLP-POL** (lines 155-161), and the user has locked it as the first of three new evaluation dimensions (DLP-POL → DLP-CLS → DLP-ENF), explicitly as "the largest foundational gap": channel-exfiltration simulations already exist, but nothing yet proves the policies behind them are correctly scoped, prioritized, or rolled out.

This package tests **configuration state**, never enforcement outcome. "Did this policy's own declared scope/mode/precedence/rollout match what it should be" is this package's entire job. "Did a real exfiltration attempt actually get blocked" stays `internal/reporting/dlp.go`'s job (DLP-ENF's eventual territory) — the two are never merged into one evidence model. This separation is a locked, non-negotiable requirement from the user, not a judgment call.

## Goals

1. Cover all six DLP-POL concerns from dlp.txt (scope/exclusions; precedence/overlapping policies/exception inheritance/conflicting actions; audit-only mistaken for enforcement; disabled/expired/unpublished/incompletely-deployed rules; cross-OU/site/tenant variance; propagation delay/stale endpoint config) in this one design, sequenced into two implementation slices — not postponed, not split into separate specs.
2. Resolve the key architecture question up front: build a model where a single rule's own configuration state and a multi-rule precedence/multi-scope variance evaluation are both first-class, neither forced into an awkward shape built for the other.
3. Reuse the proven `internal/emailgwefficacy`/`internal/webgwefficacy` pattern (declared `Expectation`, fixture-backed `EvidenceProvider` interface a real connector can satisfy later, single-dimension `VerdictDetail` with `ConfirmedSuccess`/`ConfirmedFailure`/`Inconclusive`/`NotTested`/`NotApplicable`) rather than inventing a new verification vocabulary.
4. Every result must be honestly labeled fixture-backed vs. vendor-verified (`EvidenceSource`), and missing/ambiguous evidence must default to `Inconclusive`, never a pass.

## Non-goals (explicitly out of scope for this package)

- **DLP-CLS and DLP-ENF are not built here.** This package is DLP-POL only. Whether `dlppolicy`'s foundation types get reused or independently reimplemented by DLP-CLS/DLP-ENF is their own future decision, made when they're actually scoped — not speculated on now.
- **No vendor connector wiring.** `internal/vendors/purview`/`internal/vendors/trellixdlp` are not called from this package. Every evidence provider in this design is fixture-backed; a real connector satisfying the same provider interface is separate future work, same posture as every other DLP Mastery priority so far.
- **No general policy-resolution engine.** This package never independently re-computes which rule "should" win a precedence conflict from first principles. That computation is the real DLP product's job; this package only declares an expected resolution and compares it against evidence of what the product actually reported.
- **No scenario YAML authored in this slice.** This design produces a tested Go library (types + evidence providers + verify functions), matching how `dlpfixture`/the `dlp.go` evidence extension were built as pure libraries first. Scenario content gets added later, and only where a scenario tests a materially distinct client-facing claim — not one scenario mechanically per concern.
- **No cross-import with `internal/emailgwefficacy`/`internal/webgwefficacy`.** The verification vocabulary (`VerdictDetail`, `EvidenceSource`, `Provenance`) is re-implemented independently in this package, following the identical, explicitly locked precedent those two packages already set for each other ("any cross-package relationship this initiative ever takes on borrows a structural pattern, never a shared type" — `emailgwefficacy/types.go:6-9`).

## Anti-goals (would make this a failure even if it "works")

- Presenting a fixture-backed result as proof a real vendor tenant is correctly configured. Every evidence record's `Source` field must make this impossible to miss.
- Treating a documented, intentional cross-OU policy difference (e.g. an EU subsidiary's stricter residency rule) as a finding. The variance evaluator must be able to say "this difference is accounted for" without the caller hand-suppressing it ad hoc.
- Collapsing "the right rule won but did the wrong thing" and "the wrong rule won" into one undifferentiated precedence failure — a reader needs to know which.
- Building six independent, overlapping evaluators because six bullets were listed. The six concerns resolve to four implementation surfaces (below) by design, not because scenario count was minimized for its own sake, but because several concerns are genuinely the same evaluation shape at different scope breadths.

## Constraints

- Follow `internal/emailgwefficacy/policybaseline.go`'s proven shape: a declared `Expectation`, a fixture-backed `EvidenceProvider` interface, a deterministic `Verify...(exp, provider, window, asOf) VerdictDetail` function with `asOf` as an explicit parameter (never `time.Now()` read internally).
- Every `Verify...` function must default to `Inconclusive` when evidence is absent, and must never infer a pass from absence.
- Every evidence type carries `Source EvidenceSource` and `Provenance Provenance`, matching `emailgwefficacy/types.go`'s vocabulary (independently defined in this package, not imported).
- No field, scenario, or fixture may use a real customer tenant name, OU path, or identifier — synthetic/lab values only, same discipline as every other DLP Mastery package.

## Builder's call (decided here, not re-litigated)

**The package is `internal/dlppolicy`.** New, standalone, no import of `internal/dlpfixture`, `internal/reporting`, `internal/emailgwefficacy`, or `internal/webgwefficacy`.

**The six concerns resolve to four implementation surfaces across two slices**, by recognizing that "incomplete deployment" (bullet 4) and "cross-OU/site/tenant variance" (bullet 5) and "propagation delay" (bullet 6) sit at different scope breadths rather than needing three separate evaluators — concretely:

| dlp.txt concern | Implementation surface | Slice |
|---|---|---|
| 1. Scope vs. excluded locations/users/devices/groups | `DLPPolicyRuleExpectation` (scope fields) | 1 |
| 3. Audit-only mistaken for enforcement | `DLPPolicyRuleExpectation` (mode field) | 1 |
| 4. Disabled/expired/unpublished rules *(single scope's own copy)* | `DLPPolicyRuleExpectation` (enabled/expiry/published fields) | 1 |
| 6. Propagation delay / stale endpoint config *(single scope's own freshness)* | `DLPPolicyRuleExpectation` (freshness fields) | 1 |
| 2a. Precedence, overlapping policies, conflicting actions | `DLPPolicyPrecedenceExpectation` (new multi-rule primitive) | 2a |
| 2b. Exception inheritance *(a parent/child scope relationship, not a multi-rule one)* | Slice 1's exception fields (incl. branch 9 below) evaluated once per scope, diffed by Slice 2b | 1 + 2b |
| 4 (remainder: "incompletely deployed" = multi-scope) + 5. Cross-OU/site/tenant variance | `DLPPolicyVarianceExpectation` (new multi-scope primitive, wraps either Slice-1 or Slice-2a results) | 2b |

**Note on "exception inheritance" (builder's call, added after builder-check review):** the original draft assigned this whole sub-clause to Slice 2a, but Slice 2a's evidence shape (which *rule* wins a *precedence* conflict) has nothing to do with whether an exception on one scope correctly propagates — or correctly doesn't — to a child scope. Inheritance is actually a two-*scope* comparison, the same shape Slice 2b already generalizes: declare each scope's own expected exception state in its own `DLPPolicyRuleExpectation` (set `ExceptionExpiresAt` where inheritance is expected, leave it `nil` where it is not), run Slice 1 per scope, then run Slice 2b across the parent/child pair. Slice 1's new branch 9 (below) is what makes this actually catch a real inheritance failure — without it, a scope with an undeclared-but-active exception would silently pass rather than surface as a mismatch for Slice 2b to compare.

### The key architecture decision: two orthogonal layers, not one forced hierarchy

**Layer A — atomic expectations** (Slice 1's `DLPPolicyRuleExpectation`, Slice 2a's `DLPPolicyPrecedenceExpectation`): each is a sibling, not a special case of the other. A single rule's own state and a set of rules' precedence resolution are different evidence shapes answering different questions; forcing precedence to be "N rule-expectations plus a wrapper" or forcing rule-state to be "a precedence check with one candidate" would both be awkward. Each gets its own `Expectation`/`Evidence`/`EvidenceProvider`/`Verify...` quartet, but both quartets return the exact same `VerdictDetail` type, so anything consuming a verdict never needs to know which atomic layer produced it.

**Layer B — the variance wrapper** (Slice 2b's `DLPPolicyVarianceExpectation`): generic over *either* atomic layer by construction, because it never looks inside a rule-level or precedence-level `Expectation`/`Evidence` at all. Its only input is a `map[ScopeID]DLPPolicyScopedVerdict` — each entry is a `VerdictDetail` *already computed* by calling `VerifyDLPPolicyRuleExpectation` or `VerifyDLPPolicyPrecedenceExpectation` once per scope, plus a small caller-supplied `Fingerprint` string describing what was actually observed in that scope (for explaining *why* two scopes differ, never for deciding *whether* they differ — that's the precomputed `Verdict` field's job). This is what keeps Layer B from being forced into either atomic shape: it operates purely on the `VerdictDetail` contract both atomic layers already share.

### Foundation types (`dlppolicy/types.go`)

Independently defined (no import), mirroring `emailgwefficacy/types.go`'s exact vocabulary:

```go
type DLPPOLVerdict string
const (
    VerdictConfirmedFailure DLPPOLVerdict = "confirmed-failure"
    VerdictConfirmedSuccess DLPPOLVerdict = "confirmed-success"
    VerdictInconclusive     DLPPOLVerdict = "inconclusive"
    VerdictNotTested        DLPPOLVerdict = "not-tested"
    VerdictNotApplicable    DLPPOLVerdict = "not-applicable"
)
type VerdictDetail struct {
    Verdict DLPPOLVerdict `json:"verdict"`
    Reason  string        `json:"reason,omitempty"` // required whenever Verdict != VerdictConfirmedSuccess
}

type EvidenceSource string
const (
    SourceSynthetic EvidenceSource = "synthetic"
    SourceFixture   EvidenceSource = "recorded-fixture"
    SourceLive      EvidenceSource = "live" // not used by any provider in this slice; reserved for a future real connector
)

type ProvenanceKind string
const (
    ProvenanceObserved ProvenanceKind = "observed"
    ProvenanceInferred ProvenanceKind = "inferred"
)
type Confidence string
const (
    ConfidenceHigh, ConfidenceMedium, ConfidenceLow Confidence = "high", "medium", "low"
)
type Provenance struct {
    Kind       ProvenanceKind `json:"kind"`
    Confidence Confidence     `json:"confidence"`
    Basis      string         `json:"basis,omitempty"` // required whenever Kind is ProvenanceInferred
}

type TimeWindow struct{ Start, End time.Time }

// ScopeID is an OU/site/business-unit/tenant identifier. Always a
// lab-synthetic value (e.g. "lab-ou-finance-eu"), never a real
// customer org path.
type ScopeID string
```

### Slice 1 — `DLPPolicyRuleExpectation` (`dlppolicy/rulebaseline.go`)

```go
type DLPPolicyScopeDeclaration struct {
    IncludedLocations, ExcludedLocations []string
    IncludedUsers, ExcludedUsers         []string
    IncludedDevices, ExcludedDevices     []string
    IncludedGroups, ExcludedGroups       []string
}
type DLPPolicyMode string
const ( ModeEnforce DLPPolicyMode = "enforce"; ModeAuditOnly DLPPolicyMode = "audit-only" )

type DLPPolicyRuleExpectation struct {
    RuleID               string
    ScopeID              ScopeID
    Scope                DLPPolicyScopeDeclaration
    ExpectedMode         DLPPolicyMode
    ExpectedEnabled      bool
    ExpectedPublished    bool
    RuleExpiresAt        *time.Time    // the rule's own effective-until date, if any
    ExceptionExpiresAt   *time.Time    // a time-boxed exception on this rule, if any -- distinct from RuleExpiresAt
    MaxPropagationDelay  time.Duration // 0 = freshness not checked for this expectation
    ControlProduct       string
    Note                 string
}

type DLPPolicyRuleEvidence struct {
    RuleID, ScopeID       string / ScopeID
    ObservedScope         DLPPolicyScopeDeclaration
    ObservedMode          DLPPolicyMode
    Enabled, Published    bool
    ExceptionActive       bool      // whether evidence shows the exception as still in force, independent of ExceptionExpiresAt
    ConfigChangedAt       time.Time // when the rule was last edited centrally
    LastSyncedAt          time.Time // when this scope's own endpoint/tenant last pulled that config
    Timestamp             time.Time
    Source                EvidenceSource
    Provenance            Provenance
}

type DLPPolicyRuleEvidenceProvider interface {
    DLPPolicyRuleEvidenceFor(ruleID string, scope ScopeID, window TimeWindow) ([]DLPPolicyRuleEvidence, error)
}

func VerifyDLPPolicyRuleExpectation(exp DLPPolicyRuleExpectation, provider DLPPolicyRuleEvidenceProvider, window TimeWindow, asOf time.Time) VerdictDetail
```

Verify order (first match wins, each independently reasoned — mirrors `VerifyEmailPolicyBaselineExpectation`'s layered checks exactly):

1. No evidence in window → `Inconclusive`, "no policy configuration evidence found for this rule/scope in the window."
2. `!latest.Enabled` → `ConfirmedFailure`, "rule is disabled."
3. `!latest.Published` → `ConfirmedFailure`, "rule not published/deployed to this scope."
4. `exp.RuleExpiresAt` before `asOf` but evidence still shows it enabled/published → `ConfirmedFailure`, "rule expired but still active."
5. `exp.ExceptionExpiresAt` before `asOf` and `latest.ExceptionActive` → `ConfirmedFailure`, "exception expired but still active" (direct generalization of `emailgwefficacy`'s own stale-exception check).
6. `latest.ObservedMode != exp.ExpectedMode` → `ConfirmedFailure`, naming both modes (catches bullet 3 in both directions: enforce silently downgraded to audit-only, or vice versa).
7. `latest.ObservedScope` doesn't match `exp.Scope` → `ConfirmedFailure`, naming the specific mismatched location/user/device/group entries (never just "scope mismatch").
8. `exp.MaxPropagationDelay > 0` and `latest.LastSyncedAt` is more than that duration behind `latest.ConfigChangedAt` as of `asOf` → `ConfirmedFailure`, "stale endpoint configuration, propagation delay exceeded."
9. `latest.ExceptionActive` is true but `exp.ExceptionExpiresAt == nil` (an exception is active that this expectation never declared) → `ConfirmedFailure`, "exception active but not declared/expected on this rule in this scope." **(Builder's call, added after builder-check review: without this branch, an undeclared live exception silently passes at step 10, contradicting this design's own "never infer a pass from absence" principle — and it's also the mechanism that makes exception *inheritance* testable at all; see the Slice-2 mapping note below.)**
10. Otherwise → `ConfirmedSuccess`.

### Slice 2a — `DLPPolicyPrecedenceExpectation` (`dlppolicy/precedence.go`)

**Revised after Slice 1's final review** (2026-10-18): Slice 1's own Critical finding — checking each field against its *own* declared expectation in isolation missed a scenario that only shows up when you reason about the *combined* effect (a rule expected to stay disabled that silently came back online) — applies even more directly to precedence. The original draft of this section only compared a declared `ExpectedWinningRuleID` against whatever a vendor's evidence reported, with **zero internal reasoning over the candidate rule-set itself**. That makes it impossible to tell a genuinely wrong vendor resolution apart from a self-contradictory *test*. This revision adds that reasoning as a first pass, before any evidence is even consulted — Slice 2a now evaluates the **effective combined configuration** the declared candidate set implies, not just whether one declared fact matches one observed fact.

```go
// DLPPolicyRuleRef is one member rule's full standing within a
// precedence evaluation: its priority, its own action if it wins,
// and whether it is currently eligible to be considered at all.
// Eligible is reported as a plain fact here -- enabled, published,
// and in-scope for this evaluation context -- never independently
// re-derived from DLPPolicyScopeDeclaration matching logic. Re-
// implementing location/user/device/group scope-matching generically
// is explicitly out of scope for this evaluator (see "What this
// evaluator can and cannot assess" below); a fixture author (or,
// later, a real connector) states eligibility directly.
type DLPPolicyRuleRef struct {
    RuleID         string
    Priority       *int   // nil = no priority declared; a nil Priority on an eligible candidate makes the whole resolution indeterminate (see Verify step 1) -- an explicit pointer, not a bare int defaulting to 0, for the exact reason Slice 1's ExpectedEnabled/ExpectedPublished bug existed: a legitimate "highest priority" value of 0 must never collapse with "nobody set this field."
    ExpectedAction string // this rule's declared action if it is the one that applies
    Eligible       bool   // false = disabled/unpublished/out-of-scope for this context; excluded from precedence resolution entirely
}

// DLPPolicyEvaluationContext is the hypothetical data-access attempt
// precedence is evaluated against -- a synthetic identity/location/
// data-type combination, never a real user or real sensitive content.
type DLPPolicyEvaluationContext struct {
    UserOrGroup, Location, DataType string
    Note                            string
}

type DLPPolicyPrecedenceExpectation struct {
    ScopeID                 ScopeID
    Context                 DLPPolicyEvaluationContext
    CandidateRules          []DLPPolicyRuleRef // every rule declared in scope for this context, eligible or not
    ExpectedWinningRuleID   string
    ExpectedEffectiveAction string
    // OverrideJustification, when non-empty, declares that
    // ExpectedWinningRuleID is known NOT to follow from plain
    // lowest-Priority-number resolution over CandidateRules, and
    // states why (e.g. "explicit admin-override rule always applies
    // regardless of priority"). Required to bypass the self-
    // consistency check in Verify step 3 -- this is the mechanism
    // that distinguishes a genuine, intentional precedence override
    // from a contradictory/malformed expectation.
    OverrideJustification string
    ControlProduct         string
    Note                   string
}

type DLPPolicyPrecedenceEvidence struct {
    ScopeID                 ScopeID
    Context                 DLPPolicyEvaluationContext
    ObservedWinningRuleID   string
    ObservedEffectiveAction string
    Timestamp               time.Time
    Source                  EvidenceSource
    Provenance              Provenance
}

type DLPPolicyPrecedenceEvidenceProvider interface {
    DLPPolicyPrecedenceEvidenceFor(scope ScopeID, context DLPPolicyEvaluationContext, window TimeWindow) ([]DLPPolicyPrecedenceEvidence, error)
}

func VerifyDLPPolicyPrecedenceExpectation(exp DLPPolicyPrecedenceExpectation, provider DLPPolicyPrecedenceEvidenceProvider, window TimeWindow) VerdictDetail
```

**The conflict model.** A candidate is in play for resolution only if `Eligible`. Among eligible candidates, the one with the lowest `Priority` value wins *unless* two or more eligible candidates share the lowest `Priority` — that is a **genuine conflict** (an ambiguous tie: no declared tie-break exists for it) — or `OverrideJustification` says the declared winner is an **intentional precedence relationship** that the raw priority ordering doesn't capture (e.g. an override rule). Both cases are real, testable DLP-POL scenarios, not implementation gaps — the fixture matrix below exercises each by name.

**`resolveExpectedWinner(candidates []DLPPolicyRuleRef) (winnerID string, ambiguous bool, indeterminate bool)`** is this file's own self-consistency helper, computing what the *declared* candidate set alone implies:
1. Filter to `Eligible == true`. Zero eligible candidates → `indeterminate = true` (no one can win).
2. If any eligible candidate has `Priority == nil` → `indeterminate = true` (a missing priority makes the whole set unorderable — this is the direct fixture-level analog of dlp.txt's "incomplete rule inventories"/the user's explicitly named "missing priorities" failure mode: never silently guess an order).
3. Otherwise find the eligible candidates at the minimum `*Priority`. Exactly one → that's `winnerID`, `ambiguous = false`. More than one → `ambiguous = true`, `winnerID` is unset (there is no derivable winner; **genuine conflict**, regardless of whether their `ExpectedAction`s happen to agree — which specific rule's audit trail fires is still indeterminate even when the net effect looks the same).

**Verify order:**

1. `exp.ExpectedWinningRuleID` is not a member of `exp.CandidateRules` → `Inconclusive`, "expected winning rule is not among the declared candidates" (a malformed expectation, caught before any evidence is collected).
2. The candidate named by `exp.ExpectedWinningRuleID` has `Eligible == false` → `Inconclusive`, "expected winner is marked ineligible (disabled/unpublished/out of scope); an ineligible rule cannot win" — directly covers the user's "disabled higher-priority rule" fixture category: if the fixture correctly marks the normally-higher-priority rule ineligible, `ExpectedWinningRuleID` should already name the next eligible rule down, not the disabled one.
3. Run `resolveExpectedWinner`. `indeterminate` → `Inconclusive`, "one or more eligible candidates have no declared priority (or none are eligible); precedence cannot be determined." **Never falls through to evidence** — this is the "missing priorities must not silently produce a pass" requirement, enforced before evidence is even consulted.
4. `!ambiguous && exp.OverrideJustification == "" && winnerID != exp.ExpectedWinningRuleID` → `Inconclusive`, "declared expected winner contradicts the candidate rules' own priorities; set OverrideJustification if this is an intentional override, or correct the expectation" — the **contradictory-expectation** check: a test author's own data disagrees with their own claim, and nothing in it says why on purpose.
5. Fetch evidence for `(exp.ScopeID, exp.Context, window)`. No evidence → `Inconclusive`, "no precedence evidence found for this context in the window."
6. `latest.ObservedWinningRuleID` is not a member of `exp.CandidateRules` → `Inconclusive`, "the vendor reported a winning rule that was not among the declared candidates; the candidate list may be incomplete" (unchanged from the original draft — this is evidence the test's own setup may be incomplete, not proof the product misbehaved).
7. `latest.ObservedWinningRuleID != exp.ExpectedWinningRuleID` → `ConfirmedFailure`, naming both rule IDs.
8. `latest.ObservedEffectiveAction != exp.ExpectedEffectiveAction` → `ConfirmedFailure` (a distinct, separately-named failure mode from step 7's wrong-rule-won case: the right rule won, but its own effective action didn't match).
9. Otherwise → `ConfirmedSuccess`. When step 3's `ambiguous` was `true` (a genuine tie the test still chose to assert a hypothesis about), the verdict — whichever it is — carries an explanatory suffix noting the candidate set was tied and the expected winner reflects an assumed, not derivable, tie-break, so a report reader never mistakes a declared assumption for a mathematically forced conclusion.

**Honesty note, stated directly in this file's doc comment, not just here:** `ObservedWinningRuleID`/`ObservedEffectiveAction` must be sourced from the vendor's *own* policy-resolution reporting — a "matched policy/rule" field in its audit log, or a genuine policy-simulation/dry-run API — never from independently running a real exfiltration attempt and inferring the winner from whether data was blocked, which would double-count DLP-ENF's evidence as DLP-POL's. Where the only available signal is a controlled single-match audit event (e.g. Purview's `DLP.All` records already carry `PolicyName`/`RuleName`/`Actions` per match — see `internal/vendors/purview.DLPEvent`), that event is the acceptable minimum evidence source, but `Provenance.Kind` must be `ProvenanceInferred` with `Basis` naming exactly this ("inferred from a single controlled policy-match audit event, not a dedicated policy-simulation API") so a reader can see precisely how thin the evidence gets when a vendor has no pure simulation surface.

**What this evaluator can and cannot assess (locked scope boundary).** It can: resolve a *declared* candidate set's own priority/eligibility logic deterministically, detect a self-contradictory test, detect a genuine priority tie, and compare a vendor's reported resolution against a validated expectation. It explicitly **cannot**: derive `Eligible` itself from raw location/user/device/group scope declarations (that is a materially different, generic scope-overlap-resolution engine, not built here — ambiguous real-world scope overlap is the fixture author's or a future vendor-specific connector's job to resolve into a plain `Eligible` fact before this evaluator ever sees it); independently predict what a *real* vendor's tie-break mechanism does in a genuine conflict (step 9 surfaces the tie, it never resolves it on the vendor's behalf); or normalize differing vendors' own precedence semantics (e.g. "first rule wins" vs. "most specific rule wins" vs. "explicit priority field") into one universal model — `Priority` here assumes a numeric, lower-wins ordering, which is this evaluator's modeling choice, not a claim that every real DLP product works this way.

**Fixture matrix this slice's tests must cover** (each a distinct, independently-reasoned case, not incidental coverage): a clean positive case (distinct priorities, no ties, evidence matches); a genuine conflict (tied priority, differing actions, no override — `ambiguous=true`, no derivable winner); an expected/intentional override (`OverrideJustification` set, declared winner contradicts raw priority order, still verified correctly against evidence); reversed priority / candidate-slice order independence (the winner by value, not by list position); a disabled higher-priority rule correctly yielding to the next eligible candidate; equal-priority ambiguity where both candidates happen to share the same `ExpectedAction` (still flagged ambiguous, since *which rule* fired is still indeterminate even when the net effect looks identical); an incomplete rule inventory (vendor's observed winner isn't in `CandidateRules` at all); a missing-priority candidate (`Priority == nil` on an eligible candidate, forcing `Inconclusive` before evidence); and a contradictory expectation with no `OverrideJustification` (caught at step 4, never reaching evidence).

### Slice 2b — `DLPPolicyVarianceExpectation` (`dlppolicy/variance.go`)

```go
// DLPPolicyScopedVerdict is one scope's already-computed verdict --
// the only input this file's Verify function consumes. It never
// reaches into rule-level or precedence-level internals: the caller
// has already run VerifyDLPPolicyRuleExpectation or
// VerifyDLPPolicyPrecedenceExpectation once per scope and hands the
// results here as plain data.
type DLPPolicyScopedVerdict struct {
    ScopeID     ScopeID
    Verdict     VerdictDetail
    Fingerprint string // caller-produced summary of what was observed (e.g. "mode=audit-only,enabled=true"); explains WHY scopes differ, never used to decide WHETHER they differ
}

// DLPPolicyVarianceExpectation declares which scopes are compared and
// which scope pairs are allowed to legitimately differ, and why --
// so a documented, intentional policy difference is never reported
// as a finding.
type DLPPolicyVarianceExpectation struct {
    BaselineScopeID    ScopeID
    ComparisonScopeIDs []ScopeID
    PermittedVariance  map[ScopeID]string // scopeID -> documented reason it may legitimately differ from BaselineScopeID
    Note               string
}

// VerifyDLPPolicyVarianceExpectation returns one VerdictDetail per
// ComparisonScopeIDs entry, never a single collapsed verdict --
// variance is inherently a multi-way comparison, and collapsing N
// results into one would hide which scope actually diverged.
func VerifyDLPPolicyVarianceExpectation(exp DLPPolicyVarianceExpectation, results map[ScopeID]DLPPolicyScopedVerdict) map[ScopeID]VerdictDetail
```

Per comparison scope `S`, in order:

1. Baseline or `S` missing from `results` → `Inconclusive`, "no verdict available for this scope in this window."
2. Either side's own `Verdict.Verdict` is `Inconclusive` → `Inconclusive`, "underlying check was inconclusive for at least one side; cannot claim variance."
3. The two verdicts differ (one `ConfirmedSuccess`, one `ConfirmedFailure`) **and** `S` is in `PermittedVariance` → `ConfirmedSuccess`, citing the documented reason ("scope differs as declared: `<reason>`" — the claim being tested is "is this difference accounted for," not "are all scopes identical").
4. The two verdicts differ and `S` is **not** in `PermittedVariance` → `ConfirmedFailure`, naming the scope and both fingerprints.
5. The two verdicts agree but `Fingerprint`s differ **and** `S` is not in `PermittedVariance` → `ConfirmedFailure`, "both scopes satisfy their own expectation, but observed configuration differs" (catches the subtler case dlp.txt actually cares about: two OUs can both be individually "passing" while still being inconsistent with each other — e.g. one configured to Block, the other to Quarantine).
6. Otherwise → `ConfirmedSuccess`.

### Package-level fixture-labeling discipline

Every `*EvidenceProvider` implementation shipped in this slice is a `Fixture...Provider` wrapping an in-memory slice, with every evidence record's `Source` field set to `SourceFixture` — never `SourceLive`, since no vendor connector is wired in. This makes the "fixture proves evaluator correctness, not real configuration" requirement structural (every test and every demo result carries the label), not just a README disclaimer.

## What's left to the builder

**Builder-check calls already made in this document** (settled here, not re-litigated): (1) "exception inheritance" is covered by Slice 1's exception fields + new branch 9, diffed by Slice 2b — not by Slice 2a; (2) Slice 1 gained branch 9 (an undeclared-but-active exception fails rather than silently passing); (3) `CandidateRules`/`Priority` in Slice 2a are load-bearing, validated purely inside `Verify` (not at construction): the expected winner must be a declared, eligible candidate (`Inconclusive` otherwise), the candidate set's own priorities must determine a winner or be flagged ambiguous/indeterminate before evidence is ever consulted, and an observed winner outside the candidate list is `Inconclusive`, not `ConfirmedFailure` (as built and merged `092552e5`; this replaces an earlier draft of this note that described a construction-time validator, which was dropped in favor of this in-`Verify` approach).

- Exact Go file layout within `internal/dlppolicy` (the file names above — `types.go`/`rulebaseline.go`/`precedence.go`/`variance.go` — are this design's own suggestion, not a hard requirement; a builder may split differently if it reads more clearly, as long as the type/function contracts above are preserved).
- Fixture content for each Slice-1/2a/2b test (what specific rule IDs, scopes, and scenarios demonstrate each Verify branch) — build via TDD per the established DLP Mastery convention: a failing test per Verify branch, then the implementation.
- Whether Slice 1, 2a, and 2b land as one combined worktree/PR or three sequential ones — this design recommends three (Slice 1 first since it extends a proven pattern directly; 2a and 2b after, since they're the genuinely new primitives the key architecture decision resolves), each independently reviewed and merged, consistent with every prior DLP Mastery priority's increment size.
- Whether `docs/dlp-mastery-qa-log.md` needs a new entry — only if this slice's fixtures surface a genuine open question (e.g. a specific vendor's lack of a policy-simulation API for precedence evidence); not speculatively.
