# DLP-POL Slice 2b — Cross-Scope Variance Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `DLPPolicyVarianceExpectation`/`VerifyDLPPolicyVarianceExpectation` — the Layer B cross-scope comparison primitive that closes DLP-POL concerns 4/5 (OU/site/tenant variance) and 2b (exception inheritance), completing the DLP-POL design's "two orthogonal layers" architecture.

**Architecture:** Layer B is generic over Layer A by construction: it never inspects a `DLPPolicyRuleExpectation`/`DLPPolicyPrecedenceExpectation` or their evidence types, only a `map[ScopeID]DLPPolicyScopedVerdict` of *already-computed* `VerdictDetail`s (produced by calling `VerifyDLPPolicyRuleExpectation` or `VerifyDLPPolicyPrecedenceExpectation` once per scope, outside this file) plus a caller-supplied `Fingerprint` string per scope. This slice adds exactly one new file; it reads but never modifies `rulebaseline.go`, `precedence.go`, or `types.go`.

**Tech Stack:** Go, same package `internal/dlppolicy`, stdlib only (`fmt`).

**Spec:** `orchestrator/docs/superpowers/specs/2026-10-18-dlp-pol-design.md` — read the "Slice 2b" section (the full type/Verify-order block), "The key architecture decision: two orthogonal layers" section (Layer B's genericity contract), and the concern-mapping table's rows for concerns 2b/4/5.

## Global Constraints

- No import outside `internal/dlppolicy` itself (standing rule for this package since Slice 1).
- `VerifyDLPPolicyVarianceExpectation` must never inspect `DLPPolicyRuleExpectation`, `DLPPolicyPrecedenceExpectation`, or either's evidence types — its only inputs are `DLPPolicyVarianceExpectation` and `map[ScopeID]DLPPolicyScopedVerdict`. This is the Layer B genericity contract the whole design is built on; importing or switching on either atomic type here is a design violation, not a style choice.
- **Design decision (not explicit in the spec, settled here):** the spec's Verify order names `Inconclusive` only for a missing scope or a `Verdict.Verdict == Inconclusive` side. `DLPPOLVerdict` has two more values the spec doesn't mention in this context: `VerdictNotTested` and `VerdictNotApplicable`. Neither represents a comparable pass/fail state, so both must resolve a comparison to `Inconclusive` exactly like `Inconclusive` itself does — a `NotTested` vs `ConfirmedSuccess` pair must never be reported as a verdict-level divergence (`ConfirmedFailure`) or silently treated as agreement. Implement this via a `comparableVerdict(v DLPPOLVerdict) bool` helper returning true only for `VerdictConfirmedSuccess`/`VerdictConfirmedFailure`, checked for *both* sides before any difference comparison runs. This is a direct application of principle 4 from the user's own non-negotiable design requirements for this initiative: "missing evidence is not a pass" extends to "an incomparable verdict is not a variance claim either."
- A declared `PermittedVariance[S]` entry gates **both** the verdict-level-difference path and the fingerprint-only-difference path through the same check — not two independent flags.
- `VerifyDLPPolicyVarianceExpectation` returns one `VerdictDetail` per entry in `ComparisonScopeIDs`, never a single collapsed verdict.

## Review Focus

- A verdict-level difference (one side `ConfirmedSuccess`, the other `ConfirmedFailure`) with no `PermittedVariance` entry for that scope must return `ConfirmedFailure` naming the scope and both fingerprints — never silently default to success. This is the case most likely to hide real enforcement drift between two sites.
- A same-verdict, fingerprint-only divergence (both scopes individually pass their own expectation, but observed configuration differs — e.g. one audits, the other blocks, yet both count as "a rule is active") must also return `ConfirmedFailure` unless permitted. This is the subtlest case the design calls out by name and the easiest to miss if an implementer only diffs `Verdict.Verdict`.
- `VerdictNotTested` or `VerdictNotApplicable` on either side must resolve the comparison to `Inconclusive`, never fall through to a verdict-level-difference comparison that could misfire a spurious `ConfirmedFailure`/`ConfirmedSuccess` against a state that was never actually comparable.
- The exception-inheritance use case (concern 2b in the spec's own mapping table — "Slice 1's exception fields... evaluated once per scope, diffed by Slice 2b") must be proven end-to-end: a parent scope and a child scope independently verified through `VerifyDLPPolicyRuleExpectation`, fed into this function, and a real inheritance failure (child has an undeclared-but-active exception, caught by Slice 1's branch 9) must surface here as a verdict-level divergence. This is the test that proves Slice 2b actually closes concern 2b, not just a documented intention.
- A declared `PermittedVariance` entry must suppress the finding through *either* path (verdict-differs or fingerprint-differs) when exercised through that same entry — test both paths against one `PermittedVariance` declaration, not two unrelated ones.

---

### Task 1: `DLPPolicyScopedVerdict`/`DLPPolicyVarianceExpectation` and `VerifyDLPPolicyVarianceExpectation`

**Files:**
- Create: `orchestrator/internal/dlppolicy/variance.go`
- Test: `orchestrator/internal/dlppolicy/variance_test.go`

**Interfaces:**
- Consumes: `ScopeID`, `VerdictDetail`, `DLPPOLVerdict`, `VerdictConfirmedSuccess`/`VerdictConfirmedFailure`/`VerdictInconclusive`/`VerdictNotTested`/`VerdictNotApplicable` (all from `types.go`); nothing from `rulebaseline.go` or `precedence.go` directly, though the inheritance test (below) calls `VerifyDLPPolicyRuleExpectation` to build its own inputs.
- Produces: this slice is terminal within DLP-POL's current scope — no later task consumes these types yet.

```go
type DLPPolicyScopedVerdict struct {
    ScopeID     ScopeID
    Verdict     VerdictDetail
    Fingerprint string
}

type DLPPolicyVarianceExpectation struct {
    BaselineScopeID    ScopeID
    ComparisonScopeIDs []ScopeID
    PermittedVariance  map[ScopeID]string
    Note               string
}

func VerifyDLPPolicyVarianceExpectation(exp DLPPolicyVarianceExpectation, results map[ScopeID]DLPPolicyScopedVerdict) map[ScopeID]VerdictDetail
```

Verify order, applied independently per `S` in `exp.ComparisonScopeIDs` (first match wins):

1. `results[exp.BaselineScopeID]` or `results[S]` missing → `VerdictInconclusive`, reason `"no verdict available for this scope in this window"`.
2. `!comparableVerdict(baseline.Verdict.Verdict) || !comparableVerdict(comparison.Verdict.Verdict)` → `VerdictInconclusive`, reason `"underlying check was inconclusive, not tested, or not applicable for at least one side; cannot claim variance"`.
3. `baseline.Verdict.Verdict != comparison.Verdict.Verdict`:
   - `S` in `exp.PermittedVariance` → `VerdictConfirmedSuccess`, reason `fmt.Sprintf("scope differs as declared: %s", exp.PermittedVariance[S])`.
   - otherwise → `VerdictConfirmedFailure`, reason `fmt.Sprintf("scope %q diverges from baseline %q: baseline verdict %q (fingerprint %q), comparison verdict %q (fingerprint %q)", S, exp.BaselineScopeID, baseline.Verdict.Verdict, baseline.Fingerprint, comparison.Verdict.Verdict, comparison.Fingerprint)`.
4. `baseline.Fingerprint != comparison.Fingerprint` (verdicts already equal, by step 3 not matching):
   - `S` in `exp.PermittedVariance` → `VerdictConfirmedSuccess`, reason `fmt.Sprintf("scope differs as declared: %s", exp.PermittedVariance[S])`.
   - otherwise → `VerdictConfirmedFailure`, reason `fmt.Sprintf("both scopes satisfy their own expectation, but observed configuration differs: baseline fingerprint %q, comparison fingerprint %q", baseline.Fingerprint, comparison.Fingerprint)`.
5. Otherwise → `VerdictConfirmedSuccess` (no reason).

`comparableVerdict(v DLPPOLVerdict) bool` returns true only for `VerdictConfirmedSuccess`/`VerdictConfirmedFailure`.

- [ ] **Step 1: Write the failing tests**

```go
package dlppolicy

import (
    "strings"
    "testing"
    "time"
)

func scoped(id ScopeID, verdict DLPPOLVerdict, fingerprint string) DLPPolicyScopedVerdict {
    return DLPPolicyScopedVerdict{ScopeID: id, Verdict: VerdictDetail{Verdict: verdict}, Fingerprint: fingerprint}
}

func TestVerifyDLPPolicyVarianceExpectation_IdenticalScopes_ReturnsConfirmedSuccess(t *testing.T) {
    results := map[ScopeID]DLPPolicyScopedVerdict{
        "baseline": scoped("baseline", VerdictConfirmedSuccess, "mode=enforce,enabled=true"),
        "mumbai":   scoped("mumbai", VerdictConfirmedSuccess, "mode=enforce,enabled=true"),
    }
    exp := DLPPolicyVarianceExpectation{BaselineScopeID: "baseline", ComparisonScopeIDs: []ScopeID{"mumbai"}}
    got := VerifyDLPPolicyVarianceExpectation(exp, results)
    if got["mumbai"].Verdict != VerdictConfirmedSuccess {
        t.Fatalf("Verdict = %q, want %q", got["mumbai"].Verdict, VerdictConfirmedSuccess)
    }
}

func TestVerifyDLPPolicyVarianceExpectation_MissingBaseline_ReturnsInconclusive(t *testing.T) {
    results := map[ScopeID]DLPPolicyScopedVerdict{
        "mumbai": scoped("mumbai", VerdictConfirmedSuccess, "x"),
    }
    exp := DLPPolicyVarianceExpectation{BaselineScopeID: "baseline", ComparisonScopeIDs: []ScopeID{"mumbai"}}
    got := VerifyDLPPolicyVarianceExpectation(exp, results)
    if got["mumbai"].Verdict != VerdictInconclusive {
        t.Fatalf("Verdict = %q, want %q", got["mumbai"].Verdict, VerdictInconclusive)
    }
}

func TestVerifyDLPPolicyVarianceExpectation_MissingComparisonScope_ReturnsInconclusive(t *testing.T) {
    results := map[ScopeID]DLPPolicyScopedVerdict{
        "baseline": scoped("baseline", VerdictConfirmedSuccess, "x"),
    }
    exp := DLPPolicyVarianceExpectation{BaselineScopeID: "baseline", ComparisonScopeIDs: []ScopeID{"mumbai"}}
    got := VerifyDLPPolicyVarianceExpectation(exp, results)
    if got["mumbai"].Verdict != VerdictInconclusive {
        t.Fatalf("Verdict = %q, want %q", got["mumbai"].Verdict, VerdictInconclusive)
    }
}

func TestVerifyDLPPolicyVarianceExpectation_BaselineInconclusive_ReturnsInconclusive(t *testing.T) {
    results := map[ScopeID]DLPPolicyScopedVerdict{
        "baseline": scoped("baseline", VerdictInconclusive, "x"),
        "mumbai":   scoped("mumbai", VerdictConfirmedSuccess, "x"),
    }
    exp := DLPPolicyVarianceExpectation{BaselineScopeID: "baseline", ComparisonScopeIDs: []ScopeID{"mumbai"}}
    got := VerifyDLPPolicyVarianceExpectation(exp, results)
    if got["mumbai"].Verdict != VerdictInconclusive {
        t.Fatalf("Verdict = %q, want %q -- an inconclusive side must never produce a comparable claim", got["mumbai"].Verdict, VerdictInconclusive)
    }
}

func TestVerifyDLPPolicyVarianceExpectation_ComparisonNotTested_ReturnsInconclusive(t *testing.T) {
    results := map[ScopeID]DLPPolicyScopedVerdict{
        "baseline": scoped("baseline", VerdictConfirmedSuccess, "x"),
        "mumbai":   scoped("mumbai", VerdictNotTested, "x"),
    }
    exp := DLPPolicyVarianceExpectation{BaselineScopeID: "baseline", ComparisonScopeIDs: []ScopeID{"mumbai"}}
    got := VerifyDLPPolicyVarianceExpectation(exp, results)
    if got["mumbai"].Verdict != VerdictInconclusive {
        t.Fatalf("Verdict = %q, want %q -- NotTested must never be treated as a comparable pass/fail", got["mumbai"].Verdict, VerdictInconclusive)
    }
}

func TestVerifyDLPPolicyVarianceExpectation_BaselineNotApplicable_ReturnsInconclusive(t *testing.T) {
    results := map[ScopeID]DLPPolicyScopedVerdict{
        "baseline": scoped("baseline", VerdictNotApplicable, "x"),
        "mumbai":   scoped("mumbai", VerdictConfirmedFailure, "y"),
    }
    exp := DLPPolicyVarianceExpectation{BaselineScopeID: "baseline", ComparisonScopeIDs: []ScopeID{"mumbai"}}
    got := VerifyDLPPolicyVarianceExpectation(exp, results)
    if got["mumbai"].Verdict != VerdictInconclusive {
        t.Fatalf("Verdict = %q, want %q -- NotApplicable must never be treated as a comparable pass/fail", got["mumbai"].Verdict, VerdictInconclusive)
    }
}

func TestVerifyDLPPolicyVarianceExpectation_VerdictDiffers_NotPermitted_ReturnsConfirmedFailure(t *testing.T) {
    results := map[ScopeID]DLPPolicyScopedVerdict{
        "baseline": scoped("baseline", VerdictConfirmedSuccess, "mode=enforce"),
        "mumbai":   scoped("mumbai", VerdictConfirmedFailure, "mode=audit-only"),
    }
    exp := DLPPolicyVarianceExpectation{BaselineScopeID: "baseline", ComparisonScopeIDs: []ScopeID{"mumbai"}}
    got := VerifyDLPPolicyVarianceExpectation(exp, results)
    if got["mumbai"].Verdict != VerdictConfirmedFailure {
        t.Fatalf("Verdict = %q, want %q", got["mumbai"].Verdict, VerdictConfirmedFailure)
    }
    if !strings.Contains(got["mumbai"].Reason, "mumbai") {
        t.Errorf("Reason = %q, want it to name the diverging scope", got["mumbai"].Reason)
    }
}

func TestVerifyDLPPolicyVarianceExpectation_VerdictDiffers_Permitted_ReturnsConfirmedSuccessCitingReason(t *testing.T) {
    results := map[ScopeID]DLPPolicyScopedVerdict{
        "baseline": scoped("baseline", VerdictConfirmedSuccess, "mode=enforce"),
        "eu-site":  scoped("eu-site", VerdictConfirmedFailure, "mode=audit-only"),
    }
    exp := DLPPolicyVarianceExpectation{
        BaselineScopeID:    "baseline",
        ComparisonScopeIDs: []ScopeID{"eu-site"},
        PermittedVariance:  map[ScopeID]string{"eu-site": "EU site runs audit-only pending GDPR legal review"},
    }
    got := VerifyDLPPolicyVarianceExpectation(exp, results)
    if got["eu-site"].Verdict != VerdictConfirmedSuccess {
        t.Fatalf("Verdict = %q, want %q -- a declared variance must verify, not fail", got["eu-site"].Verdict, VerdictConfirmedSuccess)
    }
    if !strings.Contains(got["eu-site"].Reason, "GDPR") {
        t.Errorf("Reason = %q, want it to cite the documented PermittedVariance reason", got["eu-site"].Reason)
    }
}

func TestVerifyDLPPolicyVarianceExpectation_SameVerdictDifferentFingerprint_NotPermitted_ReturnsConfirmedFailure(t *testing.T) {
    results := map[ScopeID]DLPPolicyScopedVerdict{
        "baseline": scoped("baseline", VerdictConfirmedSuccess, "action=block"),
        "mumbai":   scoped("mumbai", VerdictConfirmedSuccess, "action=quarantine"),
    }
    exp := DLPPolicyVarianceExpectation{BaselineScopeID: "baseline", ComparisonScopeIDs: []ScopeID{"mumbai"}}
    got := VerifyDLPPolicyVarianceExpectation(exp, results)
    if got["mumbai"].Verdict != VerdictConfirmedFailure {
        t.Fatalf("Verdict = %q, want %q -- both scopes individually passing must not hide a real configuration difference", got["mumbai"].Verdict, VerdictConfirmedFailure)
    }
}

func TestVerifyDLPPolicyVarianceExpectation_SameVerdictDifferentFingerprint_Permitted_ReturnsConfirmedSuccess(t *testing.T) {
    results := map[ScopeID]DLPPolicyScopedVerdict{
        "baseline": scoped("baseline", VerdictConfirmedSuccess, "action=block"),
        "mumbai":   scoped("mumbai", VerdictConfirmedSuccess, "action=quarantine"),
    }
    exp := DLPPolicyVarianceExpectation{
        BaselineScopeID:    "baseline",
        ComparisonScopeIDs: []ScopeID{"mumbai"},
        PermittedVariance:  map[ScopeID]string{"mumbai": "Mumbai site uses quarantine per local incident-response policy"},
    }
    got := VerifyDLPPolicyVarianceExpectation(exp, results)
    if got["mumbai"].Verdict != VerdictConfirmedSuccess {
        t.Fatalf("Verdict = %q, want %q -- the same PermittedVariance gate must cover fingerprint-only drift too", got["mumbai"].Verdict, VerdictConfirmedSuccess)
    }
    if !strings.Contains(got["mumbai"].Reason, "incident-response") {
        t.Errorf("Reason = %q, want it to cite the documented reason", got["mumbai"].Reason)
    }
}

func TestVerifyDLPPolicyVarianceExpectation_MultipleComparisonScopes_ReturnsOneVerdictEach(t *testing.T) {
    results := map[ScopeID]DLPPolicyScopedVerdict{
        "baseline": scoped("baseline", VerdictConfirmedSuccess, "x"),
        "mumbai":   scoped("mumbai", VerdictConfirmedSuccess, "x"),
        "eu-site":  scoped("eu-site", VerdictConfirmedFailure, "y"),
    }
    exp := DLPPolicyVarianceExpectation{BaselineScopeID: "baseline", ComparisonScopeIDs: []ScopeID{"mumbai", "eu-site"}}
    got := VerifyDLPPolicyVarianceExpectation(exp, results)
    if len(got) != 2 {
        t.Fatalf("len(got) = %d, want 2", len(got))
    }
    if got["mumbai"].Verdict != VerdictConfirmedSuccess {
        t.Errorf("mumbai Verdict = %q, want %q", got["mumbai"].Verdict, VerdictConfirmedSuccess)
    }
    if got["eu-site"].Verdict != VerdictConfirmedFailure {
        t.Errorf("eu-site Verdict = %q, want %q", got["eu-site"].Verdict, VerdictConfirmedFailure)
    }
}

func TestVerifyDLPPolicyVarianceExpectation_NoComparisonScopes_ReturnsEmptyMap(t *testing.T) {
    exp := DLPPolicyVarianceExpectation{BaselineScopeID: "baseline", ComparisonScopeIDs: nil}
    got := VerifyDLPPolicyVarianceExpectation(exp, map[ScopeID]DLPPolicyScopedVerdict{})
    if len(got) != 0 {
        t.Fatalf("len(got) = %d, want 0", len(got))
    }
}

func TestVerifyDLPPolicyVarianceExpectation_ExceptionInheritance_UndeclaredChildExceptionSurfacesAsDivergence(t *testing.T) {
    window := TimeWindow{Start: time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC), End: time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC)}
    asOf := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

    parentExp := DLPPolicyRuleExpectation{
        RuleID: "r-pci", ScopeID: "parent-ou", ExpectedMode: ModeEnforce,
        ExpectedEnabled: true, ExpectedPublished: true,
        ExceptionExpiresAt: ptrTime(asOf.Add(24 * time.Hour)), // exception IS declared/expected here
    }
    parentEvidence := []DLPPolicyRuleEvidence{{
        RuleID: "r-pci", ScopeID: "parent-ou", ObservedMode: ModeEnforce,
        Enabled: true, Published: true, ExceptionActive: true,
        Timestamp: asOf, Source: SourceFixture,
    }}
    parentVerdict := VerifyDLPPolicyRuleExpectation(parentExp, NewFixtureDLPPolicyRuleProvider(parentEvidence), window, asOf)

    childExp := DLPPolicyRuleExpectation{
        RuleID: "r-pci", ScopeID: "child-ou", ExpectedMode: ModeEnforce,
        ExpectedEnabled: true, ExpectedPublished: true,
        ExceptionExpiresAt: nil, // exception is NOT declared/expected on the child
    }
    childEvidence := []DLPPolicyRuleEvidence{{
        RuleID: "r-pci", ScopeID: "child-ou", ObservedMode: ModeEnforce,
        Enabled: true, Published: true, ExceptionActive: true, // but it inherited one anyway
        Timestamp: asOf, Source: SourceFixture,
    }}
    childVerdict := VerifyDLPPolicyRuleExpectation(childExp, NewFixtureDLPPolicyRuleProvider(childEvidence), window, asOf)

    if childVerdict.Verdict != VerdictConfirmedFailure {
        t.Fatalf("precondition failed: child verdict = %q, want %q (Slice 1 branch 9)", childVerdict.Verdict, VerdictConfirmedFailure)
    }

    results := map[ScopeID]DLPPolicyScopedVerdict{
        "parent-ou": {ScopeID: "parent-ou", Verdict: parentVerdict, Fingerprint: "exceptionActive=true,declared=true"},
        "child-ou":  {ScopeID: "child-ou", Verdict: childVerdict, Fingerprint: "exceptionActive=true,declared=false"},
    }
    exp := DLPPolicyVarianceExpectation{BaselineScopeID: "parent-ou", ComparisonScopeIDs: []ScopeID{"child-ou"}}
    got := VerifyDLPPolicyVarianceExpectation(exp, results)
    if got["child-ou"].Verdict != VerdictConfirmedFailure {
        t.Fatalf("Verdict = %q, want %q -- Slice 2b must surface the inheritance mismatch Slice 1 alone cannot name as a cross-scope concern", got["child-ou"].Verdict, VerdictConfirmedFailure)
    }
}

func ptrTime(t time.Time) *time.Time { return &t }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test github.com/audspect/bas/internal/dlppolicy/... -run "TestVerifyDLPPolicyVarianceExpectation" -v`
Expected: FAIL (`undefined: DLPPolicyScopedVerdict`, `undefined: DLPPolicyVarianceExpectation`, `undefined: VerifyDLPPolicyVarianceExpectation`)

- [ ] **Step 3: Implement `variance.go`**

Exactly per the Interfaces block and Verify order above.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test github.com/audspect/bas/internal/dlppolicy/... -v`
Expected: PASS (all tests in the package, including Slice 1's and Slice 2a's)

- [ ] **Step 5: `gofmt -l` and `go vet` the package**

Run: `gofmt -l orchestrator/internal/dlppolicy/` and `go vet github.com/audspect/bas/internal/dlppolicy/...`
Expected: no output from either

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/dlppolicy/variance.go orchestrator/internal/dlppolicy/variance_test.go
git commit -m "feat(dlppolicy): add DLPPolicyVarianceExpectation, closing DLP-POL concerns 4/5/2b"
```

---

## Self-Review Notes

- **Spec coverage:** every element of the Slice 2b spec block (`DLPPolicyScopedVerdict`, `DLPPolicyVarianceExpectation`, the 6-step-collapsed-to-5 Verify order, the "two orthogonal layers" genericity contract) has a corresponding test above. Concern 2b (exception inheritance) and concerns 4/5 (OU/site/tenant variance) are both exercised — 2b via the dedicated inheritance test, 4/5 via the verdict-differs and fingerprint-differs tests.
- **Type consistency:** `DLPPolicyScopedVerdict`, `DLPPolicyVarianceExpectation`, and `VerifyDLPPolicyVarianceExpectation` are named identically to the spec's own block; the inheritance test's use of `VerifyDLPPolicyRuleExpectation`/`NewFixtureDLPPolicyRuleProvider`/`DLPPolicyRuleEvidence` matches `rulebaseline.go`'s actual shipped signatures exactly (re-read from the merged file before writing this plan).
- **Review Focus:** all five items each have a named test above (verdict-differs-not-permitted, fingerprint-differs-not-permitted, NotTested/NotApplicable-both-covered-separately, exception-inheritance integration test, PermittedVariance-gates-both-paths via two separate tests sharing the pattern).
- **Proportion check:** this plan is the smallest of the three DLP-POL slices so far (no evidence provider, no self-consistency resolver) — one file, 5 Verify branches, 14 named tests. Comparable in density to Slice 1/2a's own plans; function body left to the implementer except where the spec and this plan's Verify-order block pin exact values and ordering.
