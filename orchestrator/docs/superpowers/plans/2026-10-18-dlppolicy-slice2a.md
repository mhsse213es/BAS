# dlppolicy Slice 2a Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `internal/dlppolicy`'s multi-rule precedence primitive — `DLPPolicyPrecedenceExpectation` / `VerifyDLPPolicyPrecedenceExpectation` — which evaluates the *effective combined configuration* a declared candidate rule-set implies (self-consistency, genuine-conflict and missing-priority detection) before ever comparing against a vendor's reported resolution.

**Architecture:** New files inside the existing `internal/dlppolicy` package (same package as Slice 1, zero new imports outside it, zero cross-package imports). Mirrors Slice 1's own `Expectation`/`Evidence`/`EvidenceProvider`/`Verify...(exp, provider, window) VerdictDetail` shape, but adds a self-consistency resolution pass (`resolveExpectedWinner`) that Slice 1 never needed, because precedence is inherently a claim about a *set* of rules, not one rule in isolation.

**Tech Stack:** Go (stdlib only: `fmt`, `time`).

**Spec:** `orchestrator/docs/superpowers/specs/2026-10-18-dlp-pol-design.md`, section "Slice 2a — `DLPPolicyPrecedenceExpectation`" (revised 2026-10-18 to add the self-consistency/conflict-model reasoning — read the whole revised section, including "The conflict model," `resolveExpectedWinner`'s spec, the 9-step Verify order, "What this evaluator can and cannot assess," and the fixture matrix, before starting).

## Global Constraints

- No import of anything outside `internal/dlppolicy` itself; no cross-package import of `internal/emailgwefficacy`, `internal/webgwefficacy`, `internal/dlpfixture`, or `internal/reporting`.
- `DLPPolicyRuleRef.Priority` is `*int`, never a bare `int` — a real "highest priority" value of `0` must never be indistinguishable from "nobody set this field" (the direct lesson from Slice 1's Enabled/Published bug, per the spec's own note).
- `Verify DLPPolicyPrecedenceExpectation` never falls through to evidence comparison when the candidate set itself is malformed, indeterminate, or self-contradictory (spec Verify steps 1–4) — all four return `Inconclusive` before any evidence is fetched.
- `OverrideJustification` only counts as set when it is non-empty **after trimming whitespace** — a caller passing only spaces must not silently bypass the contradictory-expectation check.
- `FixtureDLPPolicyPrecedenceProvider` always sets `Source: SourceFixture` — never `SourceLive`.
- `VerifyDLPPolicyPrecedenceExpectation` takes no `asOf` parameter (unlike Slice 1) — precedence has no time-based expiry concept of its own; only `window` bounds evidence relevance.

## Review Focus

- A genuine tie where both tied candidates happen to declare the *same* `ExpectedAction` — must still resolve as `ambiguous = true` (which rule's own audit trail actually fired is still indeterminate even when the net effect looks identical), never silently treated as "fine since the outcome matches."
- `CandidateRules` order/permutation independence — the winner is determined by `*Priority` value, never by position in the slice.
- Step ordering when more than one problem exists at once: an `ExpectedWinningRuleID` that is both ineligible *and* part of a candidate set that also has a missing-priority candidate elsewhere — step 2's ineligibility check must fire with its own specific reason, not get preempted or confused by step 3's indeterminate check.
- Evidence-selection order independence: a `DLPPolicyPrecedenceEvidenceProvider` returning multiple records out of timestamp order must still select the one with the greatest `Timestamp`, not the first/last in the slice (same class of bug Slice 1's own Review Focus caught).
- `OverrideJustification` set to only whitespace (e.g. `"   "`) must be treated as empty, not as a real justification — a caller who means to bypass the contradictory-expectation check must say something, not just type a space.

---

### Task 1: Precedence types, fixture provider, and the `resolveExpectedWinner` self-consistency helper

**Files:**
- Create: `orchestrator/internal/dlppolicy/precedence.go`
- Test: `orchestrator/internal/dlppolicy/precedence_test.go`

**Interfaces:**
- Produces (used by Task 2):
  - `type DLPPolicyRuleRef struct { RuleID string; Priority *int; ExpectedAction string; Eligible bool }`.
  - `type DLPPolicyEvaluationContext struct { UserOrGroup, Location, DataType, Note string }` (plain string fields, directly comparable with `==` — used as an equality key by the fixture provider).
  - `type DLPPolicyPrecedenceExpectation struct { ScopeID ScopeID; Context DLPPolicyEvaluationContext; CandidateRules []DLPPolicyRuleRef; ExpectedWinningRuleID string; ExpectedEffectiveAction string; OverrideJustification string; ControlProduct string; Note string }` (json tags in camelCase, `OverrideJustification`/`Note` `,omitempty`; mirror Slice 1's tagging style in `rulebaseline.go`).
  - `type DLPPolicyPrecedenceEvidence struct { ScopeID ScopeID; Context DLPPolicyEvaluationContext; ObservedWinningRuleID string; ObservedEffectiveAction string; Timestamp time.Time; Source EvidenceSource; Provenance Provenance }` (json tags in camelCase).
  - `type DLPPolicyPrecedenceEvidenceProvider interface { DLPPolicyPrecedenceEvidenceFor(scope ScopeID, context DLPPolicyEvaluationContext, window TimeWindow) ([]DLPPolicyPrecedenceEvidence, error) }`.
  - `type FixtureDLPPolicyPrecedenceProvider struct{ ... }` with `NewFixtureDLPPolicyPrecedenceProvider(events []DLPPolicyPrecedenceEvidence) *FixtureDLPPolicyPrecedenceProvider` and the interface method implemented: filters by exact `ScopeID` match, exact `Context` match (`==`), and `Timestamp` within `[window.Start, window.End]` inclusive on both ends — same filtering shape as `FixtureDLPPolicyRuleProvider.DLPPolicyRuleEvidenceFor` in `rulebaseline.go`.
  - `func resolveExpectedWinner(candidates []DLPPolicyRuleRef) (winnerID string, ambiguous bool, indeterminate bool)` — the self-consistency helper Task 2 calls. Logic: filter to `Eligible == true`; zero eligible → `indeterminate = true`; any eligible candidate with `Priority == nil` → `indeterminate = true`; otherwise find the eligible candidates at the minimum `*Priority` — exactly one → that one's `RuleID` as `winnerID`, `ambiguous = false`; more than one → `ambiguous = true`, `winnerID = ""`.

- [ ] **Step 1: Write the failing tests for the fixture provider and `resolveExpectedWinner`**

```go
func TestFixtureDLPPolicyPrecedenceProvider_FiltersByScopeContextAndWindow(t *testing.T) {
    base := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
    ctx := DLPPolicyEvaluationContext{UserOrGroup: "lab-user-finance-analyst", Location: "lab-site-mumbai", DataType: "pci"}
    otherCtx := DLPPolicyEvaluationContext{UserOrGroup: "lab-user-hr-analyst", Location: "lab-site-mumbai", DataType: "pci"}
    events := []DLPPolicyPrecedenceEvidence{
        {ScopeID: "lab-ou-finance", Context: ctx, Timestamp: base, ObservedWinningRuleID: "r1", Source: SourceFixture},      // match
        {ScopeID: "lab-ou-hr", Context: ctx, Timestamp: base, ObservedWinningRuleID: "r2", Source: SourceFixture},           // wrong scope
        {ScopeID: "lab-ou-finance", Context: otherCtx, Timestamp: base, ObservedWinningRuleID: "r3", Source: SourceFixture}, // wrong context
        {ScopeID: "lab-ou-finance", Context: ctx, Timestamp: base.Add(-48 * time.Hour), ObservedWinningRuleID: "r4", Source: SourceFixture}, // out of window
    }
    p := NewFixtureDLPPolicyPrecedenceProvider(events)
    window := TimeWindow{Start: base.Add(-time.Hour), End: base.Add(time.Hour)}

    got, err := p.DLPPolicyPrecedenceEvidenceFor("lab-ou-finance", ctx, window)
    if err != nil {
        t.Fatalf("DLPPolicyPrecedenceEvidenceFor: %v", err)
    }
    if len(got) != 1 || got[0].ObservedWinningRuleID != "r1" {
        t.Fatalf("got %+v, want exactly the one matching record (r1)", got)
    }
}

func intPtr(v int) *int { return &v }

func TestResolveExpectedWinner_SinglePriorityWins(t *testing.T) {
    candidates := []DLPPolicyRuleRef{
        {RuleID: "r1", Priority: intPtr(2), Eligible: true},
        {RuleID: "r2", Priority: intPtr(1), Eligible: true},
    }
    winnerID, ambiguous, indeterminate := resolveExpectedWinner(candidates)
    if indeterminate || ambiguous || winnerID != "r2" {
        t.Fatalf("got winnerID=%q ambiguous=%v indeterminate=%v, want r2/false/false", winnerID, ambiguous, indeterminate)
    }
}

func TestResolveExpectedWinner_OrderIndependent(t *testing.T) {
    a := []DLPPolicyRuleRef{{RuleID: "r1", Priority: intPtr(2), Eligible: true}, {RuleID: "r2", Priority: intPtr(1), Eligible: true}}
    b := []DLPPolicyRuleRef{{RuleID: "r2", Priority: intPtr(1), Eligible: true}, {RuleID: "r1", Priority: intPtr(2), Eligible: true}}
    w1, _, _ := resolveExpectedWinner(a)
    w2, _, _ := resolveExpectedWinner(b)
    if w1 != "r2" || w2 != "r2" {
        t.Fatalf("winner must not depend on slice order: got %q and %q, want both r2", w1, w2)
    }
}

func TestResolveExpectedWinner_IneligibleSkipped(t *testing.T) {
    candidates := []DLPPolicyRuleRef{
        {RuleID: "r1", Priority: intPtr(1), Eligible: false}, // disabled higher-priority rule
        {RuleID: "r2", Priority: intPtr(2), Eligible: true},
    }
    winnerID, ambiguous, indeterminate := resolveExpectedWinner(candidates)
    if indeterminate || ambiguous || winnerID != "r2" {
        t.Fatalf("got winnerID=%q ambiguous=%v indeterminate=%v, want r2/false/false (ineligible r1 must be skipped)", winnerID, ambiguous, indeterminate)
    }
}

func TestResolveExpectedWinner_TiedPriorityIsAmbiguous(t *testing.T) {
    candidates := []DLPPolicyRuleRef{
        {RuleID: "r1", Priority: intPtr(1), ExpectedAction: "block", Eligible: true},
        {RuleID: "r2", Priority: intPtr(1), ExpectedAction: "quarantine", Eligible: true},
    }
    _, ambiguous, indeterminate := resolveExpectedWinner(candidates)
    if indeterminate || !ambiguous {
        t.Fatalf("got ambiguous=%v indeterminate=%v, want ambiguous=true", ambiguous, indeterminate)
    }
}

func TestResolveExpectedWinner_TiedPrioritySameActionStillAmbiguous(t *testing.T) {
    candidates := []DLPPolicyRuleRef{
        {RuleID: "r1", Priority: intPtr(1), ExpectedAction: "block", Eligible: true},
        {RuleID: "r2", Priority: intPtr(1), ExpectedAction: "block", Eligible: true},
    }
    _, ambiguous, indeterminate := resolveExpectedWinner(candidates)
    if indeterminate || !ambiguous {
        t.Fatalf("got ambiguous=%v indeterminate=%v, want ambiguous=true -- which rule fired is still indeterminate even when the net action matches", ambiguous, indeterminate)
    }
}

func TestResolveExpectedWinner_MissingPriorityIsIndeterminate(t *testing.T) {
    candidates := []DLPPolicyRuleRef{
        {RuleID: "r1", Priority: nil, Eligible: true},
        {RuleID: "r2", Priority: intPtr(1), Eligible: true},
    }
    _, _, indeterminate := resolveExpectedWinner(candidates)
    if !indeterminate {
        t.Fatal("want indeterminate=true when any eligible candidate has a nil Priority")
    }
}

func TestResolveExpectedWinner_NoEligibleCandidatesIsIndeterminate(t *testing.T) {
    candidates := []DLPPolicyRuleRef{{RuleID: "r1", Priority: intPtr(1), Eligible: false}}
    _, _, indeterminate := resolveExpectedWinner(candidates)
    if !indeterminate {
        t.Fatal("want indeterminate=true when no candidate is eligible")
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test github.com/audspect/bas/internal/dlppolicy/... -run "TestFixtureDLPPolicyPrecedenceProvider|TestResolveExpectedWinner" -v`
Expected: FAIL (types/function not defined)

- [ ] **Step 3: Implement the types, fixture provider, and `resolveExpectedWinner` in `precedence.go`**

Exactly per the Interfaces block above. `DLPPolicyPrecedenceEvidenceFor`'s window check and the overall file style should mirror `rulebaseline.go`'s own provider implementation.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test github.com/audspect/bas/internal/dlppolicy/... -run "TestFixtureDLPPolicyPrecedenceProvider|TestResolveExpectedWinner" -v`
Expected: PASS

- [ ] **Step 5: `gofmt -l` and `go vet` the package, fix any output**

Run: `gofmt -l orchestrator/internal/dlppolicy/` and `go vet github.com/audspect/bas/internal/dlppolicy/...`
Expected: no output from either

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/dlppolicy/precedence.go orchestrator/internal/dlppolicy/precedence_test.go
git commit -m "feat(dlppolicy): add precedence types, fixture provider, and resolveExpectedWinner"
```

---

### Task 2: `VerifyDLPPolicyPrecedenceExpectation` — full 9-step coverage

**Files:**
- Modify: `orchestrator/internal/dlppolicy/precedence.go`
- Test: `orchestrator/internal/dlppolicy/precedence_test.go`

**Interfaces:**
- Consumes: every type/function from Task 1 (`DLPPolicyPrecedenceExpectation`, `DLPPolicyPrecedenceEvidence`, `DLPPolicyPrecedenceEvidenceProvider`, `FixtureDLPPolicyPrecedenceProvider`, `resolveExpectedWinner`, plus `VerdictDetail`/`DLPPOLVerdict` consts from `types.go`).
- Produces: `func VerifyDLPPolicyPrecedenceExpectation(exp DLPPolicyPrecedenceExpectation, provider DLPPolicyPrecedenceEvidenceProvider, window TimeWindow) VerdictDetail` — the package's second atomic `Verify...` entry point, a sibling to Slice 1's `VerifyDLPPolicyRuleExpectation`, used later only by Slice 2b (consuming this function's *output*, never its internals, per the design's own layering).

Verify order (first match wins — spec's revised Slice 2a section, Verify steps 1-9):

1. No candidate in `exp.CandidateRules` has `RuleID == exp.ExpectedWinningRuleID` → `VerdictInconclusive`, reason `"expected winning rule is not among the declared candidates"`.
2. That candidate has `Eligible == false` → `VerdictInconclusive`, reason `"expected winner is marked ineligible (disabled/unpublished/out of scope); an ineligible rule cannot win"`.
3. `winnerID, ambiguous, indeterminate := resolveExpectedWinner(exp.CandidateRules)`; `indeterminate` → `VerdictInconclusive`, reason `"one or more eligible candidates have no declared priority (or none are eligible); precedence cannot be determined"`.
4. `!ambiguous && strings.TrimSpace(exp.OverrideJustification) == "" && winnerID != exp.ExpectedWinningRuleID` → `VerdictInconclusive`, reason `"declared expected winner contradicts the candidate rules' own priorities; set OverrideJustification if this is an intentional override, or correct the expectation"`.
5. Fetch evidence via `provider.DLPPolicyPrecedenceEvidenceFor(exp.ScopeID, exp.Context, window)`. Provider error → `VerdictInconclusive`, reason naming the error (mirror `VerifyDLPPolicyRuleExpectation`'s own `fmt.Sprintf("policy configuration evidence collection failed: %v", err)` pattern, adapted to say "precedence evidence collection failed"). No records → `VerdictInconclusive`, reason `"no precedence evidence found for this context in the window"`.
6. `latest := ` the record with the greatest `Timestamp` among those returned (write a small `latestPrecedenceEvidenceByTimestamp` helper, parallel to `rulebaseline.go`'s `latestRuleEvidenceByTimestamp` — a different element type, so it is not reused directly). If no candidate in `exp.CandidateRules` has `RuleID == latest.ObservedWinningRuleID` → `VerdictInconclusive`, reason `"the vendor reported a winning rule that was not among the declared candidates; the candidate list may be incomplete"`.
7. `latest.ObservedWinningRuleID != exp.ExpectedWinningRuleID` → `VerdictConfirmedFailure`, reason naming both IDs, e.g. `fmt.Sprintf("expected rule %q to take precedence for this context, %q won instead", exp.ExpectedWinningRuleID, latest.ObservedWinningRuleID)`.
8. `latest.ObservedEffectiveAction != exp.ExpectedEffectiveAction` → `VerdictConfirmedFailure`, reason `"the expected rule won, but its own effective action did not match"`.
9. Otherwise → `VerdictConfirmedSuccess`.

Whatever `VerdictDetail` is returned from steps 5 through 9 (never steps 1-4, which precede knowing whether evidence even exists) gets an informational suffix appended to `Reason` when `ambiguous` was `true`: `" (note: candidate rules declare a genuine priority tie; the expected winner reflects an assumed, not derivable, tie-break)"`. Implement this as a small wrapper, e.g. `func withTieNote(ambiguous bool, v VerdictDetail) VerdictDetail`, applied to every return value from step 5 onward.

- [ ] **Step 1: Write the failing tests, one per step/fixture-matrix case**

```go
// shared builders
func baselinePrecedenceExpectation() DLPPolicyPrecedenceExpectation {
    return DLPPolicyPrecedenceExpectation{
        ScopeID: "lab-ou-finance",
        Context: DLPPolicyEvaluationContext{UserOrGroup: "lab-user-finance-analyst", Location: "lab-site-mumbai", DataType: "pci"},
        CandidateRules: []DLPPolicyRuleRef{
            {RuleID: "r-high", Priority: intPtr(1), ExpectedAction: "block", Eligible: true},
            {RuleID: "r-low", Priority: intPtr(2), ExpectedAction: "audit", Eligible: true},
        },
        ExpectedWinningRuleID:   "r-high",
        ExpectedEffectiveAction: "block",
    }
}

func baselinePrecedenceEvidence(exp DLPPolicyPrecedenceExpectation) DLPPolicyPrecedenceEvidence {
    return DLPPolicyPrecedenceEvidence{
        ScopeID: exp.ScopeID, Context: exp.Context,
        ObservedWinningRuleID: exp.ExpectedWinningRuleID, ObservedEffectiveAction: exp.ExpectedEffectiveAction,
        Timestamp: precedenceTestBase, Source: SourceFixture,
    }
}

func verifyPrecedence(exp DLPPolicyPrecedenceExpectation, evs ...DLPPolicyPrecedenceEvidence) VerdictDetail {
    return VerifyDLPPolicyPrecedenceExpectation(exp, NewFixtureDLPPolicyPrecedenceProvider(evs), precedenceTestWindow)
}

var precedenceTestBase = time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
var precedenceTestWindow = TimeWindow{Start: precedenceTestBase.Add(-time.Hour), End: precedenceTestBase.Add(time.Hour)}

func TestVerifyDLPPolicyPrecedenceExpectation_PositiveCase_ReturnsConfirmedSuccess(t *testing.T) {
    exp := baselinePrecedenceExpectation()
    got := verifyPrecedence(exp, baselinePrecedenceEvidence(exp))
    if got.Verdict != VerdictConfirmedSuccess {
        t.Fatalf("Verdict = %q, want %q", got.Verdict, VerdictConfirmedSuccess)
    }
}

func TestVerifyDLPPolicyPrecedenceExpectation_ExpectedWinnerNotACandidate_ReturnsInconclusive(t *testing.T) {
    exp := baselinePrecedenceExpectation()
    exp.ExpectedWinningRuleID = "r-nonexistent"
    got := verifyPrecedence(exp, baselinePrecedenceEvidence(exp))
    if got.Verdict != VerdictInconclusive {
        t.Fatalf("Verdict = %q, want %q", got.Verdict, VerdictInconclusive)
    }
}

func TestVerifyDLPPolicyPrecedenceExpectation_ExpectedWinnerIneligible_ReturnsInconclusive(t *testing.T) {
    exp := baselinePrecedenceExpectation()
    exp.CandidateRules[0].Eligible = false // r-high, the declared expected winner
    got := verifyPrecedence(exp, baselinePrecedenceEvidence(exp))
    if got.Verdict != VerdictInconclusive {
        t.Fatalf("Verdict = %q, want %q", got.Verdict, VerdictInconclusive)
    }
}

func TestVerifyDLPPolicyPrecedenceExpectation_DisabledHigherPriorityRule_NextEligibleWinsCorrectly(t *testing.T) {
    exp := baselinePrecedenceExpectation()
    exp.CandidateRules[0].Eligible = false // r-high disabled
    exp.ExpectedWinningRuleID = "r-low"    // correctly expect the next eligible rule
    exp.ExpectedEffectiveAction = "audit"
    ev := baselinePrecedenceEvidence(exp) // ObservedWinningRuleID/Action now follow exp's updated fields
    got := verifyPrecedence(exp, ev)
    if got.Verdict != VerdictConfirmedSuccess {
        t.Fatalf("Verdict = %q, want %q -- disabling the higher-priority rule must correctly let the next eligible one win", got.Verdict, VerdictConfirmedSuccess)
    }
}

func TestVerifyDLPPolicyPrecedenceExpectation_MissingPriority_ReturnsInconclusive(t *testing.T) {
    exp := baselinePrecedenceExpectation()
    exp.CandidateRules[1].Priority = nil // r-low
    got := verifyPrecedence(exp, baselinePrecedenceEvidence(exp))
    if got.Verdict != VerdictInconclusive {
        t.Fatalf("Verdict = %q, want %q -- a missing priority must never silently produce a pass", got.Verdict, VerdictInconclusive)
    }
}

func TestVerifyDLPPolicyPrecedenceExpectation_ContradictoryExpectationWithoutOverride_ReturnsInconclusive(t *testing.T) {
    exp := baselinePrecedenceExpectation()
    exp.ExpectedWinningRuleID = "r-low" // contradicts raw priority order (r-high has lower Priority number)
    exp.ExpectedEffectiveAction = "audit"
    got := verifyPrecedence(exp, baselinePrecedenceEvidence(exp))
    if got.Verdict != VerdictInconclusive {
        t.Fatalf("Verdict = %q, want %q", got.Verdict, VerdictInconclusive)
    }
}

func TestVerifyDLPPolicyPrecedenceExpectation_IntentionalOverride_VerifiesCorrectly(t *testing.T) {
    exp := baselinePrecedenceExpectation()
    exp.ExpectedWinningRuleID = "r-low" // contradicts raw priority order, but...
    exp.ExpectedEffectiveAction = "audit"
    exp.OverrideJustification = "r-low is an explicit admin-override rule that always applies regardless of priority"
    got := verifyPrecedence(exp, baselinePrecedenceEvidence(exp))
    if got.Verdict != VerdictConfirmedSuccess {
        t.Fatalf("Verdict = %q, want %q -- a declared, justified override must verify normally against evidence", got.Verdict, VerdictConfirmedSuccess)
    }
}

func TestVerifyDLPPolicyPrecedenceExpectation_WhitespaceOnlyOverrideJustification_StillTreatedAsContradictory(t *testing.T) {
    exp := baselinePrecedenceExpectation()
    exp.ExpectedWinningRuleID = "r-low"
    exp.ExpectedEffectiveAction = "audit"
    exp.OverrideJustification = "   "
    got := verifyPrecedence(exp, baselinePrecedenceEvidence(exp))
    if got.Verdict != VerdictInconclusive {
        t.Fatalf("Verdict = %q, want %q -- whitespace-only OverrideJustification must not count as a real justification", got.Verdict, VerdictInconclusive)
    }
}

func TestVerifyDLPPolicyPrecedenceExpectation_GenuineConflict_StillVerifiesAgainstEvidenceWithTieNote(t *testing.T) {
    exp := baselinePrecedenceExpectation()
    exp.CandidateRules[1].Priority = intPtr(1) // r-low now tied with r-high at priority 1
    got := verifyPrecedence(exp, baselinePrecedenceEvidence(exp)) // evidence still matches exp's declared winner/action
    if got.Verdict != VerdictConfirmedSuccess {
        t.Fatalf("Verdict = %q, want %q", got.Verdict, VerdictConfirmedSuccess)
    }
    if !strings.Contains(got.Reason, "tie") {
        t.Errorf("Reason = %q, want it to note the genuine priority tie even on a successful verdict", got.Reason)
    }
}

func TestVerifyDLPPolicyPrecedenceExpectation_TiedPrioritySameAction_StillFlaggedAsTie(t *testing.T) {
    exp := baselinePrecedenceExpectation()
    exp.CandidateRules[1].Priority = intPtr(1)
    exp.CandidateRules[1].ExpectedAction = exp.CandidateRules[0].ExpectedAction // both "block" now
    got := verifyPrecedence(exp, baselinePrecedenceEvidence(exp))
    if !strings.Contains(got.Reason, "tie") {
        t.Errorf("Reason = %q, want the tie noted even though both candidates share the same action", got.Reason)
    }
}

func TestVerifyDLPPolicyPrecedenceExpectation_IncompleteCandidateInventory_ReturnsInconclusive(t *testing.T) {
    exp := baselinePrecedenceExpectation()
    ev := baselinePrecedenceEvidence(exp)
    ev.ObservedWinningRuleID = "r-unknown" // the vendor matched a rule nobody declared as a candidate
    got := verifyPrecedence(exp, ev)
    if got.Verdict != VerdictInconclusive {
        t.Fatalf("Verdict = %q, want %q", got.Verdict, VerdictInconclusive)
    }
}

func TestVerifyDLPPolicyPrecedenceExpectation_WrongRuleWon_ReturnsConfirmedFailure(t *testing.T) {
    exp := baselinePrecedenceExpectation()
    ev := baselinePrecedenceEvidence(exp)
    ev.ObservedWinningRuleID = "r-low" // the vendor's own candidate, just the wrong one
    got := verifyPrecedence(exp, ev)
    if got.Verdict != VerdictConfirmedFailure {
        t.Fatalf("Verdict = %q, want %q", got.Verdict, VerdictConfirmedFailure)
    }
}

func TestVerifyDLPPolicyPrecedenceExpectation_RightRuleWrongAction_ReturnsConfirmedFailure(t *testing.T) {
    exp := baselinePrecedenceExpectation()
    ev := baselinePrecedenceEvidence(exp)
    ev.ObservedEffectiveAction = "warn" // right rule, wrong effective action
    got := verifyPrecedence(exp, ev)
    if got.Verdict != VerdictConfirmedFailure {
        t.Fatalf("Verdict = %q, want %q", got.Verdict, VerdictConfirmedFailure)
    }
}

func TestVerifyDLPPolicyPrecedenceExpectation_NoEvidence_ReturnsInconclusive(t *testing.T) {
    exp := baselinePrecedenceExpectation()
    got := VerifyDLPPolicyPrecedenceExpectation(exp, NewFixtureDLPPolicyPrecedenceProvider(nil), precedenceTestWindow)
    if got.Verdict != VerdictInconclusive {
        t.Fatalf("Verdict = %q, want %q", got.Verdict, VerdictInconclusive)
    }
}

func TestVerifyDLPPolicyPrecedenceExpectation_MultipleRecords_PicksLatestByTimestampNotOrder(t *testing.T) {
    exp := baselinePrecedenceExpectation()
    older := baselinePrecedenceEvidence(exp) // ConfirmedSuccess-shaped
    older.Timestamp = precedenceTestBase.Add(-30 * time.Minute)
    newer := baselinePrecedenceEvidence(exp) // ConfirmedFailure-shaped
    newer.Timestamp = precedenceTestBase
    newer.ObservedWinningRuleID = "r-low"
    got := verifyPrecedence(exp, older, newer) // newer appears after older in the slice
    if got.Verdict != VerdictConfirmedFailure {
        t.Fatalf("Verdict = %q, want %q -- must select the record with the latest Timestamp", got.Verdict, VerdictConfirmedFailure)
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test github.com/audspect/bas/internal/dlppolicy/... -run TestVerifyDLPPolicyPrecedenceExpectation -v`
Expected: FAIL with "VerifyDLPPolicyPrecedenceExpectation not defined"

- [ ] **Step 3: Implement `VerifyDLPPolicyPrecedenceExpectation`, `latestPrecedenceEvidenceByTimestamp`, and `withTieNote` in `precedence.go`**

Branch order and reasons exactly as specified above. Remember the `strings.TrimSpace` requirement on `OverrideJustification` (add the `strings` import if not already present in this file).

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test github.com/audspect/bas/internal/dlppolicy/... -v`
Expected: PASS (all tests in the package, including Task 1's and Slice 1's)

- [ ] **Step 5: `gofmt -l` and `go vet` the package**

Run: `gofmt -l orchestrator/internal/dlppolicy/` and `go vet github.com/audspect/bas/internal/dlppolicy/...`
Expected: no output from either

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/dlppolicy/precedence.go orchestrator/internal/dlppolicy/precedence_test.go
git commit -m "feat(dlppolicy): add VerifyDLPPolicyPrecedenceExpectation with full 9-step coverage"
```

---

## Self-Review Notes

- **Spec coverage:** Task 1 covers the spec's `DLPPolicyRuleRef`/`DLPPolicyEvaluationContext`/`DLPPolicyPrecedenceExpectation`/`DLPPolicyPrecedenceEvidence`/provider/`resolveExpectedWinner` declarations and "the conflict model." Task 2 covers all 9 Verify steps, the tie-note suffix, and every entry in the spec's fixture matrix (positive case, genuine conflict, intentional override, order independence, disabled-higher-priority-rule, equal-priority-same-action ambiguity, incomplete inventory, missing-priority, contradictory-expectation-without-override) — each has a named test above. Slice 2b and DLP-CLS/DLP-ENF are explicitly out of scope, per the user's own instruction not to expand into them yet.
- **Type consistency:** `DLPPolicyPrecedenceEvidenceProvider`, `DLPPolicyPrecedenceExpectation`, `DLPPolicyPrecedenceEvidence`, `resolveExpectedWinner`, and `VerdictDetail` are named identically between Task 1's Produces block and Task 2's Consumes block.
- **Review Focus:** all five items each have a named test above (tied-same-action ambiguity, order independence, ineligible-expected-winner-with-missing-priority-elsewhere ordering — covered implicitly since step 2 is checked strictly before step 3 in the Verify order itself, not just in a test — evidence-latest-by-timestamp, whitespace-only `OverrideJustification`).
- **Proportion check:** this plan is comparable in length to Slice 1's own plan for a comparably-sized increment (one new file, ~9 Verify branches vs. Slice 1's 10) — not a transcript of the implementation; function bodies are left to the implementer except where the spec pins exact reason strings or ordering.
