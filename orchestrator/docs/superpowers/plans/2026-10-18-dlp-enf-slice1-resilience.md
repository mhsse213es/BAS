# DLP-ENF Slice 1 (Service-Unavailability Resilience) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `internal/dlpresilience` — a new, standalone, fixture-only evaluator that compares a declared classification/policy-service-unavailability failure-mode contract (fail-open/fail-closed/defer/indeterminate-OK) against observed evidence. This is the one DLP-ENF gap the live scenario engine cannot currently exercise; it is independent of `internal/reporting/dlp.go`'s normal Allow/Block comparator and never duplicates it.

**Architecture:** A single new package, one file pair (`resilience.go`/`resilience_test.go`), following the `Expectation`/`Evidence`/`EvidenceProvider`/`Verify...` shape `dlppolicy`/`dlpclassify` already established — borrowed as architectural discipline only, with every concrete type independently defined (zero cross-import). Fixture-only (`SourceFixture`), same discipline as every prior DLP Mastery evaluator: fixture-backed tests prove the evaluator's own correctness, never real product resilience.

**Tech Stack:** Go stdlib only (`fmt`, `time`).

**Spec:** `orchestrator/docs/superpowers/specs/2026-10-18-dlp-enf-design.md`, "Part B: `internal/dlpresilience`" section — fixes the exact types (`FailureMode`, `ServiceUnavailabilityExpectation`, `ServiceUnavailabilityEvidence`, `ServiceUnavailabilityProvider`, `ResilienceOutcome`, `ResilienceVerdict`, `VerifyServiceUnavailabilityExpectation`) and the 6-step Verify order (already corrected during the spec's own builder-check to handle an unset `ExpectedMode` as step 1).

## Global Constraints

- Zero imports outside Go stdlib (`fmt`, `time`); zero cross-import of `internal/reporting`, `internal/dlppolicy`, `internal/dlpclassify`, `internal/scenario`.
- `ResilienceOutcome`/`ResilienceVerdict` are independently defined types — never `reporting.ComparisonResult`, never `dlpclassify.DLPCLSOutcome`, never `dlppolicy`'s verdict type, even though the shape is similar.
- `FailureMode` is an open string type with 4 named constants, never a closed enum assuming one mode is "correct" by default — the correct expectation is declared per-expectation.
- An unset `exp.ExpectedMode` (`""`) must resolve to `OutcomeInconclusive` before evidence is even fetched — never fall through to a comparison that produces a message like `expected failure mode "", observed "fail-open"`.
- `IndeterminateOK` matches any non-empty classified `ObservedMode` — that is its entire meaning; it is not itself a 5th real-world failure mode.

## Review Focus

- `exp.ExpectedMode == ""` — must short-circuit to `OutcomeInconclusive` with its own Reason, checked before the evidence provider is even called (not just before the mode comparison) — the spec's own builder-check caught this exact gap once already; the test must prove the provider is never invoked, not just that the outcome is right.
- `latest.ObservedMode == ""` (evidence exists but couldn't be classified) — must be `OutcomeInconclusive`, distinct from the no-evidence-at-all case, with its own Reason text.
- `exp.ExpectedMode == IndeterminateOK` paired with each of the other 3 concrete observed modes (`fail-open`/`fail-closed`/`defer`) — all three must independently match, proving `IndeterminateOK` isn't accidentally implemented as "matches only one specific mode."
- Multiple evidence records in one window — must select by latest `Timestamp`, not slice order, the same risk class this project has hit before in `dlpclassify`'s two evaluators.
- A genuine mismatch (e.g. expected `fail-closed`, observed `fail-open`) — the Reason string must name both the expected and observed mode, not a generic "mismatch" message.

---

### Task 1: Service-unavailability resilience evaluator

**Files:**
- Create: `orchestrator/internal/dlpresilience/resilience.go`
- Test: `orchestrator/internal/dlpresilience/resilience_test.go`

**Interfaces:**
- Consumes: nothing from any other package in this repo (new standalone package).
- Produces: `FailureMode` + 4 constants (`FailOpen`, `FailClosed`, `Defer`, `IndeterminateOK`), `ServiceUnavailabilityExpectation`, `ServiceUnavailabilityEvidence`, `EvidenceSource` + `SourceFixture`, `ServiceUnavailabilityProvider`, `FixtureServiceUnavailabilityProvider`, `NewFixtureServiceUnavailabilityProvider`, `TimeWindow`, `ResilienceOutcome` + 3 constants (`OutcomeModeMatched`, `OutcomeModeMismatched`, `OutcomeInconclusive`), `ResilienceVerdict`, `VerifyServiceUnavailabilityExpectation(exp ServiceUnavailabilityExpectation, provider ServiceUnavailabilityProvider, window TimeWindow) ResilienceVerdict`. Terminal within this slice's scope — no later task consumes these yet.

```go
// resilience.go -- exactly per the spec's "Part B" code block
// (FailureMode/ServiceUnavailabilityExpectation/ServiceUnavailabilityEvidence/
// ServiceUnavailabilityProvider/TimeWindow/ResilienceOutcome/ResilienceVerdict),
// plus FixtureServiceUnavailabilityProvider (mirrors
// dlpclassify.FixtureClassificationEvidenceProvider's filter style: by
// ExpectationID and inclusive TimeWindow) and
// VerifyServiceUnavailabilityExpectation's body.
```

Verify order (first match wins), with exact Reason strings, per the spec's corrected 6-step order:

1. `exp.ExpectedMode == ""` → `OutcomeInconclusive`, `"expectation declares no failure mode"` — checked before calling the provider at all.
2. No evidence records for `exp.ExpectationID` in the window → `OutcomeInconclusive`, `"no service-unavailability evidence found for this expectation in the window"`.
3. Latest (by `Timestamp`) record's `ObservedMode == ""` → `OutcomeInconclusive`, `"observed behavior could not be classified into a known failure mode"`.
4. `exp.ExpectedMode == IndeterminateOK` → `OutcomeModeMatched` (no Reason).
5. `latest.ObservedMode == exp.ExpectedMode` → `OutcomeModeMatched` (no Reason).
6. Otherwise → `OutcomeModeMismatched`, `fmt.Sprintf("expected failure mode %q, observed %q", exp.ExpectedMode, latest.ObservedMode)`.

`FixtureServiceUnavailabilityProvider.ServiceUnavailabilityEvidenceFor` filters by `ExpectationID` and inclusive `TimeWindow`, mirroring `dlpclassify.FixtureClassificationEvidenceProvider` exactly. Latest-record selection is by `Timestamp`, mirroring `latestClassificationEvidenceByTimestamp`/`latestLabelEvidenceByTimestamp`.

- [ ] **Step 1: Write the failing tests**

```go
package dlpresilience

import (
    "testing"
    "time"
)

var resilienceTestBase = time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
var resilienceTestWindow = TimeWindow{Start: resilienceTestBase.Add(-time.Hour), End: resilienceTestBase.Add(time.Hour)}

func resilienceEv(expectationID string, observedMode FailureMode, ts time.Time) ServiceUnavailabilityEvidence {
    return ServiceUnavailabilityEvidence{
        ExpectationID: expectationID, ObservedMode: observedMode,
        Timestamp: ts, Source: SourceFixture,
    }
}

func verifyResilience(exp ServiceUnavailabilityExpectation, evs ...ServiceUnavailabilityEvidence) ResilienceVerdict {
    return VerifyServiceUnavailabilityExpectation(exp, NewFixtureServiceUnavailabilityProvider(evs), resilienceTestWindow)
}

func TestFixtureServiceUnavailabilityProvider_FiltersByExpectationAndWindow(t *testing.T) {
    evs := []ServiceUnavailabilityEvidence{
        resilienceEv("exp-A", FailClosed, resilienceTestBase),
        resilienceEv("exp-B", FailClosed, resilienceTestBase),
        resilienceEv("exp-A", FailClosed, resilienceTestBase.Add(-24*time.Hour)),
    }
    p := NewFixtureServiceUnavailabilityProvider(evs)
    got, err := p.ServiceUnavailabilityEvidenceFor("exp-A", resilienceTestWindow)
    if err != nil {
        t.Fatalf("ServiceUnavailabilityEvidenceFor: %v", err)
    }
    if len(got) != 1 {
        t.Fatalf("len(got) = %d, want 1", len(got))
    }
}

func TestVerify_UnsetExpectedMode_ReturnsInconclusiveWithoutCallingProvider(t *testing.T) {
    exp := ServiceUnavailabilityExpectation{ExpectationID: "exp-A", Dependency: "classification"}
    called := false
    provider := &countingProvider{onCall: func() { called = true }}
    got := VerifyServiceUnavailabilityExpectation(exp, provider, resilienceTestWindow)
    if got.Outcome != OutcomeInconclusive {
        t.Fatalf("Outcome = %q, want %q", got.Outcome, OutcomeInconclusive)
    }
    if called {
        t.Error("provider must never be called when ExpectedMode is unset")
    }
}

type countingProvider struct{ onCall func() }

func (p *countingProvider) ServiceUnavailabilityEvidenceFor(expectationID string, window TimeWindow) ([]ServiceUnavailabilityEvidence, error) {
    p.onCall()
    return nil, nil
}

func TestVerify_NoEvidence_ReturnsInconclusive(t *testing.T) {
    exp := ServiceUnavailabilityExpectation{ExpectationID: "exp-A", Dependency: "classification", ExpectedMode: FailClosed}
    got := verifyResilience(exp)
    if got.Outcome != OutcomeInconclusive {
        t.Fatalf("Outcome = %q, want %q", got.Outcome, OutcomeInconclusive)
    }
}

func TestVerify_ObservedModeEmpty_ReturnsInconclusive(t *testing.T) {
    exp := ServiceUnavailabilityExpectation{ExpectationID: "exp-A", Dependency: "classification", ExpectedMode: FailClosed}
    got := verifyResilience(exp, resilienceEv("exp-A", "", resilienceTestBase))
    if got.Outcome != OutcomeInconclusive {
        t.Fatalf("Outcome = %q, want %q", got.Outcome, OutcomeInconclusive)
    }
}

func TestVerify_IndeterminateOK_MatchesFailOpen(t *testing.T) {
    exp := ServiceUnavailabilityExpectation{ExpectationID: "exp-A", Dependency: "policy", ExpectedMode: IndeterminateOK}
    got := verifyResilience(exp, resilienceEv("exp-A", FailOpen, resilienceTestBase))
    if got.Outcome != OutcomeModeMatched {
        t.Fatalf("Outcome = %q, want %q", got.Outcome, OutcomeModeMatched)
    }
}

func TestVerify_IndeterminateOK_MatchesFailClosed(t *testing.T) {
    exp := ServiceUnavailabilityExpectation{ExpectationID: "exp-A", Dependency: "policy", ExpectedMode: IndeterminateOK}
    got := verifyResilience(exp, resilienceEv("exp-A", FailClosed, resilienceTestBase))
    if got.Outcome != OutcomeModeMatched {
        t.Fatalf("Outcome = %q, want %q", got.Outcome, OutcomeModeMatched)
    }
}

func TestVerify_IndeterminateOK_MatchesDefer(t *testing.T) {
    exp := ServiceUnavailabilityExpectation{ExpectationID: "exp-A", Dependency: "policy", ExpectedMode: IndeterminateOK}
    got := verifyResilience(exp, resilienceEv("exp-A", Defer, resilienceTestBase))
    if got.Outcome != OutcomeModeMatched {
        t.Fatalf("Outcome = %q, want %q", got.Outcome, OutcomeModeMatched)
    }
}

func TestVerify_ExactModeMatch_ReturnsMatched(t *testing.T) {
    exp := ServiceUnavailabilityExpectation{ExpectationID: "exp-A", Dependency: "classification", ExpectedMode: FailClosed}
    got := verifyResilience(exp, resilienceEv("exp-A", FailClosed, resilienceTestBase))
    if got.Outcome != OutcomeModeMatched {
        t.Fatalf("Outcome = %q, want %q", got.Outcome, OutcomeModeMatched)
    }
}

func TestVerify_ModeMismatch_ReturnsMismatchedNamingBoth(t *testing.T) {
    exp := ServiceUnavailabilityExpectation{ExpectationID: "exp-A", Dependency: "classification", ExpectedMode: FailClosed}
    got := verifyResilience(exp, resilienceEv("exp-A", FailOpen, resilienceTestBase))
    if got.Outcome != OutcomeModeMismatched {
        t.Fatalf("Outcome = %q, want %q", got.Outcome, OutcomeModeMismatched)
    }
    if got.Reason == "" {
        t.Fatal("want a Reason naming both the expected and observed mode")
    }
}

func TestVerify_MultipleRecords_PicksLatestByTimestampNotOrder(t *testing.T) {
    exp := ServiceUnavailabilityExpectation{ExpectationID: "exp-A", Dependency: "classification", ExpectedMode: FailClosed}
    older := resilienceEv("exp-A", FailClosed, resilienceTestBase.Add(-30*time.Minute)) // match-shaped
    newer := resilienceEv("exp-A", FailOpen, resilienceTestBase)                        // mismatch-shaped
    got := verifyResilience(exp, older, newer)
    if got.Outcome != OutcomeModeMismatched {
        t.Fatalf("Outcome = %q, want %q -- must select the record with the latest Timestamp", got.Outcome, OutcomeModeMismatched)
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test github.com/audspect/bas/internal/dlpresilience/... -v`
Expected: FAIL (package does not exist / `undefined: FailureMode`, `undefined: VerifyServiceUnavailabilityExpectation`, etc.)

- [ ] **Step 3: Implement `resilience.go`**

Exactly per the Interfaces block, the Verify order, and the Global Constraints above (especially checking `exp.ExpectedMode == ""` before calling the provider at all — not just before the mode comparison).

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test github.com/audspect/bas/internal/dlpresilience/... -v`
Expected: PASS (all 10 tests)

- [ ] **Step 5: `gofmt -l` and `go vet` the package**

Run: `gofmt -l orchestrator/internal/dlpresilience/` and `go vet github.com/audspect/bas/internal/dlpresilience/...`
Expected: no output from either (note: this Windows worktree has a known CRLF/LF checkout artifact that can make `gofmt -l` flag files purely on line-ending normalization — verify any hit with `gofmt -d` before treating it as real)

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/dlpresilience/resilience.go orchestrator/internal/dlpresilience/resilience_test.go
git commit -m "feat(dlpresilience): add service-unavailability failure-mode evaluator"
```

---

## Self-Review Notes

- **Spec coverage:** every type/function Part B's code block pins (`FailureMode`, `ServiceUnavailabilityExpectation`, `ServiceUnavailabilityEvidence`, `ServiceUnavailabilityProvider`, `TimeWindow`, `ResilienceOutcome`, `ResilienceVerdict`, `VerifyServiceUnavailabilityExpectation`) and all 6 Verify-order steps (including the builder-check's unset-`ExpectedMode` fix) have a named test above.
- **Step scan / type consistency:** `VerifyServiceUnavailabilityExpectation`'s signature and the `FixtureServiceUnavailabilityProvider` naming match the spec's code block and the established `dlpclassify`/`dlppolicy` naming convention (`Fixture<Name>Provider`, `New<Name>...`) exactly.
- **Review Focus:** all 5 items each have a named test above (unset-mode short-circuit proven via a call-counting fake provider, empty-observed-mode distinct from no-evidence, `IndeterminateOK` tested against all 3 concrete modes independently, latest-by-timestamp selection, and a named-both-modes mismatch Reason).
- **Proportion check:** 1 task, comparable to DLP-CLS Slice 2's own single-task plan — proportionate to this slice's single-file-pair, zero-dependency surface.
