# dlpcorrelate Campaign 03 (Scenario Differentiation) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a third aggregate shape to `internal/dlpcorrelate` — scenario differentiation (over-blocking vs. under-blocking), not ordered chain or channel consistency — plus Campaign 03's concrete worked example.

**Architecture:** One new file, `scenariodifferentiation.go`, in the existing `internal/dlpcorrelate` package. `EvaluateScenarioDifferentiation` takes N already-computed `reporting.ComparisonResult` values, each tagged with the caller's own `ExpectedToSucceed` flag (encoding scenario design intent, not derived from the observation), and classifies the set into 5 named verdicts.

**Tech Stack:** Go stdlib only; `internal/reporting` for the `ComparisonResult` type only.

**Spec:** `orchestrator/docs/superpowers/specs/2026-10-18-dlpcorrelate-campaign03-design.md`.

## Global Constraints

- `EvaluateScenarioDifferentiation` must never import or call anything from `internal/reporting` beyond the `ComparisonResult` type itself — no `Verify` call.
- An empty `cases` slice is an error, not a verdict.
- `ScenarioDifferentiationResult.Cases` must always include every input `ScenarioCase` unchanged.
- `OverBlocking` and `UnderBlocking` must be reachable as genuinely distinct verdicts from distinct code paths — never the same branch with a relabeled constant.

## Review Focus

- A `Mismatch` on an `ExpectedToSucceed: true` case (a legitimate case that got blocked) must classify as over-blocking, never under-blocking — getting this inverted would silently swap "we're too aggressive" for "we have a real risk," the two findings this campaign exists to tell apart.
- A `Mismatch` on an `ExpectedToSucceed: false` case (the unauthorized case got through) must classify as under-blocking — the real-risk finding — and must never be masked by a simultaneous `Match` on a legitimate case (i.e. 2-of-3 correct must not average out to "mostly fine").
- Both an over-block and an under-block present in the same input (e.g. normal delivery wrongly blocked AND unauthorized sharing wrongly allowed) must resolve to a 5th, distinct "both" verdict — never silently picked as just one of the two.
- All-`MissingEvidence` input must resolve to an explicit insufficient-evidence verdict, never defaulted to "differentiates correctly" (the same false-safety-claim anti-goal as Campaign 02's `InsufficientEvidence`).
- `Campaign03EmailPolicyAndExceptionFailure`'s 3 named parameters must each retain their own case label in the returned result, and the justified-override case must be wired with `ExpectedToSucceed: true` (an authorized exception is supposed to succeed, with override evidence) — not accidentally treated like the unauthorized-sharing case just because both involve an exception-like action.

---

### Task 1: Scenario differentiation core + Campaign 03

**Files:**
- Create: `orchestrator/internal/dlpcorrelate/scenariodifferentiation.go`
- Test: `orchestrator/internal/dlpcorrelate/scenariodifferentiation_test.go`

**Interfaces:**
- Consumes: `reporting.ComparisonResult` (read-only type usage, same as `campaign01.go`/`channelconsistency.go`).
- Produces: `DifferentiationVerdict` (+5 constants), `ScenarioCase{Label, ExpectedToSucceed bool, Comparison reporting.ComparisonResult, Reason string}`, `ScenarioDifferentiationResult{Cases []ScenarioCase, Verdict DifferentiationVerdict, Reason string}`, `EvaluateScenarioDifferentiation(cases []ScenarioCase) (ScenarioDifferentiationResult, error)`, `Campaign03EmailPolicyAndExceptionFailure(normalDelivery, justifiedOverride, unauthorizedSharing ScenarioCase) (ScenarioDifferentiationResult, error)` — terminal.

- [ ] **Step 1: Write the failing tests**

```go
package dlpcorrelate

import (
	"testing"

	"github.com/audspect/bas/internal/reporting"
)

func TestEvaluateScenarioDifferentiation_AllMatch_DifferentiatesCorrectly(t *testing.T) {
	cases := []ScenarioCase{
		{Label: "normal-delivery", ExpectedToSucceed: true, Comparison: reporting.Match},
		{Label: "justified-override", ExpectedToSucceed: true, Comparison: reporting.Match},
		{Label: "unauthorized-sharing", ExpectedToSucceed: false, Comparison: reporting.Match},
	}
	got, err := EvaluateScenarioDifferentiation(cases)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Verdict != DifferentiatesCorrectly {
		t.Errorf("Verdict = %v, want DifferentiatesCorrectly", got.Verdict)
	}
	if len(got.Cases) != 3 {
		t.Fatalf("Cases len = %d, want 3", len(got.Cases))
	}
}

func TestEvaluateScenarioDifferentiation_LegitimateCaseBlocked_OverBlocking(t *testing.T) {
	cases := []ScenarioCase{
		{Label: "normal-delivery", ExpectedToSucceed: true, Comparison: reporting.Mismatch},
		{Label: "unauthorized-sharing", ExpectedToSucceed: false, Comparison: reporting.Match},
	}
	got, err := EvaluateScenarioDifferentiation(cases)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Verdict != OverBlocking {
		t.Errorf("Verdict = %v, want OverBlocking (a legitimate case was blocked), not UnderBlocking or any other verdict", got.Verdict)
	}
}

func TestEvaluateScenarioDifferentiation_UnauthorizedCaseGotThrough_UnderBlocking(t *testing.T) {
	cases := []ScenarioCase{
		{Label: "normal-delivery", ExpectedToSucceed: true, Comparison: reporting.Match},
		{Label: "unauthorized-sharing", ExpectedToSucceed: false, Comparison: reporting.Mismatch},
	}
	got, err := EvaluateScenarioDifferentiation(cases)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Verdict != UnderBlocking {
		t.Errorf("Verdict = %v, want UnderBlocking (the unauthorized case got through) -- the real-risk finding, must not be masked by the other case's Match", got.Verdict)
	}
}

func TestEvaluateScenarioDifferentiation_BothDirectionsFail_MixedDifferentiationFailure(t *testing.T) {
	cases := []ScenarioCase{
		{Label: "normal-delivery", ExpectedToSucceed: true, Comparison: reporting.Mismatch},
		{Label: "unauthorized-sharing", ExpectedToSucceed: false, Comparison: reporting.Mismatch},
	}
	got, err := EvaluateScenarioDifferentiation(cases)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Verdict != MixedDifferentiationFailure {
		t.Errorf("Verdict = %v, want MixedDifferentiationFailure -- must never silently pick just OverBlocking or just UnderBlocking when both are present", got.Verdict)
	}
}

func TestEvaluateScenarioDifferentiation_AllMissingEvidence_InsufficientEvidence(t *testing.T) {
	cases := []ScenarioCase{
		{Label: "normal-delivery", ExpectedToSucceed: true, Comparison: reporting.MissingEvidence},
		{Label: "unauthorized-sharing", ExpectedToSucceed: false, Comparison: reporting.MissingEvidence},
	}
	got, err := EvaluateScenarioDifferentiation(cases)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Verdict != DifferentiationInsufficientEvidence {
		t.Errorf("Verdict = %v, want DifferentiationInsufficientEvidence -- must never default to DifferentiatesCorrectly", got.Verdict)
	}
}

func TestEvaluateScenarioDifferentiation_EmptyInput_IsError(t *testing.T) {
	_, err := EvaluateScenarioDifferentiation(nil)
	if err == nil {
		t.Error("expected an error for an empty cases slice")
	}
}

func TestCampaign03EmailPolicyAndExceptionFailure_JustifiedOverrideExpectedToSucceed(t *testing.T) {
	normalDelivery := ScenarioCase{Label: "normal-delivery", ExpectedToSucceed: true, Comparison: reporting.Match}
	justifiedOverride := ScenarioCase{Label: "justified-override", ExpectedToSucceed: true, Comparison: reporting.Match}
	unauthorizedSharing := ScenarioCase{Label: "unauthorized-sharing", ExpectedToSucceed: false, Comparison: reporting.Match}

	got, err := Campaign03EmailPolicyAndExceptionFailure(normalDelivery, justifiedOverride, unauthorizedSharing)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Verdict != DifferentiatesCorrectly {
		t.Errorf("Verdict = %v, want DifferentiatesCorrectly", got.Verdict)
	}
	for _, c := range got.Cases {
		if c.Label == "justified-override" && !c.ExpectedToSucceed {
			t.Error("justified-override must be wired with ExpectedToSucceed=true -- an authorized exception is supposed to succeed, not treated like the unauthorized case")
		}
	}
}

func TestCampaign03EmailPolicyAndExceptionFailure_OverrideWronglyBlocked_OverBlocking(t *testing.T) {
	normalDelivery := ScenarioCase{Label: "normal-delivery", ExpectedToSucceed: true, Comparison: reporting.Match}
	justifiedOverride := ScenarioCase{Label: "justified-override", ExpectedToSucceed: true, Comparison: reporting.Mismatch}
	unauthorizedSharing := ScenarioCase{Label: "unauthorized-sharing", ExpectedToSucceed: false, Comparison: reporting.Match}

	got, err := Campaign03EmailPolicyAndExceptionFailure(normalDelivery, justifiedOverride, unauthorizedSharing)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Verdict != OverBlocking {
		t.Errorf("Verdict = %v, want OverBlocking -- an authorized override that gets blocked anyway is a false positive, not a safety success", got.Verdict)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test github.com/audspect/bas/internal/dlpcorrelate/... -run "TestEvaluateScenarioDifferentiation|TestCampaign03" -v`
Expected: FAIL (`undefined: ScenarioCase`, `undefined: EvaluateScenarioDifferentiation`, etc. — build failure)

- [ ] **Step 3: Implement**

`scenariodifferentiation.go`: `DifferentiationVerdict` string type + 5 constants (`DifferentiatesCorrectly`/`OverBlocking`/`UnderBlocking`/`MixedDifferentiationFailure`/`DifferentiationInsufficientEvidence`); `ScenarioCase{Label string, ExpectedToSucceed bool, Comparison reporting.ComparisonResult, Reason string}`; `ScenarioDifferentiationResult{Cases []ScenarioCase, Verdict DifferentiationVerdict, Reason string}`.

`EvaluateScenarioDifferentiation(cases []ScenarioCase) (ScenarioDifferentiationResult, error)`: error if `len(cases) == 0`. Scan `cases`: for each `reporting.Match`, increment `matchCount`. For each `reporting.Mismatch`, increment `overBlockCount` if `ExpectedToSucceed` else `underBlockCount`. Classify: both `overBlockCount` and `underBlockCount` > 0 → `MixedDifferentiationFailure`; only `overBlockCount` > 0 → `OverBlocking`; only `underBlockCount` > 0 → `UnderBlocking`; `matchCount` > 0 (and both block counts zero) → `DifferentiatesCorrectly`; else → `DifferentiationInsufficientEvidence`. `Reason` is a `fmt.Sprintf` naming the counts/labels for each case. Copy `cases` into `ScenarioDifferentiationResult.Cases` unchanged.

`Campaign03EmailPolicyAndExceptionFailure(normalDelivery, justifiedOverride, unauthorizedSharing ScenarioCase) (ScenarioDifferentiationResult, error)`: calls `EvaluateScenarioDifferentiation([]ScenarioCase{normalDelivery, justifiedOverride, unauthorizedSharing})` and returns its result directly. Doc comment cites `dlp.txt`'s exact Campaign 03 text and states the "policy audit evidence" half is closed by reusing `reporting.DLPEvidence.Override`/`ComparisonResult` (no new evidence source), per the spec's Non-goals.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test github.com/audspect/bas/internal/dlpcorrelate/... -v`
Expected: PASS (all tests in the package, including Campaign 01/02's pre-existing ones)

- [ ] **Step 5: `gofmt -l`, `go vet`, full module build**

Run: `gofmt -l orchestrator/internal/dlpcorrelate/`, `go vet github.com/audspect/bas/internal/dlpcorrelate/...`, `go build github.com/audspect/bas/...`
Expected: no output from the first two for the NEW files specifically (pre-existing `chain.go`/`campaign01.go` files may show a known CRLF-checkout artifact, already investigated in an earlier slice — confirm it's that, not a real issue, before dismissing), clean build from the third

- [ ] **Step 6: Commit**

```bash
git status --porcelain
git add orchestrator/internal/dlpcorrelate/scenariodifferentiation.go orchestrator/internal/dlpcorrelate/scenariodifferentiation_test.go
git commit -m "feat(dlpcorrelate): add scenario-differentiation aggregate and Campaign 03"
```

(run `git status --porcelain` BEFORE and AFTER the `git add` to confirm no other file was left uncommitted.)

---

## Self-Review Notes

- **Spec coverage:** Goal 1 (generic scenario-differentiation aggregate) → Task 1's core. Goal 2 (Campaign 03 wrapper) → Task 1's `Campaign03EmailPolicyAndExceptionFailure`. Goal 3 (decoupling) → implementation note.
- **Step scan:** classification logic described by its exact branching rule, pinned by the 8 tests above.
- **Type consistency:** `ScenarioCase` field names match across test fixtures, Interfaces block, and Step 3 notes.
- **Review Focus:** all 5 items have a named test above (over-block direction, under-block direction not masked, both-at-once distinct verdict, all-MissingEvidence not defaulted to correct, Campaign 03's override-case wiring).
- **Proportion check:** 1 task, same size as Campaign 02's single task — proportionate, reusing the existing package and `reporting.ComparisonResult` type.
- **Anti-goal check:** no `CorrelationChain`/`StageResult`/`ChannelResult`/`ConsistencyVerdict` referenced anywhere in `scenariodifferentiation.go` — confirmed structurally independent from both prior aggregates.
