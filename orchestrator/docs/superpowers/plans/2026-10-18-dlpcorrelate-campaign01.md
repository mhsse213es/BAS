# dlpcorrelate + Campaign 01 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the generic, evaluator-agnostic ordered-stage chain core (`internal/dlpcorrelate`) and one real worked example — `dlp.txt` §3C's Campaign 01 ("Sensitive record to external disclosure") — wired to already-built DLP-CLS and DLP-ENF verdicts.

**Architecture:** A single new package with two files: the generic chain core (`StageOutcome`/`StageResult`/`CorrelationChain`/`EvaluateCorrelationChain`, mirroring `internal/avefficacy/multistage.go`'s chain-stop/non-offsetting pattern, generalized away from AV-specific types) and Campaign 01's concrete definition + translation function (`EvaluateCampaign01`), which converts already-computed `dlpclassify.DLPCLSVerdict`/`reporting.ComparisonResult` values into the chain's own `StageResult` currency. No new DLP-CLS/DLP-ENF logic — this package only sequences and aggregates.

**Tech Stack:** Go stdlib only; `internal/dlpclassify` and `internal/reporting` for their verdict/comparison TYPES only (no behavioral coupling — this package never calls either package's `Verify`/`VerifyClassificationSample`/etc. functions itself).

**Spec:** `orchestrator/docs/superpowers/specs/2026-10-18-dlpcorrelate-design.md`.

## Global Constraints

- `EvaluateCorrelationChain` never imports `avefficacy`/`avcatalog`/`avval` — the chain-stop pattern is borrowed, never the dependency.
- `StageFailed` and `StageContinues` both let the chain advance; `StageCaught`/`StageInconclusive`/`StageNotTested` all stop it. A stage after the stopping point gets a `StageSkipped: true` placeholder, never silently omitted from the result list.
- `ChainResult.AnyFailed`/`AnyNotTested` scan every stage in the full result list (reached + skipped), never just the last one — a failure at stage 1 must still show up even if stage 3 blocks the disclosure.
- Campaign 01's 4th stage (security event/case evidence) is ALWAYS `StageNotTested` in `EvaluateCampaign01` today — no parameter or code path may produce anything else for it, since no DLP-specific telemetry/case-correlation evaluator exists in this repo.
- `reached []StageResult` passed to `EvaluateCorrelationChain` may be shorter than `chain.Stages` — the function itself fills in the skipped placeholders; callers never pre-build them.

## Review Focus

- A `reached` slice that is already shorter than `chain.Stages` because the CALLER stopped early (e.g. only evaluated 2 of 4 stages) must still produce correctly-labeled `StageSkipped` placeholders for stage 3 and 4, not just stage 4 — test with a 2-of-4 `reached` input, not just 3-of-4.
- `StageFailed` at a non-final stage must NOT stop the chain — a reasonable person reading "non-offsetting" would expect a failure at stage 1 to still let stage 2/3 run and report their own real outcomes, not auto-abort. Test explicitly: stage 1 `StageFailed`, stage 2 still evaluated and reaches `StageContinues`.
- `AnyFailed` must be true even when the ONLY failure is on an already-skipped stage's own result — this can't literally happen (skipped stages are never `StageFailed`, only placeholders), so instead test that `AnyFailed` stays true when stage 1 fails but a LATER stage (reached, not skipped) returns `StageContinues` — a later "clean" stage must never flip `AnyFailed` back to false.
- Campaign 01's stage 4 must be `StageNotTested` regardless of how stages 1-3 resolved — test with stages 1-3 all `StageContinues`/`Match` (a "clean" run) and confirm stage 4 is still `StageNotTested`, not silently upgraded to looking complete just because the rest of the chain passed.
- `EvaluateCampaign01`'s translation of `reporting.Mismatch` (data got through despite an expected block) must map to `StageFailed`, not `StageCaught` — confusing these two would silently invert Campaign 01's single most important real-world signal (did the unauthorized disclosure actually succeed).

---

### Task 1: Generic chain core

**Files:**
- Create: `orchestrator/internal/dlpcorrelate/chain.go`
- Test: `orchestrator/internal/dlpcorrelate/chain_test.go`

**Interfaces:**
- Consumes: nothing — this is the foundation.
- Produces: `StageOutcome` (+ 5 constants), `StageResult`, `StageDefinition`, `CorrelationChain`, `ChainResult`, `EvaluateCorrelationChain(chain CorrelationChain, reached []StageResult) (ChainResult, error)` — consumed by Task 2.

```go
// chain.go -- exactly per the spec's Builder's call code block:
// StageOutcome (StageContinues/StageCaught/StageFailed/StageInconclusive/StageNotTested),
// StageResult{StageOrder, Label, Dimension, Outcome, Reason, StageSkipped},
// StageDefinition{Label, Dimension}, CorrelationChain{ID, Name, Stages},
// ChainResult{ChainID, StageResults, AnyFailed, AnyNotTested, StoppedAtLabel}.
```

`EvaluateCorrelationChain`: validates `len(reached) <= len(chain.Stages)` (error if not). Walks `chain.Stages` in order; for `i < len(reached)`, uses `reached[i]` (overwriting its `StageOrder`/`Label`/`Dimension` from `chain.Stages[i]` if the caller left them zero-valued — simplest: trust the caller supplied them correctly, no overwrite, but validate `reached[i].StageOrder == i+1` and error if not, catching a caller ordering bug early). For `i >= len(reached)`, appends a placeholder: `StageResult{StageOrder: i+1, Label: chain.Stages[i].Label, Dimension: chain.Stages[i].Dimension, StageSkipped: true, Reason: fmt.Sprintf("stage %q not reached", chain.Stages[i].Label)}`. Sets `AnyFailed`/`AnyNotTested` by scanning the full combined list. `StoppedAtLabel` is the label of the LAST entry in `reached` (the stage where the caller itself stopped supplying results) when `len(reached) < len(chain.Stages)`, else empty.

- [ ] **Step 1: Write the failing tests**

```go
package dlpcorrelate

import "testing"

func fourStageChain() CorrelationChain {
	return CorrelationChain{
		ID:   "TEST-CHAIN",
		Name: "test chain",
		Stages: []StageDefinition{
			{Label: "stage 1", Dimension: "DIM1"},
			{Label: "stage 2", Dimension: "DIM2"},
			{Label: "stage 3", Dimension: "DIM3"},
			{Label: "stage 4", Dimension: "DIM4"},
		},
	}
}

func TestEvaluateCorrelationChain_AllContinue_NoSkips(t *testing.T) {
	reached := []StageResult{
		{StageOrder: 1, Label: "stage 1", Dimension: "DIM1", Outcome: StageContinues},
		{StageOrder: 2, Label: "stage 2", Dimension: "DIM2", Outcome: StageContinues},
		{StageOrder: 3, Label: "stage 3", Dimension: "DIM3", Outcome: StageContinues},
		{StageOrder: 4, Label: "stage 4", Dimension: "DIM4", Outcome: StageContinues},
	}
	got, err := EvaluateCorrelationChain(fourStageChain(), reached)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got.StageResults) != 4 {
		t.Fatalf("StageResults len = %d, want 4", len(got.StageResults))
	}
	for i, r := range got.StageResults {
		if r.StageSkipped {
			t.Errorf("stage %d: StageSkipped = true, want false", i+1)
		}
	}
	if got.AnyFailed || got.AnyNotTested || got.StoppedAtLabel != "" {
		t.Errorf("got = %+v, want a clean run", got)
	}
}

func TestEvaluateCorrelationChain_TwoOfFourReached_SkipsStage3And4(t *testing.T) {
	reached := []StageResult{
		{StageOrder: 1, Label: "stage 1", Dimension: "DIM1", Outcome: StageContinues},
		{StageOrder: 2, Label: "stage 2", Dimension: "DIM2", Outcome: StageCaught},
	}
	got, err := EvaluateCorrelationChain(fourStageChain(), reached)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got.StageResults) != 4 {
		t.Fatalf("StageResults len = %d, want 4", len(got.StageResults))
	}
	if got.StageResults[2].StageSkipped != true || got.StageResults[2].Label != "stage 3" {
		t.Errorf("stage 3 = %+v, want skipped with label %q", got.StageResults[2], "stage 3")
	}
	if got.StageResults[3].StageSkipped != true || got.StageResults[3].Label != "stage 4" {
		t.Errorf("stage 4 = %+v, want skipped with label %q", got.StageResults[3], "stage 4")
	}
	if got.StoppedAtLabel != "stage 2" {
		t.Errorf("StoppedAtLabel = %q, want %q", got.StoppedAtLabel, "stage 2")
	}
}

func TestEvaluateCorrelationChain_FailureAtStage1DoesNotStopChain(t *testing.T) {
	reached := []StageResult{
		{StageOrder: 1, Label: "stage 1", Dimension: "DIM1", Outcome: StageFailed, Reason: "confirmed failure"},
		{StageOrder: 2, Label: "stage 2", Dimension: "DIM2", Outcome: StageContinues},
	}
	got, err := EvaluateCorrelationChain(fourStageChain(), reached)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.StageResults[1].StageSkipped {
		t.Error("stage 2 must not be skipped just because stage 1 failed -- failure does not stop the chain")
	}
	if got.StageResults[1].Outcome != StageContinues {
		t.Errorf("stage 2 outcome = %v, want StageContinues (caller supplied it, not re-derived)", got.StageResults[1].Outcome)
	}
}

func TestEvaluateCorrelationChain_AnyFailedStaysTrueEvenAfterLaterCleanStage(t *testing.T) {
	reached := []StageResult{
		{StageOrder: 1, Label: "stage 1", Dimension: "DIM1", Outcome: StageFailed, Reason: "confirmed failure"},
		{StageOrder: 2, Label: "stage 2", Dimension: "DIM2", Outcome: StageContinues},
	}
	got, err := EvaluateCorrelationChain(fourStageChain(), reached)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !got.AnyFailed {
		t.Error("AnyFailed must stay true: stage 1 failed, and a later clean stage must never un-set it")
	}
}

func TestEvaluateCorrelationChain_CaughtStopsChain(t *testing.T) {
	reached := []StageResult{
		{StageOrder: 1, Label: "stage 1", Dimension: "DIM1", Outcome: StageContinues},
		{StageOrder: 2, Label: "stage 2", Dimension: "DIM2", Outcome: StageCaught, Reason: "blocked"},
	}
	got, err := EvaluateCorrelationChain(fourStageChain(), reached)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !got.StageResults[2].StageSkipped {
		t.Error("stage 3 must be skipped after stage 2 caught the violation")
	}
}

func TestEvaluateCorrelationChain_TooManyReachedIsError(t *testing.T) {
	reached := make([]StageResult, 5)
	for i := range reached {
		reached[i] = StageResult{StageOrder: i + 1, Outcome: StageContinues}
	}
	_, err := EvaluateCorrelationChain(fourStageChain(), reached)
	if err == nil {
		t.Error("expected an error when reached has more entries than chain.Stages")
	}
}

func TestEvaluateCorrelationChain_OutOfOrderStageOrderIsError(t *testing.T) {
	reached := []StageResult{
		{StageOrder: 2, Label: "stage 1", Dimension: "DIM1", Outcome: StageContinues},
	}
	_, err := EvaluateCorrelationChain(fourStageChain(), reached)
	if err == nil {
		t.Error("expected an error when reached[0].StageOrder does not match its position (1)")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test github.com/audspect/bas/internal/dlpcorrelate/... -v`
Expected: FAIL (package `dlpcorrelate` does not exist yet — build failure)

- [ ] **Step 3: Implement**

`chain.go` per the spec's code block plus the `EvaluateCorrelationChain` logic described above.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test github.com/audspect/bas/internal/dlpcorrelate/... -v`
Expected: PASS (all 7 tests)

- [ ] **Step 5: `gofmt -l` and `go vet`**

Run: `gofmt -l orchestrator/internal/dlpcorrelate/` and `go vet github.com/audspect/bas/internal/dlpcorrelate/...`
Expected: no output from either (verify any `gofmt -l` hit with a CRLF-stripped diff before concluding it's real — known Windows checkout artifact on this host)

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/dlpcorrelate/chain.go orchestrator/internal/dlpcorrelate/chain_test.go
git commit -m "feat(dlpcorrelate): add evaluator-agnostic ordered-stage chain core"
```

---

### Task 2: Campaign 01 definition and translation

**Files:**
- Create: `orchestrator/internal/dlpcorrelate/campaign01.go`
- Test: `orchestrator/internal/dlpcorrelate/campaign01_test.go`

**Interfaces:**
- Consumes: Task 1's `StageResult`/`StageDefinition`/`CorrelationChain`/`EvaluateCorrelationChain`/`StageOutcome` constants (exact names). Also `dlpclassify.DLPCLSVerdict`/`DLPCLSOutcome` (`OutcomeTruePositive`/`OutcomeTrueNegative`/`OutcomeFalsePositive`/`OutcomeFalseNegative`/`OutcomeMisclassified`/`OutcomeInconclusive`/`OutcomeUnsupported`/`OutcomeNotTested` for stage 1; `OutcomeLabelCurrent`/`OutcomeLabelMissing`/`OutcomeLabelIncorrect`/`OutcomeLabelWrongInheritance`/`OutcomeLabelStale`/`OutcomeInconclusive` for stage 2) and `reporting.ComparisonResult` (`Match`/`Mismatch`/`MissingEvidence` for stage 3).
- Produces: `Campaign01SensitiveRecordToExternalDisclosure` (package-level `CorrelationChain` value), `EvaluateCampaign01(classVerdict, labelVerdict dlpclassify.DLPCLSVerdict, enfComparison reporting.ComparisonResult, enfReason string) (ChainResult, error)` — terminal, no later task consumes these.

- [ ] **Step 1: Write the failing tests**

```go
package dlpcorrelate

import (
	"testing"

	"github.com/audspect/bas/internal/dlpclassify"
	"github.com/audspect/bas/internal/reporting"
)

func TestEvaluateCampaign01_CleanRun_Stage4AlwaysNotTested(t *testing.T) {
	classVerdict := dlpclassify.DLPCLSVerdict{Outcome: dlpclassify.OutcomeTruePositive}
	labelVerdict := dlpclassify.DLPCLSVerdict{Outcome: dlpclassify.OutcomeLabelCurrent}
	got, err := EvaluateCampaign01(classVerdict, labelVerdict, reporting.Match, "observed matches expected Block")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got.StageResults) != 4 {
		t.Fatalf("StageResults len = %d, want 4", len(got.StageResults))
	}
	stage4 := got.StageResults[3]
	if stage4.Outcome != StageNotTested {
		t.Errorf("stage 4 outcome = %v, want StageNotTested even on a clean run", stage4.Outcome)
	}
	if got.AnyNotTested != true {
		t.Error("AnyNotTested must be true: stage 4 is permanently not tested")
	}
}

func TestEvaluateCampaign01_Match_StageCaughtStopsChain(t *testing.T) {
	classVerdict := dlpclassify.DLPCLSVerdict{Outcome: dlpclassify.OutcomeTruePositive}
	labelVerdict := dlpclassify.DLPCLSVerdict{Outcome: dlpclassify.OutcomeLabelCurrent}
	got, err := EvaluateCampaign01(classVerdict, labelVerdict, reporting.Match, "observed matches expected Block")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.StageResults[2].Outcome != StageCaught {
		t.Errorf("stage 3 outcome = %v, want StageCaught", got.StageResults[2].Outcome)
	}
	if !got.StageResults[3].StageSkipped {
		t.Error("stage 4 should be marked skipped (chain stopped at stage 3's Caught) even though it is also always NotTested conceptually -- EvaluateCorrelationChain's own skip logic takes precedence once the chain stops")
	}
}

func TestEvaluateCampaign01_Mismatch_MapsToStageFailedNotCaught(t *testing.T) {
	classVerdict := dlpclassify.DLPCLSVerdict{Outcome: dlpclassify.OutcomeTruePositive}
	labelVerdict := dlpclassify.DLPCLSVerdict{Outcome: dlpclassify.OutcomeLabelCurrent}
	got, err := EvaluateCampaign01(classVerdict, labelVerdict, reporting.Mismatch, "operation succeeded despite expected Block")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.StageResults[2].Outcome != StageFailed {
		t.Errorf("stage 3 outcome = %v, want StageFailed for a Mismatch (disclosure succeeded)", got.StageResults[2].Outcome)
	}
	if !got.AnyFailed {
		t.Error("AnyFailed must be true when stage 3 resolves Mismatch")
	}
}

func TestEvaluateCampaign01_MissingEvidence_MapsToInconclusiveAndStopsChain(t *testing.T) {
	classVerdict := dlpclassify.DLPCLSVerdict{Outcome: dlpclassify.OutcomeTruePositive}
	labelVerdict := dlpclassify.DLPCLSVerdict{Outcome: dlpclassify.OutcomeLabelCurrent}
	got, err := EvaluateCampaign01(classVerdict, labelVerdict, reporting.MissingEvidence, "no sink evidence")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.StageResults[2].Outcome != StageInconclusive {
		t.Errorf("stage 3 outcome = %v, want StageInconclusive for MissingEvidence", got.StageResults[2].Outcome)
	}
}

func TestEvaluateCampaign01_MisclassifiedStage1_MapsToFailedAndStage2StillRuns(t *testing.T) {
	classVerdict := dlpclassify.DLPCLSVerdict{Outcome: dlpclassify.OutcomeFalseNegative, Reason: "sensitive data not flagged"}
	labelVerdict := dlpclassify.DLPCLSVerdict{Outcome: dlpclassify.OutcomeLabelCurrent}
	got, err := EvaluateCampaign01(classVerdict, labelVerdict, reporting.Match, "observed matches expected Block")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.StageResults[0].Outcome != StageFailed {
		t.Errorf("stage 1 outcome = %v, want StageFailed for a FalseNegative", got.StageResults[0].Outcome)
	}
	if got.StageResults[1].StageSkipped {
		t.Error("stage 2 must still run after stage 1's failure -- a failure does not stop the chain")
	}
	if !got.AnyFailed {
		t.Error("AnyFailed must be true")
	}
}

func TestEvaluateCampaign01_LabelInconclusive_StopsChainBeforeStage3(t *testing.T) {
	classVerdict := dlpclassify.DLPCLSVerdict{Outcome: dlpclassify.OutcomeTruePositive}
	labelVerdict := dlpclassify.DLPCLSVerdict{Outcome: dlpclassify.OutcomeInconclusive, Reason: "no label evidence found"}
	got, err := EvaluateCampaign01(classVerdict, labelVerdict, reporting.Match, "observed matches expected Block")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.StageResults[1].Outcome != StageInconclusive {
		t.Errorf("stage 2 outcome = %v, want StageInconclusive", got.StageResults[1].Outcome)
	}
	if !got.StageResults[2].StageSkipped {
		t.Error("stage 3 must be skipped: stage 2 was inconclusive")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test github.com/audspect/bas/internal/dlpcorrelate/... -run TestEvaluateCampaign01 -v`
Expected: FAIL (`undefined: Campaign01SensitiveRecordToExternalDisclosure`, `undefined: EvaluateCampaign01`)

- [ ] **Step 3: Implement**

`campaign01.go`: the `Campaign01SensitiveRecordToExternalDisclosure` value exactly per the spec's code block. `EvaluateCampaign01`:

- Stage 1 (classify, Dimension `"DLP-CLS"`): `OutcomeTruePositive`/`OutcomeTrueNegative` → `StageContinues`; `OutcomeFalsePositive`/`OutcomeFalseNegative`/`OutcomeMisclassified` → `StageFailed`; anything else (`OutcomeInconclusive`/`OutcomeUnsupported`/`OutcomeNotTested`) → `StageInconclusive`. `Reason` carries `classVerdict.Reason`.
- Stage 2 (label lifecycle, Dimension `"DLP-CLS-LABEL"`): `OutcomeLabelCurrent` → `StageContinues`; `OutcomeLabelMissing`/`OutcomeLabelIncorrect`/`OutcomeLabelWrongInheritance`/`OutcomeLabelStale` → `StageFailed`; anything else → `StageInconclusive`. `Reason` carries `labelVerdict.Reason`.
- Stage 3 (enforcement, Dimension `"DLP-ENF"`): `reporting.Match` → `StageCaught`; `reporting.Mismatch` → `StageFailed`; anything else (`MissingEvidence`/`NotApplicable`/`Unknown`) → `StageInconclusive`. `Reason` carries the passed-in `enfReason`.
- Build the `reached []StageResult` slice up to and including however many of stages 1-3 the chain-stop logic would actually reach (stage 1 and 2 are ALWAYS included in `reached` since `StageFailed` never stops the chain at this layer — only `EvaluateCorrelationChain` itself decides to skip anything downstream of an `Inconclusive`/`Caught`/`NotTested`; this function's own job is only to build however many `StageResult`s it can compute, which is always all 3 non-permanently-gapped stages, since none of their own inputs is itself "unreachable" from this function's point of view — `EvaluateCorrelationChain` is what turns an `Inconclusive` at stage 2 into stage 3 being skipped). Never append a stage-4 result — `EvaluateCorrelationChain`'s own skip-filling handles stage 4 in every case (both when the chain already stopped earlier, and when it didn't — the Review Focus's "clean run" test proves the latter).
- Call `EvaluateCorrelationChain(Campaign01SensitiveRecordToExternalDisclosure, reached)` and return its result directly.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test github.com/audspect/bas/internal/dlpcorrelate/... -v`
Expected: PASS (all tests from both tasks)

- [ ] **Step 5: `gofmt -l`, `go vet`, full module build**

Run: `gofmt -l orchestrator/internal/dlpcorrelate/`, `go vet github.com/audspect/bas/internal/dlpcorrelate/...`, `go build github.com/audspect/bas/...`
Expected: no output from the first two, clean build from the third

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/dlpcorrelate/campaign01.go orchestrator/internal/dlpcorrelate/campaign01_test.go
git commit -m "feat(dlpcorrelate): add Campaign 01 (sensitive record to external disclosure)"
```

---

## Self-Review Notes

- **Spec coverage:** Goal 1 (generic chain core) → Task 1. Goal 2 (Campaign 01 against 3 real evaluators) → Task 2. Goal 3 (stage 4 permanently `StageNotTested`) → Task 2's `EvaluateCampaign01` design plus the dedicated "clean run" test proving it isn't silently upgraded.
- **Step scan:** `EvaluateCorrelationChain`'s body is described by its exact rules (skip-filling, ordering validation, `AnyFailed`/`AnyNotTested` scanning), not transcribed — matches the plan convention of fixing only what the implementer cannot derive from the tests + spec alone.
- **Type consistency:** Task 2's `EvaluateCampaign01` signature (`classVerdict, labelVerdict dlpclassify.DLPCLSVerdict, enfComparison reporting.ComparisonResult, enfReason string`) matches the spec's own "what's left to the builder" note that the exact parameter shape was left open — this plan pins it concretely so both the test file and implementation agree.
- **Review Focus:** all 5 items have a named test above (2-of-4 reached skip-filling, failure-doesn't-stop-chain, AnyFailed-sticky, stage-4-always-NotTested-even-on-clean-run, Mismatch-maps-to-Failed-not-Caught).
- **Proportion check:** 2 tasks, matching DLP-ENF Slice 1's size (new standalone package, foundation + one concrete worked example) — proportionate to building a generic core plus exactly one of its 6 eventual campaign consumers.
- **Anti-goal check:** no import of `avefficacy`/`avcatalog`/`avval` anywhere in either task; `EvaluateCampaign01` never calls `dlpclassify.VerifyClassificationSample`/`VerifyLabelExpectation` or any `reporting` Verify function itself — both tasks only consume already-computed verdict/comparison VALUES, matching the spec's "never re-implements or second-guesses" anti-goal.
