# dlpcorrelate Campaign 04 (Departing Employee Data Exposure) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add Campaign 04's concrete worked example, reusing Campaign 01's existing `CorrelationChain`/`EvaluateCorrelationChain` core and its existing `classificationOutcome`/`enforcementOutcome` translation helpers unchanged.

**Architecture:** One new file, `campaign04.go`, in the existing `internal/dlpcorrelate` package. No new aggregate type — this campaign's own structure (3 strictly ordered stages, the last permanently gapped) is exactly Campaign 01's shape.

**Tech Stack:** Go stdlib only; `internal/dlpclassify`/`internal/reporting` for types only (no behavioral coupling).

**Spec:** `orchestrator/docs/superpowers/specs/2026-10-18-dlpcorrelate-campaign04-design.md`.

## Global Constraints

- `campaign04.go` must not redefine `classificationOutcome`/`enforcementOutcome` — it calls the existing package-private functions from `campaign01.go` directly.
- `EvaluateCampaign04` must early-return once stage 1's outcome `.stops()`, exactly like `EvaluateCampaign01` does — never unconditionally build all `reached` entries regardless of an earlier stop (this is the exact bug class `EvaluateCampaign01`'s own implementation had to be fixed for during its own slice).
- Stage 3 ("correlate identity, data, channel and alerts") must never be included in `reached` — `EvaluateCorrelationChain`'s own skip-fill logic produces its permanent `StageNotTested` placeholder, matching Campaign 01's stage 4 precedent exactly.

## Review Focus

- A classification failure at stage 1 (e.g. `OutcomeFalseNegative`) must still let stage 2 run (`StageFailed` never stops the chain) — same non-offsetting rule as Campaign 01, re-verified here because it's easy to accidentally special-case "this is an insider-risk scenario, maybe failures should stop earlier" when writing a new campaign under time pressure.
- A clean run (stage 1 `StageContinues`, stage 2 `StageCaught`) must still show stage 3 as `StageSkipped` with `Outcome: StageNotTested` — the exact invariant `EvaluateCampaign01`'s own equivalent test caught a real bug on, re-tested here to confirm the REUSED chain-core logic (not re-implemented) still produces it correctly for a 3-stage (not 4-stage) chain.
- Stage 1's `Dimension` must be `"DLP-CLS"` and stage 2's must be `"DLP-ENF"` — matching Campaign 01's own dimension-tag vocabulary exactly (a future cross-campaign report that groups findings by Dimension must be able to treat Campaign 01's and Campaign 04's `"DLP-CLS"` stages as the same evidence family).
- `EvaluateCampaign04`'s stage-2 (enforcement) `Mismatch` → `StageFailed` mapping must use the EXISTING `enforcementOutcome` function, not a re-derived inline switch — confirm by reading the actual call site, not just the test output, that no duplicate translation logic was written.

---

### Task 1: Campaign 04

**Files:**
- Create: `orchestrator/internal/dlpcorrelate/campaign04.go`
- Test: `orchestrator/internal/dlpcorrelate/campaign04_test.go`

**Interfaces:**
- Consumes: `CorrelationChain`/`StageDefinition`/`StageResult`/`EvaluateCorrelationChain`/`StageOutcome` (from `chain.go`), `classificationOutcome`/`enforcementOutcome` (from `campaign01.go`, same package, unexported — directly callable), `dlpclassify.DLPCLSVerdict`, `reporting.ComparisonResult`.
- Produces: `Campaign04DepartingEmployeeDataExposure` (package-level `CorrelationChain` value), `EvaluateCampaign04(classVerdict dlpclassify.DLPCLSVerdict, enfComparison reporting.ComparisonResult, enfReason string) (ChainResult, error)` — terminal.

- [ ] **Step 1: Write the failing tests**

```go
package dlpcorrelate

import (
	"testing"

	"github.com/audspect/bas/internal/dlpclassify"
	"github.com/audspect/bas/internal/reporting"
)

func TestEvaluateCampaign04_CleanRun_Stage3AlwaysNotTested(t *testing.T) {
	classVerdict := dlpclassify.DLPCLSVerdict{Outcome: dlpclassify.OutcomeTruePositive}
	got, err := EvaluateCampaign04(classVerdict, reporting.Match, "observed matches expected Block")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got.StageResults) != 3 {
		t.Fatalf("StageResults len = %d, want 3", len(got.StageResults))
	}
	stage3 := got.StageResults[2]
	if stage3.Outcome != StageNotTested || !stage3.StageSkipped {
		t.Errorf("stage 3 = %+v, want StageNotTested+StageSkipped even on a clean run", stage3)
	}
	if got.AnyNotTested != true {
		t.Error("AnyNotTested must be true: stage 3 is permanently not tested")
	}
}

func TestEvaluateCampaign04_Match_StageCaughtStopsChain(t *testing.T) {
	classVerdict := dlpclassify.DLPCLSVerdict{Outcome: dlpclassify.OutcomeTruePositive}
	got, err := EvaluateCampaign04(classVerdict, reporting.Match, "observed matches expected Block")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.StageResults[1].Outcome != StageCaught {
		t.Errorf("stage 2 outcome = %v, want StageCaught", got.StageResults[1].Outcome)
	}
}

func TestEvaluateCampaign04_Mismatch_MapsToStageFailedViaExistingHelper(t *testing.T) {
	classVerdict := dlpclassify.DLPCLSVerdict{Outcome: dlpclassify.OutcomeTruePositive}
	got, err := EvaluateCampaign04(classVerdict, reporting.Mismatch, "export succeeded despite expected Block")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.StageResults[1].Outcome != StageFailed {
		t.Errorf("stage 2 outcome = %v, want StageFailed for a Mismatch", got.StageResults[1].Outcome)
	}
	if !got.AnyFailed {
		t.Error("AnyFailed must be true")
	}
}

func TestEvaluateCampaign04_MisclassifiedStage1_StillRunsStage2(t *testing.T) {
	classVerdict := dlpclassify.DLPCLSVerdict{Outcome: dlpclassify.OutcomeFalseNegative, Reason: "sensitive dataset record not flagged"}
	got, err := EvaluateCampaign04(classVerdict, reporting.Match, "observed matches expected Block")
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

func TestCampaign04DepartingEmployeeDataExposure_StageDimensionsMatchCampaign01Vocabulary(t *testing.T) {
	stages := Campaign04DepartingEmployeeDataExposure.Stages
	if len(stages) != 3 {
		t.Fatalf("Stages len = %d, want 3", len(stages))
	}
	if stages[0].Dimension != "DLP-CLS" {
		t.Errorf("stage 1 Dimension = %q, want %q", stages[0].Dimension, "DLP-CLS")
	}
	if stages[1].Dimension != "DLP-ENF" {
		t.Errorf("stage 2 Dimension = %q, want %q", stages[1].Dimension, "DLP-ENF")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test github.com/audspect/bas/internal/dlpcorrelate/... -run "TestEvaluateCampaign04|TestCampaign04" -v`
Expected: FAIL (`undefined: Campaign04DepartingEmployeeDataExposure`, `undefined: EvaluateCampaign04` — build failure)

- [ ] **Step 3: Implement**

`campaign04.go`: `Campaign04DepartingEmployeeDataExposure = CorrelationChain{ID: "DLPCORRELATE-CAMPAIGN-04", Name: "Departing employee data exposure", Stages: []StageDefinition{{Label: "access seeded business dataset via scoped test identity", Dimension: "DLP-CLS"}, {Label: "exercise authorized export and controlled external-sharing cases", Dimension: "DLP-ENF"}, {Label: "correlate identity, data, channel and alerts", Dimension: ""}}}`.

`EvaluateCampaign04(classVerdict dlpclassify.DLPCLSVerdict, enfComparison reporting.ComparisonResult, enfReason string) (ChainResult, error)`: build stage 1 via `classificationOutcome(classVerdict.Outcome)` with `Dimension: "DLP-CLS"`; if `.stops()`, call `EvaluateCorrelationChain` with just that one entry. Else build stage 2 via `enforcementOutcome(enfComparison)` with `Dimension: "DLP-ENF"`, append, call `EvaluateCorrelationChain` with both entries. Never build a stage-3 entry. Mirror `EvaluateCampaign01`'s exact early-return structure (read `campaign01.go` for the precedent before writing this).

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test github.com/audspect/bas/internal/dlpcorrelate/... -v`
Expected: PASS (all tests in the package, including Campaigns 01-03's pre-existing ones)

- [ ] **Step 5: `gofmt -l`, `go vet`, full module build**

Run: `gofmt -l orchestrator/internal/dlpcorrelate/campaign04.go orchestrator/internal/dlpcorrelate/campaign04_test.go`, `go vet github.com/audspect/bas/internal/dlpcorrelate/...`, `go build github.com/audspect/bas/...`
Expected: no output from the first two (checking only the NEW files), clean build from the third

- [ ] **Step 6: Commit**

```bash
git status --porcelain
git add orchestrator/internal/dlpcorrelate/campaign04.go orchestrator/internal/dlpcorrelate/campaign04_test.go
git commit -m "feat(dlpcorrelate): add Campaign 04 (departing employee data exposure)"
```

(run `git status --porcelain` BEFORE and AFTER `git add` to confirm no other file was left uncommitted.)

---

## Self-Review Notes

- **Spec coverage:** Goal 1 (chain definition) → Step 3's `Campaign04DepartingEmployeeDataExposure`. Goal 2 (translation function reusing existing helpers) → Step 3's `EvaluateCampaign04`.
- **Step scan:** implementation described by its exact early-return structure (mirroring `campaign01.go`'s own precedent, explicitly told to read it first), not transcribed, since the tests above pin every branch.
- **Type consistency:** stage `Dimension` values (`"DLP-CLS"`/`"DLP-ENF"`) match Campaign 01's own vocabulary exactly, confirmed by a dedicated test.
- **Review Focus:** all 4 items have a named test above (non-offsetting rule re-verified for a 3-stage chain, stage-3 permanent-gap invariant re-verified, dimension-vocabulary consistency, reuse-not-reimplementation of the translation helpers implicit in the plan's own Step 3 instruction to call the existing functions directly rather than writing new ones — a code-review-time check, not a runtime-testable one, so it's listed in Review Focus for the final reviewer to hand-verify against the actual call site).
- **Proportion check:** 1 task, smaller than Campaign 01's 2 tasks — proportionate, since this slice adds zero new aggregate logic, only a new chain definition and translation wrapper reusing 100% of Campaign 01's existing machinery.
- **Anti-goal check:** no duplicate `classificationOutcome`/`enforcementOutcome`-equivalent logic anywhere in `campaign04.go`; no fabricated 4th "identity permission" stage.
