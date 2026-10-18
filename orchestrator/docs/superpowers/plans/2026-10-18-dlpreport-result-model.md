# dlpreport Unified Result Model Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a new standalone package `internal/dlpreport` holding `dlp.txt` §6's 12-field unified evidence record shape, its 4 named outcome enums, and one safe classification-translation helper.

**Architecture:** Two files: `record.go` (types + `ClassificationOutcomeFromDLPCLS` + `Validate`), `record_test.go`. No dependency on `internal/reporting` or `internal/dlpcorrelate` — only `internal/dlpclassify`, for the one translation helper's input type.

**Tech Stack:** Go stdlib only (`time`, `fmt`).

**Spec:** `orchestrator/docs/superpowers/specs/2026-10-18-dlpreport-result-model-design.md`.

## Global Constraints

- `Enforcement`/`Telemetry`/`Response` on `Record` are always caller-supplied — this package defines no function that computes them from another package's type.
- `ClassificationOutcomeFromDLPCLS` must map every `dlpclassify.DLPCLSOutcome` constant that exists today to a defined `ClassificationOutcome` value — an unrecognized/future outcome must map to `ClassificationUnknown` via a `default` case, never a zero value that looks like a real answer.
- `Validate()` only reports a defect; it must never mutate the `Record` it's called on.

## Review Focus

- `ClassificationOutcomeFromDLPCLS(OutcomeMisclassified)` must return `ClassificationIncorrect`, not `ClassificationCorrect` — easy to miss since `OutcomeMisclassified` sounds closer to "sort of correct" (the sample WAS flagged sensitive) than `OutcomeFalseNegative`, but `dlpclassify`'s own doc comment is explicit that misclassified is "never collapsed into TruePositive."
- The 5 label-lifecycle outcomes (`OutcomeLabelMissing`/`OutcomeLabelIncorrect`/`OutcomeLabelWrongInheritance`/`OutcomeLabelStale`/`OutcomeLabelCurrent`) belong to a different measurement dimension (label lifecycle, not classification accuracy) per `dlpclassify`'s own doc comment — they must map to `ClassificationUnknown`, not be silently treated as `ClassificationCorrect`/`ClassificationIncorrect`, since this helper's job is classification-accuracy translation only.
- `Validate()` must flag a `Record` whose `Enforcement` is `EnforcementUnknown` (or any of the other 3 dimensions' "uncertain" value) AND whose `Limitations` is empty — but must NOT flag a `Record` whose uncertain dimension already has a populated `Limitations` explaining why, even if every other dimension is fully certain.
- A `Record` with ALL 4 dimensions fully certain (e.g. `EnforcementBlocked`, `ClassificationCorrect`, `TelemetryPresent`, `ResponseAlerted`) and an empty `Limitations` must pass `Validate()` — the check is conditional on uncertainty existing, not a blanket "Limitations must always be non-empty" rule (that stronger rule belongs to `DLPEvidence`, a different type with a different contract, not duplicated here).

---

### Task 1: dlpreport record types, enums, and validation

**Files:**
- Create: `orchestrator/internal/dlpreport/record.go`
- Test: `orchestrator/internal/dlpreport/record_test.go`

**Interfaces:**
- Consumes: `dlpclassify.DLPCLSOutcome` and its constants (type only).
- Produces: `EnforcementOutcome`/`ClassificationOutcome`/`TelemetryOutcome`/`ResponseOutcome` (string types + constants), `EvidenceProvenance`, `Record`, `ClassificationOutcomeFromDLPCLS(dlpclassify.DLPCLSOutcome) ClassificationOutcome`, `(Record) Validate() error`.

- [ ] **Step 1: Write the failing tests**

```go
package dlpreport

import (
	"testing"

	"github.com/audspect/bas/internal/dlpclassify"
)

func TestClassificationOutcomeFromDLPCLS_TruePositiveAndTrueNegative_AreCorrect(t *testing.T) {
	if got := ClassificationOutcomeFromDLPCLS(dlpclassify.OutcomeTruePositive); got != ClassificationCorrect {
		t.Errorf("OutcomeTruePositive -> %v, want ClassificationCorrect", got)
	}
	if got := ClassificationOutcomeFromDLPCLS(dlpclassify.OutcomeTrueNegative); got != ClassificationCorrect {
		t.Errorf("OutcomeTrueNegative -> %v, want ClassificationCorrect", got)
	}
}

func TestClassificationOutcomeFromDLPCLS_Misclassified_IsIncorrectNotCorrect(t *testing.T) {
	got := ClassificationOutcomeFromDLPCLS(dlpclassify.OutcomeMisclassified)
	if got != ClassificationIncorrect {
		t.Errorf("OutcomeMisclassified -> %v, want ClassificationIncorrect", got)
	}
}

func TestClassificationOutcomeFromDLPCLS_FalsePositiveAndFalseNegative_AreIncorrect(t *testing.T) {
	if got := ClassificationOutcomeFromDLPCLS(dlpclassify.OutcomeFalsePositive); got != ClassificationIncorrect {
		t.Errorf("OutcomeFalsePositive -> %v, want ClassificationIncorrect", got)
	}
	if got := ClassificationOutcomeFromDLPCLS(dlpclassify.OutcomeFalseNegative); got != ClassificationIncorrect {
		t.Errorf("OutcomeFalseNegative -> %v, want ClassificationIncorrect", got)
	}
}

func TestClassificationOutcomeFromDLPCLS_Unsupported_IsUnsupported(t *testing.T) {
	got := ClassificationOutcomeFromDLPCLS(dlpclassify.OutcomeUnsupported)
	if got != ClassificationUnsupported {
		t.Errorf("OutcomeUnsupported -> %v, want ClassificationUnsupported", got)
	}
}

func TestClassificationOutcomeFromDLPCLS_NotTestedAndInconclusive_AreNotEvaluated(t *testing.T) {
	if got := ClassificationOutcomeFromDLPCLS(dlpclassify.OutcomeNotTested); got != ClassificationNotEvaluated {
		t.Errorf("OutcomeNotTested -> %v, want ClassificationNotEvaluated", got)
	}
	if got := ClassificationOutcomeFromDLPCLS(dlpclassify.OutcomeInconclusive); got != ClassificationNotEvaluated {
		t.Errorf("OutcomeInconclusive -> %v, want ClassificationNotEvaluated", got)
	}
}

func TestClassificationOutcomeFromDLPCLS_LabelLifecycleOutcomes_AreUnknownNotCorrect(t *testing.T) {
	labelOutcomes := []dlpclassify.DLPCLSOutcome{
		dlpclassify.OutcomeLabelMissing,
		dlpclassify.OutcomeLabelIncorrect,
		dlpclassify.OutcomeLabelWrongInheritance,
		dlpclassify.OutcomeLabelStale,
		dlpclassify.OutcomeLabelCurrent,
	}
	for _, o := range labelOutcomes {
		if got := ClassificationOutcomeFromDLPCLS(o); got != ClassificationUnknown {
			t.Errorf("%v -> %v, want ClassificationUnknown", o, got)
		}
	}
}

func TestClassificationOutcomeFromDLPCLS_UnrecognizedValue_IsUnknown(t *testing.T) {
	got := ClassificationOutcomeFromDLPCLS(dlpclassify.DLPCLSOutcome("some-future-outcome"))
	if got != ClassificationUnknown {
		t.Errorf("unrecognized outcome -> %v, want ClassificationUnknown", got)
	}
}

func TestRecordValidate_UncertainDimensionWithEmptyLimitations_IsError(t *testing.T) {
	r := Record{Enforcement: EnforcementUnknown, Limitations: ""}
	if err := r.Validate(); err == nil {
		t.Fatal("expected an error for EnforcementUnknown with empty Limitations, got nil")
	}
}

func TestRecordValidate_UncertainDimensionWithPopulatedLimitations_IsNoError(t *testing.T) {
	r := Record{Enforcement: EnforcementUnknown, Limitations: "local observer could not distinguish Allow from Warn"}
	if err := r.Validate(); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestRecordValidate_AllCertainWithEmptyLimitations_IsNoError(t *testing.T) {
	r := Record{
		Enforcement:    EnforcementBlocked,
		Classification: ClassificationCorrect,
		Telemetry:      TelemetryPresent,
		Response:       ResponseAlerted,
		Limitations:    "",
	}
	if err := r.Validate(); err != nil {
		t.Errorf("unexpected error for a fully-certain record: %v", err)
	}
}

func TestRecordValidate_TelemetryUnverifiableWithEmptyLimitations_IsError(t *testing.T) {
	r := Record{Telemetry: TelemetryUnverifiable, Limitations: ""}
	if err := r.Validate(); err == nil {
		t.Fatal("expected an error for TelemetryUnverifiable with empty Limitations, got nil")
	}
}

func TestRecordValidate_ResponseNotTestedWithEmptyLimitations_IsError(t *testing.T) {
	r := Record{Response: ResponseNotTested, Limitations: ""}
	if err := r.Validate(); err == nil {
		t.Fatal("expected an error for ResponseNotTested with empty Limitations, got nil")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test github.com/audspect/bas/internal/dlpreport/... -v`
Expected: FAIL (`no Go files in ...` / `undefined: ClassificationOutcomeFromDLPCLS` — build failure, package doesn't exist yet)

- [ ] **Step 3: Implement**

`record.go`: define the 4 enum types + constants exactly as named in the spec's Goals section (`EnforcementOutcome` with `EnforcementAllowed`/`EnforcementBlocked`/`EnforcementQuarantined`/`EnforcementEncrypted`/`EnforcementChallenged`/`EnforcementOverridden`/`EnforcementUnknown`; `ClassificationOutcome` with `ClassificationCorrect`/`ClassificationIncorrect`/`ClassificationNotEvaluated`/`ClassificationUnsupported`/`ClassificationUnknown`; `TelemetryOutcome` with `TelemetryAbsent`/`TelemetryPresent`/`TelemetryDelayed`/`TelemetryIncomplete`/`TelemetryUnverifiable`; `ResponseOutcome` with `ResponseAlerted`/`ResponseCaseCreated`/`ResponseEscalated`/`ResponseRemediated`/`ResponseNotTested`). `EvidenceProvenance` and `Record` structs per the spec's Goals section field list. `ClassificationOutcomeFromDLPCLS` as a switch per the Review Focus mapping (label-lifecycle outcomes and any unrecognized value fall to a `default: return ClassificationUnknown`). `(r Record) Validate() error`: define an `uncertain()` check per dimension (`Enforcement == EnforcementUnknown`, `Classification == ClassificationUnknown || Classification == ClassificationNotEvaluated`, `Telemetry == TelemetryUnverifiable`, `Response == ResponseNotTested`); if any is true and `r.Limitations == ""`, return an error naming which dimension(s); else return nil.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test github.com/audspect/bas/internal/dlpreport/... -v`
Expected: PASS (all 11 tests)

- [ ] **Step 5: `gofmt -l`, `go vet`, full module build**

Run: `gofmt -l orchestrator/internal/dlpreport/record.go orchestrator/internal/dlpreport/record_test.go`, `go vet github.com/audspect/bas/internal/dlpreport/...`, `go build github.com/audspect/bas/...`
Expected: no output from the first two, clean build from the third

- [ ] **Step 6: Commit**

```bash
git status --porcelain
git add orchestrator/internal/dlpreport/record.go orchestrator/internal/dlpreport/record_test.go
git commit -m "feat(dlpreport): add unified §6 result-model record type"
```

(run `git status --porcelain` BEFORE and AFTER `git add` to confirm no other file was left uncommitted.)

---

## Self-Review Notes

- **Spec coverage:** Goal 1's full bullet list → Step 3 (types, `ClassificationOutcomeFromDLPCLS`, `Validate`).
- **Step scan:** implementation described by its exact mapping table and conditional-uncertainty rule; the 11 tests above pin every branch.
- **Type consistency:** enum constant names chosen fresh for this package (no collision risk — `dlpreport` imports only `dlpclassify`'s type for one function signature).
- **Review Focus:** all 4 items have a named test above (`OutcomeMisclassified` → Incorrect; label-lifecycle outcomes → Unknown; uncertain+empty-Limitations → error; uncertain+populated-Limitations → no error; all-certain+empty-Limitations → no error).
- **Proportion check:** 1 task — proportionate; this slice is a type-and-one-safe-helper definition, not a translation layer for every dimension (see spec's own justification for why the other 3 translation helpers are explicitly NOT built here).
- **Anti-goal check:** no `EnforcementOutcomeFromComparison`/`TelemetryOutcomeFromX`/`ResponseOutcomeFromX` anywhere in this file; `Validate()` only returns an error, never mutates `r`.
