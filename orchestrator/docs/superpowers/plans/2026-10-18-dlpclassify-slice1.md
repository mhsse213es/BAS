# DLP-CLS Slice 1 — Per-Sample Classification Accuracy + Corpus Aggregation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the first standalone evaluator in `internal/dlpclassify`: ground-truth/corpus-validation foundations, the per-sample classification-accuracy evaluator, and the corpus-level aggregator (precision/recall/false-negative-rate/confusion-matrix), closing DLP-CLS concerns 1, 2, 4, 5, and 6. Concern 3 (label lifecycle) is Slice 2, not built here.

**Architecture:** A new package, `internal/dlpclassify`, structurally parallel to `internal/dlppolicy` (Expectation/Evidence/EvidenceProvider/`Verify...` quartet, fixture-only evidence, provenance tracking) but with its own independently-defined types throughout — no cross-import either direction. Ground truth is fixed at corpus-authoring time and never influenced by observed evidence. A per-sample `Verify` function compares one sample's truth against one channel's evidence; a separate aggregator rolls many per-sample verdicts into corpus-level metrics, with `Inconclusive`/`Unsupported`/`NotTested` samples always counted but excluded from the accuracy denominator.

**Tech Stack:** Go, new package `internal/dlpclassify`, stdlib only.

**Spec:** `orchestrator/docs/superpowers/specs/2026-10-18-dlp-cls-design.md` — read the whole document; this plan implements its Slice 1 scope (`corpus.go`, `sample.go`, `aggregate.go`, and the foundation types in `types.go`). Slice 2 (`labellifecycle.go`) is explicitly out of scope.

## Global Constraints

- No import of `internal/dlppolicy`, `internal/dlpfixture`, `internal/scenario`, or `internal/reporting`. The structural pattern is borrowed; the domain model is not.
- Every provider shipped here sets `Source: SourceFixture`; `SourceLive` is declared, unused.
- `GroundTruth` is validated only at construction (`NewGroundTruth`), never at verify time — the same discipline `dlpfixture.NewFixture` already uses for its own corpus-authored data.
- `ValidateCorpus` checks cross-sample invariants a single `NewGroundTruth` call cannot see: duplicate `SampleID`, a dangling `TransformationOf` reference, and duplicate-content leakage via `ContentHash` (flagged whether the two samples' `IntendedClass` agrees — a sheer duplicate — or disagrees — a contradictory label on the same content).
- `VerifyClassificationSample` never falls through to a classification-accuracy comparison when the evidence itself doesn't represent a scoreable decision (`DecisionLabelOnly`/`DecisionInspectionFailed`/`DecisionNoEvidenceReturned`/`DecisionUnsupportedFormat`) or when the ground truth is ambiguous by design — all of those resolve to `Inconclusive` or `Unsupported` before any `TruePositive`/`FalsePositive`/`FalseNegative`/`TrueNegative`/`Misclassified` branch is reached.
- `Misclassified` (sensitive sample, classified as sensitive, wrong class) counts toward `Evaluated` and the confusion matrix, but is excluded from the binary `TruePositives`/`FalsePositives`/`FalseNegatives`/`TrueNegatives` counters and from `Precision`/`Recall` — it is neither a clean positive nor a clean negative.
- `Precision`/`Recall`/`FalseNegativeRate`/`FalsePositiveRate` are `Rate{Value, Defined}`. `Defined` is `false` whenever the rate's own denominator is zero — never silently reported as `0.0`, which would misrepresent "never fired a positive" as "fired many, all wrong."
- The confusion matrix's observed-axis key for any `DecisionExplicitBenign` evidence is `SensitivityClassNone`, never the empty string, even though `ClassificationEvidence.ObservedClass` itself stays empty for a benign decision.
- `ClassificationEvidenceFor` and `VerifyClassificationSample` both take an explicit `channel` parameter — the same `SampleID` evaluated on two channels produces two independent verdicts via two calls, never two different `SampleID`s (which `ValidateCorpus` would reject as content-leakage) and never a single call that silently discards one channel's evidence via "latest wins."

## Review Focus

- A `Misclassified` verdict (sensitive sample, classified as the wrong sensitive class) must populate the confusion matrix's off-diagonal cell and the `Evaluated`/`Misclassified` counts, but must NOT increment `TruePositives`, `FalsePositives`, `FalseNegatives`, or `TrueNegatives`, and must NOT be counted in `Precision`'s or `Recall`'s numerator or denominator.
- A rate whose denominator is zero (e.g. a corpus with zero `TruePositives`+`FalsePositives`) must report `Rate{Defined: false}`, not `Rate{Value: 0, Defined: true}` — the two states are easy to conflate in a naive division-by-zero guard that returns a zero value either way.
- The confusion matrix's observed-axis key for a `TrueNegative` or `FalseNegative` verdict (both arise from `DecisionExplicitBenign`, where `ObservedClass` is empty) must be `SensitivityClassNone`, not `""` — this is exactly the gap the design doc's builder-check caught; a test must assert the actual map key, not just the verdict's `Outcome`.
- `DecisionLabelOnly`, `DecisionInspectionFailed`, and `DecisionNoEvidenceReturned` must each resolve to `OutcomeInconclusive` with their own distinct Reason text, never conflated with each other or with a missing-evidence `NotTested` outcome.
- `CompareChannelVerdicts` must compare only the two verdicts' `Outcome` field, never their `Reason` text — two channels that both produce `OutcomeTruePositive` must be reported as agreeing even if their Reason strings (which don't exist for `TruePositive` anyway) or any other metadata differ.

---

### Task 1: Foundation types, ground truth, and corpus validation

**Files:**
- Create: `orchestrator/internal/dlpclassify/types.go`
- Create: `orchestrator/internal/dlpclassify/corpus.go`
- Test: `orchestrator/internal/dlpclassify/corpus_test.go`

**Interfaces:**
- Consumes: nothing (first task in a new package).
- Produces: `SensitivityClass`, `SensitivityClassNone`, `SensitivityClassAmbiguous`, `ClassificationDecision` + its 6 constants, `DLPCLSOutcome` + its 8 constants, `(DLPCLSOutcome) evaluated() bool`, `DLPCLSVerdict`, `EvidenceSource`, `SourceFixture`, `SourceLive`, `ProvenanceKind`, `Confidence`, `Provenance`, `Rate`, `TimeWindow`, `GroundTruth`, `NewGroundTruth(sampleID, contentHash string, intendedClass SensitivityClass, rationale, format, transformationOf, adjudicationPolicy, note string) (GroundTruth, error)`, `ValidateCorpus(truths []GroundTruth) error` — all consumed by Tasks 2 and 3.

```go
// types.go — exactly per the spec's "Foundation types" code block.
// corpus.go — exactly per the spec's "Ground truth and corpus validation" code block.
```

- [ ] **Step 1: Write the failing tests**

```go
package dlpclassify

import "testing"

func validTruth(t *testing.T) GroundTruth {
    gt, err := NewGroundTruth("sample-pci-001", "hash-001", SensitivityClass("pci"), "contains a synthetic valid-format credit card number", "csv", "", "", "")
    if err != nil {
        t.Fatalf("NewGroundTruth: %v", err)
    }
    return gt
}

func TestNewGroundTruth_ValidInput_Succeeds(t *testing.T) {
    if _, err := NewGroundTruth("sample-001", "hash-001", SensitivityClass("pci"), "rationale", "csv", "", "", ""); err != nil {
        t.Fatalf("NewGroundTruth: %v", err)
    }
}

func TestNewGroundTruth_EmptySampleID_Errors(t *testing.T) {
    if _, err := NewGroundTruth("", "hash-001", SensitivityClass("pci"), "rationale", "csv", "", "", ""); err == nil {
        t.Fatal("want error for empty sampleID")
    }
}

func TestNewGroundTruth_EmptyContentHash_Errors(t *testing.T) {
    if _, err := NewGroundTruth("sample-001", "", SensitivityClass("pci"), "rationale", "csv", "", "", ""); err == nil {
        t.Fatal("want error for empty contentHash")
    }
}

func TestNewGroundTruth_EmptyRationale_Errors(t *testing.T) {
    if _, err := NewGroundTruth("sample-001", "hash-001", SensitivityClass("pci"), "", "csv", "", "", ""); err == nil {
        t.Fatal("want error for empty rationale")
    }
}

func TestNewGroundTruth_EmptyFormat_Errors(t *testing.T) {
    if _, err := NewGroundTruth("sample-001", "hash-001", SensitivityClass("pci"), "rationale", "", "", "", ""); err == nil {
        t.Fatal("want error for empty format")
    }
}

func TestNewGroundTruth_AmbiguousWithoutAdjudicationPolicy_Errors(t *testing.T) {
    if _, err := NewGroundTruth("sample-001", "hash-001", SensitivityClassAmbiguous, "rationale", "csv", "", "", ""); err == nil {
        t.Fatal("want error: AdjudicationPolicy required when IntendedClass is Ambiguous")
    }
}

func TestNewGroundTruth_AmbiguousWithAdjudicationPolicy_Succeeds(t *testing.T) {
    if _, err := NewGroundTruth("sample-001", "hash-001", SensitivityClassAmbiguous, "rationale", "csv", "", "a benign near-match of a PCI pattern; score as inconclusive", ""); err != nil {
        t.Fatalf("NewGroundTruth: %v", err)
    }
}

func TestNewGroundTruth_NonAmbiguousAdjudicationPolicyNotRequired_Succeeds(t *testing.T) {
    if _, err := NewGroundTruth("sample-001", "hash-001", SensitivityClassNone, "rationale", "csv", "", "", ""); err != nil {
        t.Fatalf("NewGroundTruth: %v", err)
    }
}

func TestValidateCorpus_EmptyCorpus_Succeeds(t *testing.T) {
    if err := ValidateCorpus(nil); err != nil {
        t.Fatalf("ValidateCorpus: %v", err)
    }
}

func TestValidateCorpus_NoIssues_Succeeds(t *testing.T) {
    a, _ := NewGroundTruth("sample-001", "hash-a", SensitivityClass("pci"), "r", "csv", "", "", "")
    b, _ := NewGroundTruth("sample-002", "hash-b", SensitivityClassNone, "r", "pdf", "", "", "")
    if err := ValidateCorpus([]GroundTruth{a, b}); err != nil {
        t.Fatalf("ValidateCorpus: %v", err)
    }
}

func TestValidateCorpus_DuplicateSampleID_Errors(t *testing.T) {
    a, _ := NewGroundTruth("sample-001", "hash-a", SensitivityClass("pci"), "r", "csv", "", "", "")
    b, _ := NewGroundTruth("sample-001", "hash-b", SensitivityClassNone, "r", "pdf", "", "", "")
    if err := ValidateCorpus([]GroundTruth{a, b}); err == nil {
        t.Fatal("want error for duplicate SampleID")
    }
}

func TestValidateCorpus_DanglingTransformationOf_Errors(t *testing.T) {
    a, _ := NewGroundTruth("sample-001", "hash-a", SensitivityClass("pci"), "r", "csv", "sample-nonexistent", "", "")
    if err := ValidateCorpus([]GroundTruth{a}); err == nil {
        t.Fatal("want error for TransformationOf referencing a SampleID absent from the corpus")
    }
}

func TestValidateCorpus_TransformationOfReferencingRealSample_Succeeds(t *testing.T) {
    a, _ := NewGroundTruth("sample-001", "hash-a", SensitivityClass("pci"), "r", "csv", "", "", "")
    b, _ := NewGroundTruth("sample-001-ocr", "hash-b", SensitivityClass("pci"), "r", "scanned-image", "sample-001", "", "")
    if err := ValidateCorpus([]GroundTruth{a, b}); err != nil {
        t.Fatalf("ValidateCorpus: %v", err)
    }
}

func TestValidateCorpus_DuplicateContentHashSameClass_Errors(t *testing.T) {
    a, _ := NewGroundTruth("sample-001", "hash-shared", SensitivityClass("pci"), "r", "csv", "", "", "")
    b, _ := NewGroundTruth("sample-002", "hash-shared", SensitivityClass("pci"), "r", "csv", "", "", "")
    if err := ValidateCorpus([]GroundTruth{a, b}); err == nil {
        t.Fatal("want error for duplicate-content leakage (same ContentHash, same class)")
    }
}

func TestValidateCorpus_DuplicateContentHashDifferentClass_Errors(t *testing.T) {
    a, _ := NewGroundTruth("sample-001", "hash-shared", SensitivityClass("pci"), "r", "csv", "", "", "")
    b, _ := NewGroundTruth("sample-002", "hash-shared", SensitivityClassNone, "r", "csv", "", "", "")
    if err := ValidateCorpus([]GroundTruth{a, b}); err == nil {
        t.Fatal("want error for a contradictory label on identical content")
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test github.com/audspect/bas/internal/dlpclassify/... -v`
Expected: FAIL (package does not exist / `undefined: NewGroundTruth`, `undefined: ValidateCorpus`, etc.)

- [ ] **Step 3: Implement `types.go` and `corpus.go`**

Exactly per the spec's "Foundation types" and "Ground truth and corpus validation" code blocks, with `NewGroundTruth`'s and `ValidateCorpus`'s exact validation rules spelled out above. `ValidateCorpus`'s duplicate-content check keys on `ContentHash` regardless of whether `IntendedClass` agrees between the two samples — both are errors.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test github.com/audspect/bas/internal/dlpclassify/... -v`
Expected: PASS (all 14 tests)

- [ ] **Step 5: `gofmt -l` and `go vet` the package**

Run: `gofmt -l orchestrator/internal/dlpclassify/` and `go vet github.com/audspect/bas/internal/dlpclassify/...`
Expected: no output from either

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/dlpclassify/types.go orchestrator/internal/dlpclassify/corpus.go orchestrator/internal/dlpclassify/corpus_test.go
git commit -m "feat(dlpclassify): add foundation types, GroundTruth, and ValidateCorpus"
```

---

### Task 2: Per-sample classification evidence and `VerifyClassificationSample`

**Files:**
- Create: `orchestrator/internal/dlpclassify/sample.go`
- Test: `orchestrator/internal/dlpclassify/sample_test.go`

**Interfaces:**
- Consumes: `GroundTruth`, `NewGroundTruth`, `SensitivityClass`/`SensitivityClassNone`/`SensitivityClassAmbiguous`, `DLPCLSOutcome` + constants, `DLPCLSVerdict`, `EvidenceSource`/`SourceFixture`, `Provenance`, `TimeWindow` (all from Task 1).
- Produces: `ClassificationEvidence`, `ClassificationEvidenceProvider`, `FixtureClassificationEvidenceProvider`, `NewFixtureClassificationEvidenceProvider`, `VerifyClassificationSample(truth GroundTruth, channel string, provider ClassificationEvidenceProvider, window TimeWindow) DLPCLSVerdict` — consumed by Task 3.

```go
// sample.go — exactly per the spec's "Per-sample evaluator" code block,
// with Channel added to ClassificationEvidence and to
// ClassificationEvidenceFor/VerifyClassificationSample's signatures
// per the spec's builder-check revision.
```

Verify order (first match wins), with exact Reason strings:

1. No evidence records for `truth.SampleID`+`channel` in the window → `OutcomeNotTested`, `"sample was never submitted for evaluation on this channel in this window"`.
2. Provider error → `OutcomeInconclusive`, `fmt.Sprintf("classification evidence collection failed: %v", err)`.
3. Latest (by `Timestamp`) record's `Decision == DecisionUnsupportedFormat` → `OutcomeUnsupported`, `fmt.Sprintf("product does not support this file format or operation: %s", truth.Format)`.
4. `Decision == DecisionLabelOnly` → `OutcomeInconclusive`, `"a label was applied but the underlying classification decision was not exposed"`.
   `Decision == DecisionInspectionFailed` → `OutcomeInconclusive`, `"product attempted but failed to inspect the file"`.
   `Decision == DecisionNoEvidenceReturned` → `OutcomeInconclusive`, `"product returned no usable evidence either way"`.
5. `truth.IntendedClass == SensitivityClassAmbiguous` → `OutcomeInconclusive`, `fmt.Sprintf("sample is ambiguous by design: %s", truth.AdjudicationPolicy)`.
6. `truth.IntendedClass == SensitivityClassNone`:
   - `Decision == DecisionExplicitBenign` → `OutcomeTrueNegative` (no Reason).
   - `Decision == DecisionExplicitSensitive` → `OutcomeFalsePositive`, `fmt.Sprintf("sample is benign but was classified as %q", evidence.ObservedClass)`.
7. Otherwise (`truth.IntendedClass` is a real sensitive class):
   - `Decision == DecisionExplicitBenign` → `OutcomeFalseNegative`, `fmt.Sprintf("sample is %q but was classified as benign", truth.IntendedClass)`.
   - `Decision == DecisionExplicitSensitive && evidence.ObservedClass == truth.IntendedClass` → `OutcomeTruePositive` (no Reason).
   - `Decision == DecisionExplicitSensitive && evidence.ObservedClass != truth.IntendedClass` → `OutcomeMisclassified`, `fmt.Sprintf("sample is %q but was classified as %q", truth.IntendedClass, evidence.ObservedClass)`.

`FixtureClassificationEvidenceProvider.ClassificationEvidenceFor` filters by `SampleID`, `Channel`, and inclusive `TimeWindow`, mirroring `dlppolicy`'s own fixture-provider filtering style exactly.

- [ ] **Step 1: Write the failing tests**

```go
package dlpclassify

import (
    "testing"
    "time"
)

var sampleTestBase = time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
var sampleTestWindow = TimeWindow{Start: sampleTestBase.Add(-time.Hour), End: sampleTestBase.Add(time.Hour)}

func evidence(sampleID, channel string, decision ClassificationDecision, observedClass SensitivityClass) ClassificationEvidence {
    return ClassificationEvidence{
        SampleID: sampleID, Channel: channel, Decision: decision, ObservedClass: observedClass,
        Timestamp: sampleTestBase, Source: SourceFixture,
    }
}

func verify(truth GroundTruth, channel string, evs ...ClassificationEvidence) DLPCLSVerdict {
    return VerifyClassificationSample(truth, channel, NewFixtureClassificationEvidenceProvider(evs), sampleTestWindow)
}

func TestFixtureClassificationEvidenceProvider_FiltersBySampleChannelAndWindow(t *testing.T) {
    evs := []ClassificationEvidence{
        evidence("sample-A", "web-upload", DecisionExplicitSensitive, SensitivityClass("pci")),
        evidence("sample-A", "email-attachment", DecisionExplicitBenign, ""),
        evidence("sample-B", "web-upload", DecisionExplicitSensitive, SensitivityClass("pci")),
        {SampleID: "sample-A", Channel: "web-upload", Decision: DecisionExplicitSensitive, Timestamp: sampleTestBase.Add(-24 * time.Hour), Source: SourceFixture},
    }
    p := NewFixtureClassificationEvidenceProvider(evs)
    got, err := p.ClassificationEvidenceFor("sample-A", "web-upload", sampleTestWindow)
    if err != nil {
        t.Fatalf("ClassificationEvidenceFor: %v", err)
    }
    if len(got) != 1 {
        t.Fatalf("len(got) = %d, want 1", len(got))
    }
}

func TestVerifyClassificationSample_NoEvidence_ReturnsNotTested(t *testing.T) {
    truth, _ := NewGroundTruth("sample-A", "hash-A", SensitivityClass("pci"), "r", "csv", "", "", "")
    got := verify(truth, "web-upload")
    if got.Outcome != OutcomeNotTested {
        t.Fatalf("Outcome = %q, want %q", got.Outcome, OutcomeNotTested)
    }
}

func TestVerifyClassificationSample_UnsupportedFormat_ReturnsUnsupported(t *testing.T) {
    truth, _ := NewGroundTruth("sample-A", "hash-A", SensitivityClass("pci"), "r", "zip-nested-encrypted", "", "", "")
    got := verify(truth, "web-upload", evidence("sample-A", "web-upload", DecisionUnsupportedFormat, ""))
    if got.Outcome != OutcomeUnsupported {
        t.Fatalf("Outcome = %q, want %q", got.Outcome, OutcomeUnsupported)
    }
}

func TestVerifyClassificationSample_LabelOnly_ReturnsInconclusive(t *testing.T) {
    truth, _ := NewGroundTruth("sample-A", "hash-A", SensitivityClass("pci"), "r", "csv", "", "", "")
    got := verify(truth, "web-upload", evidence("sample-A", "web-upload", DecisionLabelOnly, ""))
    if got.Outcome != OutcomeInconclusive {
        t.Fatalf("Outcome = %q, want %q", got.Outcome, OutcomeInconclusive)
    }
}

func TestVerifyClassificationSample_InspectionFailed_ReturnsInconclusive(t *testing.T) {
    truth, _ := NewGroundTruth("sample-A", "hash-A", SensitivityClass("pci"), "r", "csv", "", "", "")
    got := verify(truth, "web-upload", evidence("sample-A", "web-upload", DecisionInspectionFailed, ""))
    if got.Outcome != OutcomeInconclusive {
        t.Fatalf("Outcome = %q, want %q", got.Outcome, OutcomeInconclusive)
    }
}

func TestVerifyClassificationSample_NoEvidenceReturned_ReturnsInconclusive(t *testing.T) {
    truth, _ := NewGroundTruth("sample-A", "hash-A", SensitivityClass("pci"), "r", "csv", "", "", "")
    got := verify(truth, "web-upload", evidence("sample-A", "web-upload", DecisionNoEvidenceReturned, ""))
    if got.Outcome != OutcomeInconclusive {
        t.Fatalf("Outcome = %q, want %q", got.Outcome, OutcomeInconclusive)
    }
}

func TestVerifyClassificationSample_AmbiguousGroundTruth_ReturnsInconclusiveCitingPolicy(t *testing.T) {
    truth, _ := NewGroundTruth("sample-A", "hash-A", SensitivityClassAmbiguous, "r", "csv", "", "a benign near-match; score as inconclusive", "")
    got := verify(truth, "web-upload", evidence("sample-A", "web-upload", DecisionExplicitSensitive, SensitivityClass("pci")))
    if got.Outcome != OutcomeInconclusive {
        t.Fatalf("Outcome = %q, want %q", got.Outcome, OutcomeInconclusive)
    }
    if !strings.Contains(got.Reason, "benign near-match") {
        t.Errorf("Reason = %q, want it to cite the AdjudicationPolicy", got.Reason)
    }
}

func TestVerifyClassificationSample_BenignCorrectlyClassified_ReturnsTrueNegative(t *testing.T) {
    truth, _ := NewGroundTruth("sample-A", "hash-A", SensitivityClassNone, "r", "csv", "", "", "")
    got := verify(truth, "web-upload", evidence("sample-A", "web-upload", DecisionExplicitBenign, ""))
    if got.Outcome != OutcomeTrueNegative {
        t.Fatalf("Outcome = %q, want %q", got.Outcome, OutcomeTrueNegative)
    }
}

func TestVerifyClassificationSample_BenignMisclassifiedSensitive_ReturnsFalsePositive(t *testing.T) {
    truth, _ := NewGroundTruth("sample-A", "hash-A", SensitivityClassNone, "r", "csv", "", "", "")
    got := verify(truth, "web-upload", evidence("sample-A", "web-upload", DecisionExplicitSensitive, SensitivityClass("pci")))
    if got.Outcome != OutcomeFalsePositive {
        t.Fatalf("Outcome = %q, want %q", got.Outcome, OutcomeFalsePositive)
    }
}

func TestVerifyClassificationSample_SensitiveMissedAsBenign_ReturnsFalseNegative(t *testing.T) {
    truth, _ := NewGroundTruth("sample-A", "hash-A", SensitivityClass("pci"), "r", "csv", "", "", "")
    got := verify(truth, "web-upload", evidence("sample-A", "web-upload", DecisionExplicitBenign, ""))
    if got.Outcome != OutcomeFalseNegative {
        t.Fatalf("Outcome = %q, want %q", got.Outcome, OutcomeFalseNegative)
    }
}

func TestVerifyClassificationSample_SensitiveCorrectlyClassified_ReturnsTruePositive(t *testing.T) {
    truth, _ := NewGroundTruth("sample-A", "hash-A", SensitivityClass("pci"), "r", "csv", "", "", "")
    got := verify(truth, "web-upload", evidence("sample-A", "web-upload", DecisionExplicitSensitive, SensitivityClass("pci")))
    if got.Outcome != OutcomeTruePositive {
        t.Fatalf("Outcome = %q, want %q", got.Outcome, OutcomeTruePositive)
    }
}

func TestVerifyClassificationSample_SensitiveWrongClass_ReturnsMisclassified(t *testing.T) {
    truth, _ := NewGroundTruth("sample-A", "hash-A", SensitivityClass("pci"), "r", "csv", "", "", "")
    got := verify(truth, "web-upload", evidence("sample-A", "web-upload", DecisionExplicitSensitive, SensitivityClass("phi")))
    if got.Outcome != OutcomeMisclassified {
        t.Fatalf("Outcome = %q, want %q", got.Outcome, OutcomeMisclassified)
    }
}

func TestVerifyClassificationSample_MultipleRecords_PicksLatestByTimestampNotOrder(t *testing.T) {
    truth, _ := NewGroundTruth("sample-A", "hash-A", SensitivityClass("pci"), "r", "csv", "", "", "")
    older := evidence("sample-A", "web-upload", DecisionExplicitSensitive, SensitivityClass("pci")) // TruePositive-shaped
    older.Timestamp = sampleTestBase.Add(-30 * time.Minute)
    newer := evidence("sample-A", "web-upload", DecisionExplicitBenign, "") // FalseNegative-shaped
    newer.Timestamp = sampleTestBase
    got := verify(truth, "web-upload", older, newer)
    if got.Outcome != OutcomeFalseNegative {
        t.Fatalf("Outcome = %q, want %q -- must select the record with the latest Timestamp", got.Outcome, OutcomeFalseNegative)
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test github.com/audspect/bas/internal/dlpclassify/... -run "TestFixtureClassificationEvidenceProvider|TestVerifyClassificationSample" -v`
Expected: FAIL (`undefined: ClassificationEvidence`, `undefined: VerifyClassificationSample`, etc.)

- [ ] **Step 3: Implement `sample.go`**

Exactly per the Interfaces block and Verify order above. Add the `strings` import to the test file alongside `testing`/`time` (used by `TestVerifyClassificationSample_AmbiguousGroundTruth_ReturnsInconclusiveCitingPolicy`'s `strings.Contains` assertion).

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test github.com/audspect/bas/internal/dlpclassify/... -v`
Expected: PASS (all tests in the package, including Task 1's)

- [ ] **Step 5: `gofmt -l` and `go vet` the package**

Run: `gofmt -l orchestrator/internal/dlpclassify/` and `go vet github.com/audspect/bas/internal/dlpclassify/...`
Expected: no output from either

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/dlpclassify/sample.go orchestrator/internal/dlpclassify/sample_test.go
git commit -m "feat(dlpclassify): add ClassificationEvidence and VerifyClassificationSample"
```

---

### Task 3: Corpus aggregator and cross-channel comparison

**Files:**
- Create: `orchestrator/internal/dlpclassify/aggregate.go`
- Test: `orchestrator/internal/dlpclassify/aggregate_test.go`

**Interfaces:**
- Consumes: `DLPCLSVerdict`, `DLPCLSOutcome` + constants (including the package-private `evaluated()` method), `GroundTruth`, `SensitivityClass`/`SensitivityClassNone`, `ClassificationDecision`/`DecisionExplicitBenign` (all from Tasks 1–2).
- Produces: `SampleResult`, `CorpusMetrics`, `AggregateCorpusMetrics(samples []SampleResult, truths map[string]GroundTruth) CorpusMetrics`, `CompareChannelVerdicts(a, b DLPCLSVerdict) bool` — terminal within DLP-CLS's current scope; no later task consumes these yet.

```go
// aggregate.go — exactly per the spec's "Corpus aggregator" code block
// (SampleResult + the corrected AggregateCorpusMetrics signature),
// plus CompareChannelVerdicts (signature left to the implementer; see
// the spec's "What's left to the builder").
```

Aggregation rules:

- `TotalSamples` = `len(samples)`.
- `NotTested`/`Unsupported`/`Inconclusive` each count results whose `Verdict.Outcome` matches, independent of `Evaluated`.
- `Evaluated` = count of results where `Verdict.Outcome.evaluated()` is true (`TruePositive`/`FalsePositive`/`FalseNegative`/`TrueNegative`/`Misclassified`).
- `TruePositives`/`FalsePositives`/`FalseNegatives`/`TrueNegatives`/`Misclassified` each count their own matching `Outcome` exactly — `Misclassified` is never added into any of the other four.
- `Precision = Rate{Value: TP/(TP+FP), Defined: TP+FP > 0}`.
- `Recall = Rate{Value: TP/(TP+FN), Defined: TP+FN > 0}`.
- `FalseNegativeRate = Rate{Value: FN/(FN+TP), Defined: FN+TP > 0}`.
- `FalsePositiveRate = Rate{Value: FP/(FP+TN), Defined: FP+TN > 0}`.
- `ConfusionMatrix[intended][observed]++` for every `Evaluated` result, where `intended = truths[sampleID].IntendedClass` and `observed = result.ObservedClass`, **except** when `Verdict.Outcome` is `TrueNegative` or `FalseNegative` (both arise from `DecisionExplicitBenign`, where `ObservedClass` is empty), in which case `observed = SensitivityClassNone`.

- [ ] **Step 1: Write the failing tests**

```go
package dlpclassify

import "testing"

func result(sampleID string, verdict DLPCLSVerdict, observedClass SensitivityClass) SampleResult {
    return SampleResult{SampleID: sampleID, Verdict: verdict, ObservedClass: observedClass}
}

func truthsByID(ts ...GroundTruth) map[string]GroundTruth {
    m := make(map[string]GroundTruth, len(ts))
    for _, t := range ts {
        m[t.SampleID] = t
    }
    return m
}

func TestAggregateCorpusMetrics_EmptyCorpus_ReturnsZeroedUndefinedRates(t *testing.T) {
    got := AggregateCorpusMetrics(nil, nil)
    if got.TotalSamples != 0 {
        t.Errorf("TotalSamples = %d, want 0", got.TotalSamples)
    }
    if got.Precision.Defined {
        t.Error("Precision.Defined = true, want false for an empty corpus")
    }
}

func TestAggregateCorpusMetrics_CountsEachOutcomeCategory(t *testing.T) {
    truthA, _ := NewGroundTruth("A", "hA", SensitivityClass("pci"), "r", "csv", "", "", "")
    truthB, _ := NewGroundTruth("B", "hB", SensitivityClassNone, "r", "csv", "", "", "")
    truthC, _ := NewGroundTruth("C", "hC", SensitivityClass("pci"), "r", "csv", "", "", "")
    samples := []SampleResult{
        result("A", DLPCLSVerdict{Outcome: OutcomeTruePositive}, SensitivityClass("pci")),
        result("B", DLPCLSVerdict{Outcome: OutcomeFalsePositive}, SensitivityClass("pci")),
        result("C", DLPCLSVerdict{Outcome: OutcomeInconclusive}, ""),
    }
    got := AggregateCorpusMetrics(samples, truthsByID(truthA, truthB, truthC))
    if got.TotalSamples != 3 {
        t.Errorf("TotalSamples = %d, want 3", got.TotalSamples)
    }
    if got.Evaluated != 2 {
        t.Errorf("Evaluated = %d, want 2", got.Evaluated)
    }
    if got.Inconclusive != 1 {
        t.Errorf("Inconclusive = %d, want 1", got.Inconclusive)
    }
    if got.TruePositives != 1 || got.FalsePositives != 1 {
        t.Errorf("TruePositives=%d FalsePositives=%d, want 1,1", got.TruePositives, got.FalsePositives)
    }
}

func TestAggregateCorpusMetrics_MisclassifiedExcludedFromBinaryCounters(t *testing.T) {
    truthA, _ := NewGroundTruth("A", "hA", SensitivityClass("pci"), "r", "csv", "", "", "")
    samples := []SampleResult{result("A", DLPCLSVerdict{Outcome: OutcomeMisclassified}, SensitivityClass("phi"))}
    got := AggregateCorpusMetrics(samples, truthsByID(truthA))
    if got.Misclassified != 1 {
        t.Errorf("Misclassified = %d, want 1", got.Misclassified)
    }
    if got.TruePositives != 0 || got.FalsePositives != 0 || got.FalseNegatives != 0 || got.TrueNegatives != 0 {
        t.Error("a Misclassified verdict must not increment any binary counter")
    }
    if got.Evaluated != 1 {
        t.Errorf("Evaluated = %d, want 1 -- Misclassified still counts toward Evaluated", got.Evaluated)
    }
}

func TestAggregateCorpusMetrics_PrecisionUndefinedWhenNoPositivesFired(t *testing.T) {
    truthA, _ := NewGroundTruth("A", "hA", SensitivityClass("pci"), "r", "csv", "", "", "")
    samples := []SampleResult{result("A", DLPCLSVerdict{Outcome: OutcomeFalseNegative}, "")}
    got := AggregateCorpusMetrics(samples, truthsByID(truthA))
    if got.Precision.Defined {
        t.Error("Precision.Defined = true, want false -- the product never fired a positive classification at all")
    }
}

func TestAggregateCorpusMetrics_PrecisionDefinedWhenPositivesExist(t *testing.T) {
    truthA, _ := NewGroundTruth("A", "hA", SensitivityClass("pci"), "r", "csv", "", "", "")
    truthB, _ := NewGroundTruth("B", "hB", SensitivityClassNone, "r", "csv", "", "", "")
    samples := []SampleResult{
        result("A", DLPCLSVerdict{Outcome: OutcomeTruePositive}, SensitivityClass("pci")),
        result("B", DLPCLSVerdict{Outcome: OutcomeFalsePositive}, SensitivityClass("pci")),
    }
    got := AggregateCorpusMetrics(samples, truthsByID(truthA, truthB))
    if !got.Precision.Defined {
        t.Fatal("Precision.Defined = false, want true")
    }
    if got.Precision.Value != 0.5 {
        t.Errorf("Precision.Value = %v, want 0.5", got.Precision.Value)
    }
}

func TestAggregateCorpusMetrics_RecallUndefinedWhenNoSensitiveTruthExists(t *testing.T) {
    truthB, _ := NewGroundTruth("B", "hB", SensitivityClassNone, "r", "csv", "", "", "")
    samples := []SampleResult{result("B", DLPCLSVerdict{Outcome: OutcomeTrueNegative}, "")}
    got := AggregateCorpusMetrics(samples, truthsByID(truthB))
    if got.Recall.Defined {
        t.Error("Recall.Defined = true, want false -- no TruePositive or FalseNegative exists")
    }
}

func TestAggregateCorpusMetrics_ConfusionMatrixBenignKeyIsSensitivityClassNoneNotEmptyString(t *testing.T) {
    truthA, _ := NewGroundTruth("A", "hA", SensitivityClassNone, "r", "csv", "", "", "")
    samples := []SampleResult{result("A", DLPCLSVerdict{Outcome: OutcomeTrueNegative}, "")}
    got := AggregateCorpusMetrics(samples, truthsByID(truthA))
    row, ok := got.ConfusionMatrix[SensitivityClassNone]
    if !ok {
        t.Fatal("ConfusionMatrix has no row for SensitivityClassNone")
    }
    if row[SensitivityClassNone] != 1 {
        t.Errorf("ConfusionMatrix[none][none] = %d, want 1 -- the benign observed-axis key must be SensitivityClassNone, not the empty string", row[SensitivityClassNone])
    }
    if _, badKey := row[""]; badKey {
        t.Error("ConfusionMatrix must not use the empty string as an observed-axis key")
    }
}

func TestAggregateCorpusMetrics_ConfusionMatrixMisclassifiedOffDiagonalCell(t *testing.T) {
    truthA, _ := NewGroundTruth("A", "hA", SensitivityClass("pci"), "r", "csv", "", "", "")
    samples := []SampleResult{result("A", DLPCLSVerdict{Outcome: OutcomeMisclassified}, SensitivityClass("phi"))}
    got := AggregateCorpusMetrics(samples, truthsByID(truthA))
    if got.ConfusionMatrix[SensitivityClass("pci")][SensitivityClass("phi")] != 1 {
        t.Error("ConfusionMatrix[pci][phi] must be 1 for a PCI sample misclassified as PHI")
    }
}

func TestCompareChannelVerdicts_SameOutcome_ReturnsTrue(t *testing.T) {
    a := DLPCLSVerdict{Outcome: OutcomeTruePositive}
    b := DLPCLSVerdict{Outcome: OutcomeTruePositive, Reason: "irrelevant metadata difference"}
    if !CompareChannelVerdicts(a, b) {
        t.Error("want true -- same Outcome must agree regardless of Reason text")
    }
}

func TestCompareChannelVerdicts_DifferentOutcome_ReturnsFalse(t *testing.T) {
    a := DLPCLSVerdict{Outcome: OutcomeTruePositive}
    b := DLPCLSVerdict{Outcome: OutcomeFalseNegative}
    if CompareChannelVerdicts(a, b) {
        t.Error("want false for differing Outcome")
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test github.com/audspect/bas/internal/dlpclassify/... -run "TestAggregateCorpusMetrics|TestCompareChannelVerdicts" -v`
Expected: FAIL (`undefined: SampleResult`, `undefined: AggregateCorpusMetrics`, `undefined: CompareChannelVerdicts`)

- [ ] **Step 3: Implement `aggregate.go`**

Exactly per the aggregation rules above, using the `SampleResult`-based signature.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test github.com/audspect/bas/internal/dlpclassify/... -v`
Expected: PASS (all tests in the package, including Tasks 1 and 2)

- [ ] **Step 5: `gofmt -l` and `go vet` the package**

Run: `gofmt -l orchestrator/internal/dlpclassify/` and `go vet github.com/audspect/bas/internal/dlpclassify/...`
Expected: no output from either

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/dlpclassify/aggregate.go orchestrator/internal/dlpclassify/aggregate_test.go
git commit -m "feat(dlpclassify): add AggregateCorpusMetrics and CompareChannelVerdicts"
```

---

## Self-Review Notes

- **Spec coverage:** every Slice 1 type/function in the spec (`types.go`'s full foundation block, `GroundTruth`/`NewGroundTruth`/`ValidateCorpus`, `ClassificationEvidence`/`VerifyClassificationSample` and its 7-step Verify order, `CorpusMetrics`/`AggregateCorpusMetrics`, `CompareChannelVerdicts`) has a corresponding task and named tests above. Concerns 1/2/4/5/6 are each exercised; concern 3 (label lifecycle) is explicitly Slice 2, not here.
- **Step scan / type consistency:** found one real gap while writing this plan — the spec's original `AggregateCorpusMetrics(verdicts map[string]DLPCLSVerdict, truths map[string]GroundTruth) CorpusMetrics` signature could not actually populate the confusion matrix's observed axis for `TruePositive`/`Misclassified`/`FalsePositive` verdicts, because `DLPCLSVerdict` never carries the observed class — only `ClassificationEvidence.ObservedClass` does, and Task 2's Verify function returns a bare `DLPCLSVerdict`, not the evidence alongside it. Fixed by adding `SampleResult` (pairs a verdict with its evidence's `ObservedClass`) and updating `AggregateCorpusMetrics` to take `[]SampleResult`; the spec doc itself was corrected to match before this plan was finalized, so Task 3 implements the spec as written, with no implementation-time deviation.
- **Review Focus:** all five items have a named test above (Misclassified excluded from binary counters, Rate.Defined vs a zero Value, the confusion matrix's SensitivityClassNone key, the three distinct non-scoreable Decision reasons, CompareChannelVerdicts ignoring Reason).
- **Proportion check:** 3 tasks, comparable in density to DLP-POL's own Slice 1 (which was 1 task covering a smaller type surface) and Slice 2a (2 tasks) combined — proportionate to this slice's larger type surface (4 files vs. dlppolicy's 1-2 per slice). Function bodies left to the implementer except where the spec and this plan pin exact values, Reason strings, and branch order.
