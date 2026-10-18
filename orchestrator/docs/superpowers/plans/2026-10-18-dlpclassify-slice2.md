# DLP-CLS Slice 2 (Label Lifecycle) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a label-lifecycle evaluator to `internal/dlpclassify` — a declared-vs-observed check for a document's sensitivity-label metadata (missing/incorrect/wrong-inheritance/stale), structurally parallel to `dlppolicy.DLPPolicyRuleExpectation` but with zero cross-import, and kept strictly separate from Slice 1's classification-accuracy outcomes so a label-lifecycle defect is never confused with or counted toward a classifier's precision/recall.

**Architecture:** One new file pair, `labellifecycle.go`/`labellifecycle_test.go`, in the existing `internal/dlpclassify` package. `VerifyLabelExpectation` follows the same per-sample evaluator shape as Slice 1's `VerifyClassificationSample` (latest-evidence-by-timestamp selection, first-match-wins branch order, fixture-only evidence) but is a wholly separate function over its own `LabelExpectation`/`LabelEvidence`/`LabelEvidenceProvider` types. Five new `DLPCLSOutcome` constants (`OutcomeLabelMissing`/`OutcomeLabelIncorrect`/`OutcomeLabelWrongInheritance`/`OutcomeLabelStale`/`OutcomeLabelCurrent`) are added to the existing `types.go` enum; none of them is added to `evaluated()`'s switch, so `AggregateCorpusMetrics` (Slice 1) silently ignores any label-lifecycle verdict it is ever handed — this is the mechanism that keeps the two measurement dimensions from mixing.

**Tech Stack:** Go stdlib only (`fmt`, `time`), matching the rest of the package.

**Spec:** `orchestrator/docs/superpowers/specs/2026-10-18-dlp-cls-design.md`, "Label lifecycle (`labellifecycle.go`) — Slice 2" section (lines 331-384). That section fixes `LabelExpectation`/`LabelEvidence`/`LabelEvidenceProvider`/`VerifyLabelExpectation`'s exact signatures and the 6-step Verify order, and explicitly defers the exact `DLPCLSOutcome`/Reason-string mapping and the fixture matrix to this plan.

## Global Constraints

- Zero imports outside Go stdlib; no import of `dlppolicy`, `dlpfixture`, `internal/scenario`, or `internal/reporting` anywhere in `internal/dlpclassify`.
- `LabelExpectation.ScopeID` is a plain `string` — `dlppolicy.ScopeID` is never reused or imported.
- None of the 5 new `DLPCLSOutcome` constants added by this slice may be added to `evaluated()`'s switch — label-lifecycle findings must never enter `AggregateCorpusMetrics`'s `Evaluated`/`Precision`/`Recall`/confusion-matrix counters.
- `ObservedLabel == ""` ("no label present", per its own doc comment) must be treated as equivalent to `SensitivityClassNone` when comparing against `ExpectedLabel` — comparing the raw strings directly would misflag "no label present, and none was expected" as an incorrect-label finding, since `"" != "none"` as literal values.
- Multiple `LabelEvidence` records in the window: select the one with the latest `Timestamp`, never by record order — same rule Slice 1's `VerifyClassificationSample` already applies to `ClassificationEvidence`.
- The staleness check (branch 5) only applies when `exp.MaxLabelAge > 0`; a zero value means staleness is not checked at all, regardless of how old `LastModifiedAt` is.

## Review Focus

- `ExpectedLabel == SensitivityClassNone` and `ObservedLabel == ""` (no label expected, none present) — must fall through to a passing verdict, not be flagged as missing or incorrect. The empty-string/`SensitivityClassNone` normalization is exactly the kind of silent mismatch a literal string comparison would introduce.
- `ExpectedLabel == SensitivityClassNone` and `ObservedLabel` is some real label (document over-labeled when none was expected) — must be flagged `OutcomeLabelIncorrect`, not silently passed just because no label was "missing."
- Multiple `LabelEvidence` records for the same document/scope in one window — the verdict must reflect the latest-`Timestamp` record, not whichever was passed last/first to the fixture provider.
- A `VerifyLabelExpectation` verdict (any of the 5 new outcomes) run through `AggregateCorpusMetrics` must leave every counter at zero and never populate the confusion matrix — proving `evaluated()` genuinely excludes them, not just that this slice's own tests don't call `AggregateCorpusMetrics`.
- `exp.MaxLabelAge == 0` with a very old `LastModifiedAt` must still produce a passing verdict (when label value and inheritance are otherwise correct) — the staleness check must be skipped entirely, not evaluated against a zero duration.

---

### Task 1: Label-lifecycle evaluator

**Files:**
- Create: `orchestrator/internal/dlpclassify/labellifecycle.go`
- Test: `orchestrator/internal/dlpclassify/labellifecycle_test.go`

**Interfaces:**
- Consumes: `SensitivityClass`/`SensitivityClassNone` (`types.go`), `DLPCLSOutcome`/`DLPCLSVerdict`/`OutcomeInconclusive` (`types.go`), `EvidenceSource`/`SourceFixture`, `Provenance`, `TimeWindow` (all from Slice 1, unchanged).
- Produces: 5 new `DLPCLSOutcome` constants (added to `types.go`'s existing `const` block — `OutcomeLabelMissing`, `OutcomeLabelIncorrect`, `OutcomeLabelWrongInheritance`, `OutcomeLabelStale`, `OutcomeLabelCurrent`), `LabelExpectation`, `LabelEvidence`, `LabelEvidenceProvider`, `FixtureLabelEvidenceProvider`, `NewFixtureLabelEvidenceProvider`, `VerifyLabelExpectation(exp LabelExpectation, provider LabelEvidenceProvider, window TimeWindow, asOf time.Time) DLPCLSVerdict`. No later task in this slice consumes these.

```go
// labellifecycle.go -- exactly per the spec's "Label lifecycle" code
// block (LabelExpectation/LabelEvidence/LabelEvidenceProvider), plus
// FixtureLabelEvidenceProvider (mirrors FixtureClassificationEvidenceProvider's
// filter style: by DocumentID, ScopeID, and inclusive TimeWindow) and
// VerifyLabelExpectation's body.
```

Add to `types.go`'s existing `DLPCLSOutcome` `const` block (do not touch `evaluated()` — these 5 stay outside its switch, so they are never `evaluated()`):

```go
OutcomeLabelMissing          DLPCLSOutcome = "label-missing"
OutcomeLabelIncorrect        DLPCLSOutcome = "label-incorrect"
OutcomeLabelWrongInheritance DLPCLSOutcome = "label-wrong-inheritance"
OutcomeLabelStale            DLPCLSOutcome = "label-stale"
OutcomeLabelCurrent          DLPCLSOutcome = "label-current"
```

Verify order (first match wins), with exact Reason strings:

1. No evidence records for `exp.DocumentID`+`exp.ScopeID` in the window → `OutcomeInconclusive`, `"no label evidence found for this document/scope in the window"`.
2. Let `observed := latest.ObservedLabel`; if `observed == ""`, treat it as `SensitivityClassNone` for every comparison below (`observed = SensitivityClassNone`). If `observed == SensitivityClassNone` (i.e. no label present) **and** `exp.ExpectedLabel != SensitivityClassNone` → `OutcomeLabelMissing`, `fmt.Sprintf("expected label %q but no label is present", exp.ExpectedLabel)`.
3. `observed != exp.ExpectedLabel` (using the normalized `observed` from step 2 — this also catches the "present but wrong, or present when none expected" cases step 2's guard didn't) → `OutcomeLabelIncorrect`, `fmt.Sprintf("expected label %q, observed %q", exp.ExpectedLabel, observed)`.
4. `exp.ExpectedInheritedFrom != "" && latest.ObservedInheritedFrom != exp.ExpectedInheritedFrom` → `OutcomeLabelWrongInheritance`, `fmt.Sprintf("label inherited from %q, expected inheritance from %q", latest.ObservedInheritedFrom, exp.ExpectedInheritedFrom)`.
5. `exp.MaxLabelAge > 0 && asOf.Sub(latest.LastModifiedAt) > exp.MaxLabelAge` → `OutcomeLabelStale`, `fmt.Sprintf("label last modified %s ago, exceeds max age %s", asOf.Sub(latest.LastModifiedAt), exp.MaxLabelAge)`.
6. Otherwise → `OutcomeLabelCurrent` (no Reason).

`FixtureLabelEvidenceProvider.LabelEvidenceFor` filters by `DocumentID`, `ScopeID`, and inclusive `TimeWindow`, mirroring `FixtureClassificationEvidenceProvider` exactly. Latest-record selection is by `Timestamp`, mirroring `latestClassificationEvidenceByTimestamp`.

- [ ] **Step 1: Write the failing tests**

```go
package dlpclassify

import (
    "testing"
    "time"
)

var labelTestBase = time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
var labelTestWindow = TimeWindow{Start: labelTestBase.Add(-time.Hour), End: labelTestBase.Add(time.Hour)}

func labelEv(documentID, scopeID string, observedLabel SensitivityClass, inheritedFrom string, lastModifiedAt time.Time) LabelEvidence {
    return LabelEvidence{
        DocumentID: documentID, ScopeID: scopeID, ObservedLabel: observedLabel,
        ObservedInheritedFrom: inheritedFrom, LastModifiedAt: lastModifiedAt,
        Timestamp: labelTestBase, Source: SourceFixture,
    }
}

func verifyLabel(exp LabelExpectation, asOf time.Time, evs ...LabelEvidence) DLPCLSVerdict {
    return VerifyLabelExpectation(exp, NewFixtureLabelEvidenceProvider(evs), labelTestWindow, asOf)
}

func TestFixtureLabelEvidenceProvider_FiltersByDocumentScopeAndWindow(t *testing.T) {
    evs := []LabelEvidence{
        labelEv("doc-A", "scope-1", SensitivityClass("pci"), "", labelTestBase),
        labelEv("doc-A", "scope-2", SensitivityClass("pci"), "", labelTestBase),
        labelEv("doc-B", "scope-1", SensitivityClass("pci"), "", labelTestBase),
        {DocumentID: "doc-A", ScopeID: "scope-1", ObservedLabel: SensitivityClass("pci"), LastModifiedAt: labelTestBase, Timestamp: labelTestBase.Add(-24 * time.Hour), Source: SourceFixture},
    }
    p := NewFixtureLabelEvidenceProvider(evs)
    got, err := p.LabelEvidenceFor("doc-A", "scope-1", labelTestWindow)
    if err != nil {
        t.Fatalf("LabelEvidenceFor: %v", err)
    }
    if len(got) != 1 {
        t.Fatalf("len(got) = %d, want 1", len(got))
    }
}

func TestVerifyLabelExpectation_NoEvidence_ReturnsInconclusive(t *testing.T) {
    exp := LabelExpectation{DocumentID: "doc-A", ScopeID: "scope-1", ExpectedLabel: SensitivityClass("pci")}
    got := verifyLabel(exp, labelTestBase)
    if got.Outcome != OutcomeInconclusive {
        t.Fatalf("Outcome = %q, want %q", got.Outcome, OutcomeInconclusive)
    }
}

func TestVerifyLabelExpectation_SensitiveExpectedNoLabelPresent_ReturnsMissing(t *testing.T) {
    exp := LabelExpectation{DocumentID: "doc-A", ScopeID: "scope-1", ExpectedLabel: SensitivityClass("pci")}
    got := verifyLabel(exp, labelTestBase, labelEv("doc-A", "scope-1", "", "", labelTestBase))
    if got.Outcome != OutcomeLabelMissing {
        t.Fatalf("Outcome = %q, want %q", got.Outcome, OutcomeLabelMissing)
    }
}

func TestVerifyLabelExpectation_NoneExpectedNoLabelPresent_ReturnsCurrent(t *testing.T) {
    exp := LabelExpectation{DocumentID: "doc-A", ScopeID: "scope-1", ExpectedLabel: SensitivityClassNone}
    got := verifyLabel(exp, labelTestBase, labelEv("doc-A", "scope-1", "", "", labelTestBase))
    if got.Outcome != OutcomeLabelCurrent {
        t.Fatalf("Outcome = %q, want %q -- no label present when none expected must not be flagged missing or incorrect", got.Outcome, OutcomeLabelCurrent)
    }
}

func TestVerifyLabelExpectation_NoneExpectedButLabelPresent_ReturnsIncorrect(t *testing.T) {
    exp := LabelExpectation{DocumentID: "doc-A", ScopeID: "scope-1", ExpectedLabel: SensitivityClassNone}
    got := verifyLabel(exp, labelTestBase, labelEv("doc-A", "scope-1", SensitivityClass("pci"), "", labelTestBase))
    if got.Outcome != OutcomeLabelIncorrect {
        t.Fatalf("Outcome = %q, want %q -- an unexpected label when none was expected must be flagged incorrect", got.Outcome, OutcomeLabelIncorrect)
    }
}

func TestVerifyLabelExpectation_WrongLabelPresent_ReturnsIncorrect(t *testing.T) {
    exp := LabelExpectation{DocumentID: "doc-A", ScopeID: "scope-1", ExpectedLabel: SensitivityClass("pci")}
    got := verifyLabel(exp, labelTestBase, labelEv("doc-A", "scope-1", SensitivityClass("phi"), "", labelTestBase))
    if got.Outcome != OutcomeLabelIncorrect {
        t.Fatalf("Outcome = %q, want %q", got.Outcome, OutcomeLabelIncorrect)
    }
}

func TestVerifyLabelExpectation_WrongInheritanceSource_ReturnsWrongInheritance(t *testing.T) {
    exp := LabelExpectation{DocumentID: "doc-A", ScopeID: "scope-1", ExpectedLabel: SensitivityClass("pci"), ExpectedInheritedFrom: "site-root"}
    got := verifyLabel(exp, labelTestBase, labelEv("doc-A", "scope-1", SensitivityClass("pci"), "sub-folder", labelTestBase))
    if got.Outcome != OutcomeLabelWrongInheritance {
        t.Fatalf("Outcome = %q, want %q -- correct label value from the wrong inheritance source is still a lifecycle defect", got.Outcome, OutcomeLabelWrongInheritance)
    }
}

func TestVerifyLabelExpectation_StaleLabel_ReturnsStale(t *testing.T) {
    exp := LabelExpectation{DocumentID: "doc-A", ScopeID: "scope-1", ExpectedLabel: SensitivityClass("pci"), MaxLabelAge: 24 * time.Hour}
    got := verifyLabel(exp, labelTestBase, labelEv("doc-A", "scope-1", SensitivityClass("pci"), "", labelTestBase.Add(-48*time.Hour)))
    if got.Outcome != OutcomeLabelStale {
        t.Fatalf("Outcome = %q, want %q", got.Outcome, OutcomeLabelStale)
    }
}

func TestVerifyLabelExpectation_MaxLabelAgeZero_StalenessNeverChecked(t *testing.T) {
    exp := LabelExpectation{DocumentID: "doc-A", ScopeID: "scope-1", ExpectedLabel: SensitivityClass("pci")}
    got := verifyLabel(exp, labelTestBase, labelEv("doc-A", "scope-1", SensitivityClass("pci"), "", labelTestBase.Add(-10000*time.Hour)))
    if got.Outcome != OutcomeLabelCurrent {
        t.Fatalf("Outcome = %q, want %q -- MaxLabelAge == 0 must skip the staleness check entirely", got.Outcome, OutcomeLabelCurrent)
    }
}

func TestVerifyLabelExpectation_AllCorrect_ReturnsCurrent(t *testing.T) {
    exp := LabelExpectation{DocumentID: "doc-A", ScopeID: "scope-1", ExpectedLabel: SensitivityClass("pci"), ExpectedInheritedFrom: "site-root", MaxLabelAge: 24 * time.Hour}
    got := verifyLabel(exp, labelTestBase, labelEv("doc-A", "scope-1", SensitivityClass("pci"), "site-root", labelTestBase.Add(-1*time.Hour)))
    if got.Outcome != OutcomeLabelCurrent {
        t.Fatalf("Outcome = %q, want %q", got.Outcome, OutcomeLabelCurrent)
    }
}

func TestVerifyLabelExpectation_MultipleRecords_PicksLatestByTimestampNotOrder(t *testing.T) {
    exp := LabelExpectation{DocumentID: "doc-A", ScopeID: "scope-1", ExpectedLabel: SensitivityClass("pci")}
    older := labelEv("doc-A", "scope-1", SensitivityClass("pci"), "", labelTestBase) // current-shaped
    older.Timestamp = labelTestBase.Add(-30 * time.Minute)
    newer := labelEv("doc-A", "scope-1", "", "", labelTestBase) // missing-shaped
    newer.Timestamp = labelTestBase
    got := verifyLabel(exp, labelTestBase, older, newer)
    if got.Outcome != OutcomeLabelMissing {
        t.Fatalf("Outcome = %q, want %q -- must select the record with the latest Timestamp", got.Outcome, OutcomeLabelMissing)
    }
}

func TestAggregateCorpusMetrics_LabelLifecycleVerdictNeverCounted(t *testing.T) {
    samples := []SampleResult{
        {SampleID: "doc-A", Verdict: DLPCLSVerdict{Outcome: OutcomeLabelMissing}},
        {SampleID: "doc-B", Verdict: DLPCLSVerdict{Outcome: OutcomeLabelIncorrect}},
        {SampleID: "doc-C", Verdict: DLPCLSVerdict{Outcome: OutcomeLabelWrongInheritance}},
        {SampleID: "doc-D", Verdict: DLPCLSVerdict{Outcome: OutcomeLabelStale}},
        {SampleID: "doc-E", Verdict: DLPCLSVerdict{Outcome: OutcomeLabelCurrent}},
    }
    got := AggregateCorpusMetrics(samples, nil)
    if got.Evaluated != 0 {
        t.Errorf("Evaluated = %d, want 0 -- label-lifecycle outcomes must never be evaluated()", got.Evaluated)
    }
    if got.TruePositives != 0 || got.FalsePositives != 0 || got.FalseNegatives != 0 || got.TrueNegatives != 0 || got.Misclassified != 0 {
        t.Error("a label-lifecycle verdict must not increment any classification-accuracy counter")
    }
    if len(got.ConfusionMatrix) != 0 {
        t.Error("a label-lifecycle verdict must not populate the confusion matrix")
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test github.com/audspect/bas/internal/dlpclassify/... -run "TestFixtureLabelEvidenceProvider|TestVerifyLabelExpectation|TestAggregateCorpusMetrics_LabelLifecycleVerdictNeverCounted" -v`
Expected: FAIL (`undefined: LabelEvidence`, `undefined: VerifyLabelExpectation`, `undefined: OutcomeLabelMissing`, etc.)

- [ ] **Step 3: Add the 5 outcome constants to `types.go` and implement `labellifecycle.go`**

Exactly per the Interfaces block, the Verify order, and the Global Constraints above (especially the `observed == ""` → `SensitivityClassNone` normalization in step 2/3).

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test github.com/audspect/bas/internal/dlpclassify/... -v`
Expected: PASS (all tests in the package, including Slice 1's)

- [ ] **Step 5: `gofmt -l` and `go vet` the package**

Run: `gofmt -l orchestrator/internal/dlpclassify/` and `go vet github.com/audspect/bas/internal/dlpclassify/...`
Expected: no output from either

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/dlpclassify/types.go orchestrator/internal/dlpclassify/labellifecycle.go orchestrator/internal/dlpclassify/labellifecycle_test.go
git commit -m "feat(dlpclassify): add label-lifecycle evaluator (VerifyLabelExpectation)"
```

---

## Self-Review Notes

- **Spec coverage:** every type/function the spec's Label-lifecycle section pins (`LabelExpectation`, `LabelEvidence`, `LabelEvidenceProvider`, `VerifyLabelExpectation`, all 6 Verify-order steps) has a named test above. The spec's own deferred items (exact outcome/Reason mapping, fixture matrix) are resolved in this plan's Verify-order block and test list.
- **Step scan / type consistency:** `VerifyLabelExpectation`'s signature, field names (`DocumentID`/`ScopeID`/`ExpectedLabel`/`ExpectedInheritedFrom`/`LabelAppliedAt`/`MaxLabelAge`), and the 5 new `DLPCLSOutcome` constants match the spec's code block and `types.go`'s existing naming convention (`Outcome<Name>`) exactly.
- **Review Focus:** all 5 items each have a named test above (the `SensitivityClassNone`/empty-string normalization in both directions, latest-by-timestamp selection, `AggregateCorpusMetrics` exclusion, and `MaxLabelAge == 0` skipping staleness).
- **Proportion check:** 1 task, comparable to DLP-POL's own Slice 1 (1 task) — proportionate to this slice's single-file-pair surface, smaller than Slice 1's 3-task/4-file surface.
