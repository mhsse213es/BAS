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
