package dlpclassify

import (
	"strings"
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
