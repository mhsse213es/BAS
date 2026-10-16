package wafdetection

import (
	"testing"

	"github.com/audspect/bas/internal/wafval"
)

func TestNewAlertScenario_Valid_Succeeds(t *testing.T) {
	s, err := NewAlertScenario("WAFDETECT-003", "a blocked or detected-but-allowed request must produce a queryable alert", "manually authored")
	if err != nil {
		t.Fatalf("NewAlertScenario: %v", err)
	}
	if s.ID != "WAFDETECT-003" {
		t.Errorf("ID = %q, want %q", s.ID, "WAFDETECT-003")
	}
}

func TestNewAlertScenario_EmptyID_Rejected(t *testing.T) {
	_, err := NewAlertScenario("", "x", "y")
	if err == nil {
		t.Fatal("want error for empty ID, got nil")
	}
}

func TestNewAlertScenario_EmptyDescription_Rejected(t *testing.T) {
	_, err := NewAlertScenario("WAFDETECT-003", "", "y")
	if err == nil {
		t.Fatal("want error for empty description, got nil")
	}
}

func TestNewAlertScenario_EmptyProvenance_Rejected(t *testing.T) {
	_, err := NewAlertScenario("WAFDETECT-003", "x", "")
	if err == nil {
		t.Fatal("want error for empty provenance, got nil")
	}
}

func presentAlertEvidence() wafval.CollectionResult {
	return wafval.CollectionResult{Mechanism: wafval.MechanismIndependentSensor, Coverage: wafval.CoverageFound,
		Observations: []wafval.Observation{{Mechanism: wafval.MechanismIndependentSensor}}}
}

func verifiedAbsentAlertEvidence() wafval.CollectionResult {
	return wafval.CollectionResult{Mechanism: wafval.MechanismIndependentSensor, Coverage: wafval.CoverageSearchedVerifiedNone}
}

func incompleteAlertEvidence() wafval.CollectionResult {
	return wafval.CollectionResult{Mechanism: wafval.MechanismIndependentSensor, Coverage: wafval.CoverageSearchIncomplete}
}

func TestEvaluateAlertCorrelation_WarrantedAndPresent_ReturnsCorrect(t *testing.T) {
	verdict, reason, err := EvaluateAlertCorrelation(wafval.VerdictBlocked, presentAlertEvidence())
	if err != nil {
		t.Fatalf("EvaluateAlertCorrelation: %v", err)
	}
	if verdict != AlertCorrect {
		t.Errorf("verdict = %q, want %q", verdict, AlertCorrect)
	}
	if reason == "" {
		t.Error("reason must not be empty")
	}
}

func TestEvaluateAlertCorrelation_WarrantedAndVerifiedAbsent_ReturnsMissing(t *testing.T) {
	verdict, _, err := EvaluateAlertCorrelation(wafval.VerdictDetectedButAllowed, verifiedAbsentAlertEvidence())
	if err != nil {
		t.Fatalf("EvaluateAlertCorrelation: %v", err)
	}
	if verdict != AlertMissing {
		t.Errorf("verdict = %q, want %q", verdict, AlertMissing)
	}
}

// Review Focus: an incomplete search must never be conflated with a
// confirmed absence.
func TestEvaluateAlertCorrelation_WarrantedAndSearchIncomplete_ReturnsInconclusive(t *testing.T) {
	verdict, _, err := EvaluateAlertCorrelation(wafval.VerdictBlocked, incompleteAlertEvidence())
	if err != nil {
		t.Fatalf("EvaluateAlertCorrelation: %v", err)
	}
	if verdict != AlertInconclusive {
		t.Errorf("verdict = %q, want %q", verdict, AlertInconclusive)
	}
}

func TestEvaluateAlertCorrelation_NotWarrantedAndPresent_ReturnsSpurious(t *testing.T) {
	verdict, _, err := EvaluateAlertCorrelation(wafval.VerdictAllowed, presentAlertEvidence())
	if err != nil {
		t.Fatalf("EvaluateAlertCorrelation: %v", err)
	}
	if verdict != AlertSpurious {
		t.Errorf("verdict = %q, want %q", verdict, AlertSpurious)
	}
}

func TestEvaluateAlertCorrelation_NotWarrantedAndAbsent_ReturnsCorrect(t *testing.T) {
	verdict, _, err := EvaluateAlertCorrelation(wafval.VerdictMissed, verifiedAbsentAlertEvidence())
	if err != nil {
		t.Fatalf("EvaluateAlertCorrelation: %v", err)
	}
	if verdict != AlertCorrect {
		t.Errorf("verdict = %q, want %q", verdict, AlertCorrect)
	}
}
