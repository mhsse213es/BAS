package wafdetection

import (
	"testing"

	"github.com/audspect/bas/internal/wafval"
)

func TestNewCompletenessScenario_Valid_Succeeds(t *testing.T) {
	s, err := NewCompletenessScenario("WAFDETECT-001", ChannelWAFEventLog,
		"a test execution's CorrelationKey must resolve to a findable WAF-engine event-log record", "manually authored")
	if err != nil {
		t.Fatalf("NewCompletenessScenario: %v", err)
	}
	if s.ID != "WAFDETECT-001" {
		t.Errorf("ID = %q, want %q", s.ID, "WAFDETECT-001")
	}
}

func TestNewCompletenessScenario_EmptyID_Rejected(t *testing.T) {
	_, err := NewCompletenessScenario("", ChannelWAFEventLog, "x", "y")
	if err == nil {
		t.Fatal("want error for empty ID, got nil")
	}
}

func TestNewCompletenessScenario_UnknownChannel_Rejected(t *testing.T) {
	_, err := NewCompletenessScenario("WAFDETECT-001", EvidenceChannel("bogus_channel"), "x", "y")
	if err == nil {
		t.Fatal("want error for an unknown EvidenceChannel, got nil")
	}
}

func TestNewCompletenessScenario_EmptyDescription_Rejected(t *testing.T) {
	_, err := NewCompletenessScenario("WAFDETECT-001", ChannelWAFEventLog, "", "y")
	if err == nil {
		t.Fatal("want error for empty description, got nil")
	}
}

func TestNewCompletenessScenario_EmptyProvenance_Rejected(t *testing.T) {
	_, err := NewCompletenessScenario("WAFDETECT-001", ChannelWAFEventLog, "x", "")
	if err == nil {
		t.Fatal("want error for empty provenance, got nil")
	}
}

func mustCompletenessScenario(t *testing.T) CompletenessScenario {
	t.Helper()
	s, err := NewCompletenessScenario("WAFDETECT-001", ChannelWAFEventLog, "x", "y")
	if err != nil {
		t.Fatalf("NewCompletenessScenario: %v", err)
	}
	return s
}

func TestEvaluateCompleteness_CoverageFound_ReturnsPresent(t *testing.T) {
	scenario := mustCompletenessScenario(t)
	result := wafval.CollectionResult{Mechanism: wafval.MechanismWAFEngine, Coverage: wafval.CoverageFound,
		Observations: []wafval.Observation{{Mechanism: wafval.MechanismWAFEngine}}}
	verdict, reason, err := EvaluateCompleteness(scenario, result)
	if err != nil {
		t.Fatalf("EvaluateCompleteness: %v", err)
	}
	if verdict != EvidencePresent {
		t.Errorf("verdict = %q, want %q", verdict, EvidencePresent)
	}
	if reason == "" {
		t.Error("reason must not be empty")
	}
}

// Review Focus: a verified-negative search still counts as complete
// evidence, not loss.
func TestEvaluateCompleteness_CoverageSearchedVerifiedNone_ReturnsPresent(t *testing.T) {
	scenario := mustCompletenessScenario(t)
	result := wafval.CollectionResult{Mechanism: wafval.MechanismWAFEngine, Coverage: wafval.CoverageSearchedVerifiedNone}
	verdict, _, err := EvaluateCompleteness(scenario, result)
	if err != nil {
		t.Fatalf("EvaluateCompleteness: %v", err)
	}
	if verdict != EvidencePresent {
		t.Errorf("verdict = %q, want %q", verdict, EvidencePresent)
	}
}

func TestEvaluateCompleteness_CoverageSearchIncomplete_ReturnsLost(t *testing.T) {
	scenario := mustCompletenessScenario(t)
	result := wafval.CollectionResult{Mechanism: wafval.MechanismWAFEngine, Coverage: wafval.CoverageSearchIncomplete}
	verdict, _, err := EvaluateCompleteness(scenario, result)
	if err != nil {
		t.Fatalf("EvaluateCompleteness: %v", err)
	}
	if verdict != EvidenceLost {
		t.Errorf("verdict = %q, want %q", verdict, EvidenceLost)
	}
}

func TestEvaluateCompleteness_CoverageSourceUnavailable_ReturnsLost(t *testing.T) {
	scenario := mustCompletenessScenario(t)
	result := wafval.CollectionResult{Mechanism: wafval.MechanismWAFEngine, Coverage: wafval.CoverageSourceUnavailable}
	verdict, _, err := EvaluateCompleteness(scenario, result)
	if err != nil {
		t.Fatalf("EvaluateCompleteness: %v", err)
	}
	if verdict != EvidenceLost {
		t.Errorf("verdict = %q, want %q", verdict, EvidenceLost)
	}
}

func TestEvaluateCompleteness_ZeroValueResult_ReturnsLost(t *testing.T) {
	scenario := mustCompletenessScenario(t)
	verdict, _, err := EvaluateCompleteness(scenario, wafval.CollectionResult{})
	if err != nil {
		t.Fatalf("EvaluateCompleteness: %v", err)
	}
	if verdict != EvidenceLost {
		t.Errorf("verdict = %q, want %q", verdict, EvidenceLost)
	}
}
