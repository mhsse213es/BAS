package wafassessment

import (
	"testing"
	"time"

	"github.com/audspect/bas/internal/wafval"
)

// Review Focus: a real completeness failure (WAFDETECT-002, SIEM
// record lost) must register as ScenarioFail -- proving
// detectionOutcomeClass, not wafval's own failingVerdict, drives the
// classification (the bug this design deliberately avoids: "lost"
// does not equal wafval.VerdictMissed/"missed", so a naive reuse of
// failingVerdict would have silently passed this).
func TestEvaluateDetectionTelemetryScenario_CompletenessLost_ReturnsFail(t *testing.T) {
	scenario, err := NewEnterpriseScenario("S-DETECT-1", "n", "o", []string{"WAFDETECT-001", "WAFDETECT-002"}, "p", "e", "prov")
	if err != nil {
		t.Fatalf("NewEnterpriseScenario: %v", err)
	}
	fixtures := map[string]DetectionFixture{
		"WAFDETECT-001": {CompletenessEvidence: wafval.CollectionResult{Coverage: wafval.CoverageFound, Observations: []wafval.Observation{{EvidenceKind: wafval.EvidenceObserved}}}},
		"WAFDETECT-002": {CompletenessEvidence: wafval.CollectionResult{Coverage: wafval.CoverageSearchIncomplete}},
	}
	result, err := EvaluateDetectionTelemetryScenario(scenario, fixtures)
	if err != nil {
		t.Fatalf("EvaluateDetectionTelemetryScenario: %v", err)
	}
	if result.Outcome != ScenarioFail {
		t.Fatalf("Outcome = %q, want %q", result.Outcome, ScenarioFail)
	}
	var sawLost bool
	for _, a := range result.Assertions {
		if a.VectorID == "WAFDETECT-002" && string(a.Verdict) == "lost" {
			sawLost = true
		}
	}
	if !sawLost {
		t.Error("WAFDETECT-002 did not resolve to the real 'lost' verdict")
	}
}

// A real alert-pipeline failure (a blocked request with no alert found
// despite a verified-complete search) must also register as Fail.
func TestEvaluateDetectionTelemetryScenario_AlertMissing_ReturnsFail(t *testing.T) {
	scenario, err := NewEnterpriseScenario("S-DETECT-2", "n", "o", []string{"WAFDETECT-003"}, "p", "e", "prov")
	if err != nil {
		t.Fatalf("NewEnterpriseScenario: %v", err)
	}
	fixtures := map[string]DetectionFixture{
		"WAFDETECT-003": {
			UnderlyingVerdict: wafval.VerdictBlocked,
			AlertEvidence:     wafval.CollectionResult{Coverage: wafval.CoverageSearchedVerifiedNone},
		},
	}
	result, err := EvaluateDetectionTelemetryScenario(scenario, fixtures)
	if err != nil {
		t.Fatalf("EvaluateDetectionTelemetryScenario: %v", err)
	}
	if result.Outcome != ScenarioFail {
		t.Fatalf("Outcome = %q, want %q", result.Outcome, ScenarioFail)
	}
}

// A real SLA breach (alert surfaced after the scenario's declared SLA)
// must also register as Fail.
func TestEvaluateDetectionTelemetryScenario_TimingSLABreached_ReturnsFail(t *testing.T) {
	scenario, err := NewEnterpriseScenario("S-DETECT-3", "n", "o", []string{"WAFDETECT-004"}, "p", "e", "prov")
	if err != nil {
		t.Fatalf("NewEnterpriseScenario: %v", err)
	}
	eventAt := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	fixtures := map[string]DetectionFixture{
		"WAFDETECT-004": {EventObservedAt: eventAt, AlertObservedAt: eventAt.Add(10 * time.Minute)},
	}
	result, err := EvaluateDetectionTelemetryScenario(scenario, fixtures)
	if err != nil {
		t.Fatalf("EvaluateDetectionTelemetryScenario: %v", err)
	}
	if result.Outcome != ScenarioFail {
		t.Fatalf("Outcome = %q, want %q", result.Outcome, ScenarioFail)
	}
}

// All-passing evidence across all three shapes must resolve Pass.
func TestEvaluateDetectionTelemetryScenario_AllPassing_ReturnsPass(t *testing.T) {
	scenario, err := NewEnterpriseScenario("S-DETECT-4", "n", "o", []string{"WAFDETECT-001", "WAFDETECT-003", "WAFDETECT-004"}, "p", "e", "prov")
	if err != nil {
		t.Fatalf("NewEnterpriseScenario: %v", err)
	}
	eventAt := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	fixtures := map[string]DetectionFixture{
		"WAFDETECT-001": {CompletenessEvidence: wafval.CollectionResult{Coverage: wafval.CoverageFound, Observations: []wafval.Observation{{EvidenceKind: wafval.EvidenceObserved}}}},
		"WAFDETECT-003": {UnderlyingVerdict: wafval.VerdictBlocked, AlertEvidence: wafval.CollectionResult{Coverage: wafval.CoverageFound, Observations: []wafval.Observation{{EvidenceKind: wafval.EvidenceObserved}}}},
		"WAFDETECT-004": {EventObservedAt: eventAt, AlertObservedAt: eventAt.Add(1 * time.Minute)},
	}
	result, err := EvaluateDetectionTelemetryScenario(scenario, fixtures)
	if err != nil {
		t.Fatalf("EvaluateDetectionTelemetryScenario: %v", err)
	}
	if result.Outcome != ScenarioPass {
		t.Errorf("Outcome = %q, want %q", result.Outcome, ScenarioPass)
	}
}

func TestEvaluateDetectionTelemetryScenario_UnknownID_ReturnsError(t *testing.T) {
	scenario, err := NewEnterpriseScenario("S-DETECT-5", "n", "o", []string{"WAFDETECT-DOES-NOT-EXIST"}, "p", "e", "prov")
	if err != nil {
		t.Fatalf("NewEnterpriseScenario: %v", err)
	}
	if _, err := EvaluateDetectionTelemetryScenario(scenario, map[string]DetectionFixture{}); err == nil {
		t.Fatal("want error for scenario referencing an unknown WAFDETECT ID, got nil")
	}
}
