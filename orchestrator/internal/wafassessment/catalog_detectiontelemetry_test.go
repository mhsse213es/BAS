package wafassessment

import "testing"

func TestAudspectDetectionTelemetryScenario_ReferencesExactFiveScenarios(t *testing.T) {
	scenario, err := AudspectDetectionTelemetryScenario()
	if err != nil {
		t.Fatalf("AudspectDetectionTelemetryScenario: %v", err)
	}
	want := []string{"WAFDETECT-001", "WAFDETECT-002", "WAFDETECT-003", "WAFDETECT-004", "WAFDETECT-005"}
	if len(scenario.ContributingVectorIDs) != len(want) {
		t.Fatalf("len(ContributingVectorIDs) = %d, want %d", len(scenario.ContributingVectorIDs), len(want))
	}
	got := map[string]bool{}
	for _, id := range scenario.ContributingVectorIDs {
		got[id] = true
	}
	for _, id := range want {
		if !got[id] {
			t.Errorf("ContributingVectorIDs missing %q", id)
		}
	}
}

// Review Focus: the real seed data must prove the non-offsetting rule
// with a real completeness failure (WAFDETECT-002) alongside a real
// untested scenario (WAFDETECT-005) -- Fail must win.
func TestAudspectDetectionTelemetryFixtures_ThroughEvaluateDetectionTelemetryScenario_ReturnsFailWithRealLostAndUntested(t *testing.T) {
	scenario, err := AudspectDetectionTelemetryScenario()
	if err != nil {
		t.Fatalf("AudspectDetectionTelemetryScenario: %v", err)
	}
	fixtures := AudspectDetectionTelemetryFixtures()

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

	untested := map[string]bool{}
	for _, id := range result.UntestedVectorIDs {
		untested[id] = true
	}
	if !untested["WAFDETECT-005"] {
		t.Errorf("UntestedVectorIDs = %v, want WAFDETECT-005 present", result.UntestedVectorIDs)
	}
}
