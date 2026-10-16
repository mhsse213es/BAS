package wafassessment

import "testing"

func TestAudspectOriginResilienceScenario_ReferencesExactFiveVectors(t *testing.T) {
	scenario, err := AudspectOriginResilienceScenario()
	if err != nil {
		t.Fatalf("AudspectOriginResilienceScenario: %v", err)
	}
	want := []string{"WAFORIGIN-001", "WAFORIGIN-002", "WAFORIGIN-003", "WAFORIGIN-004", "WAFORIGIN-005"}
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
// with a real cross-node configuration drift (WAFORIGIN-005) alongside
// a real untested vector (WAFORIGIN-003) -- Fail must win.
func TestAudspectOriginResilienceFixtures_ThroughEvaluateOriginResilienceScenario_ReturnsFailWithRealDriftAndUntested(t *testing.T) {
	scenario, err := AudspectOriginResilienceScenario()
	if err != nil {
		t.Fatalf("AudspectOriginResilienceScenario: %v", err)
	}
	fixtures := AudspectOriginResilienceFixtures()

	result, err := EvaluateOriginResilienceScenario(scenario, originResiliencePolicyBasis, fixtures)
	if err != nil {
		t.Fatalf("EvaluateOriginResilienceScenario: %v", err)
	}
	if result.Outcome != ScenarioFail {
		t.Fatalf("Outcome = %q, want %q", result.Outcome, ScenarioFail)
	}

	var sawDrift bool
	for _, a := range result.Assertions {
		if a.VectorID == "WAFORIGIN-005" && string(a.Verdict) == "drift_detected" {
			sawDrift = true
		}
	}
	if !sawDrift {
		t.Error("WAFORIGIN-005 did not resolve to the real 'drift_detected' verdict")
	}

	untested := map[string]bool{}
	for _, id := range result.UntestedVectorIDs {
		untested[id] = true
	}
	if !untested["WAFORIGIN-003"] {
		t.Errorf("UntestedVectorIDs = %v, want WAFORIGIN-003 present", result.UntestedVectorIDs)
	}
}
