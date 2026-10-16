package wafassessment

import (
	"testing"

	"github.com/audspect/bas/internal/wafval"
)

func TestAudspectAPIProtectionScenario_ReferencesExactEightVectors(t *testing.T) {
	scenario, err := AudspectAPIProtectionScenario()
	if err != nil {
		t.Fatalf("AudspectAPIProtectionScenario: %v", err)
	}
	want := []string{"API-001", "API-002", "API-003", "APIFLOW-001", "APIFLOW-002", "APIFLOW-003", "APIFLOW-004", "APIFLOW-005"}
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

// Review Focus: the scenario spans TWO real catalogs (wafcatalog's
// API-* and wafapiflow's APIFLOW-*) and the real seed data must prove
// the non-offsetting rule with a failure in the second catalog, not
// the first -- proving severities genuinely cross-convert, not just
// for whichever catalog happens to be evaluated first.
func TestAudspectAPIProtectionFixtures_ThroughEvaluateScenarioWithSeverities_ReturnsFailWithRealMissed(t *testing.T) {
	scenario, err := AudspectAPIProtectionScenario()
	if err != nil {
		t.Fatalf("AudspectAPIProtectionScenario: %v", err)
	}
	fixtures, err := AudspectAPIProtectionFixtures()
	if err != nil {
		t.Fatalf("AudspectAPIProtectionFixtures: %v", err)
	}
	severityByID, err := apiProtectionSeverities()
	if err != nil {
		t.Fatalf("apiProtectionSeverities: %v", err)
	}

	result, err := EvaluateScenarioWithSeverities(scenario, fixtures, severityByID)
	if err != nil {
		t.Fatalf("EvaluateScenarioWithSeverities: %v", err)
	}
	if result.Outcome != ScenarioFail {
		t.Fatalf("Outcome = %q, want %q", result.Outcome, ScenarioFail)
	}

	var sawAPIFLOW003Missed bool
	for _, a := range result.Assertions {
		if a.VectorID == "APIFLOW-003" {
			sawAPIFLOW003Missed = true
			if a.Verdict != wafval.VerdictMissed {
				t.Errorf("APIFLOW-003 Verdict = %q, want %q", a.Verdict, wafval.VerdictMissed)
			}
		}
	}
	if !sawAPIFLOW003Missed {
		t.Error("APIFLOW-003 not found in Assertions")
	}

	untested := map[string]bool{}
	for _, id := range result.UntestedVectorIDs {
		untested[id] = true
	}
	if !untested["API-003"] {
		t.Errorf("UntestedVectorIDs = %v, want API-003 present", result.UntestedVectorIDs)
	}
}
