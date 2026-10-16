package wafassessment

import (
	"testing"

	"github.com/audspect/bas/internal/wafval"
)

func TestAudspectLegitimateTrafficScenario_ReferencesExactSixVectors(t *testing.T) {
	scenario, err := AudspectLegitimateTrafficScenario()
	if err != nil {
		t.Fatalf("AudspectLegitimateTrafficScenario: %v", err)
	}
	want := []string{"SQLI-001", "XSS-001", "PATHTRAV-001", "API-001", "FILEUP-001", "RATE-001"}
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
// with a real false-positive failure (API-001, incorrectly blocked)
// alongside a real untested vector (FILEUP-001) -- Fail must win.
func TestAudspectLegitimateTrafficFixtures_ThroughEvaluateLegitimateTrafficScenario_ReturnsFailWithRealIncorrectlyBlockedAndUntested(t *testing.T) {
	scenario, err := AudspectLegitimateTrafficScenario()
	if err != nil {
		t.Fatalf("AudspectLegitimateTrafficScenario: %v", err)
	}
	fixtures := AudspectLegitimateTrafficFixtures()
	severityByID, err := legitTrafficSeverities()
	if err != nil {
		t.Fatalf("legitTrafficSeverities: %v", err)
	}

	result, err := EvaluateLegitimateTrafficScenario(scenario, fixtures, severityByID)
	if err != nil {
		t.Fatalf("EvaluateLegitimateTrafficScenario: %v", err)
	}
	if result.Outcome != ScenarioFail {
		t.Fatalf("Outcome = %q, want %q", result.Outcome, ScenarioFail)
	}

	var sawAPI001 bool
	for _, a := range result.Assertions {
		if a.VectorID == "API-001" {
			sawAPI001 = true
			if a.Verdict != wafval.VerdictIncorrectlyBlocked {
				t.Errorf("API-001 Verdict = %q, want %q", a.Verdict, wafval.VerdictIncorrectlyBlocked)
			}
		}
	}
	if !sawAPI001 {
		t.Error("API-001 not found in Assertions")
	}

	untested := map[string]bool{}
	for _, id := range result.UntestedVectorIDs {
		untested[id] = true
	}
	if !untested["FILEUP-001"] {
		t.Errorf("UntestedVectorIDs = %v, want FILEUP-001 present", result.UntestedVectorIDs)
	}
}
