package wafassessment

import (
	"testing"

	"github.com/audspect/bas/internal/wafcatalog"
	"github.com/audspect/bas/internal/wafval"
)

func TestAudspectAutomatedAbuseScenario_ReferencesExactSixVectors(t *testing.T) {
	scenario, err := AudspectAutomatedAbuseScenario()
	if err != nil {
		t.Fatalf("AudspectAutomatedAbuseScenario: %v", err)
	}
	want := []string{"RATE-001", "RATE-002", "BOTABUSE-001", "BOTABUSE-002", "BOTABUSE-003", "BOTABUSE-004"}
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
// with a Critical failure (BOTABUSE-004) alongside an untested vector
// (RATE-002) -- Fail must still win.
func TestAudspectAutomatedAbuseFixtures_ThroughEvaluateScenarioWithSeverities_ReturnsFailWithRealMissedAndUntested(t *testing.T) {
	scenario, err := AudspectAutomatedAbuseScenario()
	if err != nil {
		t.Fatalf("AudspectAutomatedAbuseScenario: %v", err)
	}
	fixtures, err := AudspectAutomatedAbuseFixtures()
	if err != nil {
		t.Fatalf("AudspectAutomatedAbuseFixtures: %v", err)
	}
	severityByID, err := automatedAbuseSeverities()
	if err != nil {
		t.Fatalf("automatedAbuseSeverities: %v", err)
	}

	result, err := EvaluateScenarioWithSeverities(scenario, fixtures, severityByID)
	if err != nil {
		t.Fatalf("EvaluateScenarioWithSeverities: %v", err)
	}
	if result.Outcome != ScenarioFail {
		t.Fatalf("Outcome = %q, want %q", result.Outcome, ScenarioFail)
	}

	var sawBOTABUSE004Missed bool
	for _, a := range result.Assertions {
		if a.VectorID == "BOTABUSE-004" {
			sawBOTABUSE004Missed = true
			if a.Verdict != wafval.VerdictMissed {
				t.Errorf("BOTABUSE-004 Verdict = %q, want %q", a.Verdict, wafval.VerdictMissed)
			}
			if a.Severity != wafcatalog.SeverityCritical {
				t.Errorf("BOTABUSE-004 Severity = %q, want %q", a.Severity, wafcatalog.SeverityCritical)
			}
		}
	}
	if !sawBOTABUSE004Missed {
		t.Error("BOTABUSE-004 not found in Assertions")
	}

	untested := map[string]bool{}
	for _, id := range result.UntestedVectorIDs {
		untested[id] = true
	}
	if !untested["RATE-002"] {
		t.Errorf("UntestedVectorIDs = %v, want RATE-002 present", result.UntestedVectorIDs)
	}
}
