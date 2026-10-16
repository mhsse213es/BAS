package wafassessment

import (
	"testing"

	"github.com/audspect/bas/internal/wafval"
)

func TestAudspectPolicyIntegrityScenario_ReferencesExactSixGapIDs(t *testing.T) {
	scenario, err := AudspectPolicyIntegrityScenario()
	if err != nil {
		t.Fatalf("AudspectPolicyIntegrityScenario: %v", err)
	}
	want := []string{"GAP-001", "GAP-002", "GAP-003", "GAP-004", "GAP-005", "GAP-006"}
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
// with a real paired-weakness Missed verdict (GAP-002) alongside a
// real untested coverage-gap weakness (GAP-005) -- Fail must win.
func TestAudspectPolicyIntegrityFixtures_ThroughEvaluatePolicyIntegrityScenario_ReturnsFailWithRealMissedAndUntested(t *testing.T) {
	scenario, err := AudspectPolicyIntegrityScenario()
	if err != nil {
		t.Fatalf("AudspectPolicyIntegrityScenario: %v", err)
	}
	fixtures := AudspectPolicyIntegrityFixtures()

	result, err := EvaluatePolicyIntegrityScenario(scenario, policyIntegrityPolicyBasis, fixtures)
	if err != nil {
		t.Fatalf("EvaluatePolicyIntegrityScenario: %v", err)
	}
	if result.Outcome != ScenarioFail {
		t.Fatalf("Outcome = %q, want %q", result.Outcome, ScenarioFail)
	}

	var sawGAP002Missed bool
	for _, a := range result.Assertions {
		if a.VectorID == "GAP-002" {
			sawGAP002Missed = true
			if a.Verdict != wafval.VerdictMissed {
				t.Errorf("GAP-002 Verdict = %q, want %q", a.Verdict, wafval.VerdictMissed)
			}
		}
	}
	if !sawGAP002Missed {
		t.Error("GAP-002 not found in Assertions")
	}

	untested := map[string]bool{}
	for _, id := range result.UntestedVectorIDs {
		untested[id] = true
	}
	if !untested["GAP-005"] {
		t.Errorf("UntestedVectorIDs = %v, want GAP-005 present", result.UntestedVectorIDs)
	}
}
