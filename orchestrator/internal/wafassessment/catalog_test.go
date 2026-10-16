package wafassessment

import (
	"testing"

	"github.com/audspect/bas/internal/wafcatalog"
	"github.com/audspect/bas/internal/wafval"
)

func TestAudspectExploitPreventionScenario_ReferencesExactEightVectors(t *testing.T) {
	scenario, err := AudspectExploitPreventionScenario()
	if err != nil {
		t.Fatalf("AudspectExploitPreventionScenario: %v", err)
	}
	want := []string{"SQLI-001", "SQLI-002", "SQLI-003", "XSS-001", "XSS-002", "XSS-003", "PATHTRAV-001", "PATHTRAV-002"}
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

	catalog, err := wafcatalog.AudspectWAFAttackCatalog()
	if err != nil {
		t.Fatalf("AudspectWAFAttackCatalog: %v", err)
	}
	if err := ValidateAgainstCatalog(scenario, catalog); err != nil {
		t.Fatalf("ValidateAgainstCatalog: %v", err)
	}
}

// Review Focus: the actual seed data, not a synthetic case, must
// prove Fail wins over Incomplete when a real Missed vector and real
// untested vectors coexist.
func TestAudspectExploitPreventionFixtures_ThroughEvaluateScenario_ReturnsFailWithRealMissedAndUntested(t *testing.T) {
	scenario, err := AudspectExploitPreventionScenario()
	if err != nil {
		t.Fatalf("AudspectExploitPreventionScenario: %v", err)
	}
	fixtures, err := AudspectExploitPreventionFixtures()
	if err != nil {
		t.Fatalf("AudspectExploitPreventionFixtures: %v", err)
	}
	catalog, err := wafcatalog.AudspectWAFAttackCatalog()
	if err != nil {
		t.Fatalf("AudspectWAFAttackCatalog: %v", err)
	}

	result, err := EvaluateScenario(scenario, fixtures, catalog)
	if err != nil {
		t.Fatalf("EvaluateScenario: %v", err)
	}
	if result.Outcome != ScenarioFail {
		t.Fatalf("Outcome = %q, want %q", result.Outcome, ScenarioFail)
	}

	var sawSQLI002Missed bool
	for _, a := range result.Assertions {
		if a.VectorID == "SQLI-002" {
			sawSQLI002Missed = true
			if a.Verdict != wafval.VerdictMissed {
				t.Errorf("SQLI-002 Verdict = %q, want %q", a.Verdict, wafval.VerdictMissed)
			}
			if a.Severity != wafcatalog.SeverityCritical {
				t.Errorf("SQLI-002 Severity = %q, want %q", a.Severity, wafcatalog.SeverityCritical)
			}
		}
	}
	if !sawSQLI002Missed {
		t.Error("SQLI-002 not found in Assertions")
	}

	untested := map[string]bool{}
	for _, id := range result.UntestedVectorIDs {
		untested[id] = true
	}
	if !untested["XSS-002"] || !untested["PATHTRAV-002"] {
		t.Errorf("UntestedVectorIDs = %v, want XSS-002 and PATHTRAV-002 present", result.UntestedVectorIDs)
	}
}
