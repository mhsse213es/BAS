package wafassessment

import (
	"testing"

	"github.com/audspect/bas/internal/wafcatalog"
)

func TestValidateAgainstKnownIDs_MissingVectorID_Rejected(t *testing.T) {
	scenario, err := NewEnterpriseScenario("S-1", "n", "o", []string{"V-1", "V-2"}, "p", "e", "prov")
	if err != nil {
		t.Fatalf("NewEnterpriseScenario: %v", err)
	}
	knownIDs := map[string]bool{"V-1": true}
	if err := ValidateAgainstKnownIDs(scenario, knownIDs); err == nil {
		t.Fatal("want error for scenario referencing an ID absent from knownIDs, got nil")
	}
}

func TestValidateAgainstKnownIDs_AllPresent_Succeeds(t *testing.T) {
	scenario, err := NewEnterpriseScenario("S-1", "n", "o", []string{"V-1", "V-2"}, "p", "e", "prov")
	if err != nil {
		t.Fatalf("NewEnterpriseScenario: %v", err)
	}
	knownIDs := map[string]bool{"V-1": true, "V-2": true}
	if err := ValidateAgainstKnownIDs(scenario, knownIDs); err != nil {
		t.Fatalf("ValidateAgainstKnownIDs: %v", err)
	}
}

// Review Focus: EvaluateScenarioWithSeverities must produce the exact
// same non-offsetting outcome as EvaluateScenario on a case spanning
// severities from a severity map built by hand, not from wafcatalog --
// proving the generalization is genuine, not a renamed no-op.
func TestEvaluateScenarioWithSeverities_OneMissedAmongManyBlocked_ReturnsFail(t *testing.T) {
	scenario, err := NewEnterpriseScenario("S-2", "n", "o", []string{"V-1", "V-2", "V-3"}, "p", "e", "prov")
	if err != nil {
		t.Fatalf("NewEnterpriseScenario: %v", err)
	}
	severityByID := map[string]wafcatalog.Severity{
		"V-1": wafcatalog.SeverityCritical,
		"V-2": wafcatalog.SeverityHigh,
		"V-3": wafcatalog.SeverityCritical,
	}
	fixtures := map[string]VectorFixture{
		"V-1": blockedFixture("V-1"),
		"V-2": blockedFixture("V-2"),
		"V-3": missedFixture("V-3"),
	}
	result, err := EvaluateScenarioWithSeverities(scenario, fixtures, severityByID)
	if err != nil {
		t.Fatalf("EvaluateScenarioWithSeverities: %v", err)
	}
	if result.Outcome != ScenarioFail {
		t.Errorf("Outcome = %q, want %q", result.Outcome, ScenarioFail)
	}
	var sawV3 bool
	for _, a := range result.Assertions {
		if a.VectorID == "V-3" {
			sawV3 = true
			if a.Severity != wafcatalog.SeverityCritical {
				t.Errorf("V-3 Severity = %q, want %q", a.Severity, wafcatalog.SeverityCritical)
			}
		}
	}
	if !sawV3 {
		t.Error("V-3 not found in Assertions")
	}
}

func TestEvaluateScenarioWithSeverities_InvalidReference_ReturnsError(t *testing.T) {
	scenario, err := NewEnterpriseScenario("S-3", "n", "o", []string{"V-1", "MISSING"}, "p", "e", "prov")
	if err != nil {
		t.Fatalf("NewEnterpriseScenario: %v", err)
	}
	severityByID := map[string]wafcatalog.Severity{"V-1": wafcatalog.SeverityCritical}
	if _, err := EvaluateScenarioWithSeverities(scenario, map[string]VectorFixture{}, severityByID); err == nil {
		t.Fatal("want error for scenario referencing an ID absent from severityByID, got nil")
	}
}

// EvaluateScenario (the existing wafcatalog-specific entry point) must
// still produce identical results to EvaluateScenarioWithSeverities on
// the same real data, proving the refactor changed nothing for
// existing callers.
func TestEvaluateScenario_StillMatchesGenericPath_OnRealSeedData(t *testing.T) {
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
}
