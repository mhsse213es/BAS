package wafassessment

import (
	"testing"

	"github.com/audspect/bas/internal/wafcatalog"
)

// Positive: the scenario bundles exactly the sixteen command-injection vectors and validates against the real catalog.
func TestCommandInjectionScenario_BundlesAllSixteenVectorsAndValidates(t *testing.T) {
	scenario, err := AudspectCommandInjectionScenario()
	if err != nil {
		t.Fatalf("AudspectCommandInjectionScenario: %v", err)
	}
	if len(scenario.ContributingVectorIDs) != 16 {
		t.Fatalf("contributing vectors = %d, want 16", len(scenario.ContributingVectorIDs))
	}
	if scenario.ContributingVectorIDs[0] != "CMDI-001" || scenario.ContributingVectorIDs[15] != "CMDI-016" {
		t.Errorf("unexpected bundle bounds: first %q last %q", scenario.ContributingVectorIDs[0], scenario.ContributingVectorIDs[15])
	}
}

// Negative: no outcome is recorded. Seeding a result here would be fabricated evidence.
func TestCommandInjectionScenario_RecordsNoFixtureOutcomes(t *testing.T) {
	fixtures, err := AudspectCommandInjectionFixtures()
	if err != nil {
		t.Fatalf("AudspectCommandInjectionFixtures: %v", err)
	}
	if len(fixtures) != 0 {
		t.Fatalf("fixtures = %d, want 0 (no live run has produced evidence)", len(fixtures))
	}
}

// Negative: with no evidence, every vector is untested and the scenario is incomplete, never a pass.
func TestCommandInjectionScenario_UnevidencedRunIsIncompleteNotPass(t *testing.T) {
	scenario, result, err := EvaluateScenarioBySlug("command-injection-depth")
	if err != nil {
		t.Fatalf("EvaluateScenarioBySlug: %v", err)
	}
	if scenario.ID != "WAFSCENARIO-COMMAND-INJECTION-DEPTH" {
		t.Errorf("scenario ID = %q", scenario.ID)
	}
	if result.Outcome == ScenarioPass {
		t.Fatal("scenario with no evidence reported ScenarioPass")
	}
	if result.Outcome != ScenarioIncomplete {
		t.Errorf("outcome = %q, want %q", result.Outcome, ScenarioIncomplete)
	}
	if len(result.UntestedVectorIDs) != 16 {
		t.Errorf("untested vectors = %d, want 16", len(result.UntestedVectorIDs))
	}
	if len(result.Assertions) != 0 {
		t.Errorf("assertions = %d, want 0 (nothing was evaluated)", len(result.Assertions))
	}
}

// Negative: a bundle naming a vector that does not exist must be refused.
func TestCommandInjectionScenario_RejectsUnknownVectorID(t *testing.T) {
	scenario, err := NewEnterpriseScenario("X", "X", "X", []string{"CMDI-999"}, "X", "X", "X")
	if err != nil {
		t.Fatalf("NewEnterpriseScenario: %v", err)
	}
	catalog, err := wafcatalog.AudspectWAFAttackCatalog()
	if err != nil {
		t.Fatalf("catalog: %v", err)
	}
	if err := ValidateAgainstCatalog(scenario, catalog); err == nil {
		t.Fatal("ValidateAgainstCatalog accepted CMDI-999, want an error")
	}
}

// Positive: supplying one real result changes exactly that vector's status, showing the wiring is live. The fixture
// here is a test-only stand-in, not a recorded outcome, and it is not written into the scenario.
func TestCommandInjectionScenario_SuppliedEvidenceIsEvaluated(t *testing.T) {
	scenario, err := AudspectCommandInjectionScenario()
	if err != nil {
		t.Fatalf("AudspectCommandInjectionScenario: %v", err)
	}
	catalog, err := wafcatalog.AudspectWAFAttackCatalog()
	if err != nil {
		t.Fatalf("catalog: %v", err)
	}
	fixtures := map[string]VectorFixture{"CMDI-009": blocked("CMDI-009")}
	result, err := EvaluateScenario(scenario, fixtures, catalog)
	if err != nil {
		t.Fatalf("EvaluateScenario: %v", err)
	}
	if len(result.Assertions) != 1 || result.Assertions[0].VectorID != "CMDI-009" {
		t.Fatalf("assertions = %+v, want exactly one for CMDI-009", result.Assertions)
	}
	if len(result.UntestedVectorIDs) != 15 {
		t.Errorf("untested = %d, want 15", len(result.UntestedVectorIDs))
	}
	if result.Outcome != ScenarioIncomplete {
		t.Errorf("outcome = %q, want incomplete (15 vectors still untested)", result.Outcome)
	}
}
