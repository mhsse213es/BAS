package wafassessment

import (
	"testing"

	"github.com/audspect/bas/internal/wafcatalog"
	"github.com/audspect/bas/internal/wafval"
)

func TestAudspectHTTPProtocolIntegrityScenario_ReferencesExactTwoVectors(t *testing.T) {
	scenario, err := AudspectHTTPProtocolIntegrityScenario()
	if err != nil {
		t.Fatalf("AudspectHTTPProtocolIntegrityScenario: %v", err)
	}
	want := []string{"HTTPPARSE-001", "HTTPPARSE-002"}
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

// Review Focus: the real seed data must prove the non-offsetting rule
// against a genuine failure (HTTPPARSE-001, SeverityCritical, seeded
// Missed), not a uniform pass.
func TestAudspectHTTPProtocolIntegrityFixtures_ThroughEvaluateScenario_ReturnsFailWithRealMissed(t *testing.T) {
	scenario, err := AudspectHTTPProtocolIntegrityScenario()
	if err != nil {
		t.Fatalf("AudspectHTTPProtocolIntegrityScenario: %v", err)
	}
	fixtures, err := AudspectHTTPProtocolIntegrityFixtures()
	if err != nil {
		t.Fatalf("AudspectHTTPProtocolIntegrityFixtures: %v", err)
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

	var sawHTTPPARSE001Missed bool
	for _, a := range result.Assertions {
		if a.VectorID == "HTTPPARSE-001" {
			sawHTTPPARSE001Missed = true
			if a.Verdict != wafval.VerdictMissed {
				t.Errorf("HTTPPARSE-001 Verdict = %q, want %q", a.Verdict, wafval.VerdictMissed)
			}
			if a.Severity != wafcatalog.SeverityCritical {
				t.Errorf("HTTPPARSE-001 Severity = %q, want %q", a.Severity, wafcatalog.SeverityCritical)
			}
		}
	}
	if !sawHTTPPARSE001Missed {
		t.Error("HTTPPARSE-001 not found in Assertions")
	}
}
