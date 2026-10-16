package wafassessment

import (
	"testing"

	"github.com/audspect/bas/internal/wafcatalog"
	"github.com/audspect/bas/internal/wafval"
)

func TestAudspectRoutingCacheIntegrityScenario_ReferencesExactTwoVectors(t *testing.T) {
	scenario, err := AudspectRoutingCacheIntegrityScenario()
	if err != nil {
		t.Fatalf("AudspectRoutingCacheIntegrityScenario: %v", err)
	}
	want := []string{"CACHE-001", "CACHE-002"}
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

func TestAudspectRoutingCacheIntegrityFixtures_ThroughEvaluateScenario_ReturnsFailWithRealMissed(t *testing.T) {
	scenario, err := AudspectRoutingCacheIntegrityScenario()
	if err != nil {
		t.Fatalf("AudspectRoutingCacheIntegrityScenario: %v", err)
	}
	fixtures, err := AudspectRoutingCacheIntegrityFixtures()
	if err != nil {
		t.Fatalf("AudspectRoutingCacheIntegrityFixtures: %v", err)
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

	var sawCACHE001Missed bool
	for _, a := range result.Assertions {
		if a.VectorID == "CACHE-001" {
			sawCACHE001Missed = true
			if a.Verdict != wafval.VerdictMissed {
				t.Errorf("CACHE-001 Verdict = %q, want %q", a.Verdict, wafval.VerdictMissed)
			}
			if a.Severity != wafcatalog.SeverityHigh {
				t.Errorf("CACHE-001 Severity = %q, want %q", a.Severity, wafcatalog.SeverityHigh)
			}
		}
	}
	if !sawCACHE001Missed {
		t.Error("CACHE-001 not found in Assertions")
	}
}
