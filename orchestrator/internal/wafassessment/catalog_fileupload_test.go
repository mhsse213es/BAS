package wafassessment

import (
	"testing"

	"github.com/audspect/bas/internal/wafcatalog"
	"github.com/audspect/bas/internal/wafval"
)

func TestAudspectFileUploadContentTrustScenario_ReferencesExactThreeVectors(t *testing.T) {
	scenario, err := AudspectFileUploadContentTrustScenario()
	if err != nil {
		t.Fatalf("AudspectFileUploadContentTrustScenario: %v", err)
	}
	want := []string{"FILEUP-001", "FILEUP-002", "FILEUP-003"}
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

func TestAudspectFileUploadContentTrustFixtures_ThroughEvaluateScenario_ReturnsFailWithRealMissed(t *testing.T) {
	scenario, err := AudspectFileUploadContentTrustScenario()
	if err != nil {
		t.Fatalf("AudspectFileUploadContentTrustScenario: %v", err)
	}
	fixtures, err := AudspectFileUploadContentTrustFixtures()
	if err != nil {
		t.Fatalf("AudspectFileUploadContentTrustFixtures: %v", err)
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

	var sawFILEUP001Missed bool
	for _, a := range result.Assertions {
		if a.VectorID == "FILEUP-001" {
			sawFILEUP001Missed = true
			if a.Verdict != wafval.VerdictMissed {
				t.Errorf("FILEUP-001 Verdict = %q, want %q", a.Verdict, wafval.VerdictMissed)
			}
			if a.Severity != wafcatalog.SeverityCritical {
				t.Errorf("FILEUP-001 Severity = %q, want %q", a.Severity, wafcatalog.SeverityCritical)
			}
		}
	}
	if !sawFILEUP001Missed {
		t.Error("FILEUP-001 not found in Assertions")
	}
}

// Review Focus: closes WAF QA log item #3 for this scenario -- a third,
// deliberately-fixture-omitted vector (FILEUP-003) must be a real
// contributing ID that the fixture set never supplies, so this scenario
// itself exercises the UntestedVectorIDs/Incomplete path, not just the
// suite overall through unrelated scenarios' own seed data.
func TestAudspectFileUploadContentTrustFixtures_FILEUP003IsDeliberatelyUntested(t *testing.T) {
	scenario, err := AudspectFileUploadContentTrustScenario()
	if err != nil {
		t.Fatalf("AudspectFileUploadContentTrustScenario: %v", err)
	}
	fixtures, err := AudspectFileUploadContentTrustFixtures()
	if err != nil {
		t.Fatalf("AudspectFileUploadContentTrustFixtures: %v", err)
	}
	if _, ok := fixtures["FILEUP-003"]; ok {
		t.Fatal("FILEUP-003 has a fixture -- it must stay deliberately untested to exercise the Incomplete path")
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
	found := false
	for _, id := range result.UntestedVectorIDs {
		if id == "FILEUP-003" {
			found = true
		}
	}
	if !found {
		t.Errorf("UntestedVectorIDs = %v, want it to contain %q", result.UntestedVectorIDs, "FILEUP-003")
	}
}
