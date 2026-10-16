package wafassessment

import (
	"strings"
	"testing"

	"github.com/audspect/bas/internal/wafcatalog"
	"github.com/audspect/bas/internal/wafval"
)

func blockedFixture(vectorID string) VectorFixture {
	return VectorFixture{VectorID: vectorID, Results: []wafval.CollectionResult{
		{Mechanism: wafval.MechanismWAFEngine, Coverage: wafval.CoverageFound, Observations: []wafval.Observation{
			{Mechanism: wafval.MechanismWAFEngine, Enforcement: wafval.EnforcementBlocked, EvidenceKind: wafval.EvidenceObserved},
		}},
	}}
}

func missedFixture(vectorID string) VectorFixture {
	return VectorFixture{VectorID: vectorID, Results: []wafval.CollectionResult{
		{Mechanism: wafval.MechanismWAFEngine, Coverage: wafval.CoverageSearchedVerifiedNone, Observations: []wafval.Observation{
			{Mechanism: wafval.MechanismWAFEngine, Enforcement: wafval.EnforcementAllowed, Detection: wafval.DetectionNotMatched, EvidenceKind: wafval.EvidenceObserved},
		}},
	}}
}

func mustVectorWithSeverity(t *testing.T, id string, severity wafcatalog.Severity) wafcatalog.AttackVector {
	t.Helper()
	v, err := wafcatalog.NewAttackVector(id, 1, wafcatalog.FamilySQLInjection, "x", severity, "x",
		wafcatalog.RequestTemplate{Method: "GET", Path: "/x", PayloadLocation: "query:q", Payload: "x", Description: "x"},
		nil, "no benign needed for this test", wafcatalog.StandardsMapping{CWEIDs: []string{"CWE-89"}}, "test")
	if err != nil {
		t.Fatalf("wafcatalog.NewAttackVector(%q): %v", id, err)
	}
	return v
}

// Review Focus: the non-offsetting rule proven against a REAL mixed
// outcome, not a uniform all-pass/all-fail case.
func TestEvaluateScenario_OneMissedAmongManyBlocked_ReturnsFail(t *testing.T) {
	scenario, err := NewEnterpriseScenario("S-1", "n", "o", []string{"V-1", "V-2", "V-3", "V-4", "V-5", "V-6"}, "p", "e", "prov")
	if err != nil {
		t.Fatalf("NewEnterpriseScenario: %v", err)
	}
	catalog := []wafcatalog.AttackVector{
		mustVectorWithSeverity(t, "V-1", wafcatalog.SeverityCritical),
		mustVectorWithSeverity(t, "V-2", wafcatalog.SeverityCritical),
		mustVectorWithSeverity(t, "V-3", wafcatalog.SeverityCritical),
		mustVectorWithSeverity(t, "V-4", wafcatalog.SeverityCritical),
		mustVectorWithSeverity(t, "V-5", wafcatalog.SeverityCritical),
		mustVectorWithSeverity(t, "V-6", wafcatalog.SeverityCritical),
	}
	fixtures := map[string]VectorFixture{
		"V-1": blockedFixture("V-1"), "V-2": blockedFixture("V-2"), "V-3": blockedFixture("V-3"),
		"V-4": blockedFixture("V-4"), "V-5": blockedFixture("V-5"),
		"V-6": missedFixture("V-6"),
	}
	result, err := EvaluateScenario(scenario, fixtures, catalog)
	if err != nil {
		t.Fatalf("EvaluateScenario: %v", err)
	}
	if result.Outcome != ScenarioFail {
		t.Errorf("Outcome = %q, want %q (5 Blocked must not dilute 1 Missed)", result.Outcome, ScenarioFail)
	}
}

// Review Focus: Fail must beat Incomplete when BOTH a Missed vector
// AND an untested vector are present simultaneously.
func TestEvaluateScenario_MissedAndUntestedTogether_FailWins(t *testing.T) {
	scenario, err := NewEnterpriseScenario("S-2", "n", "o", []string{"V-1", "V-2"}, "p", "e", "prov")
	if err != nil {
		t.Fatalf("NewEnterpriseScenario: %v", err)
	}
	catalog := []wafcatalog.AttackVector{
		mustVectorWithSeverity(t, "V-1", wafcatalog.SeverityCritical),
		mustVectorWithSeverity(t, "V-2", wafcatalog.SeverityCritical),
	}
	fixtures := map[string]VectorFixture{"V-1": missedFixture("V-1")} // V-2 has no fixture -> untested
	result, err := EvaluateScenario(scenario, fixtures, catalog)
	if err != nil {
		t.Fatalf("EvaluateScenario: %v", err)
	}
	if result.Outcome != ScenarioFail {
		t.Errorf("Outcome = %q, want %q (Fail must win over Incomplete)", result.Outcome, ScenarioFail)
	}
	if len(result.UntestedVectorIDs) != 1 || result.UntestedVectorIDs[0] != "V-2" {
		t.Errorf("UntestedVectorIDs = %v, want [V-2]", result.UntestedVectorIDs)
	}
}

func TestEvaluateScenario_UntestedOnly_ReturnsIncomplete(t *testing.T) {
	scenario, err := NewEnterpriseScenario("S-3", "n", "o", []string{"V-1", "V-2"}, "p", "e", "prov")
	if err != nil {
		t.Fatalf("NewEnterpriseScenario: %v", err)
	}
	catalog := []wafcatalog.AttackVector{
		mustVectorWithSeverity(t, "V-1", wafcatalog.SeverityCritical),
		mustVectorWithSeverity(t, "V-2", wafcatalog.SeverityCritical),
	}
	fixtures := map[string]VectorFixture{"V-1": blockedFixture("V-1")} // V-2 untested, no failure anywhere
	result, err := EvaluateScenario(scenario, fixtures, catalog)
	if err != nil {
		t.Fatalf("EvaluateScenario: %v", err)
	}
	if result.Outcome != ScenarioIncomplete {
		t.Errorf("Outcome = %q, want %q", result.Outcome, ScenarioIncomplete)
	}
}

func TestEvaluateScenario_AllBlocked_ReturnsPass(t *testing.T) {
	scenario, err := NewEnterpriseScenario("S-4", "n", "o", []string{"V-1", "V-2"}, "p", "e", "prov")
	if err != nil {
		t.Fatalf("NewEnterpriseScenario: %v", err)
	}
	catalog := []wafcatalog.AttackVector{
		mustVectorWithSeverity(t, "V-1", wafcatalog.SeverityCritical),
		mustVectorWithSeverity(t, "V-2", wafcatalog.SeverityCritical),
	}
	fixtures := map[string]VectorFixture{"V-1": blockedFixture("V-1"), "V-2": blockedFixture("V-2")}
	result, err := EvaluateScenario(scenario, fixtures, catalog)
	if err != nil {
		t.Fatalf("EvaluateScenario: %v", err)
	}
	if result.Outcome != ScenarioPass {
		t.Errorf("Outcome = %q, want %q", result.Outcome, ScenarioPass)
	}
}

func TestEvaluateScenario_InvalidCatalogReference_ReturnsError(t *testing.T) {
	scenario, err := NewEnterpriseScenario("S-5", "n", "o", []string{"V-1", "MISSING"}, "p", "e", "prov")
	if err != nil {
		t.Fatalf("NewEnterpriseScenario: %v", err)
	}
	catalog := []wafcatalog.AttackVector{mustVectorWithSeverity(t, "V-1", wafcatalog.SeverityCritical)}
	if _, err := EvaluateScenario(scenario, map[string]VectorFixture{}, catalog); err == nil {
		t.Fatal("want error for scenario referencing a vector absent from the catalog, got nil")
	}
}

// Review Focus: the disclosure sentence must be in the real return
// value, present regardless of outcome, and every failing/untested
// vector ID must be named alongside its real severity.
func TestEvaluateScenario_Summary_AlwaysIncludesDisclosureAndNamesFailures(t *testing.T) {
	scenario, err := NewEnterpriseScenario("S-6", "n", "o", []string{"V-1"}, "p", "e", "prov")
	if err != nil {
		t.Fatalf("NewEnterpriseScenario: %v", err)
	}
	catalog := []wafcatalog.AttackVector{mustVectorWithSeverity(t, "V-1", wafcatalog.SeverityCritical)}
	result, err := EvaluateScenario(scenario, map[string]VectorFixture{"V-1": missedFixture("V-1")}, catalog)
	if err != nil {
		t.Fatalf("EvaluateScenario: %v", err)
	}
	if !strings.Contains(result.Summary, "fixture") {
		t.Errorf("Summary = %q, want it to mention fixture-only evidence", result.Summary)
	}
	if !strings.Contains(result.Summary, "V-1") {
		t.Errorf("Summary = %q, want it to name the failing vector V-1", result.Summary)
	}
	if !strings.Contains(result.Summary, string(wafcatalog.SeverityCritical)) {
		t.Errorf("Summary = %q, want it to name the real severity", result.Summary)
	}
}
