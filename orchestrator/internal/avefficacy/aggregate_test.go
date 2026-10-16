package avefficacy

import (
	"testing"

	"github.com/audspect/bas/internal/avcatalog"
	"github.com/audspect/bas/internal/avval"
)

func twoVectorCatalog(t *testing.T) []avcatalog.Vector {
	t.Helper()
	v1 := testVector(t, avval.ClaimPrevention)
	v1.ID = "AV-EFF-A"
	v2 := testVector(t, avval.ClaimPrevention)
	v2.ID = "AV-EFF-B"
	return []avcatalog.Vector{v1, v2}
}

func testScenario(t *testing.T, ids ...string) EfficacyScenario {
	t.Helper()
	s, err := NewEfficacyScenario("S-EFF-TEST", "name", "objective", ids, "prereq", "evidence", "prov")
	if err != nil {
		t.Fatalf("NewEfficacyScenario: %v", err)
	}
	return s
}

// Review Focus: a confirmed prevention failure on one vector must force
// ScenarioFail even when a SECOND vector's Response was a clean success --
// strong results on one dimension/vector can never hide a real failure
// elsewhere (av.txt §4's own core requirement).
func TestEvaluateEfficacyScenario_ResponseSuccessDoesNotHidePreventionFailure(t *testing.T) {
	catalog := twoVectorCatalog(t)
	scenario := testScenario(t, "AV-EFF-A", "AV-EFF-B")
	fixtures := map[string]VectorFixture{
		"AV-EFF-A": {PreventionEvidence: []avval.CollectionResult{observedMissed(avval.ControlSourceAVEngine, "e1")}}, // confirmed gap
		"AV-EFF-B": {
			PreventionEvidence: []avval.CollectionResult{observedMissed(avval.ControlSourceAVEngine, "e2")},
			ResponseEvidence: []avval.CollectionResult{
				{ControlSource: avval.ControlSourceAVEngine, Coverage: avval.CoverageFound, Observations: []avval.Observation{
					{ControlSource: avval.ControlSourceAVEngine, EventID: "r1", Response: avval.ResponseRemediated, EvidenceKind: avval.EvidenceObserved},
				}},
			},
		},
	}
	result, err := EvaluateEfficacyScenario(scenario, "baseline", fixtures, catalog)
	if err != nil {
		t.Fatalf("EvaluateEfficacyScenario: %v", err)
	}
	if result.Outcome != ScenarioFail {
		t.Fatalf("Outcome = %q, want %q (B's clean remediation must not offset A's confirmed gap)", result.Outcome, ScenarioFail)
	}
}

// Review Focus: a confirmed gap on one vector must stand even though that
// SAME vector's own Response later succeeded -- the prevention failure is
// never erased by a good cleanup.
func TestEvaluateEfficacyScenario_OwnVectorResponseSuccessDoesNotErasePreventionGap(t *testing.T) {
	catalog := twoVectorCatalog(t)
	scenario := testScenario(t, "AV-EFF-A")
	fixtures := map[string]VectorFixture{
		"AV-EFF-A": {
			PreventionEvidence: []avval.CollectionResult{observedMissed(avval.ControlSourceAVEngine, "e1")},
			ResponseEvidence: []avval.CollectionResult{
				{ControlSource: avval.ControlSourceAVEngine, Coverage: avval.CoverageFound, Observations: []avval.Observation{
					{ControlSource: avval.ControlSourceAVEngine, EventID: "r1", Response: avval.ResponseRemediated, EvidenceKind: avval.EvidenceObserved},
				}},
			},
		},
	}
	result, err := EvaluateEfficacyScenario(scenario, "baseline", fixtures, catalog)
	if err != nil {
		t.Fatalf("EvaluateEfficacyScenario: %v", err)
	}
	if result.Outcome != ScenarioFail {
		t.Fatalf("Outcome = %q, want %q", result.Outcome, ScenarioFail)
	}
	if result.VectorOutcomes[0].Response != avval.ResponseRemediated {
		t.Errorf("Response = %q, want %q (response dimension still reported correctly)", result.VectorOutcomes[0].Response, avval.ResponseRemediated)
	}
}

// Review Focus: missing/insufficient evidence must resolve Incomplete,
// never a fabricated Fail -- the classic non-offsetting proof, mirroring
// wafassessment's own precedence test: a real failure plus a real
// untested vector must resolve Fail (Fail wins), while an untested vector
// ALONE (no failure anywhere) must resolve Incomplete, not Fail.
func TestEvaluateEfficacyScenario_UntestedVectorAlone_Incomplete(t *testing.T) {
	catalog := twoVectorCatalog(t)
	scenario := testScenario(t, "AV-EFF-A", "AV-EFF-B")
	fixtures := map[string]VectorFixture{
		"AV-EFF-A": {PreventionEvidence: []avval.CollectionResult{observedBlocked(avval.ControlSourceAVEngine, "e1")}},
		// AV-EFF-B deliberately absent -> untested
	}
	result, err := EvaluateEfficacyScenario(scenario, "baseline", fixtures, catalog)
	if err != nil {
		t.Fatalf("EvaluateEfficacyScenario: %v", err)
	}
	if result.Outcome != ScenarioIncomplete {
		t.Fatalf("Outcome = %q, want %q", result.Outcome, ScenarioIncomplete)
	}
	if len(result.UntestedVectorIDs) != 1 || result.UntestedVectorIDs[0] != "AV-EFF-B" {
		t.Errorf("UntestedVectorIDs = %v, want [AV-EFF-B]", result.UntestedVectorIDs)
	}
}

func TestEvaluateEfficacyScenario_RealFailurePlusUntested_FailWins(t *testing.T) {
	catalog := twoVectorCatalog(t)
	scenario := testScenario(t, "AV-EFF-A", "AV-EFF-B")
	fixtures := map[string]VectorFixture{
		"AV-EFF-A": {PreventionEvidence: []avval.CollectionResult{observedMissed(avval.ControlSourceAVEngine, "e1")}},
		// AV-EFF-B deliberately absent -> untested AND a real failure exists
	}
	result, err := EvaluateEfficacyScenario(scenario, "baseline", fixtures, catalog)
	if err != nil {
		t.Fatalf("EvaluateEfficacyScenario: %v", err)
	}
	if result.Outcome != ScenarioFail {
		t.Fatalf("Outcome = %q, want %q (Fail must win over Incomplete)", result.Outcome, ScenarioFail)
	}
}

func TestEvaluateEfficacyScenario_AllPass_Pass(t *testing.T) {
	catalog := twoVectorCatalog(t)
	scenario := testScenario(t, "AV-EFF-A", "AV-EFF-B")
	fixtures := map[string]VectorFixture{
		"AV-EFF-A": {PreventionEvidence: []avval.CollectionResult{observedBlocked(avval.ControlSourceAVEngine, "e1")}},
		"AV-EFF-B": {PreventionEvidence: []avval.CollectionResult{observedBlocked(avval.ControlSourceAVEngine, "e2")}},
	}
	result, err := EvaluateEfficacyScenario(scenario, "baseline", fixtures, catalog)
	if err != nil {
		t.Fatalf("EvaluateEfficacyScenario: %v", err)
	}
	if result.Outcome != ScenarioPass {
		t.Fatalf("Outcome = %q, want %q", result.Outcome, ScenarioPass)
	}
}

// Configuration drift/policy-gap must force ScenarioFail exactly like a
// prevention gap, even when Finding itself is VerifiedProtection.
func TestEvaluateEfficacyScenario_ConfigurationPolicyGapAloneForcesFail(t *testing.T) {
	catalog := twoVectorCatalog(t)
	scenario := testScenario(t, "AV-EFF-A")
	fixtures := map[string]VectorFixture{
		"AV-EFF-A": {
			PreventionEvidence: []avval.CollectionResult{observedBlocked(avval.ControlSourceAVEngine, "e1")},
			Configuration: &ConfigurationCheck{
				Snapshot: avval.ConfigurationSnapshot{RealTimeProtectionEnabled: false, Coverage: avval.CoverageFound},
				Baseline: avval.ConfigurationBaseline{RequireRealTimeProtection: true},
			},
		},
	}
	result, err := EvaluateEfficacyScenario(scenario, "baseline", fixtures, catalog)
	if err != nil {
		t.Fatalf("EvaluateEfficacyScenario: %v", err)
	}
	if result.Outcome != ScenarioFail {
		t.Fatalf("Outcome = %q, want %q (a real policy gap must fail the scenario even with VerifiedProtection)", result.Outcome, ScenarioFail)
	}
}

func TestEvaluateEfficacyScenario_UnknownVectorID_Error(t *testing.T) {
	catalog := twoVectorCatalog(t)
	scenario := testScenario(t, "DOES-NOT-EXIST")
	if _, err := EvaluateEfficacyScenario(scenario, "baseline", map[string]VectorFixture{}, catalog); err == nil {
		t.Fatal("want error for scenario referencing an unknown vector ID, got nil")
	}
}
