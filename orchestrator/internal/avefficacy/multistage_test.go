package avefficacy

import (
	"testing"

	"github.com/audspect/bas/internal/avcatalog"
	"github.com/audspect/bas/internal/avval"
)

func threeStageCatalog(t *testing.T) ([]avcatalog.Vector, []StageVector) {
	t.Helper()
	v1 := testVector(t, avval.ClaimPrevention)
	v1.ID = "AV-STAGE-A"
	v2 := testVector(t, avval.ClaimPrevention)
	v2.ID = "AV-STAGE-B"
	v3 := testVector(t, avval.ClaimPrevention)
	v3.ID = "AV-STAGE-C"
	stages := []StageVector{
		{VectorID: "AV-STAGE-A", Label: "initial execution"},
		{VectorID: "AV-STAGE-B", Label: "interpreter spawn"},
		{VectorID: "AV-STAGE-C", Label: "follow-on persistence"},
	}
	return []avcatalog.Vector{v1, v2, v3}, stages
}

func TestNewMultiStageScenario_EmptyLabel_Error(t *testing.T) {
	_, stages := threeStageCatalog(t)
	stages[1].Label = ""
	if _, err := NewMultiStageScenario("S1", "name", "objective", stages, "prereq", "evidence", "prov"); err == nil {
		t.Fatal("want error for empty stage label, got nil")
	}
}

// Review Focus: a stage that blocks the attack must stop the chain -- the
// later stage is never reached, never scored as a failure or a pass.
func TestEvaluateMultiStageScenario_BlockedStageStopsChain(t *testing.T) {
	catalog, stages := threeStageCatalog(t)
	scenario, err := NewMultiStageScenario("S1", "name", "objective", stages, "prereq", "evidence", "prov")
	if err != nil {
		t.Fatalf("NewMultiStageScenario: %v", err)
	}
	fixtures := map[string]VectorFixture{
		"AV-STAGE-A": {PreventionEvidence: []avval.CollectionResult{observedBlocked(avval.ControlSourceAVEngine, "e1")}},
	}
	result, err := EvaluateMultiStageScenario(scenario, "baseline", fixtures, catalog)
	if err != nil {
		t.Fatalf("EvaluateMultiStageScenario: %v", err)
	}
	if result.Outcome != ScenarioPass {
		t.Fatalf("Outcome = %q, want %q (stage A blocked, nothing else observed a failure)", result.Outcome, ScenarioPass)
	}
	if len(result.VectorOutcomes) != 3 {
		t.Fatalf("len(VectorOutcomes) = %d, want 3 (stopped stages still reported, marked skipped)", len(result.VectorOutcomes))
	}
	if !result.VectorOutcomes[1].StageSkipped || !result.VectorOutcomes[2].StageSkipped {
		t.Error("stages B and C must be marked StageSkipped once A blocked the chain")
	}
	if result.VectorOutcomes[0].StageSkipped {
		t.Error("stage A itself must not be marked skipped -- it was evaluated")
	}
}

// Review Focus: an early-stage gap is still a real failure even though a
// LATER stage in the same chain eventually blocks the attack -- the
// non-offsetting rule applies within one multi-stage chain, not just
// across a scenario's independent vectors.
func TestEvaluateMultiStageScenario_EarlyGapNotErasedByLaterBlock(t *testing.T) {
	catalog, stages := threeStageCatalog(t)
	scenario, err := NewMultiStageScenario("S1", "name", "objective", stages, "prereq", "evidence", "prov")
	if err != nil {
		t.Fatalf("NewMultiStageScenario: %v", err)
	}
	fixtures := map[string]VectorFixture{
		"AV-STAGE-A": {PreventionEvidence: []avval.CollectionResult{observedMissed(avval.ControlSourceAVEngine, "e1")}},
		"AV-STAGE-B": {PreventionEvidence: []avval.CollectionResult{observedBlocked(avval.ControlSourceAVEngine, "e2")}},
	}
	result, err := EvaluateMultiStageScenario(scenario, "baseline", fixtures, catalog)
	if err != nil {
		t.Fatalf("EvaluateMultiStageScenario: %v", err)
	}
	if result.Outcome != ScenarioFail {
		t.Fatalf("Outcome = %q, want %q (stage A's gap must stand even though stage B blocked)", result.Outcome, ScenarioFail)
	}
	if result.VectorOutcomes[0].Finding != avval.FindingConfirmedGap {
		t.Errorf("stage A Finding = %q, want %q", result.VectorOutcomes[0].Finding, avval.FindingConfirmedGap)
	}
	if result.VectorOutcomes[1].Finding != avval.FindingVerifiedProtection {
		t.Errorf("stage B Finding = %q, want %q", result.VectorOutcomes[1].Finding, avval.FindingVerifiedProtection)
	}
	if !result.VectorOutcomes[2].StageSkipped {
		t.Error("stage C must be skipped -- stage B blocked the chain after A let it through")
	}
}

func TestEvaluateMultiStageScenario_FullChainExecutes_AllGapsFail(t *testing.T) {
	catalog, stages := threeStageCatalog(t)
	scenario, err := NewMultiStageScenario("S1", "name", "objective", stages, "prereq", "evidence", "prov")
	if err != nil {
		t.Fatalf("NewMultiStageScenario: %v", err)
	}
	fixtures := map[string]VectorFixture{
		"AV-STAGE-A": {PreventionEvidence: []avval.CollectionResult{observedMissed(avval.ControlSourceAVEngine, "e1")}},
		"AV-STAGE-B": {PreventionEvidence: []avval.CollectionResult{observedMissed(avval.ControlSourceAVEngine, "e2")}},
		"AV-STAGE-C": {PreventionEvidence: []avval.CollectionResult{observedMissed(avval.ControlSourceAVEngine, "e3")}},
	}
	result, err := EvaluateMultiStageScenario(scenario, "baseline", fixtures, catalog)
	if err != nil {
		t.Fatalf("EvaluateMultiStageScenario: %v", err)
	}
	if result.Outcome != ScenarioFail {
		t.Fatalf("Outcome = %q, want %q", result.Outcome, ScenarioFail)
	}
	for i, o := range result.VectorOutcomes {
		if o.StageSkipped {
			t.Errorf("stage %d must not be skipped -- the chain executed fully", i+1)
		}
	}
}

func TestEvaluateMultiStageScenario_MidChainUntested_StopsAdvancing(t *testing.T) {
	catalog, stages := threeStageCatalog(t)
	scenario, err := NewMultiStageScenario("S1", "name", "objective", stages, "prereq", "evidence", "prov")
	if err != nil {
		t.Fatalf("NewMultiStageScenario: %v", err)
	}
	fixtures := map[string]VectorFixture{
		"AV-STAGE-A": {PreventionEvidence: []avval.CollectionResult{observedMissed(avval.ControlSourceAVEngine, "e1")}},
		// AV-STAGE-B deliberately absent
	}
	result, err := EvaluateMultiStageScenario(scenario, "baseline", fixtures, catalog)
	if err != nil {
		t.Fatalf("EvaluateMultiStageScenario: %v", err)
	}
	if result.Outcome != ScenarioFail {
		t.Fatalf("Outcome = %q, want %q (stage A's real gap wins over stage B's untested incompleteness)", result.Outcome, ScenarioFail)
	}
	if len(result.UntestedVectorIDs) != 1 || result.UntestedVectorIDs[0] != "AV-STAGE-B" {
		t.Errorf("UntestedVectorIDs = %v, want [AV-STAGE-B]", result.UntestedVectorIDs)
	}
	if !result.VectorOutcomes[1].StageSkipped {
		t.Error("stage C must be skipped once stage B was untested")
	}
}
