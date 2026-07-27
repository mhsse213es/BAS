package coverage

import (
	"testing"

	"github.com/audspect/bas/internal/scenario"
)

func TestCompute_JoinsFourSetsCorrectly(t *testing.T) {
	sim := map[string]bool{"T1003.002": true, "T1083": true}
	profile := map[string]bool{"T1003.002": true}
	purple := map[string]bool{"T1003.002": true, "T1083": true}
	compliance := map[string]bool{}

	rows := Compute([]string{"T1003.002", "T1083", "T9999"}, sim, profile, purple, compliance)
	if len(rows) != 3 {
		t.Fatalf("got %d rows, want 3", len(rows))
	}

	r0 := rows[0]
	if r0.TechniqueID != "T1003.002" || !r0.SimulationExists || !r0.DetectionProfileExists || !r0.PurpleExerciseExists || r0.ComplianceMappingExists {
		t.Errorf("row 0 (T1003.002) = %+v, unexpected", r0)
	}

	r1 := rows[1]
	if r1.TechniqueID != "T1083" || !r1.SimulationExists || r1.DetectionProfileExists || !r1.PurpleExerciseExists {
		t.Errorf("row 1 (T1083) = %+v, unexpected", r1)
	}

	r2 := rows[2]
	if r2.TechniqueID != "T9999" || r2.SimulationExists || r2.DetectionProfileExists || r2.PurpleExerciseExists || r2.ComplianceMappingExists {
		t.Errorf("row 2 (T9999, unknown to every set) = %+v, want all false", r2)
	}
}

func TestCompute_ResponsePlaybookAlwaysNil(t *testing.T) {
	rows := Compute([]string{"T1003.002"}, map[string]bool{"T1003.002": true}, map[string]bool{"T1003.002": true}, map[string]bool{"T1003.002": true}, map[string]bool{"T1003.002": true})
	if rows[0].ResponsePlaybookExists != nil {
		t.Errorf("ResponsePlaybookExists = %v, want nil (always N/A -- no technique-level response-action linkage exists)", rows[0].ResponsePlaybookExists)
	}
}

func TestBuildSimulationIndex(t *testing.T) {
	scenarios := []*scenario.Scenario{
		{Steps: []scenario.Step{{TechniqueID: "T1003.002"}, {TechniqueID: "T1083"}}},
		{Steps: []scenario.Step{{TechniqueID: "T1490"}}},
	}
	idx := BuildSimulationIndex(scenarios)
	for _, id := range []string{"T1003.002", "T1083", "T1490"} {
		if !idx[id] {
			t.Errorf("expected %s in simulation index", id)
		}
	}
	if idx["T9999"] {
		t.Error("did not expect T9999 in simulation index")
	}
}

func TestBuildComplianceIndex_OnlyComplianceTaggedScenarios(t *testing.T) {
	scenarios := []*scenario.Scenario{
		{Tags: []string{"compliance", "cscrf"}, Steps: []scenario.Step{{TechniqueID: "T1490"}}},
		{Tags: []string{"ransomware"}, Steps: []scenario.Step{{TechniqueID: "T1486"}}}, // not compliance-tagged
	}
	idx := BuildComplianceIndex(scenarios)
	if !idx["T1490"] {
		t.Error("expected T1490 in compliance index (scenario is compliance-tagged)")
	}
	if idx["T1486"] {
		t.Error("did not expect T1486 in compliance index (scenario is not compliance-tagged)")
	}
}

func TestBuildProfileIndex(t *testing.T) {
	profiles := map[string]*scenario.DetectionProfile{
		"windows_sam_theft":         {TechniqueIDs: []string{"T1003.002"}},
		"windows_credential_access": {}, // no TechniqueIDs, abstract base
	}
	idx := BuildProfileIndex(profiles)
	if !idx["T1003.002"] {
		t.Error("expected T1003.002 in profile index")
	}
	if len(idx) != 1 {
		t.Errorf("expected exactly 1 entry, got %d: %v", len(idx), idx)
	}
}
