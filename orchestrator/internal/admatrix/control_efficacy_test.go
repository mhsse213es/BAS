package admatrix

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestCapabilityStates_ControlEfficacyDefaultsNotEvaluated(t *testing.T) {
	for _, cs := range CapabilityStates() {
		if cs.ControlEfficacy.Evaluated {
			t.Fatalf("%s: ControlEfficacy must default to not-evaluated in this slice", cs.PrimitiveID)
		}
		// Evaluated=false must not imply any verdict/outcome was manufactured.
		if cs.ControlEfficacy.Verdict != "" || cs.ControlEfficacy.Observed != "" || cs.ControlEfficacy.Provider != "" {
			t.Fatalf("%s: not-evaluated axis must carry no verdict/outcome/provider, got %+v", cs.PrimitiveID, cs.ControlEfficacy)
		}
	}
}

func TestControlEfficacy_JSONKeyIsCamelCase(t *testing.T) {
	b, err := json.Marshal(CapabilityState{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"controlEfficacy"`) {
		t.Fatalf("expected camelCase controlEfficacy key, got: %s", b)
	}
	if strings.Contains(string(b), `"ControlEfficacy"`) {
		t.Fatal("PascalCase key leaked into JSON")
	}
}

func TestSummarize_ControlValidatedIsZeroThisSlice(t *testing.T) {
	if got := SummarizeCapabilityStates().ControlValidated; got != 0 {
		t.Fatalf("ControlValidated = %d, want 0 (nothing populates the axis live yet)", got)
	}
}

func TestSummarize_FiveExistingCountsUnchanged(t *testing.T) {
	// Explicit fixture (matches TestSummarizeCapabilityStates_HonestRollup): the
	// additive sixth axis must not perturb the five existing rollups.
	s := SummarizeCapabilityStates()
	if s.Total != 28 || s.Modeled != 28 || s.ScenarioComposed != 10 || s.Executed != 0 || s.DetectionValidated != 0 {
		t.Fatalf("five existing counts drifted: %+v (want Total=28 Modeled=28 ScenarioComposed=10 Executed=0 DetectionValidated=0)", s)
	}
	if s.ControlValidated != 0 {
		t.Fatalf("ControlValidated = %d, want 0", s.ControlValidated)
	}
}
