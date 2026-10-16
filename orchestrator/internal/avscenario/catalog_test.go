package avscenario

import (
	"testing"

	"github.com/audspect/bas/internal/avcatalog"
)

func TestAudspectAVAssessmentScenario_RealCatalog_BuildsAndValidates(t *testing.T) {
	s, err := AudspectAVAssessmentScenario()
	if err != nil {
		t.Fatalf("AudspectAVAssessmentScenario: %v", err)
	}
	if err := s.Validate(); err != nil {
		t.Errorf("built scenario does not pass the real scenario.Scenario.Validate(): %v", err)
	}
	if len(s.Steps) == 0 {
		t.Error("expected at least one step")
	}
	for _, step := range s.Steps {
		if step.Executor == "binary" {
			t.Errorf("step %q uses the fictional harness-required 'binary' executor -- every dispatchable vector must use a real agent executor", step.Name)
		}
	}
}

// Review Focus: AV-BEHAV-001 now ships a real harness and must appear in
// the dispatchable assessment scenario -- this replaces the former test
// that asserted its exclusion, from before the harness existed.
func TestAudspectAVAssessmentScenario_IncludesAVBEHAV001(t *testing.T) {
	s, err := AudspectAVAssessmentScenario()
	if err != nil {
		t.Fatalf("AudspectAVAssessmentScenario: %v", err)
	}
	var found bool
	for _, step := range s.Steps {
		if len(step.Name) >= 12 && step.Name[:12] == "AV-BEHAV-001" {
			found = true
			if step.Executor != "powershell" {
				t.Errorf("AV-BEHAV-001 step executor = %q, want %q", step.Executor, "powershell")
			}
		}
	}
	if !found {
		t.Fatal("AV-BEHAV-001 not found in the dispatchable assessment scenario")
	}
}

// Review Focus: this is the structural safeguard that separates a
// vector's definition (it has a real, concretely runnable command) from
// its execution eligibility (whether it may ever run outside a dedicated
// lab endpoint). It must never be possible for dispatchableSeedVectorIDs
// to silently reintroduce a lab-restricted vector -- this test fails the
// moment anyone adds one, regardless of where in the file it's added.
func TestDispatchableSeedVectorIDs_NeverIncludesALabRestrictedVector(t *testing.T) {
	restricted := avcatalog.LabRestrictedVectorIDs()
	for id := range dispatchableSeedVectorIDs {
		if reason, ok := restricted[id]; ok {
			t.Errorf("dispatchableSeedVectorIDs includes lab-restricted vector %q: %s", id, reason)
		}
	}
}
