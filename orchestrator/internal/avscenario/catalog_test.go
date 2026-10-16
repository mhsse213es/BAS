package avscenario

import "testing"

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
			t.Errorf("step %q uses the fictional harness-required 'binary' executor; AV-BEHAV-001 must be excluded from the dispatchable seed set", step.Name)
		}
	}
}

func TestAudspectAVAssessmentScenario_ExcludesHarnessRequiredVector(t *testing.T) {
	s, err := AudspectAVAssessmentScenario()
	if err != nil {
		t.Fatalf("AudspectAVAssessmentScenario: %v", err)
	}
	for _, step := range s.Steps {
		if step.Name != "" && step.Name[:12] == "AV-BEHAV-001" {
			t.Fatalf("AV-BEHAV-001 must not appear in the dispatchable assessment scenario, found step %q", step.Name)
		}
	}
}
