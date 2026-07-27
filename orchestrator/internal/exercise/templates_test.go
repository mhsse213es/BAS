package exercise

import "testing"

func TestBuiltinTemplates_DetectionBridgeWiring(t *testing.T) {
	findStep := func(steps []PlanStep, id string) *PlanStep {
		for i := range steps {
			if steps[i].ID == id {
				return &steps[i]
			}
		}
		return nil
	}
	findTemplate := func(id string) *Template {
		for i := range BuiltinTemplates {
			if BuiltinTemplates[i].ID == id {
				return &BuiltinTemplates[i]
			}
		}
		return nil
	}

	ransomware := findTemplate("builtin-ransomware-response")
	if ransomware == nil {
		t.Fatal("builtin-ransomware-response template not found")
	}
	waitEDR := findStep(ransomware.Steps, "wait_edr")
	if waitEDR == nil || waitEDR.Config.WaitForDetection == nil || waitEDR.Config.WaitForDetection.ExecutionStepID != "sim" {
		t.Errorf("builtin-ransomware-response wait_edr.ExecutionStepID = %+v, want \"sim\"", waitEDR)
	}

	socDrill := findTemplate("builtin-soc-drill")
	if socDrill == nil {
		t.Fatal("builtin-soc-drill template not found")
	}
	waitDetect := findStep(socDrill.Steps, "wait_detect")
	if waitDetect == nil || waitDetect.Config.WaitForDetection == nil || waitDetect.Config.WaitForDetection.ExecutionStepID != "drill_sim" {
		t.Errorf("builtin-soc-drill wait_detect.ExecutionStepID = %+v, want \"drill_sim\"", waitDetect)
	}

	bec := findTemplate("builtin-bec")
	if bec == nil {
		t.Fatal("builtin-bec template not found")
	}
	waitDetection := findStep(bec.Steps, "wait_detection")
	if waitDetection == nil || waitDetection.Config.WaitForDetection == nil {
		t.Fatal("builtin-bec wait_detection step or its WaitForDetection config is missing")
	}
	if waitDetection.Config.WaitForDetection.ExecutionStepID != "" {
		t.Errorf("builtin-bec wait_detection.ExecutionStepID = %q, want empty (not a BAS-run-triggered detection)",
			waitDetection.Config.WaitForDetection.ExecutionStepID)
	}
}

func TestBuiltinTemplates_PurpleTeamDetectionBridgeWiring(t *testing.T) {
	findStep := func(steps []PlanStep, id string) *PlanStep {
		for i := range steps {
			if steps[i].ID == id {
				return &steps[i]
			}
		}
		return nil
	}
	findTemplate := func(id string) *Template {
		for i := range BuiltinTemplates {
			if BuiltinTemplates[i].ID == id {
				return &BuiltinTemplates[i]
			}
		}
		return nil
	}

	cases := []struct {
		templateID          string
		wantExecutionStepID string
	}{
		{"builtin-purple-apt29", "drill_sim"},
		{"builtin-purple-volt-typhoon", "drill_sim"},
		{"builtin-purple-kerberoasting", "drill_sim"},
	}
	for _, tc := range cases {
		tpl := findTemplate(tc.templateID)
		if tpl == nil {
			t.Fatalf("%s: template not found", tc.templateID)
		}
		wait := findStep(tpl.Steps, "wait_detect")
		if wait == nil || wait.Config.WaitForDetection == nil {
			t.Fatalf("%s: wait_detect step or its WaitForDetection config is missing", tc.templateID)
		}
		if wait.Config.WaitForDetection.ExecutionStepID != tc.wantExecutionStepID {
			t.Errorf("%s: ExecutionStepID = %q, want %q", tc.templateID, wait.Config.WaitForDetection.ExecutionStepID, tc.wantExecutionStepID)
		}
	}
}

func TestBuiltinTemplates_PurpleTeamMetadataPopulated(t *testing.T) {
	findTemplate := func(id string) *Template {
		for i := range BuiltinTemplates {
			if BuiltinTemplates[i].ID == id {
				return &BuiltinTemplates[i]
			}
		}
		return nil
	}

	ids := []string{"builtin-purple-apt29", "builtin-purple-volt-typhoon", "builtin-purple-kerberoasting"}
	for _, id := range ids {
		tpl := findTemplate(id)
		if tpl == nil {
			t.Fatalf("%s: template not found", id)
		}
		if tpl.Metadata.SuccessCriteria == "" {
			t.Errorf("%s: Metadata.SuccessCriteria is empty", id)
		}
		if len(tpl.Metadata.ExpectedTechniques) == 0 {
			t.Errorf("%s: Metadata.ExpectedTechniques is empty", id)
		}
	}
}

func TestBuiltinTemplates_KerberoastingIdentityOnlyGate(t *testing.T) {
	var tpl *Template
	for i := range BuiltinTemplates {
		if BuiltinTemplates[i].ID == "builtin-purple-kerberoasting" {
			tpl = &BuiltinTemplates[i]
		}
	}
	if tpl == nil {
		t.Fatal("builtin-purple-kerberoasting: template not found")
	}
	var wait *PlanStep
	for i := range tpl.Steps {
		if tpl.Steps[i].ID == "wait_detect" {
			wait = &tpl.Steps[i]
		}
	}
	if wait == nil || wait.Config.WaitForDetection == nil {
		t.Fatal("wait_detect step or its WaitForDetection config is missing")
	}
	types := wait.Config.WaitForDetection.DetectionTypes
	if len(types) != 1 || types[0] != "security_control_detected" {
		t.Errorf("DetectionTypes = %v, want exactly [security_control_detected] — an EDR alert must not be able to satisfy this identity-focused drill's gate", types)
	}
}
