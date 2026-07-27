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
