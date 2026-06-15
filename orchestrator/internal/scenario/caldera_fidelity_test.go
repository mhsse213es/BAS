package scenario

import "testing"

func TestCalderaStepFidelity(t *testing.T) {
	withPayload := calderaAbilityFull{Executors: []calderaExecutor{
		{Platform: "windows", Name: "psh", Command: "x", Payloads: []string{"mimikatz.exe"}},
	}}
	noPayload := calderaAbilityFull{Executors: []calderaExecutor{
		{Platform: "windows", Name: "psh", Command: "x"},
	}}
	if got := calderaStepFidelity(withPayload); got != "lab-only" {
		t.Errorf("payload-bearing ability fidelity = %q, want lab-only", got)
	}
	if got := calderaStepFidelity(noPayload); got != "" {
		t.Errorf("payload-free ability fidelity = %q, want empty", got)
	}
}

func TestFullSweepTagsPayloadAbilityLabOnly(t *testing.T) {
	abilities := []calderaAbilityFull{
		{AbilityID: "a1", Name: "safe recon", TechniqueID: "T1082",
			Executors: []calderaExecutor{{Platform: "windows", Name: "psh", Command: "systeminfo"}}},
		{AbilityID: "a2", Name: "drop tool", TechniqueID: "T1105",
			Executors: []calderaExecutor{{Platform: "windows", Name: "psh", Command: "run", Payloads: []string{"tool.exe"}}}},
	}
	got := map[string]string{}
	for _, ab := range abilities {
		if pickExecutorCommand(ab.Executors, "psh") == "" {
			continue
		}
		got[ab.Name] = calderaStepFidelity(ab)
	}
	if got["safe recon"] != "" {
		t.Errorf("safe recon fidelity = %q, want empty (telemetry+lab)", got["safe recon"])
	}
	if got["drop tool"] != "lab-only" {
		t.Errorf("drop tool fidelity = %q, want lab-only", got["drop tool"])
	}
}
