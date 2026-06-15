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
