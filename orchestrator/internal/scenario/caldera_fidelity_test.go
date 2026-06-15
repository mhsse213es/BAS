package scenario

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

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

func TestBuildCalderaAllWindowsStepsSetsFidelity(t *testing.T) {
	const abilitiesJSON = `[
	  {"ability_id":"a1","name":"safe recon","technique_id":"T1082","tactic":"discovery",
	   "executors":[{"platform":"windows","name":"psh","command":"systeminfo"}]},
	  {"ability_id":"a2","name":"drop tool","technique_id":"T1105","tactic":"command-and-control",
	   "executors":[{"platform":"windows","name":"psh","command":"run","payloads":["tool.exe"]}]}
	]`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v2/abilities" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(abilitiesJSON))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	steps, err := buildCalderaAllWindowsSteps(srv.URL, "")
	if err != nil {
		t.Fatalf("buildCalderaAllWindowsSteps: %v", err)
	}
	got := map[string]string{}
	for _, s := range steps {
		got[s.Name] = s.Fidelity
	}
	if got["safe recon"] != "" {
		t.Errorf("safe recon Fidelity = %q, want empty", got["safe recon"])
	}
	if got["drop tool"] != "lab-only" {
		t.Errorf("drop tool Fidelity = %q, want lab-only", got["drop tool"])
	}
}
