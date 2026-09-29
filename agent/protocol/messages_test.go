package protocol

import (
	"encoding/json"
	"testing"
)

func TestScenarioStep_DecodesExecutionClassificationFields(t *testing.T) {
	wire := `{
		"taskId": "task-1",
		"techniqueId": "T1490",
		"name": "VSS Delete",
		"executor": "powershell",
		"command": "vssadmin delete shadows /all /quiet",
		"timeoutSec": 30,
		"actionKey": "vss_delete",
		"executionClass": "destructive",
		"destructiveAction": "vss_delete",
		"blastRadius": "Deletes VSS shadow copies -- irreversible."
	}`
	var step ScenarioStep
	if err := json.Unmarshal([]byte(wire), &step); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if step.ActionKey != "vss_delete" {
		t.Errorf("ActionKey = %q, want %q", step.ActionKey, "vss_delete")
	}
	if step.ExecutionClass != "destructive" {
		t.Errorf("ExecutionClass = %q, want %q", step.ExecutionClass, "destructive")
	}
	if step.DestructiveAction != "vss_delete" {
		t.Errorf("DestructiveAction = %q, want %q", step.DestructiveAction, "vss_delete")
	}
	if step.BlastRadius == "" {
		t.Error("BlastRadius did not decode")
	}
}
