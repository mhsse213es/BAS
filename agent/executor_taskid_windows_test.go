//go:build windows

package main

import (
	"context"
	"strings"
	"testing"
)

// TestExecStepExposesTaskIDToPayload verifies the per-process path gives the
// payload its own step TaskID as BAS_TASK_ID, so a payload can correlate a
// marker line to exactly one step.
func TestExecStepExposesTaskIDToPayload(t *testing.T) {
	step := ScenarioStep{
		TaskID:   "task-env-7f3a",
		Executor: "powershell",
		Command:  "Write-Output $env:BAS_TASK_ID",
	}
	r := execStep(context.Background(), step, nil)
	if !strings.Contains(r.Stdout, "task-env-7f3a") {
		t.Fatalf("BAS_TASK_ID not visible to payload; stdout=%q stderr=%q", r.Stdout, r.Stderr)
	}
}
