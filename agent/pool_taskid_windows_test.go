//go:build windows

package main

import (
	"context"
	"strings"
	"testing"

	"audspect/agent/sched"
)

// TestPooledRunExposesTaskIDToPayload verifies the pooled PowerShell host path
// gives the payload its step TaskID as BAS_TASK_ID, matching the per-process
// path. The pooled path is the common one for PowerShell steps.
func TestPooledRunExposesTaskIDToPayload(t *testing.T) {
	pool := NewHostPool(1)
	defer pool.Close()
	step := ScenarioStep{
		TaskID:   "task-pool-9c1e",
		Executor: "powershell",
		Command:  "Write-Output $env:BAS_TASK_ID",
		Resource: &sched.ResourceProfile{Risk: sched.RiskObservation},
	}
	if !pooledCandidate(step) {
		t.Fatal("test step is not a pooled candidate; the test would not exercise the pool")
	}
	r, ok := pool.Run(context.Background(), step)
	if !ok {
		t.Fatal("pool.Run fell through; the pooled path was not exercised")
	}
	if !strings.Contains(r.Stdout, "task-pool-9c1e") {
		t.Fatalf("BAS_TASK_ID not visible to pooled payload; stdout=%q stderr=%q", r.Stdout, r.Stderr)
	}
}
