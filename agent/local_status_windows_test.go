//go:build windows

package main

import "testing"

// TestUpdateProgress_RecordsCompletedStepCount proves the raw completed-step
// count survives into LocalOperation, not just the derived percentage — the
// agent console's "x/y steps" readout has nothing to render otherwise.
func TestUpdateProgress_RecordsCompletedStepCount(t *testing.T) {
	s := newLocalAgentState()
	s.StartOperation("sc-1", "Full Sweep", "T1072", "", 313)

	s.UpdateProgress(80, 313, "Execution", "T1055 — Process Injection Test")

	op := s.currentOp
	if op == nil {
		t.Fatal("expected currentOp to be set after StartOperation")
	}
	if op.CompletedSteps != 80 {
		t.Errorf("CompletedSteps = %d, want 80", op.CompletedSteps)
	}
	if op.TotalSteps != 313 {
		t.Errorf("TotalSteps = %d, want 313", op.TotalSteps)
	}
	wantProgress := 80 * 100 / 313
	if op.Progress != wantProgress {
		t.Errorf("Progress = %d, want %d", op.Progress, wantProgress)
	}
}

// TestUpdateProgress_RecordsCurrentStep proves the currently-executing step's
// label survives into LocalOperation — the agent console's "Executing: ..."
// line has nothing to render otherwise.
func TestUpdateProgress_RecordsCurrentStep(t *testing.T) {
	s := newLocalAgentState()
	s.StartOperation("sc-1", "Full Sweep", "T1072", "", 313)

	s.UpdateProgress(80, 313, "Execution", "T1055 — Process Injection Test")

	op := s.currentOp
	if op == nil {
		t.Fatal("expected currentOp to be set after StartOperation")
	}
	if op.CurrentStep != "T1055 — Process Injection Test" {
		t.Errorf("CurrentStep = %q, want %q", op.CurrentStep, "T1055 — Process Injection Test")
	}
}
