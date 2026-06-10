package main

import "testing"

func TestCancelCurrentScenario(t *testing.T) {
	a := &Agent{}

	// No run active → nothing to cancel.
	if a.cancelCurrentScenario() {
		t.Error("cancelCurrentScenario with no active run = true, want false")
	}

	// Active run → cancel func is invoked and it reports true.
	cancelled := false
	a.cancelScenario = func() { cancelled = true }
	if !a.cancelCurrentScenario() {
		t.Error("cancelCurrentScenario with active run = false, want true")
	}
	if !cancelled {
		t.Error("the run's cancel func was not called")
	}
}
