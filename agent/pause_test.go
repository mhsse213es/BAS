package main

import (
	"testing"

	"audspect/agent/sched"
)

func TestPauseCurrentScenario(t *testing.T) {
	a := &Agent{}

	if a.pauseCurrentScenario() {
		t.Error("pauseCurrentScenario with no active run = true, want false")
	}

	gate := sched.NewGate()
	a.pauseGate = gate
	if !a.pauseCurrentScenario() {
		t.Error("pauseCurrentScenario with active run = false, want true")
	}
	if !gate.IsPaused() {
		t.Error("the run's gate was not paused")
	}
}

func TestResumeCurrentScenario(t *testing.T) {
	a := &Agent{}

	if a.resumeCurrentScenario() {
		t.Error("resumeCurrentScenario with no active run = true, want false")
	}

	gate := sched.NewGate()
	gate.Pause()
	a.pauseGate = gate
	if !a.resumeCurrentScenario() {
		t.Error("resumeCurrentScenario with active run = false, want true")
	}
	if gate.IsPaused() {
		t.Error("the run's gate was not resumed")
	}
}

func TestPauseCurrentScenario_EmitsConfirmationEvent(t *testing.T) {
	a := &Agent{pauseGate: sched.NewGate()}
	var got RunEvent
	a.pauseEmit = func(ev RunEvent) { got = ev }
	a.pauseCurrentScenario()
	if got.Type != "paused" {
		t.Errorf("emitted event type = %q, want %q", got.Type, "paused")
	}
}

func TestResumeCurrentScenario_EmitsConfirmationEvent(t *testing.T) {
	gate := sched.NewGate()
	gate.Pause()
	a := &Agent{pauseGate: gate}
	var got RunEvent
	a.pauseEmit = func(ev RunEvent) { got = ev }
	a.resumeCurrentScenario()
	if got.Type != "resumed" {
		t.Errorf("emitted event type = %q, want %q", got.Type, "resumed")
	}
}
