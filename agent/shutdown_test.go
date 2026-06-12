package main

import (
	"testing"
	"time"
)

func TestShutdownFinalizeNoopWhenIdle(t *testing.T) {
	a := &Agent{status: "idle"}
	cancelled := false
	a.cancelScenario = func() { cancelled = true }
	a.shutdownFinalize(time.Second)
	if cancelled {
		t.Error("shutdownFinalize cancelled a scenario while idle")
	}
}

func TestShutdownFinalizeCancelsAndWaitsForSpool(t *testing.T) {
	a := &Agent{status: "scanning"}
	cancelled := false
	a.cancelScenario = func() { cancelled = true }

	// Simulate an in-flight run that finalizes (spools its Partial) shortly after
	// cancellation.
	a.runWG.Add(1)
	go func() {
		defer a.runWG.Done()
		time.Sleep(50 * time.Millisecond)
	}()

	start := time.Now()
	a.shutdownFinalize(2 * time.Second)
	if !cancelled {
		t.Error("shutdownFinalize did not cancel the active scenario")
	}
	if time.Since(start) < 40*time.Millisecond {
		t.Error("shutdownFinalize returned before the run finalized its Partial")
	}
}

func TestShutdownFinalizeRespectsGraceBound(t *testing.T) {
	a := &Agent{status: "scanning"}
	a.cancelScenario = func() {}
	a.runWG.Add(1)       // a run that never finishes
	defer a.runWG.Done() // release the waiter after the test

	start := time.Now()
	a.shutdownFinalize(100 * time.Millisecond)
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Errorf("shutdownFinalize blocked %v past its grace bound", elapsed)
	}
}
