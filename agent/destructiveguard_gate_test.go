package main

import (
	"audspect/agent/protocol"
	"testing"
)

func withFakeGrantCheck(t *testing.T, fn func(action, scenarioID string) (bool, string)) {
	t.Helper()
	orig := checkDestructiveGrant
	checkDestructiveGrant = fn
	t.Cleanup(func() { checkDestructiveGrant = orig })
}

func TestEvaluateB5Gate_NonDestructiveNeverChecksAGrant(t *testing.T) {
	called := false
	withFakeGrantCheck(t, func(action, scenarioID string) (bool, string) { called = true; return false, "absent" })

	vetoed, _ := evaluateB5Gate(protocol.ScenarioStep{ExecutionClass: "non_destructive", Command: "echo hi", TechniqueID: "T1082", ActionKey: "enumerate"}, "run-1")
	if vetoed {
		t.Fatal("expected non_destructive to execute")
	}
	if called {
		t.Fatal("a non_destructive step must never consult the grant store")
	}
}

func TestEvaluateB5Gate_DestructiveWithoutGrantIsVetoed(t *testing.T) {
	withFakeGrantCheck(t, func(action, scenarioID string) (bool, string) { return false, "absent" })

	vetoed, source := evaluateB5Gate(protocol.ScenarioStep{ExecutionClass: "destructive", Command: "echo hi", TechniqueID: "T1003.006", ActionKey: "default"}, "run-1")
	if !vetoed {
		t.Fatal("expected destructive without a grant to be vetoed")
	}
	if source != "catalog" {
		t.Fatalf("source = %q, want catalog", source)
	}
}

func TestEvaluateB5Gate_DestructiveWithAMatchingGrantExecutes(t *testing.T) {
	var gotAction, gotScenario string
	withFakeGrantCheck(t, func(action, scenarioID string) (bool, string) {
		gotAction, gotScenario = action, scenarioID
		return true, "ok"
	})

	vetoed, _ := evaluateB5Gate(protocol.ScenarioStep{ExecutionClass: "destructive", Command: "echo hi", TechniqueID: "T1003.006", ActionKey: "default"}, "dcsync-run-1")
	if vetoed {
		t.Fatal("expected a matching grant to allow execution")
	}
	if gotAction != "T1003.006:default" {
		t.Fatalf("action passed to the grant check = %q, want T1003.006:default", gotAction)
	}
	if gotScenario != "dcsync-run-1" {
		t.Fatalf("scenarioID passed to the grant check = %q", gotScenario)
	}
}

func TestEvaluateB5Gate_MissingActionKeyDefaultsToDefault(t *testing.T) {
	var gotAction string
	withFakeGrantCheck(t, func(action, scenarioID string) (bool, string) { gotAction = action; return false, "absent" })

	evaluateB5Gate(protocol.ScenarioStep{ExecutionClass: "destructive", Command: "echo hi", TechniqueID: "T1003.006", ActionKey: ""}, "run-1")
	if gotAction != "T1003.006:default" {
		t.Fatalf("action = %q, want T1003.006:default when ActionKey is empty", gotAction)
	}
}

func TestEvaluateB5Gate_LocalBackstopAloneStillConsultsTheGrant(t *testing.T) {
	// The catalog says non_destructive, but the local rule engine independently
	// recognizes the command as destructive -- the grant check must still run,
	// keyed by the SAME action the catalog would have used (the backstop
	// doesn't invent its own action identity).
	var called bool
	withFakeGrantCheck(t, func(action, scenarioID string) (bool, string) { called = true; return true, "ok" })

	vetoed, _ := evaluateB5Gate(protocol.ScenarioStep{
		ExecutionClass: "non_destructive",
		Command:        "vssadmin.exe delete shadows /all /quiet",
		TechniqueID:    "T1490", ActionKey: "vss_delete",
	}, "run-1")
	if !called {
		t.Fatal("expected the local backstop's destructive finding to still consult the grant")
	}
	if vetoed {
		t.Fatal("expected the matching grant to allow it through")
	}
}

func TestEvaluateB5Gate_GrantForADifferentActionDoesNotLeakThrough(t *testing.T) {
	// A grant check that returns ok=true must be trusted (the fake stands in
	// for a real CheckGrant, already covered by policygrant's own tests) --
	// this test exists to pin that evaluateB5Gate passes the CORRECT action
	// string, not a wrong one that would coincidentally match something else.
	withFakeGrantCheck(t, func(action, scenarioID string) (bool, string) {
		if action != "T1558.003:default" {
			t.Fatalf("unexpected action %q", action)
		}
		return false, "absent"
	})

	vetoed, source := evaluateB5Gate(protocol.ScenarioStep{ExecutionClass: "destructive", Command: "echo hi", TechniqueID: "T1558.003", ActionKey: ""}, "run-1")
	if !vetoed || source != "catalog" {
		t.Fatalf("vetoed=%v source=%q", vetoed, source)
	}
}
