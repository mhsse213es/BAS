package main

import (
	"testing"

	"audspect/agent/protocol"
)

func TestEvaluateB5Gate_SignedDestructiveIsVetoed(t *testing.T) {
	// Command deliberately does NOT match any destructiveguard rule (see
	// destructiveguard/rules.go's seed set), isolating the catalog-only
	// path: a command that only the signed classification, not the local
	// backstop, recognizes as destructive must still be vetoed.
	step := protocol.ScenarioStep{
		TechniqueID: "T1490", ActionKey: "vss_delete",
		ExecutionClass: "destructive",
		Command:        "Invoke-VendorSpecificShadowCopyPurge -Confirm:$false",
	}
	vetoed, source := evaluateB5Gate(step)
	if !vetoed {
		t.Fatal("expected veto for a signed-destructive step")
	}
	if source != "catalog" {
		t.Errorf("block_source = %q, want %q", source, "catalog")
	}
}

func TestEvaluateB5Gate_LocalBackstopCatchesUnderclassifiedStep(t *testing.T) {
	// Signed classification claims non_destructive (a compiled-in
	// mistake or catalog gap), but the actual command matches the local
	// backstop's known-catastrophic pattern -- must still be vetoed.
	step := protocol.ScenarioStep{
		TechniqueID: "T1490", ActionKey: "vss_delete",
		ExecutionClass: "non_destructive", // WRONG on purpose for this test
		Command:        "vssadmin delete shadows /all /quiet",
	}
	vetoed, source := evaluateB5Gate(step)
	if !vetoed {
		t.Fatal("expected the local backstop to override an under-classified signed field")
	}
	if source != "local_backstop" {
		t.Errorf("block_source = %q, want %q", source, "local_backstop")
	}
}

func TestEvaluateB5Gate_NonDestructiveExecutesNormally(t *testing.T) {
	step := protocol.ScenarioStep{
		TechniqueID: "T1082", ExecutionClass: "non_destructive",
		Command: "Get-ComputerInfo",
	}
	vetoed, _ := evaluateB5Gate(step)
	if vetoed {
		t.Error("expected a genuinely non-destructive step to execute")
	}
}

func TestEvaluateB5Gate_PotentiallyDestructiveExecutesNormally(t *testing.T) {
	step := protocol.ScenarioStep{
		TechniqueID: "T1003", ExecutionClass: "potentially_destructive",
		Command: "Get-Process lsass",
	}
	vetoed, _ := evaluateB5Gate(step)
	if vetoed {
		t.Error("expected potentially_destructive to execute (no grant required in this phase's semantics, and this phase has no grant mechanism to check anyway)")
	}
}

// A compromised orchestrator controls the signed ExecutionClass. If it
// pairs a benign Command with a destructive Cleanup, the gate must still
// veto -- otherwise the destructive action runs unchecked via cleanup
// (final whole-branch review, C3). Cleanup is not independently
// catalog-classified (only the step's primary action is), so this relies
// on the local backstop scanning Cleanup text too.
func TestEvaluateB5Gate_DestructiveCleanupIsVetoedEvenWithSafeCommand(t *testing.T) {
	step := protocol.ScenarioStep{
		TechniqueID: "T1082", ExecutionClass: "non_destructive",
		Command: "Write-Output hello",
		Cleanup: "vssadmin delete shadows /all /quiet",
	}
	vetoed, source := evaluateB5Gate(step)
	if !vetoed {
		t.Fatal("expected a destructive Cleanup to be vetoed even though Command is benign")
	}
	if source != "local_backstop" {
		t.Errorf("block_source = %q, want %q", source, "local_backstop")
	}
}

// Same threat model, via a staged payload's content instead of Cleanup:
// payloads are written to disk before the gate ran historically, and
// their content was never classified at all (final whole-branch review,
// C3). A text-content payload whose content matches a known-catastrophic
// pattern must be vetoed.
func TestEvaluateB5Gate_DestructivePayloadContentIsVetoedEvenWithSafeCommand(t *testing.T) {
	step := protocol.ScenarioStep{
		TechniqueID: "T1082", ExecutionClass: "non_destructive",
		Command: "Write-Output hello",
		Payloads: []protocol.Payload{
			{Name: "helper.ps1", Content: "vssadmin delete shadows /all /quiet"},
		},
	}
	vetoed, source := evaluateB5Gate(step)
	if !vetoed {
		t.Fatal("expected a destructive payload content to be vetoed even though Command is benign")
	}
	if source != "local_backstop" {
		t.Errorf("block_source = %q, want %q", source, "local_backstop")
	}
}

func TestEvaluateB5Gate_UnclassifiedIsVetoed(t *testing.T) {
	step := protocol.ScenarioStep{
		TechniqueID: "T9999", ExecutionClass: "", // never resolved / unknown to this agent build
		Command: "something",
	}
	vetoed, _ := evaluateB5Gate(step)
	if !vetoed {
		t.Fatal("expected an unclassified step to fail closed to vetoed")
	}
}
