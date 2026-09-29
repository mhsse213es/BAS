// B5's per-step gate: combines the signed, catalog-resolved
// ExecutionClass carried on each ScenarioStep with this agent's own
// independent destructiveguard.Classify evaluation of the actual
// command text, most-restrictive-wins. See
// docs/superpowers/specs/2026-09-29-destructive-action-guardrail-b5-design.md.
//
// Phase 1 has no grant mechanism (that's Phase 2) -- a step this gate
// classifies as destructive is unconditionally vetoed. Do not add a
// bypass here; the absence of one is this phase's correct behavior.
package main

import (
	"audspect/agent/destructiveguard"
	"audspect/agent/protocol"
)

// classRank orders classes for most-restrictive-wins comparison. An
// empty/unrecognized ExecutionClass ranks as destructive (fail closed) --
// see rank's own default case.
func classRank(c string) int {
	switch c {
	case "non_destructive":
		return 1
	case "potentially_destructive":
		return 2
	case "destructive":
		return 3
	default:
		return 3 // unclassified/unrecognized -- fail closed
	}
}

// evaluateB5Gate returns whether step is vetoed, and which layer decided
// it (for BLOCKED/VETOED audit reporting, Task 8): "catalog" (the
// signed classification alone was destructive), "local_backstop" (the
// agent's own rule engine caught it independently of, or despite, the
// signed classification), or "both".
func evaluateB5Gate(step protocol.ScenarioStep) (vetoed bool, blockSource string) {
	signedRank := classRank(step.ExecutionClass)
	localClass := destructiveguard.Classify(step.Command)
	localRank := classRank(string(localClass))

	signedDestructive := signedRank >= classRank("destructive")
	localDestructive := localRank >= classRank("destructive")

	switch {
	case signedDestructive && localDestructive:
		return true, "both"
	case signedDestructive:
		return true, "catalog"
	case localDestructive:
		return true, "local_backstop"
	default:
		return false, ""
	}
}
