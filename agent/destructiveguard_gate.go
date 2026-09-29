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
//
// The local backstop scans Command, Cleanup, AND every staged payload's
// content -- not just Command. A compromised orchestrator controls the
// signed ExecutionClass and could pair a benign Command with a
// destructive Cleanup (which runs unconditionally after any non-vetoed
// step, see agent.go's runCleanup call) or a destructive payload (staged
// to disk and potentially executed via the step's own Command, e.g. `&
// $env:BAS_PAYLOAD_DIR\x.ps1`); neither is independently catalog-
// classified, only the step's primary action is (final whole-branch
// review, C3).
func evaluateB5Gate(step protocol.ScenarioStep) (vetoed bool, blockSource string) {
	signedRank := classRank(step.ExecutionClass)

	localRank := classRank(string(destructiveguard.Classify(step.Command)))
	if r := classRank(string(destructiveguard.Classify(step.Cleanup))); r > localRank {
		localRank = r
	}
	for _, p := range step.Payloads {
		if r := classRank(string(destructiveguard.Classify(p.Content))); r > localRank {
			localRank = r
		}
	}

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

// isElevatedTelemetryStep reports whether a step the gate has already
// allowed through (evaluateB5Gate returned vetoed=false) is
// potentially_destructive and so needs the elevated-telemetry treatment
// the design spec requires: "flagged distinctly, not silently identical
// to a routine step" (final whole-branch review, I4 -- the Phase 1 plan
// never scoped what "elevated telemetry" concretely meant, so none was
// built). Only the signed catalog classification is checked: the local
// backstop (destructiveguard.Classify) is binary, non_destructive or
// destructive only -- it never itself produces potentially_destructive
// (see destructiveguard/rules.go), so there is nothing to combine here
// the way evaluateB5Gate combines signed and local for the destructive
// tier.
func isElevatedTelemetryStep(step protocol.ScenarioStep) bool {
	return step.ExecutionClass == "potentially_destructive"
}
