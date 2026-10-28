// B5's per-step gate: combines the signed, catalog-resolved
// ExecutionClass carried on each ScenarioStep with this agent's own
// independent destructiveguard.Classify evaluation of the actual
// command text, most-restrictive-wins. See
// docs/superpowers/specs/2026-09-29-destructive-action-guardrail-b5-design.md.
//
// Phase 2 (the Local Policy Grant Mechanism, agent/policygrant) is the
// ONLY escape hatch for a destructive-classified step: an unexpired,
// matching grant bound to this agent's own identity. Nothing else --
// not the signed envelope, not scenario metadata, not an environment
// variable -- ever authorizes one (see the design doc's No-Bypass
// Invariant). checkDestructiveGrant's default here is deliberately
// fail-closed (always "absent"); only the Windows build
// (policygrant_windows.go's init) wires in the real grant store.
package main

import (
	"audspect/agent/destructiveguard"
	"audspect/agent/protocol"
)

// checkDestructiveGrant reports whether an unexpired, matching local policy
// grant authorizes action (e.g. "T1003.006:default") for this agent,
// optionally scoped to scenarioID. Overridden by policygrant_windows.go's
// init() on Windows; stays fail-closed (always "absent") on any platform
// without a real grant store wired in yet.
var checkDestructiveGrant = func(action, scenarioID string) (ok bool, status string) {
	return false, "absent"
}

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
func evaluateB5Gate(step protocol.ScenarioStep, scenarioID string) (vetoed bool, blockSource string) {
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

	var source string
	switch {
	case signedDestructive && localDestructive:
		source = "both"
	case signedDestructive:
		source = "catalog"
	case localDestructive:
		source = "local_backstop"
	default:
		return false, ""
	}

	// A local grant authorizes a specific catalog-defined action; it never
	// suppresses the local backstop's own detection above -- an active grant
	// means that, once classified destructive, execution is allowed to
	// proceed, not that the command stops being recognized as destructive.
	action := step.TechniqueID + ":"
	if step.ActionKey != "" {
		action += step.ActionKey
	} else {
		action += "default"
	}
	if ok, _ := checkDestructiveGrant(action, scenarioID); ok {
		return false, source
	}
	return true, source
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
