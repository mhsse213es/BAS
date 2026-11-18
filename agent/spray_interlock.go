package main

import (
	"fmt"

	"audspect/agent/protocol"
)

// sprayPolicyRefusal reports why a signed live policy cannot be honoured for a
// password-spray run, or "" when it can. It is evaluated before any step runs, so
// a refused run makes no authentication attempt at all.
//
// The rule is deliberately narrow and checkable from configuration alone: when a
// spray attempt cap is declared, the run must name the accounts it may touch, and
// the cap must allow at least one attempt per named account. Counting the attempts
// a script actually makes is not possible here; the scenario's own preflight and
// per-account single-attempt design do that part.
func sprayPolicyRefusal(p *protocol.LivePolicy) string {
	if p == nil || p.MaxSprayAttempts <= 0 {
		return ""
	}
	n := len(p.SprayAccountAllowlist)
	if n == 0 {
		return "max_spray_attempts is set but spray_account_allowlist names no accounts"
	}
	seen := make(map[string]bool, n)
	for _, a := range p.SprayAccountAllowlist {
		if a == "" {
			return "spray_account_allowlist contains an empty account name"
		}
		if seen[a] {
			return fmt.Sprintf("spray_account_allowlist lists %q more than once", a)
		}
		seen[a] = true
	}
	if p.MaxSprayAttempts < n {
		return fmt.Sprintf("max_spray_attempts=%d is below the %d allowlisted accounts (one attempt per account per run)", p.MaxSprayAttempts, n)
	}
	return ""
}

// labExemptActions lists, per scenario, the destructive action keys the lab
// exemption may lift. Nothing else is exempt. The server marks dispatches for
// these scenarios only on the lab agent; this table is the agent-side second check.
var labExemptActions = map[string]map[string]bool{
	"ad-password-spray-lab": {
		"credential_password_spray": true,
	},
	"ad-password-guessing-lab": {
		"credential_password_guess": true,
		"credential_stuffing":       true,
	},
}

// sprayLabExempt reports whether the B5 signed-destructive veto is lifted for
// this step. It requires ALL of: the signed policy carries LabException (set by the
// server only for the designated lab agent), the scenario is in labExemptActions,
// and the step's action key is in that scenario's list. The local command backstop
// still applies in every case.
func sprayLabExempt(policy *protocol.LivePolicy, scenarioID, actionKey string) bool {
	if policy == nil || !policy.LabException {
		return false
	}
	actions, ok := labExemptActions[scenarioID]
	return ok && actions[actionKey]
}
