package main

import (
	"fmt"
	"os"

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

// sprayLabHostMarker is the environment variable an operator sets in the service
// environment of the one lab host (BAS_SPRAY_LAB=1). It lives on the host, not on the
// server, so a compromised orchestrator cannot turn it on.
const sprayLabHostMarker = "BAS_SPRAY_LAB"

// sprayLabHost reports whether this agent process was started as the lab host.
func sprayLabHost() bool {
	return os.Getenv(sprayLabHostMarker) == "1"
}

// sprayLabConfigLine is the line the Linux installer writes into the agent's config
// file, so the systemd unit (EnvironmentFile=) starts the agent with the marker. It is
// empty unless the installer ran with BAS_SPRAY_LAB=1, which the operator sets in
// /etc/audspect-agent/enroll.env on the lab host only.
func sprayLabConfigLine() string {
	if sprayLabHost() {
		return sprayLabHostMarker + "=1\n"
	}
	return ""
}

// sprayLabExempt reports whether the B5 signed-destructive veto is lifted for
// this step. It requires ALL of: this host carries the local lab marker
// (BAS_SPRAY_LAB=1), the signed policy carries LabException, the scenario is in
// labExemptActions, and the step's action key is in that scenario's list. The local
// command backstop still applies in every case.
func sprayLabExempt(localLab bool, policy *protocol.LivePolicy, scenarioID, actionKey string) bool {
	if !localLab || policy == nil || !policy.LabException {
		return false
	}
	actions, ok := labExemptActions[scenarioID]
	return ok && actions[actionKey]
}
