package main

import (
	"fmt"
	"strings"

	"audspect/agent/protocol"
)

// buildPolicyEnv returns the policy variables exposed to every step of a
// scenario run as environment variables.
//
// BAS_INPROC_POLICY is always set, even when empty. An unset variable would let
// a machine-wide value decide the verdict for a run that never stated a policy.
// An empty value keeps the in-process verdict UNVERIFIED.
func buildPolicyEnv(cmd protocol.ScenarioCommand) map[string]string {
	env := map[string]string{
		"BAS_RUN_MODE":      cmd.Mode,
		"BAS_INPROC_POLICY": cmd.InProcessPolicy,
	}
	if cmd.Policy != nil {
		if cmd.Policy.MaxSprayAttempts > 0 {
			env["BAS_MAX_SPRAY_ATTEMPTS"] = fmt.Sprintf("%d", cmd.Policy.MaxSprayAttempts)
		}
		if len(cmd.Policy.SprayAccountAllowlist) > 0 {
			env["BAS_SPRAY_ALLOWLIST"] = strings.Join(cmd.Policy.SprayAccountAllowlist, ",")
		}
	}
	return env
}
