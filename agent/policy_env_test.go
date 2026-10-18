package main

import (
	"testing"

	"audspect/agent/protocol"
)

// The in-process policy is always set for a scenario run, even when empty. An
// unset value would let a machine-wide BAS_INPROC_POLICY decide the verdict for
// a run that never stated a policy.
func TestBuildPolicyEnv_InProcessPolicyAlwaysSet(t *testing.T) {
	cases := []struct {
		name   string
		policy string
		want   string
	}{
		{"not stated", "", ""},
		{"restricted", "restricted", "restricted"},
		{"unrestricted", "unrestricted", "unrestricted"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := buildPolicyEnv(protocol.ScenarioCommand{Mode: "telemetry", InProcessPolicy: tc.policy})
			got, ok := env["BAS_INPROC_POLICY"]
			if !ok {
				t.Fatalf("BAS_INPROC_POLICY must always be set, got keys %v", env)
			}
			if got != tc.want {
				t.Errorf("BAS_INPROC_POLICY = %q, want %q", got, tc.want)
			}
			if env["BAS_RUN_MODE"] != "telemetry" {
				t.Errorf("BAS_RUN_MODE = %q, want telemetry", env["BAS_RUN_MODE"])
			}
		})
	}
}
