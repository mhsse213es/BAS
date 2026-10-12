package cloudgraph

import (
	"testing"
)

// TestStepGate_BlocksDispatchWhenEdgeIsBlocked verifies a Blocked edge halts the step
func TestStepGate_BlocksDispatchWhenEdgeIsBlocked(t *testing.T) {
	user := &CloudIdentity{CanonicalID: "arn:aws:iam::123456789012:user/attacker"}
	role := &CloudResource{CanonicalID: "arn:aws:iam::123456789012:role/admin-role"}

	edge := &CloudPermission{
		Source: user,
		Target: role,
		Action: "sts:AssumeRole",
	}

	graph := &DiscoveredGraph{
		Evaluations: map[string]PathState{
			edgeKey(edge): Blocked,
		},
	}

	gate := &StepGate{}
	decision := gate.ShouldDispatch(edge, graph)

	if decision.Allowed {
		t.Error("Expected gate to block dispatch for Blocked edge")
	}
	if decision.Reason == "" {
		t.Error("Expected gate to document why dispatch was blocked")
	}
}

// TestStepGate_BlocksDispatchWhenEdgeIsUnknown verifies Unknown also halts the step
// (conservative: unresolved risk is treated the same as confirmed risk for dispatch purposes)
func TestStepGate_BlocksDispatchWhenEdgeIsUnknown(t *testing.T) {
	user := &CloudIdentity{CanonicalID: "arn:aws:iam::123456789012:user/attacker"}
	bucket := &CloudResource{CanonicalID: "arn:aws:s3:::test-bucket"}

	edge := &CloudPermission{
		Source: user,
		Target: bucket,
		Action: "s3:GetObject",
	}

	graph := &DiscoveredGraph{
		Evaluations: map[string]PathState{
			edgeKey(edge): Unknown,
		},
	}

	gate := &StepGate{}
	decision := gate.ShouldDispatch(edge, graph)

	if decision.Allowed {
		t.Error("Expected gate to block dispatch for Unknown edge")
	}
}

// TestStepGate_AllowsDispatchWhenEdgeIsPolicySupported verifies normal dispatch proceeds
func TestStepGate_AllowsDispatchWhenEdgeIsPolicySupported(t *testing.T) {
	user := &CloudIdentity{CanonicalID: "arn:aws:iam::123456789012:user/attacker"}
	bucket := &CloudResource{CanonicalID: "arn:aws:s3:::test-bucket"}

	edge := &CloudPermission{
		Source: user,
		Target: bucket,
		Action: "s3:GetObject",
	}

	graph := &DiscoveredGraph{
		Evaluations: map[string]PathState{
			edgeKey(edge): PolicySupported,
		},
	}

	gate := &StepGate{}
	decision := gate.ShouldDispatch(edge, graph)

	if !decision.Allowed {
		t.Error("Expected gate to allow dispatch for PolicySupported edge")
	}
}

// TestStepGate_AllowsDispatchWhenEdgeNotYetEvaluated verifies gate does not block
// on missing evaluation data alone — that is the resolver's job (UNKNOWN prerequisite),
// not the gate's. The gate only blocks on a KNOWN-bad evaluation.
func TestStepGate_AllowsDispatchWhenEdgeNotYetEvaluated(t *testing.T) {
	user := &CloudIdentity{CanonicalID: "arn:aws:iam::123456789012:user/attacker"}
	bucket := &CloudResource{CanonicalID: "arn:aws:s3:::test-bucket"}

	edge := &CloudPermission{
		Source: user,
		Target: bucket,
		Action: "s3:GetObject",
	}

	graph := &DiscoveredGraph{
		Evaluations: map[string]PathState{},
	}

	gate := &StepGate{}
	decision := gate.ShouldDispatch(edge, graph)

	if !decision.Allowed {
		t.Error("Expected gate to allow dispatch when edge has no prior evaluation (resolver's job to flag UNKNOWN upstream)")
	}
}
