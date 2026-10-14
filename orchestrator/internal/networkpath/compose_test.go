package networkpath

import (
	"testing"
	"time"

	"github.com/audspect/bas/internal/cloudgraph"
	"github.com/audspect/bas/internal/networkgraph"
	"github.com/audspect/bas/internal/networkpolicy"
)

func policyEval(state cloudgraph.PathState, confidence string) *networkpolicy.PolicyEvaluation {
	return &networkpolicy.PolicyEvaluation{State: state, Provenance: cloudgraph.Provenance{Confidence: confidence}}
}

func TestComposeHop_RouteSupportedPolicyPermitted_PolicySupported(t *testing.T) {
	hop := ComposeHop("dmz", "internal", true, policyEval(cloudgraph.PolicySupported, "medium"), nil)
	if hop.State != cloudgraph.PolicySupported {
		t.Fatalf("state = %q, want policy_supported", hop.State)
	}
}

func TestComposeHop_RouteSupportedPolicyDenied_Blocked(t *testing.T) {
	hop := ComposeHop("dmz", "internal", true, policyEval(cloudgraph.Blocked, "medium"), nil)
	if hop.State != cloudgraph.Blocked {
		t.Fatalf("state = %q, want blocked", hop.State)
	}
}

func TestComposeHop_NoKnownRoutePolicyPermitted_Unknown(t *testing.T) {
	hop := ComposeHop("dmz", "internal", false, policyEval(cloudgraph.PolicySupported, "medium"), nil)
	if hop.State != cloudgraph.Unknown {
		t.Fatalf("state = %q, want unknown -- a missing route must never let a permit verdict through", hop.State)
	}
	if hop.Limitations == "" {
		t.Fatal("want a non-empty limitation explaining the missing route")
	}
}

func TestComposeHop_RouteSupportedPolicyUnknown_Unknown(t *testing.T) {
	hop := ComposeHop("dmz", "internal", true, policyEval(cloudgraph.Unknown, "none"), nil)
	if hop.State != cloudgraph.Unknown {
		t.Fatalf("state = %q, want unknown -- a declared route with an unresolved policy verdict stays unknown", hop.State)
	}
}

func TestComposeHop_NoPolicyEvaluationAvailable_Unknown(t *testing.T) {
	hop := ComposeHop("dmz", "internal", true, nil, nil)
	if hop.State != cloudgraph.Unknown {
		t.Fatalf("state = %q, want unknown -- no policy evaluation at all means nothing to classify with", hop.State)
	}
	if hop.Limitations == "" {
		t.Fatal("want a non-empty limitation")
	}
}

func TestComposeHop_RealObservationOverridesRoutingGap(t *testing.T) {
	obs := []networkgraph.NetworkObservation{{
		Target:     networkgraph.Target{Host: "10.0.1.50", Port: 443},
		State:      cloudgraph.Observed,
		Provenance: cloudgraph.Provenance{Confidence: "observed", ObservedAt: time.Now()},
	}}
	eval := &networkpolicy.PolicyEvaluation{
		Query:      networkpolicy.PolicyQuery{DestCIDR: "10.0.1.50/32", Port: 443},
		State:      cloudgraph.PolicySupported,
		Provenance: cloudgraph.Provenance{Confidence: "medium"},
	}
	// routeDeclared=false: no route was found, but a real observation
	// demonstrates connectivity anyway -- it must win over the routing
	// gap, not be forced to Unknown.
	hop := ComposeHop("dmz", "internal", false, eval, obs)
	if hop.State != cloudgraph.Observed {
		t.Fatalf("state = %q, want observed -- a real observation must override a routing gap", hop.State)
	}
	if hop.Limitations == "" {
		t.Fatal("want a limitation noting the routing gap even though the observation won")
	}
	if hop.Observation == nil {
		t.Fatal("want the matched observation attached")
	}
}

func TestComposeHop_ObservationPresentButNoMatchFallsThroughToPolicy(t *testing.T) {
	// An observation slice is non-empty, but it targets a different host
	// than the policy evaluation's query -- networkcorrelation finds no
	// match, so this must fall through to ordinary policy-only logic,
	// not silently stay stuck on "no observation evidence".
	obs := []networkgraph.NetworkObservation{{
		Target: networkgraph.Target{Host: "192.168.9.9", Port: 22},
		State:  cloudgraph.Observed,
	}}
	eval := &networkpolicy.PolicyEvaluation{
		Query:      networkpolicy.PolicyQuery{DestCIDR: "10.0.1.50/32", Port: 443},
		State:      cloudgraph.PolicySupported,
		Provenance: cloudgraph.Provenance{Confidence: "medium"},
	}
	hop := ComposeHop("dmz", "internal", true, eval, obs)
	if hop.State != cloudgraph.PolicySupported {
		t.Fatalf("state = %q, want policy_supported -- no real match, must fall through to the policy verdict", hop.State)
	}
}
