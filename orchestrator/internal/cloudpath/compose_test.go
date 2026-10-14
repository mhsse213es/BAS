package cloudpath

import (
	"testing"

	"github.com/audspect/bas/internal/cloudgraph"
	"github.com/audspect/bas/internal/cloudtopology"
	"github.com/audspect/bas/internal/networkgraph"
)

func TestComposeCloudHop_NoObservation_RouteFound_PolicyPassesThrough(t *testing.T) {
	sgEval := &cloudtopology.SecurityGroupEvaluation{State: cloudgraph.PolicySupported, Provenance: cloudgraph.Provenance{Confidence: "medium"}}
	hop := ComposeCloudHop("subnet-a", "subnet-b", true, sgEval, nil)
	if hop.State != cloudgraph.PolicySupported {
		t.Fatalf("State = %q, want %q", hop.State, cloudgraph.PolicySupported)
	}
}

// TestComposeCloudHop_RouteFoundButPolicyDenies and
// TestComposeCloudHop_RouteAbsentButPolicyWouldPermit together pin the
// spec's core "two independent evidence questions" principle: route
// and policy must each be able to independently decide or override the
// other's naive expectation.
func TestComposeCloudHop_RouteFoundButPolicyDenies(t *testing.T) {
	sgEval := &cloudtopology.SecurityGroupEvaluation{State: cloudgraph.Blocked, Provenance: cloudgraph.Provenance{Confidence: "medium"}}
	hop := ComposeCloudHop("subnet-a", "subnet-b", true, sgEval, nil)
	if hop.State != cloudgraph.Blocked {
		t.Fatalf("State = %q, want %q -- a found route never overrides a security-group deny", hop.State, cloudgraph.Blocked)
	}
}

func TestComposeCloudHop_RouteAbsentButPolicyWouldPermit(t *testing.T) {
	sgEval := &cloudtopology.SecurityGroupEvaluation{State: cloudgraph.PolicySupported, Provenance: cloudgraph.Provenance{Confidence: "medium"}}
	hop := ComposeCloudHop("subnet-a", "subnet-b", false, sgEval, nil)
	if hop.State != cloudgraph.Unknown {
		t.Fatalf("State = %q, want %q -- an absent route forces Unknown even though policy would otherwise permit", hop.State, cloudgraph.Unknown)
	}
}

func TestComposeCloudHop_NoSecurityGroupEvaluation_Unknown(t *testing.T) {
	hop := ComposeCloudHop("subnet-a", "subnet-b", true, nil, nil)
	if hop.State != cloudgraph.Unknown {
		t.Fatalf("State = %q, want %q", hop.State, cloudgraph.Unknown)
	}
}

// TestComposeCloudHop_RealObservation_WinsOutright pins Review Focus
// #5: a real NetworkObservation for this hop's flow must win outright
// over security-group evidence that would otherwise classify it
// differently (here: the observation shows Blocked while the
// security-group evaluation says PolicySupported).
func TestComposeCloudHop_RealObservation_WinsOutright(t *testing.T) {
	sgEval := &cloudtopology.SecurityGroupEvaluation{
		Flow:  cloudtopology.CloudFlow{DestCIDR: "10.0.2.5/32", Protocol: "tcp", Port: 443},
		State: cloudgraph.PolicySupported,
	}
	observations := []networkgraph.NetworkObservation{
		{Target: networkgraph.Target{Host: "10.0.2.5", Port: 443, Protocol: "tcp"}, State: cloudgraph.Blocked, Provenance: cloudgraph.Provenance{Confidence: "high"}},
	}
	hop := ComposeCloudHop("subnet-a", "subnet-b", true, sgEval, observations)
	if hop.State != cloudgraph.Blocked {
		t.Fatalf("State = %q, want %q -- a real observation must win outright over security-group evidence", hop.State, cloudgraph.Blocked)
	}
	if hop.Observation == nil {
		t.Fatal("want Observation populated when a real match was found")
	}
}

func TestComposeCloudHop_ObservationForDifferentPort_DoesNotMatch(t *testing.T) {
	sgEval := &cloudtopology.SecurityGroupEvaluation{
		Flow:  cloudtopology.CloudFlow{DestCIDR: "10.0.2.5/32", Protocol: "tcp", Port: 443},
		State: cloudgraph.PolicySupported,
	}
	observations := []networkgraph.NetworkObservation{
		{Target: networkgraph.Target{Host: "10.0.2.5", Port: 22, Protocol: "tcp"}, State: cloudgraph.Blocked},
	}
	hop := ComposeCloudHop("subnet-a", "subnet-b", true, sgEval, observations)
	if hop.State != cloudgraph.PolicySupported {
		t.Fatalf("State = %q, want %q -- an observation for a different port must not match", hop.State, cloudgraph.PolicySupported)
	}
}
