package cloudpath

import (
	"testing"

	"github.com/audspect/bas/internal/cloudgraph"
	"github.com/audspect/bas/internal/cloudtopology"
	"github.com/audspect/bas/internal/networkgraph"
)

func TestComposeCloudHop_NoObservation_RouteFound_BothGatesPermit_PolicySupported(t *testing.T) {
	srcEval := &cloudtopology.SecurityGroupEvaluation{State: cloudgraph.PolicySupported, Provenance: cloudgraph.Provenance{Confidence: "medium"}}
	dstEval := &cloudtopology.SecurityGroupEvaluation{State: cloudgraph.PolicySupported, Provenance: cloudgraph.Provenance{Confidence: "medium"}}
	hop := ComposeCloudHop("subnet-a", "subnet-b", true, srcEval, dstEval, nil)
	if hop.State != cloudgraph.PolicySupported {
		t.Fatalf("State = %q, want %q", hop.State, cloudgraph.PolicySupported)
	}
}

// TestComposeCloudHop_SourceOutboundDenies_OverridesDestInboundAllow and
// TestComposeCloudHop_DestInboundDenies_OverridesSourceOutboundAllow
// together pin the Critical fix: real security groups enforce egress
// (source outbound) and ingress (destination inbound) independently,
// so either side denying the flow must deny the hop -- not just the
// source side, which was the pre-fix bug.
func TestComposeCloudHop_SourceOutboundDenies_OverridesDestInboundAllow(t *testing.T) {
	srcEval := &cloudtopology.SecurityGroupEvaluation{State: cloudgraph.Blocked, Provenance: cloudgraph.Provenance{Confidence: "medium"}}
	dstEval := &cloudtopology.SecurityGroupEvaluation{State: cloudgraph.PolicySupported, Provenance: cloudgraph.Provenance{Confidence: "medium"}}
	hop := ComposeCloudHop("subnet-a", "subnet-b", true, srcEval, dstEval, nil)
	if hop.State != cloudgraph.Blocked {
		t.Fatalf("State = %q, want %q -- the source's outbound deny must still win", hop.State, cloudgraph.Blocked)
	}
}

func TestComposeCloudHop_DestInboundDenies_OverridesSourceOutboundAllow(t *testing.T) {
	srcEval := &cloudtopology.SecurityGroupEvaluation{State: cloudgraph.PolicySupported, Provenance: cloudgraph.Provenance{Confidence: "medium"}}
	dstEval := &cloudtopology.SecurityGroupEvaluation{State: cloudgraph.Blocked, Provenance: cloudgraph.Provenance{Confidence: "medium"}}
	hop := ComposeCloudHop("subnet-a", "subnet-b", true, srcEval, dstEval, nil)
	if hop.State != cloudgraph.Blocked {
		t.Fatalf("State = %q, want %q -- the destination's own inbound deny must be consulted, not just the source's outbound rules", hop.State, cloudgraph.Blocked)
	}
}

// TestComposeCloudHop_OnlySourceEvaluationAvailable_PermitDegradesToUnknown
// and TestComposeCloudHop_OnlyDestEvaluationAvailable_DenyStillWins
// together pin the missing-side semantics: a confirmed deny from the
// side that IS evaluated still wins outright (a missing side can
// never excuse a confirmed block), but a confirmed permit degrades to
// Unknown when the other required gate has no evidence at all --
// permission can never be confirmed from only one of the two
// independent gates.
func TestComposeCloudHop_OnlySourceEvaluationAvailable_PermitDegradesToUnknown(t *testing.T) {
	srcEval := &cloudtopology.SecurityGroupEvaluation{State: cloudgraph.PolicySupported, Provenance: cloudgraph.Provenance{Confidence: "medium"}}
	hop := ComposeCloudHop("subnet-a", "subnet-b", true, srcEval, nil, nil)
	if hop.State != cloudgraph.Unknown {
		t.Fatalf("State = %q, want %q -- a permit on the evaluated side cannot confirm the hop when the other required gate has no evidence", hop.State, cloudgraph.Unknown)
	}
}

func TestComposeCloudHop_OnlyDestEvaluationAvailable_DenyStillWins(t *testing.T) {
	dstEval := &cloudtopology.SecurityGroupEvaluation{State: cloudgraph.Blocked, Provenance: cloudgraph.Provenance{Confidence: "medium"}}
	hop := ComposeCloudHop("subnet-a", "subnet-b", true, nil, dstEval, nil)
	if hop.State != cloudgraph.Blocked {
		t.Fatalf("State = %q, want %q -- a confirmed deny on the evaluated side must win even though the other side has no evidence", hop.State, cloudgraph.Blocked)
	}
}

func TestComposeCloudHop_RouteAbsentButBothGatesWouldPermit(t *testing.T) {
	srcEval := &cloudtopology.SecurityGroupEvaluation{State: cloudgraph.PolicySupported, Provenance: cloudgraph.Provenance{Confidence: "medium"}}
	dstEval := &cloudtopology.SecurityGroupEvaluation{State: cloudgraph.PolicySupported, Provenance: cloudgraph.Provenance{Confidence: "medium"}}
	hop := ComposeCloudHop("subnet-a", "subnet-b", false, srcEval, dstEval, nil)
	if hop.State != cloudgraph.Unknown {
		t.Fatalf("State = %q, want %q -- an absent route forces Unknown even though both gates would otherwise permit", hop.State, cloudgraph.Unknown)
	}
}

func TestComposeCloudHop_NoSecurityGroupEvaluationEitherSide_Unknown(t *testing.T) {
	hop := ComposeCloudHop("subnet-a", "subnet-b", true, nil, nil, nil)
	if hop.State != cloudgraph.Unknown {
		t.Fatalf("State = %q, want %q", hop.State, cloudgraph.Unknown)
	}
}

// TestComposeCloudHop_RealObservation_WinsOutright pins Review Focus
// #5: a real NetworkObservation for this hop's flow must win outright
// over security-group evidence that would otherwise classify it
// differently (here: the observation shows Blocked while both gates
// say PolicySupported).
func TestComposeCloudHop_RealObservation_WinsOutright(t *testing.T) {
	flow := cloudtopology.CloudFlow{DestCIDR: "10.0.2.5/32", Protocol: "tcp", Port: 443}
	srcEval := &cloudtopology.SecurityGroupEvaluation{Flow: flow, State: cloudgraph.PolicySupported}
	dstEval := &cloudtopology.SecurityGroupEvaluation{Flow: flow, State: cloudgraph.PolicySupported}
	observations := []networkgraph.NetworkObservation{
		{Target: networkgraph.Target{Host: "10.0.2.5", Port: 443, Protocol: "tcp"}, State: cloudgraph.Blocked, Provenance: cloudgraph.Provenance{Confidence: "high"}},
	}
	hop := ComposeCloudHop("subnet-a", "subnet-b", true, srcEval, dstEval, observations)
	if hop.State != cloudgraph.Blocked {
		t.Fatalf("State = %q, want %q -- a real observation must win outright over security-group evidence", hop.State, cloudgraph.Blocked)
	}
	if hop.Observation == nil {
		t.Fatal("want Observation populated when a real match was found")
	}
}

func TestComposeCloudHop_ObservationForDifferentPort_DoesNotMatch(t *testing.T) {
	flow := cloudtopology.CloudFlow{DestCIDR: "10.0.2.5/32", Protocol: "tcp", Port: 443}
	srcEval := &cloudtopology.SecurityGroupEvaluation{Flow: flow, State: cloudgraph.PolicySupported}
	dstEval := &cloudtopology.SecurityGroupEvaluation{Flow: flow, State: cloudgraph.PolicySupported}
	observations := []networkgraph.NetworkObservation{
		{Target: networkgraph.Target{Host: "10.0.2.5", Port: 22, Protocol: "tcp"}, State: cloudgraph.Blocked},
	}
	hop := ComposeCloudHop("subnet-a", "subnet-b", true, srcEval, dstEval, observations)
	if hop.State != cloudgraph.PolicySupported {
		t.Fatalf("State = %q, want %q -- an observation for a different port must not match", hop.State, cloudgraph.PolicySupported)
	}
}
