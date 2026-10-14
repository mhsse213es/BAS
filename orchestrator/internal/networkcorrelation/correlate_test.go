package networkcorrelation

import (
	"testing"

	"github.com/audspect/bas/internal/cloudgraph"
	"github.com/audspect/bas/internal/networkgraph"
	"github.com/audspect/bas/internal/networkpolicy"
)

func eval(destCIDR string, port int, state cloudgraph.PathState) networkpolicy.PolicyEvaluation {
	return networkpolicy.PolicyEvaluation{Query: networkpolicy.PolicyQuery{DestCIDR: destCIDR, Port: port}, State: state}
}

func obs(host string, port int, state cloudgraph.PathState) networkgraph.NetworkObservation {
	return networkgraph.NetworkObservation{Target: networkgraph.Target{Host: host, Port: port}, State: state}
}

func TestCorrelateReachability_ConsistentAllow(t *testing.T) {
	out := CorrelateReachability([]networkpolicy.PolicyEvaluation{eval("10.0.0.5/32", 443, cloudgraph.PolicySupported)},
		[]networkgraph.NetworkObservation{obs("10.0.0.5", 443, cloudgraph.Observed)})
	if out[0].Label != ConsistentAllow {
		t.Fatalf("label = %q, want consistent-allow", out[0].Label)
	}
	if out[0].Observation == nil {
		t.Fatal("want a matched observation")
	}
}

func TestCorrelateReachability_DiscrepancyUnexpectedBlock(t *testing.T) {
	out := CorrelateReachability([]networkpolicy.PolicyEvaluation{eval("10.0.0.5/32", 443, cloudgraph.PolicySupported)},
		[]networkgraph.NetworkObservation{obs("10.0.0.5", 443, cloudgraph.Blocked)})
	if out[0].Label != DiscrepancyUnexpectedBlock {
		t.Fatalf("label = %q, want discrepancy-unexpected-block", out[0].Label)
	}
}

func TestCorrelateReachability_DiscrepancyUnenforcedDeny(t *testing.T) {
	out := CorrelateReachability([]networkpolicy.PolicyEvaluation{eval("10.0.0.5/32", 22, cloudgraph.Blocked)},
		[]networkgraph.NetworkObservation{obs("10.0.0.5", 22, cloudgraph.Observed)})
	if out[0].Label != DiscrepancyUnenforcedDeny {
		t.Fatalf("label = %q, want discrepancy-unenforced-deny", out[0].Label)
	}
}

func TestCorrelateReachability_ConsistentDeny(t *testing.T) {
	out := CorrelateReachability([]networkpolicy.PolicyEvaluation{eval("10.0.0.5/32", 22, cloudgraph.Blocked)},
		[]networkgraph.NetworkObservation{obs("10.0.0.5", 22, cloudgraph.Blocked)})
	if out[0].Label != ConsistentDeny {
		t.Fatalf("label = %q, want consistent-deny", out[0].Label)
	}
}

func TestCorrelateReachability_UntestedWhenNoObservationMatches(t *testing.T) {
	out := CorrelateReachability([]networkpolicy.PolicyEvaluation{eval("10.0.0.5/32", 443, cloudgraph.PolicySupported)}, nil)
	if out[0].Label != Untested {
		t.Fatalf("label = %q, want untested", out[0].Label)
	}
	if out[0].Observation != nil {
		t.Fatal("want no observation attached")
	}
}

func TestCorrelateReachability_UntestedWhenObservationIsUnknown(t *testing.T) {
	out := CorrelateReachability([]networkpolicy.PolicyEvaluation{eval("10.0.0.5/32", 443, cloudgraph.PolicySupported)},
		[]networkgraph.NetworkObservation{obs("10.0.0.5", 443, cloudgraph.Unknown)})
	if out[0].Label != Untested {
		t.Fatalf("label = %q, want untested", out[0].Label)
	}
}

func TestCorrelateReachability_PolicyInconclusiveWhenPolicyStateIsUnknown(t *testing.T) {
	out := CorrelateReachability([]networkpolicy.PolicyEvaluation{eval("10.0.0.5/32", 443, cloudgraph.Unknown)},
		[]networkgraph.NetworkObservation{obs("10.0.0.5", 443, cloudgraph.Observed)})
	if out[0].Label != PolicyInconclusive {
		t.Fatalf("label = %q, want policy-inconclusive", out[0].Label)
	}
}

func TestCorrelateReachability_NoMatchWhenHostOutsideCIDR(t *testing.T) {
	out := CorrelateReachability([]networkpolicy.PolicyEvaluation{eval("10.0.0.5/32", 443, cloudgraph.PolicySupported)},
		[]networkgraph.NetworkObservation{obs("10.0.9.9", 443, cloudgraph.Observed)})
	if out[0].Label != Untested || out[0].Observation != nil {
		t.Fatalf("got label=%q observation=%+v, want untested with no match -- the observation's host is outside the evaluated /32", out[0].Label, out[0].Observation)
	}
}

func TestCorrelateReachability_NonIPObservationHostDoesNotCrash(t *testing.T) {
	// Phase 1's Target.Host is never required to be a literal IP. Phase 2A
	// does no DNS resolution, so this must degrade to "no match" honestly,
	// not panic or silently mismatch.
	out := CorrelateReachability([]networkpolicy.PolicyEvaluation{eval("10.0.0.5/32", 443, cloudgraph.PolicySupported)},
		[]networkgraph.NetworkObservation{obs("some-hostname.internal", 443, cloudgraph.Observed)})
	if out[0].Label != Untested || out[0].Observation != nil {
		t.Fatalf("got label=%q observation=%+v, want untested with no match for a non-IP host", out[0].Label, out[0].Observation)
	}
}
