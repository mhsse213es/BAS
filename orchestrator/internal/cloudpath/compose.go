// Package cloudpath is the one place routing evidence and
// security-group evidence (internal/cloudtopology) and direct
// observation evidence (internal/networkgraph) are combined into
// classified, multi-hop cloud network paths -- and the one place
// cloud-topology evidence and Cloud BAS IAM evidence (internal/
// cloudgraph) are allowed to meet, additively (see correlate.go). It
// plays exactly the role internal/networkpath plays for on-premises
// evidence.
package cloudpath

import (
	"fmt"
	"net"

	"github.com/audspect/bas/internal/cloudgraph"
	"github.com/audspect/bas/internal/cloudtopology"
	"github.com/audspect/bas/internal/networkgraph"
)

// CloudHopResult is one hop's evidence-composed classification.
// SourceEvaluation is the source subnet's own outbound (egress) rules
// for this flow; DestEvaluation is the destination subnet's own
// inbound (ingress) rules -- real cloud security groups enforce both
// sides independently, so a hop is only permitted when neither side
// denies it.
type CloudHopResult struct {
	FromSubnet        string                                 `json:"fromSubnet"`
	ToSubnet          string                                 `json:"toSubnet"`
	State             cloudgraph.PathState                   `json:"state"`
	Limitations       string                                 `json:"limitations,omitempty"`
	Provenance        cloudgraph.Provenance                  `json:"provenance"`
	Observation       *networkgraph.NetworkObservation       `json:"observation,omitempty"`
	SourceEvaluation  *cloudtopology.SecurityGroupEvaluation `json:"sourceEvaluation,omitempty"`
	DestEvaluation    *cloudtopology.SecurityGroupEvaluation `json:"destEvaluation,omitempty"`
	RouteFound        bool                                   `json:"routeFound"`
}

// ComposeCloudHop classifies one hop, in priority order -- identical
// discipline to networkpath.ComposeHop:
//  1. A real NetworkObservation exists for this hop's flow: it wins
//     outright, regardless of routing/security-group evidence.
//  2. No observation, route found: sourceEval (the source subnet's
//     outbound rules) and destEval (the destination subnet's inbound
//     rules) are combined -- either side denying the flow denies the
//     hop, matching real security-group enforcement, which gates
//     egress and ingress independently at each end.
//  3. No observation, route not found (or no security-group
//     evaluation available on either side): forced to Unknown,
//     regardless of what the security-group verdict would otherwise
//     have been.
func ComposeCloudHop(fromSubnet, toSubnet string, routeFound bool, sourceEval, destEval *cloudtopology.SecurityGroupEvaluation, observations []networkgraph.NetworkObservation) CloudHopResult {
	result := CloudHopResult{FromSubnet: fromSubnet, ToSubnet: toSubnet, RouteFound: routeFound, SourceEvaluation: sourceEval, DestEvaluation: destEval}

	if flow := flowFrom(sourceEval, destEval); flow != nil {
		if obs := matchingObservation(*flow, observations); obs != nil {
			result.Observation = obs
			result.State = obs.State
			result.Provenance = obs.Provenance
			if !routeFound {
				result.Limitations = "no declared route for this hop, but a live observation demonstrates connectivity directly -- topology data may be incomplete"
			}
			return result
		}
	}

	if sourceEval == nil && destEval == nil {
		result.State = cloudgraph.Unknown
		result.Provenance = cloudgraph.Provenance{Confidence: "none"}
		result.Limitations = "no security-group evaluation available for this hop"
		return result
	}

	if !routeFound {
		result.State = cloudgraph.Unknown
		result.Provenance = cloudgraph.Provenance{Confidence: "none"}
		result.Limitations = "no route found between these subnets; security-group evidence alone does not establish that a path exists"
		return result
	}

	result.State, result.Provenance, result.Limitations = combineSecurityGroupEvaluations(sourceEval, destEval)
	return result
}

// flowFrom returns the flow either evaluation describes -- both
// describe the same real-world flow (evaluated against two different
// subnets' rule sets), so either non-nil evaluation's Flow is
// authoritative.
func flowFrom(sourceEval, destEval *cloudtopology.SecurityGroupEvaluation) *cloudtopology.CloudFlow {
	if sourceEval != nil {
		return &sourceEval.Flow
	}
	if destEval != nil {
		return &destEval.Flow
	}
	return nil
}

// securityGroupGate is one side's (egress or ingress) independent
// enforcement verdict.
type securityGroupGate struct {
	state       cloudgraph.PathState
	provenance  cloudgraph.Provenance
	limitations string
	label       string
}

func gateFrom(eval *cloudtopology.SecurityGroupEvaluation, label string) securityGroupGate {
	if eval == nil {
		return securityGroupGate{
			state:       cloudgraph.Unknown,
			provenance:  cloudgraph.Provenance{Confidence: "none"},
			limitations: fmt.Sprintf("no %s security-group evaluation available", label),
			label:       label,
		}
	}
	return securityGroupGate{state: eval.State, provenance: eval.Provenance, limitations: eval.Limitations, label: label}
}

// combineSecurityGroupEvaluations combines the source's outbound
// (egress) gate and the destination's inbound (ingress) gate into one
// hop verdict. Blocked on either side wins outright (either gate
// denying the flow denies the hop); otherwise Unknown beats
// PolicySupported, matching the same priority
// AggregateCloudPathState uses across hops, applied here across the
// two independent gates of a single hop.
func combineSecurityGroupEvaluations(sourceEval, destEval *cloudtopology.SecurityGroupEvaluation) (cloudgraph.PathState, cloudgraph.Provenance, string) {
	src := gateFrom(sourceEval, "egress (source)")
	dst := gateFrom(destEval, "ingress (destination)")

	rank := func(s cloudgraph.PathState) int {
		switch s {
		case cloudgraph.Blocked:
			return 2
		case cloudgraph.Unknown:
			return 1
		default: // PolicySupported
			return 0
		}
	}
	winner := src
	if rank(dst.state) > rank(src.state) {
		winner = dst
	}

	note := fmt.Sprintf("security-group verdict determined by %s evaluation", winner.label)
	limitations := winner.limitations
	if limitations == "" {
		limitations = note
	} else {
		limitations = limitations + "; " + note
	}
	return winner.state, winner.provenance, limitations
}

// matchingObservation finds a real NetworkObservation whose Target
// falls within flow's destination CIDR and port -- the local
// equivalent of networkcorrelation.CorrelateReachability, re-grounded
// here since that function is typed to networkpolicy.PolicyEvaluation,
// not cloudtopology.SecurityGroupEvaluation.
func matchingObservation(flow cloudtopology.CloudFlow, observations []networkgraph.NetworkObservation) *networkgraph.NetworkObservation {
	if flow.DestCIDR == "" {
		return nil
	}
	_, destNet, err := net.ParseCIDR(flow.DestCIDR)
	if err != nil {
		return nil
	}
	for i := range observations {
		obs := &observations[i]
		if obs.Target.Port != flow.Port {
			continue
		}
		if flow.Protocol != "" && obs.Target.Protocol != "" && obs.Target.Protocol != flow.Protocol {
			continue
		}
		ip := net.ParseIP(obs.Target.Host)
		if ip == nil || !destNet.Contains(ip) {
			continue
		}
		return obs
	}
	return nil
}
