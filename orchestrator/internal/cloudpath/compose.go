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
	"net"

	"github.com/audspect/bas/internal/cloudgraph"
	"github.com/audspect/bas/internal/cloudtopology"
	"github.com/audspect/bas/internal/networkgraph"
)

// CloudHopResult is one hop's evidence-composed classification.
type CloudHopResult struct {
	FromSubnet              string                                 `json:"fromSubnet"`
	ToSubnet                string                                 `json:"toSubnet"`
	State                   cloudgraph.PathState                   `json:"state"`
	Limitations             string                                 `json:"limitations,omitempty"`
	Provenance              cloudgraph.Provenance                  `json:"provenance"`
	Observation             *networkgraph.NetworkObservation       `json:"observation,omitempty"`
	SecurityGroupEvaluation *cloudtopology.SecurityGroupEvaluation `json:"securityGroupEvaluation,omitempty"`
	RouteFound              bool                                   `json:"routeFound"`
}

// ComposeCloudHop classifies one hop, in priority order -- identical
// discipline to networkpath.ComposeHop:
//  1. A real NetworkObservation exists for this hop's flow: it wins
//     outright, regardless of routing/security-group evidence.
//  2. No observation, route found: the security-group verdict passes
//     through as-is.
//  3. No observation, route not found (or no security-group
//     evaluation at all): forced to Unknown, regardless of what the
//     security-group verdict would otherwise have been.
func ComposeCloudHop(fromSubnet, toSubnet string, routeFound bool, sgEval *cloudtopology.SecurityGroupEvaluation, observations []networkgraph.NetworkObservation) CloudHopResult {
	result := CloudHopResult{FromSubnet: fromSubnet, ToSubnet: toSubnet, RouteFound: routeFound, SecurityGroupEvaluation: sgEval}

	if sgEval != nil {
		if obs := matchingObservation(sgEval.Flow, observations); obs != nil {
			result.Observation = obs
			result.State = obs.State
			result.Provenance = obs.Provenance
			if !routeFound {
				result.Limitations = "no declared route for this hop, but a live observation demonstrates connectivity directly -- topology data may be incomplete"
			}
			return result
		}
	}

	if sgEval == nil {
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

	result.State = sgEval.State
	result.Provenance = sgEval.Provenance
	result.Limitations = sgEval.Limitations
	return result
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
