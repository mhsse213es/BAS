// Package networkpath is the one place routing evidence
// (internal/networktopology), policy evidence (internal/networkpolicy),
// observation evidence (internal/networkgraph, via
// internal/networkcorrelation's existing fusion), and identity-domain
// corroboration (internal/attackpath, read-only) are combined into
// classified, multi-hop attack paths.
package networkpath

import (
	"github.com/audspect/bas/internal/cloudgraph"
	"github.com/audspect/bas/internal/networkcorrelation"
	"github.com/audspect/bas/internal/networkgraph"
	"github.com/audspect/bas/internal/networkpolicy"
)

// CorroboratingEvidence is purely additive context cited from the
// identity domain's existing attackpath graph. It never changes a hop's
// own PathState -- see internal/networkpath/corroborate.go.
type CorroboratingEvidence struct {
	Source   string `json:"source"` // "attackpath"
	EdgeKind string `json:"edgeKind,omitempty"`
	Note     string `json:"note,omitempty"`
}

// HopResult is one hop's evidence-composed classification.
type HopResult struct {
	FromZone         string                           `json:"fromZone"`
	ToZone           string                           `json:"toZone"`
	State            cloudgraph.PathState             `json:"state"`
	Limitations      string                           `json:"limitations,omitempty"`
	Provenance       cloudgraph.Provenance            `json:"provenance"`
	Observation      *networkgraph.NetworkObservation `json:"observation,omitempty"`
	PolicyEvaluation *networkpolicy.PolicyEvaluation  `json:"policyEvaluation,omitempty"`
	RouteDeclared    bool                             `json:"routeDeclared"`
	Corroboration    []CorroboratingEvidence          `json:"corroboration,omitempty"`
}

// ComposeHop classifies one hop given its possible evidence inputs, in
// priority order:
//
//  1. A real observation exists for this hop (networkcorrelation finds
//     a host/port match between policyEval's query and observations).
//     It wins outright -- routing evidence never overrides a real
//     observation, since a demonstrated connection or demonstrated block
//     is physical ground truth and the topology import might simply be
//     incomplete.
//  2. No observation, route declared: the policy verdict passes through
//     as-is.
//  3. No observation, route not declared (or no policy evaluation at
//     all): forced to Unknown, regardless of what the policy verdict
//     would otherwise have been -- a missing route must never read as
//     Blocked.
func ComposeHop(fromZone, toZone string, routeDeclared bool, policyEval *networkpolicy.PolicyEvaluation, observations []networkgraph.NetworkObservation) HopResult {
	result := HopResult{FromZone: fromZone, ToZone: toZone, RouteDeclared: routeDeclared, PolicyEvaluation: policyEval}

	if len(observations) > 0 && policyEval != nil {
		comparisons := networkcorrelation.CorrelateReachability([]networkpolicy.PolicyEvaluation{*policyEval}, observations)
		if cmp := comparisons[0]; cmp.Observation != nil {
			result.Observation = cmp.Observation
			result.State = cmp.Observation.State
			result.Provenance = cmp.Observation.Provenance
			if !routeDeclared {
				result.Limitations = "no declared route for this hop, but a live observation demonstrates connectivity directly -- topology data may be incomplete"
			}
			return result
		}
	}

	if policyEval == nil {
		result.State = cloudgraph.Unknown
		result.Provenance = cloudgraph.Provenance{Confidence: "none"}
		result.Limitations = "no policy evaluation available for this hop"
		return result
	}

	if !routeDeclared {
		result.State = cloudgraph.Unknown
		result.Provenance = cloudgraph.Provenance{Confidence: "none"}
		result.Limitations = "no declared route between these zones; policy evidence alone does not establish that an L3 path exists"
		return result
	}

	result.State = policyEval.State
	result.Provenance = policyEval.Provenance
	result.Limitations = policyEval.Limitations
	return result
}
