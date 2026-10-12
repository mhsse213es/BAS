package cloudgraph

import (
	"time"

	"github.com/audspect/bas/internal/adchain"
	"github.com/audspect/bas/internal/adprimitive"
)

// HybridPathQuery describes one hybrid reachability question: can the AD
// identity holding ADHeldCapabilities reach ADTargetCapability (the capability
// that represents sync eligibility, e.g. holding valid credential material for
// the identity a FederationEdge names), and if so, does crossing a fresh
// FederationEdge into the cloud side find a supported path across CloudEdges?
type HybridPathQuery struct {
	ADCatalog          []adprimitive.Primitive
	ADHeldCapabilities []adprimitive.Capability
	ADTargetCapability adprimitive.Capability
	ADResolver         adchain.ConditionResolver

	FederationEdges  []*FederationEdge
	FederationMaxAge time.Duration

	CloudEdges     []*CloudPermission
	CloudEvaluator interface {
		EvaluatePermission(edge *CloudPermission, ctx *RequestContext) *EvaluationResult
	}
}

// HybridPathResult reports each hop's outcome independently. OverallState
// summarizes the composed path but never collapses a hop's own state into
// another hop's meaning.
type HybridPathResult struct {
	ADReachable   bool
	FederationHop string // "fresh", "stale", "no-match"
	CloudHops     []*EvaluationResult
	OverallState  string // "reachable", "blocked", "degraded", "unknown"
}

// ComposeHybridPath runs the three hops in order, stopping early whenever an
// earlier hop fails — it never evaluates the cloud side after the AD hop or
// federation hop has already failed.
func ComposeHybridPath(query *HybridPathQuery) *HybridPathResult {
	result := &HybridPathResult{}

	reachable := adchain.Reachable(query.ADCatalog, query.ADHeldCapabilities, query.ADResolver)
	result.ADReachable = containsCapability(reachable, query.ADTargetCapability)

	if !result.ADReachable {
		result.OverallState = "blocked"
		return result
	}

	fedEdge := findFederationEdgeByADRef(query.FederationEdges, query.ADTargetCapability.Target)
	if fedEdge == nil {
		result.FederationHop = "no-match"
		result.OverallState = "unknown"
		return result
	}

	if !fedEdge.IsFresh(query.FederationMaxAge) {
		result.FederationHop = "stale"
		result.OverallState = "degraded"
		return result
	}
	result.FederationHop = "fresh"

	if len(query.CloudEdges) == 0 {
		result.OverallState = "unknown"
		return result
	}

	allSupported := true
	for _, edge := range query.CloudEdges {
		eval := query.CloudEvaluator.EvaluatePermission(edge, &RequestContext{})
		result.CloudHops = append(result.CloudHops, eval)
		if eval.State != PolicySupported {
			allSupported = false
		}
	}

	if allSupported {
		result.OverallState = "reachable"
	} else {
		result.OverallState = "blocked"
	}
	return result
}

// findFederationEdgeByADRef finds the federation edge naming this AD identity
// reference, or nil if none exists -- a missing edge is "no-match", never an error.
func findFederationEdgeByADRef(edges []*FederationEdge, adRef string) *FederationEdge {
	for _, e := range edges {
		if e.ADIdentityRef == adRef {
			return e
		}
	}
	return nil
}

// containsCapability checks whether target appears in the reachable set.
// Capability equality is Kind+Target, matching adprimitive's own comparison.
func containsCapability(reachable []adprimitive.Capability, target adprimitive.Capability) bool {
	for _, c := range reachable {
		if c.Kind == target.Kind && c.Target == target.Target {
			return true
		}
	}
	return false
}
