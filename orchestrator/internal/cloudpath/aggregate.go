package cloudpath

import (
	"fmt"

	"github.com/audspect/bas/internal/cloudgraph"
)

// CloudPathResult is the full path-level result: an aggregated
// PathState and confidence, plus the per-hop detail it was derived
// from.
type CloudPathResult struct {
	State      cloudgraph.PathState `json:"state"`
	Confidence string               `json:"confidence"`
	Hops       []CloudHopResult     `json:"hops"`
}

// AggregateCloudPathState computes the path-level PathState from an
// ordered slice of per-hop results, following the exact ranking
// precedent networkpath.AggregatePathState already established on
// this same PathState enum: Blocked short-circuits immediately;
// otherwise weakest-wins in order Unknown > PolicySupported >
// Observed. Re-implemented locally rather than imported, matching
// networkpath's own precedent for keeping each evidence domain
// self-contained.
func AggregateCloudPathState(hops []CloudHopResult) cloudgraph.PathState {
	sawUnknown := false
	sawPolicySupported := false
	sawObserved := false
	for _, h := range hops {
		switch h.State {
		case cloudgraph.Blocked:
			return cloudgraph.Blocked
		case cloudgraph.Unknown:
			sawUnknown = true
		case cloudgraph.PolicySupported:
			sawPolicySupported = true
		case cloudgraph.Observed:
			sawObserved = true
		}
	}
	if sawUnknown {
		return cloudgraph.Unknown
	}
	if sawPolicySupported {
		return cloudgraph.PolicySupported
	}
	if sawObserved {
		return cloudgraph.Observed
	}
	return cloudgraph.Unknown
}

// AggregateCloudConfidence mirrors networkpath.AggregateConfidence
// exactly: "none" only when the weakest hop had no evidence at all,
// otherwise always "low" regardless of the weakest hop's own
// confidence -- chaining hops compounds uncertainty beyond any single
// hop's quality. Always annotated with hop-count and the weakest
// hop's own value.
func AggregateCloudConfidence(hopCount int, weakestHopConfidence string) string {
	label := "low"
	if weakestHopConfidence == "none" {
		label = "none"
	}
	return fmt.Sprintf("%s (%d-hop chain; weakest link: %s)", label, hopCount, weakestHopConfidence)
}

// AggregateCloudPath computes the full path-level result from an
// ordered slice of per-hop results.
func AggregateCloudPath(hops []CloudHopResult) CloudPathResult {
	state := AggregateCloudPathState(hops)
	return CloudPathResult{State: state, Confidence: AggregateCloudConfidence(len(hops), weakestCloudHopConfidence(hops, state)), Hops: hops}
}

// weakestCloudHopConfidence returns the Provenance.Confidence of the
// first hop whose State equals the path's own aggregated state -- the
// hop that actually determined it, per AggregateCloudPathState's
// ranking.
func weakestCloudHopConfidence(hops []CloudHopResult, pathState cloudgraph.PathState) string {
	for _, h := range hops {
		if h.State == pathState {
			return h.Provenance.Confidence
		}
	}
	if len(hops) > 0 {
		return hops[0].Provenance.Confidence
	}
	return "none"
}
