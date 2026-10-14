package networkpath

import (
	"fmt"

	"github.com/audspect/bas/internal/cloudgraph"
)

// PathResult is the full path-level result: an aggregated PathState and
// confidence, plus the per-hop detail it was derived from.
type PathResult struct {
	State      cloudgraph.PathState
	Confidence string
	Hops       []HopResult
}

// AggregatePathState computes the path-level PathState from an ordered
// slice of per-hop results, following the exact ranking precedent
// cloudgraph.worstState (internal/cloudgraph/cloud_reachability.go:42-87)
// already established for Cloud BAS's own multi-hop permission-path
// engine on this same PathState enum: Blocked short-circuits
// immediately (any blocked hop kills the whole path); otherwise
// weakest-wins in order Unknown > PolicySupported > Observed.
// Re-implemented locally since worstState is unexported to cloudgraph --
// this keeps networkpath's own evidence domain self-contained rather
// than reaching into cloudgraph's internals.
func AggregatePathState(hops []HopResult) cloudgraph.PathState {
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

// AggregateConfidence returns the path-level confidence string. If the
// weakest hop's own confidence is "none" (no evidence at all for that
// hop), the path's confidence floor is also "none". Otherwise the path
// always reads as "low", regardless of how confident the weakest hop
// itself was -- chaining multiple hops compounds uncertainty beyond any
// single hop's own evidence quality. Always annotated with hop-count
// and the weakest hop's own value for transparency: never a bare,
// undifferentiated "low".
func AggregateConfidence(hopCount int, weakestHopConfidence string) string {
	label := "low"
	if weakestHopConfidence == "none" {
		label = "none"
	}
	return fmt.Sprintf("%s (%d-hop chain; weakest link: %s)", label, hopCount, weakestHopConfidence)
}

// AggregatePath computes the full path-level result from an ordered
// slice of per-hop results.
func AggregatePath(hops []HopResult) PathResult {
	state := AggregatePathState(hops)
	return PathResult{State: state, Confidence: AggregateConfidence(len(hops), weakestHopConfidence(hops, state)), Hops: hops}
}

// weakestHopConfidence returns the Provenance.Confidence of the first
// hop whose State equals the path's own aggregated state -- the hop
// that actually determined it, per AggregatePathState's ranking.
func weakestHopConfidence(hops []HopResult, pathState cloudgraph.PathState) string {
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
