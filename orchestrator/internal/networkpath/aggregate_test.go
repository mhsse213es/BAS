package networkpath

import (
	"testing"

	"github.com/audspect/bas/internal/cloudgraph"
)

func hr(state cloudgraph.PathState, confidence string) HopResult {
	return HopResult{State: state, Provenance: cloudgraph.Provenance{Confidence: confidence}}
}

func TestAggregatePathState_AllPolicySupported_PolicySupported(t *testing.T) {
	got := AggregatePathState([]HopResult{hr(cloudgraph.PolicySupported, "medium"), hr(cloudgraph.PolicySupported, "medium")})
	if got != cloudgraph.PolicySupported {
		t.Fatalf("got %q, want policy_supported", got)
	}
}

func TestAggregatePathState_OneBlockedHopShortCircuits_Blocked(t *testing.T) {
	got := AggregatePathState([]HopResult{hr(cloudgraph.Observed, "observed"), hr(cloudgraph.Blocked, "medium"), hr(cloudgraph.PolicySupported, "medium")})
	if got != cloudgraph.Blocked {
		t.Fatalf("got %q, want blocked -- one blocked hop must kill the whole path regardless of the others", got)
	}
}

func TestAggregatePathState_OneUnknownHopCapsClassification_Unknown(t *testing.T) {
	got := AggregatePathState([]HopResult{hr(cloudgraph.Observed, "observed"), hr(cloudgraph.Unknown, "none")})
	if got != cloudgraph.Unknown {
		t.Fatalf("got %q, want unknown -- a path must never read stronger than its weakest hop", got)
	}
}

func TestAggregatePathState_AllObserved_Observed(t *testing.T) {
	got := AggregatePathState([]HopResult{hr(cloudgraph.Observed, "observed"), hr(cloudgraph.Observed, "observed")})
	if got != cloudgraph.Observed {
		t.Fatalf("got %q, want observed", got)
	}
}

func TestAggregateConfidence_AnnotatesHopCountAndDowngradesFromWeakestLink(t *testing.T) {
	got := AggregateConfidence(3, "medium")
	want := "low (3-hop chain; weakest link: medium)"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestAggregateConfidence_NoneFloorPreserved(t *testing.T) {
	got := AggregateConfidence(2, "none")
	want := "none (2-hop chain; weakest link: none)"
	if got != want {
		t.Fatalf("got %q, want %q -- a floor of no evidence at all must not be annotated up to low", got, want)
	}
}

func TestAggregatePath_FullIntegration_CitesTheHopThatDeterminedTheState(t *testing.T) {
	hops := []HopResult{hr(cloudgraph.Observed, "observed"), hr(cloudgraph.Unknown, "none")}
	result := AggregatePath(hops)
	if result.State != cloudgraph.Unknown {
		t.Fatalf("State = %q, want unknown", result.State)
	}
	if result.Confidence != "none (2-hop chain; weakest link: none)" {
		t.Fatalf("Confidence = %q, want it to cite the unknown hop's own confidence (none), not the observed hop's", result.Confidence)
	}
	if len(result.Hops) != 2 {
		t.Fatalf("got %d hops in result, want 2", len(result.Hops))
	}
}
