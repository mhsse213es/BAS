package cloudpath

import (
	"testing"

	"github.com/audspect/bas/internal/cloudgraph"
)

func TestAggregateCloudPathState_AnyBlockedWins(t *testing.T) {
	hops := []CloudHopResult{
		{State: cloudgraph.PolicySupported},
		{State: cloudgraph.Blocked},
		{State: cloudgraph.Observed},
	}
	if got := AggregateCloudPathState(hops); got != cloudgraph.Blocked {
		t.Fatalf("got %q, want %q", got, cloudgraph.Blocked)
	}
}

func TestAggregateCloudPathState_UnknownBeatsPolicySupported(t *testing.T) {
	hops := []CloudHopResult{{State: cloudgraph.PolicySupported}, {State: cloudgraph.Unknown}}
	if got := AggregateCloudPathState(hops); got != cloudgraph.Unknown {
		t.Fatalf("got %q, want %q", got, cloudgraph.Unknown)
	}
}

func TestAggregateCloudPathState_AllObserved(t *testing.T) {
	hops := []CloudHopResult{{State: cloudgraph.Observed}, {State: cloudgraph.Observed}}
	if got := AggregateCloudPathState(hops); got != cloudgraph.Observed {
		t.Fatalf("got %q, want %q", got, cloudgraph.Observed)
	}
}

func TestAggregateCloudPath_SingleHop_ConfidencePassesThroughConfidenceLabel(t *testing.T) {
	hops := []CloudHopResult{{State: cloudgraph.PolicySupported, Provenance: cloudgraph.Provenance{Confidence: "medium"}}}
	result := AggregateCloudPath(hops)
	if result.State != cloudgraph.PolicySupported {
		t.Fatalf("State = %q, want %q", result.State, cloudgraph.PolicySupported)
	}
	if result.Confidence == "" {
		t.Fatal("want a non-empty Confidence label")
	}
}

func TestAggregateCloudConfidence_NoneWhenWeakestHopHasNoEvidence(t *testing.T) {
	got := AggregateCloudConfidence(2, "none")
	if got != "none (2-hop chain; weakest link: none)" {
		t.Fatalf("got %q", got)
	}
}
