package zoneisolation

import (
	"testing"

	"github.com/audspect/bas/internal/cloudgraph"
	"github.com/audspect/bas/internal/networkpath"
)

func testPair() ZonePairIsolation {
	return ZonePairIsolation{CanonicalID: "zp-1", ZoneA: "guest", ZoneB: "clinical"}
}

func TestClassifyIsolation_Observed_ConfirmedViolation(t *testing.T) {
	path := networkpath.PathResult{State: cloudgraph.Observed}
	result := ClassifyIsolation(testPair(), path)
	if result.Severity != SeverityConfirmedViolation {
		t.Fatalf("severity = %q, want %q", result.Severity, SeverityConfirmedViolation)
	}
}

func TestClassifyIsolation_PolicySupported_UnconfirmedExposure(t *testing.T) {
	path := networkpath.PathResult{State: cloudgraph.PolicySupported}
	result := ClassifyIsolation(testPair(), path)
	if result.Severity != SeverityUnconfirmedExposure {
		t.Fatalf("severity = %q, want %q", result.Severity, SeverityUnconfirmedExposure)
	}
}

func TestClassifyIsolation_Blocked_NoViolationFound_NoExtraLimitation(t *testing.T) {
	path := networkpath.PathResult{State: cloudgraph.Blocked}
	result := ClassifyIsolation(testPair(), path)
	if result.Severity != SeverityNoViolationFound {
		t.Fatalf("severity = %q, want %q", result.Severity, SeverityNoViolationFound)
	}
	if result.Limitations != "" {
		t.Fatalf("limitations = %q, want empty -- a confirmed block needs no extra caveat", result.Limitations)
	}
}

func TestClassifyIsolation_Unknown_NoViolationFound_WithLimitation(t *testing.T) {
	path := networkpath.PathResult{State: cloudgraph.Unknown}
	result := ClassifyIsolation(testPair(), path)
	if result.Severity != SeverityNoViolationFound {
		t.Fatalf("severity = %q, want %q", result.Severity, SeverityNoViolationFound)
	}
	if result.Limitations == "" {
		t.Fatal("want a non-empty limitation distinguishing 'no known route' from 'confirmed isolated' -- absence of evidence is not evidence of isolation")
	}
}

func TestClassifyIsolation_BlockedAndUnknown_HaveDistinctLimitations(t *testing.T) {
	blocked := ClassifyIsolation(testPair(), networkpath.PathResult{State: cloudgraph.Blocked})
	unknown := ClassifyIsolation(testPair(), networkpath.PathResult{State: cloudgraph.Unknown})
	if blocked.Limitations == unknown.Limitations {
		t.Fatalf("blocked and unknown must never carry the same limitations text -- blocked=%q unknown=%q", blocked.Limitations, unknown.Limitations)
	}
}

func TestClassifyIsolation_CarriesPairAndPathAsEvidence(t *testing.T) {
	pair := testPair()
	path := networkpath.PathResult{State: cloudgraph.Blocked, Confidence: "low (1-hop chain; weakest link: medium)"}
	result := ClassifyIsolation(pair, path)
	if result.ZonePairIsolation != pair {
		t.Fatalf("ZonePairIsolation = %+v, want %+v", result.ZonePairIsolation, pair)
	}
	if result.Path.Confidence != path.Confidence {
		t.Fatalf("Path.Confidence = %q, want %q -- the full composed path must be carried as evidence", result.Path.Confidence, path.Confidence)
	}
}
