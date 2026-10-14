package networkefficacy

import (
	"errors"
	"testing"
	"time"

	"github.com/audspect/bas/internal/cloudgraph"
	"github.com/audspect/bas/internal/networkgraph"
)

func expectation(action ExpectedControlAction) ControlExpectation {
	return ControlExpectation{FlowSourceCIDR: "10.0.1.0/24", FlowDestCIDR: "10.0.2.0/24", FlowPort: 443, FlowProtocol: "tcp", ExpectedAction: action, ControlProduct: "opnsense"}
}

func observationState(state cloudgraph.PathState) networkgraph.NetworkObservation {
	return networkgraph.NetworkObservation{Target: networkgraph.Target{Host: "10.0.2.5", Port: 443}, State: state}
}

type erroringFirewallProvider struct{}

func (erroringFirewallProvider) FirewallEvidenceFor(Flow, TimeWindow) ([]FirewallEvidence, error) {
	return nil, errors.New("connection refused")
}

type erroringIDSProvider struct{}

func (erroringIDSProvider) IDSEvidenceFor(Flow, TimeWindow) ([]IDSEvidence, error) {
	return nil, errors.New("file not found")
}

var testWindow = TimeWindow{Start: time.Now().Add(-time.Hour), End: time.Now().Add(time.Hour)}

func TestVerifyControlExpectation_BlockProviderError_Inconclusive(t *testing.T) {
	result := VerifyControlExpectation(expectation(ExpectedBlock), observationState(cloudgraph.Unknown), nil, erroringFirewallProvider{}, NewFixtureIDSProvider(nil), testWindow)
	if result.Verdict != VerdictInconclusive {
		t.Fatalf("Verdict = %q, want inconclusive", result.Verdict)
	}
	if result.Reason == "" {
		t.Fatal("want a non-empty reason")
	}
}

func TestVerifyControlExpectation_BlockNoMatch_Inconclusive(t *testing.T) {
	result := VerifyControlExpectation(expectation(ExpectedBlock), observationState(cloudgraph.Unknown), nil, NewSyntheticFirewallProvider(nil), NewFixtureIDSProvider(nil), testWindow)
	if result.Verdict != VerdictInconclusive {
		t.Fatalf("Verdict = %q, want inconclusive -- a firewall's silence is not proof of anything", result.Verdict)
	}
}

func TestVerifyControlExpectation_BlockMatchBlock_Met(t *testing.T) {
	fw := NewSyntheticFirewallProvider([]FirewallEvidence{{SourceIP: "10.0.1.5", DestIP: "10.0.2.5", Port: 443, Protocol: "tcp", Action: "block", Timestamp: time.Now(), Source: SourceSynthetic}})
	result := VerifyControlExpectation(expectation(ExpectedBlock), observationState(cloudgraph.Blocked), nil, fw, NewFixtureIDSProvider(nil), testWindow)
	if result.Verdict != VerdictMet {
		t.Fatalf("Verdict = %q, want met", result.Verdict)
	}
	if result.FirewallEvidence == nil || result.FirewallEvidence.Action != "block" {
		t.Fatalf("want the matched FirewallEvidence attached, got %+v", result.FirewallEvidence)
	}
}

func TestVerifyControlExpectation_BlockMatchPermit_NotMet(t *testing.T) {
	fw := NewSyntheticFirewallProvider([]FirewallEvidence{{SourceIP: "10.0.1.5", DestIP: "10.0.2.5", Port: 443, Protocol: "tcp", Action: "permit", Timestamp: time.Now(), Source: SourceSynthetic}})
	result := VerifyControlExpectation(expectation(ExpectedBlock), observationState(cloudgraph.Observed), nil, fw, NewFixtureIDSProvider(nil), testWindow)
	if result.Verdict != VerdictNotMet {
		t.Fatalf("Verdict = %q, want not-met", result.Verdict)
	}
}

func TestVerifyControlExpectation_AlertProviderError_Inconclusive(t *testing.T) {
	result := VerifyControlExpectation(expectation(ExpectedAlert), observationState(cloudgraph.Observed), nil, NewSyntheticFirewallProvider(nil), erroringIDSProvider{}, testWindow)
	if result.Verdict != VerdictInconclusive {
		t.Fatalf("Verdict = %q, want inconclusive", result.Verdict)
	}
}

func TestVerifyControlExpectation_AlertNoMatch_NotMet(t *testing.T) {
	result := VerifyControlExpectation(expectation(ExpectedAlert), observationState(cloudgraph.Observed), nil, NewSyntheticFirewallProvider(nil), NewFixtureIDSProvider(nil), testWindow)
	if result.Verdict != VerdictNotMet {
		t.Fatalf("Verdict = %q, want not-met -- a clean empty IDS search is a reliable negative signal, unlike firewall silence", result.Verdict)
	}
}

func TestVerifyControlExpectation_AlertMatch_Met(t *testing.T) {
	ids := NewFixtureIDSProvider([]IDSEvidence{{SourceIP: "10.0.1.5", DestIP: "10.0.2.5", Port: 443, Protocol: "tcp", AlertName: "ET SCAN", Timestamp: time.Now(), Source: SourceFixture}})
	result := VerifyControlExpectation(expectation(ExpectedAlert), observationState(cloudgraph.Observed), nil, NewSyntheticFirewallProvider(nil), ids, testWindow)
	if result.Verdict != VerdictMet {
		t.Fatalf("Verdict = %q, want met", result.Verdict)
	}
	if result.IDSEvidence == nil || result.IDSEvidence.AlertName != "ET SCAN" {
		t.Fatalf("want the matched IDSEvidence attached, got %+v", result.IDSEvidence)
	}
}

func TestVerifyControlExpectation_MultipleMatchingRecords_MostRecentWins(t *testing.T) {
	now := time.Now()
	fw := NewSyntheticFirewallProvider([]FirewallEvidence{
		{SourceIP: "10.0.1.5", DestIP: "10.0.2.5", Port: 443, Protocol: "tcp", Action: "permit", Timestamp: now.Add(-time.Minute), Source: SourceSynthetic},
		{SourceIP: "10.0.1.5", DestIP: "10.0.2.5", Port: 443, Protocol: "tcp", Action: "block", Timestamp: now, Source: SourceSynthetic},
	})
	result := VerifyControlExpectation(expectation(ExpectedBlock), observationState(cloudgraph.Blocked), nil, fw, NewFixtureIDSProvider(nil), testWindow)
	if result.Verdict != VerdictMet {
		t.Fatalf("Verdict = %q, want met -- the LATER record (action=block) must win over the earlier permit record", result.Verdict)
	}
	if result.FirewallEvidence.Action != "block" {
		t.Fatalf("FirewallEvidence.Action = %q, want block (the most recent record)", result.FirewallEvidence.Action)
	}
}

func TestVerifyControlExpectation_Contradiction_BlockedClaimedButObservedReachable(t *testing.T) {
	fw := NewSyntheticFirewallProvider([]FirewallEvidence{{SourceIP: "10.0.1.5", DestIP: "10.0.2.5", Port: 443, Protocol: "tcp", Action: "block", Timestamp: time.Now(), Source: SourceSynthetic}})
	result := VerifyControlExpectation(expectation(ExpectedBlock), observationState(cloudgraph.Observed), nil, fw, NewFixtureIDSProvider(nil), testWindow)
	if result.Verdict != VerdictMet {
		t.Fatalf("Verdict = %q, want met -- the firewall's own evidence still says block, Contradiction is additive, not an override", result.Verdict)
	}
	if result.Contradiction == "" {
		t.Fatal("want a non-empty Contradiction -- firewall claims blocked, but our own probe observed the flow as reachable")
	}
}

func TestVerifyControlExpectation_Contradiction_PermittedClaimedButObservedBlocked(t *testing.T) {
	fw := NewSyntheticFirewallProvider([]FirewallEvidence{{SourceIP: "10.0.1.5", DestIP: "10.0.2.5", Port: 443, Protocol: "tcp", Action: "permit", Timestamp: time.Now(), Source: SourceSynthetic}})
	result := VerifyControlExpectation(expectation(ExpectedBlock), observationState(cloudgraph.Blocked), nil, fw, NewFixtureIDSProvider(nil), testWindow)
	if result.Verdict != VerdictNotMet {
		t.Fatalf("Verdict = %q, want not-met", result.Verdict)
	}
	if result.Contradiction == "" {
		t.Fatal("want a non-empty Contradiction -- firewall claims permitted, but our own probe observed the flow as blocked")
	}
}

func TestVerifyControlExpectation_NoContradictionWhenEvidenceAndObservationAgree(t *testing.T) {
	fw := NewSyntheticFirewallProvider([]FirewallEvidence{{SourceIP: "10.0.1.5", DestIP: "10.0.2.5", Port: 443, Protocol: "tcp", Action: "block", Timestamp: time.Now(), Source: SourceSynthetic}})
	result := VerifyControlExpectation(expectation(ExpectedBlock), observationState(cloudgraph.Blocked), nil, fw, NewFixtureIDSProvider(nil), testWindow)
	if result.Contradiction != "" {
		t.Fatalf("Contradiction = %q, want empty -- the firewall's claim and our observation agree", result.Contradiction)
	}
}

func TestVerifyControlExpectation_AlertExpectationNeverSetsContradiction(t *testing.T) {
	// Observation shows Blocked, which would trigger the block-path
	// heuristic if it were wrongly applied to an alert expectation --
	// it must not be, since an IDS alerting on a payload and a
	// connection failing for an unrelated reason are not evidence of
	// anything about each other.
	ids := NewFixtureIDSProvider([]IDSEvidence{{SourceIP: "10.0.1.5", DestIP: "10.0.2.5", Port: 443, Protocol: "tcp", AlertName: "ET SCAN", Timestamp: time.Now(), Source: SourceFixture}})
	result := VerifyControlExpectation(expectation(ExpectedAlert), observationState(cloudgraph.Blocked), nil, NewSyntheticFirewallProvider(nil), ids, testWindow)
	if result.Contradiction != "" {
		t.Fatalf("Contradiction = %q, want always empty for an alert expectation", result.Contradiction)
	}
}
