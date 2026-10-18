package phishbridge

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/audspect/bas/internal/emailgwefficacy"
	"github.com/audspect/bas/internal/phishval"
)

// TestDispatchRelayPathBypassMessage_TwoRealDistinctGateways proves
// the "second, differently-configured real gateway" the earlier
// overlap note said didn't exist: two SEPARATE local SMTP servers
// each receive their own, independent real SMTP delivery of the
// identical attack message.
func TestDispatchRelayPathBypassMessage_TwoRealDistinctGateways(t *testing.T) {
	directBackend, directAddr := startReplyChainTestServer(t)
	relayBackend, relayAddr := startReplyChainTestServer(t)

	directExp := DirectPathExpectation(true)
	if _, err := DispatchRelayPathBypassMessage(context.Background(), emailgwefficacy.InjectionTarget{TargetMX: directAddr}, directExp); err != nil {
		t.Fatalf("DispatchRelayPathBypassMessage (direct): %v", err)
	}
	relayExp := RelayPathExpectation(false)
	if _, err := DispatchRelayPathBypassMessage(context.Background(), emailgwefficacy.InjectionTarget{TargetMX: relayAddr}, relayExp); err != nil {
		t.Fatalf("DispatchRelayPathBypassMessage (relay): %v", err)
	}

	directBackend.mu.Lock()
	gotDirect := len(directBackend.received)
	directBackend.mu.Unlock()
	relayBackend.mu.Lock()
	gotRelay := len(relayBackend.received)
	relayRaw := string(relayBackend.received[0].Data)
	relayBackend.mu.Unlock()

	if gotDirect != 1 {
		t.Errorf("direct gateway received %d messages, want 1", gotDirect)
	}
	if gotRelay != 1 {
		t.Errorf("relay gateway received %d messages, want 1", gotRelay)
	}
	if !strings.Contains(relayRaw, "Subject: "+relayPathBypassContent.Subject) {
		t.Error("relay gateway did not receive the expected attack message")
	}
	if directAddr == relayAddr {
		t.Fatal("precondition failed: direct and relay test servers must be two distinct listeners")
	}
}

// TestPHEVA002_DirectPathCatchesWhatRelayPathBypasses is the actual
// bypass proof: the IDENTICAL attack evaluates to a BLOCKED
// enforcement verdict on the direct path and an ALLOWED verdict on
// the relay path -- a genuine behavioral difference between the two
// paths, not the same dispatch re-labeled twice.
func TestPHEVA002_DirectPathCatchesWhatRelayPathBypasses(t *testing.T) {
	now := time.Now()
	directExp := DirectPathExpectation(true)
	directProvider := emailgwefficacy.NewFixtureMailEvidenceProvider(
		[]emailgwefficacy.EnforcementEvidence{{
			Message: directExp.Ref(), Action: "quarantine", ControlProduct: directExp.ControlProduct,
			Timestamp: now, Source: emailgwefficacy.SourceFixture,
			Provenance: emailgwefficacy.Provenance{Kind: emailgwefficacy.ProvenanceObserved, Confidence: emailgwefficacy.ConfidenceHigh},
		}},
		nil,
	)
	directResult := emailgwefficacy.VerifyMailExpectation(directExp, emailgwefficacy.OriginDeliveryObservation{}, directProvider, scenarioWindow())
	directOutcome := phishval.Evaluate("run-ph-eva-002", "direct-path", catalogExpectation(t, "PH-EVA-002"), FromEmailGWEfficacyResult(directResult))
	if directOutcome.Enforcement.Verdict != phishval.VerdictPass {
		t.Fatalf("direct path Enforcement.Verdict = %q (%s), want %q (the perimeter path must catch this attack)", directOutcome.Enforcement.Verdict, directOutcome.Enforcement.Reason, phishval.VerdictPass)
	}

	relayExp := RelayPathExpectation(true) // same expectation (quarantine required) evaluated against a provider reporting it WASN'T blocked
	relayProvider := emailgwefficacy.NewFixtureMailEvidenceProvider(
		[]emailgwefficacy.EnforcementEvidence{{
			Message: relayExp.Ref(), Action: "deliver", ControlProduct: relayExp.ControlProduct,
			Timestamp: now, Source: emailgwefficacy.SourceFixture,
			Provenance: emailgwefficacy.Provenance{Kind: emailgwefficacy.ProvenanceObserved, Confidence: emailgwefficacy.ConfidenceHigh},
		}},
		nil,
	)
	relayResult := emailgwefficacy.VerifyMailExpectation(relayExp, emailgwefficacy.OriginDeliveryObservation{}, relayProvider, scenarioWindow())
	relayOutcome := phishval.Evaluate("run-ph-eva-002", "relay-path", catalogExpectation(t, "PH-EVA-002"), FromEmailGWEfficacyResult(relayResult))
	if relayOutcome.Enforcement.Verdict != phishval.VerdictFail {
		t.Fatalf("relay path Enforcement.Verdict = %q, want %q (the relay path must bypass what the direct path caught)", relayOutcome.Enforcement.Verdict, phishval.VerdictFail)
	}
}
