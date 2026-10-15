package webgwefficacy

import (
	"testing"
	"time"
)

func TestComposeAttackChain_EmptySteps_NotApplicable(t *testing.T) {
	result := ComposeAttackChain("empty-chain", nil)
	if result.OverallVerdict != VerdictNotApplicable {
		t.Errorf("OverallVerdict = %q, want %q", result.OverallVerdict, VerdictNotApplicable)
	}
}

func TestComposeAttackChain_AllStepsFail_OverallFail(t *testing.T) {
	steps := []AttackChainStep{
		{Label: "step-1", Result: VerdictDetail{Verdict: VerdictFail}},
		{Label: "step-2", Result: VerdictDetail{Verdict: VerdictFail}},
	}
	result := ComposeAttackChain("full-chain-succeeded", steps)
	if result.OverallVerdict != VerdictFail {
		t.Errorf("OverallVerdict = %q, want %q -- every control failed, so the chain succeeded for the attacker", result.OverallVerdict, VerdictFail)
	}
}

func TestComposeAttackChain_OnePassAmongFails_OverallPass(t *testing.T) {
	steps := []AttackChainStep{
		{Label: "step-1", Result: VerdictDetail{Verdict: VerdictFail}},
		{Label: "step-2-control-held", Result: VerdictDetail{Verdict: VerdictPass}},
		{Label: "step-3", Result: VerdictDetail{Verdict: VerdictFail}},
	}
	result := ComposeAttackChain("chain-broken-midway", steps)
	if result.OverallVerdict != VerdictPass {
		t.Errorf("OverallVerdict = %q, want %q -- one control holding breaks the whole chain, regardless of other steps", result.OverallVerdict, VerdictPass)
	}
}

func TestComposeAttackChain_InconclusiveWithNoPass_OverallInconclusive(t *testing.T) {
	steps := []AttackChainStep{
		{Label: "step-1", Result: VerdictDetail{Verdict: VerdictFail}},
		{Label: "step-2", Result: VerdictDetail{Verdict: VerdictInconclusive}},
	}
	result := ComposeAttackChain("missing-evidence-chain", steps)
	if result.OverallVerdict != VerdictInconclusive {
		t.Errorf("OverallVerdict = %q, want %q -- missing evidence must never be read as the chain having succeeded", result.OverallVerdict, VerdictInconclusive)
	}
}

func TestComposeAttackChain_PassTakesPrecedenceOverInconclusive(t *testing.T) {
	steps := []AttackChainStep{
		{Label: "step-1-control-held", Result: VerdictDetail{Verdict: VerdictPass}},
		{Label: "step-2-missing-evidence", Result: VerdictDetail{Verdict: VerdictInconclusive}},
	}
	result := ComposeAttackChain("pass-precedence-chain", steps)
	if result.OverallVerdict != VerdictPass {
		t.Errorf("OverallVerdict = %q, want %q -- a control that held breaks the chain even if another step's evidence is missing", result.OverallVerdict, VerdictPass)
	}
}

// TestComposeAttackChain_RealWorldComposition_DNSBypassPlusFailOpen
// proves domain 12's cross-control-attack-chain exit criterion
// end-to-end using genuine step results from two different
// capabilities (this phase's and Phase 1's), not synthetic
// VerdictDetail literals.
func TestComposeAttackChain_RealWorldComposition_DNSBypassPlusFailOpen(t *testing.T) {
	now := time.Now()
	window := TimeWindow{Start: now.Add(-time.Minute), End: now.Add(time.Minute)}

	bypassExp := HTTPExpectation{RequestURL: "https://dns.google/dns-query", ExpectedAction: ExpectedBlock}
	bypassProvider := NewFixtureGatewayProvider([]GatewayEvidence{
		{RequestURL: bypassExp.RequestURL, Action: "allow", Timestamp: now, Source: SourceFixture},
	})
	bypassResult := VerifyHTTPExpectation(bypassExp, HTTPObservation{}, bypassProvider, window)

	failureExp := FailureModeExpectation{ScenarioLabel: "gateway-outage-datacenter-failover", ExpectedBehavior: ExpectedFailClosed}
	failureProvider := NewFixtureFailureModeProvider([]FailureModeEvidence{
		{ScenarioLabel: failureExp.ScenarioLabel, ObservedBehavior: ExpectedFailOpen, Timestamp: now, Source: SourceFixture},
	})
	failureResult := VerifyFailureModeExpectation(failureExp, failureProvider, window)

	chain := ComposeAttackChain("doh-bypass-during-outage", []AttackChainStep{
		{Label: "dns-over-https-bypass", Result: bypassResult.Prevention},
		{Label: "gateway-fail-open-during-outage", Result: failureResult},
	})

	if chain.OverallVerdict != VerdictFail {
		t.Errorf("OverallVerdict = %q, want %q -- both controls failed (bypass missed, gateway failed open), so the chain succeeded for the attacker", chain.OverallVerdict, VerdictFail)
	}
}
