package webgwefficacy

import (
	"testing"
	"time"
)

// TestMutationTesting_ProxyBypassRegression_CaughtAndRecovered proves
// Phase 5's own mutation-testing exit criterion end-to-end, entirely
// at the fixture level (no live vendor lab exists yet -- Phase 2b is
// still blocked per docs/webgw-mastery-qa-log.md; this test never
// claims a real product was reconfigured). It deliberately introduces
// a regression into a fixture-backed scenario's own evidence
// (simulating a policy weakening in a lab), confirms the harness's
// existing, UNMODIFIED VerifyHTTPExpectation pipeline actually senses
// it rather than staying green, then restores the evidence and
// confirms recovery.
func TestMutationTesting_ProxyBypassRegression_CaughtAndRecovered(t *testing.T) {
	now := time.Now()
	window := TimeWindow{Start: now.Add(-time.Minute), End: now.Add(time.Minute)}
	exp := HTTPExpectation{RequestURL: "https://dns.google/dns-query", ExpectedAction: ExpectedBlock}

	// Baseline: the policy correctly blocks the DoH bypass attempt.
	healthyProvider := NewFixtureGatewayProvider([]GatewayEvidence{
		{RequestURL: exp.RequestURL, Action: "block", Timestamp: now, Source: SourceFixture},
	})
	baseline := VerifyHTTPExpectation(exp, HTTPObservation{}, healthyProvider, window)
	if baseline.Prevention.Verdict != VerdictPass {
		t.Fatalf("baseline Prevention.Verdict = %q, want %q -- the scenario must start healthy before mutation", baseline.Prevention.Verdict, VerdictPass)
	}

	// Mutation: simulate a policy regression in a lab -- the same
	// bypass attempt now gets allowed through.
	mutatedProvider := NewFixtureGatewayProvider([]GatewayEvidence{
		{RequestURL: exp.RequestURL, Action: "allow", Timestamp: now, Source: SourceFixture},
	})
	mutated := VerifyHTTPExpectation(exp, HTTPObservation{}, mutatedProvider, window)
	if mutated.Prevention.Verdict != VerdictFail {
		t.Fatalf("mutated Prevention.Verdict = %q, want %q -- the harness must catch the deliberately-introduced regression, never stay green", mutated.Prevention.Verdict, VerdictFail)
	}

	// Recovery: restore the original policy, confirm the scenario
	// reports healthy again rather than assuming the fix worked.
	recovered := VerifyHTTPExpectation(exp, HTTPObservation{}, healthyProvider, window)
	if recovered.Prevention.Verdict != VerdictPass {
		t.Errorf("recovered Prevention.Verdict = %q, want %q -- recovery after the fix must be confirmed, not assumed", recovered.Prevention.Verdict, VerdictPass)
	}
}

// TestMutationTesting_FailClosedRegression_CaughtAndRecovered is a
// second, independent proof using a different capability
// (Phase 3's fail-open/fail-closed check) so the exit criterion's
// "proven" language rests on more than one code path.
func TestMutationTesting_FailClosedRegression_CaughtAndRecovered(t *testing.T) {
	now := time.Now()
	window := TimeWindow{Start: now.Add(-time.Minute), End: now.Add(time.Minute)}
	exp := FailureModeExpectation{ScenarioLabel: "gateway-outage-datacenter-failover", ExpectedBehavior: ExpectedFailClosed}

	healthyProvider := NewFixtureFailureModeProvider([]FailureModeEvidence{
		{ScenarioLabel: exp.ScenarioLabel, ObservedBehavior: ExpectedFailClosed, Timestamp: now, Source: SourceFixture},
	})
	baseline := VerifyFailureModeExpectation(exp, healthyProvider, window)
	if baseline.Verdict != VerdictPass {
		t.Fatalf("baseline Verdict = %q, want %q", baseline.Verdict, VerdictPass)
	}

	mutatedProvider := NewFixtureFailureModeProvider([]FailureModeEvidence{
		{ScenarioLabel: exp.ScenarioLabel, ObservedBehavior: ExpectedFailOpen, Timestamp: now, Source: SourceFixture},
	})
	mutated := VerifyFailureModeExpectation(exp, mutatedProvider, window)
	if mutated.Verdict != VerdictFail {
		t.Fatalf("mutated Verdict = %q, want %q -- the harness must catch the fail-open regression", mutated.Verdict, VerdictFail)
	}

	recovered := VerifyFailureModeExpectation(exp, healthyProvider, window)
	if recovered.Verdict != VerdictPass {
		t.Errorf("recovered Verdict = %q, want %q", recovered.Verdict, VerdictPass)
	}
}
