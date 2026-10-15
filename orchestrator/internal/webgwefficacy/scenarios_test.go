package webgwefficacy

import (
	"testing"
	"time"
)

// TestURLPolicyScenario_MalwareCategoryBlocked proves Phase 2a's
// URL-policy-enforcement exit criterion: a request to a
// malware-category URL, declared expected to be blocked, verified
// end-to-end against fixture gateway evidence -- using Phase 1's
// pipeline unchanged, with realistic category data.
func TestURLPolicyScenario_MalwareCategoryBlocked(t *testing.T) {
	now := time.Now()
	exp := HTTPExpectation{
		RequestURL:     "https://malware-distribution.example/payload.exe",
		URLCategory:    "malware",
		ExpectedAction: ExpectedBlock,
		ControlProduct: "cloudflare-gateway",
	}
	provider := NewFixtureGatewayProvider([]GatewayEvidence{
		{RequestURL: exp.RequestURL, Action: "block", Category: "malware", PolicyRule: "block-malware-category", Timestamp: now, Source: SourceFixture},
	})
	window := TimeWindow{Start: now.Add(-time.Minute), End: now.Add(time.Minute)}
	result := VerifyHTTPExpectation(exp, HTTPObservation{}, provider, window)

	if result.Prevention.Verdict != VerdictPass {
		t.Errorf("Prevention.Verdict = %q, want %q -- the URL-policy exit criterion requires this to resolve end-to-end", result.Prevention.Verdict, VerdictPass)
	}
}

// TestIdentityScopedPolicyScenario_DifferentUsersDifferentVerdicts
// proves Phase 2a's identity-scoped-policy exit criterion: the same
// URL produces different gateway evidence -- and therefore different
// verdicts -- for two different users, run through the full
// VerifyHTTPExpectation pipeline (Phase 1 only unit-tested user
// matching at the provider level, never through the full pipeline).
func TestIdentityScopedPolicyScenario_DifferentUsersDifferentVerdicts(t *testing.T) {
	now := time.Now()
	provider := NewFixtureGatewayProvider([]GatewayEvidence{
		{RequestURL: "https://social-media.example/feed", User: "contractor@example.com", Action: "block", Timestamp: now, Source: SourceFixture},
		{RequestURL: "https://social-media.example/feed", User: "employee@example.com", Action: "allow", Timestamp: now, Source: SourceFixture},
	})
	window := TimeWindow{Start: now.Add(-time.Minute), End: now.Add(time.Minute)}

	contractorResult := VerifyHTTPExpectation(
		HTTPExpectation{RequestURL: "https://social-media.example/feed", User: "contractor@example.com", ExpectedAction: ExpectedBlock},
		HTTPObservation{}, provider, window,
	)
	if contractorResult.Prevention.Verdict != VerdictPass {
		t.Errorf("contractor Prevention.Verdict = %q, want %q", contractorResult.Prevention.Verdict, VerdictPass)
	}

	employeeResult := VerifyHTTPExpectation(
		HTTPExpectation{RequestURL: "https://social-media.example/feed", User: "employee@example.com", ExpectedAction: ExpectedAllow},
		HTTPObservation{}, provider, window,
	)
	if employeeResult.Prevention.Verdict != VerdictPass {
		t.Errorf("employee Prevention.Verdict = %q, want %q", employeeResult.Prevention.Verdict, VerdictPass)
	}
}
