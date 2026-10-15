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

// TestProxyBypassScenario_DNSOverHTTPSCaught proves a known-good
// baseline for domain 08 (proxy bypass): a DNS-over-HTTPS bypass
// attempt is declared expected to be caught/blocked, and fixture
// evidence confirms it was.
func TestProxyBypassScenario_DNSOverHTTPSCaught(t *testing.T) {
	now := time.Now()
	exp := HTTPExpectation{
		RequestURL:     "https://dns.google/dns-query",
		URLCategory:    "doh-bypass-attempt",
		ExpectedAction: ExpectedBlock,
		ControlProduct: "cloudflare-gateway",
		Note:           "DNS-over-HTTPS bypass of the gateway's own DNS filtering",
	}
	provider := NewFixtureGatewayProvider([]GatewayEvidence{
		{RequestURL: exp.RequestURL, Action: "block", Category: "doh-bypass-attempt", PolicyRule: "block-doh-providers", Timestamp: now, Source: SourceFixture},
	})
	window := TimeWindow{Start: now.Add(-time.Minute), End: now.Add(time.Minute)}
	result := VerifyHTTPExpectation(exp, HTTPObservation{}, provider, window)

	if result.Prevention.Verdict != VerdictPass {
		t.Errorf("Prevention.Verdict = %q, want %q -- known-good baseline: the bypass attempt was caught", result.Prevention.Verdict, VerdictPass)
	}
}

// TestProxyBypassScenario_DNSOverHTTPSMissed is the negative
// counterpart: the same bypass attempt, but fixture evidence shows
// the gateway allowed it through -- the policy gap a proxy-bypass
// test exists to surface.
func TestProxyBypassScenario_DNSOverHTTPSMissed(t *testing.T) {
	now := time.Now()
	exp := HTTPExpectation{
		RequestURL:     "https://dns.google/dns-query",
		URLCategory:    "doh-bypass-attempt",
		ExpectedAction: ExpectedBlock,
		ControlProduct: "cloudflare-gateway",
	}
	provider := NewFixtureGatewayProvider([]GatewayEvidence{
		{RequestURL: exp.RequestURL, Action: "allow", Category: "doh-bypass-attempt", Timestamp: now, Source: SourceFixture},
	})
	window := TimeWindow{Start: now.Add(-time.Minute), End: now.Add(time.Minute)}
	result := VerifyHTTPExpectation(exp, HTTPObservation{}, provider, window)

	if result.Prevention.Verdict != VerdictFail {
		t.Errorf("Prevention.Verdict = %q, want %q -- negative case: the bypass attempt was missed", result.Prevention.Verdict, VerdictFail)
	}
}

// TestCASBScenario_PersonalTenantBlocked proves a known-good baseline
// for domain 06 (SaaS/CASB): access to a SaaS application under a
// personal (non-corporate) tenant is declared expected to be
// blocked, and fixture evidence confirms it was.
func TestCASBScenario_PersonalTenantBlocked(t *testing.T) {
	now := time.Now()
	exp := HTTPExpectation{
		RequestURL:     "https://drive.google.com/personal-tenant-upload",
		URLCategory:    "saas-personal-tenant",
		ExpectedAction: ExpectedBlock,
		ControlProduct: "cloudflare-gateway",
		Note:           "personal Google Drive tenant, distinct from the corporate-managed tenant",
	}
	provider := NewFixtureGatewayProvider([]GatewayEvidence{
		{RequestURL: exp.RequestURL, Action: "block", Category: "saas-personal-tenant", PolicyRule: "casb-block-personal-tenants", Timestamp: now, Source: SourceFixture},
	})
	window := TimeWindow{Start: now.Add(-time.Minute), End: now.Add(time.Minute)}
	result := VerifyHTTPExpectation(exp, HTTPObservation{}, provider, window)

	if result.Prevention.Verdict != VerdictPass {
		t.Errorf("Prevention.Verdict = %q, want %q -- known-good baseline: personal-tenant access was blocked", result.Prevention.Verdict, VerdictPass)
	}
}

// TestCASBScenario_PersonalTenantAllowedThrough is the negative
// counterpart: the same personal-tenant access, but fixture evidence
// shows the gateway allowed it through -- the shadow-IT gap a CASB
// test exists to surface.
func TestCASBScenario_PersonalTenantAllowedThrough(t *testing.T) {
	now := time.Now()
	exp := HTTPExpectation{
		RequestURL:     "https://drive.google.com/personal-tenant-upload",
		URLCategory:    "saas-personal-tenant",
		ExpectedAction: ExpectedBlock,
		ControlProduct: "cloudflare-gateway",
	}
	provider := NewFixtureGatewayProvider([]GatewayEvidence{
		{RequestURL: exp.RequestURL, Action: "allow", Category: "saas-personal-tenant", Timestamp: now, Source: SourceFixture},
	})
	window := TimeWindow{Start: now.Add(-time.Minute), End: now.Add(time.Minute)}
	result := VerifyHTTPExpectation(exp, HTTPObservation{}, provider, window)

	if result.Prevention.Verdict != VerdictFail {
		t.Errorf("Prevention.Verdict = %q, want %q -- negative case: personal-tenant access was missed", result.Prevention.Verdict, VerdictFail)
	}
}
