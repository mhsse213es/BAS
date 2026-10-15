package webgwefficacy

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
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

// TestMalwareFileScenario_EICARTestFileBlocked proves a known-good
// baseline for domain 04 (malware, exploit delivery and file
// protection): a download of the industry-standard EICAR test file is
// declared expected to be blocked by the gateway's own malware/file
// protection policy, and fixture evidence confirms it was. Per
// webGW.txt's own domain-04 constraint, this never uses a real
// malware sample -- only the universally-recognized EICAR synthetic
// test string, the same discipline domain 03's DLP scenarios already
// apply to their own synthetic markers.
func TestMalwareFileScenario_EICARTestFileBlocked(t *testing.T) {
	now := time.Now()
	exp := HTTPExpectation{
		RequestURL:     "https://malware-test.example/eicar-test-file.com",
		URLCategory:    "eicar-test-file",
		ExpectedAction: ExpectedBlock,
		ControlProduct: "cloudflare-gateway",
		Note:           "industry-standard EICAR synthetic test string, never a real malware sample",
	}
	provider := NewFixtureGatewayProvider([]GatewayEvidence{
		{RequestURL: exp.RequestURL, Action: "block", Category: "eicar-test-file", PolicyRule: "block-malware-file-signature", Timestamp: now, Source: SourceFixture},
	})
	window := TimeWindow{Start: now.Add(-time.Minute), End: now.Add(time.Minute)}
	result := VerifyHTTPExpectation(exp, HTTPObservation{}, provider, window)

	if result.Prevention.Verdict != VerdictPass {
		t.Errorf("Prevention.Verdict = %q, want %q -- known-good baseline: the EICAR test-file download was blocked", result.Prevention.Verdict, VerdictPass)
	}
}

// TestMalwareFileScenario_EICARTestFileMissed is the negative
// counterpart: the same EICAR test-file download, but fixture
// evidence shows the gateway allowed it through -- the file-protection
// gap a domain-04 test exists to surface.
func TestMalwareFileScenario_EICARTestFileMissed(t *testing.T) {
	now := time.Now()
	exp := HTTPExpectation{
		RequestURL:     "https://malware-test.example/eicar-test-file.com",
		URLCategory:    "eicar-test-file",
		ExpectedAction: ExpectedBlock,
		ControlProduct: "cloudflare-gateway",
	}
	provider := NewFixtureGatewayProvider([]GatewayEvidence{
		{RequestURL: exp.RequestURL, Action: "allow", Category: "eicar-test-file", Timestamp: now, Source: SourceFixture},
	})
	window := TimeWindow{Start: now.Add(-time.Minute), End: now.Add(time.Minute)}
	result := VerifyHTTPExpectation(exp, HTTPObservation{}, provider, window)

	if result.Prevention.Verdict != VerdictFail {
		t.Errorf("Prevention.Verdict = %q, want %q -- negative case: the EICAR test-file download was missed", result.Prevention.Verdict, VerdictFail)
	}
}

// TestDNSPolicyScenario_C2DomainBlocked proves a known-good baseline
// for domain 07 (DNS, covert channels and C2 protection): a query to a
// known command-and-control domain is declared expected to be blocked
// by the gateway's own DNS policy, and fixture evidence confirms it
// was.
func TestDNSPolicyScenario_C2DomainBlocked(t *testing.T) {
	now := time.Now()
	exp := DNSQueryExpectation{
		QueryDomain:    "c2-beacon.example",
		ThreatCategory: "c2-dns",
		ExpectedAction: ExpectedBlock,
		ControlProduct: "cloudflare-gateway",
		Note:           "known command-and-control beacon domain, resolved via the gateway's own DNS policy",
	}
	provider := NewFixtureDNSResolutionProvider([]DNSResolutionEvidence{
		{QueryDomain: exp.QueryDomain, Action: "block", ThreatCategory: "c2-dns", Timestamp: now, Source: SourceFixture},
	})
	window := TimeWindow{Start: now.Add(-time.Minute), End: now.Add(time.Minute)}
	result := VerifyDNSQueryExpectation(exp, provider, window)

	if result.Verdict != VerdictPass {
		t.Errorf("Verdict = %q, want %q -- known-good baseline: the C2 domain query was blocked", result.Verdict, VerdictPass)
	}
}

// TestDNSPolicyScenario_C2DomainMissed is the negative counterpart:
// the same C2 domain query, but fixture evidence shows the gateway's
// DNS policy allowed it through -- the policy gap a domain-07 test
// exists to surface.
func TestDNSPolicyScenario_C2DomainMissed(t *testing.T) {
	now := time.Now()
	exp := DNSQueryExpectation{
		QueryDomain:    "c2-beacon.example",
		ThreatCategory: "c2-dns",
		ExpectedAction: ExpectedBlock,
		ControlProduct: "cloudflare-gateway",
	}
	provider := NewFixtureDNSResolutionProvider([]DNSResolutionEvidence{
		{QueryDomain: exp.QueryDomain, Action: "allow", ThreatCategory: "c2-dns", Timestamp: now, Source: SourceFixture},
	})
	window := TimeWindow{Start: now.Add(-time.Minute), End: now.Add(time.Minute)}
	result := VerifyDNSQueryExpectation(exp, provider, window)

	if result.Verdict != VerdictFail {
		t.Errorf("Verdict = %q, want %q -- negative case: the C2 domain query was missed", result.Verdict, VerdictFail)
	}
}

// TestCoverageReportingScenario_AudspectWebGWCoverage_CitesDenominatorAndExclusions
// proves Phase 5's coverage-reporting exit criterion end-to-end
// against Audspect's real, shipped coverage data -- not a synthetic
// CoverageReport built only for this test. As of this round, all 12
// webGW.txt domains have at least one fixture-backed, proven scenario
// -- this is explicitly NOT a claim that any domain's full breadth is
// built out, per CoverageStatus's own documented meaning (01-12 each
// still have unbuilt sub-capabilities named in the spec's §5 table).
func TestCoverageReportingScenario_AudspectWebGWCoverage_CitesDenominatorAndExclusions(t *testing.T) {
	report, err := AudspectWebGWCoverageReport()
	if err != nil {
		t.Fatalf("AudspectWebGWCoverageReport: %v", err)
	}

	if got := report.Denominator(); got != 12 {
		t.Errorf("Denominator() = %d, want 12 -- webGW.txt defines exactly 12 domains", got)
	}
	if got := report.CoveredCount(); got != 12 {
		t.Errorf("CoveredCount() = %d, want 12 -- all 12 domains now have at least one proven scenario", got)
	}
	if got := report.NotCoveredCount(); got != 0 {
		t.Errorf("NotCoveredCount() = %d, want 0", got)
	}
	if got := report.ExcludedCount(); got != 0 {
		t.Errorf("ExcludedCount() = %d, want 0 -- no domain has been permanently excluded from this initiative", got)
	}

	summary := report.Summary()
	if !strings.Contains(summary, "12/12") {
		t.Errorf("Summary() = %q, want it to contain the covered count alongside the denominator (\"12/12\"), never a bare percentage", summary)
	}
}

// TestMutationTestingScenario_MalwareCategoryPolicy_CatchesWeakenedPolicyAndConfirmsRecovery
// proves Phase 5's mandated mutation-testing exit criterion end-to-end:
// deliberately weaken the malware-category block policy (domain 01's
// own known-good baseline, TestURLPolicyScenario_MalwareCategoryBlocked),
// confirm RunMutationTest catches the regression, restore the policy,
// confirm recovery -- using real VerifyHTTPExpectation calls against
// real fixture providers in every one of the three phases, never
// synthetic VerdictDetail literals.
func TestMutationTestingScenario_MalwareCategoryPolicy_CatchesWeakenedPolicyAndConfirmsRecovery(t *testing.T) {
	now := time.Now()
	window := TimeWindow{Start: now.Add(-time.Minute), End: now.Add(time.Minute)}
	exp := HTTPExpectation{
		RequestURL:     "https://malware-distribution.example/payload.exe",
		URLCategory:    "malware",
		ExpectedAction: ExpectedBlock,
		ControlProduct: "cloudflare-gateway",
	}

	runWithObservedAction := func(action string) func() VerdictDetail {
		return func() VerdictDetail {
			provider := NewFixtureGatewayProvider([]GatewayEvidence{
				{RequestURL: exp.RequestURL, Action: action, Category: "malware", Timestamp: now, Source: SourceFixture},
			})
			return VerifyHTTPExpectation(exp, HTTPObservation{}, provider, window).Prevention
		}
	}

	result := RunMutationTest(
		"malware-category-block-policy",
		runWithObservedAction("block"), // baseline: policy correctly blocks
		runWithObservedAction("allow"), // mutated: policy deliberately weakened to allow
		runWithObservedAction("block"), // restored: policy reverted to its original state
	)

	if !result.CaughtRegression {
		t.Errorf("CaughtRegression = false, want true -- the weakened malware-category policy must be caught")
	}
	if !result.RecoveryConfirmed {
		t.Errorf("RecoveryConfirmed = false, want true -- reverting the policy must restore the original Pass verdict")
	}
}

// TestPolicyCorrectnessScenario_CloudflareRealResponseShape_FlowsThroughExistingPipeline
// proves Phase 2b's narrowed exit criterion end-to-end: a Cloudflare
// Gateway rule's real, documented response shape -- built from this
// package's own CloudflareGatewayPolicyProvider against an httptest
// server standing in for Cloudflare's live API -- flows correctly
// through Phase 3's existing, unmodified VerifyPolicyBaselineExpectation
// pipeline and resolves to a genuine Pass. Per the spec's Phase 2b
// amendment, per-request attack-resistance evidence remains unavailable
// on the free tier (Logpush is Enterprise-only; Log Explorer has no free
// tier), so this is a policy-CONFIGURATION-correctness proof, not a
// per-request one -- the scope this phase actually ships.
func TestPolicyCorrectnessScenario_CloudflareRealResponseShape_FlowsThroughExistingPipeline(t *testing.T) {
	rule := cloudflareGatewayRule{
		ID:      "block-malware-category",
		Name:    "Block malware category",
		Action:  "block",
		Filters: []string{"http"},
		Traffic: `http.request.uri.category == "malware"`,
		Enabled: true,
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"success": true,
			"errors":  []any{},
			"result": map[string]any{
				"id":      rule.ID,
				"name":    rule.Name,
				"action":  rule.Action,
				"filters": rule.Filters,
				"traffic": rule.Traffic,
				"enabled": rule.Enabled,
			},
		})
	}))
	defer server.Close()

	provider := NewCloudflareGatewayPolicyProvider(http.DefaultClient, server.URL, "test-account", "test-token")
	now := time.Now()
	window := TimeWindow{Start: now.Add(-time.Minute), End: now.Add(time.Minute)}

	exp := PolicyBaselineExpectation{
		PolicyRuleID:       rule.ID,
		ExpectedConfigHash: configHashFor(rule),
		ControlProduct:     "cloudflare-gateway",
	}

	result := VerifyPolicyBaselineExpectation(exp, provider, window, now)

	if result.Verdict != VerdictPass {
		t.Errorf("Verdict = %q, want %q -- Cloudflare's real documented response shape must flow correctly through the existing policy-baseline pipeline", result.Verdict, VerdictPass)
	}
}
