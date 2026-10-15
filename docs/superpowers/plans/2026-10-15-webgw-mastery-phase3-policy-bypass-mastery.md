# Web Gateway BAS Mastery Phase 3 (Policy and Bypass Mastery) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extend `internal/webgwefficacy` with fail-open/fail-closed behavior verification, policy configuration drift and exception-expiry detection, and cross-control attack-chain composition — plus prove proxy-bypass (domain 08) and SaaS/CASB tenant-distinction (domain 06) scenarios end-to-end against Phase 1's existing pipeline, same as Phase 2a did for URL policy and identity-scoped policy.

**Architecture:** Two of the four domains in this phase's scope (proxy bypass, SaaS/CASB) need no new types at all — `HTTPExpectation`/`GatewayEvidence`/`VerifyHTTPExpectation` already model "a specific request, an expected action, evidence of what actually happened," which is exactly what a bypass attempt or a personal-tenant SaaS access attempt is. The other two (fail-open/fail-closed, configuration drift) are genuinely new because they are claims about *system state over time*, not about a single request, so each gets its own expectation/evidence/verdict triplet mirroring Phase 2a's `tls.go` shape. Cross-control attack-chain composition is new because it's the first capability that combines multiple already-computed verdicts into one chain-level finding, rather than computing a verdict from evidence directly.

**Tech Stack:** Go standard library only — no new dependency, no live vendor integration (still deferred, Phase 2b, tracked in `docs/webgw-mastery-qa-log.md`).

**Spec:** `docs/superpowers/specs/2026-10-15-webgw-mastery-architecture-design.md` §3 Phase 3 ("exceptions and policy shadowing, proxy bypass and alternate protocols, fail-open/fail-closed behavior, SaaS/CASB controls, configuration drift, and the first cross-control attack chains"). Exit criteria: each addition includes both a known-good baseline and a negative test; at least one fail-open scenario and one policy-drift scenario execute end-to-end with evidence-backed verdicts.

## Global Constraints

- `internal/webgwefficacy`'s production code still imports zero other Audspect package — unchanged since Phase 1. Verify with `go list -deps ./internal/webgwefficacy/...` after every task; exactly one `github.com/audspect/bas/...` entry (itself).
- The 5-state `WebGWVerdict` is reused as-is for every new verdict this plan produces — never a new or narrower verdict type, including `ComposeAttackChain`'s chain-level verdict.
- Every function that reads "as of now" state (specifically `VerifyPolicyBaselineExpectation`'s exception-expiry check) takes an explicit `asOf time.Time` parameter rather than calling `time.Now()` internally, so it stays deterministic and testable — same discipline the rest of this package already follows by threading `TimeWindow` explicitly rather than reading the clock.
- Every new evidence provider added this phase checks its own error before inspecting returned records (matching `VerifyHTTPExpectation`'s and `CorrelateWithSIEM`'s established pattern from Phases 1-2a).
- No live vendor integration anywhere in this plan — every provider is fixture-backed.

## Review Focus

1. **An expired exception that is still active in the evidence** must flag `Fail` even when the underlying configuration hash otherwise matches — the exception's own expiry, not just the hash, is the thing being checked. Pinned in Task 3.
2. **An exception that has not yet expired being active** must NOT be flagged as drift — the asymmetric companion to item 1, proving the expiry check only fires after the deadline. Pinned in Task 3.
3. **`ComposeAttackChain` with an empty step list** must resolve to `NotApplicable`, never silently defaulting to `Pass` or `Fail`. Pinned in Task 4.
4. **`ComposeAttackChain` with a `Pass` step alongside an `Inconclusive` step** must resolve to `Pass` — a control that held breaks the chain even when some other step's evidence happens to be missing; `Pass` takes precedence over `Inconclusive`, never the reverse. Pinned in Task 4.
5. **Both new providers' (`FailureModeEvidenceProvider`, `PolicyConfigEvidenceProvider`) error-with-records case.** The error must be checked first, matching the established pattern — records returned alongside an error must never be inspected. Pinned in Tasks 2 and 3.

---

### Task 1: Proxy-bypass and SaaS/CASB scenarios

**Files:**
- Modify: `orchestrator/internal/webgwefficacy/scenarios_test.go` (append)

**Interfaces:**
- Consumes: `HTTPExpectation`, `HTTPObservation`, `TimeWindow`, `ExpectedBlock`, `VerdictPass`, `VerdictFail` (Phase 1); `NewFixtureGatewayProvider` (Phase 1); `VerifyHTTPExpectation` (Phase 1).
- Produces: nothing new — four named scenario tests (two known-good/negative pairs) proving two of Phase 3's domains against Phase 1's existing, unmodified API.

- [ ] **Step 1: Append the four scenario tests**

```go
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
```

- [ ] **Step 2: Run the tests to verify they pass**

Run: `cd orchestrator && go test ./internal/webgwefficacy/... -run "TestProxyBypassScenario|TestCASBScenario" -v`
Expected: PASS, all 4, against Phase 1's existing, unmodified code (no production code in this task — same shape as Phase 2a's Task 1).

- [ ] **Step 3: Commit**

```bash
cd orchestrator
git add internal/webgwefficacy/scenarios_test.go
git commit -m "test(webgwefficacy): prove proxy-bypass and SaaS/CASB scenarios end-to-end"
```

---

### Task 2: Fail-open/fail-closed behavior

**Files:**
- Create: `orchestrator/internal/webgwefficacy/failuremode.go`
- Test: `orchestrator/internal/webgwefficacy/failuremode_test.go`

**Interfaces:**
- Consumes: `TimeWindow`, `VerdictDetail`, `VerdictPass`, `VerdictFail`, `VerdictInconclusive`, `EvidenceSource`, `SourceFixture` (Phase 1); `inWindow` (Phase 1, `providers.go`).
- Produces: `ExpectedFailureBehavior` (string type + `ExpectedFailClosed`, `ExpectedFailOpen` constants), `FailureModeExpectation{ScenarioLabel, ExpectedBehavior, ControlProduct, Note}`, `FailureModeEvidence{ScenarioLabel, ObservedBehavior, Timestamp, Source}`, `FailureModeEvidenceProvider` interface (`FailureModeEvidenceFor(scenarioLabel string, window TimeWindow) ([]FailureModeEvidence, error)`), `FixtureFailureModeProvider` + `NewFixtureFailureModeProvider(events []FailureModeEvidence) *FixtureFailureModeProvider`, `VerifyFailureModeExpectation(exp FailureModeExpectation, provider FailureModeEvidenceProvider, window TimeWindow) VerdictDetail` — Task 4 calls this directly.

- [ ] **Step 1: Write the failing tests**

```go
package webgwefficacy

import (
	"errors"
	"testing"
	"time"
)

type erroringFailureModeProvider struct {
	err     error
	records []FailureModeEvidence
}

func (p erroringFailureModeProvider) FailureModeEvidenceFor(scenarioLabel string, window TimeWindow) ([]FailureModeEvidence, error) {
	return p.records, p.err
}

func TestFixtureFailureModeProvider_FiltersByScenarioAndWindow(t *testing.T) {
	now := time.Date(2026, 10, 15, 10, 0, 0, 0, time.UTC)
	provider := NewFixtureFailureModeProvider([]FailureModeEvidence{
		{ScenarioLabel: "gateway-outage-datacenter-failover", ObservedBehavior: ExpectedFailClosed, Timestamp: now, Source: SourceFixture},
		{ScenarioLabel: "other-scenario", ObservedBehavior: ExpectedFailClosed, Timestamp: now, Source: SourceFixture},
	})
	got, err := provider.FailureModeEvidenceFor("gateway-outage-datacenter-failover", TimeWindow{Start: now.Add(-time.Minute), End: now.Add(time.Minute)})
	if err != nil {
		t.Fatalf("FailureModeEvidenceFor: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %+v, want exactly one matching record", got)
	}
}

func TestVerifyFailureModeExpectation_FailClosedKnownGood_Pass(t *testing.T) {
	now := time.Now()
	exp := FailureModeExpectation{ScenarioLabel: "gateway-outage-datacenter-failover", ExpectedBehavior: ExpectedFailClosed}
	provider := NewFixtureFailureModeProvider([]FailureModeEvidence{
		{ScenarioLabel: exp.ScenarioLabel, ObservedBehavior: ExpectedFailClosed, Timestamp: now, Source: SourceFixture},
	})
	result := VerifyFailureModeExpectation(exp, provider, TimeWindow{Start: now.Add(-time.Minute), End: now.Add(time.Minute)})

	if result.Verdict != VerdictPass {
		t.Errorf("Verdict = %q, want %q -- known-good baseline: the gateway failed closed as expected", result.Verdict, VerdictPass)
	}
}

// TestVerifyFailureModeExpectation_UnexpectedFailOpen_Fail is the
// negative case this capability exists to catch: a gateway declared
// expected to fail closed instead failed open during an outage --
// Phase 3's required fail-open exit-criterion scenario.
func TestVerifyFailureModeExpectation_UnexpectedFailOpen_Fail(t *testing.T) {
	now := time.Now()
	exp := FailureModeExpectation{ScenarioLabel: "gateway-outage-datacenter-failover", ExpectedBehavior: ExpectedFailClosed}
	provider := NewFixtureFailureModeProvider([]FailureModeEvidence{
		{ScenarioLabel: exp.ScenarioLabel, ObservedBehavior: ExpectedFailOpen, Timestamp: now, Source: SourceFixture},
	})
	result := VerifyFailureModeExpectation(exp, provider, TimeWindow{Start: now.Add(-time.Minute), End: now.Add(time.Minute)})

	if result.Verdict != VerdictFail {
		t.Errorf("Verdict = %q, want %q -- the gateway failed open during an outage when it was expected to fail closed", result.Verdict, VerdictFail)
	}
}

func TestVerifyFailureModeExpectation_NoEvidence_Inconclusive(t *testing.T) {
	exp := FailureModeExpectation{ScenarioLabel: "gateway-outage-datacenter-failover", ExpectedBehavior: ExpectedFailClosed}
	provider := NewFixtureFailureModeProvider(nil)
	result := VerifyFailureModeExpectation(exp, provider, TimeWindow{Start: time.Now().Add(-time.Hour), End: time.Now().Add(time.Hour)})

	if result.Verdict != VerdictInconclusive {
		t.Errorf("Verdict = %q, want %q", result.Verdict, VerdictInconclusive)
	}
}

func TestVerifyFailureModeExpectation_ProviderError_Inconclusive(t *testing.T) {
	exp := FailureModeExpectation{ScenarioLabel: "gateway-outage-datacenter-failover", ExpectedBehavior: ExpectedFailClosed}
	provider := erroringFailureModeProvider{err: errors.New("outage telemetry unreachable")}
	result := VerifyFailureModeExpectation(exp, provider, TimeWindow{})

	if result.Verdict != VerdictInconclusive {
		t.Errorf("Verdict = %q, want %q", result.Verdict, VerdictInconclusive)
	}
}

func TestVerifyFailureModeExpectation_ProviderErrorWithRecords_RecordsIgnored(t *testing.T) {
	exp := FailureModeExpectation{ScenarioLabel: "gateway-outage-datacenter-failover", ExpectedBehavior: ExpectedFailClosed}
	provider := erroringFailureModeProvider{
		err:     errors.New("outage telemetry unreachable"),
		records: []FailureModeEvidence{{ScenarioLabel: exp.ScenarioLabel, ObservedBehavior: ExpectedFailClosed, Timestamp: time.Now()}},
	}
	result := VerifyFailureModeExpectation(exp, provider, TimeWindow{})

	if result.Verdict != VerdictInconclusive {
		t.Errorf("Verdict = %q, want %q -- a provider error must be checked before its records are ever inspected", result.Verdict, VerdictInconclusive)
	}
}

func TestVerifyFailureModeExpectation_MultipleRecords_MostRecentWins(t *testing.T) {
	older := time.Now().Add(-time.Hour)
	newer := time.Now()
	exp := FailureModeExpectation{ScenarioLabel: "gateway-outage-datacenter-failover", ExpectedBehavior: ExpectedFailClosed}
	provider := NewFixtureFailureModeProvider([]FailureModeEvidence{
		{ScenarioLabel: exp.ScenarioLabel, ObservedBehavior: ExpectedFailOpen, Timestamp: older, Source: SourceFixture},
		{ScenarioLabel: exp.ScenarioLabel, ObservedBehavior: ExpectedFailClosed, Timestamp: newer, Source: SourceFixture},
	})
	result := VerifyFailureModeExpectation(exp, provider, TimeWindow{Start: older.Add(-time.Minute), End: newer.Add(time.Minute)})

	if result.Verdict != VerdictPass {
		t.Errorf("Verdict = %q, want %q -- the most recent record (fail-closed) must win over the stale earlier one (fail-open)", result.Verdict, VerdictPass)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/webgwefficacy/... -run "TestFixtureFailureModeProvider|TestVerifyFailureModeExpectation" -v`
Expected: FAIL — `undefined: NewFixtureFailureModeProvider` (and related types/functions).

- [ ] **Step 3: Write the implementation**

```go
package webgwefficacy

import (
	"fmt"
	"time"
)

// ExpectedFailureBehavior is what a gateway deployment was declared
// to be expected to do for its OWN traffic when the gateway service
// itself becomes unreachable -- a system-level claim, never a
// per-request policy decision.
type ExpectedFailureBehavior string

const (
	ExpectedFailClosed ExpectedFailureBehavior = "fail-closed"
	ExpectedFailOpen   ExpectedFailureBehavior = "fail-open"
)

// FailureModeExpectation is a declared "when this gateway becomes
// unreachable, traffic should fail open/closed" claim for one named
// outage scenario.
type FailureModeExpectation struct {
	ScenarioLabel    string                  `json:"scenarioLabel"`
	ExpectedBehavior ExpectedFailureBehavior `json:"expectedBehavior"`
	ControlProduct   string                  `json:"controlProduct"`
	Note             string                  `json:"note,omitempty"`
}

// FailureModeEvidence is one normalized record of what a gateway
// deployment actually did during a specific outage scenario.
type FailureModeEvidence struct {
	ScenarioLabel    string                  `json:"scenarioLabel"`
	ObservedBehavior ExpectedFailureBehavior `json:"observedBehavior"`
	Timestamp        time.Time               `json:"timestamp"`
	Source           EvidenceSource          `json:"source"`
}

// FailureModeEvidenceProvider supplies failure-mode evidence for a
// named outage scenario and time window.
type FailureModeEvidenceProvider interface {
	FailureModeEvidenceFor(scenarioLabel string, window TimeWindow) ([]FailureModeEvidence, error)
}

// FixtureFailureModeProvider wraps an in-memory slice of hand-built
// FailureModeEvidence values -- no real outage is induced in this
// phase.
type FixtureFailureModeProvider struct {
	events []FailureModeEvidence
}

func NewFixtureFailureModeProvider(events []FailureModeEvidence) *FixtureFailureModeProvider {
	return &FixtureFailureModeProvider{events: events}
}

func (p *FixtureFailureModeProvider) FailureModeEvidenceFor(scenarioLabel string, window TimeWindow) ([]FailureModeEvidence, error) {
	var out []FailureModeEvidence
	for _, e := range p.events {
		if e.ScenarioLabel != scenarioLabel {
			continue
		}
		if !inWindow(e.Timestamp, window) {
			continue
		}
		out = append(out, e)
	}
	return out, nil
}

// VerifyFailureModeExpectation checks one declared failure-mode
// expectation against evidence. Never infers fail-open/fail-closed
// from an absence of evidence -- an outage that produced no evidence
// is Inconclusive, not a pass.
func VerifyFailureModeExpectation(
	exp FailureModeExpectation,
	provider FailureModeEvidenceProvider,
	window TimeWindow,
) VerdictDetail {
	records, err := provider.FailureModeEvidenceFor(exp.ScenarioLabel, window)
	if err != nil {
		return VerdictDetail{Verdict: VerdictInconclusive, Reason: fmt.Sprintf("failure-mode evidence collection failed: %v", err)}
	}
	if len(records) == 0 {
		return VerdictDetail{
			Verdict: VerdictInconclusive,
			Reason:  "no failure-mode evidence found for this outage scenario in the window",
		}
	}
	latest := records[0]
	for _, r := range records {
		if r.Timestamp.After(latest.Timestamp) {
			latest = r
		}
	}
	if latest.ObservedBehavior == exp.ExpectedBehavior {
		return VerdictDetail{Verdict: VerdictPass}
	}
	return VerdictDetail{
		Verdict: VerdictFail,
		Reason:  fmt.Sprintf("observed failure behavior %q did not match expected %q", latest.ObservedBehavior, exp.ExpectedBehavior),
	}
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/webgwefficacy/... -v`
Expected: PASS, every test from Tasks 1-2 plus the existing suite.

- [ ] **Step 5: Commit**

```bash
cd orchestrator
git add internal/webgwefficacy/failuremode.go internal/webgwefficacy/failuremode_test.go
git commit -m "feat(webgwefficacy): add fail-open/fail-closed behavior verification"
```

---

### Task 3: Policy configuration drift and exception expiry

**Files:**
- Create: `orchestrator/internal/webgwefficacy/drift.go`
- Test: `orchestrator/internal/webgwefficacy/drift_test.go`

**Interfaces:**
- Consumes: `TimeWindow`, `VerdictDetail`, `VerdictPass`, `VerdictFail`, `VerdictInconclusive`, `EvidenceSource`, `SourceFixture` (Phase 1); `inWindow` (Phase 1, `providers.go`).
- Produces: `PolicyBaselineExpectation{PolicyRuleID, ExpectedConfigHash, ExceptionExpiresAt *time.Time, ControlProduct, Note}`, `PolicyConfigEvidence{PolicyRuleID, ObservedConfigHash, StillActive, Timestamp, Source}`, `PolicyConfigEvidenceProvider` interface (`PolicyConfigEvidenceFor(policyRuleID string, window TimeWindow) ([]PolicyConfigEvidence, error)`), `FixturePolicyConfigProvider` + `NewFixturePolicyConfigProvider(events []PolicyConfigEvidence) *FixturePolicyConfigProvider`, `VerifyPolicyBaselineExpectation(exp PolicyBaselineExpectation, provider PolicyConfigEvidenceProvider, window TimeWindow, asOf time.Time) VerdictDetail` — Task 4 does not consume this directly but could in a later phase; signature is final for this plan.

- [ ] **Step 1: Write the failing tests**

```go
package webgwefficacy

import (
	"errors"
	"testing"
	"time"
)

type erroringPolicyConfigProvider struct {
	err     error
	records []PolicyConfigEvidence
}

func (p erroringPolicyConfigProvider) PolicyConfigEvidenceFor(policyRuleID string, window TimeWindow) ([]PolicyConfigEvidence, error) {
	return p.records, p.err
}

func TestFixturePolicyConfigProvider_FiltersByRuleAndWindow(t *testing.T) {
	now := time.Date(2026, 10, 15, 10, 0, 0, 0, time.UTC)
	provider := NewFixturePolicyConfigProvider([]PolicyConfigEvidence{
		{PolicyRuleID: "block-malware-category", ObservedConfigHash: "abc123", Timestamp: now, Source: SourceFixture},
		{PolicyRuleID: "other-rule", ObservedConfigHash: "zzz999", Timestamp: now, Source: SourceFixture},
	})
	got, err := provider.PolicyConfigEvidenceFor("block-malware-category", TimeWindow{Start: now.Add(-time.Minute), End: now.Add(time.Minute)})
	if err != nil {
		t.Fatalf("PolicyConfigEvidenceFor: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %+v, want exactly one matching record", got)
	}
}

func TestVerifyPolicyBaselineExpectation_HashMatches_Pass(t *testing.T) {
	now := time.Now()
	exp := PolicyBaselineExpectation{PolicyRuleID: "block-malware-category", ExpectedConfigHash: "abc123"}
	provider := NewFixturePolicyConfigProvider([]PolicyConfigEvidence{
		{PolicyRuleID: exp.PolicyRuleID, ObservedConfigHash: "abc123", Timestamp: now, Source: SourceFixture},
	})
	result := VerifyPolicyBaselineExpectation(exp, provider, TimeWindow{Start: now.Add(-time.Minute), End: now.Add(time.Minute)}, now)

	if result.Verdict != VerdictPass {
		t.Errorf("Verdict = %q, want %q -- known-good baseline: configuration matches", result.Verdict, VerdictPass)
	}
}

func TestVerifyPolicyBaselineExpectation_HashMismatch_Fail(t *testing.T) {
	now := time.Now()
	exp := PolicyBaselineExpectation{PolicyRuleID: "block-malware-category", ExpectedConfigHash: "abc123"}
	provider := NewFixturePolicyConfigProvider([]PolicyConfigEvidence{
		{PolicyRuleID: exp.PolicyRuleID, ObservedConfigHash: "drifted456", Timestamp: now, Source: SourceFixture},
	})
	result := VerifyPolicyBaselineExpectation(exp, provider, TimeWindow{Start: now.Add(-time.Minute), End: now.Add(time.Minute)}, now)

	if result.Verdict != VerdictFail {
		t.Errorf("Verdict = %q, want %q -- negative case: the observed configuration drifted from baseline", result.Verdict, VerdictFail)
	}
}

// TestVerifyPolicyBaselineExpectation_ExpiredExceptionStillActive_Fail
// is Phase 3's required policy-drift exit-criterion scenario: a
// temporary exception past its own declared expiry, but still live
// in the gateway's configuration.
func TestVerifyPolicyBaselineExpectation_ExpiredExceptionStillActive_Fail(t *testing.T) {
	now := time.Now()
	expiredAt := now.Add(-24 * time.Hour)
	exp := PolicyBaselineExpectation{PolicyRuleID: "temp-exception-vendor-x", ExpectedConfigHash: "abc123", ExceptionExpiresAt: &expiredAt}
	provider := NewFixturePolicyConfigProvider([]PolicyConfigEvidence{
		{PolicyRuleID: exp.PolicyRuleID, ObservedConfigHash: "abc123", StillActive: true, Timestamp: now, Source: SourceFixture},
	})
	result := VerifyPolicyBaselineExpectation(exp, provider, TimeWindow{Start: now.Add(-time.Minute), End: now.Add(time.Minute)}, now)

	if result.Verdict != VerdictFail {
		t.Errorf("Verdict = %q, want %q -- an expired exception still active in the gateway is configuration drift, even though the config hash matches", result.Verdict, VerdictFail)
	}
}

// TestVerifyPolicyBaselineExpectation_UnexpiredExceptionStillActive_Pass
// confirms the drift check only fires after expiry -- an exception
// that is still within its declared window being active is correct
// behavior, not drift.
func TestVerifyPolicyBaselineExpectation_UnexpiredExceptionStillActive_Pass(t *testing.T) {
	now := time.Now()
	notYetExpired := now.Add(24 * time.Hour)
	exp := PolicyBaselineExpectation{PolicyRuleID: "temp-exception-vendor-x", ExpectedConfigHash: "abc123", ExceptionExpiresAt: &notYetExpired}
	provider := NewFixturePolicyConfigProvider([]PolicyConfigEvidence{
		{PolicyRuleID: exp.PolicyRuleID, ObservedConfigHash: "abc123", StillActive: true, Timestamp: now, Source: SourceFixture},
	})
	result := VerifyPolicyBaselineExpectation(exp, provider, TimeWindow{Start: now.Add(-time.Minute), End: now.Add(time.Minute)}, now)

	if result.Verdict != VerdictPass {
		t.Errorf("Verdict = %q, want %q -- the exception has not expired yet, so it being active is correct, not drift", result.Verdict, VerdictPass)
	}
}

func TestVerifyPolicyBaselineExpectation_NoEvidence_Inconclusive(t *testing.T) {
	exp := PolicyBaselineExpectation{PolicyRuleID: "block-malware-category", ExpectedConfigHash: "abc123"}
	provider := NewFixturePolicyConfigProvider(nil)
	now := time.Now()
	result := VerifyPolicyBaselineExpectation(exp, provider, TimeWindow{Start: now.Add(-time.Hour), End: now.Add(time.Hour)}, now)

	if result.Verdict != VerdictInconclusive {
		t.Errorf("Verdict = %q, want %q", result.Verdict, VerdictInconclusive)
	}
}

func TestVerifyPolicyBaselineExpectation_ProviderError_Inconclusive(t *testing.T) {
	exp := PolicyBaselineExpectation{PolicyRuleID: "block-malware-category", ExpectedConfigHash: "abc123"}
	provider := erroringPolicyConfigProvider{err: errors.New("configuration API unreachable")}
	result := VerifyPolicyBaselineExpectation(exp, provider, TimeWindow{}, time.Now())

	if result.Verdict != VerdictInconclusive {
		t.Errorf("Verdict = %q, want %q", result.Verdict, VerdictInconclusive)
	}
}

func TestVerifyPolicyBaselineExpectation_ProviderErrorWithRecords_RecordsIgnored(t *testing.T) {
	exp := PolicyBaselineExpectation{PolicyRuleID: "block-malware-category", ExpectedConfigHash: "abc123"}
	provider := erroringPolicyConfigProvider{
		err:     errors.New("configuration API unreachable"),
		records: []PolicyConfigEvidence{{PolicyRuleID: exp.PolicyRuleID, ObservedConfigHash: "abc123", Timestamp: time.Now()}},
	}
	result := VerifyPolicyBaselineExpectation(exp, provider, TimeWindow{}, time.Now())

	if result.Verdict != VerdictInconclusive {
		t.Errorf("Verdict = %q, want %q -- a provider error must be checked before its records are ever inspected", result.Verdict, VerdictInconclusive)
	}
}

func TestVerifyPolicyBaselineExpectation_MultipleRecords_MostRecentWins(t *testing.T) {
	older := time.Now().Add(-time.Hour)
	newer := time.Now()
	exp := PolicyBaselineExpectation{PolicyRuleID: "block-malware-category", ExpectedConfigHash: "abc123"}
	provider := NewFixturePolicyConfigProvider([]PolicyConfigEvidence{
		{PolicyRuleID: exp.PolicyRuleID, ObservedConfigHash: "drifted456", Timestamp: older, Source: SourceFixture},
		{PolicyRuleID: exp.PolicyRuleID, ObservedConfigHash: "abc123", Timestamp: newer, Source: SourceFixture},
	})
	result := VerifyPolicyBaselineExpectation(exp, provider, TimeWindow{Start: older.Add(-time.Minute), End: newer.Add(time.Minute)}, newer)

	if result.Verdict != VerdictPass {
		t.Errorf("Verdict = %q, want %q -- the most recent record (matching hash) must win over the stale earlier one (drifted)", result.Verdict, VerdictPass)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/webgwefficacy/... -run "TestFixturePolicyConfigProvider|TestVerifyPolicyBaselineExpectation" -v`
Expected: FAIL — `undefined: NewFixturePolicyConfigProvider` (and related types/functions).

- [ ] **Step 3: Write the implementation**

```go
package webgwefficacy

import (
	"fmt"
	"time"
)

// PolicyBaselineExpectation is a declared "this policy rule's
// configuration, and whether any time-boxed exception on it, should
// look like this" claim -- a claim about configuration STATE over
// time, never a per-request decision.
type PolicyBaselineExpectation struct {
	PolicyRuleID       string     `json:"policyRuleId"`
	ExpectedConfigHash string     `json:"expectedConfigHash"`
	ExceptionExpiresAt *time.Time `json:"exceptionExpiresAt,omitempty"`
	ControlProduct     string     `json:"controlProduct"`
	Note               string     `json:"note,omitempty"`
}

// PolicyConfigEvidence is one normalized record of a policy rule's
// actually-observed configuration state.
type PolicyConfigEvidence struct {
	PolicyRuleID       string         `json:"policyRuleId"`
	ObservedConfigHash string         `json:"observedConfigHash"`
	StillActive        bool           `json:"stillActive"`
	Timestamp          time.Time      `json:"timestamp"`
	Source             EvidenceSource `json:"source"`
}

// PolicyConfigEvidenceProvider supplies policy-configuration evidence
// for a policy rule ID and time window.
type PolicyConfigEvidenceProvider interface {
	PolicyConfigEvidenceFor(policyRuleID string, window TimeWindow) ([]PolicyConfigEvidence, error)
}

// FixturePolicyConfigProvider wraps an in-memory slice of hand-built
// PolicyConfigEvidence values -- no real configuration-management API
// is called in this phase.
type FixturePolicyConfigProvider struct {
	events []PolicyConfigEvidence
}

func NewFixturePolicyConfigProvider(events []PolicyConfigEvidence) *FixturePolicyConfigProvider {
	return &FixturePolicyConfigProvider{events: events}
}

func (p *FixturePolicyConfigProvider) PolicyConfigEvidenceFor(policyRuleID string, window TimeWindow) ([]PolicyConfigEvidence, error) {
	var out []PolicyConfigEvidence
	for _, e := range p.events {
		if e.PolicyRuleID != policyRuleID {
			continue
		}
		if !inWindow(e.Timestamp, window) {
			continue
		}
		out = append(out, e)
	}
	return out, nil
}

// VerifyPolicyBaselineExpectation checks one declared policy-baseline
// expectation against evidence, as of asOf. An expired exception
// (ExceptionExpiresAt before asOf) that is still active in the
// evidence is configuration drift, flagged as Fail regardless of
// whether the underlying config hash otherwise matches -- a stale
// exception left live past its expiry is itself the finding, not
// something a hash comparison would catch. asOf is an explicit
// parameter, never time.Now() read internally, so this function
// stays deterministic and testable.
func VerifyPolicyBaselineExpectation(
	exp PolicyBaselineExpectation,
	provider PolicyConfigEvidenceProvider,
	window TimeWindow,
	asOf time.Time,
) VerdictDetail {
	records, err := provider.PolicyConfigEvidenceFor(exp.PolicyRuleID, window)
	if err != nil {
		return VerdictDetail{Verdict: VerdictInconclusive, Reason: fmt.Sprintf("policy configuration evidence collection failed: %v", err)}
	}
	if len(records) == 0 {
		return VerdictDetail{
			Verdict: VerdictInconclusive,
			Reason:  "no policy configuration evidence found for this rule in the window",
		}
	}
	latest := records[0]
	for _, r := range records {
		if r.Timestamp.After(latest.Timestamp) {
			latest = r
		}
	}
	if exp.ExceptionExpiresAt != nil && asOf.After(*exp.ExceptionExpiresAt) && latest.StillActive {
		return VerdictDetail{
			Verdict: VerdictFail,
			Reason:  fmt.Sprintf("exception on policy rule %q expired at %s but is still active in the gateway's own configuration", exp.PolicyRuleID, exp.ExceptionExpiresAt.Format(time.RFC3339)),
		}
	}
	if latest.ObservedConfigHash != exp.ExpectedConfigHash {
		return VerdictDetail{
			Verdict: VerdictFail,
			Reason:  fmt.Sprintf("observed configuration hash %q did not match expected %q", latest.ObservedConfigHash, exp.ExpectedConfigHash),
		}
	}
	return VerdictDetail{Verdict: VerdictPass}
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/webgwefficacy/... -v`
Expected: PASS, every test from Tasks 1-3 plus the existing suite.

- [ ] **Step 5: Commit**

```bash
cd orchestrator
git add internal/webgwefficacy/drift.go internal/webgwefficacy/drift_test.go
git commit -m "feat(webgwefficacy): add policy configuration drift and exception-expiry detection"
```

---

### Task 4: Cross-control attack-chain composition

**Files:**
- Create: `orchestrator/internal/webgwefficacy/chain.go`
- Test: `orchestrator/internal/webgwefficacy/chain_test.go`

**Interfaces:**
- Consumes: `VerdictDetail`, `WebGWVerdict`, `VerdictPass`, `VerdictFail`, `VerdictInconclusive`, `VerdictUnsupported`, `VerdictNotApplicable` (Phase 1); `HTTPExpectation`, `HTTPObservation`, `TimeWindow`, `ExpectedBlock`, `NewFixtureGatewayProvider`, `VerifyHTTPExpectation` (Phase 1, for the real-world composition test only); `FailureModeExpectation`, `ExpectedFailClosed`, `ExpectedFailOpen`, `NewFixtureFailureModeProvider`, `VerifyFailureModeExpectation` (Task 2, for the real-world composition test only).
- Produces: `AttackChainStep{Label, Result}`, `AttackChainResult{ChainLabel, Steps, OverallVerdict}`, `ComposeAttackChain(chainLabel string, steps []AttackChainStep) AttackChainResult` — this is this plan's terminal capability; later phases call it to compose whatever steps they build.

- [ ] **Step 1: Write the failing tests**

```go
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/webgwefficacy/... -run TestComposeAttackChain -v`
Expected: FAIL — `undefined: ComposeAttackChain` (and `AttackChainStep`).

- [ ] **Step 3: Write the implementation**

```go
package webgwefficacy

// AttackChainStep is one step's own already-computed verdict,
// labeled for reporting -- ComposeAttackChain never recomputes a
// step's verdict itself, it only combines verdicts callers already
// derived from VerifyHTTPExpectation, VerifyTLSInspectionExpectation,
// VerifyFailureModeExpectation, or VerifyPolicyBaselineExpectation.
type AttackChainStep struct {
	Label  string        `json:"label"`
	Result VerdictDetail `json:"result"`
}

// AttackChainResult composes several independently-verified steps
// into one chain-level finding.
type AttackChainResult struct {
	ChainLabel     string            `json:"chainLabel"`
	Steps          []AttackChainStep `json:"steps"`
	OverallVerdict WebGWVerdict      `json:"overallVerdict"`
}

// ComposeAttackChain combines each step's own verdict into one
// chain-level verdict representing whether the organization's
// controls, collectively, stopped this kill chain. A single step
// whose control held (Pass) breaks the chain -- the attacker's
// objective requires every step to succeed, so one blocked step is
// enough to defeat the whole chain, regardless of any other step's
// status. Only when every step's control failed (Fail) does the
// chain succeed for the attacker, the worst finding. A step with no
// evidence (Inconclusive/Unsupported) that isn't overridden by an
// actual Pass elsewhere in the chain leaves the overall result
// Inconclusive -- missing evidence is never read as the chain having
// succeeded.
func ComposeAttackChain(chainLabel string, steps []AttackChainStep) AttackChainResult {
	result := AttackChainResult{ChainLabel: chainLabel, Steps: steps}
	if len(steps) == 0 {
		result.OverallVerdict = VerdictNotApplicable
		return result
	}
	anyPass := false
	anyInconclusive := false
	for _, s := range steps {
		switch s.Result.Verdict {
		case VerdictPass:
			anyPass = true
		case VerdictInconclusive, VerdictUnsupported:
			anyInconclusive = true
		}
	}
	switch {
	case anyPass:
		result.OverallVerdict = VerdictPass
	case anyInconclusive:
		result.OverallVerdict = VerdictInconclusive
	default:
		result.OverallVerdict = VerdictFail
	}
	return result
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/webgwefficacy/... -v`
Expected: PASS, every test from Tasks 1-4 plus the existing suite.

- [ ] **Step 5: Verify the zero-import-dependency constraint**

Run: `cd orchestrator && go list -deps ./internal/webgwefficacy/... | grep "audspect/bas"`
Expected: exactly one line, `github.com/audspect/bas/internal/webgwefficacy` itself.

- [ ] **Step 6: Commit**

```bash
cd orchestrator
git add internal/webgwefficacy/chain.go internal/webgwefficacy/chain_test.go
git commit -m "feat(webgwefficacy): add cross-control attack-chain composition"
```

---

## Execution Handoff

Per the user's explicit instruction, this plan proceeds directly to Native inline execution without a separate approval checkpoint.
