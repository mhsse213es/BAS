# Web Gateway BAS Mastery Domain 07 (DNS, Covert Channels and C2 Protection) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close domain 07's exit criterion for this round -- at least one known-good scenario (a C2/malicious-domain query correctly blocked by the gateway's own DNS policy) and one negative counterpart execute end-to-end against a fixture-backed `DNSResolutionEvidenceProvider` -- and keep `AudspectWebGWCoverageReport()` in sync with that change.

**Architecture:** One new leaf file in `internal/webgwefficacy`, `dns.go`, mirroring `tls.go`'s exact shape (a DNS resolution is a different protocol from HTTP -- no URL, no TLS to inspect -- the same reasoning that gave TLS inspection its own file rather than overloading `HTTPExpectation`). Two scenario tests prove the exit criterion against the real, unmodified verdict pipeline. A final small task flips domain 07 from `CoverageNotCovered` to `CoverageCovered` in the one place that claim is made, and updates the existing coverage-report scenario test's asserted numbers to match.

**Tech Stack:** Go standard library only (`fmt`, `time`) -- no new dependency, continuing Phase 1-5's zero-dependency discipline.

**Spec:** `docs/superpowers/specs/2026-10-15-webgw-mastery-architecture-design.md`, "Post-Phase-5 domain closure: Domain 07 (DNS, covert channels and C2 protection)", committed directly beneath Phase 5's own section, and §5's domain-07 table row (updated in the same commit).

## Global Constraints

- `internal/webgwefficacy`'s production code still imports zero other `github.com/audspect/bas/...` package -- unchanged since Phase 1. Verify with `go list -deps ./internal/webgwefficacy/...` after Task 1; exactly one `github.com/audspect/bas/...` entry (itself).
- `DNSResolutionEvidence.Action` is compared against `exp.ExpectedAction` case-sensitively, with no normalization -- matching `VerifyHTTPExpectation`'s own established discipline (`TestVerifyHTTPExpectation_ActionCaseMismatch_TreatedAsMismatchNotNormalized`). An action-case mismatch is a real mismatch, never silently normalized away.
- No evidence found in the requested window returns `VerdictInconclusive`, never an assumed `Pass` or `Fail` -- the same discipline every other `Verify...` function in this package already follows (`tls.go`, `drift.go`, `siem.go`).
- Most-recent-by-timestamp wins when multiple records exist, via the existing shared `latestByTimestamp[T any]` helper (`providers.go`) -- no new sorting/selection logic is written.
- `AudspectWebGWCoverageReport()` (`coverage.go`) must stay in sync with §5's own table -- a divergence between the two is a defect in whichever one is stale, per the spec's own living-document rule.

## Review Focus

1. **A DNS query with no resolution evidence at all in the requested window.** `VerifyDNSQueryExpectation` must return `VerdictInconclusive`, never an assumed `Pass` -- absence of evidence is not proof the gateway's DNS policy ran correctly, the same principle `tls.go`'s own `NoEvidence_Inconclusive` test already pins for TLS inspection. Pinned in Task 1.
2. **The evidence provider itself returns an error** (a collection failure, not a legitimate "nothing found"). `VerifyDNSQueryExpectation` must return `VerdictInconclusive` with a reason citing the error, matching every other `Verify...` function's provider-error handling in this package. Pinned in Task 1.
3. **An action-case mismatch** (e.g. evidence records `"Block"` but the expectation declares `ExpectedBlock`, which stringifies to `"block"`). Must resolve to `VerdictFail`, not `VerdictPass` -- a silent case-insensitive match would let a logging/formatting quirk in a real vendor's evidence mask an actual policy gap. Pinned in Task 1.
4. **Multiple resolution-evidence records for the same domain in the window, out of timestamp order.** The most recent one must win, not the first one in the slice or the one with the "best" (most reassuring) action -- matching `tls.go`'s own `MultipleRecords_MostRecentWins` test exactly. Pinned in Task 1.
5. **`AudspectWebGWCoverageReport()`'s asserted counts going stale the moment domain 07 flips.** The existing `TestCoverageReportingScenario_AudspectWebGWCoverage_CitesDenominatorAndExclusions` test hardcodes `10`/`12`/`2` and the exact substring `"domains 04 and 07 remain unbuilt"` -- if Task 3 updates `coverage.go` without updating this test's assertions in the same commit, the suite will not catch the mismatch on its own (the test would simply start failing, which is the intended signal, but the fix must land together, not as an afterthought). Pinned in Task 3.

---

### Task 1: DNS resolution policy verification

**Files:**
- Create: `orchestrator/internal/webgwefficacy/dns.go`
- Test: `orchestrator/internal/webgwefficacy/dns_test.go`

**Interfaces:**
- Consumes: `ExpectedGatewayAction` (`ExpectedAllow`/`ExpectedBlock`), `EvidenceSource`, `TimeWindow`, `VerdictDetail`, `VerdictPass`/`VerdictFail`/`VerdictInconclusive` (`types.go`, Phase 1, unmodified); `latestByTimestamp[T any](records []T, ts func(T) time.Time) T` (`providers.go`, unmodified); `inWindow(t time.Time, window TimeWindow) bool` (`providers.go`, unmodified).
- Produces: `DNSQueryExpectation{QueryDomain, ThreatCategory, ExpectedAction ExpectedGatewayAction, ControlProduct, Note}`, `DNSResolutionEvidence{QueryDomain, Action string, ThreatCategory, Timestamp time.Time, Source EvidenceSource}`, `DNSResolutionEvidenceProvider` interface (`DNSResolutionEvidenceFor(queryDomain string, window TimeWindow) ([]DNSResolutionEvidence, error)`), `FixtureDNSResolutionProvider` + `NewFixtureDNSResolutionProvider(events []DNSResolutionEvidence) *FixtureDNSResolutionProvider`, `VerifyDNSQueryExpectation(exp DNSQueryExpectation, provider DNSResolutionEvidenceProvider, window TimeWindow) VerdictDetail` -- Task 2's scenario tests call `DNSQueryExpectation`, `DNSResolutionEvidence`, `NewFixtureDNSResolutionProvider`, and `VerifyDNSQueryExpectation` directly; their exact field names and signatures are final for this plan.

- [ ] **Step 1: Write the failing tests**

```go
package webgwefficacy

import (
	"errors"
	"testing"
	"time"
)

type erroringDNSProvider struct{ err error }

func (p erroringDNSProvider) DNSResolutionEvidenceFor(queryDomain string, window TimeWindow) ([]DNSResolutionEvidence, error) {
	return nil, p.err
}

func TestFixtureDNSResolutionProvider_FiltersByDomainAndWindow(t *testing.T) {
	now := time.Date(2026, 10, 15, 10, 0, 0, 0, time.UTC)
	provider := NewFixtureDNSResolutionProvider([]DNSResolutionEvidence{
		{QueryDomain: "c2-beacon.example", Action: "block", Timestamp: now, Source: SourceFixture},
		{QueryDomain: "other.example", Action: "block", Timestamp: now, Source: SourceFixture},
	})
	got, err := provider.DNSResolutionEvidenceFor("c2-beacon.example", TimeWindow{Start: now.Add(-time.Minute), End: now.Add(time.Minute)})
	if err != nil {
		t.Fatalf("DNSResolutionEvidenceFor: %v", err)
	}
	if len(got) != 1 || got[0].Action != "block" {
		t.Fatalf("got %+v, want exactly one blocked record for the matching domain", got)
	}
}

func TestFixtureDNSResolutionProvider_OutsideWindowExcluded(t *testing.T) {
	now := time.Date(2026, 10, 15, 10, 0, 0, 0, time.UTC)
	provider := NewFixtureDNSResolutionProvider([]DNSResolutionEvidence{
		{QueryDomain: "c2-beacon.example", Action: "block", Timestamp: now, Source: SourceFixture},
	})
	got, err := provider.DNSResolutionEvidenceFor("c2-beacon.example", TimeWindow{Start: now.Add(time.Hour), End: now.Add(2 * time.Hour)})
	if err != nil {
		t.Fatalf("DNSResolutionEvidenceFor: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("got %+v, want empty -- outside the requested window", got)
	}
}

func TestVerifyDNSQueryExpectation_ActionMatchesExpectation_Pass(t *testing.T) {
	now := time.Now()
	exp := DNSQueryExpectation{QueryDomain: "c2-beacon.example", ThreatCategory: "c2-dns", ExpectedAction: ExpectedBlock, ControlProduct: "cloudflare-gateway"}
	provider := NewFixtureDNSResolutionProvider([]DNSResolutionEvidence{
		{QueryDomain: exp.QueryDomain, Action: "block", ThreatCategory: "c2-dns", Timestamp: now, Source: SourceFixture},
	})
	result := VerifyDNSQueryExpectation(exp, provider, TimeWindow{Start: now.Add(-time.Minute), End: now.Add(time.Minute)})

	if result.Verdict != VerdictPass {
		t.Errorf("Verdict = %q, want %q", result.Verdict, VerdictPass)
	}
}

func TestVerifyDNSQueryExpectation_ActionMismatch_Fail(t *testing.T) {
	now := time.Now()
	exp := DNSQueryExpectation{QueryDomain: "c2-beacon.example", ThreatCategory: "c2-dns", ExpectedAction: ExpectedBlock, ControlProduct: "cloudflare-gateway"}
	provider := NewFixtureDNSResolutionProvider([]DNSResolutionEvidence{
		{QueryDomain: exp.QueryDomain, Action: "allow", ThreatCategory: "c2-dns", Timestamp: now, Source: SourceFixture},
	})
	result := VerifyDNSQueryExpectation(exp, provider, TimeWindow{Start: now.Add(-time.Minute), End: now.Add(time.Minute)})

	if result.Verdict != VerdictFail {
		t.Errorf("Verdict = %q, want %q -- expected block but evidence shows the query was allowed through", result.Verdict, VerdictFail)
	}
}

func TestVerifyDNSQueryExpectation_ActionCaseMismatch_TreatedAsMismatchNotNormalized(t *testing.T) {
	now := time.Now()
	exp := DNSQueryExpectation{QueryDomain: "c2-beacon.example", ExpectedAction: ExpectedBlock}
	provider := NewFixtureDNSResolutionProvider([]DNSResolutionEvidence{
		{QueryDomain: exp.QueryDomain, Action: "Block", Timestamp: now, Source: SourceFixture},
	})
	result := VerifyDNSQueryExpectation(exp, provider, TimeWindow{Start: now.Add(-time.Minute), End: now.Add(time.Minute)})

	if result.Verdict != VerdictFail {
		t.Errorf("Verdict = %q, want %q -- \"Block\" must not be silently normalized to match \"block\"", result.Verdict, VerdictFail)
	}
}

func TestVerifyDNSQueryExpectation_NoEvidence_Inconclusive(t *testing.T) {
	exp := DNSQueryExpectation{QueryDomain: "c2-beacon.example", ExpectedAction: ExpectedBlock}
	provider := NewFixtureDNSResolutionProvider(nil)
	result := VerifyDNSQueryExpectation(exp, provider, TimeWindow{Start: time.Now().Add(-time.Hour), End: time.Now().Add(time.Hour)})

	if result.Verdict != VerdictInconclusive {
		t.Errorf("Verdict = %q, want %q -- absence of evidence is not proof the gateway's DNS policy ran", result.Verdict, VerdictInconclusive)
	}
}

func TestVerifyDNSQueryExpectation_ProviderError_Inconclusive(t *testing.T) {
	exp := DNSQueryExpectation{QueryDomain: "c2-beacon.example", ExpectedAction: ExpectedBlock}
	provider := erroringDNSProvider{err: errors.New("DNS log store unreachable")}
	result := VerifyDNSQueryExpectation(exp, provider, TimeWindow{})

	if result.Verdict != VerdictInconclusive {
		t.Errorf("Verdict = %q, want %q", result.Verdict, VerdictInconclusive)
	}
}

func TestVerifyDNSQueryExpectation_MultipleRecords_MostRecentWins(t *testing.T) {
	older := time.Now().Add(-time.Hour)
	newer := time.Now()
	exp := DNSQueryExpectation{QueryDomain: "c2-beacon.example", ExpectedAction: ExpectedBlock}
	provider := NewFixtureDNSResolutionProvider([]DNSResolutionEvidence{
		{QueryDomain: exp.QueryDomain, Action: "allow", Timestamp: older, Source: SourceFixture},
		{QueryDomain: exp.QueryDomain, Action: "block", Timestamp: newer, Source: SourceFixture},
	})
	result := VerifyDNSQueryExpectation(exp, provider, TimeWindow{Start: older.Add(-time.Minute), End: newer.Add(time.Minute)})

	if result.Verdict != VerdictPass {
		t.Errorf("Verdict = %q, want %q -- the most recent record (blocked) must win over the stale earlier one (allowed)", result.Verdict, VerdictPass)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/webgwefficacy/... -run "TestFixtureDNSResolutionProvider|TestVerifyDNSQueryExpectation" -v`
Expected: FAIL -- `undefined: NewFixtureDNSResolutionProvider` (and related symbols).

- [ ] **Step 3: Write the implementation**

```go
package webgwefficacy

import (
	"fmt"
	"time"
)

// DNSQueryExpectation is a declared "this domain's resolution should
// be blocked/allowed by the gateway's own DNS policy" claim -- domain
// 07's own axis, structurally distinct from HTTPExpectation's
// allow/block policy action: a DNS resolution has no URL and no TLS
// to inspect, the same reasoning that gave TLS inspection its own
// TLSInspectionExpectation rather than overloading HTTPExpectation.
type DNSQueryExpectation struct {
	QueryDomain    string                `json:"queryDomain"`
	ThreatCategory string                `json:"threatCategory,omitempty"`
	ExpectedAction ExpectedGatewayAction `json:"expectedAction"`
	ControlProduct string                `json:"controlProduct"`
	Note           string                `json:"note,omitempty"`
}

// DNSResolutionEvidence is one normalized record of how the gateway's
// own DNS policy actually resolved a specific domain. Action is a
// plain string (e.g. "block"/"allow") compared case-sensitively
// against DNSQueryExpectation.ExpectedAction -- matching
// VerifyHTTPExpectation's own established discipline that an
// action-case mismatch is a real mismatch, never silently normalized
// away.
type DNSResolutionEvidence struct {
	QueryDomain    string         `json:"queryDomain"`
	Action         string         `json:"action"`
	ThreatCategory string         `json:"threatCategory,omitempty"`
	Timestamp      time.Time      `json:"timestamp"`
	Source         EvidenceSource `json:"source"`
}

// DNSResolutionEvidenceProvider supplies DNS-resolution-policy
// evidence for a queried domain and time window. A returned error
// means collection failed -- distinct from a successful search that
// found nothing.
type DNSResolutionEvidenceProvider interface {
	DNSResolutionEvidenceFor(queryDomain string, window TimeWindow) ([]DNSResolutionEvidence, error)
}

// FixtureDNSResolutionProvider wraps an in-memory slice of hand-built
// DNSResolutionEvidence values -- no real DNS resolver log is queried
// in this phase.
type FixtureDNSResolutionProvider struct {
	events []DNSResolutionEvidence
}

func NewFixtureDNSResolutionProvider(events []DNSResolutionEvidence) *FixtureDNSResolutionProvider {
	return &FixtureDNSResolutionProvider{events: events}
}

func (p *FixtureDNSResolutionProvider) DNSResolutionEvidenceFor(queryDomain string, window TimeWindow) ([]DNSResolutionEvidence, error) {
	var out []DNSResolutionEvidence
	for _, e := range p.events {
		if e.QueryDomain != queryDomain {
			continue
		}
		if !inWindow(e.Timestamp, window) {
			continue
		}
		out = append(out, e)
	}
	return out, nil
}

// VerifyDNSQueryExpectation checks one declared DNS-query expectation
// against evidence. No evidence in the window is Inconclusive, never
// an assumed Pass or Fail -- the same discipline every other
// Verify... function in this package already follows.
func VerifyDNSQueryExpectation(
	exp DNSQueryExpectation,
	provider DNSResolutionEvidenceProvider,
	window TimeWindow,
) VerdictDetail {
	records, err := provider.DNSResolutionEvidenceFor(exp.QueryDomain, window)
	if err != nil {
		return VerdictDetail{Verdict: VerdictInconclusive, Reason: fmt.Sprintf("DNS resolution evidence collection failed: %v", err)}
	}
	if len(records) == 0 {
		return VerdictDetail{
			Verdict: VerdictInconclusive,
			Reason:  "no DNS resolution evidence found for this domain in the window",
		}
	}
	latest := latestByTimestamp(records, func(e DNSResolutionEvidence) time.Time { return e.Timestamp })
	if latest.Action == string(exp.ExpectedAction) {
		return VerdictDetail{Verdict: VerdictPass}
	}
	return VerdictDetail{Verdict: VerdictFail, Reason: fmt.Sprintf("observed DNS resolution action %q did not match expected %q", latest.Action, exp.ExpectedAction)}
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/webgwefficacy/... -v`
Expected: PASS, every test in the package including Task 1's new ones.

- [ ] **Step 5: Verify the zero-import-dependency constraint still holds**

Run: `cd orchestrator && go list -deps ./internal/webgwefficacy/... | grep "audspect/bas"`
Expected: exactly one line, `github.com/audspect/bas/internal/webgwefficacy` itself.

- [ ] **Step 6: Commit**

```bash
cd orchestrator
git add internal/webgwefficacy/dns.go internal/webgwefficacy/dns_test.go
git commit -m "feat(webgwefficacy): add gateway-side DNS resolution policy verification -- domain 07

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

### Task 2: Known-good and negative DNS policy scenarios

**Files:**
- Modify: `orchestrator/internal/webgwefficacy/scenarios_test.go`

**Interfaces:**
- Consumes: `DNSQueryExpectation`, `DNSResolutionEvidence`, `NewFixtureDNSResolutionProvider`, `VerifyDNSQueryExpectation` (Task 1, `dns.go`).
- Produces: nothing new -- this task adds no production code. It proves domain 07's exit criterion end-to-end: one known-good scenario and one negative counterpart, matching the two-test pattern domains 06 and 08 already established in this same file.

- [ ] **Step 1: Write the scenario tests**

Append to `orchestrator/internal/webgwefficacy/scenarios_test.go`:

```go
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
```

- [ ] **Step 2: Run the tests to verify they pass**

Run: `cd orchestrator && go test ./internal/webgwefficacy/... -run TestDNSPolicyScenario -v`
Expected: PASS directly -- every piece these tests call already exists from Task 1; there is no new implementation to watch fail against. Confirm the compiler has no errors and both tests genuinely ran before proceeding.

- [ ] **Step 3: Run the full package suite**

Run: `cd orchestrator && go test ./internal/webgwefficacy/... -v`
Expected: PASS, every test from Task 1 and Task 2 plus the full existing suite.

- [ ] **Step 4: Commit**

```bash
cd orchestrator
git add internal/webgwefficacy/scenarios_test.go
git commit -m "test(webgwefficacy): prove the C2-domain DNS policy scenario end-to-end -- domain 07

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

### Task 3: Flip domain 07 to Covered in the coverage report

**Files:**
- Modify: `orchestrator/internal/webgwefficacy/coverage.go:126`
- Modify: `orchestrator/internal/webgwefficacy/scenarios_test.go` (the existing coverage-reporting scenario test)

**Interfaces:**
- Consumes: `AudspectWebGWCoverageReport`, `CoverageCovered` (`coverage.go`, Phase 5, unmodified except for this task's own one-line change).
- Produces: nothing new -- this task updates one existing line of production code and the one existing test whose assertions depend on it.

- [ ] **Step 1: Update the existing coverage-reporting test's assertions first (RED)**

In `orchestrator/internal/webgwefficacy/scenarios_test.go`, find `TestCoverageReportingScenario_AudspectWebGWCoverage_CitesDenominatorAndExclusions` and replace its body's assertions and doc comment to reflect domain 07 now being covered:

```go
// TestCoverageReportingScenario_AudspectWebGWCoverage_CitesDenominatorAndExclusions
// proves Phase 5's coverage-reporting exit criterion end-to-end
// against Audspect's real, shipped coverage data -- not a synthetic
// CoverageReport built only for this test. As of this round, 11 of
// the 12 webGW.txt domains have at least one fixture-backed, proven
// scenario (01, 02, 03, 05, 06, 07, 08, 09, 10, 11, 12); only domain 04
// (malware/file protection) remains not-yet-built, matching the
// spec's own §5 table.
func TestCoverageReportingScenario_AudspectWebGWCoverage_CitesDenominatorAndExclusions(t *testing.T) {
	report, err := AudspectWebGWCoverageReport()
	if err != nil {
		t.Fatalf("AudspectWebGWCoverageReport: %v", err)
	}

	if got := report.Denominator(); got != 12 {
		t.Errorf("Denominator() = %d, want 12 -- webGW.txt defines exactly 12 domains", got)
	}
	if got := report.CoveredCount(); got != 11 {
		t.Errorf("CoveredCount() = %d, want 11", got)
	}
	if got := report.NotCoveredCount(); got != 1 {
		t.Errorf("NotCoveredCount() = %d, want 1 -- only domain 04 remains unbuilt", got)
	}
	if got := report.ExcludedCount(); got != 0 {
		t.Errorf("ExcludedCount() = %d, want 0 -- no domain has been permanently excluded from this initiative", got)
	}

	summary := report.Summary()
	if !strings.Contains(summary, "11/12") {
		t.Errorf("Summary() = %q, want it to contain the covered count alongside the denominator (\"11/12\"), never a bare percentage", summary)
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd orchestrator && go test ./internal/webgwefficacy/... -run TestCoverageReportingScenario -v`
Expected: FAIL -- `CoveredCount() = 10, want 11` (and the other now-stale assertions), since `coverage.go` still has domain 07 as `CoverageNotCovered`.

- [ ] **Step 3: Flip domain 07 in `AudspectWebGWCoverageReport`**

In `orchestrator/internal/webgwefficacy/coverage.go`, change line 126:

```go
		{DomainID: "07", DomainName: "DNS/covert channels/C2 (gateway-side policy)", Status: CoverageNotCovered},
```

to:

```go
		{DomainID: "07", DomainName: "DNS/covert channels/C2 (gateway-side policy)", Status: CoverageCovered},
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd orchestrator && go test ./internal/webgwefficacy/... -v`
Expected: PASS, every test in the package, including the updated coverage-reporting scenario test.

- [ ] **Step 5: Commit**

```bash
cd orchestrator
git add internal/webgwefficacy/coverage.go internal/webgwefficacy/scenarios_test.go
git commit -m "feat(webgwefficacy): flip domain 07 to Covered in AudspectWebGWCoverageReport

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

## Execution Handoff

Plan complete and saved to `docs/superpowers/plans/2026-10-15-webgw-mastery-domain07-dns-policy.md`.

**Native** — I implement all 3 tasks myself in this session, then one fresh reviewer checks the whole branch at the end, matching this initiative's own established execution method (every task here is deterministic, in-memory, and zero-dependency, the same risk profile that already ran natively on every prior round).
