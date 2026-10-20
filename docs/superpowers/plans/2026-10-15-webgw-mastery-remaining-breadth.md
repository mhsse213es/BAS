# Web Gateway BAS Mastery — Remaining Breadth (Domains 04/07, RBI, Industry Profiles) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the four remaining items that were deliberately deferred across Phases 2a-4 as Goal-text beyond each phase's own binding Exit Criteria — not blocked by anything external, just out of each phase's minimal scope at the time. (1) Domain 04 (malware/exploit delivery/file protection). (2) Domain 07 (gateway-side DNS policy, distinct from `dnssink`'s data-exfiltration angle and from domain 08's content-filter-bypass angle). (3) RBI as India's second mapped regulator (`regulatory.go` already handles CERT-In). (4) Industry profiles (BFSI/NBFC, Healthcare, Manufacturing/OT-adjacent, MSP/shared-tenant) as pure configuration, never a second scoring system.

**Architecture:** Four independent deliverables, three of which need zero new types.
- **Domains 04 and 07 (Tasks 1-2):** both fit Phase 1's existing `HTTPExpectation`/`GatewayEvidence`/`VerifyHTTPExpectation` pipeline exactly, the same "reuse the pipeline, add no new types" pattern every prior domain-coverage addition in this package has used. Domain 04 uses the industry-standard EICAR antivirus test string (synthetic, universally safe, never real malware) as the file-level signal, distinct from domain 01's URL-category reputation block since EICAR detection requires inspecting the file's own content, not the URL's category. Domain 07 uses an alternate public DoH resolver (Quad9, distinct from domain 08's `dns.google` example) framed as a DNS-infrastructure-policy question (is any unauthorized external resolver reachable at all), distinct from domain 08's content-filter-bypass framing (did a specific URL category filter get evaded via DoH).
- **RBI (Task 3):** reuses `regulatory.go`'s existing `RegulatoryObligation`/`MapObligationToScenarioEvidence` unchanged. The citation (RBI Circular RBI/2015-16/418, "Cyber Security Framework in Banks," control NET-02 "Firewall and perimeter security," dated 2 June 2016) is independently verified this session against RBI's own primary source (`rbi.org.in`'s notification page) and is also already seeded in this repo's `internal/compliance/mappings/rbi_csf.yaml`. Mapped to the proxy-bypass scenario (domain 08), deliberately distinct from the existing CERT-In obligation's fail-closed mapping (domain 11), so India's two regulators are each independently evidenced rather than both resting on the same proof.
- **Industry profiles (Task 4):** the one genuinely new type in this plan. `IndustryProfile` is pure configuration — priorities, data classifications, business-impact weighting — and structurally cannot become a second scoring system because it has no method that returns a `WebGWVerdict` or `VerdictDetail`, and never will; this is a property to preserve, not test at runtime. `NewIndustryProfile` validates at construction time (mirroring `coverage.go`'s own discipline, closed out in the prior review) that every domain ID it references is one of Audspect's real, current 12 domains per `AudspectWebGWCoverageReport()` — never a fictional or stale reference.

**Tech Stack:** Go standard library only — no new dependency, no live vendor integration, same discipline as every prior phase.

**Spec:** `docs/superpowers/specs/2026-10-15-webgw-mastery-architecture-design.md` §1 (domain gap analysis), §3 Phase 3/4 (Goal text naming these items), §5 (Coverage Matrix). This plan closes out Goal-text items that were never bound by any phase's own Exit Criteria — there is no new exit criterion to satisfy here beyond "ship real, honestly-scoped coverage," matching this package's standing discipline throughout.

## Global Constraints

- `internal/webgwefficacy`'s production code still imports zero other `github.com/audspect/bas/...` package — unchanged since Phase 1. Verify with `go list -deps ./internal/webgwefficacy/...` after Task 4; exactly one `github.com/audspect/bas/...` entry (itself).
- Tasks 1 and 2 add zero new production code — both are pure scenario tests against Phase 1's existing, unmodified pipeline, each with a known-good baseline and a negative test per this package's own standing discipline.
- Task 3 adds zero new production code — reuses `regulatory.go`'s existing types and `MapObligationToScenarioEvidence` unchanged.
- No fabricated regulatory citations. The RBI circular's date (2 June 2016) was independently verified this session against `rbi.org.in`'s own notification page, not assumed.
- `IndustryProfile` never gains a method returning `WebGWVerdict` or `VerdictDetail` — the architecture spec's own explicit instruction that industry profiles are "never a second scoring system." This is enforced by never writing such a method, not by a runtime check.
- `NewIndustryProfile` validates every domain ID it's given against `AudspectWebGWCoverageReport()`'s real 12-domain set at construction time — the same "validate at construction, never at render time" discipline `coverage.go` already established.

## Review Focus

1. **Domain 04's EICAR scenario must be genuinely distinct from domain 01's URL-category block** — file-content/signature scanning, not URL reputation — and its doc comment must state the distinction honestly, not just assert a different domain number. Pinned in Task 1.
2. **Domain 07's alternate-resolver scenario must be genuinely distinct from domain 08's DoH-bypass scenario** — a DNS-infrastructure-policy question (is any unauthorized resolver reachable), not a content-filter-bypass question (did a URL category filter get evaded) — using a different resolver endpoint and category tag, not a copy with renamed labels. Pinned in Task 2.
3. **RBI's obligation must map to a different real scenario than the existing CERT-In obligation** (proxy-bypass/domain 08, not fail-closed/domain 11) so India's two regulators are each independently evidenced, never both resting on the same proof. Pinned in Task 3.
4. **`NewIndustryProfile` must reject any domain ID** (in `PriorityDomainIDs` or as a `BusinessImpactWeight` key) **that isn't one of the real 12 domains** in `AudspectWebGWCoverageReport()`'s current set — never a fictional or typo'd reference. Pinned in Task 4.
5. **Every one of the four shipped industry profiles must pass its own construction validation** (not just the generic constructor's unit tests) — a profile with a stale domain reference would otherwise ship silently. Pinned in Task 4.

---

### Task 1: Domain 04 — malware/file protection (EICAR scenario)

**Files:**
- Modify: `orchestrator/internal/webgwefficacy/scenarios_test.go` (append)

**Interfaces:**
- Consumes: `HTTPExpectation`, `HTTPObservation`, `TimeWindow`, `ExpectedBlock`, `VerdictPass`, `VerdictFail`, `NewFixtureGatewayProvider`, `GatewayEvidence`, `SourceFixture`, `VerifyHTTPExpectation` (all Phase 1, unmodified).
- Produces: nothing new.

- [ ] **Step 1: Append the known-good and negative scenario tests**

```go
// TestMalwareDownloadScenario_EICARTestFileBlocked proves a known-good
// baseline for domain 04 (malware/exploit delivery/file protection):
// a download request carrying the industry-standard EICAR antivirus
// test string (a synthetic, universally-safe test marker, never real
// malware) is declared expected to be blocked, and fixture evidence
// confirms the gateway's own file-level scanning caught it -- distinct
// from domain 01's URL-category reputation block, since EICAR
// detection requires inspecting the file's own content/signature, not
// just the URL's category.
func TestMalwareDownloadScenario_EICARTestFileBlocked(t *testing.T) {
	now := time.Now()
	exp := HTTPExpectation{
		RequestURL:     "https://file-scan-test.example/eicar.com.txt",
		URLCategory:    "malware-file-scan",
		ExpectedAction: ExpectedBlock,
		ControlProduct: "cloudflare-gateway",
		Note:           "EICAR standard antivirus test file -- synthetic, universally safe, never real malware",
	}
	provider := NewFixtureGatewayProvider([]GatewayEvidence{
		{RequestURL: exp.RequestURL, Action: "block", Category: "malware-file-scan", PolicyRule: "block-eicar-signature", Timestamp: now, Source: SourceFixture},
	})
	window := TimeWindow{Start: now.Add(-time.Minute), End: now.Add(time.Minute)}
	result := VerifyHTTPExpectation(exp, HTTPObservation{}, provider, window)

	if result.Prevention.Verdict != VerdictPass {
		t.Errorf("Prevention.Verdict = %q, want %q -- known-good baseline: the EICAR test file was caught by file-level scanning", result.Prevention.Verdict, VerdictPass)
	}
}

// TestMalwareDownloadScenario_EICARTestFileMissed is the negative
// counterpart: the same EICAR test download, but fixture evidence
// shows the gateway allowed it through -- the file-scanning gap this
// test exists to surface.
func TestMalwareDownloadScenario_EICARTestFileMissed(t *testing.T) {
	now := time.Now()
	exp := HTTPExpectation{
		RequestURL:     "https://file-scan-test.example/eicar.com.txt",
		URLCategory:    "malware-file-scan",
		ExpectedAction: ExpectedBlock,
		ControlProduct: "cloudflare-gateway",
	}
	provider := NewFixtureGatewayProvider([]GatewayEvidence{
		{RequestURL: exp.RequestURL, Action: "allow", Category: "malware-file-scan", Timestamp: now, Source: SourceFixture},
	})
	window := TimeWindow{Start: now.Add(-time.Minute), End: now.Add(time.Minute)}
	result := VerifyHTTPExpectation(exp, HTTPObservation{}, provider, window)

	if result.Prevention.Verdict != VerdictFail {
		t.Errorf("Prevention.Verdict = %q, want %q -- negative case: the EICAR test file was missed", result.Prevention.Verdict, VerdictFail)
	}
}
```

- [ ] **Step 2: Run the tests to verify they pass**

Run: `cd orchestrator && go test ./internal/webgwefficacy/... -run "TestMalwareDownloadScenario" -v`
Expected: PASS, both tests, against Phase 1's existing, unmodified code.

- [ ] **Step 3: Commit**

```bash
cd orchestrator
git add internal/webgwefficacy/scenarios_test.go
git commit -m "test(webgwefficacy): prove the EICAR malware-download scenario end-to-end -- domain 04"
```

---

### Task 2: Domain 07 — gateway-side DNS policy (alternate-resolver bypass)

**Files:**
- Modify: `orchestrator/internal/webgwefficacy/scenarios_test.go` (append)

**Interfaces:**
- Consumes: same as Task 1.
- Produces: nothing new.

- [ ] **Step 1: Append the known-good and negative scenario tests**

```go
// TestDNSPolicyScenario_AlternateResolverBlocked proves a known-good
// baseline for domain 07 (gateway-side DNS policy): a client
// attempting to resolve DNS via an unauthorized external DoH resolver
// (Quad9, distinct from domain 08's own dns.google bypass example) is
// declared expected to be blocked by the gateway's own DNS-policy
// enforcement -- a DNS-infrastructure control (is any external
// resolver reachable at all), distinct from domain 08's
// content-filter-bypass angle (did a specific URL category filter get
// evaded). Distinct from internal/dnssink, which validates
// DNS-tunneled data exfiltration (a data-movement-domain capability),
// never modified by this test.
func TestDNSPolicyScenario_AlternateResolverBlocked(t *testing.T) {
	now := time.Now()
	exp := HTTPExpectation{
		RequestURL:     "https://dns.quad9.net/dns-query",
		URLCategory:    "dns-policy-alternate-resolver",
		ExpectedAction: ExpectedBlock,
		ControlProduct: "cloudflare-gateway",
		Note:           "unauthorized external DoH resolver -- gateway-side DNS-infrastructure policy, not a content-filter-bypass case",
	}
	provider := NewFixtureGatewayProvider([]GatewayEvidence{
		{RequestURL: exp.RequestURL, Action: "block", Category: "dns-policy-alternate-resolver", PolicyRule: "block-unauthorized-dns-resolvers", Timestamp: now, Source: SourceFixture},
	})
	window := TimeWindow{Start: now.Add(-time.Minute), End: now.Add(time.Minute)}
	result := VerifyHTTPExpectation(exp, HTTPObservation{}, provider, window)

	if result.Prevention.Verdict != VerdictPass {
		t.Errorf("Prevention.Verdict = %q, want %q -- known-good baseline: the alternate resolver was blocked", result.Prevention.Verdict, VerdictPass)
	}
}

// TestDNSPolicyScenario_AlternateResolverMissed is the negative
// counterpart: the same alternate-resolver attempt, but fixture
// evidence shows the gateway allowed it through -- the DNS-policy gap
// this test exists to surface.
func TestDNSPolicyScenario_AlternateResolverMissed(t *testing.T) {
	now := time.Now()
	exp := HTTPExpectation{
		RequestURL:     "https://dns.quad9.net/dns-query",
		URLCategory:    "dns-policy-alternate-resolver",
		ExpectedAction: ExpectedBlock,
		ControlProduct: "cloudflare-gateway",
	}
	provider := NewFixtureGatewayProvider([]GatewayEvidence{
		{RequestURL: exp.RequestURL, Action: "allow", Category: "dns-policy-alternate-resolver", Timestamp: now, Source: SourceFixture},
	})
	window := TimeWindow{Start: now.Add(-time.Minute), End: now.Add(time.Minute)}
	result := VerifyHTTPExpectation(exp, HTTPObservation{}, provider, window)

	if result.Prevention.Verdict != VerdictFail {
		t.Errorf("Prevention.Verdict = %q, want %q -- negative case: the alternate resolver was missed", result.Prevention.Verdict, VerdictFail)
	}
}
```

- [ ] **Step 2: Run the tests to verify they pass**

Run: `cd orchestrator && go test ./internal/webgwefficacy/... -run "TestDNSPolicyScenario" -v`
Expected: PASS, both tests.

- [ ] **Step 3: Commit**

```bash
cd orchestrator
git add internal/webgwefficacy/scenarios_test.go
git commit -m "test(webgwefficacy): prove the gateway-side DNS-policy scenario end-to-end -- domain 07"
```

---

### Task 3: RBI as India's second mapped regulator

**Files:**
- Modify: `orchestrator/internal/webgwefficacy/regulatory_test.go` (append)

**Interfaces:**
- Consumes: `RegulatoryObligation`, `MapObligationToScenarioEvidence`, `ObligationSnapshotCaptured` (Phase 4, `regulatory.go`, unmodified); `HTTPExpectation`, `HTTPObservation`, `TimeWindow`, `ExpectedBlock`, `NewFixtureGatewayProvider`, `GatewayEvidence`, `SourceFixture`, `VerifyHTTPExpectation` (Phase 1, unmodified).
- Produces: nothing new.

- [ ] **Step 1: Append the RBI end-to-end test**

```go
// TestMapObligationToScenarioEvidence_RBICyberSecurityFramework_FirewallPerimeterSecurity
// maps domain 08 end-to-end for India's second regulator, the RBI
// Cyber Security Framework (Circular RBI/2015-16/418, "Cyber Security
// Framework in Banks," dated 2 June 2016 -- independently verified
// this session against rbi.org.in's own notification page -- control
// NET-02, "Firewall and perimeter security -- rules reviewed,
// inbound/outbound filtered," also seeded in
// internal/compliance/mappings/rbi_csf.yaml). Deliberately mapped to
// the proxy-bypass scenario (domain 08), distinct from the existing
// CERT-In obligation's fail-closed mapping (domain 11), so India's
// two regulators are each independently evidenced rather than both
// resting on the same proof.
func TestMapObligationToScenarioEvidence_RBICyberSecurityFramework_FirewallPerimeterSecurity(t *testing.T) {
	obligation := RegulatoryObligation{
		ID:              "rbi-csf-net-02",
		Jurisdiction:    "India",
		Regulator:       "RBI",
		Title:           "Firewall and perimeter security -- rules reviewed, inbound/outbound filtered",
		SourceReference: "RBI Circular RBI/2015-16/418 (DBS.CO/CSITE/BC.11/33.01.001/2015-16), \"Cyber Security Framework in Banks\"",
		Version:         "2016",
		EffectiveDate:   time.Date(2016, 6, 2, 0, 0, 0, 0, time.UTC),
		ControlLabel:    "webgwefficacy.proxybypass",
	}

	now := time.Now()
	window := TimeWindow{Start: now.Add(-time.Minute), End: now.Add(time.Minute)}
	exp := HTTPExpectation{RequestURL: "https://dns.google/dns-query", ExpectedAction: ExpectedBlock}
	provider := NewFixtureGatewayProvider([]GatewayEvidence{
		{RequestURL: exp.RequestURL, Action: "block", Timestamp: now, Source: SourceFixture},
	})
	result := VerifyHTTPExpectation(exp, HTTPObservation{}, provider, window)

	snapshot := MapObligationToScenarioEvidence(obligation, "doh-bypass-caught", result.Prevention.Verdict, now)

	if snapshot.Status != ObligationSnapshotCaptured {
		t.Errorf("Status = %q, want %q", snapshot.Status, ObligationSnapshotCaptured)
	}
	if snapshot.CapturedVerdict != VerdictPass {
		t.Errorf("CapturedVerdict = %q, want %q", snapshot.CapturedVerdict, VerdictPass)
	}
}
```

- [ ] **Step 2: Run the test to verify it passes**

Run: `cd orchestrator && go test ./internal/webgwefficacy/... -run "TestMapObligationToScenarioEvidence_RBI" -v`
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
cd orchestrator
git add internal/webgwefficacy/regulatory_test.go
git commit -m "test(webgwefficacy): add RBI as India's second mapped regulator, distinct from CERT-In's scenario"
```

---

### Task 4: Industry profiles — configuration only, never a second scoring system

**Files:**
- Create: `orchestrator/internal/webgwefficacy/industry.go`
- Test: `orchestrator/internal/webgwefficacy/industry_test.go`

**Interfaces:**
- Consumes: `AudspectWebGWCoverageReport` (Phase 5, `coverage.go`, unmodified) — used only to validate domain-ID references at construction time, never to compute a verdict.
- Produces: `IndustryProfile{Name, PriorityDomainIDs, DataClassifications, BusinessImpactWeight, Note}`, `NewIndustryProfile(name string, priorityDomainIDs []string, dataClassifications []string, businessImpactWeight map[string]float64, note string) (IndustryProfile, error)`, `BFSINBFCProfile() (IndustryProfile, error)`, `HealthcareProfile() (IndustryProfile, error)`, `ManufacturingOTProfile() (IndustryProfile, error)`, `MSPSharedTenantProfile() (IndustryProfile, error)` — this plan's terminal capability; no later task consumes it.

- [ ] **Step 1: Write the failing tests**

```go
package webgwefficacy

import "testing"

func TestNewIndustryProfile_UnknownPriorityDomainID_Errors(t *testing.T) {
	_, err := NewIndustryProfile("test", []string{"99"}, nil, nil, "")
	if err == nil {
		t.Fatal("NewIndustryProfile: want error for an unknown priority domain ID, got nil")
	}
}

func TestNewIndustryProfile_UnknownBusinessImpactWeightDomainID_Errors(t *testing.T) {
	_, err := NewIndustryProfile("test", nil, nil, map[string]float64{"99": 1.0}, "")
	if err == nil {
		t.Fatal("NewIndustryProfile: want error for an unknown business-impact-weight domain ID, got nil")
	}
}

func TestNewIndustryProfile_ValidDomainIDs_Succeeds(t *testing.T) {
	_, err := NewIndustryProfile("test", []string{"01", "02"}, []string{"PII"}, map[string]float64{"01": 1.0}, "note")
	if err != nil {
		t.Fatalf("NewIndustryProfile: %v", err)
	}
}

func TestBFSINBFCProfile_RealDomainReferences(t *testing.T) {
	profile, err := BFSINBFCProfile()
	if err != nil {
		t.Fatalf("BFSINBFCProfile: %v", err)
	}
	if len(profile.PriorityDomainIDs) == 0 {
		t.Error("PriorityDomainIDs is empty, want real domain references")
	}
}

func TestHealthcareProfile_RealDomainReferences(t *testing.T) {
	profile, err := HealthcareProfile()
	if err != nil {
		t.Fatalf("HealthcareProfile: %v", err)
	}
	if len(profile.PriorityDomainIDs) == 0 {
		t.Error("PriorityDomainIDs is empty, want real domain references")
	}
}

func TestManufacturingOTProfile_RealDomainReferences(t *testing.T) {
	profile, err := ManufacturingOTProfile()
	if err != nil {
		t.Fatalf("ManufacturingOTProfile: %v", err)
	}
	if len(profile.PriorityDomainIDs) == 0 {
		t.Error("PriorityDomainIDs is empty, want real domain references")
	}
}

func TestMSPSharedTenantProfile_RealDomainReferences(t *testing.T) {
	profile, err := MSPSharedTenantProfile()
	if err != nil {
		t.Fatalf("MSPSharedTenantProfile: %v", err)
	}
	if len(profile.PriorityDomainIDs) == 0 {
		t.Error("PriorityDomainIDs is empty, want real domain references")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/webgwefficacy/... -run "TestNewIndustryProfile|TestBFSINBFCProfile|TestHealthcareProfile|TestManufacturingOTProfile|TestMSPSharedTenantProfile" -v`
Expected: FAIL -- `undefined: NewIndustryProfile` (and related functions).

- [ ] **Step 3: Write the implementation**

```go
package webgwefficacy

import "fmt"

// IndustryProfile is pure configuration -- priorities, data
// classifications, and business-impact weighting layered onto this
// package's existing scenario library. It computes nothing and
// verifies nothing itself, and never gains a method returning a
// WebGWVerdict or VerdictDetail -- per the architecture spec's own
// explicit instruction, an industry profile is never a second scoring
// system. A caller applies a profile by reading its
// PriorityDomainIDs and DataClassifications when deciding which
// already-existing scenarios to run first, and BusinessImpactWeight
// when weighting an already-computed verdict's business impact.
type IndustryProfile struct {
	Name                 string             `json:"name"`
	PriorityDomainIDs    []string           `json:"priorityDomainIds"`
	DataClassifications  []string           `json:"dataClassifications"`
	BusinessImpactWeight map[string]float64 `json:"businessImpactWeight"`
	Note                 string             `json:"note,omitempty"`
}

// NewIndustryProfile validates at construction time that every
// domain ID this profile references -- in priorityDomainIDs and as
// businessImpactWeight keys -- is one of Audspect's real, current
// WebGW domains per AudspectWebGWCoverageReport's own 12-domain set,
// never a fictional or stale reference.
func NewIndustryProfile(
	name string,
	priorityDomainIDs []string,
	dataClassifications []string,
	businessImpactWeight map[string]float64,
	note string,
) (IndustryProfile, error) {
	report, err := AudspectWebGWCoverageReport()
	if err != nil {
		return IndustryProfile{}, fmt.Errorf("loading domain set: %w", err)
	}
	known := make(map[string]bool, len(report.domains))
	for _, d := range report.domains {
		known[d.DomainID] = true
	}
	for _, id := range priorityDomainIDs {
		if !known[id] {
			return IndustryProfile{}, fmt.Errorf("priority domain ID %q is not one of Audspect's real WebGW domains", id)
		}
	}
	for id := range businessImpactWeight {
		if !known[id] {
			return IndustryProfile{}, fmt.Errorf("business-impact-weight domain ID %q is not one of Audspect's real WebGW domains", id)
		}
	}
	return IndustryProfile{
		Name:                 name,
		PriorityDomainIDs:    priorityDomainIDs,
		DataClassifications:  dataClassifications,
		BusinessImpactWeight: businessImpactWeight,
		Note:                 note,
	}, nil
}

// BFSINBFCProfile returns the BFSI/NBFC industry profile. Financial
// data protection, strict configuration change control, and
// availability dominate; DLP (03), configuration drift (09), and
// availability/resilience (11) are prioritized -- matching
// RBI/CERT-In's own emphasis on data residency, encryption, and
// perimeter controls (see the real obligations mapped in
// regulatory_test.go).
func BFSINBFCProfile() (IndustryProfile, error) {
	return NewIndustryProfile(
		"BFSI/NBFC",
		[]string{"03", "09", "11"},
		[]string{"PII", "financial-transaction-data", "payment-card-data"},
		map[string]float64{"03": 1.0, "09": 0.8, "11": 0.9},
		"Financial-sector priorities: data loss prevention, configuration-drift control, and availability dominate.",
	)
}

// HealthcareProfile returns the Healthcare industry profile.
// Patient-data protection dominates: TLS inspection of PHI in transit
// (02), DLP (03), and CASB/shadow-IT detection for unauthorized SaaS
// carrying patient data (06) are prioritized.
func HealthcareProfile() (IndustryProfile, error) {
	return NewIndustryProfile(
		"Healthcare",
		[]string{"02", "03", "06"},
		[]string{"PHI", "PII"},
		map[string]float64{"02": 0.9, "03": 1.0, "06": 0.8},
		"Patient-data-protection priorities: TLS inspection of PHI in transit, DLP, and CASB dominate.",
	)
}

// ManufacturingOTProfile returns the Manufacturing/OT-adjacent
// industry profile. OT uptime dominates over confidentiality:
// availability/resilience (11), configuration drift (09), and
// egress-bypass control for unusual OT network patterns (08) are
// prioritized. This profile is configuration only, never a probe --
// the architecture spec's own safety contract already prohibits any
// active probing into OT-adjacent deployments without a
// separately-approved test design, and nothing in this profile
// initiates one.
func ManufacturingOTProfile() (IndustryProfile, error) {
	return NewIndustryProfile(
		"Manufacturing/OT-adjacent",
		[]string{"11", "09", "08"},
		[]string{"OT-telemetry", "industrial-control-data"},
		map[string]float64{"11": 1.0, "09": 0.7, "08": 0.6},
		"OT-uptime priorities: availability/resilience dominates over confidentiality.",
	)
}

// MSPSharedTenantProfile returns the MSP/shared-tenant industry
// profile. Tenant isolation dominates: CASB/tenant-isolation (06),
// identity-scoped per-client policy differentiation (05), and
// cross-control chains (12, since each client relationship must be
// proven separately) are prioritized.
func MSPSharedTenantProfile() (IndustryProfile, error) {
	return NewIndustryProfile(
		"MSP/shared-tenant",
		[]string{"06", "05", "12"},
		[]string{"multi-tenant-client-data"},
		map[string]float64{"06": 1.0, "05": 0.9, "12": 0.8},
		"Multi-tenant priorities: tenant isolation and per-client policy differentiation dominate.",
	)
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/webgwefficacy/... -v`
Expected: PASS, every existing test plus this task's 8 new tests, plus Tasks 1-3's 5 new tests (97 total).

- [ ] **Step 5: Verify the zero-import-dependency constraint**

Run: `cd orchestrator && go list -deps ./internal/webgwefficacy/... | grep "audspect/bas"`
Expected: exactly one line, `github.com/audspect/bas/internal/webgwefficacy` itself.

- [ ] **Step 6: Commit**

```bash
cd orchestrator
git add internal/webgwefficacy/industry.go internal/webgwefficacy/industry_test.go
git commit -m "feat(webgwefficacy): add industry profiles as pure configuration, never a second scoring system"
```

---

## Execution Handoff

Per the user's explicit instruction ("build all four"), this plan proceeds directly to Native inline execution without a separate approval checkpoint.
