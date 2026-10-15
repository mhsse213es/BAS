# Web Gateway BAS Mastery Phase 2a (Fixture-Backed First Vertical) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extend `internal/webgwefficacy` with TLS-inspection-visibility and SIEM-evidence-correlation capabilities, prove URL-policy and identity-scoped-policy scenarios end-to-end against Phase 1's existing pipeline, and prove the DLP-upload scenario end-to-end by driving a real HTTP upload attempt against `internal/cloudsink`'s synthetic endpoints — all fixture-backed, with the live Cloudflare Gateway adapter itself deferred as Phase 2b (blocked on account access; tracked in `docs/webgw-mastery-qa-log.md`).

**Architecture:** Two genuinely new capabilities (TLS inspection, SIEM correlation) are added to `internal/webgwefficacy` as new files, each mirroring Phase 1's expectation/evidence/verdict shape in miniature; `internal/webgwefficacy`'s own production code stays a zero-dependency leaf package exactly as Phase 1 locked it. The DLP-upload scenario is proved by a test-only file that imports `internal/cloudsink` and `internal/testutil` — a test file's imports never appear in a plain `go list -deps` of the package, so this does not violate that constraint. URL-policy and identity-scoped-policy scenarios need no new production code at all — Phase 1's `HTTPExpectation`/`GatewayEvidence`/`VerifyHTTPExpectation` already model exactly this; Phase 2a just proves it with named, realistic fixture scenarios.

**Tech Stack:** Go (standard library plus `internal/cloudsink`, `internal/testutil`, `github.com/jackc/pgx/v5/pgxpool` for Task 4's integration test only — none of this appears in the package's own non-test dependency graph).

**Spec:** `docs/superpowers/specs/2026-10-15-webgw-mastery-architecture-design.md` — this plan implements §3 Phase 2's goal, as revised by the 2026-10-15 amendment splitting Phase 2 into 2a (this plan, fixture-only) and 2b (deferred, live Cloudflare adapter). Executors should read both the spec and that amendment.

## Global Constraints

- `internal/webgwefficacy`'s own production code (non-test files) still imports no other Audspect package — unchanged from Phase 1. Verify with `go list -deps ./internal/webgwefficacy/...` after every task; it must show exactly one `github.com/audspect/bas/...` entry (itself). Task 4's test file importing `cloudsink`/`testutil` must NOT appear in this check (confirm separately that it doesn't).
- No live Cloudflare Gateway integration anywhere in this plan — every provider added here is fixture-backed, matching Phase 1's own discipline. The live adapter is Phase 2b, tracked in `docs/webgw-mastery-qa-log.md`, not this plan's job.
- The 5-state `WebGWVerdict` (pass/fail/inconclusive/unsupported/not-applicable) is reused as-is for every new verdict this plan produces (TLS inspection, SIEM-corroborated detection) — never a new or narrower verdict type.
- "Never infer successful TLS inspection merely because a request succeeded" (spec §2.3 condition #4, binding here too even though no live adapter exists yet): `VerifyTLSInspectionExpectation` must require explicit evidence, never infer from absence.
- "Never rely on one gateway log as sole proof of gateway behavior" (spec §4): `CorrelateWithSIEM` treats a missing independent SIEM record as `Inconclusive`, never silently leaves Detection at `Pass` unexamined.
- DLP validation uses only synthetic, non-sensitive markers and controlled destinations (spec §2.3 condition #5) — Task 4's payload is an obviously-fake string, never real-looking PII or financial data.
- Task 4 requires a running Docker Desktop (it starts a real `postgres:16-alpine` testcontainer via `internal/testutil.NewTestDB`) — check free memory before running it, per this project's standing convention for DB-backed test runs.

## Review Focus

1. **TLS inspection expectation with no matching evidence.** Must resolve to `Inconclusive`, never an inferred `Pass`/`Fail` based on the request having succeeded or failed at the HTTP level. Pinned in Task 2.
2. **`CorrelateWithSIEM` called when Detection was never `Pass` to begin with** (e.g., still `Inconclusive` or `Fail` from Phase 1's `VerifyHTTPExpectation`). Must return the result completely unchanged — SIEM can only corroborate an existing gateway-local detection, never manufacture one on its own. Pinned in Task 3.
3. **Multiple TLS-inspection evidence records for the same URL.** The most recent timestamp must win, matching every other evidence-selection function in this package. Pinned in Task 2.
4. **`CorrelateWithSIEM`'s provider returning both an error and non-empty records.** The error must be checked first, matching the established pattern from Phase 1's `VerifyHTTPExpectation`. Pinned in Task 3.
5. **The DLP-upload integration test's synthetic payload actually reaching `dlp_sink_receipts`.** A test that only checks the HTTP response code (200 OK) without also checking the receipt was actually written would pass even if cloudsink's token-matching silently failed — the scenario is only meaningful if the full round trip (token insert → real PUT → real DB receipt) is checked, not just the HTTP layer. Pinned in Task 4.

---

### Task 1: URL-policy and identity-scoped-policy scenarios

**Files:**
- Create: `orchestrator/internal/webgwefficacy/scenarios_test.go`

**Interfaces:**
- Consumes: `HTTPExpectation`, `HTTPObservation`, `TimeWindow`, `ExpectedAllow`, `ExpectedBlock`, `VerdictPass` (Phase 1, `types.go`); `NewFixtureGatewayProvider` (Phase 1, `providers.go`); `VerifyHTTPExpectation` (Phase 1, `verify.go`).
- Produces: nothing new — this task adds no production code, only named test scenarios proving two of Phase 2a's exit criteria against Phase 1's existing, unmodified API.

- [ ] **Step 1: Write the two scenario tests**

```go
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
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd orchestrator && go test ./internal/webgwefficacy/... -run "TestURLPolicyScenario|TestIdentityScopedPolicyScenario" -v`
Expected: FAIL — the test file doesn't exist as production code yet, so this step is really "confirm the file doesn't exist"; once written, go straight to Step 3 since this task adds no new implementation to watch fail against. (This is the one task in this plan where RED is "the test file is absent," not "the test fails against existing code" — there's nothing to implement.)

- [ ] **Step 3: Run the tests to verify they pass**

Run: `cd orchestrator && go test ./internal/webgwefficacy/... -run "TestURLPolicyScenario|TestIdentityScopedPolicyScenario" -v`
Expected: PASS, both tests, against Phase 1's existing, unmodified code.

- [ ] **Step 4: Commit**

```bash
cd orchestrator
git add internal/webgwefficacy/scenarios_test.go
git commit -m "test(webgwefficacy): prove URL-policy and identity-scoped-policy scenarios end-to-end"
```

---

### Task 2: TLS inspection visibility

**Files:**
- Create: `orchestrator/internal/webgwefficacy/tls.go`
- Test: `orchestrator/internal/webgwefficacy/tls_test.go`

**Interfaces:**
- Consumes: `TimeWindow`, `EvidenceSource`, `SourceFixture`, `VerdictDetail`, `WebGWVerdict`, `VerdictPass`, `VerdictFail`, `VerdictInconclusive` (Phase 1, `types.go`); `inWindow` (Phase 1, `providers.go`).
- Produces: `TLSInspectionExpectation{RequestURL, ExpectedInspected, ControlProduct, Note}`, `TLSInspectionEvidence{RequestURL, WasInspected, CertIssuer, Timestamp, Source}`, `TLSInspectionEvidenceProvider` interface (`TLSInspectionEvidenceFor(requestURL string, window TimeWindow) ([]TLSInspectionEvidence, error)`), `FixtureTLSInspectionProvider` + `NewFixtureTLSInspectionProvider(events []TLSInspectionEvidence) *FixtureTLSInspectionProvider`, `VerifyTLSInspectionExpectation(exp TLSInspectionExpectation, provider TLSInspectionEvidenceProvider, window TimeWindow) VerdictDetail` — later phases (and Phase 2b's live adapter) call this directly; its signature is final for this plan.

- [ ] **Step 1: Write the failing tests**

```go
package webgwefficacy

import (
	"errors"
	"testing"
	"time"
)

type erroringTLSProvider struct{ err error }

func (p erroringTLSProvider) TLSInspectionEvidenceFor(requestURL string, window TimeWindow) ([]TLSInspectionEvidence, error) {
	return nil, p.err
}

func TestFixtureTLSInspectionProvider_FiltersByURLAndWindow(t *testing.T) {
	now := time.Date(2026, 10, 15, 10, 0, 0, 0, time.UTC)
	provider := NewFixtureTLSInspectionProvider([]TLSInspectionEvidence{
		{RequestURL: "https://intranet.example/portal", WasInspected: true, Timestamp: now, Source: SourceFixture},
		{RequestURL: "https://other.example/page", WasInspected: true, Timestamp: now, Source: SourceFixture},
	})
	got, err := provider.TLSInspectionEvidenceFor("https://intranet.example/portal", TimeWindow{Start: now.Add(-time.Minute), End: now.Add(time.Minute)})
	if err != nil {
		t.Fatalf("TLSInspectionEvidenceFor: %v", err)
	}
	if len(got) != 1 || !got[0].WasInspected {
		t.Fatalf("got %+v, want exactly one inspected record for the matching URL", got)
	}
}

func TestFixtureTLSInspectionProvider_OutsideWindowExcluded(t *testing.T) {
	now := time.Date(2026, 10, 15, 10, 0, 0, 0, time.UTC)
	provider := NewFixtureTLSInspectionProvider([]TLSInspectionEvidence{
		{RequestURL: "https://intranet.example/portal", WasInspected: true, Timestamp: now, Source: SourceFixture},
	})
	got, err := provider.TLSInspectionEvidenceFor("https://intranet.example/portal", TimeWindow{Start: now.Add(time.Hour), End: now.Add(2 * time.Hour)})
	if err != nil {
		t.Fatalf("TLSInspectionEvidenceFor: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("got %+v, want empty -- outside the requested window", got)
	}
}

func TestVerifyTLSInspectionExpectation_InspectedMatchesExpectation_Pass(t *testing.T) {
	now := time.Now()
	exp := TLSInspectionExpectation{RequestURL: "https://intranet.example/portal", ExpectedInspected: true}
	provider := NewFixtureTLSInspectionProvider([]TLSInspectionEvidence{
		{RequestURL: exp.RequestURL, WasInspected: true, CertIssuer: "Cloudflare Gateway CA", Timestamp: now, Source: SourceFixture},
	})
	result := VerifyTLSInspectionExpectation(exp, provider, TimeWindow{Start: now.Add(-time.Minute), End: now.Add(time.Minute)})

	if result.Verdict != VerdictPass {
		t.Errorf("Verdict = %q, want %q", result.Verdict, VerdictPass)
	}
}

func TestVerifyTLSInspectionExpectation_NotInspectedWhenExpected_Fail(t *testing.T) {
	now := time.Now()
	exp := TLSInspectionExpectation{RequestURL: "https://intranet.example/portal", ExpectedInspected: true}
	provider := NewFixtureTLSInspectionProvider([]TLSInspectionEvidence{
		{RequestURL: exp.RequestURL, WasInspected: false, Timestamp: now, Source: SourceFixture},
	})
	result := VerifyTLSInspectionExpectation(exp, provider, TimeWindow{Start: now.Add(-time.Minute), End: now.Add(time.Minute)})

	if result.Verdict != VerdictFail {
		t.Errorf("Verdict = %q, want %q -- expected inspection but evidence shows bypass", result.Verdict, VerdictFail)
	}
}

func TestVerifyTLSInspectionExpectation_NoEvidence_Inconclusive(t *testing.T) {
	exp := TLSInspectionExpectation{RequestURL: "https://intranet.example/portal", ExpectedInspected: true}
	provider := NewFixtureTLSInspectionProvider(nil)
	result := VerifyTLSInspectionExpectation(exp, provider, TimeWindow{Start: time.Now().Add(-time.Hour), End: time.Now().Add(time.Hour)})

	if result.Verdict != VerdictInconclusive {
		t.Errorf("Verdict = %q, want %q -- a successful request must never be read as proof of inspection", result.Verdict, VerdictInconclusive)
	}
}

func TestVerifyTLSInspectionExpectation_ProviderError_Inconclusive(t *testing.T) {
	exp := TLSInspectionExpectation{RequestURL: "https://intranet.example/portal", ExpectedInspected: true}
	provider := erroringTLSProvider{err: errors.New("certificate store unreachable")}
	result := VerifyTLSInspectionExpectation(exp, provider, TimeWindow{})

	if result.Verdict != VerdictInconclusive {
		t.Errorf("Verdict = %q, want %q", result.Verdict, VerdictInconclusive)
	}
}

func TestVerifyTLSInspectionExpectation_MultipleRecords_MostRecentWins(t *testing.T) {
	older := time.Now().Add(-time.Hour)
	newer := time.Now()
	exp := TLSInspectionExpectation{RequestURL: "https://intranet.example/portal", ExpectedInspected: true}
	provider := NewFixtureTLSInspectionProvider([]TLSInspectionEvidence{
		{RequestURL: exp.RequestURL, WasInspected: false, Timestamp: older, Source: SourceFixture},
		{RequestURL: exp.RequestURL, WasInspected: true, Timestamp: newer, Source: SourceFixture},
	})
	result := VerifyTLSInspectionExpectation(exp, provider, TimeWindow{Start: older.Add(-time.Minute), End: newer.Add(time.Minute)})

	if result.Verdict != VerdictPass {
		t.Errorf("Verdict = %q, want %q -- the most recent record (inspected) must win over the stale earlier one (bypassed)", result.Verdict, VerdictPass)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/webgwefficacy/... -run "TestFixtureTLSInspectionProvider|TestVerifyTLSInspectionExpectation" -v`
Expected: FAIL — `undefined: NewFixtureTLSInspectionProvider` (and related types/functions).

- [ ] **Step 3: Write the implementation**

```go
package webgwefficacy

import (
	"fmt"
	"time"
)

// TLSInspectionExpectation is a declared "should this HTTPS request
// have been TLS-inspected" claim -- orthogonal to HTTPExpectation's
// allow/block policy action. A request can be allowed and inspected,
// allowed and bypassed, or blocked either way; this type exists
// because policy action and inspection depth are independent claims
// that must never be inferred from one another.
type TLSInspectionExpectation struct {
	RequestURL        string `json:"requestUrl"`
	ExpectedInspected bool   `json:"expectedInspected"`
	ControlProduct    string `json:"controlProduct"`
	Note              string `json:"note,omitempty"`
}

// TLSInspectionEvidence is one normalized record of whether a
// specific request was actually decrypted and re-inspected by the
// gateway, however it was obtained.
type TLSInspectionEvidence struct {
	RequestURL   string         `json:"requestUrl"`
	WasInspected bool           `json:"wasInspected"`
	CertIssuer   string         `json:"certIssuer,omitempty"`
	Timestamp    time.Time      `json:"timestamp"`
	Source       EvidenceSource `json:"source"`
}

// TLSInspectionEvidenceProvider supplies TLS-inspection evidence for
// a request URL and time window. A returned error means collection
// failed -- distinct from a successful search that found nothing.
type TLSInspectionEvidenceProvider interface {
	TLSInspectionEvidenceFor(requestURL string, window TimeWindow) ([]TLSInspectionEvidence, error)
}

// FixtureTLSInspectionProvider wraps an in-memory slice of hand-built
// TLSInspectionEvidence values -- no real certificate-chain
// inspection happens in this phase.
type FixtureTLSInspectionProvider struct {
	events []TLSInspectionEvidence
}

func NewFixtureTLSInspectionProvider(events []TLSInspectionEvidence) *FixtureTLSInspectionProvider {
	return &FixtureTLSInspectionProvider{events: events}
}

func (p *FixtureTLSInspectionProvider) TLSInspectionEvidenceFor(requestURL string, window TimeWindow) ([]TLSInspectionEvidence, error) {
	var out []TLSInspectionEvidence
	for _, e := range p.events {
		if e.RequestURL != requestURL {
			continue
		}
		if !inWindow(e.Timestamp, window) {
			continue
		}
		out = append(out, e)
	}
	return out, nil
}

// VerifyTLSInspectionExpectation checks one declared TLS-inspection
// expectation against evidence. Never infers successful inspection
// merely because a request succeeded -- the evidence must say so
// explicitly, or the result is Inconclusive.
func VerifyTLSInspectionExpectation(
	exp TLSInspectionExpectation,
	provider TLSInspectionEvidenceProvider,
	window TimeWindow,
) VerdictDetail {
	records, err := provider.TLSInspectionEvidenceFor(exp.RequestURL, window)
	if err != nil {
		return VerdictDetail{Verdict: VerdictInconclusive, Reason: fmt.Sprintf("TLS inspection evidence collection failed: %v", err)}
	}
	if len(records) == 0 {
		return VerdictDetail{
			Verdict: VerdictInconclusive,
			Reason:  "no TLS inspection evidence found for this request in the window; absence of evidence is not proof of inspection or bypass",
		}
	}
	latest := records[0]
	for _, r := range records {
		if r.Timestamp.After(latest.Timestamp) {
			latest = r
		}
	}
	if latest.WasInspected == exp.ExpectedInspected {
		return VerdictDetail{Verdict: VerdictPass}
	}
	return VerdictDetail{Verdict: VerdictFail, Reason: "observed inspection state did not match expectation"}
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/webgwefficacy/... -v`
Expected: PASS, every test from Task 1 and Task 2 plus Phase 1's existing suite.

- [ ] **Step 5: Commit**

```bash
cd orchestrator
git add internal/webgwefficacy/tls.go internal/webgwefficacy/tls_test.go
git commit -m "feat(webgwefficacy): add TLS inspection visibility -- expectation/evidence/verdict, orthogonal to policy action"
```

---

### Task 3: SIEM evidence correlation

**Files:**
- Modify: `orchestrator/internal/webgwefficacy/types.go` (add a `SIEMEvidence` field to `EfficacyResult`)
- Create: `orchestrator/internal/webgwefficacy/siem.go`
- Test: `orchestrator/internal/webgwefficacy/siem_test.go`

**Interfaces:**
- Consumes: `EfficacyResult`, `VerdictDetail`, `VerdictPass`, `VerdictInconclusive`, `HTTPRequestRef`, `TimeWindow`, `EvidenceSource` (Phase 1/Task 2, `types.go`); `matchesRequest`, `inWindow` (Phase 1, `providers.go`).
- Produces: `SIEMEvidence{RequestURL, User, EventType, Timestamp, Source, RawEvent}`, `SIEMEvidenceProvider` interface (`SIEMEvidenceFor(req HTTPRequestRef, window TimeWindow) ([]SIEMEvidence, error)`), `FixtureSIEMProvider` + `NewFixtureSIEMProvider(events []SIEMEvidence) *FixtureSIEMProvider`, `CorrelateWithSIEM(result EfficacyResult, siem SIEMEvidenceProvider, window TimeWindow) EfficacyResult` — this is the function any later phase or scenario runner calls after `VerifyHTTPExpectation` to add independent SIEM corroboration; its signature is final for this plan.

- [ ] **Step 1: Write the failing tests**

```go
package webgwefficacy

import (
	"errors"
	"testing"
	"time"
)

type erroringSIEMProvider struct {
	err     error
	records []SIEMEvidence
}

func (p erroringSIEMProvider) SIEMEvidenceFor(req HTTPRequestRef, window TimeWindow) ([]SIEMEvidence, error) {
	return p.records, p.err
}

func TestFixtureSIEMProvider_ReturnsMatchingEvidence(t *testing.T) {
	now := time.Now()
	provider := NewFixtureSIEMProvider([]SIEMEvidence{
		{RequestURL: "https://malware.example/payload", EventType: "web-gateway-alert", Timestamp: now, Source: SourceFixture},
	})
	got, err := provider.SIEMEvidenceFor(HTTPRequestRef{URL: "https://malware.example/payload"}, TimeWindow{Start: now.Add(-time.Minute), End: now.Add(time.Minute)})
	if err != nil {
		t.Fatalf("SIEMEvidenceFor: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %+v, want one matching record", got)
	}
}

func TestCorrelateWithSIEM_DetectionNotPass_ReturnedUnchanged(t *testing.T) {
	now := time.Now()
	original := EfficacyResult{
		Expectation: HTTPExpectation{RequestURL: "https://malware.example/payload"},
		Detection:   VerdictDetail{Verdict: VerdictInconclusive, Reason: "no gateway evidence found"},
	}
	provider := NewFixtureSIEMProvider([]SIEMEvidence{
		{RequestURL: "https://malware.example/payload", EventType: "web-gateway-alert", Timestamp: now, Source: SourceFixture},
	})
	result := CorrelateWithSIEM(original, provider, TimeWindow{Start: now.Add(-time.Minute), End: now.Add(time.Minute)})

	if result.Detection.Verdict != VerdictInconclusive || result.Detection.Reason != "no gateway evidence found" {
		t.Errorf("Detection = %+v, want unchanged from the input -- SIEM must never manufacture a detection the gateway never showed", result.Detection)
	}
}

func TestCorrelateWithSIEM_MatchingRecord_DetectionStaysPassWithCorroboration(t *testing.T) {
	now := time.Now()
	original := EfficacyResult{
		Expectation: HTTPExpectation{RequestURL: "https://malware.example/payload"},
		Detection:   VerdictDetail{Verdict: VerdictPass},
	}
	provider := NewFixtureSIEMProvider([]SIEMEvidence{
		{RequestURL: "https://malware.example/payload", EventType: "web-gateway-alert", Timestamp: now, Source: SourceFixture},
	})
	result := CorrelateWithSIEM(original, provider, TimeWindow{Start: now.Add(-time.Minute), End: now.Add(time.Minute)})

	if result.Detection.Verdict != VerdictPass {
		t.Errorf("Detection.Verdict = %q, want %q", result.Detection.Verdict, VerdictPass)
	}
	if result.Detection.Reason == "" {
		t.Error("Detection.Reason is empty, want a stated corroboration note")
	}
	if len(result.SIEMEvidence) != 1 {
		t.Errorf("SIEMEvidence = %+v, want the matching record attached", result.SIEMEvidence)
	}
}

func TestCorrelateWithSIEM_NoMatchingRecord_DetectionDowngradedToInconclusive(t *testing.T) {
	now := time.Now()
	original := EfficacyResult{
		Expectation: HTTPExpectation{RequestURL: "https://malware.example/payload"},
		Detection:   VerdictDetail{Verdict: VerdictPass},
	}
	provider := NewFixtureSIEMProvider(nil)
	result := CorrelateWithSIEM(original, provider, TimeWindow{Start: now.Add(-time.Minute), End: now.Add(time.Minute)})

	if result.Detection.Verdict != VerdictInconclusive {
		t.Errorf("Detection.Verdict = %q, want %q -- missing SIEM corroboration is not proof the alert was lost, only that it is uncorroborated", result.Detection.Verdict, VerdictInconclusive)
	}
}

func TestCorrelateWithSIEM_ProviderError_DetectionInconclusive(t *testing.T) {
	original := EfficacyResult{
		Expectation: HTTPExpectation{RequestURL: "https://malware.example/payload"},
		Detection:   VerdictDetail{Verdict: VerdictPass},
	}
	provider := erroringSIEMProvider{err: errors.New("SIEM API unreachable")}
	result := CorrelateWithSIEM(original, provider, TimeWindow{})

	if result.Detection.Verdict != VerdictInconclusive {
		t.Errorf("Detection.Verdict = %q, want %q", result.Detection.Verdict, VerdictInconclusive)
	}
}

func TestCorrelateWithSIEM_ProviderErrorWithRecords_RecordsIgnored(t *testing.T) {
	now := time.Now()
	original := EfficacyResult{
		Expectation: HTTPExpectation{RequestURL: "https://malware.example/payload"},
		Detection:   VerdictDetail{Verdict: VerdictPass},
	}
	provider := erroringSIEMProvider{
		err:     errors.New("SIEM API unreachable"),
		records: []SIEMEvidence{{RequestURL: "https://malware.example/payload", EventType: "web-gateway-alert", Timestamp: now}},
	}
	result := CorrelateWithSIEM(original, provider, TimeWindow{})

	if len(result.SIEMEvidence) != 0 {
		t.Errorf("SIEMEvidence = %+v, want empty -- records returned alongside an error must be ignored", result.SIEMEvidence)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/webgwefficacy/... -run "TestFixtureSIEMProvider|TestCorrelateWithSIEM" -v`
Expected: FAIL — `undefined: NewFixtureSIEMProvider` (and related types/functions); also `unknown field SIEMEvidence in struct literal` until Step 3's `types.go` edit lands.

- [ ] **Step 3: Add the SIEMEvidence field to EfficacyResult**

In `orchestrator/internal/webgwefficacy/types.go`, find the `EfficacyResult` struct and add one field:

```go
type EfficacyResult struct {
	Expectation  HTTPExpectation   `json:"expectation"`
	Observation  HTTPObservation   `json:"observation"`
	Evidence     []GatewayEvidence `json:"evidence,omitempty"`
	SIEMEvidence []SIEMEvidence    `json:"siemEvidence,omitempty"`
	Prevention   VerdictDetail     `json:"prevention"`
	Detection    VerdictDetail     `json:"detection"`
	Response     VerdictDetail     `json:"response"`
}
```

- [ ] **Step 4: Write the implementation**

```go
package webgwefficacy

import (
	"encoding/json"
	"fmt"
	"time"
)

// SIEMEvidence is one normalized SIEM telemetry record independently
// corroborating (or failing to corroborate) a gateway event -- a
// second, separately-sourced signal, never derived from
// GatewayEvidence itself.
type SIEMEvidence struct {
	RequestURL string          `json:"requestUrl"`
	User       string          `json:"user,omitempty"`
	EventType  string          `json:"eventType"`
	Timestamp  time.Time       `json:"timestamp"`
	Source     EvidenceSource  `json:"source"`
	RawEvent   json.RawMessage `json:"rawEvent,omitempty"`
}

// SIEMEvidenceProvider supplies SIEM evidence for a request shape and
// time window. Mirrors the *shape* of a real vendor connector (call
// a real product, normalize, return typed evidence) without
// importing internal/detectverify -- see the master spec's locked
// decision against type-level cross-package dependencies here.
type SIEMEvidenceProvider interface {
	SIEMEvidenceFor(req HTTPRequestRef, window TimeWindow) ([]SIEMEvidence, error)
}

// FixtureSIEMProvider wraps an in-memory slice of hand-built
// SIEMEvidence values -- no real SIEM API call happens in this
// phase.
type FixtureSIEMProvider struct {
	events []SIEMEvidence
}

func NewFixtureSIEMProvider(events []SIEMEvidence) *FixtureSIEMProvider {
	return &FixtureSIEMProvider{events: events}
}

func (p *FixtureSIEMProvider) SIEMEvidenceFor(req HTTPRequestRef, window TimeWindow) ([]SIEMEvidence, error) {
	var out []SIEMEvidence
	for _, e := range p.events {
		if !matchesRequest(e.RequestURL, e.User, req) {
			continue
		}
		if !inWindow(e.Timestamp, window) {
			continue
		}
		out = append(out, e)
	}
	return out, nil
}

// CorrelateWithSIEM strengthens or weakens an already-computed
// EfficacyResult's Detection verdict using independent SIEM
// telemetry. A gateway's own log is never treated as sufficient
// proof that an alert reached the SOC's detection surface: if the
// gateway itself never showed detection (Detection != Pass), there is
// nothing to corroborate and the result is returned unchanged; if it
// did, a missing SIEM record downgrades Detection to Inconclusive
// (never Fail -- absence of SIEM evidence is not proof the alert was
// lost, only that it is uncorroborated), and a matching record keeps
// Detection at Pass with an annotated Reason.
func CorrelateWithSIEM(result EfficacyResult, siem SIEMEvidenceProvider, window TimeWindow) EfficacyResult {
	if result.Detection.Verdict != VerdictPass {
		return result
	}
	req := HTTPRequestRef{URL: result.Expectation.RequestURL, User: result.Expectation.User}
	records, err := siem.SIEMEvidenceFor(req, window)
	if err != nil {
		result.Detection = VerdictDetail{Verdict: VerdictInconclusive, Reason: fmt.Sprintf("SIEM evidence collection failed: %v", err)}
		return result
	}
	if len(records) == 0 {
		result.Detection = VerdictDetail{
			Verdict: VerdictInconclusive,
			Reason:  "gateway evidence shows detection, but no independent SIEM record corroborates it reaching the SOC's detection surface",
		}
		return result
	}
	result.SIEMEvidence = records
	result.Detection = VerdictDetail{Verdict: VerdictPass, Reason: "corroborated by independent SIEM telemetry"}
	return result
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/webgwefficacy/... -v`
Expected: PASS, every test from Tasks 1-3 plus Phase 1's existing suite.

- [ ] **Step 6: Commit**

```bash
cd orchestrator
git add internal/webgwefficacy/types.go internal/webgwefficacy/siem.go internal/webgwefficacy/siem_test.go
git commit -m "feat(webgwefficacy): add SIEM evidence correlation -- independent corroboration, never a substitute detection source"
```

---

### Task 4: DLP-upload scenario, end-to-end via real cloudsink upload

**Files:**
- Create: `orchestrator/internal/webgwefficacy/dlp_integration_test.go`

**Interfaces:**
- Consumes: `HTTPExpectation`, `HTTPObservation`, `TimeWindow`, `ExpectedBlock`, `VerdictPass`, `SourceFixture` (Phase 1, `types.go`); `NewFixtureGatewayProvider` (Phase 1, `providers.go`); `VerifyHTTPExpectation` (Phase 1, `verify.go`); `cloudsink.Routes(db *pgxpool.Pool) chi.Router` (`internal/cloudsink/cloudsink.go`); `testutil.NewTestDB(t *testing.T) *testutil.TestDB` (`internal/testutil/testdb.go`).
- Produces: nothing new for later tasks — this is this plan's last task, proving the DLP-upload exit criterion end-to-end. Its imports of `cloudsink`/`testutil` are test-only and must not appear in `go list -deps ./internal/webgwefficacy/...` (verified in Step 5).

Before starting, check free memory (this test starts a real Docker container): run `Get-CimInstance Win32_OperatingSystem | Select-Object FreePhysicalMemory,TotalVisibleMemorySize` and confirm Docker Desktop is running.

- [ ] **Step 1: Write the failing test**

```go
package webgwefficacy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/audspect/bas/internal/cloudsink"
	"github.com/audspect/bas/internal/testutil"
)

// TestDLPUploadScenario_SyntheticMarkerBlockedByFixtureGateway proves
// Phase 2a's DLP-upload exit criterion end-to-end: a synthetic,
// non-sensitive marker payload is actually PUT over real HTTP to
// cloudsink's S3-mimicking endpoint (the real "destination-side"
// half -- did the attempt reach the destination at all), and the
// result is run through VerifyHTTPExpectation against fixture
// gateway evidence (the "gateway policy" half, since no live gateway
// exists in this phase). This is an integration test -- it imports
// cloudsink and testutil, which internal/webgwefficacy's own
// production code never does.
func TestDLPUploadScenario_SyntheticMarkerBlockedByFixtureGateway(t *testing.T) {
	testDB := testutil.NewTestDB(t)
	ctx := context.Background()

	token := "webgw-phase2a-dlp-test-token"
	_, err := testDB.Pool.Exec(ctx,
		`INSERT INTO dlp_sink_tokens (token, run_id, technique_id, expires_at) VALUES ($1, $2, $3, $4)`,
		token, "webgw-phase2a-run", "T1567", time.Now().Add(time.Hour),
	)
	if err != nil {
		t.Fatalf("insert dlp_sink_tokens: %v", err)
	}

	server := httptest.NewServer(cloudsink.Routes(testDB.Pool))
	defer server.Close()

	syntheticMarker := strings.NewReader("BAS-SYNTHETIC-DLP-MARKER-0000111122223333-NOT-REAL-DATA")
	req, err := http.NewRequest(http.MethodPut, server.URL+"/s3/bas-test-bucket/"+token+".dat", syntheticMarker)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("PUT upload: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("upload status = %d, want 200", resp.StatusCode)
	}

	var receiptCount int
	if err := testDB.Pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM dlp_sink_receipts WHERE token = $1`, token,
	).Scan(&receiptCount); err != nil {
		t.Fatalf("query dlp_sink_receipts: %v", err)
	}
	if receiptCount == 0 {
		t.Fatalf("got 0 receipts for token %q, want at least 1 -- the upload attempt must actually reach cloudsink for this scenario to be meaningful", token)
	}
	observation := HTTPObservation{
		RequestURL:   server.URL + "/s3/bas-test-bucket/" + token + ".dat",
		ClientResult: "upload-received-by-destination",
		Timestamp:    time.Now(),
	}

	now := time.Now()
	exp := HTTPExpectation{
		RequestURL:     "https://cloud-storage.example/upload",
		ExpectedAction: ExpectedBlock,
		ControlProduct: "cloudflare-gateway",
		Note:           "synthetic DLP marker upload -- destination-side receipt confirms the attempt would have succeeded had no gateway DLP policy existed",
	}
	gatewayProvider := NewFixtureGatewayProvider([]GatewayEvidence{
		{RequestURL: exp.RequestURL, Action: "block", PolicyRule: "dlp-financial-data", Timestamp: now, Source: SourceFixture},
	})
	result := VerifyHTTPExpectation(exp, observation, gatewayProvider, TimeWindow{Start: now.Add(-time.Minute), End: now.Add(time.Minute)})

	if result.Prevention.Verdict != VerdictPass {
		t.Errorf("Prevention.Verdict = %q, want %q -- fixture gateway evidence shows the DLP policy blocked this request shape", result.Prevention.Verdict, VerdictPass)
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd orchestrator && go test ./internal/webgwefficacy/... -run TestDLPUploadScenario -v`
Expected: FAIL to compile (`undefined` errors) before any implementation exists in this task — there is none to write, since everything this test calls already exists in `internal/cloudsink`, `internal/testutil`, and Phase 1/Tasks 1-3's `webgwefficacy` code. Confirm it fails only because the test file is new, not because of a typo: read the compiler output carefully before proceeding.

- [ ] **Step 3: Run the test to verify it passes**

Run: `cd orchestrator && go test ./internal/webgwefficacy/... -run TestDLPUploadScenario -v`
Expected: PASS. Requires Docker Desktop running (the test starts a real `postgres:16-alpine` container via `testutil.NewTestDB`); if it fails with a container-startup error, start Docker Desktop and retry before treating this as a code problem.

- [ ] **Step 4: Run the full package suite**

Run: `cd orchestrator && go test ./internal/webgwefficacy/... -v`
Expected: PASS, every test from Tasks 1-4 plus Phase 1's existing suite.

- [ ] **Step 5: Verify the zero-import-dependency constraint still holds**

Run: `cd orchestrator && go list -deps ./internal/webgwefficacy/... | grep "audspect/bas"`
Expected: exactly one line, `github.com/audspect/bas/internal/webgwefficacy` itself — `cloudsink` and `testutil` must NOT appear, confirming Task 4's imports are test-only and never reach the package's own production dependency graph.

- [ ] **Step 6: Commit**

```bash
cd orchestrator
git add internal/webgwefficacy/dlp_integration_test.go
git commit -m "test(webgwefficacy): prove DLP-upload scenario end-to-end via a real cloudsink upload attempt"
```

---

## Execution Handoff

Plan complete and saved to `docs/superpowers/plans/2026-10-15-webgw-mastery-phase2a-fixture-vertical.md`. Please review the plan. Does it capture what you want?

Keeping the previously-chosen execution approach: **Native** — I implement all 4 tasks myself in this session, then one fresh reviewer on the most capable model checks the whole branch at the end. Task 4 is the one task with real operational weight (a live Docker container, a real HTTP round trip, a real DB write) — everything else is deterministic, in-memory, and low-risk, the same shape as every task Phase 1 ran natively.
