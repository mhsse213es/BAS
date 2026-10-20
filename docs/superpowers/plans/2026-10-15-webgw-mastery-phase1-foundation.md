# Web Gateway BAS Mastery Phase 1 (Foundation and Evidence Contract) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `internal/webgwefficacy`, a new, architecturally independent leaf package that defines WebGW Mastery's expectation/evidence/verdict contract and proves it end-to-end against fixture-backed (never live) gateway evidence.

**Architecture:** Mirrors `internal/networkefficacy`'s own file split (`types.go` / `providers.go` / `verify.go`) and TDD discipline exactly, substituting HTTP-request matching for that package's network-5-tuple matching, and a fresh 5-state verdict (`Pass`/`Fail`/`Inconclusive`/`Unsupported`/`NotApplicable`) with prevention/detection/response scored as three independent `VerdictDetail` values instead of one `Verdict` field. No live vendor integration, no HTTP API, no database persistence — those are Phase 2's deliverables once there is a real Cloudflare Gateway adapter to expose. This phase is pure, fixture-tested business logic, exactly as `internal/networkefficacy` shipped before its own first real provider (Suricata) existed.

**Tech Stack:** Go (standard library only for this phase — `encoding/json`, `time`, `sort`, `strings`, `fmt`). No new third-party dependency.

**Spec:** `docs/superpowers/specs/2026-10-15-webgw-mastery-architecture-design.md` — this plan implements that spec's §2.1 (core types) and §3 Phase 1's exit criteria only. Executors should read both.

## Global Constraints

- `internal/webgwefficacy` imports no other Audspect package (spec §2.1, §7) — every cross-package relationship in this initiative is a borrowed structural pattern, never a type-level dependency. `go list -deps ./internal/webgwefficacy/...` must show zero `github.com/audspect/bas/...` entries other than itself.
- The verdict type is exactly 5 states — `pass`/`fail`/`inconclusive`/`unsupported`/`not-applicable` — never unified with `scenario.ExecutionOutcome`, `networkefficacy.EfficacyVerdict`, or the DLP outcome-catalog comparator (spec §1, §7, locked).
- Prevention, detection, and response are always three independently-scored `VerdictDetail` values on `EfficacyResult` — never collapsed into one overall verdict (spec §2.1, §4).
- `Unsupported` (the capability/integration genuinely does not exist) and `Inconclusive` (the capability exists but this run's evidence is missing/ambiguous) are structurally distinct outcomes, not a convention — every function that can produce either must make the distinction from its own inputs, never by accident (spec §2.1).
- JSON field names are camelCase, matching every other type in this codebase (`internal/networkefficacy/types.go` is the direct precedent) — optional fields get `omitempty`.
- No live vendor integration, no HTTP handler, no database table in this phase (spec §3, Phase 1's own scope) — that is Phase 2's work once Cloudflare Gateway access is verified.
- "Never count missing telemetry as proof of a successful bypass" (`webGW.txt`, directly binding): absence of gateway evidence must resolve to `Inconclusive` for prevention, never `Fail`.

## Review Focus

1. **Action-string case mismatch.** A fixture (or, later, a live adapter) that returns an action string in a different case than `ExpectedGatewayAction`'s own lowercase constants (`"Block"` vs `"block"`) must be treated as a genuine mismatch (`Fail`), not silently normalized — normalization is the live adapter's job in Phase 2, not this package's. Task 3's tests pin this.
2. **Duplicate/multiple matching evidence records for one request.** The most recent timestamp must win, matching `networkefficacy.VerifyControlExpectation`'s own precedent — a stale, earlier log line must never override a more recent one. Task 3's tests pin this.
3. **Zero-value `HTTPExpectation`** (an empty struct, no `RequestURL`). The verification pipeline must not panic — it should run through the normal no-evidence path and produce an ordinary, if unhelpful, result. Task 3's tests pin this.
4. **Inverted `TimeWindow`** (`Start` after `End`). `inWindow` must treat this as containing nothing, not panic or silently treat it as an unbounded window. Task 2's tests pin this.
5. **A provider that misbehaves — returns both a non-nil error and non-empty records.** The error must be checked and returned first; the records must never be inspected once an error is present, matching `networkefficacy.VerifyControlExpectation`'s own precedent of checking `err` before looking at the evidence slice's length. Task 3's tests pin this.

---

### Task 1: Core types

**Files:**
- Create: `orchestrator/internal/webgwefficacy/types.go`
- Test: `orchestrator/internal/webgwefficacy/types_test.go`

**Interfaces:**
- Consumes: nothing (first task in a new package).
- Produces: `ExpectedGatewayAction` (string type + 4 constants: `ExpectedAllow`, `ExpectedBlock`, `ExpectedChallenge`, `ExpectedQuarantine`), `HTTPExpectation{RequestURL, URLCategory, User, ExpectedAction, ControlProduct, Note string}`, `EvidenceSource` (string type + 3 constants: `SourceSynthetic`, `SourceFixture`, `SourceLive`), `GatewayEvidence{RequestURL, User, Action, Category, PolicyRule string; Timestamp time.Time; Source EvidenceSource; RawEvent json.RawMessage}`, `HTTPObservation{RequestURL, ClientResult string; Timestamp time.Time}`, `HTTPRequestRef{URL, User string}` (no JSON tags — in-process only, matching `networkefficacy.Flow`'s own precedent), `TimeWindow{Start, End time.Time}` (no JSON tags, same precedent), `WebGWVerdict` (string type + 5 constants: `VerdictPass`, `VerdictFail`, `VerdictInconclusive`, `VerdictUnsupported`, `VerdictNotApplicable`), `VerdictDetail{Verdict WebGWVerdict; Reason string}`, `EfficacyResult{Expectation HTTPExpectation; Observation HTTPObservation; Evidence []GatewayEvidence; Prevention, Detection, Response VerdictDetail}`.

- [ ] **Step 1: Write the failing tests**

```go
package webgwefficacy

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestHTTPExpectation_SerializesWithCamelCaseKeys(t *testing.T) {
	exp := HTTPExpectation{RequestURL: "https://malware.example/payload", URLCategory: "malware", ExpectedAction: ExpectedBlock, ControlProduct: "cloudflare-gateway"}
	data, err := json.Marshal(exp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	raw := string(data)
	for _, want := range []string{`"requestUrl"`, `"urlCategory"`, `"expectedAction"`, `"controlProduct"`} {
		if !strings.Contains(raw, want) {
			t.Fatalf("got %s, want it to contain %s", raw, want)
		}
	}
	if strings.Contains(raw, `"RequestURL"`) || strings.Contains(raw, `"ExpectedAction"`) {
		t.Fatalf("got %s, want no PascalCase keys", raw)
	}
}

func TestGatewayEvidence_SerializesWithCamelCaseKeys(t *testing.T) {
	ev := GatewayEvidence{RequestURL: "https://malware.example/payload", Action: "block", Source: SourceSynthetic}
	data, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	raw := string(data)
	for _, want := range []string{`"requestUrl"`, `"action"`, `"source"`} {
		if !strings.Contains(raw, want) {
			t.Fatalf("got %s, want it to contain %s", raw, want)
		}
	}
	if strings.Contains(raw, `"RequestURL"`) || strings.Contains(raw, `"Action"`) {
		t.Fatalf("got %s, want no PascalCase keys", raw)
	}
}

func TestEfficacyResult_SerializesWithCamelCaseKeysAndOmitsEmptyEvidence(t *testing.T) {
	result := EfficacyResult{
		Expectation: HTTPExpectation{RequestURL: "https://malware.example/payload", ExpectedAction: ExpectedBlock},
		Observation: HTTPObservation{RequestURL: "https://malware.example/payload", ClientResult: "succeeded"},
		Prevention:  VerdictDetail{Verdict: VerdictInconclusive, Reason: "no gateway evidence found"},
		Detection:   VerdictDetail{Verdict: VerdictFail},
		Response:    VerdictDetail{Verdict: VerdictUnsupported, Reason: "no response-evidence integration exists in this phase"},
	}
	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	raw := string(data)
	for _, want := range []string{`"expectation"`, `"observation"`, `"prevention"`, `"detection"`, `"response"`} {
		if !strings.Contains(raw, want) {
			t.Fatalf("got %s, want it to contain %s", raw, want)
		}
	}
	if strings.Contains(raw, `"evidence"`) {
		t.Fatalf("got %s, want \"evidence\" omitted when nil", raw)
	}
}

func TestWebGWVerdict_HasExactlyFiveStates(t *testing.T) {
	states := []WebGWVerdict{VerdictPass, VerdictFail, VerdictInconclusive, VerdictUnsupported, VerdictNotApplicable}
	seen := make(map[WebGWVerdict]bool)
	for _, s := range states {
		if seen[s] {
			t.Fatalf("duplicate verdict constant value %q", s)
		}
		seen[s] = true
	}
	if len(seen) != 5 {
		t.Fatalf("got %d distinct verdict states, want 5", len(seen))
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/webgwefficacy/... -v`
Expected: FAIL — the package does not exist yet (`no Go files in ...` or `undefined: HTTPExpectation` once the test file alone exists).

- [ ] **Step 3: Write the implementation**

```go
package webgwefficacy

import (
	"encoding/json"
	"time"
)

// ExpectedGatewayAction is what a web-gateway policy was declared to
// be expected to do for a request shape -- never inferred from
// observed behavior.
type ExpectedGatewayAction string

const (
	ExpectedAllow      ExpectedGatewayAction = "allow"
	ExpectedBlock      ExpectedGatewayAction = "block"
	ExpectedChallenge  ExpectedGatewayAction = "challenge"
	ExpectedQuarantine ExpectedGatewayAction = "quarantine"
)

// HTTPExpectation is one declared "what should this gateway have
// done" for one request shape.
type HTTPExpectation struct {
	RequestURL     string                `json:"requestUrl"`
	URLCategory    string                `json:"urlCategory,omitempty"`
	User           string                `json:"user,omitempty"`
	ExpectedAction ExpectedGatewayAction `json:"expectedAction"`
	ControlProduct string                `json:"controlProduct"`
	Note           string                `json:"note,omitempty"`
}

// EvidenceSource records how a piece of gateway evidence was
// obtained. Always explicit, never implied by which fields are
// populated -- synthetic or fixture data must never be mistaken for
// live proof that a real gateway behaved a certain way.
type EvidenceSource string

const (
	SourceSynthetic EvidenceSource = "synthetic"
	SourceFixture   EvidenceSource = "recorded-fixture"
	SourceLive      EvidenceSource = "live"
)

// GatewayEvidence is one normalized gateway log/policy-decision
// record, however it was obtained.
type GatewayEvidence struct {
	RequestURL string          `json:"requestUrl"`
	User       string          `json:"user,omitempty"`
	Action     string          `json:"action"`
	Category   string          `json:"category,omitempty"`
	PolicyRule string          `json:"policyRule,omitempty"`
	Timestamp  time.Time       `json:"timestamp"`
	Source     EvidenceSource  `json:"source"`
	RawEvent   json.RawMessage `json:"rawEvent,omitempty"`
}

// HTTPObservation is what the client-side test itself actually
// attempted/saw, independent of the gateway's own evidence.
type HTTPObservation struct {
	RequestURL   string    `json:"requestUrl"`
	ClientResult string    `json:"clientResult"`
	Timestamp    time.Time `json:"timestamp,omitempty"`
}

// HTTPRequestRef identifies the request an evidence lookup should
// correlate against. No JSON tags -- in-process only, matching
// networkefficacy.Flow's own precedent.
type HTTPRequestRef struct {
	URL  string
	User string
}

// TimeWindow bounds the time range evidence must fall within to count
// as relevant to a check. No JSON tags, same precedent as
// networkefficacy.TimeWindow.
type TimeWindow struct {
	Start, End time.Time
}

// WebGWVerdict is the 5-state verdict every WebGW domain uses --
// never 3-state or 4-state, never unified with any other domain's
// taxonomy already in this codebase.
type WebGWVerdict string

const (
	VerdictPass          WebGWVerdict = "pass"
	VerdictFail          WebGWVerdict = "fail"
	VerdictInconclusive  WebGWVerdict = "inconclusive"
	VerdictUnsupported   WebGWVerdict = "unsupported"
	VerdictNotApplicable WebGWVerdict = "not-applicable"
)

// VerdictDetail is one independently-scored dimension's result.
// Reason should be set whenever Verdict is not VerdictPass.
type VerdictDetail struct {
	Verdict WebGWVerdict `json:"verdict"`
	Reason  string       `json:"reason,omitempty"`
}

// EfficacyResult keeps prevention, detection, and response as three
// independently-verdicted dimensions -- never collapsed into one
// overall pass/fail, per webGW.txt's own explicit requirement that a
// gateway "can block an action but fail to alert" and both are
// material findings.
type EfficacyResult struct {
	Expectation HTTPExpectation   `json:"expectation"`
	Observation HTTPObservation   `json:"observation"`
	Evidence    []GatewayEvidence `json:"evidence,omitempty"`
	Prevention  VerdictDetail     `json:"prevention"`
	Detection   VerdictDetail     `json:"detection"`
	Response    VerdictDetail     `json:"response"`
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/webgwefficacy/... -v`
Expected: PASS, all 4 tests.

- [ ] **Step 5: Commit**

```bash
cd orchestrator
git add internal/webgwefficacy/types.go internal/webgwefficacy/types_test.go
git commit -m "feat(webgwefficacy): add core types -- HTTPExpectation, GatewayEvidence, 5-state WebGWVerdict, EfficacyResult"
```

---

### Task 2: Matching helpers and fixture provider

**Files:**
- Create: `orchestrator/internal/webgwefficacy/providers.go`
- Test: `orchestrator/internal/webgwefficacy/providers_test.go`

**Interfaces:**
- Consumes: `HTTPRequestRef`, `TimeWindow`, `GatewayEvidence` (Task 1).
- Produces: `GatewayEvidenceProvider` interface (`GatewayEvidenceFor(req HTTPRequestRef, window TimeWindow) ([]GatewayEvidence, error)`), `FixtureGatewayProvider` struct + `NewFixtureGatewayProvider(events []GatewayEvidence) *FixtureGatewayProvider` + its `GatewayEvidenceFor` method, package-level `inWindow(t time.Time, window TimeWindow) bool` helper (used again by Task 3's tests indirectly through the provider, and directly reusable by a future Phase 2 live adapter).

- [ ] **Step 1: Write the failing tests**

```go
package webgwefficacy

import (
	"testing"
	"time"
)

func TestFixtureGatewayProvider_ReturnsMatchingEvidence(t *testing.T) {
	now := time.Date(2026, 10, 15, 10, 0, 0, 0, time.UTC)
	provider := NewFixtureGatewayProvider([]GatewayEvidence{
		{RequestURL: "https://malware.example/payload", User: "alice", Action: "block", Timestamp: now, Source: SourceFixture},
	})
	got, err := provider.GatewayEvidenceFor(HTTPRequestRef{URL: "https://malware.example/payload", User: "alice"}, TimeWindow{Start: now.Add(-time.Minute), End: now.Add(time.Minute)})
	if err != nil {
		t.Fatalf("GatewayEvidenceFor: %v", err)
	}
	if len(got) != 1 || got[0].Action != "block" {
		t.Fatalf("got %+v, want one block record", got)
	}
}

func TestFixtureGatewayProvider_NoMatchReturnsEmptyNotError(t *testing.T) {
	now := time.Date(2026, 10, 15, 10, 0, 0, 0, time.UTC)
	provider := NewFixtureGatewayProvider([]GatewayEvidence{
		{RequestURL: "https://malware.example/payload", Action: "block", Timestamp: now, Source: SourceFixture},
	})
	got, err := provider.GatewayEvidenceFor(HTTPRequestRef{URL: "https://other.example/page"}, TimeWindow{Start: now.Add(-time.Minute), End: now.Add(time.Minute)})
	if err != nil {
		t.Fatalf("GatewayEvidenceFor: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("got %+v, want empty for a non-matching URL", got)
	}
}

func TestFixtureGatewayProvider_UserMatchingIsCaseInsensitive(t *testing.T) {
	now := time.Date(2026, 10, 15, 10, 0, 0, 0, time.UTC)
	provider := NewFixtureGatewayProvider([]GatewayEvidence{
		{RequestURL: "https://malware.example/payload", User: "Alice", Action: "block", Timestamp: now, Source: SourceFixture},
	})
	got, err := provider.GatewayEvidenceFor(HTTPRequestRef{URL: "https://malware.example/payload", User: "alice"}, TimeWindow{Start: now.Add(-time.Minute), End: now.Add(time.Minute)})
	if err != nil {
		t.Fatalf("GatewayEvidenceFor: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %+v, want a case-insensitive user match", got)
	}
}

func TestFixtureGatewayProvider_EmptyReqUserMatchesAny(t *testing.T) {
	now := time.Date(2026, 10, 15, 10, 0, 0, 0, time.UTC)
	provider := NewFixtureGatewayProvider([]GatewayEvidence{
		{RequestURL: "https://malware.example/payload", User: "alice", Action: "block", Timestamp: now, Source: SourceFixture},
	})
	got, err := provider.GatewayEvidenceFor(HTTPRequestRef{URL: "https://malware.example/payload"}, TimeWindow{Start: now.Add(-time.Minute), End: now.Add(time.Minute)})
	if err != nil {
		t.Fatalf("GatewayEvidenceFor: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %+v, want an unconstrained-user request to match any user", got)
	}
}

func TestFixtureGatewayProvider_OutsideTimeWindowExcluded(t *testing.T) {
	now := time.Date(2026, 10, 15, 10, 0, 0, 0, time.UTC)
	provider := NewFixtureGatewayProvider([]GatewayEvidence{
		{RequestURL: "https://malware.example/payload", Action: "block", Timestamp: now, Source: SourceFixture},
	})
	got, err := provider.GatewayEvidenceFor(HTTPRequestRef{URL: "https://malware.example/payload"}, TimeWindow{Start: now.Add(time.Hour), End: now.Add(2 * time.Hour)})
	if err != nil {
		t.Fatalf("GatewayEvidenceFor: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("got %+v, want empty -- the record's timestamp falls outside the requested window", got)
	}
}

func TestInWindow_InvertedWindowContainsNothing(t *testing.T) {
	now := time.Date(2026, 10, 15, 10, 0, 0, 0, time.UTC)
	inverted := TimeWindow{Start: now.Add(time.Hour), End: now.Add(-time.Hour)}
	if inWindow(now, inverted) {
		t.Fatalf("inWindow(%v, %+v) = true, want false -- Start is after End", now, inverted)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/webgwefficacy/... -run "TestFixtureGatewayProvider|TestInWindow" -v`
Expected: FAIL — `undefined: NewFixtureGatewayProvider` (and `inWindow`).

- [ ] **Step 3: Write the implementation**

```go
package webgwefficacy

import (
	"strings"
	"time"
)

// GatewayEvidenceProvider supplies gateway evidence for a request
// shape and time window. A returned error means collection/parsing
// failed -- distinct from a successful search that found nothing
// (nil error, empty slice).
type GatewayEvidenceProvider interface {
	GatewayEvidenceFor(req HTTPRequestRef, window TimeWindow) ([]GatewayEvidence, error)
}

// matchesRequest reports whether a concrete evidence record's URL and
// user fall within req's declared scope. User matching is
// case-insensitive; an empty req.User matches any user (the
// expectation did not constrain it).
func matchesRequest(url, user string, req HTTPRequestRef) bool {
	if url != req.URL {
		return false
	}
	if req.User != "" && !strings.EqualFold(user, req.User) {
		return false
	}
	return true
}

// inWindow reports whether t falls within window. An inverted window
// (Start after End) contains nothing -- it is never treated as
// unbounded.
func inWindow(t time.Time, window TimeWindow) bool {
	if window.Start.After(window.End) {
		return false
	}
	return !t.Before(window.Start) && !t.After(window.End)
}

// FixtureGatewayProvider wraps an in-memory slice of hand-built
// GatewayEvidence values -- no real vendor API call happens in this
// phase; the live Cloudflare Gateway adapter is Phase 2's
// deliverable.
type FixtureGatewayProvider struct {
	events []GatewayEvidence
}

func NewFixtureGatewayProvider(events []GatewayEvidence) *FixtureGatewayProvider {
	return &FixtureGatewayProvider{events: events}
}

func (p *FixtureGatewayProvider) GatewayEvidenceFor(req HTTPRequestRef, window TimeWindow) ([]GatewayEvidence, error) {
	var out []GatewayEvidence
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/webgwefficacy/... -v`
Expected: PASS, all tests from Task 1 and Task 2.

- [ ] **Step 5: Commit**

```bash
cd orchestrator
git add internal/webgwefficacy/providers.go internal/webgwefficacy/providers_test.go
git commit -m "feat(webgwefficacy): add GatewayEvidenceProvider interface and FixtureGatewayProvider"
```

---

### Task 3: Verification pipeline

**Files:**
- Create: `orchestrator/internal/webgwefficacy/verify.go`
- Test: `orchestrator/internal/webgwefficacy/verify_test.go`

**Interfaces:**
- Consumes: `HTTPExpectation`, `HTTPObservation`, `EfficacyResult`, `VerdictDetail`, verdict constants (Task 1); `GatewayEvidenceProvider`, `FixtureGatewayProvider`/`NewFixtureGatewayProvider` (Task 2).
- Produces: `VerifyHTTPExpectation(exp HTTPExpectation, observation HTTPObservation, provider GatewayEvidenceProvider, window TimeWindow) EfficacyResult` — Phase 2's Cloudflare adapter work and any later phase's scenario-execution code call this directly; its signature is final for this phase.

- [ ] **Step 1: Write the failing tests**

```go
package webgwefficacy

import (
	"errors"
	"testing"
	"time"
)

// erroringProvider always returns err, and optionally also non-empty
// records -- used to prove VerifyHTTPExpectation checks the error
// before ever looking at the records slice's length.
type erroringProvider struct {
	err     error
	records []GatewayEvidence
}

func (p erroringProvider) GatewayEvidenceFor(req HTTPRequestRef, window TimeWindow) ([]GatewayEvidence, error) {
	return p.records, p.err
}

func TestVerifyHTTPExpectation_ProviderError_PreventionAndDetectionInconclusive(t *testing.T) {
	exp := HTTPExpectation{RequestURL: "https://malware.example/payload", ExpectedAction: ExpectedBlock}
	provider := erroringProvider{err: errors.New("gateway API unreachable")}
	result := VerifyHTTPExpectation(exp, HTTPObservation{}, provider, TimeWindow{})

	if result.Prevention.Verdict != VerdictInconclusive {
		t.Errorf("Prevention.Verdict = %q, want %q", result.Prevention.Verdict, VerdictInconclusive)
	}
	if result.Detection.Verdict != VerdictInconclusive {
		t.Errorf("Detection.Verdict = %q, want %q", result.Detection.Verdict, VerdictInconclusive)
	}
	if result.Response.Verdict != VerdictUnsupported {
		t.Errorf("Response.Verdict = %q, want %q", result.Response.Verdict, VerdictUnsupported)
	}
}

func TestVerifyHTTPExpectation_ProviderErrorWithRecords_RecordsIgnored(t *testing.T) {
	exp := HTTPExpectation{RequestURL: "https://malware.example/payload", ExpectedAction: ExpectedBlock}
	provider := erroringProvider{
		err:     errors.New("gateway API unreachable"),
		records: []GatewayEvidence{{RequestURL: "https://malware.example/payload", Action: "block", Timestamp: time.Now()}},
	}
	result := VerifyHTTPExpectation(exp, HTTPObservation{}, provider, TimeWindow{})

	if result.Prevention.Verdict != VerdictInconclusive {
		t.Errorf("Prevention.Verdict = %q, want %q -- a provider error must be checked before its records are ever inspected", result.Prevention.Verdict, VerdictInconclusive)
	}
	if len(result.Evidence) != 0 {
		t.Errorf("Evidence = %+v, want empty -- records returned alongside an error must be ignored", result.Evidence)
	}
}

func TestVerifyHTTPExpectation_NoEvidence_PreventionInconclusiveDetectionFail(t *testing.T) {
	exp := HTTPExpectation{RequestURL: "https://malware.example/payload", ExpectedAction: ExpectedBlock}
	provider := NewFixtureGatewayProvider(nil)
	result := VerifyHTTPExpectation(exp, HTTPObservation{}, provider, TimeWindow{Start: time.Now().Add(-time.Hour), End: time.Now().Add(time.Hour)})

	if result.Prevention.Verdict != VerdictInconclusive {
		t.Errorf("Prevention.Verdict = %q, want %q -- missing telemetry is never proof of a successful bypass", result.Prevention.Verdict, VerdictInconclusive)
	}
	if result.Detection.Verdict != VerdictFail {
		t.Errorf("Detection.Verdict = %q, want %q -- no log/alert at all is a genuine detection failure", result.Detection.Verdict, VerdictFail)
	}
}

func TestVerifyHTTPExpectation_ActionMatches_PreventionPass(t *testing.T) {
	now := time.Now()
	exp := HTTPExpectation{RequestURL: "https://malware.example/payload", ExpectedAction: ExpectedBlock}
	provider := NewFixtureGatewayProvider([]GatewayEvidence{
		{RequestURL: "https://malware.example/payload", Action: "block", Timestamp: now, Source: SourceFixture},
	})
	result := VerifyHTTPExpectation(exp, HTTPObservation{}, provider, TimeWindow{Start: now.Add(-time.Minute), End: now.Add(time.Minute)})

	if result.Prevention.Verdict != VerdictPass {
		t.Errorf("Prevention.Verdict = %q, want %q", result.Prevention.Verdict, VerdictPass)
	}
	if result.Detection.Verdict != VerdictPass {
		t.Errorf("Detection.Verdict = %q, want %q -- evidence existing at all is this phase's detection signal", result.Detection.Verdict, VerdictPass)
	}
}

func TestVerifyHTTPExpectation_ActionMismatch_PreventionFail(t *testing.T) {
	now := time.Now()
	exp := HTTPExpectation{RequestURL: "https://malware.example/payload", ExpectedAction: ExpectedBlock}
	provider := NewFixtureGatewayProvider([]GatewayEvidence{
		{RequestURL: "https://malware.example/payload", Action: "allow", Timestamp: now, Source: SourceFixture},
	})
	result := VerifyHTTPExpectation(exp, HTTPObservation{}, provider, TimeWindow{Start: now.Add(-time.Minute), End: now.Add(time.Minute)})

	if result.Prevention.Verdict != VerdictFail {
		t.Errorf("Prevention.Verdict = %q, want %q -- the gateway allowed a request expected to be blocked", result.Prevention.Verdict, VerdictFail)
	}
	if result.Detection.Verdict != VerdictPass {
		t.Errorf("Detection.Verdict = %q, want %q -- the gateway still logged the request, even though it took the wrong action", result.Detection.Verdict, VerdictPass)
	}
}

func TestVerifyHTTPExpectation_ActionCaseMismatch_TreatedAsMismatchNotNormalized(t *testing.T) {
	now := time.Now()
	exp := HTTPExpectation{RequestURL: "https://malware.example/payload", ExpectedAction: ExpectedBlock}
	provider := NewFixtureGatewayProvider([]GatewayEvidence{
		{RequestURL: "https://malware.example/payload", Action: "Block", Timestamp: now, Source: SourceFixture},
	})
	result := VerifyHTTPExpectation(exp, HTTPObservation{}, provider, TimeWindow{Start: now.Add(-time.Minute), End: now.Add(time.Minute)})

	if result.Prevention.Verdict != VerdictFail {
		t.Errorf("Prevention.Verdict = %q, want %q -- this phase does exact-case matching; normalizing vendor casing is a live adapter's job (Phase 2), not this package's", result.Prevention.Verdict, VerdictFail)
	}
}

func TestVerifyHTTPExpectation_ResponseAlwaysUnsupportedInThisPhase(t *testing.T) {
	now := time.Now()
	exp := HTTPExpectation{RequestURL: "https://malware.example/payload", ExpectedAction: ExpectedBlock}
	provider := NewFixtureGatewayProvider([]GatewayEvidence{
		{RequestURL: "https://malware.example/payload", Action: "block", Timestamp: now, Source: SourceFixture},
	})
	result := VerifyHTTPExpectation(exp, HTTPObservation{}, provider, TimeWindow{Start: now.Add(-time.Minute), End: now.Add(time.Minute)})

	if result.Response.Verdict != VerdictUnsupported {
		t.Errorf("Response.Verdict = %q, want %q -- no response-evidence integration exists until a later phase", result.Response.Verdict, VerdictUnsupported)
	}
	if result.Response.Reason == "" {
		t.Error("Response.Reason is empty, want a stated reason since Verdict != Pass")
	}
}

func TestVerifyHTTPExpectation_MultipleMatchingRecords_MostRecentWins(t *testing.T) {
	older := time.Now().Add(-time.Hour)
	newer := time.Now()
	exp := HTTPExpectation{RequestURL: "https://malware.example/payload", ExpectedAction: ExpectedBlock}
	provider := NewFixtureGatewayProvider([]GatewayEvidence{
		{RequestURL: "https://malware.example/payload", Action: "allow", Timestamp: older, Source: SourceFixture},
		{RequestURL: "https://malware.example/payload", Action: "block", Timestamp: newer, Source: SourceFixture},
	})
	result := VerifyHTTPExpectation(exp, HTTPObservation{}, provider, TimeWindow{Start: older.Add(-time.Minute), End: newer.Add(time.Minute)})

	if result.Prevention.Verdict != VerdictPass {
		t.Errorf("Prevention.Verdict = %q, want %q -- the most recent record (block) must win over the stale earlier one (allow)", result.Prevention.Verdict, VerdictPass)
	}
}

func TestVerifyHTTPExpectation_ZeroValueExpectation_DoesNotPanic(t *testing.T) {
	provider := NewFixtureGatewayProvider(nil)
	result := VerifyHTTPExpectation(HTTPExpectation{}, HTTPObservation{}, provider, TimeWindow{})

	if result.Prevention.Verdict != VerdictInconclusive {
		t.Errorf("Prevention.Verdict = %q, want %q for a zero-value expectation with no matching evidence", result.Prevention.Verdict, VerdictInconclusive)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/webgwefficacy/... -run TestVerifyHTTPExpectation -v`
Expected: FAIL — `undefined: VerifyHTTPExpectation`.

- [ ] **Step 3: Write the implementation**

```go
package webgwefficacy

import (
	"fmt"
	"sort"
)

// unsupportedResponseReason is this phase's constant reason for every
// Response verdict -- no response-evidence integration (SOC/
// ticketing/EDR action correlation) exists at all yet; this is a
// structural "capability does not exist," distinct from a run whose
// evidence happened to be missing (Inconclusive).
const unsupportedResponseReason = "no response-evidence integration exists in this phase"

// VerifyHTTPExpectation checks one declared expectation against
// gateway evidence, scoring prevention, detection, and response
// independently. Mirrors networkefficacy.VerifyControlExpectation's
// precedent (every failure mode resolves to a verdict with a reason;
// this function never returns an error) with three independently
// computed dimensions instead of one.
func VerifyHTTPExpectation(
	exp HTTPExpectation,
	observation HTTPObservation,
	provider GatewayEvidenceProvider,
	window TimeWindow,
) EfficacyResult {
	result := EfficacyResult{
		Expectation: exp,
		Observation: observation,
		Response:    VerdictDetail{Verdict: VerdictUnsupported, Reason: unsupportedResponseReason},
	}
	req := HTTPRequestRef{URL: exp.RequestURL, User: exp.User}

	records, err := provider.GatewayEvidenceFor(req, window)
	if err != nil {
		reason := fmt.Sprintf("gateway evidence collection failed: %v", err)
		result.Prevention = VerdictDetail{Verdict: VerdictInconclusive, Reason: reason}
		result.Detection = VerdictDetail{Verdict: VerdictInconclusive, Reason: reason}
		return result
	}
	if len(records) == 0 {
		result.Prevention = VerdictDetail{
			Verdict: VerdictInconclusive,
			Reason:  "no gateway evidence found for this request in the window; absence of evidence is not proof the expected action occurred",
		}
		result.Detection = VerdictDetail{
			Verdict: VerdictFail,
			Reason:  "no gateway log or alert found; expected the gateway to record this request",
		}
		return result
	}

	result.Evidence = records
	latest := latestGatewayEvidence(records)

	if latest.Action == string(exp.ExpectedAction) {
		result.Prevention = VerdictDetail{Verdict: VerdictPass}
	} else {
		result.Prevention = VerdictDetail{
			Verdict: VerdictFail,
			Reason:  fmt.Sprintf("gateway action %q did not match expected %q", latest.Action, exp.ExpectedAction),
		}
	}

	result.Detection = VerdictDetail{Verdict: VerdictPass}

	return result
}

// latestGatewayEvidence returns the record with the latest Timestamp
// -- a later event reflects the gateway's final decision for a
// request more faithfully than an earlier one (retries, duplicate log
// lines, a policy change mid-test).
func latestGatewayEvidence(records []GatewayEvidence) GatewayEvidence {
	sorted := make([]GatewayEvidence, len(records))
	copy(sorted, records)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Timestamp.Before(sorted[j].Timestamp) })
	return sorted[len(sorted)-1]
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/webgwefficacy/... -v`
Expected: PASS, every test from Tasks 1-3.

- [ ] **Step 5: Verify the zero-import-dependency constraint**

Run: `cd orchestrator && go list -deps ./internal/webgwefficacy/... | grep "audspect/bas"`
Expected: exactly one line, `github.com/audspect/bas/internal/webgwefficacy` itself — nothing else. This is the Global Constraint from the spec (§2.1, §7): zero dependency on `networkefficacy`, `detectverify`, `compliance`, `regobligation`, or anything else in this codebase.

- [ ] **Step 6: Commit**

```bash
cd orchestrator
git add internal/webgwefficacy/verify.go internal/webgwefficacy/verify_test.go
git commit -m "feat(webgwefficacy): add VerifyHTTPExpectation -- prevention/detection/response scored independently"
```

---

## Execution Handoff

Plan complete and saved to `docs/superpowers/plans/2026-10-15-webgw-mastery-phase1-foundation.md`. Please review the plan. Which execution approach would you prefer?

- **Subagent-driven** — A fresh subagent implements each task and a fresh reviewer checks it before the next one starts, then a whole-branch review at the end. Most thorough; costs a fresh context per task and per review.
- **Native** — I implement every task myself in this session, the way this harness runs work, then one fresh reviewer on the most capable model checks the whole branch. Cheapest and fastest; no independent review until the end. Runs well with a mid-tier session model, since the plan carries the design.

For this plan I recommend **Native**, because this entire phase is three small, tightly sequential tasks in one new leaf package with zero external dependencies and zero live-system risk — the same size and shape as every prior Network BAS Mastery phase this session ran natively, and a shipped mistake here costs nothing beyond a quick fix-and-retest since nothing else in the codebase depends on this package yet.

Does the plan capture what you want, and which approach should we use?
