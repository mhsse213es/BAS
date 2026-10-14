# Network BAS Mastery Phase 4: Network Security Control Efficacy Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task (Native/inline execution, pre-selected for this plan — see Execution Handoff). Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Determine whether a real firewall/IDS-IPS product actually did what it was expected to do for a network flow that Network BAS has already modeled (Phase 2A policy evaluation) and tested (Phase 1 observation), producing a provenance-linked `met`/`not-met`/`inconclusive` efficacy verdict — provable entirely from fixtures, with zero modification to the existing `detectverify` EDR/SIEM pipeline.

**Architecture:** New package `internal/networkefficacy` — data model, two small evidence-provider interfaces (firewall, IDS/IPS) with a real Suricata-EVE-JSON parser for one and a synthetic in-memory provider for the other, and an orchestration function with a deliberately asymmetric verdict table plus an independent contradiction detector. A new Postgres store and HTTP API layer mirror Phases 2A/3's exact precedent: a persisted "import" document for declared expectations, plus a stateless "verify" endpoint that computes results fresh from inline-supplied evidence.

**Tech Stack:** Go, Postgres (via `pgxpool`), chi router — same stack as every prior phase.

**Spec:** `docs/superpowers/specs/2026-10-14-network-bas-phase4-control-efficacy-design.md` (as corrected `29304c1d` — `FirewallEvidence`/`IDSEvidence` gained `SourceIP`/`DestIP`/`Port`/`Protocol` fields, `VerifyControlExpectation` dropped its vestigial `error` return, and the zero-matching-observation handler behavior was specified)

## Global Constraints

- `MaxExpectationsPerImport = 500` — mirrors the 500-scale cap every prior phase's import uses (`MaxZonesPerTopologyImport`, `MaxZonesPerImport`).
- `MaxFirewallEvidencePerVerification = 2000`, `MaxIDSEvidencePerVerification = 2000` — caps on the inline evidence arrays a single verify request may supply.
- `http.MaxBytesReader` on every new POST endpoint from the start: import `5 << 20` (mirrors Phase 2A/3's import caps), verify `1 << 20` (1MiB — larger than Phase 3's 64KiB path-query cap, since this body also carries inline evidence arrays, not just a flow query).
- No new `cloudgraph.PathState` value is introduced — `detectContradiction` reuses only the existing `Observed`/`Blocked` values.
- `internal/detectverify` (its `Connector` interface, `VerifyRequest`/`VerifyResult`, `VerifyRun`, and every existing EDR/SIEM provider implementation) is **not modified or imported** by this plan.
- `internal/networktopology`'s CIDR-containment pattern (`ZoneForHost` in `resolve.go`) is duplicated locally inside this plan's own handler code, never imported — `internal/networkefficacy` has no dependency on `internal/networktopology`.
- Every new struct field in every task gets an explicit, lowerCamelCase `json:` tag from the first draft — Phase 3's final review caught exactly this omission (`HopResult`/`PathResult` had none at all) as an Important finding; there is no excuse to repeat it.
- `VerifyControlExpectation` never returns an error — every failure mode resolves to `Verdict: VerdictInconclusive` with a `Reason`, matching `ComposeHop`'s exact precedent (`internal/networkpath/compose.go`).

## Review Focus

- **Multiple matching evidence records for one flow** (retries, duplicate log lines, a state change mid-test) — the spec requires "most recent by timestamp wins," and this must be proven with a fixture where an *earlier* record has the opposite action/alert from the *later* one, so a test that merely checks "a record was found" cannot pass by accident. Owned by Task 4.
- **A clean, successful, empty-result search is not the same finding as a provider error** — for a `block` expectation this distinction changes the whole verdict (`inconclusive` either way, but for different reasons) while for an `alert` expectation it changes the verdict itself (`inconclusive` vs. `not-met`). A test that only exercises one of the two for either expected-action value would miss half of this. Owned by Task 4.
- **Case differences in `Protocol`** (`"TCP"` vs `"tcp"`) between a declared expectation and a stored evidence record or observation `Target.Protocol` — a naive exact-match filter would silently never find a real match, masking as "no evidence" (`inconclusive`/`not-met`) when evidence genuinely exists. Owned by Task 2 and Task 3 (one test each, since each provider implements its own filtering).
- **Zero matching `NetworkObservation` for an expectation's flow** — distinct from "zero matching *evidence*." The spec requires the handler to produce a direct `inconclusive` result for that expectation without ever calling `VerifyControlExpectation` (which has no valid zero value for a required `Observation`). A test that only covers "discovery run has no observations at all" would miss the more likely case: observations exist, but none match *this specific* expectation's flow. Owned by Task 7.
- **`Contradiction` must stay empty for `alert` expectations even when `Observation` would, by the `block`-path heuristic, look contradictory** (e.g. an `alert`-expectation's flow was independently observed as `Blocked`) — since an IDS alerting on a payload and a connection failing for an unrelated reason are not evidence of anything about each other. A test that never exercises an `alert` expectation alongside a non-`Observed` `Observation` could let a future refactor accidentally wire the two together. Owned by Task 4.

---

### Task 1: Data Model

**Files:**
- Create: `orchestrator/internal/networkefficacy/types.go`
- Test: `orchestrator/internal/networkefficacy/types_test.go`

**Interfaces:**
- Consumes: `cloudgraph.PathState`/`Provenance` (existing, read-only), `networkgraph.NetworkObservation` (existing, read-only), `networkpolicy.PolicyEvaluation` (existing, read-only).
- Produces: `ExpectedControlAction` (`ExpectedBlock`, `ExpectedAlert`), `EvidenceSource` (`SourceSynthetic`, `SourceFixture`, `SourceLive`), `ControlExpectation{ID, FlowSourceCIDR, FlowDestCIDR, FlowPort, FlowProtocol, ExpectedAction, ControlProduct, Note}`, `ControlExpectationImport{ID, SourceType, ImportedBy, ImportedAt, ConfigVersion, Expectations, Limitations}`, `FirewallEvidence{SourceIP, DestIP, Port, Protocol, Action, Timestamp, Source, RawEvent}`, `IDSEvidence{SourceIP, DestIP, Port, Protocol, AlertName, Severity, Timestamp, Source, RawEvent}`, `EfficacyVerdict` (`VerdictMet`, `VerdictNotMet`, `VerdictInconclusive`), `EfficacyResult{Expectation, PolicyEval, Observation, FirewallEvidence, IDSEvidence, Verdict, Reason, Contradiction}`.

- [ ] **Step 1: Write the failing tests**

```go
// orchestrator/internal/networkefficacy/types_test.go
package networkefficacy

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/audspect/bas/internal/cloudgraph"
	"github.com/audspect/bas/internal/networkgraph"
)

func TestControlExpectation_SerializesWithCamelCaseKeys(t *testing.T) {
	exp := ControlExpectation{FlowSourceCIDR: "10.0.1.0/24", FlowDestCIDR: "10.0.2.0/24", FlowPort: 443, ExpectedAction: ExpectedBlock, ControlProduct: "opnsense"}
	data, err := json.Marshal(exp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	raw := string(data)
	for _, want := range []string{`"flowSourceCidr"`, `"flowDestCidr"`, `"flowPort"`, `"expectedAction"`, `"controlProduct"`} {
		if !strings.Contains(raw, want) {
			t.Fatalf("got %s, want it to contain %s", raw, want)
		}
	}
	if strings.Contains(raw, `"FlowSourceCIDR"`) || strings.Contains(raw, `"ExpectedAction"`) {
		t.Fatalf("got %s, want no PascalCase keys", raw)
	}
}

func TestFirewallEvidence_SerializesWithCamelCaseKeys(t *testing.T) {
	ev := FirewallEvidence{SourceIP: "10.0.1.5", DestIP: "10.0.2.5", Port: 443, Action: "block", Source: SourceSynthetic}
	data, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	raw := string(data)
	for _, want := range []string{`"sourceIp"`, `"destIp"`, `"port"`, `"action"`, `"source"`} {
		if !strings.Contains(raw, want) {
			t.Fatalf("got %s, want it to contain %s", raw, want)
		}
	}
	if strings.Contains(raw, `"SourceIP"`) || strings.Contains(raw, `"Action"`) {
		t.Fatalf("got %s, want no PascalCase keys", raw)
	}
}

func TestIDSEvidence_SerializesWithCamelCaseKeys(t *testing.T) {
	ev := IDSEvidence{SourceIP: "10.0.1.5", DestIP: "10.0.2.5", Port: 443, AlertName: "ET SCAN", Source: SourceFixture}
	data, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	raw := string(data)
	for _, want := range []string{`"sourceIp"`, `"destIp"`, `"alertName"`, `"source"`} {
		if !strings.Contains(raw, want) {
			t.Fatalf("got %s, want it to contain %s", raw, want)
		}
	}
	if strings.Contains(raw, `"AlertName"`) {
		t.Fatalf("got %s, want no PascalCase keys", raw)
	}
}

func TestEfficacyResult_SerializesWithCamelCaseKeysAndOmitsEmptyOptionals(t *testing.T) {
	result := EfficacyResult{
		Expectation: ControlExpectation{FlowSourceCIDR: "10.0.1.0/24", FlowDestCIDR: "10.0.2.0/24", FlowPort: 443, ExpectedAction: ExpectedBlock},
		Observation: networkgraph.NetworkObservation{Target: networkgraph.Target{Host: "10.0.2.5", Port: 443}, State: cloudgraph.Unknown},
		Verdict:     VerdictInconclusive,
		Reason:      "no firewall log entry found",
	}
	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	raw := string(data)
	for _, want := range []string{`"expectation"`, `"observation"`, `"verdict"`, `"reason"`} {
		if !strings.Contains(raw, want) {
			t.Fatalf("got %s, want it to contain %s", raw, want)
		}
	}
	for _, unwanted := range []string{`"firewallEvidence"`, `"idsEvidence"`, `"contradiction"`, `"policyEvaluation"`} {
		if strings.Contains(raw, unwanted) {
			t.Fatalf("got %s, want %s omitted when empty", raw, unwanted)
		}
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/networkefficacy/... -v`
Expected: FAIL — `package networkefficacy` does not exist / all referenced types undefined.

- [ ] **Step 3: Write the types**

```go
// orchestrator/internal/networkefficacy/types.go

// Package networkefficacy correlates a declared expected network-control
// outcome against a real firewall/IDS-IPS product's own evidence for a
// flow Network BAS has already modeled (internal/networkpolicy) and
// tested (internal/networkgraph), producing a provenance-linked
// efficacy verdict. It is deliberately independent of
// internal/detectverify -- see
// docs/superpowers/specs/2026-10-14-network-bas-phase4-control-efficacy-design.md
// §2 for why the two are not merged. It imports internal/networkpolicy
// and internal/networkgraph read-only, and internal/cloudgraph only for
// its existing PathState values (never a new one). It does not import
// internal/networktopology or internal/detectverify.
package networkefficacy

import (
	"encoding/json"
	"time"

	"github.com/audspect/bas/internal/networkgraph"
	"github.com/audspect/bas/internal/networkpolicy"
)

// ExpectedControlAction is what a control product was declared to be
// expected to do for a flow. Never inferred from a PolicyEvaluation --
// a permit verdict and "no control test declared" are different things.
type ExpectedControlAction string

const (
	ExpectedBlock ExpectedControlAction = "block"
	ExpectedAlert ExpectedControlAction = "alert"
)

// EvidenceSource records how a piece of control-product evidence was
// obtained. Always explicit, never implied by which fields are
// populated -- synthetic or fixture data must never be mistaken for
// live proof that a real product behaved a certain way.
type EvidenceSource string

const (
	SourceSynthetic EvidenceSource = "synthetic"
	SourceFixture   EvidenceSource = "recorded-fixture"
	SourceLive      EvidenceSource = "live"
)

// ControlExpectation is one declared "what should this control have
// done" for one flow.
type ControlExpectation struct {
	ID             string                `json:"id,omitempty"`
	FlowSourceCIDR string                `json:"flowSourceCidr"`
	FlowDestCIDR   string                `json:"flowDestCidr"`
	FlowPort       int                   `json:"flowPort"`
	FlowProtocol   string                `json:"flowProtocol,omitempty"`
	ExpectedAction ExpectedControlAction `json:"expectedAction"`
	ControlProduct string                `json:"controlProduct"`
	Note           string                `json:"note,omitempty"`
}

// ControlExpectationImport is one auditable, versioned set of declared
// expectations -- same shape discipline as networkpolicy.PolicyImport
// and networktopology.TopologyImport.
type ControlExpectationImport struct {
	ID            string               `json:"id,omitempty"`
	SourceType    string               `json:"sourceType"`
	ImportedBy    string               `json:"importedBy,omitempty"`
	ImportedAt    time.Time            `json:"importedAt,omitempty"`
	ConfigVersion string               `json:"configVersion,omitempty"`
	Expectations  []ControlExpectation `json:"expectations"`
	Limitations   []string             `json:"limitations,omitempty"`
}

// FirewallEvidence is one firewall log entry's normalized shape.
type FirewallEvidence struct {
	SourceIP  string          `json:"sourceIp"`
	DestIP    string          `json:"destIp"`
	Port      int             `json:"port"`
	Protocol  string          `json:"protocol,omitempty"`
	Action    string          `json:"action"` // "block" | "permit"
	Timestamp time.Time       `json:"timestamp"`
	Source    EvidenceSource  `json:"source"`
	RawEvent  json.RawMessage `json:"rawEvent,omitempty"`
}

// IDSEvidence is one IDS/IPS alert's normalized shape (e.g. parsed from
// a Suricata EVE JSON "alert" event).
type IDSEvidence struct {
	SourceIP  string          `json:"sourceIp"`
	DestIP    string          `json:"destIp"`
	Port      int             `json:"port"`
	Protocol  string          `json:"protocol,omitempty"`
	AlertName string          `json:"alertName"`
	Severity  string          `json:"severity,omitempty"`
	Timestamp time.Time       `json:"timestamp"`
	Source    EvidenceSource  `json:"source"`
	RawEvent  json.RawMessage `json:"rawEvent,omitempty"`
}

// EfficacyVerdict is the outcome of comparing a ControlExpectation
// against the control product's own evidence.
type EfficacyVerdict string

const (
	VerdictMet          EfficacyVerdict = "met"
	VerdictNotMet       EfficacyVerdict = "not-met"
	VerdictInconclusive EfficacyVerdict = "inconclusive" // Reason is required
)

// EfficacyResult keeps all four evidence dimensions visible and
// separately attributable -- never collapsed into just Verdict.
// Observation is required (not a pointer): it is what proves the test
// flow was actually attempted, and it is load-bearing for Contradiction
// detection.
type EfficacyResult struct {
	Expectation      ControlExpectation              `json:"expectation"`
	PolicyEval       *networkpolicy.PolicyEvaluation  `json:"policyEvaluation,omitempty"`
	Observation      networkgraph.NetworkObservation  `json:"observation"`
	FirewallEvidence *FirewallEvidence                `json:"firewallEvidence,omitempty"`
	IDSEvidence      *IDSEvidence                     `json:"idsEvidence,omitempty"`
	Verdict          EfficacyVerdict                  `json:"verdict"`
	Reason           string                           `json:"reason,omitempty"`
	Contradiction    string                           `json:"contradiction,omitempty"`
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/networkefficacy/... -v`
Expected: PASS — 4/4.

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/networkefficacy/types.go orchestrator/internal/networkefficacy/types_test.go
git commit -m "feat(networkefficacy): add control-expectation and evidence data model"
```

---

### Task 2: Evidence Collection — Interfaces & Synthetic Firewall Provider

**Files:**
- Create: `orchestrator/internal/networkefficacy/providers.go`
- Test: `orchestrator/internal/networkefficacy/providers_test.go`

**Interfaces:**
- Consumes: `FirewallEvidence` (Task 1).
- Produces: `Flow{SourceCIDR, DestCIDR, Port, Protocol}`, `TimeWindow{Start, End}`, `FirewallEvidenceProvider` interface (`FirewallEvidenceFor(flow Flow, window TimeWindow) ([]FirewallEvidence, error)`), `IDSEvidenceProvider` interface (`IDSEvidenceFor(flow Flow, window TimeWindow) ([]IDSEvidence, error)`), `func NewSyntheticFirewallProvider(events []FirewallEvidence) *SyntheticFirewallProvider`, `(*SyntheticFirewallProvider).FirewallEvidenceFor`.

- [ ] **Step 1: Write the failing tests**

```go
// orchestrator/internal/networkefficacy/providers_test.go
package networkefficacy

import (
	"testing"
	"time"
)

func TestSyntheticFirewallProvider_ReturnsMatchingEvidence(t *testing.T) {
	now := time.Now()
	p := NewSyntheticFirewallProvider([]FirewallEvidence{
		{SourceIP: "10.0.1.5", DestIP: "10.0.2.5", Port: 443, Protocol: "tcp", Action: "block", Timestamp: now, Source: SourceSynthetic},
	})
	flow := Flow{SourceCIDR: "10.0.1.0/24", DestCIDR: "10.0.2.0/24", Port: 443, Protocol: "tcp"}
	window := TimeWindow{Start: now.Add(-time.Minute), End: now.Add(time.Minute)}
	got, err := p.FirewallEvidenceFor(flow, window)
	if err != nil {
		t.Fatalf("FirewallEvidenceFor: %v", err)
	}
	if len(got) != 1 || got[0].Action != "block" {
		t.Fatalf("got %+v, want one block event", got)
	}
}

func TestSyntheticFirewallProvider_NoMatchReturnsEmptyNotError(t *testing.T) {
	now := time.Now()
	p := NewSyntheticFirewallProvider([]FirewallEvidence{
		{SourceIP: "192.168.9.9", DestIP: "192.168.9.10", Port: 22, Action: "permit", Timestamp: now, Source: SourceSynthetic},
	})
	flow := Flow{SourceCIDR: "10.0.1.0/24", DestCIDR: "10.0.2.0/24", Port: 443}
	window := TimeWindow{Start: now.Add(-time.Minute), End: now.Add(time.Minute)}
	got, err := p.FirewallEvidenceFor(flow, window)
	if err != nil {
		t.Fatalf("FirewallEvidenceFor: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("got %+v, want none", got)
	}
}

func TestSyntheticFirewallProvider_ProtocolMatchingIsCaseInsensitive(t *testing.T) {
	now := time.Now()
	p := NewSyntheticFirewallProvider([]FirewallEvidence{
		{SourceIP: "10.0.1.5", DestIP: "10.0.2.5", Port: 443, Protocol: "TCP", Action: "block", Timestamp: now, Source: SourceSynthetic},
	})
	flow := Flow{SourceCIDR: "10.0.1.0/24", DestCIDR: "10.0.2.0/24", Port: 443, Protocol: "tcp"}
	window := TimeWindow{Start: now.Add(-time.Minute), End: now.Add(time.Minute)}
	got, err := p.FirewallEvidenceFor(flow, window)
	if err != nil {
		t.Fatalf("FirewallEvidenceFor: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %+v, want one match -- protocol matching must be case-insensitive (TCP vs tcp)", got)
	}
}

func TestSyntheticFirewallProvider_OutsideTimeWindowExcluded(t *testing.T) {
	now := time.Now()
	p := NewSyntheticFirewallProvider([]FirewallEvidence{
		{SourceIP: "10.0.1.5", DestIP: "10.0.2.5", Port: 443, Protocol: "tcp", Action: "block", Timestamp: now.Add(-time.Hour), Source: SourceSynthetic},
	})
	flow := Flow{SourceCIDR: "10.0.1.0/24", DestCIDR: "10.0.2.0/24", Port: 443, Protocol: "tcp"}
	window := TimeWindow{Start: now.Add(-time.Minute), End: now.Add(time.Minute)}
	got, err := p.FirewallEvidenceFor(flow, window)
	if err != nil {
		t.Fatalf("FirewallEvidenceFor: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("got %+v, want none -- the event's timestamp is an hour outside the window", got)
	}
}

func TestSyntheticFirewallProvider_WrongPortExcluded(t *testing.T) {
	now := time.Now()
	p := NewSyntheticFirewallProvider([]FirewallEvidence{
		{SourceIP: "10.0.1.5", DestIP: "10.0.2.5", Port: 22, Protocol: "tcp", Action: "block", Timestamp: now, Source: SourceSynthetic},
	})
	flow := Flow{SourceCIDR: "10.0.1.0/24", DestCIDR: "10.0.2.0/24", Port: 443, Protocol: "tcp"}
	window := TimeWindow{Start: now.Add(-time.Minute), End: now.Add(time.Minute)}
	got, err := p.FirewallEvidenceFor(flow, window)
	if err != nil {
		t.Fatalf("FirewallEvidenceFor: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("got %+v, want none -- port 22 does not match the flow's port 443", got)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/networkefficacy/... -run TestSyntheticFirewallProvider -v`
Expected: FAIL — `Flow`, `TimeWindow`, `NewSyntheticFirewallProvider` undefined.

- [ ] **Step 3: Implement**

```go
// orchestrator/internal/networkefficacy/providers.go
package networkefficacy

import (
	"net"
	"strings"
	"time"
)

// Flow is the 4-tuple (plus source) a control-expectation check
// correlates evidence against.
type Flow struct {
	SourceCIDR, DestCIDR string
	Port                 int
	Protocol             string
}

// TimeWindow bounds the time range evidence must fall within to count
// as relevant to a check.
type TimeWindow struct {
	Start, End time.Time
}

// FirewallEvidenceProvider supplies firewall evidence for a flow and
// time window. A returned error means collection/parsing failed --
// distinct from a successful search that found nothing (nil error,
// empty slice).
type FirewallEvidenceProvider interface {
	FirewallEvidenceFor(flow Flow, window TimeWindow) ([]FirewallEvidence, error)
}

// IDSEvidenceProvider supplies IDS/IPS evidence for a flow and time
// window, with the same error-vs-empty-result distinction.
type IDSEvidenceProvider interface {
	IDSEvidenceFor(flow Flow, window TimeWindow) ([]IDSEvidence, error)
}

// matchesFlow reports whether a concrete source/dest IP, port, and
// protocol fall within flow's declared CIDRs/port/protocol. Protocol
// matching is case-insensitive; an empty flow.Protocol matches any
// protocol (the expectation did not constrain it).
func matchesFlow(sourceIP, destIP string, port int, protocol string, flow Flow) bool {
	if port != flow.Port {
		return false
	}
	if flow.Protocol != "" && !strings.EqualFold(protocol, flow.Protocol) {
		return false
	}
	if !cidrContains(flow.SourceCIDR, sourceIP) {
		return false
	}
	if !cidrContains(flow.DestCIDR, destIP) {
		return false
	}
	return true
}

// cidrContains duplicates the small CIDR-containment check already
// duplicated independently in internal/networktopology and
// internal/networkpolicy, per this codebase's established convention
// of not sharing this logic across domain packages.
func cidrContains(cidr, ip string) bool {
	if cidr == "" || ip == "" {
		return false
	}
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}
	return ipNet.Contains(parsedIP)
}

func inWindow(t time.Time, window TimeWindow) bool {
	return !t.Before(window.Start) && !t.After(window.End)
}

// SyntheticFirewallProvider wraps an in-memory slice of hand-built
// FirewallEvidence values -- no real OPNsense log-format parser exists
// yet (deferred per the spec §8).
type SyntheticFirewallProvider struct {
	events []FirewallEvidence
}

func NewSyntheticFirewallProvider(events []FirewallEvidence) *SyntheticFirewallProvider {
	return &SyntheticFirewallProvider{events: events}
}

func (p *SyntheticFirewallProvider) FirewallEvidenceFor(flow Flow, window TimeWindow) ([]FirewallEvidence, error) {
	var out []FirewallEvidence
	for _, e := range p.events {
		if !matchesFlow(e.SourceIP, e.DestIP, e.Port, e.Protocol, flow) {
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

Run: `cd orchestrator && go test ./internal/networkefficacy/... -v`
Expected: PASS — 9/9 (4 from Task 1 + 5 from this task).

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/networkefficacy/providers.go orchestrator/internal/networkefficacy/providers_test.go
git commit -m "feat(networkefficacy): add evidence-provider interfaces and synthetic firewall provider"
```

---

### Task 3: Suricata EVE JSON Parser & Fixture IDS Provider

**Files:**
- Create: `orchestrator/internal/networkefficacy/eve.go`
- Test: `orchestrator/internal/networkefficacy/eve_test.go`

**Interfaces:**
- Consumes: `IDSEvidence`, `Flow`, `TimeWindow`, `matchesFlow`, `inWindow`, `IDSEvidenceProvider` (Tasks 1-2).
- Produces: `func ParseSuricataEVE(r io.Reader) ([]IDSEvidence, error)`, `func NewFixtureIDSProvider(records []IDSEvidence) *FixtureIDSProvider`, `(*FixtureIDSProvider).IDSEvidenceFor`.

- [ ] **Step 1: Write the failing tests**

```go
// orchestrator/internal/networkefficacy/eve_test.go
package networkefficacy

import (
	"strings"
	"testing"
	"time"
)

const sampleEVE = `{"timestamp":"2026-10-14T10:00:00.000000+0000","event_type":"flow","src_ip":"10.0.1.5","dest_ip":"10.0.2.5"}
{"timestamp":"2026-10-14T10:00:05.000000+0000","event_type":"alert","src_ip":"10.0.1.5","src_port":51000,"dest_ip":"10.0.2.5","dest_port":443,"proto":"TCP","alert":{"signature":"ET SCAN Suspicious inbound","severity":2}}
{"timestamp":"2026-10-14T10:00:06.000000+0000","event_type":"alert","src_ip":"192.168.9.9","src_port":51000,"dest_ip":"192.168.9.10","dest_port":22,"proto":"TCP","alert":{"signature":"ET SCAN unrelated","severity":3}}
`

func TestParseSuricataEVE_ExtractsOnlyAlertEvents(t *testing.T) {
	records, err := ParseSuricataEVE(strings.NewReader(sampleEVE))
	if err != nil {
		t.Fatalf("ParseSuricataEVE: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("got %d records, want 2 -- the \"flow\" event_type line must be skipped", len(records))
	}
	if records[0].AlertName != "ET SCAN Suspicious inbound" || records[0].DestIP != "10.0.2.5" || records[0].Port != 443 {
		t.Fatalf("got %+v, fields not extracted correctly", records[0])
	}
}

func TestParseSuricataEVE_MalformedLineErrors(t *testing.T) {
	bad := `{"timestamp":"2026-10-14T10:00:00.000000+0000","event_type":"alert"` // truncated JSON
	if _, err := ParseSuricataEVE(strings.NewReader(bad)); err == nil {
		t.Fatal("want an error for malformed EVE JSON, not a silently empty result")
	}
}

func TestParseSuricataEVE_EmptyInputReturnsEmptyNotError(t *testing.T) {
	records, err := ParseSuricataEVE(strings.NewReader(""))
	if err != nil {
		t.Fatalf("ParseSuricataEVE: %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("got %d records, want 0", len(records))
	}
}

func TestFixtureIDSProvider_ReturnsMatchingAlert(t *testing.T) {
	records, err := ParseSuricataEVE(strings.NewReader(sampleEVE))
	if err != nil {
		t.Fatalf("ParseSuricataEVE: %v", err)
	}
	p := NewFixtureIDSProvider(records)
	flow := Flow{SourceCIDR: "10.0.1.0/24", DestCIDR: "10.0.2.0/24", Port: 443, Protocol: "tcp"}
	ts, _ := time.Parse(time.RFC3339, "2026-10-14T10:00:05Z")
	window := TimeWindow{Start: ts.Add(-time.Minute), End: ts.Add(time.Minute)}
	got, err := p.IDSEvidenceFor(flow, window)
	if err != nil {
		t.Fatalf("IDSEvidenceFor: %v", err)
	}
	if len(got) != 1 || got[0].AlertName != "ET SCAN Suspicious inbound" {
		t.Fatalf("got %+v, want exactly the one alert matching this flow -- the unrelated 192.168.x alert must not match", got)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/networkefficacy/... -run 'TestParseSuricataEVE|TestFixtureIDSProvider' -v`
Expected: FAIL — `ParseSuricataEVE`, `NewFixtureIDSProvider` undefined.

- [ ] **Step 3: Implement**

```go
// orchestrator/internal/networkefficacy/eve.go
package networkefficacy

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"time"
)

// eveRecord is the subset of Suricata's EVE JSON schema this parser
// cares about. Suricata emits many more fields and event types; only
// "alert" events are kept, since those are this phase's IDS/IPS
// evidence.
type eveRecord struct {
	Timestamp string `json:"timestamp"`
	EventType string `json:"event_type"`
	SrcIP     string `json:"src_ip"`
	SrcPort   int    `json:"src_port"`
	DestIP    string `json:"dest_ip"`
	DestPort  int    `json:"dest_port"`
	Proto     string `json:"proto"`
	Alert     *struct {
		Signature string `json:"signature"`
		Severity  int    `json:"severity"`
	} `json:"alert,omitempty"`
}

// ParseSuricataEVE reads newline-delimited Suricata EVE JSON and
// returns the normalized IDSEvidence for every "alert" event. Any
// other event_type (flow, dns, http, ...) is skipped. A malformed line
// is an error, not a silently dropped record -- collection/parsing
// failure must be distinguishable from "no alerts occurred" by the
// caller (internal/networkefficacy's own VerifyControlExpectation
// relies on this distinction, see Task 4). Source is always
// SourceFixture: this parser's only caller in this phase is a recorded
// fixture file, never a live stream (deferred per the spec §8).
func ParseSuricataEVE(r io.Reader) ([]IDSEvidence, error) {
	var out []IDSEvidence
	scanner := bufio.NewScanner(r)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var rec eveRecord
		if err := json.Unmarshal(line, &rec); err != nil {
			return nil, fmt.Errorf("networkefficacy: eve line %d: %w", lineNum, err)
		}
		if rec.EventType != "alert" || rec.Alert == nil {
			continue
		}
		ts, err := time.Parse("2006-01-02T15:04:05.999999-0700", rec.Timestamp)
		if err != nil {
			return nil, fmt.Errorf("networkefficacy: eve line %d: invalid timestamp %q: %w", lineNum, rec.Timestamp, err)
		}
		out = append(out, IDSEvidence{
			SourceIP:  rec.SrcIP,
			DestIP:    rec.DestIP,
			Port:      rec.DestPort,
			Protocol:  rec.Proto,
			AlertName: rec.Alert.Signature,
			Severity:  strconv.Itoa(rec.Alert.Severity),
			Timestamp: ts,
			Source:    SourceFixture,
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("networkefficacy: eve scan: %w", err)
	}
	return out, nil
}

// FixtureIDSProvider wraps a slice of already-parsed IDSEvidence (from
// ParseSuricataEVE) and implements IDSEvidenceProvider by filtering to
// the ones matching a flow and time window.
type FixtureIDSProvider struct {
	records []IDSEvidence
}

func NewFixtureIDSProvider(records []IDSEvidence) *FixtureIDSProvider {
	return &FixtureIDSProvider{records: records}
}

func (p *FixtureIDSProvider) IDSEvidenceFor(flow Flow, window TimeWindow) ([]IDSEvidence, error) {
	var out []IDSEvidence
	for _, r := range p.records {
		if !matchesFlow(r.SourceIP, r.DestIP, r.Port, r.Protocol, flow) {
			continue
		}
		if !inWindow(r.Timestamp, window) {
			continue
		}
		out = append(out, r)
	}
	return out, nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/networkefficacy/... -v`
Expected: PASS — 13/13 (9 from Tasks 1-2 + 4 from this task).

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/networkefficacy/eve.go orchestrator/internal/networkefficacy/eve_test.go
git commit -m "feat(networkefficacy): add Suricata EVE JSON parser and fixture IDS provider"
```

---

### Task 4: Orchestration — Verdict Logic & Contradiction Detection

**Files:**
- Create: `orchestrator/internal/networkefficacy/verify.go`
- Test: `orchestrator/internal/networkefficacy/verify_test.go`

**Interfaces:**
- Consumes: everything from Tasks 1-3, plus `cloudgraph.Observed`/`Blocked` (existing), `networkgraph.NetworkObservation`/`Target` (existing), `networkpolicy.PolicyEvaluation` (existing, optional).
- Produces: `func VerifyControlExpectation(exp ControlExpectation, observation networkgraph.NetworkObservation, policyEval *networkpolicy.PolicyEvaluation, firewallProvider FirewallEvidenceProvider, idsProvider IDSEvidenceProvider, window TimeWindow) EfficacyResult`.

- [ ] **Step 1: Write the failing tests**

```go
// orchestrator/internal/networkefficacy/verify_test.go
package networkefficacy

import (
	"errors"
	"testing"
	"time"

	"github.com/audspect/bas/internal/cloudgraph"
	"github.com/audspect/bas/internal/networkgraph"
)

func expectation(action ExpectedControlAction) ControlExpectation {
	return ControlExpectation{FlowSourceCIDR: "10.0.1.0/24", FlowDestCIDR: "10.0.2.0/24", FlowPort: 443, FlowProtocol: "tcp", ExpectedAction: action, ControlProduct: "opnsense"}
}

func observationState(state cloudgraph.PathState) networkgraph.NetworkObservation {
	return networkgraph.NetworkObservation{Target: networkgraph.Target{Host: "10.0.2.5", Port: 443}, State: state}
}

type erroringFirewallProvider struct{}

func (erroringFirewallProvider) FirewallEvidenceFor(Flow, TimeWindow) ([]FirewallEvidence, error) {
	return nil, errors.New("connection refused")
}

type erroringIDSProvider struct{}

func (erroringIDSProvider) IDSEvidenceFor(Flow, TimeWindow) ([]IDSEvidence, error) {
	return nil, errors.New("file not found")
}

var testWindow = TimeWindow{Start: time.Now().Add(-time.Hour), End: time.Now().Add(time.Hour)}

func TestVerifyControlExpectation_BlockProviderError_Inconclusive(t *testing.T) {
	result := VerifyControlExpectation(expectation(ExpectedBlock), observationState(cloudgraph.Unknown), nil, erroringFirewallProvider{}, NewFixtureIDSProvider(nil), testWindow)
	if result.Verdict != VerdictInconclusive {
		t.Fatalf("Verdict = %q, want inconclusive", result.Verdict)
	}
	if result.Reason == "" {
		t.Fatal("want a non-empty reason")
	}
}

func TestVerifyControlExpectation_BlockNoMatch_Inconclusive(t *testing.T) {
	result := VerifyControlExpectation(expectation(ExpectedBlock), observationState(cloudgraph.Unknown), nil, NewSyntheticFirewallProvider(nil), NewFixtureIDSProvider(nil), testWindow)
	if result.Verdict != VerdictInconclusive {
		t.Fatalf("Verdict = %q, want inconclusive -- a firewall's silence is not proof of anything", result.Verdict)
	}
}

func TestVerifyControlExpectation_BlockMatchBlock_Met(t *testing.T) {
	fw := NewSyntheticFirewallProvider([]FirewallEvidence{{SourceIP: "10.0.1.5", DestIP: "10.0.2.5", Port: 443, Protocol: "tcp", Action: "block", Timestamp: time.Now(), Source: SourceSynthetic}})
	result := VerifyControlExpectation(expectation(ExpectedBlock), observationState(cloudgraph.Blocked), nil, fw, NewFixtureIDSProvider(nil), testWindow)
	if result.Verdict != VerdictMet {
		t.Fatalf("Verdict = %q, want met", result.Verdict)
	}
	if result.FirewallEvidence == nil || result.FirewallEvidence.Action != "block" {
		t.Fatalf("want the matched FirewallEvidence attached, got %+v", result.FirewallEvidence)
	}
}

func TestVerifyControlExpectation_BlockMatchPermit_NotMet(t *testing.T) {
	fw := NewSyntheticFirewallProvider([]FirewallEvidence{{SourceIP: "10.0.1.5", DestIP: "10.0.2.5", Port: 443, Protocol: "tcp", Action: "permit", Timestamp: time.Now(), Source: SourceSynthetic}})
	result := VerifyControlExpectation(expectation(ExpectedBlock), observationState(cloudgraph.Observed), nil, fw, NewFixtureIDSProvider(nil), testWindow)
	if result.Verdict != VerdictNotMet {
		t.Fatalf("Verdict = %q, want not-met", result.Verdict)
	}
}

func TestVerifyControlExpectation_AlertProviderError_Inconclusive(t *testing.T) {
	result := VerifyControlExpectation(expectation(ExpectedAlert), observationState(cloudgraph.Observed), nil, NewSyntheticFirewallProvider(nil), erroringIDSProvider{}, testWindow)
	if result.Verdict != VerdictInconclusive {
		t.Fatalf("Verdict = %q, want inconclusive", result.Verdict)
	}
}

func TestVerifyControlExpectation_AlertNoMatch_NotMet(t *testing.T) {
	result := VerifyControlExpectation(expectation(ExpectedAlert), observationState(cloudgraph.Observed), nil, NewSyntheticFirewallProvider(nil), NewFixtureIDSProvider(nil), testWindow)
	if result.Verdict != VerdictNotMet {
		t.Fatalf("Verdict = %q, want not-met -- a clean empty IDS search is a reliable negative signal, unlike firewall silence", result.Verdict)
	}
}

func TestVerifyControlExpectation_AlertMatch_Met(t *testing.T) {
	ids := NewFixtureIDSProvider([]IDSEvidence{{SourceIP: "10.0.1.5", DestIP: "10.0.2.5", Port: 443, Protocol: "tcp", AlertName: "ET SCAN", Timestamp: time.Now(), Source: SourceFixture}})
	result := VerifyControlExpectation(expectation(ExpectedAlert), observationState(cloudgraph.Observed), nil, NewSyntheticFirewallProvider(nil), ids, testWindow)
	if result.Verdict != VerdictMet {
		t.Fatalf("Verdict = %q, want met", result.Verdict)
	}
	if result.IDSEvidence == nil || result.IDSEvidence.AlertName != "ET SCAN" {
		t.Fatalf("want the matched IDSEvidence attached, got %+v", result.IDSEvidence)
	}
}

func TestVerifyControlExpectation_MultipleMatchingRecords_MostRecentWins(t *testing.T) {
	now := time.Now()
	fw := NewSyntheticFirewallProvider([]FirewallEvidence{
		{SourceIP: "10.0.1.5", DestIP: "10.0.2.5", Port: 443, Protocol: "tcp", Action: "permit", Timestamp: now.Add(-time.Minute), Source: SourceSynthetic},
		{SourceIP: "10.0.1.5", DestIP: "10.0.2.5", Port: 443, Protocol: "tcp", Action: "block", Timestamp: now, Source: SourceSynthetic},
	})
	result := VerifyControlExpectation(expectation(ExpectedBlock), observationState(cloudgraph.Blocked), nil, fw, NewFixtureIDSProvider(nil), testWindow)
	if result.Verdict != VerdictMet {
		t.Fatalf("Verdict = %q, want met -- the LATER record (action=block) must win over the earlier permit record", result.Verdict)
	}
	if result.FirewallEvidence.Action != "block" {
		t.Fatalf("FirewallEvidence.Action = %q, want block (the most recent record)", result.FirewallEvidence.Action)
	}
}

func TestVerifyControlExpectation_Contradiction_BlockedClaimedButObservedReachable(t *testing.T) {
	fw := NewSyntheticFirewallProvider([]FirewallEvidence{{SourceIP: "10.0.1.5", DestIP: "10.0.2.5", Port: 443, Protocol: "tcp", Action: "block", Timestamp: time.Now(), Source: SourceSynthetic}})
	result := VerifyControlExpectation(expectation(ExpectedBlock), observationState(cloudgraph.Observed), nil, fw, NewFixtureIDSProvider(nil), testWindow)
	if result.Verdict != VerdictMet {
		t.Fatalf("Verdict = %q, want met -- the firewall's own evidence still says block, Contradiction is additive, not an override", result.Verdict)
	}
	if result.Contradiction == "" {
		t.Fatal("want a non-empty Contradiction -- firewall claims blocked, but our own probe observed the flow as reachable")
	}
}

func TestVerifyControlExpectation_Contradiction_PermittedClaimedButObservedBlocked(t *testing.T) {
	fw := NewSyntheticFirewallProvider([]FirewallEvidence{{SourceIP: "10.0.1.5", DestIP: "10.0.2.5", Port: 443, Protocol: "tcp", Action: "permit", Timestamp: time.Now(), Source: SourceSynthetic}})
	result := VerifyControlExpectation(expectation(ExpectedBlock), observationState(cloudgraph.Blocked), nil, fw, NewFixtureIDSProvider(nil), testWindow)
	if result.Verdict != VerdictNotMet {
		t.Fatalf("Verdict = %q, want not-met", result.Verdict)
	}
	if result.Contradiction == "" {
		t.Fatal("want a non-empty Contradiction -- firewall claims permitted, but our own probe observed the flow as blocked")
	}
}

func TestVerifyControlExpectation_NoContradictionWhenEvidenceAndObservationAgree(t *testing.T) {
	fw := NewSyntheticFirewallProvider([]FirewallEvidence{{SourceIP: "10.0.1.5", DestIP: "10.0.2.5", Port: 443, Protocol: "tcp", Action: "block", Timestamp: time.Now(), Source: SourceSynthetic}})
	result := VerifyControlExpectation(expectation(ExpectedBlock), observationState(cloudgraph.Blocked), nil, fw, NewFixtureIDSProvider(nil), testWindow)
	if result.Contradiction != "" {
		t.Fatalf("Contradiction = %q, want empty -- the firewall's claim and our observation agree", result.Contradiction)
	}
}

func TestVerifyControlExpectation_AlertExpectationNeverSetsContradiction(t *testing.T) {
	// Observation shows Blocked, which would trigger the block-path
	// heuristic if it were wrongly applied to an alert expectation --
	// it must not be, since an IDS alerting on a payload and a
	// connection failing for an unrelated reason are not evidence of
	// anything about each other.
	ids := NewFixtureIDSProvider([]IDSEvidence{{SourceIP: "10.0.1.5", DestIP: "10.0.2.5", Port: 443, Protocol: "tcp", AlertName: "ET SCAN", Timestamp: time.Now(), Source: SourceFixture}})
	result := VerifyControlExpectation(expectation(ExpectedAlert), observationState(cloudgraph.Blocked), nil, NewSyntheticFirewallProvider(nil), ids, testWindow)
	if result.Contradiction != "" {
		t.Fatalf("Contradiction = %q, want always empty for an alert expectation", result.Contradiction)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/networkefficacy/... -run TestVerifyControlExpectation -v`
Expected: FAIL — `VerifyControlExpectation` undefined.

- [ ] **Step 3: Implement**

```go
// orchestrator/internal/networkefficacy/verify.go
package networkefficacy

import (
	"fmt"
	"sort"

	"github.com/audspect/bas/internal/cloudgraph"
	"github.com/audspect/bas/internal/networkgraph"
	"github.com/audspect/bas/internal/networkpolicy"
)

// VerifyControlExpectation checks one declared expectation against the
// real control product's own evidence, correlating it with Network
// BAS's own flow evidence for the same flow. Independent of
// detectverify.VerifyRun by design -- no shared code path. Every
// failure mode resolves to Verdict: VerdictInconclusive with a Reason;
// this function never returns an error, matching ComposeHop's exact
// precedent (internal/networkpath/compose.go).
func VerifyControlExpectation(
	exp ControlExpectation,
	observation networkgraph.NetworkObservation,
	policyEval *networkpolicy.PolicyEvaluation,
	firewallProvider FirewallEvidenceProvider,
	idsProvider IDSEvidenceProvider,
	window TimeWindow,
) EfficacyResult {
	result := EfficacyResult{Expectation: exp, PolicyEval: policyEval, Observation: observation}
	flow := Flow{SourceCIDR: exp.FlowSourceCIDR, DestCIDR: exp.FlowDestCIDR, Port: exp.FlowPort, Protocol: exp.FlowProtocol}

	switch exp.ExpectedAction {
	case ExpectedBlock:
		records, err := firewallProvider.FirewallEvidenceFor(flow, window)
		if err != nil {
			result.Verdict = VerdictInconclusive
			result.Reason = fmt.Sprintf("firewall evidence collection failed: %v", err)
			return result
		}
		if len(records) == 0 {
			result.Verdict = VerdictInconclusive
			result.Reason = "no firewall log entry found for this flow; absence of a log entry is not proof of a permitted connection, since not every flow is guaranteed to be logged"
			return result
		}
		latest := latestFirewallEvidence(records)
		result.FirewallEvidence = &latest
		if latest.Action == "block" {
			result.Verdict = VerdictMet
		} else {
			result.Verdict = VerdictNotMet
			result.Reason = "firewall evidence shows this flow was permitted, expected block"
		}
		result.Contradiction = detectContradiction(result.FirewallEvidence, observation)
		return result

	case ExpectedAlert:
		records, err := idsProvider.IDSEvidenceFor(flow, window)
		if err != nil {
			result.Verdict = VerdictInconclusive
			result.Reason = fmt.Sprintf("IDS evidence collection/parsing failed: %v", err)
			return result
		}
		if len(records) == 0 {
			result.Verdict = VerdictNotMet
			result.Reason = "no IDS alert found for this flow in the window; expected an alert to be raised"
			return result
		}
		latest := latestIDSEvidence(records)
		result.IDSEvidence = &latest
		result.Verdict = VerdictMet
		return result

	default:
		result.Verdict = VerdictInconclusive
		result.Reason = fmt.Sprintf("unknown expected control action %q", exp.ExpectedAction)
		return result
	}
}

// latestFirewallEvidence returns the record with the latest Timestamp
// -- a later event reflects the control's final state for a flow more
// faithfully than an earlier one (retries, duplicate log lines, a
// state change mid-test).
func latestFirewallEvidence(records []FirewallEvidence) FirewallEvidence {
	sorted := make([]FirewallEvidence, len(records))
	copy(sorted, records)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Timestamp.Before(sorted[j].Timestamp) })
	return sorted[len(sorted)-1]
}

func latestIDSEvidence(records []IDSEvidence) IDSEvidence {
	sorted := make([]IDSEvidence, len(records))
	copy(sorted, records)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Timestamp.Before(sorted[j].Timestamp) })
	return sorted[len(sorted)-1]
}

// detectContradiction flags a disagreement between the firewall's own
// claimed action and our independently-observed reachability for the
// same flow. It is additive context, never a verdict override, and
// only ever applies to the block path with a firewall match -- an IDS
// alerting on a payload and a connection succeeding are not mutually
// exclusive, so this is never computed for alert expectations.
func detectContradiction(fw *FirewallEvidence, obs networkgraph.NetworkObservation) string {
	if fw == nil {
		return ""
	}
	switch fw.Action {
	case "block":
		if obs.State == cloudgraph.Observed {
			return "firewall evidence claims this flow was blocked, but our own connectivity probe observed it as reachable"
		}
	case "permit":
		if obs.State == cloudgraph.Blocked {
			return "firewall evidence claims this flow was permitted, but our own connectivity probe observed it as blocked"
		}
	}
	return ""
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/networkefficacy/... -v`
Expected: PASS — 25/25 (13 from Tasks 1-3 + 12 from this task).

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/networkefficacy/verify.go orchestrator/internal/networkefficacy/verify_test.go
git commit -m "feat(networkefficacy): add control-expectation verification with asymmetric verdict logic"
```

---

### Task 5: Control-Expectation Import Schema & Store

**Files:**
- Create: `orchestrator/internal/db/networkcontrolexpectation_store.go`
- Test: `orchestrator/internal/db/networkcontrolexpectation_store_test.go`
- Modify: `orchestrator/internal/testutil/testdb.go:146-150` (immediately after the existing `EnsureNetworkTopologySchema` block)
- Modify: `orchestrator/cmd/server/main.go:299-301` (immediately after the existing `EnsureNetworkTopologySchema` block)

**Interfaces:**
- Consumes: `networkefficacy.ControlExpectationImport`/`ControlExpectation` (Task 1), the existing `nullableString(s string) *string` helper (`orchestrator/internal/db/networkdiscovery_store.go:78`, same `db` package, reused not redefined).
- Produces: `func EnsureNetworkControlExpectationSchema(ctx context.Context, pool *pgxpool.Pool) error`, `func InsertNetworkControlExpectationImport(ctx context.Context, pool *pgxpool.Pool, imp *networkefficacy.ControlExpectationImport) error`, `func GetNetworkControlExpectationImport(ctx context.Context, pool *pgxpool.Pool, id string) (*networkefficacy.ControlExpectationImport, error)`, `func ListNetworkControlExpectationImports(ctx context.Context, pool *pgxpool.Pool, limit int) ([]*networkefficacy.ControlExpectationImport, error)`.

- [ ] **Step 1: Write the failing tests**

```go
// orchestrator/internal/db/networkcontrolexpectation_store_test.go
package db_test

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/networkefficacy"
)

func TestInsertNetworkControlExpectationImport_RoundTripsThroughGetAndList(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		imp := &networkefficacy.ControlExpectationImport{
			ID: "nceimp-roundtrip-1", SourceType: "manual-declared", ImportedBy: "alice", ConfigVersion: "v1",
			Expectations: []networkefficacy.ControlExpectation{
				{FlowSourceCIDR: "10.0.1.0/24", FlowDestCIDR: "10.0.2.0/24", FlowPort: 443, FlowProtocol: "tcp", ExpectedAction: networkefficacy.ExpectedBlock, ControlProduct: "opnsense"},
			},
			Limitations: []string{"lab-only, no production firewall yet"},
		}
		if err := db.InsertNetworkControlExpectationImport(context.Background(), pool, imp); err != nil {
			t.Fatalf("insert: %v", err)
		}

		got, err := db.GetNetworkControlExpectationImport(context.Background(), pool, imp.ID)
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		if got.SourceType != "manual-declared" || got.ImportedBy != "alice" || got.ConfigVersion != "v1" {
			t.Fatalf("got %+v, want SourceType=manual-declared ImportedBy=alice ConfigVersion=v1", got)
		}
		if len(got.Expectations) != 1 || got.Expectations[0].ExpectedAction != networkefficacy.ExpectedBlock {
			t.Fatalf("Expectations round-trip mismatch: %+v", got.Expectations)
		}
		if len(got.Limitations) != 1 {
			t.Fatalf("Limitations round-trip mismatch: %+v", got.Limitations)
		}
		if got.ImportedAt.IsZero() {
			t.Fatal("ImportedAt should be populated by the database default")
		}

		list, err := db.ListNetworkControlExpectationImports(context.Background(), pool, 100)
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		found := false
		for _, r := range list {
			if r.ID == imp.ID {
				found = true
			}
		}
		if !found {
			t.Fatal("inserted import should appear in the list")
		}
	})
}

func TestGetNetworkControlExpectationImport_NonexistentIDReturnsErrNoRows(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		_, err := db.GetNetworkControlExpectationImport(context.Background(), pool, "nonexistent-id")
		if !errors.Is(err, pgx.ErrNoRows) {
			t.Fatalf("got %v, want an error satisfying errors.Is(err, pgx.ErrNoRows)", err)
		}
	})
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go vet ./internal/db/...`
Expected: FAIL — `db.InsertNetworkControlExpectationImport`, `db.GetNetworkControlExpectationImport`, `db.ListNetworkControlExpectationImports` undefined.

- [ ] **Step 3: Implement the store**

```go
// orchestrator/internal/db/networkcontrolexpectation_store.go
package db

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/networkefficacy"
)

// EnsureNetworkControlExpectationSchema creates the
// network_control_expectations table.
func EnsureNetworkControlExpectationSchema(ctx context.Context, pool *pgxpool.Pool) error {
	_, err := pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS network_control_expectations (
			id              text        PRIMARY KEY DEFAULT gen_random_uuid()::text,
			source_type     text        NOT NULL,
			imported_by     text,
			imported_at     timestamptz NOT NULL DEFAULT NOW(),
			config_version  text,
			limitations     text[],
			expectations_data jsonb     NOT NULL
		)`)
	if err != nil {
		return fmt.Errorf("network_control_expectations: ensure schema: %w", err)
	}
	return nil
}

// InsertNetworkControlExpectationImport writes a new
// network_control_expectations row. The caller supplies imp.ID already
// generated.
func InsertNetworkControlExpectationImport(ctx context.Context, pool *pgxpool.Pool, imp *networkefficacy.ControlExpectationImport) error {
	data, err := json.Marshal(imp.Expectations)
	if err != nil {
		return fmt.Errorf("network_control_expectations: marshal expectations for %s: %w", imp.ID, err)
	}
	_, err = pool.Exec(ctx,
		`INSERT INTO network_control_expectations (id, source_type, imported_by, config_version, limitations, expectations_data)
		 VALUES ($1,$2,$3,$4,$5,$6)`,
		imp.ID, imp.SourceType, nullableString(imp.ImportedBy), nullableString(imp.ConfigVersion), imp.Limitations, data)
	if err != nil {
		return fmt.Errorf("network_control_expectations: insert %s: %w", imp.ID, err)
	}
	return nil
}

func scanNetworkControlExpectationImport(row pgx.Row) (*networkefficacy.ControlExpectationImport, error) {
	imp := &networkefficacy.ControlExpectationImport{}
	var importedBy, configVersion *string
	var data []byte
	if err := row.Scan(&imp.ID, &imp.SourceType, &importedBy, &imp.ImportedAt, &configVersion, &imp.Limitations, &data); err != nil {
		return nil, err
	}
	if importedBy != nil {
		imp.ImportedBy = *importedBy
	}
	if configVersion != nil {
		imp.ConfigVersion = *configVersion
	}
	if err := json.Unmarshal(data, &imp.Expectations); err != nil {
		return nil, fmt.Errorf("network_control_expectations: unmarshal expectations for %s: %w", imp.ID, err)
	}
	return imp, nil
}

// GetNetworkControlExpectationImport returns one import by id. A
// missing id returns an error satisfying errors.Is(err, pgx.ErrNoRows).
func GetNetworkControlExpectationImport(ctx context.Context, pool *pgxpool.Pool, id string) (*networkefficacy.ControlExpectationImport, error) {
	row := pool.QueryRow(ctx,
		`SELECT id, source_type, imported_by, imported_at, config_version, limitations, expectations_data
		 FROM network_control_expectations WHERE id = $1`, id)
	imp, err := scanNetworkControlExpectationImport(row)
	if err != nil {
		return nil, fmt.Errorf("network_control_expectations: get %s: %w", id, err)
	}
	return imp, nil
}

// ListNetworkControlExpectationImports returns up to limit rows, newest
// first.
func ListNetworkControlExpectationImports(ctx context.Context, pool *pgxpool.Pool, limit int) ([]*networkefficacy.ControlExpectationImport, error) {
	rows, err := pool.Query(ctx,
		`SELECT id, source_type, imported_by, imported_at, config_version, limitations, expectations_data
		 FROM network_control_expectations ORDER BY imported_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("network_control_expectations: list: %w", err)
	}
	defer rows.Close()
	var out []*networkefficacy.ControlExpectationImport
	for rows.Next() {
		imp, err := scanNetworkControlExpectationImport(rows)
		if err != nil {
			return nil, fmt.Errorf("network_control_expectations: list scan: %w", err)
		}
		out = append(out, imp)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("network_control_expectations: list rows: %w", err)
	}
	return out, nil
}
```

- [ ] **Step 4: Wire schema creation into the test pool and server startup**

In `orchestrator/internal/testutil/testdb.go`, immediately after the existing block ending at line 150:
```go
	if err := db.EnsureNetworkTopologySchema(ctx, pool); err != nil {
		pool.Close()
		_ = container.Terminate(context.Background())
		return nil, fmt.Errorf("testutil: EnsureNetworkTopologySchema: %w", err)
	}
```
add:
```go
	if err := db.EnsureNetworkControlExpectationSchema(ctx, pool); err != nil {
		pool.Close()
		_ = container.Terminate(context.Background())
		return nil, fmt.Errorf("testutil: EnsureNetworkControlExpectationSchema: %w", err)
	}
```

In `orchestrator/cmd/server/main.go`, immediately after the existing block ending at line 301:
```go
	if err := db.EnsureNetworkTopologySchema(context.Background(), adminPool); err != nil {
		log.Fatalf("[FATAL] network topology schema: %v", err)
	}
```
add:
```go
	if err := db.EnsureNetworkControlExpectationSchema(context.Background(), adminPool); err != nil {
		log.Fatalf("[FATAL] network control expectation schema: %v", err)
	}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd orchestrator && go build ./... && go test ./internal/db/... -run 'TestInsertNetworkControlExpectationImport|TestGetNetworkControlExpectationImport' -v`
Expected: PASS — 2/2.

- [ ] **Step 6: Run the full `internal/db` suite to confirm no regression**

Check memory headroom first: `Get-CimInstance Win32_OperatingSystem | Select-Object FreePhysicalMemory,TotalVisibleMemorySize` (PowerShell). If free memory is below ~1GB, check `docker ps` for stray/orphaned testcontainers and any orphaned `*.test.exe` processes (`Get-Process -Name "*.test"`) left over from an earlier interrupted run, and clean those up before proceeding — this happened once during Phase 3's own execution and was resolved safely by stopping the stray container and killing the orphaned process.

Run: `cd orchestrator && go test ./internal/db/... -v`
Expected: PASS — all tests, no regressions.

- [ ] **Step 7: Commit**

```bash
git add orchestrator/internal/db/networkcontrolexpectation_store.go orchestrator/internal/db/networkcontrolexpectation_store_test.go orchestrator/internal/testutil/testdb.go orchestrator/cmd/server/main.go
git commit -m "feat(networkefficacy): add schema and store layer for control-expectation imports"
```

---

### Task 6: Control-Expectation Import HTTP API & Permission

**Files:**
- Create: `orchestrator/internal/api/networkcontrolexpectation_handlers.go`
- Test: `orchestrator/internal/api/networkcontrolexpectation_handlers_test.go`
- Modify: `orchestrator/internal/auth/permissions.go:231` (const block), `:291` (RoleAdmin map), `:307` (RoleAnalyst map) — re-grep these exact line numbers at task start, they may have shifted since this plan was written if any other work landed on `main` first.
- Modify: `orchestrator/internal/api/routes.go:252-253` (GET routes), `:425-426` (POST routes) — re-grep at task start for the same reason.
- Modify: `orchestrator/internal/api/rbac_matrix_test.go:65-66` (GET rows), `:211-212` (POST rows) — re-grep at task start for the same reason.

**Interfaces:**
- Consumes: `networkefficacy.ControlExpectationImport`/`ControlExpectation`/`ExpectedBlock`/`ExpectedAlert`/`MaxExpectationsPerImport` (Task 1 + this task's own new constant), `db.InsertNetworkControlExpectationImport`/`GetNetworkControlExpectationImport`/`ListNetworkControlExpectationImports` (Task 5), existing `jsonError`/`respond`/`respondStatus`/`newID`/`auth.ClaimsFrom`/`h.auditLog`/`h.db` helpers (unchanged).
- Produces: `auth.CanImportNetworkControlExpectation Permission`, `networkefficacy.MaxExpectationsPerImport = 500` (added to Task 1's package in this task, since it is a safety constant the validator needs — see Step 3), `func (h *Handler) CreateNetworkControlExpectationImport(w http.ResponseWriter, r *http.Request)`, `func (h *Handler) ListNetworkControlExpectationImports(w http.ResponseWriter, r *http.Request)`, `func (h *Handler) GetNetworkControlExpectationImport(w http.ResponseWriter, r *http.Request)`, routes `POST /api/network-control-expectations`, `GET /api/network-control-expectations`, `GET /api/network-control-expectations/{id}`.

- [ ] **Step 1: Write the failing tests**

```go
// orchestrator/internal/api/networkcontrolexpectation_handlers_test.go
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/networkefficacy"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

func validControlExpectationImportBody() map[string]any {
	return map[string]any{
		"sourceType": "manual-declared",
		"expectations": []map[string]any{
			{"flowSourceCidr": "10.0.1.0/24", "flowDestCidr": "10.0.2.0/24", "flowPort": 443, "flowProtocol": "tcp", "expectedAction": "block", "controlProduct": "opnsense"},
		},
	}
}

func networkControlExpectationImportReq(t *testing.T, pool *pgxpool.Pool, body map[string]any) *http.Request {
	t.Helper()
	userID := seedUser(t, pool, "nce-op", "pw12345678", string(auth.RoleAnalyst), true)
	b, _ := json.Marshal(body)
	return authedRequest(t, http.MethodPost, "/api/network-control-expectations", bytes.NewReader(b), auth.RoleAnalyst, userID)
}

func TestCreateNetworkControlExpectationImport_ValidImportPersists(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		req := networkControlExpectationImportReq(t, pool, validControlExpectationImportBody())
		rec := callAuthed(h.CreateNetworkControlExpectationImport, req)
		if rec.Code != http.StatusCreated {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var resp networkefficacy.ControlExpectationImport
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if resp.ID == "" {
			t.Fatal("want non-empty id")
		}
	})
}

func TestCreateNetworkControlExpectationImport_EmptyExpectationsRejected(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		body := validControlExpectationImportBody()
		body["expectations"] = []map[string]any{}
		req := networkControlExpectationImportReq(t, pool, body)
		rec := callAuthed(h.CreateNetworkControlExpectationImport, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
	})
}

func TestCreateNetworkControlExpectationImport_InvalidCIDRRejected(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		body := validControlExpectationImportBody()
		body["expectations"] = []map[string]any{{"flowSourceCidr": "not-a-cidr", "flowDestCidr": "10.0.2.0/24", "flowPort": 443, "expectedAction": "block"}}
		req := networkControlExpectationImportReq(t, pool, body)
		rec := callAuthed(h.CreateNetworkControlExpectationImport, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
	})
}

func TestCreateNetworkControlExpectationImport_InvalidExpectedActionRejected(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		body := validControlExpectationImportBody()
		body["expectations"] = []map[string]any{{"flowSourceCidr": "10.0.1.0/24", "flowDestCidr": "10.0.2.0/24", "flowPort": 443, "expectedAction": "redirect"}}
		req := networkControlExpectationImportReq(t, pool, body)
		rec := callAuthed(h.CreateNetworkControlExpectationImport, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, body = %s -- \"redirect\" is not a declared ExpectedControlAction", rec.Code, rec.Body.String())
		}
	})
}

func TestCreateNetworkControlExpectationImport_InvalidPortRejected(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		body := validControlExpectationImportBody()
		body["expectations"] = []map[string]any{{"flowSourceCidr": "10.0.1.0/24", "flowDestCidr": "10.0.2.0/24", "flowPort": 70000, "expectedAction": "block"}}
		req := networkControlExpectationImportReq(t, pool, body)
		rec := callAuthed(h.CreateNetworkControlExpectationImport, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
	})
}

func TestCreateNetworkControlExpectationImport_OversizedBodyRejectedBeforeFullDecode(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		userID := seedUser(t, pool, "nce-op-oversize", "pw12345678", string(auth.RoleAnalyst), true)
		oversized := []byte(`{"sourceType":"` + strings.Repeat("x", maxNetworkControlExpectationImportRequestBytes+1) + `"}`)
		req := authedRequest(t, http.MethodPost, "/api/network-control-expectations", bytes.NewReader(oversized), auth.RoleAnalyst, userID)
		rec := callAuthed(h.CreateNetworkControlExpectationImport, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
	})
}

func TestCreateNetworkControlExpectationImport_ImportedByIsServerControlled(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		userID := seedUser(t, pool, "nce-op-spoof", "pw12345678", string(auth.RoleAnalyst), true)
		body := validControlExpectationImportBody()
		body["importedBy"] = "spoofed-user"
		b, _ := json.Marshal(body)
		req := authedRequest(t, http.MethodPost, "/api/network-control-expectations", bytes.NewReader(b), auth.RoleAnalyst, userID)
		rec := callAuthed(h.CreateNetworkControlExpectationImport, req)
		if rec.Code != http.StatusCreated {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var resp networkefficacy.ControlExpectationImport
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
		got, err := db.GetNetworkControlExpectationImport(context.Background(), pool, resp.ID)
		if err != nil {
			t.Fatalf("lookup: %v", err)
		}
		if got.ImportedBy != userID {
			t.Fatalf("ImportedBy = %q, want %q (the authenticated caller, not the spoofed body value)", got.ImportedBy, userID)
		}
	})
}

func TestListAndGetNetworkControlExpectationImport_RoundTrip(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		req := networkControlExpectationImportReq(t, pool, validControlExpectationImportBody())
		createRec := callAuthed(h.CreateNetworkControlExpectationImport, req)
		if createRec.Code != http.StatusCreated {
			t.Fatalf("create status = %d, body = %s", createRec.Code, createRec.Body.String())
		}
		var created networkefficacy.ControlExpectationImport
		if err := json.Unmarshal(createRec.Body.Bytes(), &created); err != nil {
			t.Fatalf("decode create: %v", err)
		}

		listReq := authedRequest(t, http.MethodGet, "/api/network-control-expectations", nil, auth.RoleViewer, "")
		listRec := callAuthed(h.ListNetworkControlExpectationImports, listReq)
		if listRec.Code != http.StatusOK {
			t.Fatalf("list status = %d, body = %s", listRec.Code, listRec.Body.String())
		}

		getReq := authedRequest(t, http.MethodGet, "/api/network-control-expectations/"+created.ID, nil, auth.RoleViewer, "")
		getReq = withURLParam(getReq, "id", created.ID)
		getRec := callAuthed(h.GetNetworkControlExpectationImport, getReq)
		if getRec.Code != http.StatusOK {
			t.Fatalf("get status = %d, body = %s", getRec.Code, getRec.Body.String())
		}
	})
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go vet ./internal/api/...`
Expected: FAIL — `h.CreateNetworkControlExpectationImport`, `maxNetworkControlExpectationImportRequestBytes` undefined.

- [ ] **Step 3: Add `MaxExpectationsPerImport` to Task 1's package**

In `orchestrator/internal/networkefficacy/types.go`, add near the top of the file (after the imports, before `ExpectedControlAction`):
```go
// MaxExpectationsPerImport caps the number of declared expectations a
// single ControlExpectationImport may carry, mirroring the 500-scale
// cap every prior phase's import uses.
const MaxExpectationsPerImport = 500
```

- [ ] **Step 4: Add the permission**

Re-grep `orchestrator/internal/auth/permissions.go` for the current exact text and line numbers of `CanImportNetworkTopology`'s const declaration and its two `rolePermissions` map entries before editing (they may have shifted). As of this plan's writing:

Replace:
```go
	CanImportNetworkTopology Permission = "network-topology:import"
)
```
with:
```go
	CanImportNetworkTopology Permission = "network-topology:import"

	// network-control-expectation:import gates importing a declared set
	// of expected firewall/IDS-IPS control outcomes (Network BAS Phase
	// 4) -- same placement as CanImportNetworkTopology, for the same
	// reason.
	CanImportNetworkControlExpectation Permission = "network-control-expectation:import"
)
```

Add `CanImportNetworkControlExpectation: true,` alongside the existing `CanImportNetworkTopology: true,` line inside the `RoleAdmin` map, and alongside the existing `CanImportNetworkPolicy: true, CanImportNetworkTopology: true,` line inside the `RoleAnalyst` map (both exact lines found by the re-grep above).

- [ ] **Step 5: Implement the handlers**

```go
// orchestrator/internal/api/networkcontrolexpectation_handlers.go
package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/networkefficacy"
)

// maxNetworkControlExpectationImportRequestBytes mirrors every prior
// phase's import cap -- a real expectation document can be as large as
// a real policy or topology document.
const maxNetworkControlExpectationImportRequestBytes = 5 << 20

// CreateNetworkControlExpectationImport -- POST /api/network-control-expectations.
func (h *Handler) CreateNetworkControlExpectationImport(w http.ResponseWriter, r *http.Request) {
	var req networkefficacy.ControlExpectationImport
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxNetworkControlExpectationImportRequestBytes)).Decode(&req); err != nil {
		jsonError(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if err := validateControlExpectationImport(&req); err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}

	var importedBy string
	if c, ok := auth.ClaimsFrom(r.Context()); ok && c != nil {
		importedBy = c.UserID
	}
	req.ID = newID()
	req.ImportedBy = importedBy

	if err := db.InsertNetworkControlExpectationImport(r.Context(), h.db, &req); err != nil {
		h.auditLog(r, "networkcontrolexpectation.import", "", map[string]any{"error": err.Error()}, "error")
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	h.auditLog(r, "networkcontrolexpectation.import", req.ID, map[string]any{"expectationCount": len(req.Expectations)}, "ok")
	respondStatus(w, req, http.StatusCreated)
}

func validateControlExpectationImport(imp *networkefficacy.ControlExpectationImport) error {
	if len(imp.Expectations) == 0 {
		return fmt.Errorf("at least one expectation is required")
	}
	if len(imp.Expectations) > networkefficacy.MaxExpectationsPerImport {
		return fmt.Errorf("too many expectations — got %d, max %d", len(imp.Expectations), networkefficacy.MaxExpectationsPerImport)
	}
	for i, exp := range imp.Expectations {
		if _, _, err := net.ParseCIDR(exp.FlowSourceCIDR); err != nil {
			return fmt.Errorf("expectations[%d]: invalid flowSourceCidr %q", i, exp.FlowSourceCIDR)
		}
		if _, _, err := net.ParseCIDR(exp.FlowDestCIDR); err != nil {
			return fmt.Errorf("expectations[%d]: invalid flowDestCidr %q", i, exp.FlowDestCIDR)
		}
		if exp.FlowPort < 1 || exp.FlowPort > 65535 {
			return fmt.Errorf("expectations[%d]: flowPort must be between 1 and 65535", i)
		}
		if exp.ExpectedAction != networkefficacy.ExpectedBlock && exp.ExpectedAction != networkefficacy.ExpectedAlert {
			return fmt.Errorf("expectations[%d]: expectedAction must be %q or %q", i, networkefficacy.ExpectedBlock, networkefficacy.ExpectedAlert)
		}
	}
	return nil
}

// ListNetworkControlExpectationImports -- GET /api/network-control-expectations.
func (h *Handler) ListNetworkControlExpectationImports(w http.ResponseWriter, r *http.Request) {
	limit := 20
	if l, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && l > 0 && l <= 100 {
		limit = l
	}
	imports, err := db.ListNetworkControlExpectationImports(r.Context(), h.db, limit)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if imports == nil {
		imports = []*networkefficacy.ControlExpectationImport{}
	}
	respond(w, imports)
}

// GetNetworkControlExpectationImport -- GET /api/network-control-expectations/{id}.
func (h *Handler) GetNetworkControlExpectationImport(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	imp, err := db.GetNetworkControlExpectationImport(r.Context(), h.db, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			jsonError(w, "network control expectation import not found", http.StatusNotFound)
			return
		}
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respond(w, imp)
}
```

- [ ] **Step 6: Wire routes and RBAC matrix rows**

Re-grep `orchestrator/internal/api/routes.go` and `orchestrator/internal/api/rbac_matrix_test.go` for the current exact text of the last network-related GET/POST lines before editing. As of this plan's writing, in `routes.go`, after:
```go
		r.Get("/api/network-topology-imports/{id}", h.GetNetworkTopologyImport)
```
add:
```go
		r.Get("/api/network-control-expectations", h.ListNetworkControlExpectationImports)
		r.Get("/api/network-control-expectations/{id}", h.GetNetworkControlExpectationImport)
```

After:
```go
		r.With(auth.RequirePermission(auth.CanImportNetworkTopology)).Post("/api/network-topology-imports", h.CreateNetworkTopologyImport)
```
add:
```go
		r.With(auth.RequirePermission(auth.CanImportNetworkControlExpectation)).Post("/api/network-control-expectations", h.CreateNetworkControlExpectationImport)
```

In `rbac_matrix_test.go`, after:
```go
	{http.MethodGet, "/api/network-topology-imports/{id}", tierAny, ""},
```
add:
```go
	{http.MethodGet, "/api/network-control-expectations", tierAny, ""},
	{http.MethodGet, "/api/network-control-expectations/{id}", tierAny, ""},
```

After:
```go
	{http.MethodPost, "/api/network-topology-imports", tierPermission, auth.CanImportNetworkTopology},
```
add:
```go
	{http.MethodPost, "/api/network-control-expectations", tierPermission, auth.CanImportNetworkControlExpectation},
```

(The `/api/network-paths` POST route and RBAC row stay exactly where they are — this task inserts before them, not after, since this plan's own verify endpoint, Task 7, is a distinct new route added in its own step.)

- [ ] **Step 7: Run tests to verify they pass**

Check memory headroom first (`Get-CimInstance Win32_OperatingSystem`); clean up stray containers/processes if free memory is below ~1GB (same check as Task 5 Step 6).

Run: `cd orchestrator && go build ./... && go test ./internal/api/... -run 'TestCreateNetworkControlExpectationImport|TestListAndGetNetworkControlExpectationImport|TestRBACMatrix_NoDrift' -v`
Expected: PASS — 9/9.

- [ ] **Step 8: Commit**

```bash
git add orchestrator/internal/api/networkcontrolexpectation_handlers.go orchestrator/internal/api/networkcontrolexpectation_handlers_test.go orchestrator/internal/networkefficacy/types.go orchestrator/internal/auth/permissions.go orchestrator/internal/api/routes.go orchestrator/internal/api/rbac_matrix_test.go
git commit -m "feat(networkefficacy): add control-expectation import HTTP API and CanImportNetworkControlExpectation permission"
```

---

### Task 7: Control-Expectation Verification HTTP API

**Files:**
- Create: `orchestrator/internal/api/networkcontrolverification_handlers.go`
- Test: `orchestrator/internal/api/networkcontrolverification_handlers_test.go`
- Modify: `orchestrator/internal/api/routes.go` (one more POST route, after Task 6's own addition and before/after the existing `/api/network-paths` line — order between the two does not matter, this plan adds it immediately after `/api/network-paths`'s own line for a stable anchor)
- Modify: `orchestrator/internal/api/rbac_matrix_test.go` (one more POST row, same anchor)

**Interfaces:**
- Consumes: everything from Tasks 1-6, plus the existing `db.GetNetworkPolicyImport`, `db.GetNetworkDiscoveryRun`, `db.ListNetworkObservationsByRun` (all existing, unmodified, same reuse Phase 3's `internal/api/networkpath_handlers.go` already established for this exact pattern).
- Produces: `func (h *Handler) VerifyNetworkControlExpectations(w http.ResponseWriter, r *http.Request)`, route `POST /api/network-control-verifications`.

- [ ] **Step 1: Write the failing tests**

```go
// orchestrator/internal/api/networkcontrolverification_handlers_test.go
package api

import (
	"bytes"
	"encoding/json"
	"net"
	"net/http"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/networkefficacy"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

func createTestControlExpectationImport(t *testing.T, h *Handler, pool *pgxpool.Pool, body map[string]any) string {
	t.Helper()
	req := networkControlExpectationImportReq(t, pool, body)
	rec := callAuthed(h.CreateNetworkControlExpectationImport, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create control expectation import: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var created struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return created.ID
}

// runDiscoveryAgainstOpenPort triggers a real network discovery run
// against a freshly-opened local TCP listener, returning the run's ID.
// Mirrors internal/api/networkpath_handlers_test.go's own precedent for
// getting a real NetworkObservation into a test without a live remote
// host.
func runDiscoveryAgainstOpenPort(t *testing.T, h *Handler, pool *pgxpool.Pool, host string, port int) string {
	t.Helper()
	discoveryReq := networkDiscoveryReq(t, pool, map[string]any{"targets": []map[string]any{{"host": host, "port": port}}})
	rec := callAuthed(h.TriggerNetworkDiscoveryRun, discoveryReq)
	if rec.Code != http.StatusCreated {
		t.Fatalf("trigger discovery: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		RunID string `json:"runId"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode discovery: %v", err)
	}
	return resp.RunID
}

func TestVerifyNetworkControlExpectations_BlockExpectationWithMatchingEvidence_Met(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		vp := testVantagePoint()
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret).WithNetworkVantagePoint(vp)

		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		defer ln.Close()
		openPort := ln.Addr().(*net.TCPAddr).Port

		runID := runDiscoveryAgainstOpenPort(t, h, pool, "127.0.0.1", openPort)
		expID := createTestControlExpectationImport(t, h, pool, map[string]any{
			"sourceType": "manual-declared",
			"expectations": []map[string]any{
				{"flowSourceCidr": "10.0.1.0/24", "flowDestCidr": "127.0.0.0/24", "flowPort": openPort, "flowProtocol": "tcp", "expectedAction": "block", "controlProduct": "opnsense"},
			},
		})

		body := map[string]any{
			"expectationImportId": expID,
			"discoveryRunId":      runID,
			"firewallEvidence": []map[string]any{
				{"sourceIp": "10.0.1.5", "destIp": "127.0.0.1", "port": openPort, "protocol": "tcp", "action": "block", "timestamp": "2026-10-14T10:00:00Z", "source": "synthetic"},
			},
		}
		b, _ := json.Marshal(body)
		userID := seedUser(t, pool, "ncv-op-met", "pw12345678", string(auth.RoleAnalyst), true)
		req := authedRequest(t, http.MethodPost, "/api/network-control-verifications", bytes.NewReader(b), auth.RoleAnalyst, userID)
		rec := callAuthed(h.VerifyNetworkControlExpectations, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var results []networkefficacy.EfficacyResult
		if err := json.Unmarshal(rec.Body.Bytes(), &results); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(results) != 1 || results[0].Verdict != networkefficacy.VerdictMet {
			t.Fatalf("got %+v, want one result with verdict met", results)
		}
	})
}

func TestVerifyNetworkControlExpectations_NoMatchingObservation_InconclusiveWithoutCallingVerify(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		vp := testVantagePoint()
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret).WithNetworkVantagePoint(vp)

		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		defer ln.Close()
		openPort := ln.Addr().(*net.TCPAddr).Port

		// Discovery run observes 127.0.0.1, but the expectation declares
		// a completely different, unrelated destination flow -- no
		// observation will ever match it.
		runID := runDiscoveryAgainstOpenPort(t, h, pool, "127.0.0.1", openPort)
		expID := createTestControlExpectationImport(t, h, pool, map[string]any{
			"sourceType": "manual-declared",
			"expectations": []map[string]any{
				{"flowSourceCidr": "10.0.1.0/24", "flowDestCidr": "10.0.9.0/24", "flowPort": 443, "expectedAction": "block", "controlProduct": "opnsense"},
			},
		})

		body := map[string]any{"expectationImportId": expID, "discoveryRunId": runID}
		b, _ := json.Marshal(body)
		userID := seedUser(t, pool, "ncv-op-nomatch", "pw12345678", string(auth.RoleAnalyst), true)
		req := authedRequest(t, http.MethodPost, "/api/network-control-verifications", bytes.NewReader(b), auth.RoleAnalyst, userID)
		rec := callAuthed(h.VerifyNetworkControlExpectations, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var results []networkefficacy.EfficacyResult
		if err := json.Unmarshal(rec.Body.Bytes(), &results); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(results) != 1 || results[0].Verdict != networkefficacy.VerdictInconclusive {
			t.Fatalf("got %+v, want one inconclusive result", results)
		}
		if results[0].Reason == "" {
			t.Fatal("want a non-empty reason explaining no observation matched")
		}
	})
}

func TestVerifyNetworkControlExpectations_UnknownExpectationImportReturns404(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		body := map[string]any{"expectationImportId": "nonexistent-id", "discoveryRunId": "also-nonexistent"}
		b, _ := json.Marshal(body)
		userID := seedUser(t, pool, "ncv-op-404", "pw12345678", string(auth.RoleAnalyst), true)
		req := authedRequest(t, http.MethodPost, "/api/network-control-verifications", bytes.NewReader(b), auth.RoleAnalyst, userID)
		rec := callAuthed(h.VerifyNetworkControlExpectations, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
	})
}

func TestVerifyNetworkControlExpectations_MissingRequiredFieldsRejected(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		body := map[string]any{"expectationImportId": "some-id"}
		b, _ := json.Marshal(body)
		userID := seedUser(t, pool, "ncv-op-missing", "pw12345678", string(auth.RoleAnalyst), true)
		req := authedRequest(t, http.MethodPost, "/api/network-control-verifications", bytes.NewReader(b), auth.RoleAnalyst, userID)
		rec := callAuthed(h.VerifyNetworkControlExpectations, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
	})
}

func TestVerifyNetworkControlExpectations_OversizedBodyRejected(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		userID := seedUser(t, pool, "ncv-op-oversize", "pw12345678", string(auth.RoleAnalyst), true)
		oversized := make([]byte, maxNetworkControlVerificationRequestBytes+1)
		for i := range oversized {
			oversized[i] = 'x'
		}
		req := authedRequest(t, http.MethodPost, "/api/network-control-verifications", bytes.NewReader(oversized), auth.RoleAnalyst, userID)
		rec := callAuthed(h.VerifyNetworkControlExpectations, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
	})
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go vet ./internal/api/...`
Expected: FAIL — `h.VerifyNetworkControlExpectations`, `maxNetworkControlVerificationRequestBytes` undefined.

- [ ] **Step 3: Implement**

```go
// orchestrator/internal/api/networkcontrolverification_handlers.go
package api

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/networkefficacy"
	"github.com/audspect/bas/internal/networkgraph"
	"github.com/audspect/bas/internal/networkpolicy"
)

// maxNetworkControlVerificationRequestBytes is larger than Phase 3's
// 64KiB path-query cap, since this body also carries inline firewall/
// IDS evidence arrays, not just a flow query.
const maxNetworkControlVerificationRequestBytes = 1 << 20

const (
	maxFirewallEvidencePerVerification = 2000
	maxIDSEvidencePerVerification      = 2000
)

type networkControlVerificationRequest struct {
	ExpectationImportID string                          `json:"expectationImportId"`
	DiscoveryRunID       string                          `json:"discoveryRunId"`
	PolicyImportID       string                          `json:"policyImportId,omitempty"`
	FirewallEvidence     []networkefficacy.FirewallEvidence `json:"firewallEvidence,omitempty"`
	IDSEvidence          []networkefficacy.IDSEvidence      `json:"idsEvidence,omitempty"`
}

// VerifyNetworkControlExpectations -- POST /api/network-control-verifications.
// Correlates every expectation in the named import against inline-
// supplied, normalized firewall/IDS evidence and Network BAS's own
// Phase 1 observations (+ optional Phase 2A policy evaluation). Not
// persisted -- computed fresh on every call, same pattern as
// FindNetworkPaths.
func (h *Handler) VerifyNetworkControlExpectations(w http.ResponseWriter, r *http.Request) {
	var req networkControlVerificationRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxNetworkControlVerificationRequestBytes)).Decode(&req); err != nil {
		jsonError(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.ExpectationImportID == "" || req.DiscoveryRunID == "" {
		jsonError(w, "expectationImportId and discoveryRunId are required", http.StatusBadRequest)
		return
	}
	if len(req.FirewallEvidence) > maxFirewallEvidencePerVerification {
		jsonError(w, "too many firewallEvidence entries", http.StatusBadRequest)
		return
	}
	if len(req.IDSEvidence) > maxIDSEvidencePerVerification {
		jsonError(w, "too many idsEvidence entries", http.StatusBadRequest)
		return
	}

	expImport, err := db.GetNetworkControlExpectationImport(r.Context(), h.db, req.ExpectationImportID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			jsonError(w, "network control expectation import not found", http.StatusNotFound)
			return
		}
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if _, err := db.GetNetworkDiscoveryRun(r.Context(), h.db, req.DiscoveryRunID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			jsonError(w, "network discovery run not found", http.StatusNotFound)
			return
		}
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	observations, err := db.ListNetworkObservationsByRun(r.Context(), h.db, req.DiscoveryRunID)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	var policyImport *networkpolicy.PolicyImport
	if req.PolicyImportID != "" {
		policyImport, err = db.GetNetworkPolicyImport(r.Context(), h.db, req.PolicyImportID)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				jsonError(w, "network policy import not found", http.StatusNotFound)
				return
			}
			jsonError(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}

	firewallProvider := networkefficacy.NewSyntheticFirewallProvider(req.FirewallEvidence)
	idsProvider := networkefficacy.NewFixtureIDSProvider(req.IDSEvidence)
	window := networkefficacy.TimeWindow{Start: time.Now().Add(-24 * time.Hour), End: time.Now().Add(24 * time.Hour)}

	results := make([]networkefficacy.EfficacyResult, 0, len(expImport.Expectations))
	for _, exp := range expImport.Expectations {
		obs, found := selectMatchingObservation(exp, observations)
		if !found {
			results = append(results, networkefficacy.EfficacyResult{
				Expectation: exp,
				Verdict:     networkefficacy.VerdictInconclusive,
				Reason:      "no corresponding Network BAS observation found for this flow in the specified discovery run",
			})
			continue
		}

		var policyEval *networkpolicy.PolicyEvaluation
		if policyImport != nil {
			evals, err := networkpolicy.EvaluatePolicyMatrix(policyImport, []networkpolicy.PolicyQuery{{SourceCIDR: exp.FlowSourceCIDR, DestCIDR: exp.FlowDestCIDR, Port: exp.FlowPort, Protocol: exp.FlowProtocol}})
			if err == nil && len(evals) == 1 {
				policyEval = &evals[0]
			}
		}

		results = append(results, networkefficacy.VerifyControlExpectation(exp, obs, policyEval, firewallProvider, idsProvider, window))
	}

	respond(w, results)
}

// selectMatchingObservation finds the NetworkObservation whose Target
// falls within exp's declared flow (dest-CIDR containment, exact port,
// case-insensitive protocol). When more than one matches, the one with
// the most recent Provenance.ObservedAt wins -- same "latest wins" rule
// orchestration.go applies to evidence selection, for the same reason.
// Duplicates the small CIDR-containment check already duplicated
// independently in internal/networktopology and
// internal/networkpolicy; this package has no dependency on either.
func selectMatchingObservation(exp networkefficacy.ControlExpectation, observations []networkgraph.NetworkObservation) (networkgraph.NetworkObservation, bool) {
	var best networkgraph.NetworkObservation
	found := false
	for _, obs := range observations {
		if obs.Target.Port != exp.FlowPort {
			continue
		}
		if exp.FlowProtocol != "" && !strings.EqualFold(obs.Target.Protocol, exp.FlowProtocol) {
			continue
		}
		if !destCIDRContains(exp.FlowDestCIDR, obs.Target.Host) {
			continue
		}
		if !found || obs.Provenance.ObservedAt.After(best.Provenance.ObservedAt) {
			best = obs
			found = true
		}
	}
	return best, found
}

func destCIDRContains(cidr, host string) bool {
	if cidr == "" || host == "" {
		return false
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}
	return ipNet.Contains(ip)
}
```

Note: this file needs `"strings"` imported alongside the others shown above for `strings.EqualFold` in `selectMatchingObservation` — add it to the `import` block.

- [ ] **Step 4: Wire the route and RBAC row**

Re-grep for the current exact text before editing. In `orchestrator/internal/api/routes.go`, after:
```go
		r.With(auth.RequirePermission(auth.CanImportNetworkTopology)).Post("/api/network-paths", h.FindNetworkPaths)
```
add:
```go
		r.With(auth.RequirePermission(auth.CanImportNetworkControlExpectation)).Post("/api/network-control-verifications", h.VerifyNetworkControlExpectations)
```

In `orchestrator/internal/api/rbac_matrix_test.go`, after:
```go
	{http.MethodPost, "/api/network-paths", tierPermission, auth.CanImportNetworkTopology},
```
add:
```go
	{http.MethodPost, "/api/network-control-verifications", tierPermission, auth.CanImportNetworkControlExpectation},
```

- [ ] **Step 5: Run tests to verify they pass**

Check memory headroom first (same check as prior tasks).

Run: `cd orchestrator && go build ./... && go test ./internal/api/... -run 'TestVerifyNetworkControlExpectations|TestRBACMatrix_NoDrift' -v`
Expected: PASS — 6/6.

- [ ] **Step 6: Run the full network+RBAC regression set**

Run: `cd orchestrator && go vet ./... && go test ./internal/api/... -run 'Network|RBACMatrix' -v`
Expected: PASS — all tests, no regressions.

- [ ] **Step 7: Commit**

```bash
git add orchestrator/internal/api/networkcontrolverification_handlers.go orchestrator/internal/api/networkcontrolverification_handlers_test.go orchestrator/internal/api/routes.go orchestrator/internal/api/rbac_matrix_test.go
git commit -m "feat(networkefficacy): add network control expectation verification HTTP API"
```

---

## Execution Handoff

This plan uses **Native/inline execution** (pre-selected — standing convention for this session, same as the Phase 1, Phase 2A, and Phase 3 plans): implement every task directly in this session, then one fresh reviewer on the most capable model checks the whole branch at the end.

**REQUIRED SUB-SKILL:** Use superpowers:executing-plans.
