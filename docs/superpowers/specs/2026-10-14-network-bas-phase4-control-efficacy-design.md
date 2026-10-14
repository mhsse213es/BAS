# Network BAS Mastery Phase 4: Network Security Control Efficacy — Design Spec

## 1. Goal

Phase 4 answers a question Phases 1–3 cannot: given that Network BAS has already modeled and tested a network flow (Phase 2A's policy evaluation, Phase 1's live observation, Phase 3's multi-hop path), **did the real security control product (firewall, IDS/IPS) actually do what it was expected to do for that flow?** This is the master architecture spec's "Network Security Control Efficacy" domain (`docs/superpowers/specs/2026-10-13-network-bas-architecture-design.md`, §4, Phase 4), extending `internal/detectverify`'s existing provider pattern into firewall/IDS-IPS coverage — priority-ordered ahead of NDR, NAC, SWG/SASE/SSE, and VPN per that spec's locked ordering.

This phase delivers a complete, fixture-provable evidence pipeline and a new orchestration/API layer. It does **not** deliver a live OPNsense or Suricata connection, or any commercial vendor adapter — those are explicitly deferred (§8).

## 2. Why This Is Not `detectverify.VerifyRun`

`internal/detectverify.Connector` (`Verify`/`TestConnection`) and its `VerifyRun` orchestration exist to check whether a SIEM/EDR product generated an alert for a scenario step's executed ATT&CK technique. `VerifyRequest` is built around a single host and a `TechniqueID`; there is no concept of a network flow (source, destination, port, protocol) anywhere in that package, and Network BAS Phases 1–3 are not scenario-step-driven at all — they are their own standalone API surface (`/api/network-discovery-runs`, `/api/network-policy-evaluations`, `/api/network-paths`).

Forcing network-flow semantics into `VerifyRequest`/`VerifyRun` would either corrupt a working, orthogonal system or require awkward field overloading. Phase 4 therefore adds a new, independent orchestration entry point. `detectverify.Connector`, `VerifyRequest`, `VerifyResult`, `VerifyRun`, and every existing EDR/SIEM provider implementation are **not modified** by this phase.

The trigger for a Phase 4 check is Network BAS's own evidence — a Phase 2A `PolicyEvaluation` (what the modeled policy predicts) plus a Phase 1 `NetworkObservation` (what connectivity was actually observed) — correlated against a real control product's own evidence for the same flow. Scenario-step-driven network-control expectations (a scenario step declaring "this step's flow should be blocked by firewall X") are an explicitly deferred follow-on; nothing like that exists in `scenario.Engine` today and building it is a separately-scoped project.

## 3. The Four Evidence Dimensions

A policy evaluation plus a connectivity observation do not, by themselves, prove a firewall or IDS/IPS correctly detected or prevented anything. A permitted TCP connection may be entirely legitimate; an IDS may detect a malicious payload without blocking the connection. Phase 4 therefore keeps four evidence dimensions explicitly separate, never collapsed into one judgment:

| Evidence | What it establishes |
|---|---|
| Policy evaluation (Phase 2A, optional) | What the modeled network policy predicts, and why this expectation was declared |
| Network observation (Phase 1, required) | What connectivity test actually occurred, from which vantage point, when |
| Firewall/IDS-IPS evidence | What the security product itself recorded or enforced |
| Efficacy verdict | Whether the product met an **explicitly declared expected outcome** |

The expected outcome is its own first-class declaration — `ControlExpectation` — never inferred from the policy evaluation. Missing or unparseable control-product evidence is represented as `inconclusive` with a reason; it is never silently read as a control failure. This mirrors a lesson learned the hard way in Phase 2A (a stand-in value silently satisfying evidence the system didn't actually have, caught as a Critical finding in that phase's final review) and in Phase 3 (a missing route must never read as `Blocked`): **an absence of evidence is not evidence of absence**, and this phase must not repeat that mistake in a new shape.

## 4. Package: `internal/networkefficacy`

New package, following the established `network*` naming convention (`networkgraph`, `networkpolicy`, `networkcorrelation`, `networktopology`, `networkpath`). Imports `internal/networkpolicy` (for `PolicyEvaluation`, read-only) and `internal/networkgraph` (for `NetworkObservation`, read-only) and `internal/cloudgraph` (for `PathState` values, read-only, reused exactly as every prior phase reuses it — no new `PathState` value is introduced). Does **not** import `internal/detectverify`, and nothing in `detectverify` imports this package.

### 4.1 Data Model

```go
package networkefficacy

import (
	"encoding/json"
	"time"

	"github.com/audspect/bas/internal/cloudgraph"
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
// live proof that a real product behaved a certain way (per
// network.txt §9, the master spec's own non-negotiable rule).
type EvidenceSource string

const (
	SourceSynthetic EvidenceSource = "synthetic"       // hand-built test data, proves Audspect's own logic only
	SourceFixture   EvidenceSource = "recorded-fixture" // a real product's recorded output, replayed deterministically
	SourceLive      EvidenceSource = "live"             // a live query against a real, reachable product
)

// ControlExpectation is one declared "what should this control have
// done" for one flow.
type ControlExpectation struct {
	ID             string                 `json:"id,omitempty"`
	FlowSourceCIDR string                 `json:"flowSourceCidr"`
	FlowDestCIDR   string                 `json:"flowDestCidr"`
	FlowPort       int                    `json:"flowPort"`
	FlowProtocol   string                 `json:"flowProtocol,omitempty"`
	ExpectedAction ExpectedControlAction  `json:"expectedAction"`
	ControlProduct string                 `json:"controlProduct"` // "opnsense" | "suricata" | ... ; free text, not an enum -- new products are added without a schema change
	Note           string                 `json:"note,omitempty"`
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

// IDSEvidence is one IDS/IPS alert's normalized shape (e.g. parsed
// from a Suricata EVE JSON "alert" event).
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
type EfficacyResult struct {
	Expectation      ControlExpectation               `json:"expectation"`
	PolicyEval       *networkpolicy.PolicyEvaluation   `json:"policyEvaluation,omitempty"`
	Observation      networkgraph.NetworkObservation   `json:"observation"`
	FirewallEvidence *FirewallEvidence                 `json:"firewallEvidence,omitempty"`
	IDSEvidence      *IDSEvidence                      `json:"idsEvidence,omitempty"`
	Verdict          EfficacyVerdict                    `json:"verdict"`
	Reason           string                             `json:"reason,omitempty"`
	Contradiction    string                             `json:"contradiction,omitempty"`
}
```

`Observation` is required (not a pointer): it is what proves the test flow was actually attempted, and it is load-bearing for contradiction detection (§4.3). `PolicyEval` remains optional context — the "why" behind the declared expectation, not required to compute a verdict.

### 4.2 Evidence Collection

Two small, separate provider interfaces. Firewall and IDS/IPS evidence are deliberately not unified into one interface or one evidence type, since they come from different products and must stay separately attributable — an IDS alert must never be mistaken for proof a firewall blocked a flow.

```go
type Flow struct {
	SourceCIDR, DestCIDR string
	Port                 int
	Protocol             string
}

type TimeWindow struct {
	Start, End time.Time
}

// FirewallEvidenceProvider supplies firewall evidence for a flow and
// time window. A provider error means collection/parsing failed --
// distinct from a successful search that found nothing.
type FirewallEvidenceProvider interface {
	FirewallEvidenceFor(flow Flow, window TimeWindow) ([]FirewallEvidence, error)
}

// IDSEvidenceProvider supplies IDS/IPS evidence for a flow and time
// window, with the same error-vs-empty-result distinction.
type IDSEvidenceProvider interface {
	IDSEvidenceFor(flow Flow, window TimeWindow) ([]IDSEvidence, error)
}
```

**First implementations are deliberately asymmetric, matching the build-order decision in §8:**

- **IDS (Suricata EVE JSON): a real parser, built now.** `ParseSuricataEVE(r io.Reader) ([]eveRecord, error)` reads newline-delimited EVE JSON, keeps only `event_type:"alert"` records, and extracts `src_ip`/`dest_ip`/`src_port`/`dest_port`/`proto`/`timestamp`/`alert.signature`/`alert.severity` into the normalized `IDSEvidence` shape (§4.1 — `SourceIP`/`DestIP`/`Port`/`Protocol` fields carry the concrete event address so a provider can filter against `flow` without round-tripping through `RawEvent`). `FixtureIDSProvider` wraps a slice of parsed records and implements `IDSEvidenceFor` by filtering to records whose `SourceIP`/`DestIP` fall within `flow.SourceCIDR`/`flow.DestCIDR` (containment via `net.ParseCIDR`/`Contains`, duplicating the small CIDR-containment check already duplicated independently in `networktopology` and `networkpolicy`, per this codebase's established "duplicate small match logic across domain packages, never share it" convention), whose `Port`/`Protocol` match exactly (protocol case-insensitive, below), and whose `Timestamp` falls within `window`. This is real EVE-JSON-shaped parsing logic, tested against recorded fixture files, so the exact same code path will run against a live Suricata EVE JSON output file later — only the `io.Reader` source changes.
- **Firewall (OPNsense/generic): synthetic only, for now.** `SyntheticFirewallProvider` wraps an in-memory slice of hand-built `FirewallEvidence` values with the same flow/window filtering logic. No real OPNsense log-format parser exists yet; building one is explicitly deferred to §8 until real lab log/API access exists.

Protocol matching in both providers is case-insensitive (`strings.EqualFold`), since real logs and operator-declared `FlowProtocol` values are not guaranteed to agree on case (e.g. `"TCP"` vs `"tcp"`) — same looseness `CorroborateSegmentation` (Phase 3) already applies to its own best-effort string matching.

### 4.3 Orchestration

```go
// VerifyControlExpectation checks one declared expectation against the
// real control product's own evidence, correlating it with Network
// BAS's own flow evidence for the same flow. Independent of
// detectverify.VerifyRun by design (§2) -- no shared code path.
func VerifyControlExpectation(
	exp ControlExpectation,
	observation networkgraph.NetworkObservation,
	policyEval *networkpolicy.PolicyEvaluation,
	firewallProvider FirewallEvidenceProvider,
	idsProvider IDSEvidenceProvider,
	window TimeWindow,
) EfficacyResult
```

No `error` return: every failure mode in the verdict table below already resolves to `Verdict: VerdictInconclusive` with a `Reason`, so a separate error channel would be vestigial — exactly the same shape `ComposeHop` (Phase 3, `internal/networkpath/compose.go`) already settled on for the same reason. A `FirewallEvidenceProvider`/`IDSEvidenceProvider` implementation's own error is caught inside this function and converted to `Inconclusive`, never propagated.

**Verdict rule — deliberately asymmetric between `block` and `alert` expectations**, because the two evidence sources have different reliability characteristics in practice: a firewall's permitted/default traffic is not guaranteed to be logged at all (a documented OPNsense configuration behavior), whereas a correctly-operating IDS's EVE JSON stream is a comprehensive record of everything it inspected.

| Expectation | Provider returns an error | Provider succeeds, no matching evidence | Provider succeeds, match found |
|---|---|---|---|
| `block` | `inconclusive` — "firewall evidence collection failed: \<err\>" | **`inconclusive`** — "no firewall log entry found for this flow; absence of a log entry is not proof of a permitted connection, since not every flow is guaranteed to be logged" | `action=="block"` → **`met`**; `action=="permit"` → **`not-met`** — "firewall evidence shows this flow was permitted, expected block" |
| `alert` | `inconclusive` — "IDS evidence collection/parsing failed: \<err\>" | **`not-met`** — "no IDS alert found for this flow in the window; expected an alert to be raised" | **`met`** |

A provider error and a clean empty result are never conflated: the first means "we don't know," the second means "we looked and found nothing," and those carry different weight for a `block` expectation (ambiguous, since firewalls under-log) versus an `alert` expectation (a reliable negative, since EVE JSON is comprehensive when collection succeeds).

**Multiple matching evidence records.** A provider may legitimately return more than one record for the same flow and window (retries, duplicate log lines, a state change mid-test). When more than one record matches, the most recent by `Timestamp` is the one used for the verdict table above — a later event reflects the control's final state for that flow more faithfully than an earlier one. Duplicate identical records (same `Action`/`AlertName`) never change the outcome regardless of which one is picked. This is a real scenario the required test coverage (§6) must exercise directly, not infer from a single-record test passing.

**Multiple matching observations.** When an expectation's flow (by dest-CIDR containment, port, protocol) matches more than one `NetworkObservation` from the supplied discovery run, the handler selects the one whose `Target` falls inside the flow's CIDR with the most recent `Provenance.ObservedAt` — same "latest wins" rule as evidence selection, for the same reason.

**Zero matching observations.** `Observation` is a required, non-pointer field on `EfficacyResult` (§4.1) precisely because `VerifyControlExpectation` must never be called without one — there is no meaningful zero value for "a flow we have no corresponding test evidence for at all." When the handler finds no `NetworkObservation` matching an expectation's flow in the supplied discovery run, it does not call `VerifyControlExpectation` for that expectation; it constructs the `EfficacyResult` directly with `Verdict: VerdictInconclusive`, `Reason: "no corresponding Network BAS observation found for this flow in the specified discovery run"`, and a zero-value `Expectation` field populated from the declared expectation (so the caller still knows which expectation this refers to).

**Contradiction detection** is independent of the verdict table above, and never changes `Verdict`. It fires only when `FirewallEvidence` has a match, by comparing the firewall's own claimed action against the independently-observed `networkgraph.NetworkObservation.State` for the same flow:

```go
// detectContradiction flags a disagreement between the firewall's own
// claimed action and our independently-observed reachability for the
// same flow. It is additive context, never a verdict override.
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

This does not apply to `alert` expectations: an IDS alerting on a payload and a connection succeeding are not mutually exclusive (an IDS/IPS can alert without blocking), so there is no reachability-vs-alert conflict to detect.

### 4.4 Persistence & API

Mirrors Phase 2A (`internal/networkpolicy` + its HTTP handlers) and Phase 3 (`internal/networktopology`/`internal/networkpath` + theirs) exactly: a persisted, auditable "import" document for declared expectations, plus a stateless "verify" endpoint that computes results fresh from supplied evidence. `EfficacyResult` is never persisted.

**New table `network_control_expectations`**, same shape discipline as `network_policy_imports`/`network_topology_imports`: `id`, `source_type`, `imported_by`, `imported_at`, `config_version`, `limitations text[]`, `expectations_data jsonb` (holds `[]ControlExpectation`).

**New permission** `CanImportNetworkControlExpectation = "network-control-expectation:import"` (granted to Admin + Analyst, same placement as `CanImportNetworkPolicy`/`CanImportNetworkTopology`), reused for both endpoints below rather than minting a second permission per verb — same precedent Phase 2A and Phase 3 both established.

**Endpoints:**
- `POST /api/network-control-expectations` — import (create). Validates: at least one expectation; each expectation's `FlowSourceCIDR`/`FlowDestCIDR` parse as valid CIDRs; `ExpectedAction` is one of the two declared constants; `FlowPort` is in `1..65535`. `http.MaxBytesReader`-capped from the start, same cap class as the prior phases' import endpoints.
- `GET /api/network-control-expectations` / `GET .../{id}` — list/get, `tierAny`.
- `POST /api/network-control-verifications` — verify. Body: `{expectationImportId, discoveryRunId, policyImportId?, firewallEvidence: [...], idsEvidence: [...]}`. The handler loads the named `ControlExpectationImport` and `NetworkDiscoveryRun`'s observations (and `PolicyImport` if supplied), wraps the inline-supplied `firewallEvidence`/`idsEvidence` arrays in `SyntheticFirewallProvider`/`FixtureIDSProvider`-shaped in-memory providers, then calls `VerifyControlExpectation` once per expectation in the import — matching each expectation's flow to the relevant observation by CIDR containment (same pattern `FindNetworkPaths` already uses to resolve a host to a zone). Returns `[]EfficacyResult`, computed fresh on every call, `http.MaxBytesReader`-capped (small, structured body, same class as `POST /api/network-paths`).

This keeps the HTTP layer itself provider-neutral: it has no idea whether the evidence array came from a hand-built synthetic fixture or a real Suricata EVE JSON file already parsed upstream — it consumes the same normalized wire shape either way, so adding a live connector later is additive to this endpoint, not a rewrite of it.

## 5. First Target Product & Evidence-Source Build Order

Per the master spec's priority ordering ("firewall and IDS/IPS first"), the lab reference stack is **OPNsense (firewall) + Suricata (IDS/IPS)** — chosen specifically because it proves the complete efficacy workflow end-to-end without requiring a commercial appliance, not because it is the easiest API to reach. OPNsense firewall-event evidence and Suricata IDS-alert evidence are kept separately identified throughout (§4.1, §4.2) so one is never mistaken for proof of the other.

Build order (locked, do not re-litigate):
1. Normalized evidence pipeline against **recorded Suricata EVE JSON fixtures** — real parsing logic (§4.2), proving flow correlation, timestamps, missing fields, duplicate events, and efficacy-verdict computation without owning a real IDS.
2. **Synthetic fixtures** for firewall permit/deny events, clearly labeled `synthetic` (§4.1's `EvidenceSource`) — proving Audspect's own permit/deny correlation and edge cases, not real firewall efficacy.
3. A live lab integration (Suricata first, in an isolated lab; OPNsense once its event collection and a test environment are available) is **optional and deferred** — not part of this phase's deliverable.
4. Commercial vendor adapters (Palo Alto PAN-OS traffic/threat-log APIs, then Fortinet FortiGate) are **deferred** until representative logs, a supported API, or real lab/customer access exists. Neither is claimed as verified before then.

## 6. Required Test Coverage (locked)

Automated tests must prove Audspect correctly distinguishes all four of these, each directly, not inferred from other passing tests:
1. Expected `block` + matching block evidence → `met`.
2. Expected `alert` + matching IDS alert → `met`.
3. Unexpected permit (evidence found, wrong action) **or** a clean, successful search that found no matching alert for an `alert` expectation → `not-met`.
4. No matching event for a `block` expectation, or any evidence-collection/parsing failure regardless of expected action → `inconclusive`, with a `Reason`.

Plus, directly exercising §4.3's contradiction detector: a `met` block verdict whose `Observation` shows the flow was nonetheless reachable, and a `not-met`-via-permit verdict whose `Observation` shows the flow was nonetheless blocked — both must set `Contradiction` to a non-empty string without changing `Verdict`.

Fixtures validate Audspect's own logic; only live product evidence validates a real control's actual behavior. These are not interchangeable claims, and no test or report may conflate them (`EvidenceSource` exists specifically to keep this distinction visible on every evidence record, per §4.1).

## 7. Safety Constraints

- Validate using controlled, authorized lab traffic only (per the master spec's `network.txt` §9, non-negotiable).
- Phase 4 must never depend on changing a customer's real firewall rules, or on sending disruptive traffic, to prove a control works.
- Never claim a real security product was tested when only a `synthetic` or `recorded-fixture` provider was used (`EvidenceSource` makes this mechanically checkable, not just a documentation promise).
- Missing control-product evidence is recorded as `inconclusive` with a reason, never as a detection/prevention failure, until the evidence source's own operability is independently confirmed (same principle as the master spec's Phase 4 section states for EDR/SIEM providers, applied identically here).

## 8. Explicitly Out of Scope / Deferred

- Any real/live connection to OPNsense, Suricata, Palo Alto, or Fortinet. This phase delivers the evidence pipeline and verdict logic, fixture-provable end-to-end; live connectors are a follow-on once real lab/API access exists.
- A real OPNsense firewall-log parser (only a synthetic in-memory provider exists in this phase).
- Scenario-step-driven network-control expectations (a scenario step declaring its own expected control behavior) — requires a new `scenario.Engine` primitive that does not exist today; separately scoped.
- NDR, NAC, SWG/SASE/SSE, and VPN provider categories — later in the master spec's locked priority order, not this phase.
- Any modification to `internal/detectverify`, its `Connector` interface, `VerifyRequest`/`VerifyResult`, `VerifyRun`, or any existing EDR/SIEM provider implementation.

## 9. Acceptance Criteria

Given a declared expected network-control outcome, a corresponding Network BAS flow observation, and available vendor evidence, Audspect produces a provenance-linked efficacy verdict — or explicitly reports why the evidence is insufficient.

Concretely: `POST /api/network-control-expectations` persists a set of declared expectations; `POST /api/network-control-verifications` correlates them against inline-supplied, normalized firewall/IDS evidence (from either synthetic fixtures or real recorded Suricata EVE JSON) and Network BAS's own Phase 1 observation + optional Phase 2A policy evaluation, returning a `met`/`not-met`/`inconclusive` verdict per expectation with full evidence-dimension provenance and, where applicable, a contradiction flag — end to end, provable entirely from fixtures, with zero modification to any existing `detectverify` code.
