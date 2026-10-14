# Network BAS Mastery Phase 5: DNS, Protocol & Infrastructure Security — Design Spec

## 1. Goal

Phase 5 adds real DNS-security and protocol/transport-security testing to Network BAS Mastery — this is Phase 5 of the master spec's 7-phase roadmap (`docs/superpowers/specs/2026-10-13-network-bas-architecture-design.md`, lines 127-139). Today, `internal/dnssink` only detects DNS-tunnel exfiltration (data moving *through* DNS as a covert channel) — nothing in the codebase tests whether DNS resolution itself, or the transport-layer protocols a target exposes, are configured securely. This phase builds four concrete, bounded, evidence-backed checks:

1. **Open-resolver test** — does a DNS resolver answer recursive queries from an untrusted position that it shouldn't.
2. **DNSSEC chain validation** — does a domain's own DNSSEC deployment validate correctly from a defined trust anchor.
3. **Cleartext-protocol detection** — does a declared cleartext endpoint (e.g. a plaintext-HTTP or Telnet/FTP port) have anything listening at all.
4. **TLS certificate validation** — is a target's presented TLS certificate currently valid, hostname-matched, and chain-trusted, negotiated at a currently-acceptable TLS version floor.

Weak-TLS-version/cipher *downgrade* testing (actively probing whether a server can be forced to negotiate down) and resolver-AD-flag validation (testing whether a *specific resolver* claims to validate DNSSEC, as opposed to testing the *domain's own* DNSSEC deployment) are both explicitly deferred — see §8.

## 2. Reuse / No-Rebuild Boundary

`internal/dnssink` (the DNS-tunnel-exfiltration UDP listener + reassembler) and the `dlp-exfiltration-dns-tunnel` scenario are **not modified, not imported, not duplicated**. Confirmed by reading `internal/dnssink/listener.go`: it is a passive receiver of exfil-encoded DNS queries, with zero DNS-resolution-behavior or DNS-security-posture logic of any kind — there is no overlap risk, and this phase's DNS work is a distinct network-connectivity-domain capability, exactly as the master spec requires.

Also not modified: `internal/networkgraph`'s existing types (`Target`, `VantagePoint`, `NetworkObservation`, `cloudgraph.PathState`/`Provenance`) and the Phase 1 discovery-run store/API. This phase reuses them read-only, following the same reuse discipline as Phases 2A-4.

`github.com/miekg/dns` is already a dependency (via `internal/dnssink`) and is reused for DNSSEC record parsing and signature verification — no new DNS library is introduced.

## 3. Package Structure

Three new packages, following this codebase's established `network*` naming convention and its "narrow, single-responsibility sibling packages" precedent (every prior phase added 1-2 new packages rather than one large generic one):

- **`internal/networksecurity`** — a tiny leaf package, no logic. Holds `SecurityState` (`Secure`/`Insecure`/`Unknown`) and `SecurityCheckResult{Target networkgraph.Target, State SecurityState, Reason string, Provenance cloudgraph.Provenance}`. Imported read-only by `networktransport` (both its checks) and is the *only* new type shared across the DNS and transport check families.
- **`internal/networkdns`** — the open-resolver test (produces `networkgraph.NetworkObservation`, reusing `cloudgraph.PathState` exactly as Phase 1 does) and DNSSEC chain validation (produces its own `DNSSECResult`/`DNSSECState`, kept deliberately separate from `networksecurity.SecurityState` — see §4.2).
- **`internal/networktransport`** — cleartext-protocol detection and TLS certificate validation, both producing `networksecurity.SecurityCheckResult`.

### Why DNS and transport checks don't share one state vocabulary

Of the four checks, only the open-resolver test is genuinely *reachability*-shaped (does an arbitrary external query get answered — the same shape as Phase 1's `TCPReachabilityProbe`, just against a DNS payload instead of a bare handshake), so it alone reuses `cloudgraph.PathState` unchanged. The other three ask "is what's here configured correctly," not "is this reachable," so forcing them onto `PathState` would be the same kind of category error Phase 4 avoided by introducing its own `EfficacyVerdict` rather than stretching `PathState` to mean "met/not-met." Within those three, DNSSEC validation needs a fourth state (`Invalid`, distinct from `Insecure`) that `SecurityState`'s three values cannot faithfully represent — see §4.2 — so it gets its own enum rather than sharing `SecurityState` with the two transport checks.

## 4. Data Model

### 4.1 `internal/networksecurity` (shared by both transport checks)

```go
package networksecurity

import (
	"github.com/audspect/bas/internal/cloudgraph"
	"github.com/audspect/bas/internal/networkgraph"
)

type SecurityState string

const (
	Secure  SecurityState = "secure"  // the tested requirement was positively demonstrated
	Insecure SecurityState = "insecure" // a specific weakness was positively demonstrated
	Unknown SecurityState = "unknown"  // the evidence cannot support either conclusion
)

type SecurityCheckResult struct {
	Target     networkgraph.Target   `json:"target"`
	State      SecurityState         `json:"state"`
	Reason     string                `json:"reason,omitempty"`
	Provenance cloudgraph.Provenance `json:"provenance"`
}
```

**Shared rule across every check in this spec:** `Secure` means the tested requirement was positively demonstrated; `Insecure` means a specific weakness was positively demonstrated; `Unknown` means the evidence cannot support either conclusion. No check in this phase ever promotes an absence of bad evidence into `Secure` — that would be exactly the kind of false assurance the master spec's "encrypted-traffic visibility limitations are recorded explicitly, not silently skipped" requirement exists to prevent.

### 4.2 `internal/networkdns`

```go
package networkdns

import (
	"time"

	"github.com/audspect/bas/internal/cloudgraph"
	"github.com/audspect/bas/internal/networkgraph"
)

type CheckType string

const (
	CheckOpenResolver CheckType = "open-resolver"
	CheckDNSSEC       CheckType = "dnssec"
)

// DNSCheckRequest declares one check. Target and QueryDomain are always
// explicitly caller-supplied, never auto-discovered or inferred --
// mirrors networkgraph.Target's own "no discovery-of-targets" rule.
// Target is required for CheckOpenResolver (the resolver being tested)
// and must be omitted for CheckDNSSEC -- DNSSEC chain validation
// resolves the chain itself starting from the root trust anchor and
// has no declared target host/port at all. Validated at the API layer;
// a CheckDNSSEC request carrying a non-zero Target is rejected rather
// than silently ignored, so a caller can never mistake it for having
// any effect.
type DNSCheckRequest struct {
	CheckType   CheckType           `json:"checkType"`
	Target      networkgraph.Target `json:"target,omitempty"` // required for open-resolver, must be omitted for dnssec
	QueryDomain string              `json:"queryDomain"`      // the domain to query (open-resolver) or validate (dnssec)
}

// DNSSECState mirrors the four validation states RFC 4035 defines for a
// validating resolver (Secure/Insecure/Bogus/Indeterminate), using this
// codebase's own plainer wording for Bogus ("Invalid") and Indeterminate
// ("Unknown"). Kept separate from networksecurity.SecurityState because
// that type's three values cannot faithfully represent the distinction
// between "legitimately unsigned" and "signature validation failed" --
// collapsing them would hide a real security-relevant difference.
type DNSSECState string

const (
	DNSSECSecure   DNSSECState = "secure"   // the chain validates successfully to the trust anchor
	DNSSECInsecure DNSSECState = "insecure" // legitimately unsigned, or a proven-insecure delegation (authenticated denial of a DS record)
	DNSSECInvalid  DNSSECState = "invalid"  // signatures or delegation data fail validation
	DNSSECUnknown  DNSSECState = "unknown"  // timeout, incomplete response, unsupported case, or insufficient evidence
)

type DNSSECResult struct {
	Domain     string                `json:"domain"`
	State      DNSSECState           `json:"state"`
	Reason     string                `json:"reason,omitempty"`
	Provenance cloudgraph.Provenance `json:"provenance"`
}

// DNSCheckResult is a tagged union: exactly one of Observation/DNSSEC is
// populated, selected by CheckType -- the two checks in this package
// produce genuinely different result shapes, so this avoids forcing a
// false shared shape on them.
type DNSCheckResult struct {
	CheckType   CheckType                       `json:"checkType"`
	Observation *networkgraph.NetworkObservation `json:"observation,omitempty"`
	DNSSEC      *DNSSECResult                    `json:"dnssec,omitempty"`
}
```

### 4.3 `internal/networktransport`

```go
package networktransport

import (
	"github.com/audspect/bas/internal/networkgraph"
)

type CheckType string

const (
	CheckCleartext CheckType = "cleartext"
	CheckCert      CheckType = "cert"
)

// TransportCheckRequest declares one check. For CheckCleartext, Target
// identifies the cleartext endpoint being tested (e.g. host:80 for an
// HTTP-redirect policy, host:21 for FTP) -- declaring which disallowed
// cleartext protocol/port to test against is itself the policy
// declaration; no separate policy object is needed.
type TransportCheckRequest struct {
	CheckType CheckType           `json:"checkType"`
	Target    networkgraph.Target `json:"target"`
}
```

Both checks return `networksecurity.SecurityCheckResult` directly (§4.1); no additional wrapper type is needed since they already share one result shape.

## 5. Check Logic

### 5.1 Open-resolver test (`networkdns`, → `networkgraph.NetworkObservation` / `cloudgraph.PathState`)

Sends one bounded, single, normal-record-type (A) recursive UDP DNS query with the RD bit set, from the vantage point to `Target.Host:Target.Port` (conventionally 53), for the caller-supplied `QueryDomain`.

- Any real answer or referral comes back → `Observed` (misconfigured — it recursed when it shouldn't have, from this vantage point's position).
- `REFUSED` → `Blocked` (correctly restricted).
- Timeout or no response → `Unknown`, never `Blocked` — a timeout proves nothing, same discipline as `networkgraph.DialerProbe`.

### 5.2 DNSSEC chain validation (`networkdns`, → `DNSSECResult` / `DNSSECState`)

For the caller-supplied `QueryDomain`: starting from a hardcoded root-zone trust anchor constant (the current IANA-published root KSK — embedded in code, never fetched at runtime from an untrusted source), walk DS→DNSKEY→RRSIG from the anchor down through each delegation to the target domain, verifying each signature with `miekg/dns`'s RRSIG verification helpers (`RRSIG.Verify`) against the corresponding DNSKEY — never merely checking that a DNSKEY or RRSIG record *exists*, since presence alone proves nothing cryptographically.

- Every signature in the chain verifies → `DNSSECSecure`.
- A parent zone's signed NSEC/NSEC3 record *proves* (via authenticated denial of existence, itself signature-verified) that no DS record exists at a delegation point → `DNSSECInsecure` (legitimately unsigned, or a proven-insecure delegation). A missing DS record for any *other* reason (incomplete response, stripped in transit, unsupported NSEC3 parameters) is **not** assumed `DNSSECInsecure` — it falls through to `DNSSECUnknown`.
- Any signature in the chain fails cryptographic verification → `DNSSECInvalid`.
- Timeout, incomplete response, or an unsupported case (e.g. an algorithm this validator doesn't implement) → `DNSSECUnknown`.

Resolver-AD-flag validation (does *this specific resolver* claim to have validated DNSSEC for a query) is a different, later check — the AD flag is evidence supplied by the resolver, not independent proof the resolver validated correctly, and must never be conflated with this check's own independent chain validation. Deferred per §8.

### 5.3 Cleartext-protocol detection (`networktransport`, → `networksecurity.SecurityCheckResult`)

Connects to the declared cleartext endpoint (`Target.Host`/`Port`) and reads only whatever the service offers unprompted on connect — **no request is ever sent**, consistent with "no credential interception, no disruptive protocol abuse."

| Observation | Result |
|---|---|
| Connection actively refused (RST — nothing bound to that port at all) | `Secure` — the only path to `Secure`: there is genuinely nothing there to downgrade to |
| Timeout, no response | `Unknown` — proves nothing, same `DialerProbe` discipline |
| Connection succeeds, unprompted banner positively identifies the cleartext protocol | `Insecure` |
| Connection succeeds, response is a redirect, ambiguous, or unrecognized | `Unknown` — **a redirect alone does not prove no plaintext path exists** (sensitive requests could still be sent in the clear before any redirect is honored); this is deliberately conservative |

A successful TLS handshake on a *different* port (e.g. 443) is never treated as evidence that a *separate* cleartext endpoint (e.g. 80) enforces encryption — each declared endpoint is tested independently.

### 5.4 TLS certificate validation (`networktransport`, → `networksecurity.SecurityCheckResult`)

Dials TLS to `Target.Host:Target.Port` with `InsecureSkipVerify` set (so the certificate can be inspected without the handshake itself failing on an invalid cert), then checks expiry, hostname match, chain trust against system roots, and that the negotiated protocol version is at least TLS 1.2 (a floor, not an active downgrade probe — downgrade-resistance testing is deferred per §8).

- Valid expiry, hostname match, trusted chain, TLS ≥ 1.2 → `Secure`.
- Any single failure (expired, self-signed/untrusted, hostname mismatch, or negotiated below TLS 1.2) → `Insecure`, with the specific reason.
- Handshake fails entirely (refused, timeout, not a TLS service) → `Unknown`, never `Insecure` — can't assess what isn't there.

## 6. Orchestration & Persistence

These are active probes, not declare-then-verify-later evidence (unlike Phases 2A-4) — structurally closer to Phase 1's `RunDiscovery`. Each package gets its own trigger function and its own run-plus-results persistence, kept **separate from each other** (DNS and transport checks are never triggered together as one combined run — simpler to reason about and test):

- `networkdns.RunChecks(ctx, checks []DNSCheckRequest, vp networkgraph.VantagePoint) ([]DNSCheckResult, error)`. Tables: `dns_security_check_runs` (run metadata: id, requested_by, requested_at, status, vantage_point_id) + `dns_security_check_results` (one row per check: run_id, check_type, target jsonb, state, reason, provenance jsonb, domain).
- `networktransport.RunChecks(ctx, checks []TransportCheckRequest, vp networkgraph.VantagePoint) ([]networksecurity.SecurityCheckResult, error)`. Tables: `transport_security_check_runs` + `transport_security_check_results`.

Both reuse Phase 1's exact safety-cap discipline, re-declared per package with these values: `MaxChecksPerRun = 50` (same as Phase 1's `MaxTargetsPerRun`), `DefaultCheckTimeout = 5s` / `MaxCheckTimeout = 10s` (slightly more generous than Phase 1's 2s/5s, since DNSSEC chain-walking is several sequential DNS round-trips, not one bare TCP connect), `maxConcurrency = 10`, `MaxRunDuration = 60s` (vs. Phase 1's 30s, for the same reason). Both packages use the same vantage-point model (`networkgraph.VantagePoint`, fail-closed via `Configured()` if unset).

**API:** `POST /api/dns-security-checks` + `GET /api/dns-security-checks/{id}`, `POST /api/transport-security-checks` + `GET /api/transport-security-checks/{id}`. Both trigger endpoints are gated by whichever permission Phase 1's own `TriggerNetworkDiscoveryRun` uses today — triggering an active DNS/TLS probe is the same risk class as triggering a TCP discovery probe, so this phase reuses that permission rather than minting a new one. (The exact permission name is confirmed by reading `internal/api/networkdiscovery_handlers.go`/`routes.go` at plan-writing time, not guessed here.)

## 7. Safety Constraints

- Every `Target`, domain, and query parameter across all four checks is explicitly caller-supplied — never auto-discovered, never inferred from a prior result. Same rule `networkgraph.Target`'s own doc comment already states for Phase 1.
- No credential interception, no crafted payloads: cleartext detection only ever reads an unprompted banner or performs a bare connect, never sends a constructed request. DNS checks send only standard, single, bounded queries (normal record types, no amplification-shaped queries, no retries-as-abuse).
- Same bounded-concurrency/per-check-timeout/max-checks-per-run/max-run-duration caps as Phase 1's `RunDiscovery`, reused, not reinvented.
- Encrypted-traffic and incomplete-evidence limitations are surfaced as explicit `Unknown` + `Reason`, never silently dropped — built into every check's decision tree in §5.

## 8. Explicitly Out of Scope / Deferred

- **Resolver-AD-flag validation** — testing whether a *specific* resolver claims to have validated DNSSEC (as opposed to §5.2's independent chain validation of the domain itself). A separate, later check; never conflated with §5.2.
- **Active weak-TLS-version/cipher downgrade testing** — actively probing whether a server *can be forced* to negotiate down to an obsolete version/cipher. §5.4's TLS-version floor is a passive observation of what was actually negotiated, not an active downgrade attempt; the dedicated downgrade-resistance check requires explicit support for distinguishing a confirmed weak configuration from an inconclusive handshake, deferred until that distinction can be built correctly.
- **Any positive proof of cleartext-access enforcement beyond "nothing is listening."** A redirect, an upgrade negotiation, or any other observed behavior short of a confirmed RST stays `Unknown` — see §5.3's rationale.
- Any modification to `internal/dnssink`, the `dlp-exfiltration-dns-tunnel` scenario, or `internal/networkgraph`'s existing types/probe/store/API beyond read-only reuse.

## 9. Acceptance Criteria (from the master spec, §5)

Each new check type has a documented expected-vs-observed behavior and records `PathState`-equivalent confidence (§4-5 above). Encrypted-traffic visibility limitations are recorded explicitly, not silently skipped (§5.3, §7). Tests cover at least one DNS-resolution-behavior check (open-resolver, §5.1) and one insecure-protocol/weak-transport check (cleartext detection, §5.3) end-to-end, plus the two additional checks this design adds (DNSSEC chain validation, TLS certificate validation) — all four execute end-to-end with evidence-backed, scope-limited results, clearly separated from the existing DNS-tunnel exfiltration detection capability (§2).
