# Network BAS Mastery Phase 7A: OT/ICS Safety — Design Spec

## 1. Goal

Validate IT/OT network-boundary separation per `network.txt` §2.2 and the master spec's Phase 7 (lines 155-167), scoped to exactly the master spec's own exit bar: "at least one OT/ICS-safe test... under documented stricter safeguards" — not a new industrial-protocol-visibility subsystem, and not healthcare or regulatory mapping (7B/7C, separate phases).

Two genuinely new capabilities, both safety-first:

1. **Boundary-violation detection**: a declared-architecture constraint ("any path between an IT zone and a declared OT zone must visit a required DMZ/jump zone") checked against whatever Phase 3's existing route search actually finds — catching unauthorised routes into critical production/engineering zones, never baked into the routing graph itself.
2. **Active-test safety gating**: every existing capability in this codebase that performs real network I/O against a target host (Phase 1's `TriggerNetworkDiscoveryRun`, Phase 5A's `TriggerDNSSecurityCheckRun`, Phase 5B's `TriggerTransportSecurityCheckRun`) must refuse to run against a target that resolves into a declared-sensitive OT zone unless the request carries explicit authorization and a non-empty sign-off — per `network.txt` §9's "stricter safeguards for industrial... environments" and "explicit authorisation... for every run."

Industrial-protocol parsing (Modbus/DNP3/etc.) and industrial-asset discovery are explicitly deferred (§10).

## 2. Relationship to Existing Phases

`internal/otsafety` never modifies `networktopology`, `networkpath`, `networkgraph`, `networkdns`, or `networktransport`. It imports `networktopology.Zone`/`RoutePath`/`ZoneForHost` read-only, and references zone names as plain strings elsewhere — the same cross-reference-by-name convention every prior phase in this initiative uses. No new type is added to any existing package; the three active-probe endpoints gain new *optional* request fields only (§6), and their existing behavior when those fields are omitted is unchanged byte-for-byte.

Boundary-violation detection needs no new route-search engine. Unlike Phase 6B (which added VPN tunnels — a new kind of edge Phase 3's graph doesn't know about), OT/ICS boundary validation uses the exact same physical zone/route graph Phase 3 already searches. There is nothing new to union into the adjacency, so `POST /api/network-paths` is extended directly (§6) rather than given a new sibling endpoint — the only genuinely new logic is a `ValidateRequiredTransits` function, structurally identical to Phase 6B's `ValidateMandatoryTransit` but re-implemented fresh in this package (§4.3), per this project's standing discipline of never reaching into a previously-shipped phase's package for unrelated reasons.

## 3. Why a Separate Import, Not New Fields on `TopologyImport`

Sensitivity-tier and required-transit data comes from a different real-world source than zone/route topology data (an OT/ICS risk assessment or segmentation-design document, not a network diagram) — the same argument every prior phase's independent-import packages already embody. `OTSafetyImport` is therefore its own import type, referencing `networktopology` zones by name only, never by direct struct reference or foreign key.

One consequence, stated honestly rather than silently assumed: because the two imports are independently sourced, `otsafety`'s own import validation cannot check that a `SensitiveZone.ZoneName` or a `RequiredTransit.ViaZone` actually matches a zone declared in some real `networktopology.TopologyImport` — it can only check that the string is non-empty. This gap is recorded as a `Limitations` entry at import time, not assumed away, mirroring Phase 6B's `remoteaccess` import exactly.

## 4. Package: `internal/otsafety`

### 4.1 Data Model

```go
package otsafety

import "time"

const (
	// TierOT is the single sensitivity tier for this increment --
	// deliberately not a broader taxonomy (e.g. Engineering/Production/
	// Supervisory as distinct values) until a real need for finer
	// granularity appears. network.txt §2.2 names several network
	// types, but the master spec's own Phase 7 exit bar is "at least
	// one OT/ICS-safe test" -- a single tier clears that bar honestly
	// without inventing unused categories.
	TierOT = "ot"
)

// SensitiveZone declares that a networktopology zone (referenced by
// name only, never cross-validated -- see §3) requires the stricter
// active-testing safeguards of §4.4. Tier is currently always TierOT;
// the field exists so a future increment can add tiers without a
// breaking schema change.
type SensitiveZone struct {
	ZoneName string `json:"zoneName"`
	Tier     string `json:"tier"` // TierOT
	Note     string `json:"note,omitempty"`
}

// RequiredTransit declares that any path between FromZone and ToZone,
// in either direction, must visit ViaZone -- e.g. "any path between
// the corporate zone and the OT zone must pass through the DMZ zone."
// This is a declared-architecture constraint, validated against
// whatever the route search actually finds (§4.3), never baked into
// the routing graph itself -- structurally identical to
// remoteaccess.MandatoryTransit, re-implemented fresh here rather than
// imported, per this project's standing cross-phase-isolation
// discipline (§2). Direction-agnostic matching is built in from the
// start, incorporating Phase 6B's own final-review lesson rather than
// re-learning it.
type RequiredTransit struct {
	CanonicalID string `json:"canonicalId"`
	FromZone    string `json:"fromZone"`
	ToZone      string `json:"toZone"`
	ViaZone     string `json:"viaZone"`
	Note        string `json:"note,omitempty"`
}

// OTSafetyImport is one auditable, versioned snapshot -- the same
// shape discipline as remoteaccess.RemoteAccessImport /
// networktopology.TopologyImport.
type OTSafetyImport struct {
	ID               string            `json:"id,omitempty"`
	SourceType       string            `json:"sourceType"`
	ImportedBy       string            `json:"importedBy,omitempty"`
	ImportedAt       time.Time         `json:"importedAt,omitempty"`
	ConfigVersion    string            `json:"configVersion,omitempty"`
	SensitiveZones   []SensitiveZone   `json:"sensitiveZones"`
	RequiredTransits []RequiredTransit `json:"requiredTransits,omitempty"`
	Limitations      []string          `json:"limitations,omitempty"`
}
```

### 4.1.1 Safety Caps

```go
const (
	MaxSensitiveZonesPerImport   = 500
	MaxRequiredTransitsPerImport = 500
)
```

### 4.2 Import Validation

Enforced at the API validation layer (mirroring `validateRemoteAccessImport`), not inside the `otsafety` package itself:

- Every `SensitiveZone.Tier` must equal `TierOT` (the only declared constant) — an unrecognized value is rejected, never silently accepted.
- `ZoneName` (on `SensitiveZone`) and `FromZone`/`ToZone`/`ViaZone` (on `RequiredTransit`) must be non-empty strings. They are **not** cross-checked against a real `networktopology.TopologyImport`'s declared zones (§3) — this limitation is itself required to appear in the import's `Limitations`.
- Any `SensitiveZones`/`RequiredTransits` present requires the import's top-level `Limitations` to be non-empty, mirroring Phase 6B's identical requirement.

### 4.3 Boundary-Violation Detection

```go
// TransitViolation is evidence that a found route between a
// RequiredTransit's FromZone and ToZone (in either direction) never
// visited ViaZone.
type TransitViolation struct {
	Transit RequiredTransit          `json:"transit"`
	Route   networktopology.RoutePath `json:"route"`
	Note    string                    `json:"note"`
}

// ValidateRequiredTransits checks each route against every
// RequiredTransit whose FromZone/ToZone match the route's own
// endpoints in EITHER order (a boundary requirement holds regardless
// of which zone a query started from -- see Phase 6B's own
// final-review finding), returning one TransitViolation per route
// that bypasses ViaZone. A route that does not match a transit's
// endpoints (in either order) at all is not a candidate for that rule
// -- it is not a bypass, it is simply unrelated. Purely additive: it
// never removes a route from the caller's own result set, only
// annotates which ones violate a declared constraint.
func ValidateRequiredTransits(routes []networktopology.RoutePath, transits []RequiredTransit) []TransitViolation
```

### 4.4 Active-Test Authorization Check

```go
// ActiveTestAuthorization is the per-request authorization a caller
// must supply when any named target resolves into a declared
// SensitiveZone. Authorized alone is not sufficient -- SignOff must
// also be non-empty, mirroring every other "Limitations must be
// non-empty" discipline in this initiative.
type ActiveTestAuthorization struct {
	Authorized bool   `json:"authorized"`
	SignOff    string `json:"signOff,omitempty"`
}

// CheckActiveTestAuthorization resolves each target host to a zone
// via networktopology.ZoneForHost (reused, unmodified). If any
// resolved zone matches a SensitiveZone.ZoneName in safety, auth must
// have Authorized == true and a non-empty SignOff, or an error naming
// every matching sensitive zone is returned -- the caller (§6) turns
// that into a hard 400, not a downgrade-to-passive. A target that does
// not resolve to any known zone at all, or resolves to a zone absent
// from safety.SensitiveZones, is never gated -- this only ever fails
// closed where there is positive evidence of OT-zone membership,
// never as a blanket new requirement on every caller.
func CheckActiveTestAuthorization(targetHosts []string, topo *networktopology.TopologyImport, safety *OTSafetyImport, auth *ActiveTestAuthorization) error
```

## 5. Evidence Composition — Extends `/api/network-paths`, No New Composition Package

`networkpath.ComposeHop`/`AggregatePath` are reused completely unchanged (§2) — boundary-violation detection adds no new per-hop evidence semantics, only a separate, additive `ValidateRequiredTransits` pass over whatever routes Phase 3's existing search already found. `POST /api/network-paths` gains one new optional request field, `otSafetyImportId`; when supplied, the handler calls `ValidateRequiredTransits` over the composed routes after the existing, unmodified route-search-and-composition logic runs, and attaches any violations to the response as additive data (`transitViolations`), never altering a `PathResult`'s `State`. When `otSafetyImportId` is omitted (every caller today), the endpoint's behavior and response shape are unchanged.

## 6. Safety-Gating Integration Across Active-Probe Endpoints

`POST /api/network-discovery-runs` (`TriggerNetworkDiscoveryRun`), `POST /api/dns-security-checks` (`TriggerDNSSecurityCheckRun`), and `POST /api/transport-security-checks` (`TriggerTransportSecurityCheckRun`) each gain the same two new optional fields:

```go
type activeTestSafetyContext struct {
	TopologyImportID        string                    `json:"topologyImportId,omitempty"`
	OTSafetyImportID        string                    `json:"otSafetyImportId,omitempty"`
	ActiveTestAuthorization *otsafety.ActiveTestAuthorization `json:"activeTestAuthorization,omitempty"`
}
```

When both `TopologyImportID` and `OTSafetyImportID` are supplied, the handler loads both imports and calls `otsafety.CheckActiveTestAuthorization` with every target host present in the request, before any probing begins — for `TriggerNetworkDiscoveryRun` and `TriggerTransportSecurityCheckRun` that means every `Target.Host` across `Targets`/`Checks`; for `TriggerDNSSecurityCheckRun` it means every non-empty `Target.Host` across `Checks` only (a `dnssec`-type check carries no IP target at all, just a `QueryDomain` — it has nothing to resolve to a zone and is therefore never gated, the same "no resolvable target" case as Review Focus #2, not a special case). A non-nil error rejects the entire request with 400, naming the sensitive zone(s) that triggered it — nothing runs. On success with a sensitive-zone match, the sign-off is recorded via the existing `h.auditLog` call already present on each of these three handlers, alongside the run/check's own ID, so there is a traceable record of who authorized active testing against a sensitive zone and why. When either field is omitted (every existing caller, today), the check is skipped entirely and behavior is unchanged.

This increment does not add any new evidence-retention or tamper-evidence subsystem — `network.txt` §9's "tamper-evident integrity mechanisms" line belongs to a later, separate phase (network.txt's own "Enterprise Assurance and Continuous Regression" concept, distinct from this master-spec Phase 7). The audit-log entry is the full extent of traceability in this increment.

## 7. Persistence & API

```go
// internal/db/otsafety_store.go -- same pattern as every prior
// EnsureXSchema/InsertX/GetX/ListX store this session.
func EnsureOTSafetyImportSchema(ctx context.Context, pool *pgxpool.Pool) error
func InsertOTSafetyImport(ctx context.Context, pool *pgxpool.Pool, imp *otsafety.OTSafetyImport) error
func GetOTSafetyImport(ctx context.Context, pool *pgxpool.Pool, id string) (*otsafety.OTSafetyImport, error)
func ListOTSafetyImports(ctx context.Context, pool *pgxpool.Pool, limit int) ([]*otsafety.OTSafetyImport, error)
```

- `POST /api/ot-safety-imports`, `GET /api/ot-safety-imports`, `GET /api/ot-safety-imports/{id}` — validate-then-insert shape identical to `CreateRemoteAccessImport`. New permission `auth.CanImportOTSafetyConfig`, granted to `RoleAdmin` and `RoleAnalyst`, same placement as every other import permission.
- `POST /api/network-paths` — extended per §5 (`otSafetyImportId` request field, `transitViolations` response field), not a new endpoint.
- `POST /api/network-discovery-runs`, `POST /api/dns-security-checks`, `POST /api/transport-security-checks` — each extended per §6 with the three new optional fields and the pre-execution authorization check.

## 8. Review Focus

1. A zone marked sensitive with **no** `RequiredTransit` declared at all must still gate active probing against it, but must never manufacture a spurious boundary violation — the two gates (§4.3 boundary detection, §4.4 active-test authorization) are independent and must never be conflated.
2. A target host that **does not resolve to any declared zone at all** (via `networktopology.ZoneForHost`) must fail *open* on the authorization gate — identical to the "no topology import supplied" case — never reject a request solely because the topology import happens not to cover every host named.
3. A multi-target request where **only one** target resolves to a sensitive zone must still gate the entire request — not require every named target to match before the check applies.
4. `ActiveTestAuthorization` supplied with `Authorized: true` when **no target actually touches a sensitive zone** must be harmless and must never become an error — over-cautious callers are never penalized.
5. Boundary-bypass detection in the **reverse query direction** gets its own dedicated test from the start (`ValidateRequiredTransits` is direction-agnostic by design, §4.3) — this project's own standing lesson from Phase 6B's final review, applied proactively rather than re-learned.

## 9. Safety Constraints

- Industrial-protocol parsing (Modbus/DNP3/etc.) and industrial-asset discovery are out of scope for this increment (§1, §10) — `otsafety` makes no claim about what traffic actually traverses a zone, only about declared zone sensitivity and declared boundary requirements.
- The authorization check in §4.4 is a hard rejection, never a silent downgrade to a passive/synthetic mode — a caller who needs to run an active probe against a sensitive zone must explicitly say so, every time, per `network.txt` §9's "explicit authorisation... for every run."
- `TransitViolation` is strictly additive evidence; it is never permitted to alter a `PathResult`'s `State`, mirroring Phase 6B's identical constraint on its own `TransitViolation`.
- Zone-name references in `SensitiveZone`/`RequiredTransit` cannot be cross-validated against a real `networktopology.TopologyImport` at import time (§3); this is a declared `Limitations` requirement, not a silently accepted gap.

## 10. Explicitly Out of Scope / Deferred

- Industrial-protocol visibility (Modbus/DNP3/etc.) and industrial-asset discovery/inventory.
- Phase 7B (healthcare network-isolation validation) and Phase 7C (India/UAE regulatory mapping) — separate phases, built after 7A per the user's own ordering.
- Weak-TLS/active-downgrade testing — already deferred from Phase 5B, not reopened here.
- A standing or blanket pre-authorization recorded on the `OTSafetyImport` itself (e.g., "active testing pre-approved until a given date") — authorization in this increment is per-request only, every time, per §9's "explicit authorisation... for every run."
- Any tamper-evident audit/evidence-retention subsystem beyond the existing `h.auditLog` call — belongs to network.txt's own later "Enterprise Assurance and Continuous Regression" phase, not this one.
- Sensitivity tiers beyond the single `TierOT` value.

## 11. Acceptance Criteria

At least one OT/ICS boundary-violation test (a path between a declared IT and OT zone that bypasses a required DMZ/jump zone, correctly surfaced as a `TransitViolation` via the extended `/api/network-paths`) and at least one active-test safety-gating test (a discovery run, DNS check, or transport check against a target resolving into a declared sensitive zone, correctly rejected with 400 absent explicit authorization, and correctly permitted with a recorded sign-off when authorized) both execute end-to-end. A sensitive zone with no declared `RequiredTransit` is gated for active testing but never produces a spurious boundary violation. A `RequiredTransit` rule with no candidate route at all for its endpoints produces zero violations, never a false bypass report.
