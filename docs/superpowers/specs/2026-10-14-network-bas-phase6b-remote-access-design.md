# Network BAS Mastery Phase 6B: VPN / Remote-Access Networking — Design Spec

## 1. Goal

Validate on-premises remote-access and trust-boundary controls per `network.txt` §1.5: VPN access boundaries, jump hosts/bastion servers and mandatory administrative-access paths, and trust-zone separation (corporate/guest/production/restricted, branch-to-data-centre). Scope for this increment is **on-premises only** — a VPN tunnel or bastion rule connects two zones from the existing `internal/networktopology` zone model. Hybrid cloud-to-on-prem remote access is explicitly deferred to a later increment (§9), the same way Phase 6A deferred native vendor parsers.

Two genuinely new primitives are added: **VPN tunnels** (a logical, state-carrying route edge — configured existence and operational state are separate evidence questions) and **mandatory-transit / bastion rules** (a declared-architecture constraint — any path between two zones must visit a required zone — checked against found routes, never baked into the routing graph). Everything else §1.5 names (corporate/guest/production/restricted separation, branch-to-DC) is already fully representable by Phase 2/3's existing `Zone`/`RouteEdge`/`Rule` model and requires no new code — only new zone/rule *data*.

## 2. Relationship to `networktopology` and `networkpolicy`

`internal/remoteaccess` never modifies `internal/networktopology` or `internal/networkpolicy`. It imports `networktopology.Zone`/`RouteEdge`/`TopologyImport` read-only (for its own route search, which must see physical edges alongside tunnel edges) and references zone names as plain strings elsewhere — the same cross-reference-by-name convention `networkpolicy` and `networktopology` already use with each other. No new type is added to either existing package.

Hop-level evidence composition reuses `internal/networkpath`'s existing `ComposeHop`/`AggregatePath` **unchanged** (§5). There is no new composition package for this phase — see §5 for why.

## 3. Why a Separate Import, Not New Fields on `TopologyImport`

VPN tunnel and bastion-rule data comes from a genuinely different real-world source than zone/route topology data (VPN-concentrator and firewall configs, not network diagrams or route tables) — the same argument `networkpolicy` and `networktopology` already embody by staying independent packages with independent imports, despite both describing on-prem zones. `RemoteAccessImport` is therefore its own import type, referencing `networktopology` zones by name only, never by direct struct reference or foreign key.

One consequence, stated honestly rather than silently assumed: because the two imports are independently sourced, `remoteaccess`'s own import validation cannot check that a `VPNTunnel.FromZone` or a `MandatoryTransit.ViaZone` actually matches a zone declared in some real `networktopology.TopologyImport` — it can only check that the string is non-empty. This gap is recorded as a `Limitations` entry at import time, not assumed away.

## 4. Package: `internal/remoteaccess`

### 4.1 Data Model

```go
package remoteaccess

import "time"

const (
	TunnelUp      = "up"      // real evidence: operationally established, usable as a route edge
	TunnelDown    = "down"    // real evidence: configured but not established -- not a usable edge, but also not proof no path exists at all
	TunnelUnknown = "unknown" // missing evidence -- never treated as usable, never treated as confirmed-down
)

// VPNTunnel is one logical tunnel connecting two networktopology zones
// by name. It may connect zones with no CIDR adjacency at all (e.g. a
// branch zone and a data-centre zone reachable only across the public
// internet) -- configured existence and operational state are two
// separate evidence questions, mirroring
// cloudtopology.PeeringConnection's exact discipline: only
// State == TunnelUp is ever treated as a usable route edge.
type VPNTunnel struct {
	CanonicalID string `json:"canonicalId"`
	FromZone    string `json:"fromZone"`
	ToZone      string `json:"toZone"`
	Directed    bool   `json:"directed,omitempty"`
	State       string `json:"state"` // TunnelUp | TunnelDown | TunnelUnknown
	Note        string `json:"note,omitempty"`
}

// MandatoryTransit declares that any path between FromZone and ToZone
// must visit ViaZone -- e.g. "any administrative path from the
// corporate zone to the production zone must pass through the bastion
// zone." This is a declared-architecture constraint, validated against
// whatever the route search actually finds (§4.3) -- never baked into
// the routing graph itself, so a real bypass route that skips the
// bastion is surfaced as a violation instead of silently disappearing
// from the search.
type MandatoryTransit struct {
	CanonicalID string `json:"canonicalId"`
	FromZone    string `json:"fromZone"`
	ToZone      string `json:"toZone"`
	ViaZone     string `json:"viaZone"`
	Note        string `json:"note,omitempty"`
}

// RemoteAccessImport is one auditable, versioned snapshot -- the same
// shape discipline as networkpolicy.PolicyImport /
// networktopology.TopologyImport. Tunnels/Transits reference zone
// names declared in a separate networktopology.TopologyImport; this
// package never imports networktopology's types for validation, only
// networktopology.Zone/RouteEdge/TopologyImport read-only for route
// search (§4.3) -- the two imports stay independently sourced, as §3
// argues.
type RemoteAccessImport struct {
	ID            string             `json:"id,omitempty"`
	SourceType    string             `json:"sourceType"`
	ImportedBy    string             `json:"importedBy,omitempty"`
	ImportedAt    time.Time          `json:"importedAt,omitempty"`
	ConfigVersion string             `json:"configVersion,omitempty"`
	Tunnels       []VPNTunnel        `json:"tunnels"`
	Transits      []MandatoryTransit `json:"transits,omitempty"`
	Limitations   []string           `json:"limitations,omitempty"`
}
```

### 4.1.1 Safety Caps

```go
const (
	MaxTunnelsPerImport  = 500
	MaxTransitsPerImport = 500

	// maxRouteSearchSteps is the same defensive bound on total
	// route-search work every prior phase's search function carries,
	// independent of the tunnel/transit caps above.
	maxRouteSearchSteps = 20000
)
```

### 4.2 Import Validation

Enforced at the API validation layer (Task-level, mirroring `validateCloudTopologyImport`), not inside the `remoteaccess` package itself:

- Every `VPNTunnel.State` must be one of the three declared constants; an unrecognized value is rejected, never silently accepted (same discipline as 6A's own Minor-fix precedent for `RouteTableEntry.Target`/`PeeringConnection.State`).
- A `VPNTunnel` in `TunnelUnknown` state requires the import's top-level `Limitations` to be non-empty (mirrors `ScopeUnresolved`'s exact requirement).
- `FromZone`/`ToZone` (on `VPNTunnel`) and `FromZone`/`ToZone`/`ViaZone` (on `MandatoryTransit`) must be non-empty strings. They are **not** cross-checked against a real `networktopology.TopologyImport`'s declared zones (§3) — this limitation is itself required to appear in the import's `Limitations`.

### 4.3 Route Search and Bastion Validation

```go
// RoutePath is a sequence of zone names, same shape as
// networktopology.RoutePath.
type RoutePath []string

// FindCandidateRemoteAccessRoutes finds bounded-depth paths from
// sourceZone to destZone over the UNION of topo's declared RouteEdges
// and remote's VPN tunnels in State == TunnelUp -- a Down or Unknown
// tunnel is never a usable edge, mirroring exactly how
// cloudtopology.FindCandidateCloudRoutes treats only PeeringActive as
// usable. This is a new bounded DFS (not a reuse of
// networktopology.FindCandidateRoutes, which is hardcoded to
// topo.Edges alone), walking the combined adjacency; same exhausted
// bool and maxRouteSearchSteps defensive step budget as every prior
// phase's route search.
func FindCandidateRemoteAccessRoutes(topo *networktopology.TopologyImport, remote *RemoteAccessImport, sourceZone, destZone string, maxHops int) (routes []RoutePath, exhausted bool, err error)

// TransitViolation is evidence that a found route between a
// MandatoryTransit's FromZone and ToZone never visited ViaZone.
type TransitViolation struct {
	Transit MandatoryTransit `json:"transit"`
	Route   RoutePath        `json:"route"`
	Note    string           `json:"note"`
}

// ValidateMandatoryTransit checks each route against every
// MandatoryTransit whose FromZone/ToZone match the route's endpoints,
// returning one TransitViolation per route that bypasses ViaZone. A
// route that never reaches ToZone is not a candidate for that Transit
// rule at all -- it is not a bypass, it is simply unrelated. This
// function is purely additive: it never removes a route from the
// caller's result set, only annotates which ones violate a declared
// constraint, mirroring cloudpath.CorrelateCloudFinding's
// non-mutating discipline exactly.
func ValidateMandatoryTransit(routes []RoutePath, transits []MandatoryTransit) []TransitViolation
```

A tunnel-carrying route can include zones that are not CIDR-adjacent at all — the DFS does not care *why* an edge exists (a physical `RouteEdge` or a `TunnelUp` tunnel), only that it is usable. The same zone pair may be reachable both physically and via VPN; both are found as separate candidate routes.

## 5. Evidence Composition — Reuses `internal/networkpath` Unchanged

`networkpath.ComposeHop(fromZone, toZone string, routeDeclared bool, policyEval *networkpolicy.PolicyEvaluation, observations []networkgraph.NetworkObservation) HopResult` does not care why a hop counts as "declared" — that decision is made entirely by whatever the caller passes. Since a VPN-tunnel hop needs exactly the same three-branch evidence discipline (a real observation wins outright; route-declared-and-policy-evaluated passes the policy verdict through; no route forces `Unknown` regardless of what policy would otherwise say), there is no genuinely new per-hop composition logic for this phase to invent. `networkpath.AggregatePath`/`AggregateConfidence` are reused unchanged for the same reason.

This phase therefore adds **no new composition package**. The API handler (§6) calls `FindCandidateRemoteAccessRoutes`, then composes each hop with the existing, unmodified `networkpath.ComposeHop`/`AggregatePath` exactly as `FindNetworkPaths` already does — and separately calls `ValidateMandatoryTransit`, attaching any violations alongside the composed results as additive data, never altering a result's `State`.

One evidence nuance handled entirely at the handler layer, not by adding a new `PathState` value: when no route is found, `ComposeHop` already forces `Unknown`. The handler may attach a more specific `Limitations` string distinguishing "no edge of any kind was declared between these zones" from "a VPN tunnel is declared for this zone pair but reported down" — the same post-composition `Limitations`-appending pattern `cloudpath_handlers.go` already uses for intermediate hops with no observation evidence.

## 6. Persistence & API

```go
// internal/db/remoteaccess_store.go -- same pattern as every prior
// EnsureXSchema/InsertX/GetX/ListX store this session (networkpolicy_store.go,
// networktopology_store.go, cloudtopology_store.go, etc).
func EnsureRemoteAccessImportSchema(ctx context.Context, pool *pgxpool.Pool) error
func InsertRemoteAccessImport(ctx context.Context, pool *pgxpool.Pool, imp *remoteaccess.RemoteAccessImport) error
func GetRemoteAccessImport(ctx context.Context, pool *pgxpool.Pool, id string) (*remoteaccess.RemoteAccessImport, error)
func ListRemoteAccessImports(ctx context.Context, pool *pgxpool.Pool, limit int) ([]*remoteaccess.RemoteAccessImport, error)
```

- `POST /api/remote-access-imports`, `GET /api/remote-access-imports`, `GET /api/remote-access-imports/{id}` -- validate-then-insert shape identical to `CreateCloudTopologyImport` (§4.2). New permission `auth.CanImportRemoteAccessTopology`, granted to `RoleAdmin` and `RoleAnalyst`.
- `POST /api/remote-access-paths` -- a **separate** endpoint from `/api/network-paths` (the same choice Phase 6A made for `/api/cloud-paths` vs. `/api/network-paths`), so the existing, already-tested endpoint is never touched. Request:

```go
type remoteAccessPathRequest struct {
	TopologyImportID     string `json:"topologyImportId"`
	RemoteAccessImportID string `json:"remoteAccessImportId"`
	PolicyImportID       string `json:"policyImportId,omitempty"`
	DiscoveryRunID       string `json:"discoveryRunId,omitempty"`
	SourceHost           string `json:"sourceHost"`
	DestHost             string `json:"destHost"`
	Port                 int    `json:"port"`
	Protocol             string `json:"protocol,omitempty"`
	MaxHops              int    `json:"maxHops,omitempty"`
}

type remoteAccessPathResponse struct {
	Results           []networkpath.PathResult        `json:"results"`
	SearchExhausted   bool                             `json:"searchExhausted,omitempty"`
	TransitViolations []remoteaccess.TransitViolation `json:"transitViolations,omitempty"`
}
```

`FindRemoteAccessPaths` resolves `sourceHost`/`destHost` to zones via `networktopology.ZoneForHost` (reused, unmodified), calls `FindCandidateRemoteAccessRoutes`, composes each hop via `networkpath.ComposeHop`/`AggregatePath` (reused, unmodified), and separately calls `ValidateMandatoryTransit` over the found routes, attaching violations to the response.

## 7. Review Focus

1. A `TunnelDown` tunnel between two zones with **no other route** must force `Unknown`, never `Blocked` and never silently vanish — mirrors 6A's non-active-peering distinction (down/missing evidence proves nothing about the broader topology, it only removes one candidate edge).
2. A route that is perfectly valid connectivity-wise (tunnel up, policy permits) but **bypasses** a `MandatoryTransit`'s required `ViaZone` must still surface as a `TransitViolation` — connectivity validity and architecture-conformance are orthogonal questions; the first must never suppress the second.
3. A `MandatoryTransit` rule whose `FromZone`/`ToZone` has **no candidate route at all** (genuinely isolated zones) must **not** produce a spurious violation — "no route found" and "found a route that bypasses the bastion" are different findings and must never be conflated.
4. A multi-hop path mixing one tunnel hop and one physical hop, where the tunnel hop's policy evaluation independently blocks while the physical hop's permits, must still classify the **whole path** as `Blocked` — the regression test proving §5's "reuse `AggregatePath` unchanged" decision holds under a genuinely mixed hop-kind path, not just under same-kind hops.
5. A genuinely multi-tier fixture (3+ zones, 2+ tunnels, one physical edge down) where two *different* candidate routes exist and only one satisfies a `MandatoryTransit` rule — proving route search and bastion validation interact correctly across multiple candidates, not just a trivial 2-zone case. Direct response to this project's own standing lesson: flat-hierarchy fixtures have twice masked real multi-tier bugs (DNSSEC and TLS-certificate chain validation, Phase 5).

## 8. Safety Constraints

- Cloud-to-on-prem hybrid connectivity is out of scope for this increment (§9) -- `remoteaccess` never claims to represent a tunnel terminating in a cloud VPC.
- A down or unknown tunnel is never read as proof that no path exists; it only removes that specific edge as a candidate, identical to Phase 6A's peering-state discipline.
- Zone-name references in `VPNTunnel`/`MandatoryTransit` cannot be cross-validated against a real `networktopology.TopologyImport` at import time (§3); this is a declared `Limitations` requirement, not a silently accepted gap.
- `TransitViolation` is strictly additive evidence; it is never permitted to alter a `HopResult`/`PathResult`'s `State`.

## 9. Explicitly Out of Scope / Deferred

- Hybrid cloud-to-on-prem remote access (a tunnel terminating in a `cloudtopology` subnet) -- deferred to a later increment, consistent with Phase 6A's own deferral of cloud/on-prem hybrid connectivity.
- Zero-trust, identity-aware access policy (per-request device/identity posture conditions) -- this schema has no representation for identity-conditional rules; deferred.
- Management-plane-exposure and "unintended access from permissive routing" derived queries -- deferred, the same way Phase 6A deferred public-exposure and management-plane derived queries.
- Third-party/partner network connectivity as a distinct construct -- representable today as an ordinary zone with a appropriately-worded `Note`; no new type needed, so not separately built.
- Native VPN-concentrator/firewall vendor parsers -- out of scope; import is vendor-agnostic JSON, same as every prior phase.

## 10. Acceptance Criteria

At least one on-premises VPN-tunnel path and one bastion/mandatory-transit boundary test execute end-to-end with evidence-backed results, using the same `PathState` values and the same configured-vs-demonstrated evidence discipline as every prior on-premises phase. A `TunnelDown` tunnel and a non-active-peering-style missing-route case are both classified as `Unknown`, never `Blocked`. A declared `MandatoryTransit` rule correctly flags a real bypass route found by the search and correctly stays silent when no route exists between its endpoints at all.
