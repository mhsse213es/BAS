# Network BAS Mastery Phase 3: L3/L4 Attack-Path Engine — Design

## Status

Approved by the user in-chat, section by section, 2026-10-14.

## Context

Parent: `docs/superpowers/specs/2026-10-13-network-bas-architecture-design.md` (master spec, 7-phase roadmap, three-evidence-domain architecture). Phase 1 (`internal/networkgraph` — orchestrator-originated TCP reachability evidence) and Phase 2A (`internal/networkpolicy` + `internal/networkcorrelation` — normalized policy evaluation and policy/observation correlation) are both done, reviewed, and merged (`main`, through commit `e619e3c3`).

Phase 3 of the locked roadmap is "L3/L4 attack-path engine" — multi-hop path construction across zones, routes, and firewall rules. Repo survey (2026-10-14): `internal/attackpath` already builds multi-hop paths, but exclusively for the identity domain (Windows/AD lateral movement — `Node`/`Edge` keyed by hostname/SID/user@domain). No general network-layer multi-hop engine exists. The master spec's own Phase 3 section locks the reuse boundary: Phase 3 does **not** extend `attackpath`'s `Node`/`Edge` types; it treats `attackpath`'s existing SMB/WinRM/RDP reachability and `SegmentationViolations()` output as **corroborating evidence only**, referenced by asset key, never inherited from or mutated.

**Locked design decision (user-directed, overriding the author's initial recommendation):** reachability is not fully determined by firewall policy alone. Three evidence questions stay structurally distinct and combine without collapsing into one result:

1. **Routing** — is there a plausible Layer 3 path between two zones?
2. **Policy** — does modeled firewall/segmentation policy (Phase 2A) permit the relevant traffic?
3. **Observation** — has connectivity actually been demonstrated from a vantage point (Phase 1)?

A firewall rule can permit traffic that has no viable route, and a route can exist while a firewall blocks the traffic — treating routing and policy as the same thing creates blind spots. The user supplied this interpretation table directly, which this spec treats as binding:

| Routing evidence | Policy evidence | Correct interpretation |
|---|---|---|
| Route supported | Traffic permitted | Candidate path; **not** proof of connectivity |
| Route supported | Traffic denied | Policy-blocked candidate path |
| No known route | Traffic permitted | Policy permits it, but the route is unproven or absent |
| Unknown | Traffic permitted | Reachability remains unknown |
| Route supported | Policy unknown | Potential path requiring further evidence |

**Critical, explicit rule from the user:** no known route must never automatically mean blocked. Missing topology data is not proof of isolation.

The user also directed: start with declared/imported zone adjacency, not automatic reconstruction of an entire routing fabric. Asymmetric routing, dynamic-routing convergence, NAT interactions, and policy-based routing are represented as explicit limitations until supported, not built now. Topology may be unknown or partially modeled — operators are never required to fully map every route before Audspect reports anything useful.

## Scope

**In scope (this spec, Phase 3):**
- A declared/imported zone-adjacency (routing) model, structurally independent of `networkpolicy`'s firewall rules.
- Goal-directed candidate-path generation: caller supplies a source and destination (resolved to zones via CIDR containment), engine returns bounded-depth candidate routes across the adjacency graph.
- Per-hop evidence composition: routing + Phase 2A policy evaluation + Phase 1 observation (via Phase 2A's existing correlation), combined per the table above, never inventing a new `PathState` value.
- Path-level aggregation: classification never exceeds the weakest hop's; confidence is derived from, not equal to, the weakest hop's confidence.
- Optional, non-authoritative corroboration from `attackpath`'s SMB/WinRM/RDP edges and `SegmentationViolation` output, cited by asset key.
- Persistence and HTTP API for importing topology and running path queries, following the `networkpolicy`/`network_discovery` precedent.

**Explicitly out of scope / deferred:**
- **Automatic topology discovery or reconstruction** (e.g. deriving routes from traceroute, routing-table scraping, or SDN controller APIs) — a possible future ingestion mode, not Phase 3. Topology is declared/imported only.
- **Asymmetric routing, dynamic-routing convergence, NAT interactions, policy-based routing** — represented honestly as limitations on a `TopologyImport`, not modeled.
- **Batch/exhaustive path generation across all zone pairs** — Phase 3 is goal-directed (source+destination supplied by the caller) only; a full network-exposure sweep is a possible future report built on top of repeated goal-directed queries, not this phase's own API shape.
- **Extending `attackpath`'s `Node`/`Edge` types** — locked by the master spec; corroboration is read-only, by asset key, never authoritative.
- **A new `PathState` enum value** — the existing six values (`Candidate`/`ConditionallyReachable`/`PolicySupported`/`Observed`/`Blocked`/`Unknown`) are preserved as-is and reused for every classification in this phase.

## Architecture

Two new packages, mirroring the isolation discipline Phase 2A already established:

- **`internal/networktopology`** (new) — pure types + candidate-route generation. Defines its own `Zone{Name, CIDRs}` (same shape as `networkpolicy.Zone`, but its own type — topology and policy stay correlated only by matching `Name` strings at evaluation time, never a shared struct or foreign key) and `RouteEdge{FromZone, ToZone, Directed, Note}`. Imports nothing from `networkpolicy`, `networkgraph`, `networkcorrelation`, or `attackpath` — routing evidence is independent, per the user's explicit instruction.
- **`internal/networkpath`** (new) — the path engine. The only package that imports `networktopology`, `networkpolicy`, `networkcorrelation`, `networkgraph`, and (for corroboration only) `attackpath`. Composes per-hop evidence, aggregates path-level state/confidence, attaches corroboration. `networkcorrelation` itself is **not modified** — its existing policy+observation fusion is reused as-is, called from `networkpath` for each hop that has a real observation.
- **`internal/networkpolicy`**, **`internal/networkgraph`**, **`internal/networkcorrelation`**, **`internal/attackpath`** — unchanged.

Persistence and HTTP follow the established `cloud_run`/`network_discovery`/`network_policy_imports` pattern (dedicated API + Postgres, `http.MaxBytesReader` from the start, server-controlled actor identity via `auth.ClaimsFrom`, a new granular permission).

## Data Model (`internal/networktopology`)

```go
type Zone struct {
    Name  string
    CIDRs []string
}

// RouteEdge is one declared L3 adjacency between two zones. Directed=false
// means the edge is usable in either direction (the common case for a
// routed network); Directed=true models a one-way route explicitly,
// never assumed.
type RouteEdge struct {
    FromZone string
    ToZone   string
    Directed bool
    Note     string
}

// TopologyImport is one auditable, versioned routing-topology snapshot --
// the same shape discipline as networkpolicy.PolicyImport. Limitations
// carries honest gaps (asymmetric routing, NAT, policy-based routing,
// dynamic convergence) rather than silently omitting them.
type TopologyImport struct {
    ID            string
    SourceType    string
    ImportedBy    string
    ImportedAt    time.Time
    ConfigVersion string
    Zones         []Zone
    Edges         []RouteEdge
    Limitations   []string
}
```

Caps: `MaxZonesPerTopologyImport = 500`, `MaxEdgesPerTopologyImport = 5000` (mirrors Phase 2A's zone/rule caps).

## Candidate Path Generation (`internal/networktopology`)

```go
type RoutePath []string // ordered zone names, source to destination

const (
    MaxHopsPerPathQuery        = 10 // hard ceiling; a caller-supplied maxHops is clamped to this, never above
    MaxCandidateRoutesPerQuery = 20 // bounds BFS output even within the hop cap
)

func FindCandidateRoutes(topo *TopologyImport, sourceZone, destZone string, maxHops int) ([]RoutePath, error)
```

Bounded-depth BFS over the zone-adjacency graph built from `topo.Edges`. Returns **all** simple paths up to `MaxCandidateRoutesPerQuery`, not just the shortest — a longer path through an unexpected pivot zone can be the one that actually matters for an attack-path assessment, but the search still stays bounded. Zero candidate routes is a valid, honest result (not an error): if `sourceZone`/`destZone` aren't connected within `maxHops`, the function returns an empty slice, and the caller classifies this as "no known route," never as blocked. The adjacency graph may be cyclic (real routed networks often are); BFS must terminate regardless.

Resolving a concrete host to the zone whose `CIDRs` contain it is the caller's job (`internal/networkpath`), using the same CIDR-containment check `networkpolicy.resolveSide` already uses, duplicated locally rather than imported — consistent with `Zone` itself being duplicated rather than shared. Two zones sharing the same `Name` in one `TopologyImport` are genuinely ambiguous, the same failure mode Phase 2A's `networkpolicy` already treats as unresolvable rather than silently picking one: zone-name resolution (both for `sourceZone`/`destZone` lookups and for host-to-zone CIDR resolution) fails closed on a duplicate name, surfacing as "zone not found" rather than guessing.

## Per-Hop Evidence Composition (`internal/networkpath`)

For one hop (a consecutive zone pair in a candidate route), composition happens in priority order:

1. **A real Phase 1 observation exists for this hop.** Reuse `networkcorrelation.CorrelateReachability`'s existing policy+observation fusion as-is. Routing evidence never overrides a real observation — a demonstrated connection or demonstrated block is physical ground truth; the topology import might simply be incomplete. If routing was absent for this hop, the hop's `Limitations` notes it, but `PathState` still comes from the real observation.
2. **No observation, route declared.** Use the Phase 2A policy verdict as-is (`PolicySupported`/`Blocked`/`Unknown`). Table rows 1, 2, 5.
3. **No observation, route not declared or not resolvable.** Force `Unknown`, regardless of what the policy verdict would otherwise have been. Table rows 3, 4 — this is the rule that must never leak through as `Blocked`. The `Limitations` text distinguishes "declared-absent" (both zones exist in the topology import, no edge between them) from "no topology data at all" (the zone pair isn't covered by any imported topology) — the same `PathState` either way, but an honest, different explanation.

No new `PathState` value is introduced anywhere in this composition.

## Path-Level Aggregation (`internal/networkpath`)

**Classification** follows the exact ranking precedent already established by `cloudgraph.worstState()` (`internal/cloudgraph/cloud_reachability.go`) for Cloud BAS's own multi-hop permission-path engine, on this same `PathState` enum: `Blocked` short-circuits immediately (any blocked hop kills the whole path); otherwise weakest-wins in order `Unknown > PolicySupported > Observed`. `worstState` itself is unexported to `cloudgraph`, so `internal/networkpath` implements an equivalent small ranking function locally — same semantics, explicitly cited as the precedent, keeping this phase's evidence domain self-contained rather than reaching into `cloudgraph`'s internals.

**Confidence** has no existing ordinal system anywhere in this codebase — `Provenance.Confidence` is always a free-text descriptive string (`"observed"`, `"low"`, `"medium"`, `"none"`), never programmatically ranked, and nothing today drives control flow off it. Path-level confidence is the weakest hop's own `Confidence` string, always annotated with hop-count context (e.g. `"low (3-hop chain; weakest link: medium)"`) — never a bare copy of a single hop's value. This satisfies "derived from, not equal to" honestly without inventing new ranking machinery nothing else in this codebase needs.

Candidate-route generation itself stays blind to policy/observation (Section above) — a route later found `Blocked` at hop 2 is still a valid, useful candidate to surface, not pruned during generation.

## Attackpath Corroboration (`internal/networkpath`)

When a path query's endpoints are concrete hosts (the normal case), `networkpath` builds an `attackpath.Graph` the same way existing handlers already do (`attackpath.BuildGraph(cols...)` from stored collections) and looks for an edge between the two hostnames, normalized via `attackpath.NormalizeHostKey` (reused directly), restricted to `EdgeSMB`/`EdgeWinRM`/`EdgeRDP`. If found, it is attached to that hop as:

```go
type CorroboratingEvidence struct {
    Source   string // "attackpath"
    EdgeKind string // "smb" | "winrm" | "rdp"
    Note     string
}
```

This is purely additive — it never changes the hop's own `PathState`. Same treatment for `attackpath.SegmentationViolation`: if its `FromSegment`/`ToSegment` happen to name-match a hop's zone pair, it is cited as a loose, best-effort note, never depended on (`attackpath.Segment` is a manually-tagged string with no guaranteed correspondence to this phase's declared zones). A name mismatch, or no `attackpath` data at all, degrades to no citation — never an error.

## HTTP API & Persistence

New Postgres table `network_topology_imports` (`topology_data jsonb` holding `{zones, edges}`, same shape discipline as `network_policy_imports.policy_data`). New `networktopology_store.go` with the same `Ensure.../Insert.../Get.../List...` pattern as `networkpolicy_store.go`.

New permission `CanImportNetworkTopology = "network-topology:import"`, granted to `RoleAdmin` and `RoleAnalyst` (same placement as `CanImportNetworkPolicy`).

Endpoints:
- `POST /api/network-topology-imports` (gated by `CanImportNetworkTopology`) / `GET /api/network-topology-imports` + `GET /api/network-topology-imports/{id}` (baseline auth) — import/list/get, same shape as Phase 2A's policy-import trio.
- `POST /api/network-paths` (gated by `CanImportNetworkTopology` — reusing the import permission for this evaluate-style action, following Phase 2A's own precedent of not minting a permission per verb). Body: `{topologyImportId, policyImportId?, discoveryRunId?, sourceHost, destHost, maxHops}`. Response: candidate routes, each with per-hop evidence (routing/policy/observation/corroboration) plus the path-level aggregated `PathState` and confidence.

## Safety Constraints

- `MaxZonesPerTopologyImport = 500`, `MaxEdgesPerTopologyImport = 5000`.
- `MaxHopsPerPathQuery = 10` (hard ceiling; a caller's `maxHops` is clamped to it, never allowed above).
- `MaxCandidateRoutesPerQuery = 20`.
- `http.MaxBytesReader` on both new POST endpoints from the start (topology import sized like policy import, ~5MiB; path-finding request body small, ~64KiB) — ships correct from day one, not a post-hoc fix, matching the discipline Phase 2A's own Review Focus called out and this session's final review on Phase 2A reinforced with a real bug.
- BFS over the adjacency graph must terminate on a cyclic topology — never an unbounded loop.

## Testing Strategy

- `internal/networktopology`: `FindCandidateRoutes` — single-hop, multi-hop, no-route-found returns empty (not an error), directed-vs-undirected edges, hop-cap enforcement, candidate-count cap, and a cyclic adjacency graph (must terminate).
- `internal/networkpath`: one test per row of the evidence-combination table (5 rows) plus "a real observation overrides a routing gap" and "a `Blocked` hop short-circuits the whole path's aggregation" — the same "prove the hard-to-reach branch directly" discipline used in Phases 1 and 2A.
- Attackpath corroboration: a found SMB/WinRM/RDP edge attaches without altering `PathState`; no edge found doesn't break anything; a `Segment`-name mismatch degrades to no citation, never a crash.
- DB/API layer: store round-trip, handler validation, RBAC matrix, oversized-body rejection — mirrors Phase 1/2A's existing test patterns exactly.

## Acceptance Criteria

- A path's `PathState` never exceeds its weakest hop's classification (one `Unknown` or `Blocked` hop prevents the whole path from reading as `Observed`).
- A missing or unresolvable route never silently reads as `Blocked` — it reads as `Unknown`, with a `Limitations` string distinguishing a declared-absent edge from a complete absence of topology data for that zone pair.
- A real Phase 1 observation always takes precedence over an absent route for that hop's own classification.
- Every classification is traceable to named per-hop evidence (routing, policy, observation).
- `attackpath` corroboration, when present, is visibly attached but never authoritative — removing all `attackpath` data from a path's response must never change any hop's `PathState`.
- Candidate-route generation terminates and respects `MaxHopsPerPathQuery`/`MaxCandidateRoutesPerQuery` even on a cyclic topology.
