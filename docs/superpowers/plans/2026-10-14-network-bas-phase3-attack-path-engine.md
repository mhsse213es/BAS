# Network BAS Mastery Phase 3: L3/L4 Attack-Path Engine Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task (Native/inline execution, pre-selected for this plan — see Execution Handoff). Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a goal-directed, multi-hop network attack-path engine that combines declared L3 routing adjacency, Phase 2A firewall-policy evaluation, and Phase 1 live-observation evidence into honestly-classified candidate paths, with optional non-authoritative corroboration from the identity domain.

**Architecture:** Two new packages — `internal/networktopology` (pure types + bounded-depth BFS path generation over a declared zone-adjacency graph) and `internal/networkpath` (the path engine: per-hop evidence composition, path-level aggregation, and `attackpath` corroboration) — plus a Postgres store and HTTP API layer mirroring Phase 2A's exact precedent. `internal/networkpolicy`, `internal/networkgraph`, `internal/networkcorrelation`, and `internal/attackpath` are all reused as-is, none modified.

**Tech Stack:** Go, Postgres (via `pgxpool`), chi router — same stack as every prior phase.

**Spec:** `docs/superpowers/specs/2026-10-14-network-bas-phase3-attack-path-engine-design.md`

## Global Constraints

- `MaxZonesPerTopologyImport = 500`, `MaxEdgesPerTopologyImport = 5000`.
- `MaxHopsPerPathQuery = 10` — a caller-supplied `maxHops` is clamped to this ceiling, never allowed above it; 0 or negative also clamps to the ceiling (means "no limit specified", not "zero hops allowed").
- `MaxCandidateRoutesPerQuery = 20` — bounds `FindCandidateRoutes`' output even within the hop cap.
- `http.MaxBytesReader` on every new POST endpoint from the start: topology import `5 << 20` (mirrors Phase 2A's policy import), path-finding request `1 << 16` (small, structured body).
- No new `cloudgraph.PathState` value is introduced anywhere in this plan — every classification reuses the existing six (`Candidate`/`ConditionallyReachable`/`PolicySupported`/`Observed`/`Blocked`/`Unknown`).
- A missing or unresolvable route must never classify as `Blocked` — it classifies as `Unknown`.
- `internal/networkcorrelation` is reused as-is and is **not modified** by this plan.
- `internal/attackpath`'s `Node`/`Edge` types are **not extended** by this plan; all corroboration is read-only, by asset key.

## Review Focus

- **A query whose source and destination hosts resolve to the identical zone** (a very common real input — two hosts on the same subnet). This must still produce a meaningful single-hop evaluation, never a crash, an empty result, or a nonsensical "zero-hop" classification. Owned by Task 2's `FindCandidateRoutes` test and Task 8's end-to-end test.
- **A `RouteEdge` declaring `FromZone == ToZone`** (a self-loop) in an imported topology. This is malformed input and must be rejected at import validation, not silently accepted as meaningless data. Owned by Task 7.
- **`maxHops` omitted, zero, or negative.** Must deliberately default to `MaxHopsPerPathQuery`, not silently search zero hops deep (which would make every query return no candidates). Owned by Task 2.
- **A policy import and a topology import that use completely disjoint zone-naming schemes** (a very plausible real misconfiguration — different tools, different naming conventions). Every hop must degrade honestly to `Unknown`, never crash or misattribute a policy verdict to the wrong zone. Owned by Task 8.
- **A multi-hop candidate route queried with a `discoveryRunId` supplied.** Phase 1 only ever observes "vantage point → destination host" directly, never an arbitrary intermediate hop, so observation evidence is only ever eligible for a single-hop path. A caller supplying `discoveryRunId` against a multi-hop route must see a clear `Limitations` note on intermediate hops explaining why no observation was attempted — not silent omission that looks like a bug. Owned by Task 8.

---

### Task 1: Zone/Topology Types & CIDR-Containment Resolution

**Files:**
- Create: `orchestrator/internal/networktopology/types.go`
- Create: `orchestrator/internal/networktopology/resolve.go`
- Test: `orchestrator/internal/networktopology/resolve_test.go`

**Interfaces:**
- Consumes: nothing from this plan (first task).
- Produces: `Zone{Name string, CIDRs []string}`, `RouteEdge{FromZone, ToZone string, Directed bool, Note string}`, `TopologyImport{ID, SourceType, ImportedBy, ConfigVersion string, ImportedAt time.Time, Zones []Zone, Edges []RouteEdge, Limitations []string}`, `func ResolveZoneCIDRs(zoneName string, zones []Zone) ([]string, error)`, `func ZoneForHost(host string, zones []Zone) (string, error)`.

- [ ] **Step 1: Write the failing tests**

```go
// orchestrator/internal/networktopology/resolve_test.go
package networktopology

import "testing"

func TestResolveZoneCIDRs_ReturnsCIDRsForNamedZone(t *testing.T) {
	zones := []Zone{{Name: "dmz", CIDRs: []string{"10.0.1.0/24"}}}
	cidrs, err := ResolveZoneCIDRs("dmz", zones)
	if err != nil {
		t.Fatalf("ResolveZoneCIDRs: %v", err)
	}
	if len(cidrs) != 1 || cidrs[0] != "10.0.1.0/24" {
		t.Fatalf("got %v, want [10.0.1.0/24]", cidrs)
	}
}

func TestResolveZoneCIDRs_UnknownZoneNameErrors(t *testing.T) {
	zones := []Zone{{Name: "dmz", CIDRs: []string{"10.0.1.0/24"}}}
	if _, err := ResolveZoneCIDRs("does-not-exist", zones); err == nil {
		t.Fatal("want error for a zone name absent from this topology")
	}
}

func TestResolveZoneCIDRs_AmbiguousZoneNameErrors(t *testing.T) {
	zones := []Zone{{Name: "dup", CIDRs: []string{"10.0.1.0/24"}}, {Name: "dup", CIDRs: []string{"10.0.9.0/24"}}}
	if _, err := ResolveZoneCIDRs("dup", zones); err == nil {
		t.Fatal("want error -- two zones sharing a name must never be silently resolved to one of them")
	}
}

func TestZoneForHost_ReturnsMatchingZoneName(t *testing.T) {
	zones := []Zone{{Name: "dmz", CIDRs: []string{"10.0.1.0/24"}}, {Name: "internal", CIDRs: []string{"10.0.2.0/24"}}}
	name, err := ZoneForHost("10.0.1.50", zones)
	if err != nil {
		t.Fatalf("ZoneForHost: %v", err)
	}
	if name != "dmz" {
		t.Fatalf("got %q, want dmz", name)
	}
}

func TestZoneForHost_NoMatchErrors(t *testing.T) {
	zones := []Zone{{Name: "dmz", CIDRs: []string{"10.0.1.0/24"}}}
	if _, err := ZoneForHost("192.168.1.1", zones); err == nil {
		t.Fatal("want error when no declared zone contains this host")
	}
}

func TestZoneForHost_AmbiguousMatchErrors(t *testing.T) {
	zones := []Zone{{Name: "a", CIDRs: []string{"10.0.0.0/8"}}, {Name: "b", CIDRs: []string{"10.0.1.0/24"}}}
	if _, err := ZoneForHost("10.0.1.50", zones); err == nil {
		t.Fatal("want error -- host falls inside two overlapping zones, ambiguous")
	}
}

func TestZoneForHost_NonIPHostErrors(t *testing.T) {
	zones := []Zone{{Name: "dmz", CIDRs: []string{"10.0.1.0/24"}}}
	if _, err := ZoneForHost("not-an-ip", zones); err == nil {
		t.Fatal("want error for a non-literal-IP host")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/networktopology/... -v`
Expected: FAIL — `package networktopology` does not exist / `ResolveZoneCIDRs`, `ZoneForHost`, `Zone` undefined.

- [ ] **Step 3: Write the types**

```go
// orchestrator/internal/networktopology/types.go

// Package networktopology models a declared, auditable Layer 3
// zone-adjacency (routing) topology, kept structurally independent of
// internal/networkpolicy's firewall-rule evaluation -- a route existing
// and a policy permitting traffic are two separate evidence questions.
// It never imports internal/networkpolicy, internal/networkgraph, or
// internal/attackpath; internal/networkpath is the one place all of
// those evidence sources are combined.
package networktopology

import "time"

// Zone is a named network segment, resolved to one or more CIDRs. Same
// shape as networkpolicy.Zone, but its own type -- networktopology and
// networkpolicy correlate only by matching Name strings at evaluation
// time (internal/networkpath), never a shared struct or foreign key.
type Zone struct {
	Name  string   `json:"name"`
	CIDRs []string `json:"cidrs"`
}

// RouteEdge is one declared L3 adjacency between two zones. Directed
// false means the edge is usable in either direction (the common case
// for a routed network); Directed true models a one-way route
// explicitly, never assumed.
type RouteEdge struct {
	FromZone string `json:"fromZone"`
	ToZone   string `json:"toZone"`
	Directed bool   `json:"directed,omitempty"`
	Note     string `json:"note,omitempty"`
}

// TopologyImport is one auditable, versioned routing-topology snapshot
// -- the same shape discipline as networkpolicy.PolicyImport.
// Limitations carries honest gaps (asymmetric routing, NAT,
// policy-based routing, dynamic convergence) rather than silently
// omitting them.
type TopologyImport struct {
	ID            string      `json:"id,omitempty"`
	SourceType    string      `json:"sourceType"`
	ImportedBy    string      `json:"importedBy,omitempty"`
	ImportedAt    time.Time   `json:"importedAt,omitempty"`
	ConfigVersion string      `json:"configVersion,omitempty"`
	Zones         []Zone      `json:"zones"`
	Edges         []RouteEdge `json:"edges"`
	Limitations   []string    `json:"limitations,omitempty"`
}
```

- [ ] **Step 4: Write the resolution helpers**

```go
// orchestrator/internal/networktopology/resolve.go
package networktopology

import (
	"fmt"
	"net"
)

// ResolveZoneCIDRs returns the CIDRs for the zone named zoneName in
// zones. Two zones sharing the same Name are genuinely ambiguous -- this
// returns an error rather than silently picking one, the same failure
// mode networkpolicy's own (unexported) zone resolution already treats
// as unresolvable.
func ResolveZoneCIDRs(zoneName string, zones []Zone) ([]string, error) {
	var found []Zone
	for _, z := range zones {
		if z.Name == zoneName {
			found = append(found, z)
		}
	}
	if len(found) == 0 {
		return nil, fmt.Errorf("networktopology: zone %q not found", zoneName)
	}
	if len(found) > 1 {
		return nil, fmt.Errorf("networktopology: zone name %q is ambiguous -- %d zones share this name", zoneName, len(found))
	}
	return found[0].CIDRs, nil
}

// ZoneForHost returns the name of the zone whose CIDRs contain host (a
// literal IP address). If more than one zone's CIDRs contain host, that
// is ambiguous and returns an error rather than picking one arbitrarily.
func ZoneForHost(host string, zones []Zone) (string, error) {
	ip := net.ParseIP(host)
	if ip == nil {
		return "", fmt.Errorf("networktopology: %q is not a literal IP address", host)
	}
	var matches []string
	for _, z := range zones {
		for _, c := range z.CIDRs {
			_, ipNet, err := net.ParseCIDR(c)
			if err != nil {
				continue
			}
			if ipNet.Contains(ip) {
				matches = append(matches, z.Name)
				break
			}
		}
	}
	if len(matches) == 0 {
		return "", fmt.Errorf("networktopology: no declared zone contains host %q", host)
	}
	if len(matches) > 1 {
		return "", fmt.Errorf("networktopology: host %q matches multiple zones (%v) -- ambiguous", host, matches)
	}
	return matches[0], nil
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/networktopology/... -v`
Expected: PASS — 6/6.

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/networktopology/types.go orchestrator/internal/networktopology/resolve.go orchestrator/internal/networktopology/resolve_test.go
git commit -m "feat(networktopology): add zone/topology types and CIDR-containment resolution"
```

---

### Task 2: Candidate Route Generation

**Files:**
- Create: `orchestrator/internal/networktopology/routes.go`
- Test: `orchestrator/internal/networktopology/routes_test.go`

**Interfaces:**
- Consumes: `Zone`, `RouteEdge`, `TopologyImport` (Task 1).
- Produces: `RoutePath []string`, `MaxZonesPerTopologyImport = 500`, `MaxEdgesPerTopologyImport = 5000`, `MaxHopsPerPathQuery = 10`, `MaxCandidateRoutesPerQuery = 20`, `func FindCandidateRoutes(topo *TopologyImport, sourceZone, destZone string, maxHops int) ([]RoutePath, error)`.

- [ ] **Step 1: Write the failing tests**

```go
// orchestrator/internal/networktopology/routes_test.go
package networktopology

import "testing"

func TestFindCandidateRoutes_SingleHopDirectRoute(t *testing.T) {
	topo := &TopologyImport{Edges: []RouteEdge{{FromZone: "dmz", ToZone: "internal"}}}
	routes, err := FindCandidateRoutes(topo, "dmz", "internal", 10)
	if err != nil {
		t.Fatalf("FindCandidateRoutes: %v", err)
	}
	if len(routes) != 1 || len(routes[0]) != 2 || routes[0][0] != "dmz" || routes[0][1] != "internal" {
		t.Fatalf("got %v, want one route [dmz internal]", routes)
	}
}

func TestFindCandidateRoutes_MultiHopThroughPivotZone(t *testing.T) {
	topo := &TopologyImport{Edges: []RouteEdge{
		{FromZone: "dmz", ToZone: "core"},
		{FromZone: "core", ToZone: "internal"},
	}}
	routes, err := FindCandidateRoutes(topo, "dmz", "internal", 10)
	if err != nil {
		t.Fatalf("FindCandidateRoutes: %v", err)
	}
	if len(routes) != 1 || len(routes[0]) != 3 {
		t.Fatalf("got %v, want one 3-zone route through core", routes)
	}
}

func TestFindCandidateRoutes_NoRouteReturnsEmptyNotError(t *testing.T) {
	topo := &TopologyImport{Edges: []RouteEdge{{FromZone: "dmz", ToZone: "core"}}}
	routes, err := FindCandidateRoutes(topo, "dmz", "isolated-segment", 10)
	if err != nil {
		t.Fatalf("FindCandidateRoutes: want no error for an unreachable destination, got %v", err)
	}
	if len(routes) != 0 {
		t.Fatalf("got %d routes, want 0 -- an absent route is a valid result, not an error", len(routes))
	}
}

func TestFindCandidateRoutes_DirectedEdgeNotUsableBackwards(t *testing.T) {
	topo := &TopologyImport{Edges: []RouteEdge{{FromZone: "dmz", ToZone: "internal", Directed: true}}}
	routes, err := FindCandidateRoutes(topo, "internal", "dmz", 10)
	if err != nil {
		t.Fatalf("FindCandidateRoutes: %v", err)
	}
	if len(routes) != 0 {
		t.Fatalf("got %v, want no route -- a directed edge must not be traversable backwards", routes)
	}
}

func TestFindCandidateRoutes_UndirectedEdgeUsableBothWays(t *testing.T) {
	topo := &TopologyImport{Edges: []RouteEdge{{FromZone: "dmz", ToZone: "internal", Directed: false}}}
	routes, err := FindCandidateRoutes(topo, "internal", "dmz", 10)
	if err != nil {
		t.Fatalf("FindCandidateRoutes: %v", err)
	}
	if len(routes) != 1 {
		t.Fatalf("got %v, want one route -- an undirected edge must be usable in either direction", routes)
	}
}

func TestFindCandidateRoutes_HopCapEnforced(t *testing.T) {
	topo := &TopologyImport{Edges: []RouteEdge{
		{FromZone: "a", ToZone: "b"},
		{FromZone: "b", ToZone: "c"},
	}}
	routes, err := FindCandidateRoutes(topo, "a", "c", 1)
	if err != nil {
		t.Fatalf("FindCandidateRoutes: %v", err)
	}
	if len(routes) != 0 {
		t.Fatalf("got %v, want no route -- reaching c from a needs 2 hops, maxHops was 1", routes)
	}
}

func TestFindCandidateRoutes_MaxHopsClampedToCeiling(t *testing.T) {
	// Build a chain of exactly 11 edges (needs 11 hops, one more than
	// the MaxHopsPerPathQuery=10 ceiling), then pass an absurdly large
	// maxHops to prove the caller cannot exceed the real ceiling.
	zones := []string{"z0", "z1", "z2", "z3", "z4", "z5", "z6", "z7", "z8", "z9", "z10", "z11"}
	var edges []RouteEdge
	for i := 0; i < len(zones)-1; i++ {
		edges = append(edges, RouteEdge{FromZone: zones[i], ToZone: zones[i+1]})
	}
	topo := &TopologyImport{Edges: edges}
	routes, err := FindCandidateRoutes(topo, "z0", "z11", 999)
	if err != nil {
		t.Fatalf("FindCandidateRoutes: %v", err)
	}
	if len(routes) != 0 {
		t.Fatalf("got %v, want no route -- z0 to z11 needs 11 hops, which exceeds the real ceiling of %d even though maxHops=999 was requested", routes, MaxHopsPerPathQuery)
	}
}

func TestFindCandidateRoutes_ZeroOrNegativeMaxHopsDefaultsToCeiling(t *testing.T) {
	topo := &TopologyImport{Edges: []RouteEdge{{FromZone: "dmz", ToZone: "internal"}}}
	for _, mh := range []int{0, -1, -100} {
		routes, err := FindCandidateRoutes(topo, "dmz", "internal", mh)
		if err != nil {
			t.Fatalf("FindCandidateRoutes(maxHops=%d): %v", mh, err)
		}
		if len(routes) != 1 {
			t.Fatalf("FindCandidateRoutes(maxHops=%d): got %v, want one direct route -- 0/negative must default to the ceiling, not mean zero hops allowed", mh, routes)
		}
	}
}

func TestFindCandidateRoutes_CandidateCountCapEnforced(t *testing.T) {
	// A "hub" zone h connects to 25 distinct intermediate zones, each of
	// which connects on to the destination -- 25 distinct 2-hop routes
	// exist, more than MaxCandidateRoutesPerQuery=20.
	var edges []RouteEdge
	for i := 0; i < 25; i++ {
		mid := "mid" + string(rune('a'+i))
		edges = append(edges, RouteEdge{FromZone: "hub", ToZone: mid})
		edges = append(edges, RouteEdge{FromZone: mid, ToZone: "dest"})
	}
	topo := &TopologyImport{Edges: edges}
	routes, err := FindCandidateRoutes(topo, "hub", "dest", 10)
	if err != nil {
		t.Fatalf("FindCandidateRoutes: %v", err)
	}
	if len(routes) != MaxCandidateRoutesPerQuery {
		t.Fatalf("got %d routes, want exactly the cap of %d", len(routes), MaxCandidateRoutesPerQuery)
	}
}

func TestFindCandidateRoutes_CyclicTopologyTerminates(t *testing.T) {
	// a -> b -> c -> a is a cycle; a real routed network's redundant
	// paths often look like this. The search must still terminate and
	// find the real route to d.
	topo := &TopologyImport{Edges: []RouteEdge{
		{FromZone: "a", ToZone: "b"},
		{FromZone: "b", ToZone: "c"},
		{FromZone: "c", ToZone: "a"},
		{FromZone: "c", ToZone: "d"},
	}}
	routes, err := FindCandidateRoutes(topo, "a", "d", 10)
	if err != nil {
		t.Fatalf("FindCandidateRoutes: %v", err)
	}
	if len(routes) != 1 || routes[0][len(routes[0])-1] != "d" {
		t.Fatalf("got %v, want exactly one route ending at d -- the cycle must not prevent termination or correctness", routes)
	}
}

func TestFindCandidateRoutes_SameZoneQueryReturnsTrivialSingleElementRoute(t *testing.T) {
	// Source and destination are the same zone -- a very common real
	// query (two hosts on the same subnet). This must not require any
	// declared edge and must not be treated as "no route".
	topo := &TopologyImport{Zones: []Zone{{Name: "dmz", CIDRs: []string{"10.0.1.0/24"}}}}
	routes, err := FindCandidateRoutes(topo, "dmz", "dmz", 10)
	if err != nil {
		t.Fatalf("FindCandidateRoutes: %v", err)
	}
	if len(routes) != 1 || len(routes[0]) != 2 || routes[0][0] != "dmz" || routes[0][1] != "dmz" {
		t.Fatalf("got %v, want one trivial [dmz dmz] route -- a zone can always trivially reach itself", routes)
	}
}

func TestFindCandidateRoutes_RejectsImportOverZoneCap(t *testing.T) {
	zones := make([]Zone, MaxZonesPerTopologyImport+1)
	topo := &TopologyImport{Zones: zones}
	if _, err := FindCandidateRoutes(topo, "a", "b", 10); err == nil {
		t.Fatal("want error for a topology with too many zones")
	}
}

func TestFindCandidateRoutes_RejectsImportOverEdgeCap(t *testing.T) {
	edges := make([]RouteEdge, MaxEdgesPerTopologyImport+1)
	topo := &TopologyImport{Edges: edges}
	if _, err := FindCandidateRoutes(topo, "a", "b", 10); err == nil {
		t.Fatal("want error for a topology with too many edges")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/networktopology/... -run TestFindCandidateRoutes -v`
Expected: FAIL — `FindCandidateRoutes`, `RoutePath`, `MaxZonesPerTopologyImport`, `MaxEdgesPerTopologyImport`, `MaxCandidateRoutesPerQuery` undefined.

- [ ] **Step 3: Implement**

```go
// orchestrator/internal/networktopology/routes.go
package networktopology

import "fmt"

const (
	MaxZonesPerTopologyImport  = 500
	MaxEdgesPerTopologyImport  = 5000
	MaxHopsPerPathQuery        = 10
	MaxCandidateRoutesPerQuery = 20

	// maxRouteSearchSteps is a defensive bound on total DFS work,
	// independent of the hop/candidate-count caps -- a dense, highly
	// cyclic topology within the zone/edge caps could still cost a lot
	// of exploration before finding MaxCandidateRoutesPerQuery results.
	// Unexported: not a caller-tunable safety knob.
	maxRouteSearchSteps = 20000
)

// RoutePath is an ordered sequence of zone names from source to
// destination, inclusive of both endpoints.
type RoutePath []string

// FindCandidateRoutes returns up to MaxCandidateRoutesPerQuery simple
// paths (no repeated zone) from sourceZone to destZone across topo's
// declared adjacency, each at most maxHops edges long. maxHops is
// clamped to MaxHopsPerPathQuery if it exceeds that ceiling, or if it is
// zero or negative (meaning "no limit specified", never "zero hops
// allowed"). Zero candidate routes is a valid result, not an error --
// callers must classify this as "no known route", never "blocked".
// sourceZone == destZone always returns exactly one trivial
// two-element route (a zone can always trivially reach itself,
// independent of any declared edge).
func FindCandidateRoutes(topo *TopologyImport, sourceZone, destZone string, maxHops int) ([]RoutePath, error) {
	if len(topo.Zones) > MaxZonesPerTopologyImport {
		return nil, fmt.Errorf("networktopology: topology has too many zones -- got %d, max %d", len(topo.Zones), MaxZonesPerTopologyImport)
	}
	if len(topo.Edges) > MaxEdgesPerTopologyImport {
		return nil, fmt.Errorf("networktopology: topology has too many edges -- got %d, max %d", len(topo.Edges), MaxEdgesPerTopologyImport)
	}
	if sourceZone == destZone {
		return []RoutePath{{sourceZone, destZone}}, nil
	}
	if maxHops > MaxHopsPerPathQuery || maxHops <= 0 {
		maxHops = MaxHopsPerPathQuery
	}

	adj := buildAdjacency(topo.Edges)

	var results []RoutePath
	steps := 0
	visited := map[string]bool{sourceZone: true}
	var dfs func(current string, path RoutePath)
	dfs = func(current string, path RoutePath) {
		steps++
		if steps > maxRouteSearchSteps || len(results) >= MaxCandidateRoutesPerQuery {
			return
		}
		if current == destZone {
			found := make(RoutePath, len(path))
			copy(found, path)
			results = append(results, found)
			return
		}
		if len(path)-1 >= maxHops {
			return
		}
		for _, next := range adj[current] {
			if visited[next] {
				continue
			}
			visited[next] = true
			dfs(next, append(path, next))
			visited[next] = false
			if steps > maxRouteSearchSteps || len(results) >= MaxCandidateRoutesPerQuery {
				return
			}
		}
	}
	dfs(sourceZone, RoutePath{sourceZone})
	return results, nil
}

// buildAdjacency turns edges into an adjacency list. An undirected edge
// (Directed=false) is added in both directions; a directed edge only
// FromZone -> ToZone.
func buildAdjacency(edges []RouteEdge) map[string][]string {
	adj := map[string][]string{}
	for _, e := range edges {
		adj[e.FromZone] = append(adj[e.FromZone], e.ToZone)
		if !e.Directed {
			adj[e.ToZone] = append(adj[e.ToZone], e.FromZone)
		}
	}
	return adj
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/networktopology/... -v`
Expected: PASS — 18/18 (6 from Task 1 + 12 from this task).

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/networktopology/routes.go orchestrator/internal/networktopology/routes_test.go
git commit -m "feat(networktopology): add bounded-depth candidate route generation"
```

---

### Task 3: Per-Hop Evidence Composition

**Files:**
- Create: `orchestrator/internal/networkpath/compose.go`
- Test: `orchestrator/internal/networkpath/compose_test.go`

**Interfaces:**
- Consumes: `cloudgraph.PathState`/`Provenance` (existing), `networkpolicy.PolicyEvaluation` (Phase 2A, existing), `networkgraph.NetworkObservation` (Phase 1, existing), `networkcorrelation.CorrelateReachability` (Phase 2A, existing, called as-is).
- Produces: `CorroboratingEvidence{Source, EdgeKind, Note string}`, `HopResult{FromZone, ToZone string, State cloudgraph.PathState, Limitations string, Provenance cloudgraph.Provenance, Observation *networkgraph.NetworkObservation, PolicyEvaluation *networkpolicy.PolicyEvaluation, RouteDeclared bool, Corroboration []CorroboratingEvidence}`, `func ComposeHop(fromZone, toZone string, routeDeclared bool, policyEval *networkpolicy.PolicyEvaluation, observations []networkgraph.NetworkObservation) HopResult`.

- [ ] **Step 1: Write the failing tests**

```go
// orchestrator/internal/networkpath/compose_test.go
package networkpath

import (
	"testing"
	"time"

	"github.com/audspect/bas/internal/cloudgraph"
	"github.com/audspect/bas/internal/networkgraph"
	"github.com/audspect/bas/internal/networkpolicy"
)

func policyEval(state cloudgraph.PathState, confidence string) *networkpolicy.PolicyEvaluation {
	return &networkpolicy.PolicyEvaluation{State: state, Provenance: cloudgraph.Provenance{Confidence: confidence}}
}

func TestComposeHop_RouteSupportedPolicyPermitted_PolicySupported(t *testing.T) {
	hop := ComposeHop("dmz", "internal", true, policyEval(cloudgraph.PolicySupported, "medium"), nil)
	if hop.State != cloudgraph.PolicySupported {
		t.Fatalf("state = %q, want policy_supported", hop.State)
	}
}

func TestComposeHop_RouteSupportedPolicyDenied_Blocked(t *testing.T) {
	hop := ComposeHop("dmz", "internal", true, policyEval(cloudgraph.Blocked, "medium"), nil)
	if hop.State != cloudgraph.Blocked {
		t.Fatalf("state = %q, want blocked", hop.State)
	}
}

func TestComposeHop_NoKnownRoutePolicyPermitted_Unknown(t *testing.T) {
	hop := ComposeHop("dmz", "internal", false, policyEval(cloudgraph.PolicySupported, "medium"), nil)
	if hop.State != cloudgraph.Unknown {
		t.Fatalf("state = %q, want unknown -- a missing route must never let a permit verdict through", hop.State)
	}
	if hop.Limitations == "" {
		t.Fatal("want a non-empty limitation explaining the missing route")
	}
}

func TestComposeHop_RouteSupportedPolicyUnknown_Unknown(t *testing.T) {
	hop := ComposeHop("dmz", "internal", true, policyEval(cloudgraph.Unknown, "none"), nil)
	if hop.State != cloudgraph.Unknown {
		t.Fatalf("state = %q, want unknown -- a declared route with an unresolved policy verdict stays unknown", hop.State)
	}
}

func TestComposeHop_NoPolicyEvaluationAvailable_Unknown(t *testing.T) {
	hop := ComposeHop("dmz", "internal", true, nil, nil)
	if hop.State != cloudgraph.Unknown {
		t.Fatalf("state = %q, want unknown -- no policy evaluation at all means nothing to classify with", hop.State)
	}
	if hop.Limitations == "" {
		t.Fatal("want a non-empty limitation")
	}
}

func TestComposeHop_RealObservationOverridesRoutingGap(t *testing.T) {
	obs := []networkgraph.NetworkObservation{{
		Target:     networkgraph.Target{Host: "10.0.1.50", Port: 443},
		State:      cloudgraph.Observed,
		Provenance: cloudgraph.Provenance{Confidence: "observed", ObservedAt: time.Now()},
	}}
	eval := &networkpolicy.PolicyEvaluation{
		Query:      networkpolicy.PolicyQuery{DestCIDR: "10.0.1.50/32", Port: 443},
		State:      cloudgraph.PolicySupported,
		Provenance: cloudgraph.Provenance{Confidence: "medium"},
	}
	// routeDeclared=false: no route was found, but a real observation
	// demonstrates connectivity anyway -- it must win over the routing
	// gap, not be forced to Unknown.
	hop := ComposeHop("dmz", "internal", false, eval, obs)
	if hop.State != cloudgraph.Observed {
		t.Fatalf("state = %q, want observed -- a real observation must override a routing gap", hop.State)
	}
	if hop.Limitations == "" {
		t.Fatal("want a limitation noting the routing gap even though the observation won")
	}
	if hop.Observation == nil {
		t.Fatal("want the matched observation attached")
	}
}

func TestComposeHop_ObservationPresentButNoMatchFallsThroughToPolicy(t *testing.T) {
	// An observation slice is non-empty, but it targets a different host
	// than the policy evaluation's query -- networkcorrelation finds no
	// match, so this must fall through to ordinary policy-only logic,
	// not silently stay stuck on "no observation evidence".
	obs := []networkgraph.NetworkObservation{{
		Target: networkgraph.Target{Host: "192.168.9.9", Port: 22},
		State:  cloudgraph.Observed,
	}}
	eval := &networkpolicy.PolicyEvaluation{
		Query:      networkpolicy.PolicyQuery{DestCIDR: "10.0.1.50/32", Port: 443},
		State:      cloudgraph.PolicySupported,
		Provenance: cloudgraph.Provenance{Confidence: "medium"},
	}
	hop := ComposeHop("dmz", "internal", true, eval, obs)
	if hop.State != cloudgraph.PolicySupported {
		t.Fatalf("state = %q, want policy_supported -- no real match, must fall through to the policy verdict", hop.State)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/networkpath/... -v`
Expected: FAIL — `package networkpath` does not exist / `ComposeHop` undefined.

- [ ] **Step 3: Implement**

```go
// orchestrator/internal/networkpath/compose.go

// Package networkpath is the one place routing evidence
// (internal/networktopology), policy evidence (internal/networkpolicy),
// observation evidence (internal/networkgraph, via
// internal/networkcorrelation's existing fusion), and identity-domain
// corroboration (internal/attackpath, read-only) are combined into
// classified, multi-hop attack paths.
package networkpath

import (
	"github.com/audspect/bas/internal/cloudgraph"
	"github.com/audspect/bas/internal/networkcorrelation"
	"github.com/audspect/bas/internal/networkgraph"
	"github.com/audspect/bas/internal/networkpolicy"
)

// CorroboratingEvidence is purely additive context cited from the
// identity domain's existing attackpath graph. It never changes a hop's
// own PathState -- see internal/networkpath/corroborate.go.
type CorroboratingEvidence struct {
	Source   string `json:"source"` // "attackpath"
	EdgeKind string `json:"edgeKind,omitempty"`
	Note     string `json:"note,omitempty"`
}

// HopResult is one hop's evidence-composed classification.
type HopResult struct {
	FromZone, ToZone string
	State            cloudgraph.PathState
	Limitations      string
	Provenance       cloudgraph.Provenance
	Observation       *networkgraph.NetworkObservation
	PolicyEvaluation  *networkpolicy.PolicyEvaluation
	RouteDeclared     bool
	Corroboration     []CorroboratingEvidence
}

// ComposeHop classifies one hop given its possible evidence inputs, in
// priority order:
//
//  1. A real observation exists for this hop (networkcorrelation finds
//     a host/port match between policyEval's query and observations).
//     It wins outright -- routing evidence never overrides a real
//     observation, since a demonstrated connection or demonstrated block
//     is physical ground truth and the topology import might simply be
//     incomplete.
//  2. No observation, route declared: the policy verdict passes through
//     as-is.
//  3. No observation, route not declared (or no policy evaluation at
//     all): forced to Unknown, regardless of what the policy verdict
//     would otherwise have been -- a missing route must never read as
//     Blocked.
func ComposeHop(fromZone, toZone string, routeDeclared bool, policyEval *networkpolicy.PolicyEvaluation, observations []networkgraph.NetworkObservation) HopResult {
	result := HopResult{FromZone: fromZone, ToZone: toZone, RouteDeclared: routeDeclared, PolicyEvaluation: policyEval}

	if len(observations) > 0 && policyEval != nil {
		comparisons := networkcorrelation.CorrelateReachability([]networkpolicy.PolicyEvaluation{*policyEval}, observations)
		if cmp := comparisons[0]; cmp.Observation != nil {
			result.Observation = cmp.Observation
			result.State = cmp.Observation.State
			result.Provenance = cmp.Observation.Provenance
			if !routeDeclared {
				result.Limitations = "no declared route for this hop, but a live observation demonstrates connectivity directly -- topology data may be incomplete"
			}
			return result
		}
	}

	if policyEval == nil {
		result.State = cloudgraph.Unknown
		result.Provenance = cloudgraph.Provenance{Confidence: "none"}
		result.Limitations = "no policy evaluation available for this hop"
		return result
	}

	if !routeDeclared {
		result.State = cloudgraph.Unknown
		result.Provenance = cloudgraph.Provenance{Confidence: "none"}
		result.Limitations = "no declared route between these zones; policy evidence alone does not establish that an L3 path exists"
		return result
	}

	result.State = policyEval.State
	result.Provenance = policyEval.Provenance
	result.Limitations = policyEval.Limitations
	return result
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/networkpath/... -v`
Expected: PASS — 7/7.

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/networkpath/compose.go orchestrator/internal/networkpath/compose_test.go
git commit -m "feat(networkpath): add per-hop routing/policy/observation evidence composition"
```

---

### Task 4: Path-Level Aggregation

**Files:**
- Create: `orchestrator/internal/networkpath/aggregate.go`
- Test: `orchestrator/internal/networkpath/aggregate_test.go`

**Interfaces:**
- Consumes: `HopResult` (Task 3).
- Produces: `PathResult{State cloudgraph.PathState, Confidence string, Hops []HopResult}`, `func AggregatePathState(hops []HopResult) cloudgraph.PathState`, `func AggregateConfidence(hopCount int, weakestHopConfidence string) string`, `func AggregatePath(hops []HopResult) PathResult`.

- [ ] **Step 1: Write the failing tests**

```go
// orchestrator/internal/networkpath/aggregate_test.go
package networkpath

import (
	"testing"

	"github.com/audspect/bas/internal/cloudgraph"
)

func hr(state cloudgraph.PathState, confidence string) HopResult {
	return HopResult{State: state, Provenance: cloudgraph.Provenance{Confidence: confidence}}
}

func TestAggregatePathState_AllPolicySupported_PolicySupported(t *testing.T) {
	got := AggregatePathState([]HopResult{hr(cloudgraph.PolicySupported, "medium"), hr(cloudgraph.PolicySupported, "medium")})
	if got != cloudgraph.PolicySupported {
		t.Fatalf("got %q, want policy_supported", got)
	}
}

func TestAggregatePathState_OneBlockedHopShortCircuits_Blocked(t *testing.T) {
	got := AggregatePathState([]HopResult{hr(cloudgraph.Observed, "observed"), hr(cloudgraph.Blocked, "medium"), hr(cloudgraph.PolicySupported, "medium")})
	if got != cloudgraph.Blocked {
		t.Fatalf("got %q, want blocked -- one blocked hop must kill the whole path regardless of the others", got)
	}
}

func TestAggregatePathState_OneUnknownHopCapsClassification_Unknown(t *testing.T) {
	got := AggregatePathState([]HopResult{hr(cloudgraph.Observed, "observed"), hr(cloudgraph.Unknown, "none")})
	if got != cloudgraph.Unknown {
		t.Fatalf("got %q, want unknown -- a path must never read stronger than its weakest hop", got)
	}
}

func TestAggregatePathState_AllObserved_Observed(t *testing.T) {
	got := AggregatePathState([]HopResult{hr(cloudgraph.Observed, "observed"), hr(cloudgraph.Observed, "observed")})
	if got != cloudgraph.Observed {
		t.Fatalf("got %q, want observed", got)
	}
}

func TestAggregateConfidence_AnnotatesHopCountAndDowngradesFromWeakestLink(t *testing.T) {
	got := AggregateConfidence(3, "medium")
	want := "low (3-hop chain; weakest link: medium)"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestAggregateConfidence_NoneFloorPreserved(t *testing.T) {
	got := AggregateConfidence(2, "none")
	want := "none (2-hop chain; weakest link: none)"
	if got != want {
		t.Fatalf("got %q, want %q -- a floor of no evidence at all must not be annotated up to low", got, want)
	}
}

func TestAggregatePath_FullIntegration_CitesTheHopThatDeterminedTheState(t *testing.T) {
	hops := []HopResult{hr(cloudgraph.Observed, "observed"), hr(cloudgraph.Unknown, "none")}
	result := AggregatePath(hops)
	if result.State != cloudgraph.Unknown {
		t.Fatalf("State = %q, want unknown", result.State)
	}
	if result.Confidence != "none (2-hop chain; weakest link: none)" {
		t.Fatalf("Confidence = %q, want it to cite the unknown hop's own confidence (none), not the observed hop's", result.Confidence)
	}
	if len(result.Hops) != 2 {
		t.Fatalf("got %d hops in result, want 2", len(result.Hops))
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/networkpath/... -run 'TestAggregate' -v`
Expected: FAIL — `AggregatePathState`, `AggregateConfidence`, `AggregatePath`, `PathResult` undefined.

- [ ] **Step 3: Implement**

```go
// orchestrator/internal/networkpath/aggregate.go
package networkpath

import (
	"fmt"

	"github.com/audspect/bas/internal/cloudgraph"
)

// PathResult is the full path-level result: an aggregated PathState and
// confidence, plus the per-hop detail it was derived from.
type PathResult struct {
	State      cloudgraph.PathState
	Confidence string
	Hops       []HopResult
}

// AggregatePathState computes the path-level PathState from an ordered
// slice of per-hop results, following the exact ranking precedent
// cloudgraph.worstState (internal/cloudgraph/cloud_reachability.go:42-87)
// already established for Cloud BAS's own multi-hop permission-path
// engine on this same PathState enum: Blocked short-circuits
// immediately (any blocked hop kills the whole path); otherwise
// weakest-wins in order Unknown > PolicySupported > Observed.
// Re-implemented locally since worstState is unexported to cloudgraph --
// this keeps networkpath's own evidence domain self-contained rather
// than reaching into cloudgraph's internals.
func AggregatePathState(hops []HopResult) cloudgraph.PathState {
	sawUnknown := false
	sawPolicySupported := false
	sawObserved := false
	for _, h := range hops {
		switch h.State {
		case cloudgraph.Blocked:
			return cloudgraph.Blocked
		case cloudgraph.Unknown:
			sawUnknown = true
		case cloudgraph.PolicySupported:
			sawPolicySupported = true
		case cloudgraph.Observed:
			sawObserved = true
		}
	}
	if sawUnknown {
		return cloudgraph.Unknown
	}
	if sawPolicySupported {
		return cloudgraph.PolicySupported
	}
	if sawObserved {
		return cloudgraph.Observed
	}
	return cloudgraph.Unknown
}

// AggregateConfidence returns the path-level confidence string. If the
// weakest hop's own confidence is "none" (no evidence at all for that
// hop), the path's confidence floor is also "none". Otherwise the path
// always reads as "low", regardless of how confident the weakest hop
// itself was -- chaining multiple hops compounds uncertainty beyond any
// single hop's own evidence quality. Always annotated with hop-count
// and the weakest hop's own value for transparency: never a bare,
// undifferentiated "low".
func AggregateConfidence(hopCount int, weakestHopConfidence string) string {
	label := "low"
	if weakestHopConfidence == "none" {
		label = "none"
	}
	return fmt.Sprintf("%s (%d-hop chain; weakest link: %s)", label, hopCount, weakestHopConfidence)
}

// AggregatePath computes the full path-level result from an ordered
// slice of per-hop results.
func AggregatePath(hops []HopResult) PathResult {
	state := AggregatePathState(hops)
	return PathResult{State: state, Confidence: AggregateConfidence(len(hops), weakestHopConfidence(hops, state)), Hops: hops}
}

// weakestHopConfidence returns the Provenance.Confidence of the first
// hop whose State equals the path's own aggregated state -- the hop
// that actually determined it, per AggregatePathState's ranking.
func weakestHopConfidence(hops []HopResult, pathState cloudgraph.PathState) string {
	for _, h := range hops {
		if h.State == pathState {
			return h.Provenance.Confidence
		}
	}
	if len(hops) > 0 {
		return hops[0].Provenance.Confidence
	}
	return "none"
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/networkpath/... -v`
Expected: PASS — 14/14 (7 from Task 3 + 7 from this task).

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/networkpath/aggregate.go orchestrator/internal/networkpath/aggregate_test.go
git commit -m "feat(networkpath): add path-level classification and confidence aggregation"
```

---

### Task 5: Attackpath Corroboration

**Files:**
- Create: `orchestrator/internal/networkpath/corroborate.go`
- Test: `orchestrator/internal/networkpath/corroborate_test.go`

**Interfaces:**
- Consumes: `CorroboratingEvidence` (Task 3), `attackpath.Graph`/`BuildGraph`/`Edges`/`EdgeSMB`/`EdgeWinRM`/`EdgeRDP`/`NormalizeHostKey`/`SegmentationViolations`/`SegmentationViolation` (existing, unmodified).
- Produces: `func CorroborateHop(g *attackpath.Graph, fromHost, toHost string) []CorroboratingEvidence`, `func CorroborateSegmentation(g *attackpath.Graph, fromZone, toZone string) []CorroboratingEvidence`.

- [ ] **Step 1: Write the failing tests**

```go
// orchestrator/internal/networkpath/corroborate_test.go
package networkpath

import (
	"testing"

	"github.com/audspect/bas/internal/attackpath"
)

func graphWithEdge(from, to string, kind attackpath.EdgeKind) *attackpath.Graph {
	g := attackpath.BuildGraph(attackpath.Collection{
		Nodes: []attackpath.Node{{ID: from, Kind: attackpath.KindHost}, {ID: to, Kind: attackpath.KindHost}},
		Edges: []attackpath.Edge{{From: from, To: to, Kind: kind}},
	})
	return g
}

func TestCorroborateHop_FindsMatchingSMBEdge(t *testing.T) {
	g := graphWithEdge("WIN-ALPHA", "WIN-BETA", attackpath.EdgeSMB)
	got := CorroborateHop(g, "WIN-ALPHA", "WIN-BETA")
	if len(got) != 1 || got[0].EdgeKind != string(attackpath.EdgeSMB) {
		t.Fatalf("got %+v, want one smb corroboration", got)
	}
}

func TestCorroborateHop_NoMatchReturnsEmptyNotError(t *testing.T) {
	g := graphWithEdge("WIN-ALPHA", "WIN-BETA", attackpath.EdgeSMB)
	got := CorroborateHop(g, "WIN-GAMMA", "WIN-DELTA")
	if len(got) != 0 {
		t.Fatalf("got %+v, want none", got)
	}
}

func TestCorroborateHop_NilGraphReturnsEmpty(t *testing.T) {
	got := CorroborateHop(nil, "WIN-ALPHA", "WIN-BETA")
	if len(got) != 0 {
		t.Fatalf("got %+v, want none for a nil graph", got)
	}
}

func TestCorroborateHop_IgnoresNonLateralEdgeKinds(t *testing.T) {
	g := graphWithEdge("alice", "admins", attackpath.EdgeMemberOf)
	got := CorroborateHop(g, "alice", "admins")
	if len(got) != 0 {
		t.Fatalf("got %+v, want none -- member-of is not a network-reachability edge", got)
	}
}

func TestCorroborateHop_NormalizesHostKeysBeforeComparing(t *testing.T) {
	g := graphWithEdge("win-alpha.corp.local", "WIN-BETA", attackpath.EdgeWinRM)
	got := CorroborateHop(g, "WIN-ALPHA", "win-beta.corp.local")
	if len(got) != 1 {
		t.Fatalf("got %+v, want one match -- hostnames must be normalized before comparing", got)
	}
}

func TestCorroborateSegmentation_FindsNameMatchedViolation(t *testing.T) {
	g := attackpath.BuildGraph(attackpath.Collection{
		Nodes: []attackpath.Node{
			{ID: "WIN-ALPHA", Kind: attackpath.KindHost, Segment: "dmz"},
			{ID: "WIN-BETA", Kind: attackpath.KindHost, Segment: "internal"},
		},
		Edges: []attackpath.Edge{{From: "WIN-ALPHA", To: "WIN-BETA", Kind: attackpath.EdgeSMB}},
	})
	got := CorroborateSegmentation(g, "dmz", "internal")
	if len(got) != 1 {
		t.Fatalf("got %+v, want one segmentation-violation corroboration", got)
	}
}

func TestCorroborateSegmentation_MismatchedNameReturnsEmpty(t *testing.T) {
	g := attackpath.BuildGraph(attackpath.Collection{
		Nodes: []attackpath.Node{
			{ID: "WIN-ALPHA", Kind: attackpath.KindHost, Segment: "dmz"},
			{ID: "WIN-BETA", Kind: attackpath.KindHost, Segment: "internal"},
		},
		Edges: []attackpath.Edge{{From: "WIN-ALPHA", To: "WIN-BETA", Kind: attackpath.EdgeSMB}},
	})
	got := CorroborateSegmentation(g, "dmz", "some-other-zone-name")
	if len(got) != 0 {
		t.Fatalf("got %+v, want none -- attackpath.Segment has no guaranteed correspondence to this phase's zone names", got)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/networkpath/... -run 'TestCorroborate' -v`
Expected: FAIL — `CorroborateHop`, `CorroborateSegmentation` undefined.

- [ ] **Step 3: Implement**

```go
// orchestrator/internal/networkpath/corroborate.go
package networkpath

import (
	"strings"

	"github.com/audspect/bas/internal/attackpath"
)

// lateralEdgeKinds restricts corroboration to the identity domain's own
// host-to-host lateral-movement edges -- never ACL-abuse/delegation
// edges, which aren't network-reachability evidence.
var lateralEdgeKinds = map[attackpath.EdgeKind]bool{
	attackpath.EdgeSMB:   true,
	attackpath.EdgeWinRM: true,
	attackpath.EdgeRDP:   true,
}

// CorroborateHop looks for an attackpath edge between fromHost and
// toHost (normalized via attackpath.NormalizeHostKey, since Node.ID is
// not guaranteed pre-normalized) restricted to SMB/WinRM/RDP. Absence of
// any match, or of an attackpath graph at all, returns an empty slice,
// never an error -- corroboration is optional and fails open, and never
// changes a hop's own PathState.
func CorroborateHop(g *attackpath.Graph, fromHost, toHost string) []CorroboratingEvidence {
	if g == nil {
		return nil
	}
	from := attackpath.NormalizeHostKey(fromHost)
	to := attackpath.NormalizeHostKey(toHost)
	var out []CorroboratingEvidence
	for _, e := range g.Edges() {
		if !lateralEdgeKinds[e.Kind] {
			continue
		}
		if attackpath.NormalizeHostKey(e.From) != from || attackpath.NormalizeHostKey(e.To) != to {
			continue
		}
		out = append(out, CorroboratingEvidence{Source: "attackpath", EdgeKind: string(e.Kind), Note: "identity-domain lateral-movement edge exists between these hosts -- corroborating, not authoritative"})
	}
	return out
}

// CorroborateSegmentation cites an attackpath SegmentationViolation
// whose FromSegment/ToSegment name-match the given zone pair -- a
// loose, best-effort note. attackpath.Segment has no guaranteed
// correspondence to this phase's declared zones, so a mismatch or
// absence is silent, never an error.
func CorroborateSegmentation(g *attackpath.Graph, fromZone, toZone string) []CorroboratingEvidence {
	if g == nil {
		return nil
	}
	var out []CorroboratingEvidence
	for _, v := range g.SegmentationViolations() {
		if !strings.EqualFold(v.FromSegment, fromZone) || !strings.EqualFold(v.ToSegment, toZone) {
			continue
		}
		out = append(out, CorroboratingEvidence{Source: "attackpath", EdgeKind: string(v.Kind), Note: "identity-domain segmentation violation recorded between these zone-named segments -- corroborating, not authoritative"})
	}
	return out
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/networkpath/... -v`
Expected: PASS — 21/21 (14 from Tasks 3-4 + 7 from this task).

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/networkpath/corroborate.go orchestrator/internal/networkpath/corroborate_test.go
git commit -m "feat(networkpath): add optional, non-authoritative attackpath corroboration"
```

---

### Task 6: Topology Import Schema & Store

**Files:**
- Create: `orchestrator/internal/db/networktopology_store.go`
- Test: `orchestrator/internal/db/networktopology_store_test.go`
- Modify: `orchestrator/internal/testutil/testdb.go` (immediately after the `EnsureNetworkPolicySchema` call, confirmed at lines 141-144 this session)
- Modify: `orchestrator/cmd/server/main.go` (immediately after the `EnsureNetworkPolicySchema` call, confirmed at line 296 this session)

**Interfaces:**
- Consumes: `networktopology.TopologyImport`/`Zone`/`RouteEdge` (Task 1), the existing `nullableString(s string) *string` helper already defined in `orchestrator/internal/db/networkdiscovery_store.go:78` (same `db` package, reused, not redefined).
- Produces: `func EnsureNetworkTopologySchema(ctx context.Context, pool *pgxpool.Pool) error`, `func InsertNetworkTopologyImport(ctx context.Context, pool *pgxpool.Pool, imp *networktopology.TopologyImport) error`, `func GetNetworkTopologyImport(ctx context.Context, pool *pgxpool.Pool, id string) (*networktopology.TopologyImport, error)`, `func ListNetworkTopologyImports(ctx context.Context, pool *pgxpool.Pool, limit int) ([]*networktopology.TopologyImport, error)`.

- [ ] **Step 1: Write the failing tests**

```go
// orchestrator/internal/db/networktopology_store_test.go
package db_test

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/networktopology"
)

func TestInsertNetworkTopologyImport_RoundTripsThroughGetAndList(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		imp := &networktopology.TopologyImport{
			ID: "ntimp-roundtrip-1", SourceType: "manual-declared", ImportedBy: "alice", ConfigVersion: "v1",
			Zones:       []networktopology.Zone{{Name: "dmz", CIDRs: []string{"10.0.1.0/24"}}},
			Edges:       []networktopology.RouteEdge{{FromZone: "dmz", ToZone: "internal"}},
			Limitations: []string{"no NAT interaction modeled"},
		}
		if err := db.InsertNetworkTopologyImport(context.Background(), pool, imp); err != nil {
			t.Fatalf("insert: %v", err)
		}

		got, err := db.GetNetworkTopologyImport(context.Background(), pool, imp.ID)
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		if got.SourceType != "manual-declared" || got.ImportedBy != "alice" || got.ConfigVersion != "v1" {
			t.Fatalf("got %+v, want SourceType=manual-declared ImportedBy=alice ConfigVersion=v1", got)
		}
		if len(got.Zones) != 1 || got.Zones[0].Name != "dmz" {
			t.Fatalf("Zones round-trip mismatch: %+v", got.Zones)
		}
		if len(got.Edges) != 1 || got.Edges[0].FromZone != "dmz" || got.Edges[0].ToZone != "internal" {
			t.Fatalf("Edges round-trip mismatch: %+v", got.Edges)
		}
		if len(got.Limitations) != 1 || got.Limitations[0] != "no NAT interaction modeled" {
			t.Fatalf("Limitations round-trip mismatch: %+v", got.Limitations)
		}
		if got.ImportedAt.IsZero() {
			t.Fatal("ImportedAt should be populated by the database default")
		}

		list, err := db.ListNetworkTopologyImports(context.Background(), pool, 100)
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

func TestGetNetworkTopologyImport_NonexistentIDReturnsErrNoRows(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		_, err := db.GetNetworkTopologyImport(context.Background(), pool, "nonexistent-topology-id")
		if !errors.Is(err, pgx.ErrNoRows) {
			t.Fatalf("got %v, want an error satisfying errors.Is(err, pgx.ErrNoRows)", err)
		}
	})
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go vet ./internal/db/...`
Expected: FAIL — `db.InsertNetworkTopologyImport`, `db.GetNetworkTopologyImport`, `db.ListNetworkTopologyImports` undefined.

- [ ] **Step 3: Implement the store**

```go
// orchestrator/internal/db/networktopology_store.go
package db

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/networktopology"
)

// EnsureNetworkTopologySchema creates the network_topology_imports table.
func EnsureNetworkTopologySchema(ctx context.Context, pool *pgxpool.Pool) error {
	_, err := pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS network_topology_imports (
			id             text        PRIMARY KEY DEFAULT gen_random_uuid()::text,
			source_type    text        NOT NULL,
			imported_by    text,
			imported_at    timestamptz NOT NULL DEFAULT NOW(),
			config_version text,
			limitations    text[],
			topology_data  jsonb       NOT NULL
		)`)
	if err != nil {
		return fmt.Errorf("network_topology_imports: ensure schema: %w", err)
	}
	return nil
}

// topologyData is the shape persisted in the topology_data jsonb column
// -- just the two slices that make an import's content, not its
// metadata (which live in their own columns).
type topologyData struct {
	Zones []networktopology.Zone      `json:"zones"`
	Edges []networktopology.RouteEdge `json:"edges"`
}

// InsertNetworkTopologyImport writes a new network_topology_imports
// row. The caller supplies imp.ID already generated.
func InsertNetworkTopologyImport(ctx context.Context, pool *pgxpool.Pool, imp *networktopology.TopologyImport) error {
	data, err := json.Marshal(topologyData{Zones: imp.Zones, Edges: imp.Edges})
	if err != nil {
		return fmt.Errorf("network_topology_imports: marshal topology data for %s: %w", imp.ID, err)
	}
	_, err = pool.Exec(ctx,
		`INSERT INTO network_topology_imports (id, source_type, imported_by, config_version, limitations, topology_data)
		 VALUES ($1,$2,$3,$4,$5,$6)`,
		imp.ID, imp.SourceType, nullableString(imp.ImportedBy), nullableString(imp.ConfigVersion), imp.Limitations, data)
	if err != nil {
		return fmt.Errorf("network_topology_imports: insert %s: %w", imp.ID, err)
	}
	return nil
}

func scanNetworkTopologyImport(row pgx.Row) (*networktopology.TopologyImport, error) {
	imp := &networktopology.TopologyImport{}
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
	var td topologyData
	if err := json.Unmarshal(data, &td); err != nil {
		return nil, fmt.Errorf("network_topology_imports: unmarshal topology data for %s: %w", imp.ID, err)
	}
	imp.Zones = td.Zones
	imp.Edges = td.Edges
	return imp, nil
}

// GetNetworkTopologyImport returns one import by id. A missing id
// returns an error satisfying errors.Is(err, pgx.ErrNoRows).
func GetNetworkTopologyImport(ctx context.Context, pool *pgxpool.Pool, id string) (*networktopology.TopologyImport, error) {
	row := pool.QueryRow(ctx,
		`SELECT id, source_type, imported_by, imported_at, config_version, limitations, topology_data
		 FROM network_topology_imports WHERE id = $1`, id)
	imp, err := scanNetworkTopologyImport(row)
	if err != nil {
		return nil, fmt.Errorf("network_topology_imports: get %s: %w", id, err)
	}
	return imp, nil
}

// ListNetworkTopologyImports returns up to limit rows, newest first.
func ListNetworkTopologyImports(ctx context.Context, pool *pgxpool.Pool, limit int) ([]*networktopology.TopologyImport, error) {
	rows, err := pool.Query(ctx,
		`SELECT id, source_type, imported_by, imported_at, config_version, limitations, topology_data
		 FROM network_topology_imports ORDER BY imported_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("network_topology_imports: list: %w", err)
	}
	defer rows.Close()
	var out []*networktopology.TopologyImport
	for rows.Next() {
		imp, err := scanNetworkTopologyImport(rows)
		if err != nil {
			return nil, fmt.Errorf("network_topology_imports: list scan: %w", err)
		}
		out = append(out, imp)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("network_topology_imports: list rows: %w", err)
	}
	return out, nil
}
```

- [ ] **Step 4: Wire schema creation into the test pool and server startup**

In `orchestrator/internal/testutil/testdb.go`, immediately after the existing block:
```go
	if err := db.EnsureNetworkPolicySchema(ctx, pool); err != nil {
		pool.Close()
		_ = container.Terminate(context.Background())
		return nil, fmt.Errorf("testutil: EnsureNetworkPolicySchema: %w", err)
	}
```
add:
```go
	if err := db.EnsureNetworkTopologySchema(ctx, pool); err != nil {
		pool.Close()
		_ = container.Terminate(context.Background())
		return nil, fmt.Errorf("testutil: EnsureNetworkTopologySchema: %w", err)
	}
```

In `orchestrator/cmd/server/main.go`, immediately after the existing block:
```go
	if err := db.EnsureNetworkPolicySchema(context.Background(), adminPool); err != nil {
		log.Fatalf("[FATAL] network policy schema: %v", err)
	}
```
add:
```go
	if err := db.EnsureNetworkTopologySchema(context.Background(), adminPool); err != nil {
		log.Fatalf("[FATAL] network topology schema: %v", err)
	}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd orchestrator && go build ./... && go test ./internal/db/... -run 'TestInsertNetworkTopologyImport|TestGetNetworkTopologyImport' -v`
Expected: PASS — 2/2.

- [ ] **Step 6: Run the full `internal/db` suite to confirm no regression**

Check memory headroom first: `Get-CimInstance Win32_OperatingSystem | Select-Object FreePhysicalMemory,TotalVisibleMemorySize` (PowerShell).

Run: `cd orchestrator && go test ./internal/db/... -v`
Expected: PASS — all tests, no regressions.

- [ ] **Step 7: Commit**

```bash
git add orchestrator/internal/db/networktopology_store.go orchestrator/internal/db/networktopology_store_test.go orchestrator/internal/testutil/testdb.go orchestrator/cmd/server/main.go
git commit -m "feat(networktopology): add schema and store layer for topology imports"
```

---

### Task 7: Topology Import HTTP API & Permission

**Files:**
- Create: `orchestrator/internal/api/networktopology_handlers.go`
- Test: `orchestrator/internal/api/networktopology_handlers_test.go`
- Modify: `orchestrator/internal/auth/permissions.go` (const block ends at line 227 this session; `RoleAdmin` map includes `CanImportNetworkPolicy: true,` at line 285; `RoleAnalyst` map includes `CanImportNetworkPolicy: true,` at line 301 — add alongside both)
- Modify: `orchestrator/internal/api/routes.go` (GET routes end at line 251, POST routes end at line 422 this session)
- Modify: `orchestrator/internal/api/rbac_matrix_test.go` (GET rows end at line 64, POST rows end at line 208 this session)

**Interfaces:**
- Consumes: `networktopology.TopologyImport`/`Zone`/`RouteEdge`/`MaxZonesPerTopologyImport`/`MaxEdgesPerTopologyImport` (Tasks 1-2), `db.InsertNetworkTopologyImport`/`GetNetworkTopologyImport`/`ListNetworkTopologyImports` (Task 6), existing `jsonError`/`respond`/`respondStatus`/`newID`/`auth.ClaimsFrom`/`h.auditLog`/`h.db` helpers (unchanged).
- Produces: `auth.CanImportNetworkTopology Permission`, `func (h *Handler) CreateNetworkTopologyImport(w http.ResponseWriter, r *http.Request)`, `func (h *Handler) ListNetworkTopologyImports(w http.ResponseWriter, r *http.Request)`, `func (h *Handler) GetNetworkTopologyImport(w http.ResponseWriter, r *http.Request)`, routes `POST /api/network-topology-imports`, `GET /api/network-topology-imports`, `GET /api/network-topology-imports/{id}`.

- [ ] **Step 1: Write the failing tests**

```go
// orchestrator/internal/api/networktopology_handlers_test.go
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
	"github.com/audspect/bas/internal/networktopology"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

func validTopologyImportBody() map[string]any {
	return map[string]any{
		"sourceType": "manual-declared",
		"zones":      []map[string]any{{"name": "dmz", "cidrs": []string{"10.0.1.0/24"}}, {"name": "internal", "cidrs": []string{"10.0.2.0/24"}}},
		"edges":      []map[string]any{{"fromZone": "dmz", "toZone": "internal"}},
	}
}

func networkTopologyImportReq(t *testing.T, pool *pgxpool.Pool, body map[string]any) *http.Request {
	t.Helper()
	userID := seedUser(t, pool, "nettopo-op", "pw12345678", string(auth.RoleAnalyst), true)
	b, _ := json.Marshal(body)
	return authedRequest(t, http.MethodPost, "/api/network-topology-imports", bytes.NewReader(b), auth.RoleAnalyst, userID)
}

func TestCreateNetworkTopologyImport_ValidImportPersists(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		req := networkTopologyImportReq(t, pool, validTopologyImportBody())
		rec := callAuthed(h.CreateNetworkTopologyImport, req)
		if rec.Code != http.StatusCreated {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var resp networktopology.TopologyImport
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if resp.ID == "" {
			t.Fatal("want non-empty id")
		}
	})
}

func TestCreateNetworkTopologyImport_ZeroEdgesAllowed(t *testing.T) {
	// A topology may legitimately declare zones with no mapped routes
	// yet -- "topology may be unknown or partially modeled" per the
	// spec. Unlike Phase 2A's PolicyImport, edges are not required.
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		body := validTopologyImportBody()
		body["edges"] = []map[string]any{}
		req := networkTopologyImportReq(t, pool, body)
		rec := callAuthed(h.CreateNetworkTopologyImport, req)
		if rec.Code != http.StatusCreated {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
	})
}

func TestCreateNetworkTopologyImport_EmptyZonesRejected(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		body := validTopologyImportBody()
		body["zones"] = []map[string]any{}
		req := networkTopologyImportReq(t, pool, body)
		rec := callAuthed(h.CreateNetworkTopologyImport, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
	})
}

func TestCreateNetworkTopologyImport_DuplicateZoneNameRejected(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		body := validTopologyImportBody()
		body["zones"] = []map[string]any{{"name": "dmz", "cidrs": []string{"10.0.1.0/24"}}, {"name": "dmz", "cidrs": []string{"10.0.9.0/24"}}}
		req := networkTopologyImportReq(t, pool, body)
		rec := callAuthed(h.CreateNetworkTopologyImport, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
	})
}

func TestCreateNetworkTopologyImport_InvalidCIDRRejected(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		body := validTopologyImportBody()
		body["zones"] = []map[string]any{{"name": "dmz", "cidrs": []string{"not-a-cidr"}}}
		req := networkTopologyImportReq(t, pool, body)
		rec := callAuthed(h.CreateNetworkTopologyImport, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
	})
}

func TestCreateNetworkTopologyImport_EdgeReferencingUnknownZoneRejected(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		body := validTopologyImportBody()
		body["edges"] = []map[string]any{{"fromZone": "dmz", "toZone": "does-not-exist"}}
		req := networkTopologyImportReq(t, pool, body)
		rec := callAuthed(h.CreateNetworkTopologyImport, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
	})
}

func TestCreateNetworkTopologyImport_SelfLoopEdgeRejected(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		body := validTopologyImportBody()
		body["edges"] = []map[string]any{{"fromZone": "dmz", "toZone": "dmz"}}
		req := networkTopologyImportReq(t, pool, body)
		rec := callAuthed(h.CreateNetworkTopologyImport, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, body = %s -- a self-loop edge is malformed input", rec.Code, rec.Body.String())
		}
	})
}

func TestCreateNetworkTopologyImport_OversizedBodyRejectedBeforeFullDecode(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		userID := seedUser(t, pool, "nettopo-op-oversize", "pw12345678", string(auth.RoleAnalyst), true)
		oversized := []byte(`{"sourceType":"` + strings.Repeat("x", maxNetworkTopologyImportRequestBytes+1) + `"}`)
		req := authedRequest(t, http.MethodPost, "/api/network-topology-imports", bytes.NewReader(oversized), auth.RoleAnalyst, userID)
		rec := callAuthed(h.CreateNetworkTopologyImport, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
	})
}

func TestCreateNetworkTopologyImport_ImportedByIsServerControlled(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		userID := seedUser(t, pool, "nettopo-op-spoof", "pw12345678", string(auth.RoleAnalyst), true)
		body := validTopologyImportBody()
		body["importedBy"] = "spoofed-user"
		b, _ := json.Marshal(body)
		req := authedRequest(t, http.MethodPost, "/api/network-topology-imports", bytes.NewReader(b), auth.RoleAnalyst, userID)
		rec := callAuthed(h.CreateNetworkTopologyImport, req)
		if rec.Code != http.StatusCreated {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var resp networktopology.TopologyImport
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
		got, err := db.GetNetworkTopologyImport(context.Background(), pool, resp.ID)
		if err != nil {
			t.Fatalf("lookup: %v", err)
		}
		if got.ImportedBy != userID {
			t.Fatalf("ImportedBy = %q, want %q (the authenticated caller, not the spoofed body value)", got.ImportedBy, userID)
		}
	})
}

func TestListAndGetNetworkTopologyImport_RoundTrip(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		req := networkTopologyImportReq(t, pool, validTopologyImportBody())
		createRec := callAuthed(h.CreateNetworkTopologyImport, req)
		if createRec.Code != http.StatusCreated {
			t.Fatalf("create status = %d, body = %s", createRec.Code, createRec.Body.String())
		}
		var created networktopology.TopologyImport
		if err := json.Unmarshal(createRec.Body.Bytes(), &created); err != nil {
			t.Fatalf("decode create: %v", err)
		}

		listReq := authedRequest(t, http.MethodGet, "/api/network-topology-imports", nil, auth.RoleViewer, "")
		listRec := callAuthed(h.ListNetworkTopologyImports, listReq)
		if listRec.Code != http.StatusOK {
			t.Fatalf("list status = %d, body = %s", listRec.Code, listRec.Body.String())
		}

		getReq := authedRequest(t, http.MethodGet, "/api/network-topology-imports/"+created.ID, nil, auth.RoleViewer, "")
		getReq = withURLParam(getReq, "id", created.ID)
		getRec := callAuthed(h.GetNetworkTopologyImport, getReq)
		if getRec.Code != http.StatusOK {
			t.Fatalf("get status = %d, body = %s", getRec.Code, getRec.Body.String())
		}
	})
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go vet ./internal/api/...`
Expected: FAIL — `h.CreateNetworkTopologyImport`, `maxNetworkTopologyImportRequestBytes` undefined.

- [ ] **Step 3: Add the permission**

In `orchestrator/internal/auth/permissions.go`, replace:
```go
	// TCF Phase 2A: link/new/dismiss unresolved actor identities (Admin only).
	CanResolveActorIdentity Permission = "intel:resolve-actor"

	// network-policy:import gates importing a normalized firewall/
	// segmentation policy document (Network BAS Phase 2A) -- granted
	// alongside CanRunScenario, not admin-only, since this is an
	// analyst-usable, evidence-producing action.
	CanImportNetworkPolicy Permission = "network-policy:import"
)
```
with:
```go
	// TCF Phase 2A: link/new/dismiss unresolved actor identities (Admin only).
	CanResolveActorIdentity Permission = "intel:resolve-actor"

	// network-policy:import gates importing a normalized firewall/
	// segmentation policy document (Network BAS Phase 2A) -- granted
	// alongside CanRunScenario, not admin-only, since this is an
	// analyst-usable, evidence-producing action.
	CanImportNetworkPolicy Permission = "network-policy:import"

	// network-topology:import gates importing a declared L3
	// zone-adjacency topology (Network BAS Phase 3) -- same placement
	// as CanImportNetworkPolicy, for the same reason.
	CanImportNetworkTopology Permission = "network-topology:import"
)
```
(Match against the real current text around line 220-227 before replacing -- it may differ slightly if other work has landed; preserve any lines in between untouched.)

Then add `CanImportNetworkTopology: true,` alongside the existing `CanImportNetworkPolicy: true,` line inside the `RoleAdmin` map, and alongside the existing `CanImportNetworkPolicy: true,` line inside the `RoleAnalyst` map.

- [ ] **Step 4: Implement the handlers**

```go
// orchestrator/internal/api/networktopology_handlers.go
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
	"github.com/audspect/bas/internal/networktopology"
)

// maxNetworkTopologyImportRequestBytes mirrors Phase 2A's policy-import
// cap -- a real topology document can be as large as a real policy
// document.
const maxNetworkTopologyImportRequestBytes = 5 << 20

// CreateNetworkTopologyImport -- POST /api/network-topology-imports.
func (h *Handler) CreateNetworkTopologyImport(w http.ResponseWriter, r *http.Request) {
	var req networktopology.TopologyImport
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxNetworkTopologyImportRequestBytes)).Decode(&req); err != nil {
		jsonError(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if err := validateNetworkTopologyImport(&req); err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}

	var importedBy string
	if c, ok := auth.ClaimsFrom(r.Context()); ok && c != nil {
		importedBy = c.UserID
	}
	req.ID = newID()
	req.ImportedBy = importedBy

	if err := db.InsertNetworkTopologyImport(r.Context(), h.db, &req); err != nil {
		h.auditLog(r, "networktopology.import", "", map[string]any{"error": err.Error()}, "error")
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	h.auditLog(r, "networktopology.import", req.ID, map[string]any{"zoneCount": len(req.Zones), "edgeCount": len(req.Edges)}, "ok")
	respondStatus(w, req, http.StatusCreated)
}

func validateNetworkTopologyImport(imp *networktopology.TopologyImport) error {
	if len(imp.Zones) == 0 {
		return fmt.Errorf("at least one zone is required")
	}
	if len(imp.Zones) > networktopology.MaxZonesPerTopologyImport {
		return fmt.Errorf("too many zones — got %d, max %d", len(imp.Zones), networktopology.MaxZonesPerTopologyImport)
	}
	if len(imp.Edges) > networktopology.MaxEdgesPerTopologyImport {
		return fmt.Errorf("too many edges — got %d, max %d", len(imp.Edges), networktopology.MaxEdgesPerTopologyImport)
	}
	zoneNames := map[string]bool{}
	for i, z := range imp.Zones {
		if z.Name == "" {
			return fmt.Errorf("zones[%d]: name required", i)
		}
		if zoneNames[z.Name] {
			return fmt.Errorf("zones[%d]: duplicate zone name %q", i, z.Name)
		}
		zoneNames[z.Name] = true
		for _, c := range z.CIDRs {
			if _, _, err := net.ParseCIDR(c); err != nil {
				return fmt.Errorf("zones[%d]: invalid CIDR %q", i, c)
			}
		}
	}
	for i, e := range imp.Edges {
		if e.FromZone == e.ToZone {
			return fmt.Errorf("edges[%d]: fromZone and toZone must not be the same zone (%q)", i, e.FromZone)
		}
		if !zoneNames[e.FromZone] {
			return fmt.Errorf("edges[%d]: fromZone %q is not a declared zone", i, e.FromZone)
		}
		if !zoneNames[e.ToZone] {
			return fmt.Errorf("edges[%d]: toZone %q is not a declared zone", i, e.ToZone)
		}
	}
	return nil
}

// ListNetworkTopologyImports -- GET /api/network-topology-imports.
func (h *Handler) ListNetworkTopologyImports(w http.ResponseWriter, r *http.Request) {
	limit := 20
	if l, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && l > 0 && l <= 100 {
		limit = l
	}
	imports, err := db.ListNetworkTopologyImports(r.Context(), h.db, limit)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if imports == nil {
		imports = []*networktopology.TopologyImport{}
	}
	respond(w, imports)
}

// GetNetworkTopologyImport -- GET /api/network-topology-imports/{id}.
func (h *Handler) GetNetworkTopologyImport(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	imp, err := db.GetNetworkTopologyImport(r.Context(), h.db, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			jsonError(w, "network topology import not found", http.StatusNotFound)
			return
		}
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respond(w, imp)
}
```

- [ ] **Step 5: Wire routes and RBAC matrix rows**

In `orchestrator/internal/api/routes.go`, after the existing:
```go
		r.Get("/api/network-reachability-comparisons", h.GetNetworkReachabilityComparison)
```
add:
```go
		r.Get("/api/network-topology-imports", h.ListNetworkTopologyImports)
		r.Get("/api/network-topology-imports/{id}", h.GetNetworkTopologyImport)
```

After the existing:
```go
		r.With(auth.RequirePermission(auth.CanImportNetworkPolicy)).Post("/api/network-policy-evaluations", h.EvaluateNetworkPolicy)
```
add:
```go
		r.With(auth.RequirePermission(auth.CanImportNetworkTopology)).Post("/api/network-topology-imports", h.CreateNetworkTopologyImport)
```

In `orchestrator/internal/api/rbac_matrix_test.go`, after the existing:
```go
	{http.MethodGet, "/api/network-reachability-comparisons", tierAny, ""},
```
add:
```go
	{http.MethodGet, "/api/network-topology-imports", tierAny, ""},
	{http.MethodGet, "/api/network-topology-imports/{id}", tierAny, ""},
```

After the existing:
```go
	{http.MethodPost, "/api/network-policy-evaluations", tierPermission, auth.CanImportNetworkPolicy},
```
add:
```go
	{http.MethodPost, "/api/network-topology-imports", tierPermission, auth.CanImportNetworkTopology},
```

- [ ] **Step 6: Run tests to verify they pass**

Check memory headroom first (`Get-CimInstance Win32_OperatingSystem`).

Run: `cd orchestrator && go build ./... && go test ./internal/api/... -run 'TestCreateNetworkTopologyImport|TestListAndGetNetworkTopologyImport|TestRBACMatrix_NoDrift' -v`
Expected: PASS — 11/11.

- [ ] **Step 7: Commit**

```bash
git add orchestrator/internal/api/networktopology_handlers.go orchestrator/internal/api/networktopology_handlers_test.go orchestrator/internal/auth/permissions.go orchestrator/internal/api/routes.go orchestrator/internal/api/rbac_matrix_test.go
git commit -m "feat(networktopology): add topology-import HTTP API and CanImportNetworkTopology permission"
```

---

### Task 8: Network Path-Finding HTTP API

**Files:**
- Create: `orchestrator/internal/api/networkpath_handlers.go`
- Test: `orchestrator/internal/api/networkpath_handlers_test.go`
- Modify: `orchestrator/internal/api/routes.go` (one more POST route)
- Modify: `orchestrator/internal/api/rbac_matrix_test.go` (one more POST row)

**Interfaces:**
- Consumes: everything from Tasks 1-7, plus the existing `attackpath.BuildGraph`, `h.loadAttackPathCollections(r)` (`internal/api/attackpath_handlers.go:135`, reused as-is), `db.GetNetworkPolicyImport`, `db.GetNetworkDiscoveryRun`, `db.ListNetworkObservationsByRun` (all existing, unmodified).
- Produces: `func (h *Handler) FindNetworkPaths(w http.ResponseWriter, r *http.Request)`, route `POST /api/network-paths`.

- [ ] **Step 1: Write the failing tests**

```go
// orchestrator/internal/api/networkpath_handlers_test.go
package api

import (
	"bytes"
	"encoding/json"
	"net"
	"net/http"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/cloudgraph"
	"github.com/audspect/bas/internal/networkpath"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

func createTestTopologyImport(t *testing.T, h *Handler, pool *pgxpool.Pool, body map[string]any) string {
	t.Helper()
	req := networkTopologyImportReq(t, pool, body)
	rec := callAuthed(h.CreateNetworkTopologyImport, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create topology import: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var created struct{ ID string `json:"id"` }
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return created.ID
}

func TestFindNetworkPaths_SameZoneQueryReturnsSingleHopResult(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		topoID := createTestTopologyImport(t, h, pool, map[string]any{
			"sourceType": "manual-declared",
			"zones":      []map[string]any{{"name": "dmz", "cidrs": []string{"10.0.1.0/24"}}},
			"edges":      []map[string]any{},
		})

		body := map[string]any{"topologyImportId": topoID, "sourceHost": "10.0.1.5", "destHost": "10.0.1.50", "port": 443}
		b, _ := json.Marshal(body)
		userID := seedUser(t, pool, "netpath-op-samezone", "pw12345678", string(auth.RoleAnalyst), true)
		req := authedRequest(t, http.MethodPost, "/api/network-paths", bytes.NewReader(b), auth.RoleAnalyst, userID)
		rec := callAuthed(h.FindNetworkPaths, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var results []networkpath.PathResult
		if err := json.Unmarshal(rec.Body.Bytes(), &results); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(results) != 1 || len(results[0].Hops) != 1 {
			t.Fatalf("got %+v, want exactly one result with one hop -- a same-zone query must still produce a meaningful single hop", results)
		}
	})
}

func TestFindNetworkPaths_NoRouteProducesUnknownNotBlocked(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		topoID := createTestTopologyImport(t, h, pool, map[string]any{
			"sourceType": "manual-declared",
			"zones":      []map[string]any{{"name": "dmz", "cidrs": []string{"10.0.1.0/24"}}, {"name": "isolated", "cidrs": []string{"10.0.9.0/24"}}},
			"edges":      []map[string]any{},
		})

		body := map[string]any{"topologyImportId": topoID, "sourceHost": "10.0.1.5", "destHost": "10.0.9.5", "port": 443}
		b, _ := json.Marshal(body)
		userID := seedUser(t, pool, "netpath-op-noroute", "pw12345678", string(auth.RoleAnalyst), true)
		req := authedRequest(t, http.MethodPost, "/api/network-paths", bytes.NewReader(b), auth.RoleAnalyst, userID)
		rec := callAuthed(h.FindNetworkPaths, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var results []networkpath.PathResult
		if err := json.Unmarshal(rec.Body.Bytes(), &results); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(results) != 1 {
			t.Fatalf("got %d results, want exactly one synthetic result for the no-route case", len(results))
		}
		if results[0].State != cloudgraph.Unknown {
			t.Fatalf("State = %q, want unknown -- a missing route must never read as blocked", results[0].State)
		}
	})
}

func TestFindNetworkPaths_DisjointZoneNamingBetweenTopologyAndPolicyDegradesToUnknown(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		topoID := createTestTopologyImport(t, h, pool, map[string]any{
			"sourceType": "manual-declared",
			"zones":      []map[string]any{{"name": "topology-zone-a", "cidrs": []string{"10.0.1.0/24"}}, {"name": "topology-zone-b", "cidrs": []string{"10.0.2.0/24"}}},
			"edges":      []map[string]any{{"fromZone": "topology-zone-a", "toZone": "topology-zone-b"}},
		})
		policyReq := networkPolicyImportReq(t, pool, map[string]any{
			"sourceType": "manual-normalized", "defaultPolicy": "deny",
			"zones": []map[string]any{{"name": "completely-different-policy-zone-name", "cidrs": []string{"10.0.1.0/24"}}},
			"rules": []map[string]any{{"id": "r1", "order": 1, "sourceZone": "completely-different-policy-zone-name", "destCidr": "10.0.2.0/24", "action": "allow"}},
		})
		policyRec := callAuthed(h.CreateNetworkPolicyImport, policyReq)
		if policyRec.Code != http.StatusCreated {
			t.Fatalf("create policy: status = %d, body = %s", policyRec.Code, policyRec.Body.String())
		}
		var policyResp struct{ ID string `json:"id"` }
		if err := json.Unmarshal(policyRec.Body.Bytes(), &policyResp); err != nil {
			t.Fatalf("decode policy: %v", err)
		}

		body := map[string]any{"topologyImportId": topoID, "policyImportId": policyResp.ID, "sourceHost": "10.0.1.5", "destHost": "10.0.2.5", "port": 443}
		b, _ := json.Marshal(body)
		userID := seedUser(t, pool, "netpath-op-disjoint", "pw12345678", string(auth.RoleAnalyst), true)
		req := authedRequest(t, http.MethodPost, "/api/network-paths", bytes.NewReader(b), auth.RoleAnalyst, userID)
		rec := callAuthed(h.FindNetworkPaths, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var results []networkpath.PathResult
		if err := json.Unmarshal(rec.Body.Bytes(), &results); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(results) != 1 || results[0].State != cloudgraph.Unknown {
			t.Fatalf("got %+v, want one result with state unknown -- disjoint zone-naming schemes must degrade honestly, never crash or misattribute a policy verdict", results)
		}
	})
}

func TestFindNetworkPaths_MultiHopWithDiscoveryRunNotesNoObservationOnIntermediateHops(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		vp := testVantagePoint()
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret).WithNetworkVantagePoint(vp)

		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		defer ln.Close()
		openPort := ln.Addr().(*net.TCPAddr).Port

		discoveryReq := networkDiscoveryReq(t, pool, map[string]any{"targets": []map[string]any{{"host": "127.0.0.1", "port": openPort}}})
		discoveryRec := callAuthed(h.TriggerNetworkDiscoveryRun, discoveryReq)
		if discoveryRec.Code != http.StatusCreated {
			t.Fatalf("trigger discovery: status = %d, body = %s", discoveryRec.Code, discoveryRec.Body.String())
		}
		var discoveryResp struct{ RunID string `json:"runId"` }
		if err := json.Unmarshal(discoveryRec.Body.Bytes(), &discoveryResp); err != nil {
			t.Fatalf("decode discovery: %v", err)
		}

		topoID := createTestTopologyImport(t, h, pool, map[string]any{
			"sourceType": "manual-declared",
			"zones":      []map[string]any{{"name": "a", "cidrs": []string{"10.0.1.0/24"}}, {"name": "pivot", "cidrs": []string{"10.0.2.0/24"}}, {"name": "b", "cidrs": []string{"127.0.0.0/24"}}},
			"edges":      []map[string]any{{"fromZone": "a", "toZone": "pivot"}, {"fromZone": "pivot", "toZone": "b"}},
		})

		body := map[string]any{"topologyImportId": topoID, "discoveryRunId": discoveryResp.RunID, "sourceHost": "10.0.1.5", "destHost": "127.0.0.1", "port": openPort}
		b, _ := json.Marshal(body)
		userID := seedUser(t, pool, "netpath-op-multihop", "pw12345678", string(auth.RoleAnalyst), true)
		req := authedRequest(t, http.MethodPost, "/api/network-paths", bytes.NewReader(b), auth.RoleAnalyst, userID)
		rec := callAuthed(h.FindNetworkPaths, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var results []networkpath.PathResult
		if err := json.Unmarshal(rec.Body.Bytes(), &results); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(results) != 1 || len(results[0].Hops) != 2 {
			t.Fatalf("got %+v, want one result with 2 hops (a->pivot, pivot->b)", results)
		}
		firstHop := results[0].Hops[0]
		if firstHop.Observation != nil {
			t.Fatal("want no observation on the intermediate hop a->pivot -- Phase 1 never observes an arbitrary intermediate hop")
		}
		if firstHop.Limitations == "" {
			t.Fatal("want a non-empty limitation explaining why no observation was attempted on this intermediate hop, since a discovery run was supplied")
		}
	})
}

func TestFindNetworkPaths_UnknownTopologyImportReturns404(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		body := map[string]any{"topologyImportId": "nonexistent-id", "sourceHost": "10.0.1.5", "destHost": "10.0.1.50", "port": 443}
		b, _ := json.Marshal(body)
		userID := seedUser(t, pool, "netpath-op-404", "pw12345678", string(auth.RoleAnalyst), true)
		req := authedRequest(t, http.MethodPost, "/api/network-paths", bytes.NewReader(b), auth.RoleAnalyst, userID)
		rec := callAuthed(h.FindNetworkPaths, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
	})
}

func TestFindNetworkPaths_MissingRequiredFieldsRejected(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		body := map[string]any{"topologyImportId": "some-id"}
		b, _ := json.Marshal(body)
		userID := seedUser(t, pool, "netpath-op-missing", "pw12345678", string(auth.RoleAnalyst), true)
		req := authedRequest(t, http.MethodPost, "/api/network-paths", bytes.NewReader(b), auth.RoleAnalyst, userID)
		rec := callAuthed(h.FindNetworkPaths, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
	})
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go vet ./internal/api/...`
Expected: FAIL — `h.FindNetworkPaths` undefined.

- [ ] **Step 3: Implement**

```go
// orchestrator/internal/api/networkpath_handlers.go
package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/jackc/pgx/v5"

	"github.com/audspect/bas/internal/attackpath"
	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/networkgraph"
	"github.com/audspect/bas/internal/networkpath"
	"github.com/audspect/bas/internal/networkpolicy"
	"github.com/audspect/bas/internal/networktopology"
)

const maxNetworkPathRequestBytes = 1 << 16

type networkPathRequest struct {
	TopologyImportID string `json:"topologyImportId"`
	PolicyImportID   string `json:"policyImportId,omitempty"`
	DiscoveryRunID   string `json:"discoveryRunId,omitempty"`
	SourceHost       string `json:"sourceHost"`
	DestHost         string `json:"destHost"`
	Port             int    `json:"port"`
	Protocol         string `json:"protocol,omitempty"`
	MaxHops          int    `json:"maxHops,omitempty"`
}

// FindNetworkPaths -- POST /api/network-paths. Resolves sourceHost/
// destHost to zones in the named topology import, finds candidate
// routes, and composes+aggregates each one's evidence. Not persisted --
// computed fresh on every call from already-persisted evidence sources.
func (h *Handler) FindNetworkPaths(w http.ResponseWriter, r *http.Request) {
	var req networkPathRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxNetworkPathRequestBytes)).Decode(&req); err != nil {
		jsonError(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.TopologyImportID == "" || req.SourceHost == "" || req.DestHost == "" || req.Port == 0 {
		jsonError(w, "topologyImportId, sourceHost, destHost, and port are all required", http.StatusBadRequest)
		return
	}

	topo, err := db.GetNetworkTopologyImport(r.Context(), h.db, req.TopologyImportID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			jsonError(w, "network topology import not found", http.StatusNotFound)
			return
		}
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	sourceZone, err := networktopology.ZoneForHost(req.SourceHost, topo.Zones)
	if err != nil {
		jsonError(w, "sourceHost: "+err.Error(), http.StatusBadRequest)
		return
	}
	destZone, err := networktopology.ZoneForHost(req.DestHost, topo.Zones)
	if err != nil {
		jsonError(w, "destHost: "+err.Error(), http.StatusBadRequest)
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

	var observations []networkgraph.NetworkObservation
	if req.DiscoveryRunID != "" {
		if _, err := db.GetNetworkDiscoveryRun(r.Context(), h.db, req.DiscoveryRunID); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				jsonError(w, "network discovery run not found", http.StatusNotFound)
				return
			}
			jsonError(w, err.Error(), http.StatusInternalServerError)
			return
		}
		observations, err = db.ListNetworkObservationsByRun(r.Context(), h.db, req.DiscoveryRunID)
		if err != nil {
			jsonError(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}

	g := attackpath.BuildGraph(h.loadAttackPathCollections(r)...)

	routes, err := networktopology.FindCandidateRoutes(topo, sourceZone, destZone, req.MaxHops)
	if err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}

	var results []networkpath.PathResult
	if len(routes) == 0 {
		// No declared route at all: still evaluate policy directly for
		// the source/dest zone pair (per the spec's own table -- "policy
		// permits it, but the route is unproven or absent" is still a
		// meaningful, distinct result from silence).
		hop := h.composeNetworkPathHop(sourceZone, destZone, false, policyImport, req, observations, g, true)
		results = append(results, networkpath.AggregatePath([]networkpath.HopResult{hop}))
	} else {
		for _, route := range routes {
			singleHop := len(route) == 2
			hops := make([]networkpath.HopResult, 0, len(route)-1)
			for i := 0; i < len(route)-1; i++ {
				hop := h.composeNetworkPathHop(route[i], route[i+1], true, policyImport, req, observations, g, singleHop)
				hops = append(hops, hop)
			}
			results = append(results, networkpath.AggregatePath(hops))
		}
	}

	respond(w, results)
}

// composeNetworkPathHop evaluates policy for one fromZone->toZone hop
// (if a policy import was supplied) and composes its evidence.
// attachObservation gates both observation correlation and host-based
// attackpath corroboration: Phase 1 only ever observes "vantage point ->
// destination host" directly, never an arbitrary intermediate hop, so
// both are only ever eligible when the entire candidate route is
// exactly one hop (the literal sourceHost/destHost the caller supplied).
// Zone-name segmentation corroboration has no such constraint and is
// attempted for every hop. When the caller supplied observations but
// this hop structurally cannot use them (a multi-hop route's hop), the
// hop's Limitations says so explicitly rather than silently omitting
// the observation -- a caller who asked for live-evidence correlation
// should never have to guess why a hop has none.
func (h *Handler) composeNetworkPathHop(fromZone, toZone string, routeDeclared bool, policyImport *networkpolicy.PolicyImport, req networkPathRequest, observations []networkgraph.NetworkObservation, g *attackpath.Graph, attachObservation bool) networkpath.HopResult {
	// The single-hop case's destination is the caller's own literal
	// destHost -- querying by its concrete /32 CIDR (rather than the
	// zone name) is what lets networkcorrelation's host/port matching
	// inside ComposeHop actually find the real observation.
	query := networkpolicy.PolicyQuery{SourceZone: fromZone, DestZone: toZone, Port: req.Port, Protocol: req.Protocol}
	if attachObservation {
		query.DestCIDR = req.DestHost + "/32"
		query.DestZone = ""
	}
	var policyEval *networkpolicy.PolicyEvaluation
	if policyImport != nil {
		evals, err := networkpolicy.EvaluatePolicyMatrix(policyImport, []networkpolicy.PolicyQuery{query})
		if err == nil && len(evals) == 1 {
			policyEval = &evals[0]
		}
	}

	var hopObservations []networkgraph.NetworkObservation
	if attachObservation {
		hopObservations = observations
	}

	hop := networkpath.ComposeHop(fromZone, toZone, routeDeclared, policyEval, hopObservations)
	if !attachObservation && len(observations) > 0 {
		note := "a discovery run was supplied, but Phase 1 only observes the vantage point's direct probe to the final destination host -- this intermediate hop has no real observation evidence available"
		if hop.Limitations == "" {
			hop.Limitations = note
		} else {
			hop.Limitations = hop.Limitations + "; " + note
		}
	}
	hop.Corroboration = networkpath.CorroborateSegmentation(g, fromZone, toZone)
	if attachObservation {
		hop.Corroboration = append(hop.Corroboration, networkpath.CorroborateHop(g, req.SourceHost, req.DestHost)...)
	}
	return hop
}
```

- [ ] **Step 4: Wire the route and RBAC row**

In `orchestrator/internal/api/routes.go`, after the existing:
```go
		r.With(auth.RequirePermission(auth.CanImportNetworkTopology)).Post("/api/network-topology-imports", h.CreateNetworkTopologyImport)
```
add:
```go
		r.With(auth.RequirePermission(auth.CanImportNetworkTopology)).Post("/api/network-paths", h.FindNetworkPaths)
```

In `orchestrator/internal/api/rbac_matrix_test.go`, after the existing:
```go
	{http.MethodPost, "/api/network-topology-imports", tierPermission, auth.CanImportNetworkTopology},
```
add:
```go
	{http.MethodPost, "/api/network-paths", tierPermission, auth.CanImportNetworkTopology},
```

- [ ] **Step 5: Run tests to verify they pass**

Check memory headroom first (`Get-CimInstance Win32_OperatingSystem`).

Run: `cd orchestrator && go build ./... && go test ./internal/api/... -run 'TestFindNetworkPaths|TestRBACMatrix_NoDrift' -v`
Expected: PASS — 7/7.

- [ ] **Step 6: Run the full network+RBAC regression set**

Run: `cd orchestrator && go vet ./... && go test ./internal/api/... -run 'Network|RBACMatrix' -v`
Expected: PASS — all tests, no regressions.

- [ ] **Step 7: Commit**

```bash
git add orchestrator/internal/api/networkpath_handlers.go orchestrator/internal/api/networkpath_handlers_test.go orchestrator/internal/api/routes.go orchestrator/internal/api/rbac_matrix_test.go
git commit -m "feat(networkpath): add goal-directed network attack-path HTTP API"
```

---

## Execution Handoff

This plan uses **Native/inline execution** (pre-selected — standing convention for this session, same as the Phase 1 and Phase 2A plans): implement every task directly in this session, then one fresh reviewer on the most capable model checks the whole branch at the end.

**REQUIRED SUB-SKILL:** Use superpowers:executing-plans.
