# Network BAS Mastery Phase 6B: VPN / Remote-Access Networking Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add VPN-tunnel and bastion/mandatory-transit boundary modeling and validation as a new on-premises evidence package, reusing the existing zone/route/policy model for everything else `network.txt` §1.5 names.

**Architecture:** A single new package, `internal/remoteaccess`, holds two new primitives (a state-carrying VPN-tunnel route edge, and a declared-architecture mandatory-transit/bastion constraint) plus its own tunnel-aware route search. No new composition package is created: the API handler composes evidence by calling `internal/networkpath`'s existing `ComposeHop`/`AggregatePath` directly, unmodified, exactly the way `FindNetworkPaths` already does.

**Tech Stack:** Go, PostgreSQL (via `pgxpool`), chi router, the same `EnsureXSchema`/`InsertX`/`GetX`/`ListX` persistence pattern used by every prior phase.

**Spec:** `docs/superpowers/specs/2026-10-14-network-bas-phase6b-remote-access-design.md`

## Global Constraints

- No new composition package (`internal/remoteaccesspath` or similar) is created. The handler reuses `internal/networkpath.ComposeHop`/`AggregatePath` directly, unmodified (spec §5).
- `internal/remoteaccess` never modifies `internal/networktopology`, `internal/networkpolicy`, or `internal/networkpath` — it imports their types read-only.
- Only `VPNTunnel.State == TunnelUp` is ever treated as a usable route edge; `TunnelDown`/`TunnelUnknown` remove that edge as a candidate but never prove the zones are unreachable by some other path (spec §4.1, §8).
- `MandatoryTransit`/`TransitViolation` are purely additive evidence — they never alter a `HopResult`/`PathResult`'s `State` (spec §4.3, §8).
- Zone names on `VPNTunnel`/`MandatoryTransit` are validated only for non-emptiness, never cross-checked against a real `networktopology.TopologyImport`'s declared zones — this is a standing, always-applicable gap, so a `RemoteAccessImport` with any `Tunnels`/`Transits` must always carry a non-empty `Limitations` (spec §3, §4.2).
- Safety caps: `MaxTunnelsPerImport = 500`, `MaxTransitsPerImport = 500`, `maxRouteSearchSteps = 20000` (unexported, not caller-tunable) (spec §4.1.1).
- Host machine has ~7.84-8.2GB RAM: never run unscoped `go test ./internal/api/...` or `./internal/db/...`; always `go build ./...` + scoped package tests + a `-run` regex covering every new/changed test together. Check free memory via `Get-CimInstance Win32_OperatingSystem | Select-Object FreePhysicalMemory,TotalVisibleMemorySize` before any `internal/api`/`internal/db` test run; if below ~1GB, check for stray Docker testcontainers/`*.test.exe` processes before proceeding (a transient dip right after a prior test run is common and usually resolves on its own within a minute).
- Work happens inline on `main`, no worktree, no feature branch. `git push` immediately after every single commit.
- RED must be watched failing (not assumed) before every GREEN.

## Review Focus

1. A `TunnelDown` (or `TunnelUnknown`) tunnel between two zones with no other declared edge must leave `FindCandidateRemoteAccessRoutes` returning zero routes (not an error, not a route), and the API handler composing that into `Unknown`, never `Blocked` — mirrors Phase 6A's non-active-peering fix exactly.
2. A route that is connectivity-valid (tunnel up, or physical edge, policy permits) but bypasses a declared `MandatoryTransit`'s required `ViaZone` must still surface as a `TransitViolation` — connectivity validity and architecture-conformance are orthogonal, and the first must never suppress the second.
3. A `MandatoryTransit` rule whose `FromZone`/`ToZone` has no candidate route at all must produce zero violations for that rule — "no route found" and "found a route that bypasses the bastion" are different findings and must never be conflated.
4. A multi-hop path mixing one tunnel hop and one physical hop, where the tunnel hop's policy evaluation independently blocks while the physical hop's permits, must still classify the whole path as `Blocked` via the reused, unmodified `networkpath.AggregatePath` — proving the "reuse unchanged" decision holds under a genuinely mixed hop-kind path.
5. A genuinely multi-tier fixture (3+ zones, 2+ tunnels, one physical edge down) where two distinct candidate routes exist and only one satisfies a `MandatoryTransit` rule — proving route search and bastion validation interact correctly across multiple candidates, not just a trivial 2-zone case.

---

### Task 1: `internal/remoteaccess` — Data Model and Tunnel-Aware Route Search

**Files:**
- Create: `orchestrator/internal/remoteaccess/types.go`
- Create: `orchestrator/internal/remoteaccess/routes.go`
- Test: `orchestrator/internal/remoteaccess/routes_test.go`

**Interfaces:**
- Consumes: `networktopology.Zone{Name,CIDRs}`, `networktopology.RouteEdge{FromZone,ToZone,Directed,Note}`, `networktopology.TopologyImport{ID,SourceType,ImportedBy,ImportedAt,ConfigVersion,Zones,Edges,Limitations}` (all read-only, `github.com/audspect/bas/internal/networktopology`).
- Produces: `remoteaccess.TunnelUp`/`TunnelDown`/`TunnelUnknown` (string constants), `remoteaccess.VPNTunnel{CanonicalID,FromZone,ToZone,Directed,State,Note}`, `remoteaccess.MandatoryTransit{CanonicalID,FromZone,ToZone,ViaZone,Note}`, `remoteaccess.RemoteAccessImport{ID,SourceType,ImportedBy,ImportedAt,ConfigVersion,Tunnels,Transits,Limitations}`, `remoteaccess.RoutePath []string`, `remoteaccess.MaxTunnelsPerImport = 500`, `remoteaccess.MaxTransitsPerImport = 500`, `func FindCandidateRemoteAccessRoutes(topo *networktopology.TopologyImport, remote *RemoteAccessImport, sourceZone, destZone string, maxHops int) ([]RoutePath, bool, error)` — used directly by Task 4's API handler.

- [ ] **Step 1: Write `types.go`**

```go
// Package remoteaccess models on-premises VPN tunnels and
// mandatory-transit (bastion) boundary rules, kept structurally
// independent of internal/networktopology's own zone/edge model --
// configured existence and operational tunnel state are two separate
// evidence questions, the same way internal/networkpolicy and
// internal/networktopology stay independent of each other despite
// both describing on-prem zones. It never modifies networktopology,
// networkpolicy, or networkpath; it imports networktopology's types
// read-only for its own route search (routes.go). internal/networkpath
// is reused directly, unmodified, for evidence composition -- see
// docs/superpowers/specs/2026-10-14-network-bas-phase6b-remote-access-design.md
// §5 for why no new composition package exists.
package remoteaccess

import "time"

const (
	TunnelUp      = "up"      // real evidence: operationally established, usable as a route edge
	TunnelDown    = "down"    // real evidence: configured but not established -- not usable, but also not proof no path exists at all
	TunnelUnknown = "unknown" // missing evidence -- never treated as usable, never treated as confirmed-down

	MaxTunnelsPerImport  = 500
	MaxTransitsPerImport = 500
)

// VPNTunnel is one logical tunnel connecting two networktopology zones
// by name. It may connect zones with no CIDR adjacency at all (e.g. a
// branch zone and a data-centre zone reachable only across the public
// internet) -- only State == TunnelUp is ever treated as a usable
// route edge, mirroring cloudtopology.PeeringConnection's exact
// discipline for peering state.
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
// whatever the route search actually finds (routes.go, transit.go) --
// never baked into the routing graph itself, so a real bypass route
// that skips the bastion is surfaced as a violation instead of
// silently disappearing from the search.
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
// package never cross-validates those names against a real import
// (they stay independently sourced -- spec §3).
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

- [ ] **Step 2: Write the failing test for route search (physical-edge parity + tunnel-up usability)**

```go
package remoteaccess

import (
	"testing"

	"github.com/audspect/bas/internal/networktopology"
)

func testTopo() *networktopology.TopologyImport {
	return &networktopology.TopologyImport{
		Zones: []networktopology.Zone{
			{Name: "corporate", CIDRs: []string{"10.0.1.0/24"}},
			{Name: "production", CIDRs: []string{"10.0.2.0/24"}},
		},
		Edges: []networktopology.RouteEdge{
			{FromZone: "corporate", ToZone: "production"},
		},
	}
}

func TestFindCandidateRemoteAccessRoutes_PhysicalEdgeOnly_FindsRoute(t *testing.T) {
	topo := testTopo()
	remote := &RemoteAccessImport{}
	routes, exhausted, err := FindCandidateRemoteAccessRoutes(topo, remote, "corporate", "production", 5)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if exhausted {
		t.Fatal("want exhausted=false for a trivial single-edge search")
	}
	if len(routes) != 1 || len(routes[0]) != 2 {
		t.Fatalf("routes = %v, want one 2-zone route", routes)
	}
}

func TestFindCandidateRemoteAccessRoutes_TunnelUpIsUsableEdge(t *testing.T) {
	topo := &networktopology.TopologyImport{
		Zones: []networktopology.Zone{
			{Name: "branch", CIDRs: []string{"10.1.0.0/24"}},
			{Name: "datacenter", CIDRs: []string{"10.2.0.0/24"}},
		},
	}
	remote := &RemoteAccessImport{
		Tunnels: []VPNTunnel{
			{CanonicalID: "vpn-1", FromZone: "branch", ToZone: "datacenter", State: TunnelUp},
		},
	}
	routes, _, err := FindCandidateRemoteAccessRoutes(topo, remote, "branch", "datacenter", 5)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(routes) != 1 || len(routes[0]) != 2 {
		t.Fatalf("routes = %v, want one 2-zone route via the tunnel -- zones with no physical adjacency must still be reachable via an up tunnel", routes)
	}
}
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `cd orchestrator && go test ./internal/remoteaccess/... -v`
Expected: FAIL -- `FindCandidateRemoteAccessRoutes` (and the package itself beyond `types.go`) is undefined.

- [ ] **Step 4: Write `routes.go`**

```go
package remoteaccess

import (
	"fmt"

	"github.com/audspect/bas/internal/networktopology"
)

// maxRouteSearchSteps is the same defensive bound on total DFS work
// every prior phase's route search carries, independent of the
// tunnel/transit caps above. Unexported: not a caller-tunable safety
// knob.
const maxRouteSearchSteps = 20000

// MaxHopsPerPathQuery and MaxCandidateRoutesPerQuery mirror
// networktopology's own ceilings exactly (networktopology/routes.go).
const (
	MaxHopsPerPathQuery        = 10
	MaxCandidateRoutesPerQuery = 20
)

// RoutePath is an ordered sequence of zone names from source to
// destination, inclusive of both endpoints -- same shape as
// networktopology.RoutePath.
type RoutePath []string

// FindCandidateRemoteAccessRoutes returns up to
// MaxCandidateRoutesPerQuery simple paths (no repeated zone) from
// sourceZone to destZone across the UNION of topo's declared
// RouteEdges and remote's VPN tunnels in State == TunnelUp -- a Down
// or Unknown tunnel is never a usable edge, mirroring exactly how
// cloudtopology.FindCandidateCloudRoutes treats only PeeringActive as
// usable. This is a new bounded DFS (not a reuse of
// networktopology.FindCandidateRoutes, which is hardcoded to
// topo.Edges alone), modeled directly on that function's own
// implementation. sourceZone == destZone always returns exactly one
// trivial two-element route. maxHops is clamped to
// MaxHopsPerPathQuery if it exceeds that ceiling, or if zero/negative.
func FindCandidateRemoteAccessRoutes(topo *networktopology.TopologyImport, remote *RemoteAccessImport, sourceZone, destZone string, maxHops int) ([]RoutePath, bool, error) {
	if len(remote.Tunnels) > MaxTunnelsPerImport {
		return nil, false, fmt.Errorf("remoteaccess: import has too many tunnels -- got %d, max %d", len(remote.Tunnels), MaxTunnelsPerImport)
	}
	if sourceZone == destZone {
		return []RoutePath{{sourceZone, destZone}}, false, nil
	}
	if maxHops > MaxHopsPerPathQuery || maxHops <= 0 {
		maxHops = MaxHopsPerPathQuery
	}

	adj := buildCombinedAdjacency(topo.Edges, remote.Tunnels)

	var results []RoutePath
	steps := 0
	exhausted := false
	visited := map[string]bool{sourceZone: true}
	var dfs func(current string, path RoutePath)
	dfs = func(current string, path RoutePath) {
		steps++
		if steps > maxRouteSearchSteps {
			exhausted = true
			return
		}
		if len(results) >= MaxCandidateRoutesPerQuery {
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
	return results, exhausted, nil
}

// buildCombinedAdjacency unions topo's declared physical RouteEdges
// with remote's VPN tunnels filtered to State == TunnelUp. A Down or
// Unknown tunnel contributes no edge at all. Directed semantics match
// networktopology.RouteEdge's own convention for both edge kinds.
func buildCombinedAdjacency(edges []networktopology.RouteEdge, tunnels []VPNTunnel) map[string][]string {
	adj := map[string][]string{}
	for _, e := range edges {
		adj[e.FromZone] = append(adj[e.FromZone], e.ToZone)
		if !e.Directed {
			adj[e.ToZone] = append(adj[e.ToZone], e.FromZone)
		}
	}
	for _, tun := range tunnels {
		if tun.State != TunnelUp {
			continue
		}
		adj[tun.FromZone] = append(adj[tun.FromZone], tun.ToZone)
		if !tun.Directed {
			adj[tun.ToZone] = append(adj[tun.ToZone], tun.FromZone)
		}
	}
	return adj
}
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cd orchestrator && go test ./internal/remoteaccess/... -v`
Expected: PASS -- both tests green.

- [ ] **Step 6: Write the failing tests for the remaining Review Focus items this task owns (RF#1's search half, RF#5)**

```go
func TestFindCandidateRemoteAccessRoutes_TunnelDownNotUsable_NoOtherRoute_EmptyResult(t *testing.T) {
	topo := &networktopology.TopologyImport{
		Zones: []networktopology.Zone{
			{Name: "branch", CIDRs: []string{"10.1.0.0/24"}},
			{Name: "datacenter", CIDRs: []string{"10.2.0.0/24"}},
		},
	}
	remote := &RemoteAccessImport{
		Tunnels: []VPNTunnel{
			{CanonicalID: "vpn-1", FromZone: "branch", ToZone: "datacenter", State: TunnelDown},
		},
	}
	routes, exhausted, err := FindCandidateRemoteAccessRoutes(topo, remote, "branch", "datacenter", 5)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if exhausted {
		t.Fatal("want exhausted=false -- the search space was fully (trivially) explored, not truncated")
	}
	if len(routes) != 0 {
		t.Fatalf("routes = %v, want zero -- a down tunnel with no other edge must not be usable", routes)
	}
}

func TestFindCandidateRemoteAccessRoutes_TunnelUnknownNotUsable(t *testing.T) {
	topo := &networktopology.TopologyImport{
		Zones: []networktopology.Zone{
			{Name: "branch", CIDRs: []string{"10.1.0.0/24"}},
			{Name: "datacenter", CIDRs: []string{"10.2.0.0/24"}},
		},
	}
	remote := &RemoteAccessImport{
		Tunnels: []VPNTunnel{
			{CanonicalID: "vpn-1", FromZone: "branch", ToZone: "datacenter", State: TunnelUnknown},
		},
	}
	routes, _, err := FindCandidateRemoteAccessRoutes(topo, remote, "branch", "datacenter", 5)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(routes) != 0 {
		t.Fatalf("routes = %v, want zero -- missing evidence is never treated as a usable edge", routes)
	}
}

// TestFindCandidateRemoteAccessRoutes_DenseMultiTierFixture_TwoDistinctRoutesFound
// pins Review Focus #5's search half: 4 zones, 2 tunnels, one
// physical edge down -- two genuinely distinct candidate routes must
// both be found (one via each tunnel), not just whichever the DFS
// happens to visit first.
func TestFindCandidateRemoteAccessRoutes_DenseMultiTierFixture_TwoDistinctRoutesFound(t *testing.T) {
	topo := &networktopology.TopologyImport{
		Zones: []networktopology.Zone{
			{Name: "corporate", CIDRs: []string{"10.0.1.0/24"}},
			{Name: "bastion", CIDRs: []string{"10.0.2.0/24"}},
			{Name: "staging", CIDRs: []string{"10.0.3.0/24"}},
			{Name: "production", CIDRs: []string{"10.0.4.0/24"}},
		},
		// corporate -> production direct physical edge is intentionally
		// absent (e.g. decommissioned) -- only the two tunnel-mediated
		// routes below remain.
	}
	remote := &RemoteAccessImport{
		Tunnels: []VPNTunnel{
			{CanonicalID: "vpn-direct", FromZone: "corporate", ToZone: "production", State: TunnelUp},
			{CanonicalID: "vpn-via-bastion-1", FromZone: "corporate", ToZone: "bastion", State: TunnelUp},
			{CanonicalID: "vpn-via-bastion-2", FromZone: "bastion", ToZone: "production", State: TunnelUp},
			{CanonicalID: "vpn-unused", FromZone: "corporate", ToZone: "staging", State: TunnelUp},
		},
	}
	routes, exhausted, err := FindCandidateRemoteAccessRoutes(topo, remote, "corporate", "production", 5)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if exhausted {
		t.Fatal("want exhausted=false for this small a graph")
	}
	if len(routes) != 2 {
		t.Fatalf("routes = %v, want exactly 2 distinct candidate routes (direct tunnel, and via-bastion tunnel chain)", routes)
	}
	foundDirect, foundViaBastion := false, false
	for _, r := range routes {
		if len(r) == 2 {
			foundDirect = true
		}
		if len(r) == 3 && r[1] == "bastion" {
			foundViaBastion = true
		}
	}
	if !foundDirect || !foundViaBastion {
		t.Fatalf("routes = %v, want both the direct route and the via-bastion route", routes)
	}
}
```

- [ ] **Step 7: Run the tests to verify they fail, then implement/verify they pass**

Run: `cd orchestrator && go test ./internal/remoteaccess/... -v`
Expected (before any further code changes): the two new "not usable" tests should already PASS against Step 4's implementation (no code change needed -- `buildCombinedAdjacency` already filters on `TunnelUp` only), and the dense-fixture test should also PASS. If any of the three fail, re-examine `buildCombinedAdjacency`/`FindCandidateRemoteAccessRoutes` against this step's fixtures before proceeding -- do not change the test's expectations to match a bug.

Run again to confirm: `cd orchestrator && go test ./internal/remoteaccess/... -v`
Expected: PASS -- all 5 tests in this file green.

- [ ] **Step 8: Commit**

```bash
git add orchestrator/internal/remoteaccess/types.go orchestrator/internal/remoteaccess/routes.go orchestrator/internal/remoteaccess/routes_test.go
git commit -m "feat(remoteaccess): add VPN-tunnel data model and tunnel-aware route search"
git push
```

---

### Task 2: `internal/remoteaccess` — Mandatory-Transit (Bastion) Validation

**Files:**
- Create: `orchestrator/internal/remoteaccess/transit.go`
- Test: `orchestrator/internal/remoteaccess/transit_test.go`

**Interfaces:**
- Consumes: `remoteaccess.RoutePath` and `remoteaccess.MandatoryTransit{CanonicalID,FromZone,ToZone,ViaZone,Note}` (Task 1).
- Produces: `remoteaccess.TransitViolation{Transit,Route,Note}`, `func ValidateMandatoryTransit(routes []RoutePath, transits []MandatoryTransit) []TransitViolation` -- used directly by Task 5's API handler.

- [ ] **Step 1: Write the failing tests**

```go
package remoteaccess

import "testing"

func TestValidateMandatoryTransit_BypassRoute_FlaggedAsViolation(t *testing.T) {
	routes := []RoutePath{{"corporate", "production"}} // skips the bastion entirely
	transits := []MandatoryTransit{
		{CanonicalID: "mt-1", FromZone: "corporate", ToZone: "production", ViaZone: "bastion"},
	}
	violations := ValidateMandatoryTransit(routes, transits)
	if len(violations) != 1 {
		t.Fatalf("violations = %v, want exactly 1 -- the route bypasses the required bastion zone", violations)
	}
	if violations[0].Transit.CanonicalID != "mt-1" {
		t.Fatalf("violations[0].Transit.CanonicalID = %q, want %q", violations[0].Transit.CanonicalID, "mt-1")
	}
}

func TestValidateMandatoryTransit_RouteVisitsViaZone_NoViolation(t *testing.T) {
	routes := []RoutePath{{"corporate", "bastion", "production"}}
	transits := []MandatoryTransit{
		{CanonicalID: "mt-1", FromZone: "corporate", ToZone: "production", ViaZone: "bastion"},
	}
	violations := ValidateMandatoryTransit(routes, transits)
	if len(violations) != 0 {
		t.Fatalf("violations = %v, want zero -- the route does visit the required bastion zone", violations)
	}
}

// TestValidateMandatoryTransit_NoRouteAtAllForTransitEndpoints_NoViolation
// pins Review Focus #3: a MandatoryTransit whose FromZone/ToZone
// simply has no candidate route among the ones supplied must produce
// no violation -- "no route found" is a different finding entirely,
// never force-reported as a bypass.
func TestValidateMandatoryTransit_NoRouteAtAllForTransitEndpoints_NoViolation(t *testing.T) {
	routes := []RoutePath{} // genuinely isolated zones -- the caller found nothing
	transits := []MandatoryTransit{
		{CanonicalID: "mt-1", FromZone: "corporate", ToZone: "production", ViaZone: "bastion"},
	}
	violations := ValidateMandatoryTransit(routes, transits)
	if len(violations) != 0 {
		t.Fatalf("violations = %v, want zero -- no candidate route exists for this Transit's endpoints at all", violations)
	}
}

func TestValidateMandatoryTransit_UnrelatedTransit_DoesNotInterfere(t *testing.T) {
	routes := []RoutePath{{"corporate", "production"}}
	transits := []MandatoryTransit{
		{CanonicalID: "mt-unrelated", FromZone: "guest", ToZone: "staging", ViaZone: "bastion"},
	}
	violations := ValidateMandatoryTransit(routes, transits)
	if len(violations) != 0 {
		t.Fatalf("violations = %v, want zero -- a Transit rule for a different zone pair must not match this route", violations)
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd orchestrator && go test ./internal/remoteaccess/... -run TestValidateMandatoryTransit -v`
Expected: FAIL -- `TransitViolation`/`ValidateMandatoryTransit` undefined.

- [ ] **Step 3: Write `transit.go`**

```go
package remoteaccess

// TransitViolation is evidence that a found route between a
// MandatoryTransit's FromZone and ToZone never visited ViaZone.
type TransitViolation struct {
	Transit MandatoryTransit `json:"transit"`
	Route   RoutePath        `json:"route"`
	Note    string           `json:"note"`
}

// ValidateMandatoryTransit checks each route against every
// MandatoryTransit whose FromZone/ToZone match the route's own
// endpoints (route[0] and route[len(route)-1]), returning one
// TransitViolation per route that bypasses ViaZone. A route that does
// not match a Transit's endpoints at all is not a candidate for that
// rule -- it is not a bypass, it is simply unrelated. This function is
// purely additive: it never removes a route from the caller's own
// result set, only annotates which ones violate a declared
// constraint, mirroring cloudpath.CorrelateCloudFinding's
// non-mutating discipline exactly.
func ValidateMandatoryTransit(routes []RoutePath, transits []MandatoryTransit) []TransitViolation {
	var violations []TransitViolation
	for _, route := range routes {
		if len(route) == 0 {
			continue
		}
		from, to := route[0], route[len(route)-1]
		for _, transit := range transits {
			if transit.FromZone != from || transit.ToZone != to {
				continue
			}
			if routeVisits(route, transit.ViaZone) {
				continue
			}
			violations = append(violations, TransitViolation{
				Transit: transit,
				Route:   route,
				Note:    "this route reaches the declared destination zone without visiting the required transit zone",
			})
		}
	}
	return violations
}

func routeVisits(route RoutePath, zone string) bool {
	for _, z := range route {
		if z == zone {
			return true
		}
	}
	return false
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd orchestrator && go test ./internal/remoteaccess/... -v`
Expected: PASS -- all tests in the package green (9 total: 5 from Task 1, 4 from this task).

- [ ] **Step 5: Write the failing test for Review Focus #5's bastion half (reusing Task 1's dense fixture)**

```go
// TestValidateMandatoryTransit_DenseFixture_OnlyNonCompliantRouteFlagged
// pins the rest of Review Focus #5: of the two distinct routes
// Task 1's dense fixture finds (a direct tunnel, and a route via the
// bastion zone), only the direct one should be flagged when a
// MandatoryTransit requires the bastion -- proving route search and
// bastion validation interact correctly across multiple real
// candidates, not just a trivial 2-zone case.
func TestValidateMandatoryTransit_DenseFixture_OnlyNonCompliantRouteFlagged(t *testing.T) {
	routes := []RoutePath{
		{"corporate", "production"},
		{"corporate", "bastion", "production"},
	}
	transits := []MandatoryTransit{
		{CanonicalID: "mt-1", FromZone: "corporate", ToZone: "production", ViaZone: "bastion"},
	}
	violations := ValidateMandatoryTransit(routes, transits)
	if len(violations) != 1 {
		t.Fatalf("violations = %v, want exactly 1 (only the direct route bypasses the bastion)", violations)
	}
	if len(violations[0].Route) != 2 {
		t.Fatalf("violations[0].Route = %v, want the 2-zone direct route, not the compliant 3-zone one", violations[0].Route)
	}
}
```

- [ ] **Step 6: Run the test to verify it fails, then verify it passes against the existing implementation**

Run: `cd orchestrator && go test ./internal/remoteaccess/... -run TestValidateMandatoryTransit_DenseFixture -v`
Expected: PASS against Step 3's implementation with no further code change (the function already loops over every route and checks only matching-endpoint Transits) -- if it fails, debug `ValidateMandatoryTransit` against this fixture before proceeding.

- [ ] **Step 7: Run the full package test suite**

Run: `cd orchestrator && go test ./internal/remoteaccess/... -v`
Expected: PASS -- 10 tests total, all green.

- [ ] **Step 8: Commit**

```bash
git add orchestrator/internal/remoteaccess/transit.go orchestrator/internal/remoteaccess/transit_test.go
git commit -m "feat(remoteaccess): add mandatory-transit (bastion) violation checking"
git push
```

---

### Task 3: `internal/db` — Persistence for `RemoteAccessImport`

**Files:**
- Create: `orchestrator/internal/db/remoteaccess_store.go`
- Test: `orchestrator/internal/db/remoteaccess_store_test.go`
- Modify: `orchestrator/internal/testutil/testdb.go:166-170` (insert a new `EnsureRemoteAccessImportSchema` block immediately after the existing `EnsureCloudTopologySchema` block)
- Modify: `orchestrator/cmd/server/main.go:311-313` (insert a new `EnsureRemoteAccessImportSchema` call immediately after the existing `EnsureCloudTopologySchema` call)

**Interfaces:**
- Consumes: `remoteaccess.RemoteAccessImport{ID,SourceType,ImportedBy,ImportedAt,ConfigVersion,Tunnels,Transits,Limitations}`, `remoteaccess.VPNTunnel`, `remoteaccess.MandatoryTransit` (Task 1); `db.nullableString(s string) *string` (`orchestrator/internal/db/networkdiscovery_store.go:78`, reused unmodified).
- Produces: `db.EnsureRemoteAccessImportSchema(ctx, pool) error`, `db.InsertRemoteAccessImport(ctx, pool, imp *remoteaccess.RemoteAccessImport) error`, `db.GetRemoteAccessImport(ctx, pool, id string) (*remoteaccess.RemoteAccessImport, error)` (404 via `errors.Is(err, pgx.ErrNoRows)`), `db.ListRemoteAccessImports(ctx, pool, limit int) ([]*remoteaccess.RemoteAccessImport, error)` -- used directly by Task 4's API handlers.

- [ ] **Step 1: Write the failing test**

```go
package db_test

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/remoteaccess"
)

func TestInsertAndGetRemoteAccessImport_RoundTrip(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		imp := &remoteaccess.RemoteAccessImport{
			ID:         "ra-roundtrip-1",
			SourceType: "manual",
			Tunnels: []remoteaccess.VPNTunnel{
				{CanonicalID: "vpn-1", FromZone: "branch", ToZone: "datacenter", State: remoteaccess.TunnelUp},
			},
			Transits: []remoteaccess.MandatoryTransit{
				{CanonicalID: "mt-1", FromZone: "corporate", ToZone: "production", ViaZone: "bastion"},
			},
		}
		if err := db.InsertRemoteAccessImport(context.Background(), pool, imp); err != nil {
			t.Fatalf("insert: %v", err)
		}
		got, err := db.GetRemoteAccessImport(context.Background(), pool, imp.ID)
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		if len(got.Tunnels) != 1 || got.Tunnels[0].CanonicalID != "vpn-1" {
			t.Fatalf("got.Tunnels = %v, want one tunnel vpn-1", got.Tunnels)
		}
		if len(got.Transits) != 1 || got.Transits[0].CanonicalID != "mt-1" {
			t.Fatalf("got.Transits = %v, want one transit mt-1", got.Transits)
		}
	})
}

func TestGetRemoteAccessImport_NotFound(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		_, err := db.GetRemoteAccessImport(context.Background(), pool, "does-not-exist")
		if !errors.Is(err, pgx.ErrNoRows) {
			t.Fatalf("err = %v, want errors.Is(err, pgx.ErrNoRows)", err)
		}
	})
}

func TestListRemoteAccessImports_NewestFirst(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		first := &remoteaccess.RemoteAccessImport{ID: "ra-list-1", SourceType: "manual"}
		second := &remoteaccess.RemoteAccessImport{ID: "ra-list-2", SourceType: "manual"}
		if err := db.InsertRemoteAccessImport(context.Background(), pool, first); err != nil {
			t.Fatalf("insert first: %v", err)
		}
		if err := db.InsertRemoteAccessImport(context.Background(), pool, second); err != nil {
			t.Fatalf("insert second: %v", err)
		}
		list, err := db.ListRemoteAccessImports(context.Background(), pool, 10)
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		if len(list) < 2 {
			t.Fatalf("list = %v, want at least 2 entries", list)
		}
	})
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Before running: check free memory with `Get-CimInstance Win32_OperatingSystem | Select-Object FreePhysicalMemory,TotalVisibleMemorySize` and, if below ~1GB, confirm no stray containers/`*.test.exe` via `docker ps` / `tasklist` first.

Run: `cd orchestrator && go test ./internal/db/... -run "TestInsertAndGetRemoteAccessImport|TestGetRemoteAccessImport_NotFound|TestListRemoteAccessImports" -v`
Expected: FAIL -- `db.EnsureRemoteAccessImportSchema`/`InsertRemoteAccessImport`/`GetRemoteAccessImport`/`ListRemoteAccessImports` undefined (compile error).

- [ ] **Step 3: Write `remoteaccess_store.go`**

```go
package db

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/remoteaccess"
)

// EnsureRemoteAccessImportSchema creates the remote_access_imports table.
func EnsureRemoteAccessImportSchema(ctx context.Context, pool *pgxpool.Pool) error {
	_, err := pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS remote_access_imports (
			id              text        PRIMARY KEY DEFAULT gen_random_uuid()::text,
			source_type     text        NOT NULL,
			imported_by     text,
			imported_at     timestamptz NOT NULL DEFAULT NOW(),
			config_version  text,
			limitations     text[],
			remote_access_data jsonb    NOT NULL
		)`)
	if err != nil {
		return fmt.Errorf("remote_access_imports: ensure schema: %w", err)
	}
	return nil
}

// remoteAccessData is the shape persisted in the remote_access_data
// jsonb column -- just the two slices that make an import's content,
// not its metadata (which live in their own columns).
type remoteAccessData struct {
	Tunnels  []remoteaccess.VPNTunnel        `json:"tunnels"`
	Transits []remoteaccess.MandatoryTransit `json:"transits"`
}

// InsertRemoteAccessImport writes a new remote_access_imports row. The
// caller supplies imp.ID already generated.
func InsertRemoteAccessImport(ctx context.Context, pool *pgxpool.Pool, imp *remoteaccess.RemoteAccessImport) error {
	data, err := json.Marshal(remoteAccessData{Tunnels: imp.Tunnels, Transits: imp.Transits})
	if err != nil {
		return fmt.Errorf("remote_access_imports: marshal remote access data for %s: %w", imp.ID, err)
	}
	_, err = pool.Exec(ctx,
		`INSERT INTO remote_access_imports (id, source_type, imported_by, config_version, limitations, remote_access_data)
		 VALUES ($1,$2,$3,$4,$5,$6)`,
		imp.ID, imp.SourceType, nullableString(imp.ImportedBy), nullableString(imp.ConfigVersion), imp.Limitations, data)
	if err != nil {
		return fmt.Errorf("remote_access_imports: insert %s: %w", imp.ID, err)
	}
	return nil
}

func scanRemoteAccessImport(row pgx.Row) (*remoteaccess.RemoteAccessImport, error) {
	imp := &remoteaccess.RemoteAccessImport{}
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
	var rd remoteAccessData
	if err := json.Unmarshal(data, &rd); err != nil {
		return nil, fmt.Errorf("remote_access_imports: unmarshal remote access data for %s: %w", imp.ID, err)
	}
	imp.Tunnels, imp.Transits = rd.Tunnels, rd.Transits
	return imp, nil
}

// GetRemoteAccessImport returns one import by id. A missing id returns
// an error satisfying errors.Is(err, pgx.ErrNoRows).
func GetRemoteAccessImport(ctx context.Context, pool *pgxpool.Pool, id string) (*remoteaccess.RemoteAccessImport, error) {
	row := pool.QueryRow(ctx,
		`SELECT id, source_type, imported_by, imported_at, config_version, limitations, remote_access_data
		 FROM remote_access_imports WHERE id = $1`, id)
	imp, err := scanRemoteAccessImport(row)
	if err != nil {
		return nil, fmt.Errorf("remote_access_imports: get %s: %w", id, err)
	}
	return imp, nil
}

// ListRemoteAccessImports returns up to limit rows, newest first.
func ListRemoteAccessImports(ctx context.Context, pool *pgxpool.Pool, limit int) ([]*remoteaccess.RemoteAccessImport, error) {
	rows, err := pool.Query(ctx,
		`SELECT id, source_type, imported_by, imported_at, config_version, limitations, remote_access_data
		 FROM remote_access_imports ORDER BY imported_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("remote_access_imports: list: %w", err)
	}
	defer rows.Close()
	var out []*remoteaccess.RemoteAccessImport
	for rows.Next() {
		imp, err := scanRemoteAccessImport(rows)
		if err != nil {
			return nil, fmt.Errorf("remote_access_imports: list scan: %w", err)
		}
		out = append(out, imp)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("remote_access_imports: list rows: %w", err)
	}
	return out, nil
}
```

- [ ] **Step 4: Wire the schema into `testdb.go`**

In `orchestrator/internal/testutil/testdb.go`, immediately after the existing block ending at line 170 (`db.EnsureCloudTopologySchema`), add:

```go
	if err := db.EnsureRemoteAccessImportSchema(ctx, pool); err != nil {
		pool.Close()
		_ = container.Terminate(context.Background())
		return nil, fmt.Errorf("testutil: EnsureRemoteAccessImportSchema: %w", err)
	}
```

(Re-check the exact current line number with `grep -n "EnsureCloudTopologySchema" orchestrator/internal/testutil/testdb.go` before editing -- it may have shifted since this plan was written.)

- [ ] **Step 5: Wire the schema into `main.go`**

In `orchestrator/cmd/server/main.go`, immediately after the existing block ending at line 313 (`db.EnsureCloudTopologySchema`), add:

```go
	if err := db.EnsureRemoteAccessImportSchema(context.Background(), adminPool); err != nil {
		log.Fatalf("[FATAL] remote access import schema: %v", err)
	}
```

(Re-check the exact current line number with `grep -n "EnsureCloudTopologySchema" orchestrator/cmd/server/main.go` before editing.)

- [ ] **Step 6: Run the tests to verify they pass**

Check free memory first (`Get-CimInstance Win32_OperatingSystem | Select-Object FreePhysicalMemory,TotalVisibleMemorySize`).

Run: `cd orchestrator && go test ./internal/db/... -run "TestInsertAndGetRemoteAccessImport|TestGetRemoteAccessImport_NotFound|TestListRemoteAccessImports" -v`
Expected: PASS -- all 3 tests green.

- [ ] **Step 7: Commit**

```bash
git add orchestrator/internal/db/remoteaccess_store.go orchestrator/internal/db/remoteaccess_store_test.go orchestrator/internal/testutil/testdb.go orchestrator/cmd/server/main.go
git commit -m "feat(db): add remote_access_imports persistence"
git push
```

---

### Task 4: `internal/api` — Import Endpoints (`CreateRemoteAccessImport`, List, Get)

**Files:**
- Create: `orchestrator/internal/api/remoteaccess_handlers.go`
- Test: `orchestrator/internal/api/remoteaccess_handlers_test.go`
- Modify: `orchestrator/internal/auth/permissions.go:243` (add `CanImportRemoteAccessTopology` constant after `CanImportCloudTopology`'s declaration; add it to both the `RoleAdmin` map around line 305 and the `RoleAnalyst` map around line 321)
- Modify: `orchestrator/internal/api/routes.go:259` (add GET routes immediately after the existing `cloud-topology-imports` GETs); `routes.go:436` (add the POST route immediately after the existing `cloud-topology-imports` POST)
- Modify: `orchestrator/internal/api/rbac_matrix_test.go:72` (add GET rows immediately after the existing `cloud-topology-imports` GET rows); `rbac_matrix_test.go:222` (add the POST row immediately after the existing `cloud-topology-imports` POST row)

**Interfaces:**
- Consumes: `remoteaccess.RemoteAccessImport`, `remoteaccess.VPNTunnel`, `remoteaccess.MandatoryTransit`, `remoteaccess.TunnelUp/Down/Unknown`, `remoteaccess.MaxTunnelsPerImport/MaxTransitsPerImport` (Task 1); `db.InsertRemoteAccessImport`/`GetRemoteAccessImport`/`ListRemoteAccessImports` (Task 3); `h.db`, `newID()`, `jsonError`, `respond`/`respondStatus`, `h.auditLog`, `auth.ClaimsFrom` (existing `Handler` helpers, same as `cloudtopology_handlers.go`).
- Produces: `auth.CanImportRemoteAccessTopology Permission`; `(h *Handler) CreateRemoteAccessImport`, `ListRemoteAccessImports`, `GetRemoteAccessImport` HTTP handlers; `validateRemoteAccessImport(imp *remoteaccess.RemoteAccessImport) error` -- used directly by `CreateRemoteAccessImport`.

- [ ] **Step 1: Add the permission**

In `orchestrator/internal/auth/permissions.go`, immediately after the `CanImportCloudTopology` declaration (re-check the exact current line with `grep -n "CanImportCloudTopology" orchestrator/internal/auth/permissions.go`):

```go
	// remote-access:import gates importing on-premises VPN-tunnel and
	// mandatory-transit (bastion) boundary data (Network BAS Phase 6B)
	// -- same placement as CanImportCloudTopology, for the same reason.
	CanImportRemoteAccessTopology Permission = "remote-access:import"
```

Add `CanImportRemoteAccessTopology: true,` to the `RoleAdmin` map's permission list (immediately after `CanImportCloudTopology: true,`) and `CanImportRemoteAccessTopology: true` to the `RoleAnalyst` map's inline permission list (immediately after `CanImportCloudTopology: true`).

- [ ] **Step 2: Write the failing tests**

```go
package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/remoteaccess"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

func validRemoteAccessImportBody() map[string]any {
	return map[string]any{
		"sourceType": "manual",
		"tunnels": []map[string]any{
			{"canonicalId": "vpn-1", "fromZone": "branch", "toZone": "datacenter", "state": "up"},
		},
		"limitations": []string{"zone names are not cross-validated against a real network-topology import"},
	}
}

func TestCreateRemoteAccessImport_Valid_Created(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		b, _ := json.Marshal(validRemoteAccessImportBody())
		userID := seedUser(t, pool, "remoteaccess-op", "pw12345678", string(auth.RoleAnalyst), true)
		req := authedRequest(t, http.MethodPost, "/api/remote-access-imports", bytes.NewReader(b), auth.RoleAnalyst, userID)
		rec := callAuthed(h.CreateRemoteAccessImport, req)
		if rec.Code != http.StatusCreated {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var created remoteaccess.RemoteAccessImport
		if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if created.ID == "" {
			t.Fatal("want non-empty ID")
		}
	})
}

func TestCreateRemoteAccessImport_InvalidTunnelState_Rejected(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		body := validRemoteAccessImportBody()
		body["tunnels"] = []map[string]any{
			{"canonicalId": "vpn-1", "fromZone": "branch", "toZone": "datacenter", "state": "Active"},
		}
		b, _ := json.Marshal(body)
		userID := seedUser(t, pool, "remoteaccess-op-badstate", "pw12345678", string(auth.RoleAnalyst), true)
		req := authedRequest(t, http.MethodPost, "/api/remote-access-imports", bytes.NewReader(b), auth.RoleAnalyst, userID)
		rec := callAuthed(h.CreateRemoteAccessImport, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, body = %s, want 400 -- an unknown tunnel state must be rejected", rec.Code, rec.Body.String())
		}
	})
}

func TestCreateRemoteAccessImport_TunnelsWithoutLimitations_Rejected(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		body := validRemoteAccessImportBody()
		delete(body, "limitations")
		b, _ := json.Marshal(body)
		userID := seedUser(t, pool, "remoteaccess-op-nolim", "pw12345678", string(auth.RoleAnalyst), true)
		req := authedRequest(t, http.MethodPost, "/api/remote-access-imports", bytes.NewReader(b), auth.RoleAnalyst, userID)
		rec := callAuthed(h.CreateRemoteAccessImport, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, body = %s, want 400 -- any Tunnels/Transits present requires non-empty Limitations (zone names are never cross-validated)", rec.Code, rec.Body.String())
		}
	})
}

func TestCreateRemoteAccessImport_EmptyZoneName_Rejected(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		body := validRemoteAccessImportBody()
		body["tunnels"] = []map[string]any{
			{"canonicalId": "vpn-1", "fromZone": "", "toZone": "datacenter", "state": "up"},
		}
		b, _ := json.Marshal(body)
		userID := seedUser(t, pool, "remoteaccess-op-emptyzone", "pw12345678", string(auth.RoleAnalyst), true)
		req := authedRequest(t, http.MethodPost, "/api/remote-access-imports", bytes.NewReader(b), auth.RoleAnalyst, userID)
		rec := callAuthed(h.CreateRemoteAccessImport, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, body = %s, want 400 -- an empty zone name must be rejected", rec.Code, rec.Body.String())
		}
	})
}

func TestListAndGetRemoteAccessImport_RoundTrip(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		b, _ := json.Marshal(validRemoteAccessImportBody())
		userID := seedUser(t, pool, "remoteaccess-op-rt", "pw12345678", string(auth.RoleAnalyst), true)
		createReq := authedRequest(t, http.MethodPost, "/api/remote-access-imports", bytes.NewReader(b), auth.RoleAnalyst, userID)
		createRec := callAuthed(h.CreateRemoteAccessImport, createReq)
		if createRec.Code != http.StatusCreated {
			t.Fatalf("create status = %d, body = %s", createRec.Code, createRec.Body.String())
		}
		var created remoteaccess.RemoteAccessImport
		if err := json.Unmarshal(createRec.Body.Bytes(), &created); err != nil {
			t.Fatalf("decode create: %v", err)
		}

		listReq := authedRequest(t, http.MethodGet, "/api/remote-access-imports", nil, auth.RoleViewer, "")
		listRec := callAuthed(h.ListRemoteAccessImports, listReq)
		if listRec.Code != http.StatusOK {
			t.Fatalf("list status = %d, body = %s", listRec.Code, listRec.Body.String())
		}

		getReq := authedRequest(t, http.MethodGet, "/api/remote-access-imports/"+created.ID, nil, auth.RoleViewer, "")
		getReq = withURLParam(getReq, "id", created.ID)
		getRec := callAuthed(h.GetRemoteAccessImport, getReq)
		if getRec.Code != http.StatusOK {
			t.Fatalf("get status = %d, body = %s", getRec.Code, getRec.Body.String())
		}
	})
}
```

- [ ] **Step 3: Run the tests to verify they fail**

Check free memory first.

Run: `cd orchestrator && go test ./internal/api/... -run "TestCreateRemoteAccessImport|TestListAndGetRemoteAccessImport" -v`
Expected: FAIL -- `h.CreateRemoteAccessImport` etc. undefined (compile error).

- [ ] **Step 4: Write `remoteaccess_handlers.go`**

```go
package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/remoteaccess"
)

const maxRemoteAccessImportRequestBytes = 5 << 20

// CreateRemoteAccessImport -- POST /api/remote-access-imports.
func (h *Handler) CreateRemoteAccessImport(w http.ResponseWriter, r *http.Request) {
	var req remoteaccess.RemoteAccessImport
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRemoteAccessImportRequestBytes)).Decode(&req); err != nil {
		jsonError(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if err := validateRemoteAccessImport(&req); err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}

	var importedBy string
	if c, ok := auth.ClaimsFrom(r.Context()); ok && c != nil {
		importedBy = c.UserID
	}
	req.ID = newID()
	req.ImportedBy = importedBy

	if err := db.InsertRemoteAccessImport(r.Context(), h.db, &req); err != nil {
		h.auditLog(r, "remoteaccess.import", "", map[string]any{"error": err.Error()}, "error")
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	h.auditLog(r, "remoteaccess.import", req.ID, map[string]any{"tunnelCount": len(req.Tunnels), "transitCount": len(req.Transits)}, "ok")
	respondStatus(w, req, http.StatusCreated)
}

func validateRemoteAccessImport(imp *remoteaccess.RemoteAccessImport) error {
	if len(imp.Tunnels) > remoteaccess.MaxTunnelsPerImport {
		return fmt.Errorf("too many tunnels — got %d, max %d", len(imp.Tunnels), remoteaccess.MaxTunnelsPerImport)
	}
	if len(imp.Transits) > remoteaccess.MaxTransitsPerImport {
		return fmt.Errorf("too many transits — got %d, max %d", len(imp.Transits), remoteaccess.MaxTransitsPerImport)
	}

	hasLimitations := len(imp.Limitations) > 0
	if (len(imp.Tunnels) > 0 || len(imp.Transits) > 0) && !hasLimitations {
		return fmt.Errorf("limitations must be non-empty whenever any tunnel or transit is declared — zone names are never cross-validated against a real network-topology import")
	}

	for i, tun := range imp.Tunnels {
		if tun.FromZone == "" || tun.ToZone == "" {
			return fmt.Errorf("tunnels[%d]: fromZone and toZone are both required", i)
		}
		switch tun.State {
		case remoteaccess.TunnelUp, remoteaccess.TunnelDown, remoteaccess.TunnelUnknown:
		default:
			return fmt.Errorf("tunnels[%d]: unknown state %q", i, tun.State)
		}
	}
	for i, t := range imp.Transits {
		if t.FromZone == "" || t.ToZone == "" || t.ViaZone == "" {
			return fmt.Errorf("transits[%d]: fromZone, toZone, and viaZone are all required", i)
		}
	}
	return nil
}

// ListRemoteAccessImports -- GET /api/remote-access-imports.
func (h *Handler) ListRemoteAccessImports(w http.ResponseWriter, r *http.Request) {
	limit := 20
	if l, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && l > 0 && l <= 100 {
		limit = l
	}
	imports, err := db.ListRemoteAccessImports(r.Context(), h.db, limit)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if imports == nil {
		imports = []*remoteaccess.RemoteAccessImport{}
	}
	respond(w, imports)
}

// GetRemoteAccessImport -- GET /api/remote-access-imports/{id}.
func (h *Handler) GetRemoteAccessImport(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	imp, err := db.GetRemoteAccessImport(r.Context(), h.db, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			jsonError(w, "remote access import not found", http.StatusNotFound)
			return
		}
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respond(w, imp)
}
```

- [ ] **Step 5: Wire routes**

In `orchestrator/internal/api/routes.go`, immediately after the existing `cloud-topology-imports` GET routes (re-check current line numbers with `grep -n "cloud-topology-imports" orchestrator/internal/api/routes.go`), add:

```go
		r.Get("/api/remote-access-imports", h.ListRemoteAccessImports)
		r.Get("/api/remote-access-imports/{id}", h.GetRemoteAccessImport)
```

Immediately after the existing `cloud-topology-imports` POST route, add:

```go
		r.With(auth.RequirePermission(auth.CanImportRemoteAccessTopology)).Post("/api/remote-access-imports", h.CreateRemoteAccessImport)
```

- [ ] **Step 6: Add RBAC matrix rows**

In `orchestrator/internal/api/rbac_matrix_test.go`, immediately after the existing `cloud-topology-imports` GET rows (re-check current line numbers), add:

```go
	{http.MethodGet, "/api/remote-access-imports", tierAny, ""},
	{http.MethodGet, "/api/remote-access-imports/{id}", tierAny, ""},
```

Immediately after the existing `cloud-topology-imports` POST row, add:

```go
	{http.MethodPost, "/api/remote-access-imports", tierPermission, auth.CanImportRemoteAccessTopology},
```

- [ ] **Step 7: Run the tests to verify they pass**

Check free memory first.

Run: `cd orchestrator && go test ./internal/api/... -run "TestRBACMatrix|TestCreateRemoteAccessImport|TestListAndGetRemoteAccessImport" -v`
Expected: PASS -- all tests green, including the no-drift RBAC matrix.

- [ ] **Step 8: Commit**

```bash
git add orchestrator/internal/auth/permissions.go orchestrator/internal/api/routes.go orchestrator/internal/api/rbac_matrix_test.go orchestrator/internal/api/remoteaccess_handlers.go orchestrator/internal/api/remoteaccess_handlers_test.go
git commit -m "feat(api): add remote-access import endpoints"
git push
```

---

### Task 5: `internal/api` — `FindRemoteAccessPaths` (Reuses `networkpath` Unchanged)

**Files:**
- Create: `orchestrator/internal/api/remoteaccesspath_handlers.go`
- Test: `orchestrator/internal/api/remoteaccesspath_handlers_test.go`
- Modify: `orchestrator/internal/api/routes.go:439` (add the POST route immediately after the existing `cloud-paths` POST, reusing the `CanImportRemoteAccessTopology` permission from Task 4)
- Modify: `orchestrator/internal/api/rbac_matrix_test.go:225` (add the POST row immediately after the existing `cloud-paths` POST row)

**Interfaces:**
- Consumes: `remoteaccess.FindCandidateRemoteAccessRoutes`, `remoteaccess.RoutePath`, `remoteaccess.ValidateMandatoryTransit`, `remoteaccess.TransitViolation` (Tasks 1-2); `db.GetRemoteAccessImport` (Task 3); `networktopology.ZoneForHost`, `networktopology.TopologyImport` (existing, read `orchestrator/internal/networktopology/resolve.go` in full before writing this task); `networkpolicy.PolicyQuery/PolicyEvaluation/PolicyImport/EvaluatePolicyMatrix` (existing); `networkpath.ComposeHop/AggregatePath/HopResult/PathResult/CorroborateHop/CorroborateSegmentation` (existing, reused unmodified); `attackpath.Graph`, `h.loadAttackPathCollections` (existing); `db.GetNetworkTopologyImport`, `db.GetNetworkPolicyImport`, `db.GetNetworkDiscoveryRun`, `db.ListNetworkObservationsByRun` (existing).
- Produces: `(h *Handler) FindRemoteAccessPaths` HTTP handler.

- [ ] **Step 1: Read the precedent in full**

Before writing any code, read `orchestrator/internal/api/networkpath_handlers.go` in its entirety -- this task's handler follows `FindNetworkPaths`/`composeNetworkPathHop`'s exact structure, extended only with the tunnel-aware route search (Task 1) and mandatory-transit validation (Task 2) layered on top.

- [ ] **Step 2: Write the failing tests**

```go
package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/networkpath"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

func createNetworkTopologyImportForRemoteAccessTest(t *testing.T, h *Handler, userID string, zones []map[string]any, edges []map[string]any) string {
	t.Helper()
	body := map[string]any{"sourceType": "manual", "zones": zones, "edges": edges}
	b, _ := json.Marshal(body)
	req := authedRequest(t, http.MethodPost, "/api/network-topology-imports", bytes.NewReader(b), auth.RoleAnalyst, userID)
	rec := callAuthed(h.CreateNetworkTopologyImport, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create network topology import: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var created struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return created.ID
}

func createRemoteAccessImportForPathTest(t *testing.T, h *Handler, userID string, tunnels []map[string]any) string {
	t.Helper()
	body := map[string]any{
		"sourceType":  "manual",
		"tunnels":     tunnels,
		"limitations": []string{"zone names are not cross-validated against a real network-topology import"},
	}
	b, _ := json.Marshal(body)
	req := authedRequest(t, http.MethodPost, "/api/remote-access-imports", bytes.NewReader(b), auth.RoleAnalyst, userID)
	rec := callAuthed(h.CreateRemoteAccessImport, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create remote access import: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var created struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return created.ID
}

// TestFindRemoteAccessPaths_TunnelOnlyConnectivity_PolicySupported pins
// that a VPN tunnel alone (no physical edge at all) makes two zones
// reachable, and (with no policy import supplied) the handler still
// composes a route-declared-but-unevaluated-policy hop consistently
// with networkpath.ComposeHop's own existing semantics.
func TestFindRemoteAccessPaths_TunnelOnlyConnectivity_RouteFound(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		userID := seedUser(t, pool, "raPath-op-tunnel", "pw12345678", string(auth.RoleAnalyst), true)
		topoID := createNetworkTopologyImportForRemoteAccessTest(t, h, userID,
			[]map[string]any{
				{"name": "branch", "cidrs": []string{"10.1.0.0/24"}},
				{"name": "datacenter", "cidrs": []string{"10.2.0.0/24"}},
			}, []map[string]any{})
		remoteID := createRemoteAccessImportForPathTest(t, h, userID, []map[string]any{
			{"canonicalId": "vpn-1", "fromZone": "branch", "toZone": "datacenter", "state": "up"},
		})

		body := map[string]any{
			"topologyImportId":     topoID,
			"remoteAccessImportId": remoteID,
			"sourceHost":           "10.1.0.5",
			"destHost":             "10.2.0.5",
			"port":                 443,
			"protocol":             "tcp",
		}
		b, _ := json.Marshal(body)
		req := authedRequest(t, http.MethodPost, "/api/remote-access-paths", bytes.NewReader(b), auth.RoleAnalyst, userID)
		rec := callAuthed(h.FindRemoteAccessPaths, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var resp struct {
			Results []networkpath.PathResult `json:"results"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(resp.Results) != 1 {
			t.Fatalf("got %d results, want 1", len(resp.Results))
		}
		if !resp.Results[0].Hops[0].RouteDeclared {
			t.Fatal("want RouteDeclared=true -- the tunnel provides a route even with no physical edge")
		}
	})
}

// TestFindRemoteAccessPaths_TunnelDown_NoOtherRoute_Unknown pins
// Review Focus #1's end-to-end half.
func TestFindRemoteAccessPaths_TunnelDown_NoOtherRoute_Unknown(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		userID := seedUser(t, pool, "raPath-op-down", "pw12345678", string(auth.RoleAnalyst), true)
		topoID := createNetworkTopologyImportForRemoteAccessTest(t, h, userID,
			[]map[string]any{
				{"name": "branch", "cidrs": []string{"10.1.0.0/24"}},
				{"name": "datacenter", "cidrs": []string{"10.2.0.0/24"}},
			}, []map[string]any{})
		remoteID := createRemoteAccessImportForPathTest(t, h, userID, []map[string]any{
			{"canonicalId": "vpn-1", "fromZone": "branch", "toZone": "datacenter", "state": "down"},
		})

		body := map[string]any{
			"topologyImportId":     topoID,
			"remoteAccessImportId": remoteID,
			"sourceHost":           "10.1.0.5",
			"destHost":             "10.2.0.5",
			"port":                 443,
			"protocol":             "tcp",
		}
		b, _ := json.Marshal(body)
		req := authedRequest(t, http.MethodPost, "/api/remote-access-paths", bytes.NewReader(b), auth.RoleAnalyst, userID)
		rec := callAuthed(h.FindRemoteAccessPaths, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var resp struct {
			Results []networkpath.PathResult `json:"results"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(resp.Results) != 1 || resp.Results[0].State != "unknown" {
			t.Fatalf("Results = %v, want exactly 1 result with State unknown -- a down tunnel with no other route must never read as blocked", resp.Results)
		}
	})
}

// TestFindRemoteAccessPaths_BypassRoute_TransitViolationAttached pins
// Review Focus #2's end-to-end half.
func TestFindRemoteAccessPaths_BypassRoute_TransitViolationAttached(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		userID := seedUser(t, pool, "raPath-op-bypass", "pw12345678", string(auth.RoleAnalyst), true)
		topoID := createNetworkTopologyImportForRemoteAccessTest(t, h, userID,
			[]map[string]any{
				{"name": "corporate", "cidrs": []string{"10.0.1.0/24"}},
				{"name": "production", "cidrs": []string{"10.0.2.0/24"}},
			},
			[]map[string]any{
				{"fromZone": "corporate", "toZone": "production"},
			})
		// This test needs a MandatoryTransit, which
		// createRemoteAccessImportForPathTest's helper signature does
		// not take -- build the import body directly instead.
		remoteBody := map[string]any{
			"sourceType": "manual",
			"transits": []map[string]any{
				{"canonicalId": "mt-1", "fromZone": "corporate", "toZone": "production", "viaZone": "bastion"},
			},
			"limitations": []string{"zone names are not cross-validated against a real network-topology import"},
		}
		rb, _ := json.Marshal(remoteBody)
		remoteReq := authedRequest(t, http.MethodPost, "/api/remote-access-imports", bytes.NewReader(rb), auth.RoleAnalyst, userID)
		remoteRec := callAuthed(h.CreateRemoteAccessImport, remoteReq)
		if remoteRec.Code != http.StatusCreated {
			t.Fatalf("create remote access import with transit: status = %d, body = %s", remoteRec.Code, remoteRec.Body.String())
		}
		var remoteCreated struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(remoteRec.Body.Bytes(), &remoteCreated); err != nil {
			t.Fatalf("decode: %v", err)
		}

		body := map[string]any{
			"topologyImportId":     topoID,
			"remoteAccessImportId": remoteCreated.ID,
			"sourceHost":           "10.0.1.5",
			"destHost":             "10.0.2.5",
			"port":                 443,
			"protocol":             "tcp",
		}
		b, _ := json.Marshal(body)
		req := authedRequest(t, http.MethodPost, "/api/remote-access-paths", bytes.NewReader(b), auth.RoleAnalyst, userID)
		rec := callAuthed(h.FindRemoteAccessPaths, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var resp struct {
			TransitViolations []map[string]any `json:"transitViolations"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(resp.TransitViolations) != 1 {
			t.Fatalf("transitViolations = %v, want exactly 1 -- the direct corporate->production route bypasses the required bastion zone", resp.TransitViolations)
		}
	})
}

func TestFindRemoteAccessPaths_MissingRequiredFields_Rejected(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		userID := seedUser(t, pool, "raPath-op-bad", "pw12345678", string(auth.RoleAnalyst), true)
		b, _ := json.Marshal(map[string]any{"sourceHost": "10.1.0.5"})
		req := authedRequest(t, http.MethodPost, "/api/remote-access-paths", bytes.NewReader(b), auth.RoleAnalyst, userID)
		rec := callAuthed(h.FindRemoteAccessPaths, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, body = %s, want 400", rec.Code, rec.Body.String())
		}
	})
}
```

- [ ] **Step 3: Run the tests to verify they fail**

Check free memory first.

Run: `cd orchestrator && go test ./internal/api/... -run "TestFindRemoteAccessPaths" -v`
Expected: FAIL -- `h.FindRemoteAccessPaths` undefined (compile error).

- [ ] **Step 4: Write `remoteaccesspath_handlers.go`**

```go
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
	"github.com/audspect/bas/internal/remoteaccess"
)

const maxRemoteAccessPathRequestBytes = 1 << 16

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

// remoteAccessPathResponse mirrors networkPathResponse's shape, with
// TransitViolations attached additively -- never altering a result's
// State.
type remoteAccessPathResponse struct {
	Results           []networkpath.PathResult        `json:"results"`
	SearchExhausted   bool                             `json:"searchExhausted,omitempty"`
	TransitViolations []remoteaccess.TransitViolation `json:"transitViolations,omitempty"`
}

// FindRemoteAccessPaths -- POST /api/remote-access-paths. Resolves
// sourceHost/destHost to zones in the named network-topology import,
// finds candidate routes over the combined physical-edge/VPN-tunnel
// graph, composes+aggregates each one's evidence by reusing
// networkpath.ComposeHop/AggregatePath directly (unmodified -- spec
// §5), and separately validates every found route against the named
// remote-access import's MandatoryTransit rules.
func (h *Handler) FindRemoteAccessPaths(w http.ResponseWriter, r *http.Request) {
	var req remoteAccessPathRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRemoteAccessPathRequestBytes)).Decode(&req); err != nil {
		jsonError(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.TopologyImportID == "" || req.RemoteAccessImportID == "" || req.SourceHost == "" || req.DestHost == "" || req.Port == 0 {
		jsonError(w, "topologyImportId, remoteAccessImportId, sourceHost, destHost, and port are all required", http.StatusBadRequest)
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
	remote, err := db.GetRemoteAccessImport(r.Context(), h.db, req.RemoteAccessImportID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			jsonError(w, "remote access import not found", http.StatusNotFound)
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

	routes, exhausted, err := remoteaccess.FindCandidateRemoteAccessRoutes(topo, remote, sourceZone, destZone, req.MaxHops)
	if err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}

	var results []networkpath.PathResult
	if len(routes) == 0 {
		hop := h.composeRemoteAccessPathHop(sourceZone, destZone, false, policyImport, req, observations, g, true)
		results = append(results, networkpath.AggregatePath([]networkpath.HopResult{hop}))
	} else {
		for _, route := range routes {
			singleHop := len(route) == 2
			hops := make([]networkpath.HopResult, 0, len(route)-1)
			for i := 0; i < len(route)-1; i++ {
				hop := h.composeRemoteAccessPathHop(route[i], route[i+1], true, policyImport, req, observations, g, singleHop)
				hops = append(hops, hop)
			}
			results = append(results, networkpath.AggregatePath(hops))
		}
	}

	violations := remoteaccess.ValidateMandatoryTransit(routes, remote.Transits)

	respond(w, remoteAccessPathResponse{Results: results, SearchExhausted: exhausted, TransitViolations: violations})
}

// composeRemoteAccessPathHop mirrors internal/api/networkpath_handlers.go's
// composeNetworkPathHop exactly -- the policy/observation/corroboration
// composition logic is identical regardless of whether routeDeclared
// came from a physical RouteEdge or a VPN tunnel, since
// networkpath.ComposeHop does not distinguish the two.
func (h *Handler) composeRemoteAccessPathHop(fromZone, toZone string, routeDeclared bool, policyImport *networkpolicy.PolicyImport, req remoteAccessPathRequest, observations []networkgraph.NetworkObservation, g *attackpath.Graph, attachObservation bool) networkpath.HopResult {
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

- [ ] **Step 5: Wire the route**

In `orchestrator/internal/api/routes.go`, immediately after the existing `cloud-paths` POST route (re-check current line numbers), add:

```go
		r.With(auth.RequirePermission(auth.CanImportRemoteAccessTopology)).Post("/api/remote-access-paths", h.FindRemoteAccessPaths)
```

- [ ] **Step 6: Add the RBAC matrix row**

In `orchestrator/internal/api/rbac_matrix_test.go`, immediately after the existing `cloud-paths` POST row (re-check current line numbers), add:

```go
	{http.MethodPost, "/api/remote-access-paths", tierPermission, auth.CanImportRemoteAccessTopology},
```

- [ ] **Step 7: Run the new tests to verify they pass**

Check free memory first.

Run: `cd orchestrator && go test ./internal/api/... -run "TestFindRemoteAccessPaths|TestRBACMatrix" -v`
Expected: PASS -- all tests green, including the no-drift RBAC matrix.

- [ ] **Step 8: Write the failing test for Review Focus #4 (mixed tunnel/physical hop, one hop's policy blocks)**

```go
// TestFindRemoteAccessPaths_MixedTunnelAndPhysicalHops_OneHopPolicyBlocks_WholePathBlocked
// pins Review Focus #4: a 3-zone path (corporate -[physical]-> bastion
// -[tunnel]-> production) where the policy import blocks the second
// (tunnel) hop and permits the first -- the whole path must still
// aggregate to Blocked via the reused, unmodified
// networkpath.AggregatePath.
func TestFindRemoteAccessPaths_MixedTunnelAndPhysicalHops_OneHopPolicyBlocks_WholePathBlocked(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		userID := seedUser(t, pool, "raPath-op-mixed", "pw12345678", string(auth.RoleAnalyst), true)
		topoID := createNetworkTopologyImportForRemoteAccessTest(t, h, userID,
			[]map[string]any{
				{"name": "corporate", "cidrs": []string{"10.0.1.0/24"}},
				{"name": "bastion", "cidrs": []string{"10.0.2.0/24"}},
				{"name": "production", "cidrs": []string{"10.0.3.0/24"}},
			},
			[]map[string]any{
				{"fromZone": "corporate", "toZone": "bastion"},
			})
		remoteID := createRemoteAccessImportForPathTest(t, h, userID, []map[string]any{
			{"canonicalId": "vpn-1", "fromZone": "bastion", "toZone": "production", "state": "up"},
		})

		policyBody := map[string]any{
			"sourceType": "manual",
			"zones": []map[string]any{
				{"name": "corporate", "cidrs": []string{"10.0.1.0/24"}},
				{"name": "bastion", "cidrs": []string{"10.0.2.0/24"}},
				{"name": "production", "cidrs": []string{"10.0.3.0/24"}},
			},
			"defaultPolicy": "allow",
			"rules": []map[string]any{
				{"id": "deny-bastion-to-prod", "order": 10, "sourceZone": "bastion", "destZone": "production", "action": "deny", "protocol": "tcp", "portRange": "443"},
			},
		}
		pb, _ := json.Marshal(policyBody)
		pReq := authedRequest(t, http.MethodPost, "/api/network-policy-imports", bytes.NewReader(pb), auth.RoleAnalyst, userID)
		pRec := callAuthed(h.CreateNetworkPolicyImport, pReq)
		if pRec.Code != http.StatusCreated {
			t.Fatalf("create policy import: status = %d, body = %s", pRec.Code, pRec.Body.String())
		}
		var policyCreated struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(pRec.Body.Bytes(), &policyCreated); err != nil {
			t.Fatalf("decode: %v", err)
		}

		body := map[string]any{
			"topologyImportId":     topoID,
			"remoteAccessImportId": remoteID,
			"policyImportId":       policyCreated.ID,
			"sourceHost":           "10.0.1.5",
			"destHost":             "10.0.3.5",
			"port":                 443,
			"protocol":             "tcp",
		}
		b, _ := json.Marshal(body)
		req := authedRequest(t, http.MethodPost, "/api/remote-access-paths", bytes.NewReader(b), auth.RoleAnalyst, userID)
		rec := callAuthed(h.FindRemoteAccessPaths, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var resp struct {
			Results []networkpath.PathResult `json:"results"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(resp.Results) != 1 || resp.Results[0].State != "blocked" {
			t.Fatalf("Results = %v, want exactly 1 result with State blocked -- one blocking hop must still block the whole mixed-kind path", resp.Results)
		}
	})
}
```

- [ ] **Step 9: Run the test to verify it fails, then verify it passes**

Run: `cd orchestrator && go test ./internal/api/... -run "TestFindRemoteAccessPaths_MixedTunnelAndPhysicalHops" -v`
Expected: PASS against the existing Step 4 implementation with no further code change -- `networkpath.AggregatePath`'s own any-Blocked-wins rule already covers this once the handler supplies both hops correctly. If it fails, debug the handler's hop composition against this fixture (do not modify `networkpath.AggregatePath` itself -- it is reused unmodified, per the Global Constraints).

- [ ] **Step 10: Run the full scoped suite one more time**

Check free memory first.

Run: `cd orchestrator && go test ./internal/api/... -run "TestRBACMatrix|TestCreateRemoteAccessImport|TestListAndGetRemoteAccessImport|TestFindRemoteAccessPaths" -v`
Expected: PASS -- all tests green.

- [ ] **Step 11: Commit**

```bash
git add orchestrator/internal/api/routes.go orchestrator/internal/api/rbac_matrix_test.go orchestrator/internal/api/remoteaccesspath_handlers.go orchestrator/internal/api/remoteaccesspath_handlers_test.go
git commit -m "feat(api): add remote-access path query endpoint"
git push
```

---

## Final Combined Gate (run once, after Task 5)

Check free memory first.

```bash
cd orchestrator
go build ./...
go vet ./internal/remoteaccess/... ./internal/db/... ./internal/api/... ./internal/auth/...
go test ./internal/remoteaccess/... -v
go test ./internal/db/... -run "TestInsertAndGetRemoteAccessImport|TestGetRemoteAccessImport_NotFound|TestListRemoteAccessImports" -v
go test ./internal/api/... -run "TestRBACMatrix|TestCreateRemoteAccessImport|TestListAndGetRemoteAccessImport|TestFindRemoteAccessPaths" -v
```

Expected: `go build`/`go vet` clean; all scoped test runs green.

## Execution Handoff

This phase is implemented inline (Native execution), the same way every prior phase this session (1, 2A, 3, 4, 5A, 5B, 6A) was: work happens directly on `main`, no worktree, no feature branch, with `git push` after every commit. This is a standing session convention, carried forward rather than re-selected.

Plan complete and saved to `docs/superpowers/plans/2026-10-14-network-bas-phase6b-remote-access.md`. Please review the plan — does it capture what you want?
