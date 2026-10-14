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
