package cloudtopology

import "testing"

func TestSubnetForHost_FindsContainingSubnet(t *testing.T) {
	subnets := []CloudSubnet{{CanonicalID: "subnet-1", CIDRBlock: "10.0.1.0/24"}, {CanonicalID: "subnet-2", CIDRBlock: "10.0.2.0/24"}}
	got, err := SubnetForHost("10.0.1.5", subnets)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "subnet-1" {
		t.Fatalf("got %q, want subnet-1", got)
	}
}

func TestSubnetForHost_NoMatch_Error(t *testing.T) {
	subnets := []CloudSubnet{{CanonicalID: "subnet-1", CIDRBlock: "10.0.1.0/24"}}
	if _, err := SubnetForHost("192.168.1.1", subnets); err == nil {
		t.Fatal("want error for a host no subnet contains")
	}
}

// threeHopImport builds: subnet-a (vpc-1) --local--> subnet-b (vpc-1)
// --peering(active)--> subnet-c (vpc-2) -- a genuinely multi-hop
// fixture (3 subnets, 2 peered networks), not a 2-node degenerate
// case, per the plan's own grounding note about Phase 5's bugs that
// flat fixtures masked.
func threeHopImport() *CloudTopologyImport {
	return &CloudTopologyImport{
		Networks: []CloudNetwork{
			{CanonicalID: "vpc-1", CIDRBlocks: []string{"10.0.0.0/16"}},
			{CanonicalID: "vpc-2", CIDRBlocks: []string{"10.1.0.0/16"}},
		},
		Subnets: []CloudSubnet{
			{CanonicalID: "subnet-a", NetworkID: "vpc-1", CIDRBlock: "10.0.1.0/24"},
			{CanonicalID: "subnet-b", NetworkID: "vpc-1", CIDRBlock: "10.0.2.0/24"},
			{CanonicalID: "subnet-c", NetworkID: "vpc-2", CIDRBlock: "10.1.1.0/24"},
		},
		Peerings: []PeeringConnection{
			{CanonicalID: "peer-1", NetworkAID: "vpc-1", NetworkBID: "vpc-2", State: PeeringActive},
		},
		Routes: []RouteTableEntry{
			{ID: "rt-a-local", SubnetID: "subnet-a", DestinationCIDR: "10.0.2.0/24", Target: TargetLocal},
			{ID: "rt-b-peer", SubnetID: "subnet-b", DestinationCIDR: "10.1.1.0/24", Target: TargetPeering, TargetRef: "peer-1"},
		},
	}
}

func TestFindCandidateCloudRoutes_MultiHopThroughPeering(t *testing.T) {
	imp := threeHopImport()
	routes, exhausted, err := FindCandidateCloudRoutes(imp, "subnet-a", "subnet-c", 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if exhausted {
		t.Fatal("did not expect the search to be exhausted for a tiny topology")
	}
	if len(routes) != 1 {
		t.Fatalf("got %d routes, want 1", len(routes))
	}
	want := CloudRoutePath{"subnet-a", "subnet-b", "subnet-c"}
	got := routes[0]
	if len(got) != len(want) {
		t.Fatalf("route = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("route = %v, want %v", got, want)
		}
	}
}

// TestFindCandidateCloudRoutes_PendingPeering_NoRouteButNotIsolated
// pins Review Focus #3: a pending (non-active) peering is real
// evidence of no route via THAT connection, distinct from "no peering
// declared at all" -- both currently surface as zero candidate
// routes with exhausted=false, which callers must read as "no known
// route", never "proven blocked".
func TestFindCandidateCloudRoutes_PendingPeering_NoRouteButNotIsolated(t *testing.T) {
	imp := threeHopImport()
	imp.Peerings[0].State = PeeringPending
	routes, exhausted, err := FindCandidateCloudRoutes(imp, "subnet-a", "subnet-c", 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(routes) != 0 {
		t.Fatalf("got %d routes, want 0 -- a pending peering must not be a usable route edge", len(routes))
	}
	if exhausted {
		t.Fatal("a small topology with no usable edge must report exhausted=false (fully explored), not true (truncated)")
	}
}

func TestFindCandidateCloudRoutes_SameSubnet_TrivialRoute(t *testing.T) {
	imp := threeHopImport()
	routes, _, err := FindCandidateCloudRoutes(imp, "subnet-a", "subnet-a", 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(routes) != 1 || len(routes[0]) != 1 {
		t.Fatalf("routes = %v, want one trivial single-element route", routes)
	}
}

// TestFindCandidateCloudRoutes_DenseMesh_ExhaustsBudget pins Review
// Focus #4 with a genuinely dense, highly interconnected mesh (every
// subnet locally routed to every other subnet in the same network,
// across many networks chained by active peerings) sized to reliably
// blow maxRouteSearchSteps=20000 before the search can prove no route
// exists to an unreachable target -- mirroring Phase 3's own final-
// review requirement for a deliberately dense fixture, not a trivial
// one.
func TestFindCandidateCloudRoutes_DenseMesh_ExhaustsBudget(t *testing.T) {
	const networks = 8
	const subnetsPerNetwork = 6
	imp := &CloudTopologyImport{}
	for n := 0; n < networks; n++ {
		netID := vpcID(n)
		imp.Networks = append(imp.Networks, CloudNetwork{CanonicalID: netID})
		for s := 0; s < subnetsPerNetwork; s++ {
			imp.Subnets = append(imp.Subnets, CloudSubnet{CanonicalID: subnetID(n, s), NetworkID: netID, CIDRBlock: subnetCIDR(n, s)})
		}
		for s := 0; s < subnetsPerNetwork; s++ {
			for t := 0; t < subnetsPerNetwork; t++ {
				if s == t {
					continue
				}
				imp.Routes = append(imp.Routes, RouteTableEntry{SubnetID: subnetID(n, s), DestinationCIDR: subnetCIDR(n, t), Target: TargetLocal})
			}
		}
		if n > 0 {
			peerID := peeringID(n - 1)
			imp.Peerings = append(imp.Peerings, PeeringConnection{CanonicalID: peerID, NetworkAID: vpcID(n - 1), NetworkBID: netID, State: PeeringActive})
			for s := 0; s < subnetsPerNetwork; s++ {
				imp.Routes = append(imp.Routes, RouteTableEntry{SubnetID: subnetID(n-1, s), DestinationCIDR: subnetCIDR(n, 0), Target: TargetPeering, TargetRef: peerID})
				imp.Routes = append(imp.Routes, RouteTableEntry{SubnetID: subnetID(n, s), DestinationCIDR: subnetCIDR(n-1, 0), Target: TargetPeering, TargetRef: peerID})
			}
		}
	}
	// An isolated subnet in its own, otherwise-unconnected network --
	// no route can ever reach it, but the search must exhaust its step
	// budget exploring the dense mesh above before it could prove that.
	imp.Networks = append(imp.Networks, CloudNetwork{CanonicalID: "vpc-isolated"})
	imp.Subnets = append(imp.Subnets, CloudSubnet{CanonicalID: "subnet-isolated", NetworkID: "vpc-isolated", CIDRBlock: "192.168.99.0/24"})

	_, exhausted, err := FindCandidateCloudRoutes(imp, subnetID(0, 0), "subnet-isolated", MaxHopsPerPathQuery)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !exhausted {
		t.Fatal("want exhausted=true -- a dense mesh this large must blow the step budget before exhaustively ruling out the isolated subnet")
	}
}

func vpcID(n int) string       { return "vpc-" + itoa(n) }
func subnetID(n, s int) string { return "subnet-" + itoa(n) + "-" + itoa(s) }
func peeringID(n int) string   { return "peer-" + itoa(n) }
func subnetCIDR(n, s int) string {
	return "10." + itoa(n) + "." + itoa(s) + ".0/24"
}
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	digits := ""
	for n > 0 {
		digits = string(rune('0'+n%10)) + digits
		n /= 10
	}
	return digits
}
