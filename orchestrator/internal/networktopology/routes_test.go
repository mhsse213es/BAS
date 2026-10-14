package networktopology

import "testing"

func TestFindCandidateRoutes_SingleHopDirectRoute(t *testing.T) {
	topo := &TopologyImport{Edges: []RouteEdge{{FromZone: "dmz", ToZone: "internal"}}}
	routes, _, err := FindCandidateRoutes(topo, "dmz", "internal", 10)
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
	routes, _, err := FindCandidateRoutes(topo, "dmz", "internal", 10)
	if err != nil {
		t.Fatalf("FindCandidateRoutes: %v", err)
	}
	if len(routes) != 1 || len(routes[0]) != 3 {
		t.Fatalf("got %v, want one 3-zone route through core", routes)
	}
}

func TestFindCandidateRoutes_NoRouteReturnsEmptyNotError(t *testing.T) {
	topo := &TopologyImport{Edges: []RouteEdge{{FromZone: "dmz", ToZone: "core"}}}
	routes, _, err := FindCandidateRoutes(topo, "dmz", "isolated-segment", 10)
	if err != nil {
		t.Fatalf("FindCandidateRoutes: want no error for an unreachable destination, got %v", err)
	}
	if len(routes) != 0 {
		t.Fatalf("got %d routes, want 0 -- an absent route is a valid result, not an error", len(routes))
	}
}

func TestFindCandidateRoutes_DirectedEdgeNotUsableBackwards(t *testing.T) {
	topo := &TopologyImport{Edges: []RouteEdge{{FromZone: "dmz", ToZone: "internal", Directed: true}}}
	routes, _, err := FindCandidateRoutes(topo, "internal", "dmz", 10)
	if err != nil {
		t.Fatalf("FindCandidateRoutes: %v", err)
	}
	if len(routes) != 0 {
		t.Fatalf("got %v, want no route -- a directed edge must not be traversable backwards", routes)
	}
}

func TestFindCandidateRoutes_UndirectedEdgeUsableBothWays(t *testing.T) {
	topo := &TopologyImport{Edges: []RouteEdge{{FromZone: "dmz", ToZone: "internal", Directed: false}}}
	routes, _, err := FindCandidateRoutes(topo, "internal", "dmz", 10)
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
	routes, _, err := FindCandidateRoutes(topo, "a", "c", 1)
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
	routes, _, err := FindCandidateRoutes(topo, "z0", "z11", 999)
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
		routes, _, err := FindCandidateRoutes(topo, "dmz", "internal", mh)
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
	routes, _, err := FindCandidateRoutes(topo, "hub", "dest", 10)
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
		{FromZone: "a", ToZone: "b", Directed: true},
		{FromZone: "b", ToZone: "c", Directed: true},
		{FromZone: "c", ToZone: "a", Directed: true},
		{FromZone: "c", ToZone: "d", Directed: true},
	}}
	routes, _, err := FindCandidateRoutes(topo, "a", "d", 10)
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
	routes, _, err := FindCandidateRoutes(topo, "dmz", "dmz", 10)
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
	if _, _, err := FindCandidateRoutes(topo, "a", "b", 10); err == nil {
		t.Fatal("want error for a topology with too many zones")
	}
}

func TestFindCandidateRoutes_RejectsImportOverEdgeCap(t *testing.T) {
	edges := make([]RouteEdge, MaxEdgesPerTopologyImport+1)
	topo := &TopologyImport{Edges: edges}
	if _, _, err := FindCandidateRoutes(topo, "a", "b", 10); err == nil {
		t.Fatal("want error for a topology with too many edges")
	}
}

func TestFindCandidateRoutes_StepBudgetExhaustionSignaled(t *testing.T) {
	// A complete directed graph on 12 nodes (132 edges, well under the
	// 5000-edge cap) gives an astronomically large number of simple
	// paths up to 10 hops deep. The destination is a genuinely isolated
	// island with no edges to or from the complete graph, so the DFS
	// can never short-circuit by finding it -- it must exhaust the
	// maxRouteSearchSteps budget before it could ever claim to have
	// exhaustively searched the space. Exhausted must come back true so
	// a caller can tell "truncated search" apart from "genuinely no
	// route" -- both currently return zero routes, but they are not the
	// same finding.
	var nodes []string
	for i := 0; i < 12; i++ {
		nodes = append(nodes, "n"+string(rune('a'+i)))
	}
	var edges []RouteEdge
	for _, from := range nodes {
		for _, to := range nodes {
			if from != to {
				edges = append(edges, RouteEdge{FromZone: from, ToZone: to, Directed: true})
			}
		}
	}
	topo := &TopologyImport{Edges: edges}
	routes, exhausted, err := FindCandidateRoutes(topo, "na", "unreachable-island", 10)
	if err != nil {
		t.Fatalf("FindCandidateRoutes: %v", err)
	}
	if len(routes) != 0 {
		t.Fatalf("got %d routes, want 0 -- the island is never actually reachable", len(routes))
	}
	if !exhausted {
		t.Fatal("want exhausted=true -- the search space here vastly exceeds the step budget before it could prove the island unreachable by exhaustive search")
	}
}
