package attackpath

import "testing"

func TestBuildGraphMergesEnrichment(t *testing.T) {
	// Agent A reports FILE01 as a bare reachable host (no metadata) plus an edge.
	// Agent B (the FILE01 agent itself) reports FILE01 with full metadata.
	a := Collection{
		AgentID: "ws01", Source: "agent",
		Edges: []Edge{{From: "WS01", To: "FILE01", Kind: EdgeSMB}},
	}
	b := Collection{
		AgentID: "file01", Source: "agent",
		Nodes: []Node{{ID: "FILE01", Kind: KindHost, Label: "FILE01", Role: RoleServer, Segment: "server-vlan", CrownJewel: "FileServer"}},
	}
	g := BuildGraph(a, b)

	n, ok := g.Node("FILE01")
	if !ok {
		t.Fatal("FILE01 should exist")
	}
	// Enrichment from agent B must survive the bare auto-host from agent A's edge.
	if n.Role != RoleServer || n.Segment != "server-vlan" || n.CrownJewel != "FileServer" {
		t.Fatalf("FILE01 metadata not merged: %+v", n)
	}
	if g.EdgeCount() != 1 {
		t.Fatalf("want 1 edge, got %d", g.EdgeCount())
	}
}

func TestBuildGraphDedupesEdges(t *testing.T) {
	// Two agents independently observe the same reachability fact.
	a := Collection{AgentID: "a", Edges: []Edge{{From: "X", To: "Y", Kind: EdgeRDP}}}
	b := Collection{AgentID: "b", Edges: []Edge{{From: "X", To: "Y", Kind: EdgeRDP}}}
	g := BuildGraph(a, b)
	if g.EdgeCount() != 1 {
		t.Fatalf("duplicate edge should collapse to 1, got %d", g.EdgeCount())
	}
}

func TestBuildGraphPromotesBareHostToUser(t *testing.T) {
	// An edge auto-creates HOST "alice"; a later node identifies it as a user.
	a := Collection{AgentID: "a", Edges: []Edge{{From: "FILE01", To: "alice", Kind: EdgeHasSession}}}
	b := Collection{AgentID: "b", Nodes: []Node{{ID: "alice", Kind: KindUser, Label: "alice@corp"}}}
	g := BuildGraph(a, b)
	n, _ := g.Node("alice")
	if n.Kind != KindUser {
		t.Fatalf("alice should be promoted to user, got kind=%q", n.Kind)
	}
}

func TestBuildGraphHighValueIsSticky(t *testing.T) {
	a := Collection{AgentID: "a", Nodes: []Node{{ID: "DA", Kind: KindGroup, HighValue: true}}}
	// A second, less-informed report must not clear the HighValue flag.
	b := Collection{AgentID: "b", Nodes: []Node{{ID: "DA", Kind: KindGroup}}}
	g := BuildGraph(a, b)
	n, _ := g.Node("DA")
	if !n.HighValue {
		t.Fatal("HighValue must remain set after a later non-HV report")
	}
}

func TestBuildGraphEndToEndAnalyze(t *testing.T) {
	// A realistic two-agent collection that should yield domain compromise.
	cols := []Collection{
		{AgentID: "ws01", Source: "agent",
			Nodes: []Node{{ID: "WS01", Kind: KindHost, Role: RoleEndpoint, Segment: "user-vlan"}},
			Edges: []Edge{{From: "WS01", To: "FILE01", Kind: EdgeSMB}}},
		{AgentID: "file01", Source: "sharphound",
			Nodes: []Node{
				{ID: "FILE01", Kind: KindHost, Role: RoleServer, Segment: "server-vlan", CrownJewel: "FileServer"},
				{ID: "svc", Kind: KindUser, Label: "svc-backup"},
				{ID: "DA", Kind: KindGroup, Label: "Domain Admins", HighValue: true},
			},
			Edges: []Edge{
				{From: "FILE01", To: "svc", Kind: EdgeHasSession},
				{From: "svc", To: "DA", Kind: EdgeMemberOf},
			}},
	}
	s := BuildGraph(cols...).Analyze()
	if !s.DomainCompromise {
		t.Fatalf("merged graph should report domain compromise: %+v", s)
	}
	if s.Hosts != 2 {
		t.Fatalf("want 2 hosts, got %d", s.Hosts)
	}
}
