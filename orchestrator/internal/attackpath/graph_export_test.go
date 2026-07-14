package attackpath

import "testing"

func TestGraphEdgesTo(t *testing.T) {
	g := New()
	g.AddEdge(Edge{From: "WS01", To: "FILE01", Kind: EdgeSMB})
	g.AddEdge(Edge{From: "WS02", To: "FILE01", Kind: EdgeRDP})
	g.AddEdge(Edge{From: "WS01", To: "WS02", Kind: EdgeWinRM})

	edges := g.EdgesTo("FILE01")
	if len(edges) != 2 {
		t.Fatalf("want 2 edges into FILE01, got %d: %+v", len(edges), edges)
	}
	seen := map[string]bool{}
	for _, e := range edges {
		if e.To != "FILE01" {
			t.Fatalf("EdgesTo returned an edge not targeting FILE01: %+v", e)
		}
		seen[e.From] = true
	}
	if !seen["WS01"] || !seen["WS02"] {
		t.Fatalf("expected edges from both WS01 and WS02, got %+v", edges)
	}

	if got := g.EdgesTo("NOBODY"); len(got) != 0 {
		t.Fatalf("want 0 edges into an untargeted node, got %d", len(got))
	}
}

func TestBuildGraphAndAnalyzeReturnsSameSummaryAsBuildAndAnalyze(t *testing.T) {
	cols := []Collection{
		{AgentID: "ws01", Source: "agent",
			Nodes: []Node{{ID: "WS01", Kind: KindHost, Role: RoleEndpoint}},
			Edges: []Edge{{From: "WS01", To: "FILE01", Kind: EdgeSMB}}},
	}
	tags := []AssetTag{{HostKey: "FILE01", CrownJewel: "FileServer"}}

	g, s := BuildGraphAndAnalyze(cols, tags)
	if g == nil {
		t.Fatal("BuildGraphAndAnalyze must return a non-nil graph")
	}
	if g.NodeCount() != s.Hosts {
		// FILE01 is host-only in this fixture, so NodeCount == Hosts.
		t.Fatalf("graph node count (%d) should match summary host count (%d)", g.NodeCount(), s.Hosts)
	}

	want := BuildAndAnalyze(cols, tags)
	if s.AttackPathScore != want.AttackPathScore || s.Band != want.Band {
		t.Fatalf("BuildGraphAndAnalyze summary diverged from BuildAndAnalyze: got %+v want %+v", s, want)
	}
}
