package pathcorrelation

import (
	"testing"

	"github.com/audspect/bas/internal/attackpath"
)

func testGraph() (*attackpath.Graph, attackpath.Summary) {
	cols := []attackpath.Collection{
		{AgentID: "ws01", Source: "agent",
			Nodes: []attackpath.Node{{ID: "WS01", Kind: attackpath.KindHost, Role: attackpath.RoleEndpoint}},
			Edges: []attackpath.Edge{{From: "WS01", To: "FILE01", Kind: attackpath.EdgeSMB}}},
		{AgentID: "file01", Source: "sharphound",
			Nodes: []attackpath.Node{
				{ID: "FILE01", Kind: attackpath.KindHost, Role: attackpath.RoleServer, CrownJewel: "FileServer"},
				{ID: "svc", Kind: attackpath.KindUser, Label: "svc-backup"},
				{ID: "DA", Kind: attackpath.KindGroup, Label: "Domain Admins", HighValue: true},
			},
			Edges: []attackpath.Edge{
				{From: "FILE01", To: "svc", Kind: attackpath.EdgeHasSession},
				{From: "svc", To: "DA", Kind: attackpath.EdgeMemberOf},
			}},
	}
	return attackpath.BuildGraphAndAnalyze(cols, nil)
}

func TestDefaultPaths_IncludesDAPathAndCrownJewelPath(t *testing.T) {
	g, s := testGraph()
	if !s.DomainCompromise {
		t.Fatalf("fixture should produce domain compromise: %+v", s)
	}

	paths := DefaultPaths(g, s)

	var haveDA, haveCJ bool
	for _, p := range paths {
		if len(p.Edges) == len(s.ShortestDAPath) && p.Weight == pathWeightDA {
			haveDA = true
		}
		if p.Weight > 0 && p.Weight != pathWeightDA {
			haveCJ = true
			if p.Edges[len(p.Edges)-1].To != "FILE01" {
				t.Fatalf("crown-jewel path should end at FILE01, got %+v", p.Edges)
			}
		}
	}
	if !haveDA {
		t.Fatalf("expected a Domain-Admin path among %+v", paths)
	}
	if !haveCJ {
		t.Fatalf("expected a crown-jewel path among %+v", paths)
	}
}

func TestDefaultPaths_EmptyGraphReturnsNoPaths(t *testing.T) {
	g, s := attackpath.BuildGraphAndAnalyze(nil, nil)
	if paths := DefaultPaths(g, s); len(paths) != 0 {
		t.Fatalf("empty graph should produce 0 paths, got %d", len(paths))
	}
}
