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
