package attackpath

import "testing"

// TestGraphEdges_ReturnsEveryEdge pins the Edges() accessor: internal/recommend
// needs to enumerate all edges to decide which ATT&CK techniques are relevant
// to this environment, and adj is unexported.
func TestGraphEdges_ReturnsEveryEdge(t *testing.T) {
	g := New()
	g.AddEdge(Edge{From: "A", To: "B", Kind: EdgeSMB})
	g.AddEdge(Edge{From: "B", To: "C", Kind: EdgeWinRM})
	g.AddEdge(Edge{From: "A", To: "C", Kind: EdgeRDP})

	got := g.Edges()
	if len(got) != 3 {
		t.Fatalf("Edges() returned %d edges, want 3", len(got))
	}
	if len(got) != g.EdgeCount() {
		t.Errorf("Edges() length %d disagrees with EdgeCount() %d", len(got), g.EdgeCount())
	}
	seen := map[EdgeKind]bool{}
	for _, e := range got {
		seen[e.Kind] = true
	}
	for _, want := range []EdgeKind{EdgeSMB, EdgeWinRM, EdgeRDP} {
		if !seen[want] {
			t.Errorf("Edges() missing an edge of kind %q", want)
		}
	}
}

func TestGraphEdges_EmptyGraphReturnsNothing(t *testing.T) {
	g := New()
	if got := g.Edges(); len(got) != 0 {
		t.Errorf("Edges() on an empty graph = %d edges, want 0", len(got))
	}
}
