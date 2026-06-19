package attackpath

import "time"

// Collection is the normalized recon payload ONE agent submits for the attack-
// path engine. The agent is a pure collector — it emits observed relationship
// and reachability facts (its own identity, domain membership, local admins,
// sessions, host-to-host reachability, and SharpHound output where domain-
// joined). It never builds the graph or computes anything: all analytics happen
// server-side from these facts.
//
// Source distinguishes how the facts were gathered so the server can reason
// about confidence and provenance (e.g. SharpHound edges vs. live reachability
// probes). CollectedAt lets the server age out stale topology.
type Collection struct {
	AgentID     string    `json:"agentId"`
	Hostname    string    `json:"hostname"`
	Source      string    `json:"source"` // "agent" | "sharphound" | "monkey"
	CollectedAt time.Time `json:"collectedAt"`
	Nodes       []Node    `json:"nodes"`
	Edges       []Edge    `json:"edges"`
}

// BuildGraph merges one or more agent collections into a single fleet graph.
//
// Nodes with the same ID reported by different agents are merged field-by-field:
// a later collection ENRICHES an existing node (fills an empty role/segment,
// sets a crown-jewel tag, raises HighValue) but never blanks a field another
// agent already populated. This makes the result independent of collection
// order — exactly what an at-least-once, multi-agent pipeline needs. Duplicate
// edges (same from/to/kind) are collapsed.
func BuildGraph(cols ...Collection) *Graph {
	g := New()
	for _, c := range cols {
		for _, n := range c.Nodes {
			g.mergeNode(n)
		}
	}
	// Edges added after all nodes so explicit node metadata (role/segment/crown
	// jewel) is never clobbered by AddEdge's bare-node auto-creation.
	seen := map[Edge]bool{}
	for _, c := range cols {
		for _, e := range c.Edges {
			if e.From == "" || e.To == "" || seen[e] {
				continue
			}
			seen[e] = true
			g.AddEdge(e)
		}
	}
	return g
}

// mergeNode inserts n, or enriches an existing node of the same ID without
// discarding fields a previous collection already set.
func (g *Graph) mergeNode(n Node) {
	if n.ID == "" {
		return
	}
	cur, ok := g.nodes[n.ID]
	if !ok {
		g.nodes[n.ID] = n
		return
	}
	// Prefer a more specific kind (user/group) over a bare auto-host default.
	if n.Kind != "" && (cur.Kind == "" || cur.Kind == KindHost) {
		cur.Kind = n.Kind
	}
	if cur.Label == "" {
		cur.Label = n.Label
	}
	if cur.Role == "" {
		cur.Role = n.Role
	}
	if cur.Segment == "" {
		cur.Segment = n.Segment
	}
	if cur.CrownJewel == "" {
		cur.CrownJewel = n.CrownJewel
	}
	if n.HighValue {
		cur.HighValue = true
	}
	g.nodes[n.ID] = cur
}
