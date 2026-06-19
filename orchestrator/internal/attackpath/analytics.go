package attackpath

import "sort"

// neighbors returns the outgoing edges from a node id.
func (g *Graph) neighbors(id string) []Edge { return g.adj[id] }

// hostKinds returns whether a node id is a host.
func (g *Graph) isHost(id string) bool {
	n, ok := g.nodes[id]
	return ok && n.Kind == KindHost
}

// ShortestPath returns the fewest-edge attacker path From → To over ALL edge
// kinds (lateral movement + identity/credential escalation), or nil if To is
// unreachable. The attacker model: from a compromised node you may move
// laterally (smb/winrm/rdp), harvest sessions, inherit group membership, and
// use admin/credential rights — exactly the BloodHound traversal.
func (g *Graph) ShortestPath(from, to string) []Edge {
	if from == to {
		return []Edge{}
	}
	if _, ok := g.nodes[from]; !ok {
		return nil
	}
	prev := map[string]Edge{}
	seen := map[string]bool{from: true}
	queue := []string{from}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for _, e := range g.neighbors(cur) {
			if seen[e.To] {
				continue
			}
			seen[e.To] = true
			prev[e.To] = e
			if e.To == to {
				return reconstruct(prev, from, to)
			}
			queue = append(queue, e.To)
		}
	}
	return nil
}

// shortestPathToAny returns the shortest path to the nearest node in targets.
func (g *Graph) shortestPathToAny(from string, targets map[string]bool) []Edge {
	if targets[from] {
		return []Edge{}
	}
	prev := map[string]Edge{}
	seen := map[string]bool{from: true}
	queue := []string{from}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for _, e := range g.neighbors(cur) {
			if seen[e.To] {
				continue
			}
			seen[e.To] = true
			prev[e.To] = e
			if targets[e.To] {
				return reconstruct(prev, from, e.To)
			}
			queue = append(queue, e.To)
		}
	}
	return nil
}

func reconstruct(prev map[string]Edge, from, to string) []Edge {
	var rev []Edge
	cur := to
	for cur != from {
		e, ok := prev[cur]
		if !ok {
			return nil
		}
		rev = append(rev, e)
		cur = e.From
	}
	// reverse
	out := make([]Edge, len(rev))
	for i, e := range rev {
		out[len(rev)-1-i] = e
	}
	return out
}

// ReachableFrom returns the set of every node id an attacker who owns `from`
// can ultimately compromise (full edge closure). `from` itself is included.
func (g *Graph) ReachableFrom(from string) map[string]bool {
	seen := map[string]bool{from: true}
	queue := []string{from}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for _, e := range g.neighbors(cur) {
			if !seen[e.To] {
				seen[e.To] = true
				queue = append(queue, e.To)
			}
		}
	}
	return seen
}

// BlastRadius is the number of OTHER hosts compromisable from an entry host.
func (g *Graph) BlastRadius(from string) int {
	n := 0
	for id := range g.ReachableFrom(from) {
		if id != from && g.isHost(id) {
			n++
		}
	}
	return n
}

// Reachability counts reachable hosts by role from an entry host.
type Reachability struct {
	Entry     string `json:"entry"`
	Endpoints int    `json:"endpoints"`
	Servers   int    `json:"servers"`
	DCs       int    `json:"dcs"`
	Total     int    `json:"total"` // total other hosts (== BlastRadius)
}

// Reachability classifies the blast radius of an entry host by host role.
func (g *Graph) Reachability(from string) Reachability {
	r := Reachability{Entry: from}
	for id := range g.ReachableFrom(from) {
		if id == from {
			continue
		}
		n, ok := g.nodes[id]
		if !ok || n.Kind != KindHost {
			continue
		}
		r.Total++
		switch n.Role {
		case RoleDC:
			r.DCs++
		case RoleServer:
			r.Servers++
		default:
			r.Endpoints++
		}
	}
	return r
}

// highValueTargets returns the set of node ids flagged HighValue (Domain
// Admins / Tier-0 / DA-equivalent group nodes).
func (g *Graph) highValueTargets() map[string]bool {
	t := map[string]bool{}
	for id, n := range g.nodes {
		if n.HighValue {
			t[id] = true
		}
	}
	return t
}

// crownJewelTargets returns the set of node ids tagged as crown jewels.
func (g *Graph) crownJewelTargets() map[string]bool {
	t := map[string]bool{}
	for id, n := range g.nodes {
		if n.CrownJewel != "" {
			t[id] = true
		}
	}
	return t
}

// ShortestPathToDomainAdmin returns the shortest path from an entry host to the
// nearest HighValue (Domain Admin / Tier-0) node, or nil if none reachable.
func (g *Graph) ShortestPathToDomainAdmin(from string) []Edge {
	return g.shortestPathToAny(from, g.highValueTargets())
}

// CanReachDomainAdmin reports whether ANY host can reach a HighValue target.
func (g *Graph) CanReachDomainAdmin() bool {
	hv := g.highValueTargets()
	if len(hv) == 0 {
		return false
	}
	for id, n := range g.nodes {
		if n.Kind != KindHost {
			continue
		}
		if p := g.shortestPathToAny(id, hv); p != nil {
			return true
		}
	}
	return false
}

// CrownJewelExposure summarizes how exposed a crown-jewel asset is.
type CrownJewelExposure struct {
	Node       string `json:"node"`
	Tag        string `json:"tag"`
	Reachable  bool   `json:"reachable"`
	EntryHosts int    `json:"entryHosts"` // distinct hosts from which it is reachable
	MinHops    int    `json:"minHops"`    // fewest hops from any entry host (0 if unreachable)
}

// CrownJewelExposures evaluates each tagged crown jewel against every host
// entry point: how many hosts can reach it and the shortest hop count.
func (g *Graph) CrownJewelExposures() []CrownJewelExposure {
	var out []CrownJewelExposure
	hosts := g.hostIDs()
	for _, n := range g.sortedNodes() {
		if n.CrownJewel == "" {
			continue
		}
		ex := CrownJewelExposure{Node: n.ID, Tag: n.CrownJewel, MinHops: 0}
		best := -1
		for _, h := range hosts {
			if h == n.ID {
				continue
			}
			p := g.ShortestPath(h, n.ID)
			if p == nil {
				continue
			}
			ex.Reachable = true
			ex.EntryHosts++
			if best < 0 || len(p) < best {
				best = len(p)
			}
		}
		if best >= 0 {
			ex.MinHops = best
		}
		out = append(out, ex)
	}
	return out
}

// SegmentationViolation is a lateral-movement edge that crosses a network
// segment boundary (both endpoints tagged, different segments).
type SegmentationViolation struct {
	From        string   `json:"from"`
	To          string   `json:"to"`
	Kind        EdgeKind `json:"kind"`
	FromSegment string   `json:"fromSegment"`
	ToSegment   string   `json:"toSegment"`
}

// SegmentationViolations returns lateral-movement edges that cross segments.
func (g *Graph) SegmentationViolations() []SegmentationViolation {
	var out []SegmentationViolation
	for _, src := range g.sortedNodeIDs() {
		for _, e := range g.adj[src] {
			if !reachKinds[e.Kind] {
				continue
			}
			fn, ok1 := g.nodes[e.From]
			tn, ok2 := g.nodes[e.To]
			if !ok1 || !ok2 {
				continue
			}
			if fn.Segment == "" || tn.Segment == "" || fn.Segment == tn.Segment {
				continue
			}
			out = append(out, SegmentationViolation{
				From: e.From, To: e.To, Kind: e.Kind,
				FromSegment: fn.Segment, ToSegment: tn.Segment,
			})
		}
	}
	return out
}

// ChokePoint is a node that lies on many attacker paths to high-value targets;
// remediating it eliminates a disproportionate number of paths.
type ChokePoint struct {
	Node     string  `json:"node"`
	Label    string  `json:"label"`
	OnPaths  int     `json:"onPaths"`  // number of host entries whose DA/crown-jewel path traverses this node
	Coverage float64 `json:"coverage"` // OnPaths / total host entries with a path (0..1)
}

// ChokePoints finds the intermediate nodes that appear most often on the
// shortest paths from each host to the nearest high-value or crown-jewel
// target. Sorted by coverage descending.
func (g *Graph) ChokePoints() []ChokePoint {
	targets := g.highValueTargets()
	for id := range g.crownJewelTargets() {
		targets[id] = true
	}
	if len(targets) == 0 {
		return nil
	}
	count := map[string]int{}
	pathsWithRoute := 0
	for _, h := range g.hostIDs() {
		if targets[h] {
			continue
		}
		p := g.shortestPathToAny(h, targets)
		if p == nil {
			continue
		}
		pathsWithRoute++
		// intermediate nodes only: skip the entry host and the final target
		seen := map[string]bool{}
		for i, e := range p {
			if i == len(p)-1 {
				break // e.To is the target
			}
			if e.To == h || targets[e.To] {
				continue
			}
			if !seen[e.To] {
				seen[e.To] = true
				count[e.To]++
			}
		}
	}
	if pathsWithRoute == 0 {
		return nil
	}
	var out []ChokePoint
	for id, c := range count {
		lbl := id
		if n, ok := g.nodes[id]; ok && n.Label != "" {
			lbl = n.Label
		}
		out = append(out, ChokePoint{
			Node: id, Label: lbl, OnPaths: c,
			Coverage: round2(float64(c) / float64(pathsWithRoute)),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].OnPaths != out[j].OnPaths {
			return out[i].OnPaths > out[j].OnPaths
		}
		return out[i].Node < out[j].Node
	})
	return out
}

// Difficulty bands a path by how hard it is to walk.
type Difficulty string

const (
	DiffEasy     Difficulty = "Easy"
	DiffMedium   Difficulty = "Medium"
	DiffHard     Difficulty = "Hard"
	DiffVeryHard Difficulty = "Very Hard"
)

// PathDifficulty rates a path by hop count and whether it requires credential
// theft / privilege abuse (identity edges raise difficulty). Shorter,
// reachability-only paths are easier for an attacker; long paths needing
// credential or admin escalation are harder.
func PathDifficulty(path []Edge) Difficulty {
	if path == nil {
		return DiffVeryHard
	}
	hops := len(path)
	credSteps := 0
	for _, e := range path {
		switch e.Kind {
		case EdgeHasSession, EdgeCredential, EdgeAdminTo, EdgeMemberOf:
			credSteps++
		}
	}
	score := hops + 2*credSteps
	switch {
	case score <= 2:
		return DiffEasy
	case score <= 5:
		return DiffMedium
	case score <= 9:
		return DiffHard
	default:
		return DiffVeryHard
	}
}

// LateralMovementBand summarizes fleet-wide lateral movement risk from the
// average blast radius across host entry points.
func (g *Graph) LateralMovementBand() string {
	hosts := g.hostIDs()
	if len(hosts) == 0 {
		return "Unknown"
	}
	total := 0
	for _, h := range hosts {
		total += g.BlastRadius(h)
	}
	avg := float64(total) / float64(len(hosts))
	frac := avg / float64(maxInt(len(hosts)-1, 1))
	switch {
	case frac >= 0.6:
		return "Critical"
	case frac >= 0.35:
		return "High"
	case frac >= 0.15:
		return "Medium"
	default:
		return "Low"
	}
}

// hostIDs returns sorted host node ids (deterministic iteration).
func (g *Graph) hostIDs() []string {
	var out []string
	for id, n := range g.nodes {
		if n.Kind == KindHost {
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out
}

func (g *Graph) sortedNodeIDs() []string {
	out := make([]string, 0, len(g.nodes))
	for id := range g.nodes {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

func (g *Graph) sortedNodes() []Node {
	ids := g.sortedNodeIDs()
	out := make([]Node, 0, len(ids))
	for _, id := range ids {
		out = append(out, g.nodes[id])
	}
	return out
}

func round2(f float64) float64 {
	return float64(int(f*100+0.5)) / 100
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
