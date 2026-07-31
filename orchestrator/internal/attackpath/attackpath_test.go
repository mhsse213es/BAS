package attackpath

import "testing"

// sample builds a small but representative enterprise graph. JUMP01 is the
// classic choke point: every attacker path from the user VLAN to the server
// VLAN funnels through it.
//
//	WS01 ─smb──▶ WS02              (same user VLAN, dead end)
//	WS01 ─winrm▶ JUMP01            (crosses user-vlan → dmz-vlan)
//	JUMP01 ─smb▶ FILE01            (crosses dmz-vlan → server-vlan; FILE01 is a crown jewel)
//	FILE01 ─has-session▶ alice     (creds harvestable on FILE01)
//	alice ─member-of▶ DA           (Domain Admins, high-value)
//	DA ─admin-to▶ DC01             (so DA owns the domain controller)
func sample() *Graph {
	g := New()
	g.AddNode(Node{ID: "WS01", Kind: KindHost, Label: "WS01", Role: RoleEndpoint, Segment: "user-vlan"})
	g.AddNode(Node{ID: "WS02", Kind: KindHost, Label: "WS02", Role: RoleEndpoint, Segment: "user-vlan"})
	g.AddNode(Node{ID: "JUMP01", Kind: KindHost, Label: "JUMP01", Role: RoleServer, Segment: "dmz-vlan"})
	g.AddNode(Node{ID: "FILE01", Kind: KindHost, Label: "FILE01", Role: RoleServer, Segment: "server-vlan", CrownJewel: "FileServer"})
	g.AddNode(Node{ID: "DC01", Kind: KindHost, Label: "DC01", Role: RoleDC, Segment: "server-vlan"})
	g.AddNode(Node{ID: "alice", Kind: KindUser, Label: "alice@corp"})
	g.AddNode(Node{ID: "DA", Kind: KindGroup, Label: "Domain Admins", HighValue: true})

	g.AddEdge(Edge{From: "WS01", To: "WS02", Kind: EdgeSMB})
	g.AddEdge(Edge{From: "WS01", To: "JUMP01", Kind: EdgeWinRM})
	g.AddEdge(Edge{From: "JUMP01", To: "FILE01", Kind: EdgeSMB})
	g.AddEdge(Edge{From: "FILE01", To: "alice", Kind: EdgeHasSession})
	g.AddEdge(Edge{From: "alice", To: "DA", Kind: EdgeMemberOf})
	g.AddEdge(Edge{From: "DA", To: "DC01", Kind: EdgeAdminTo})
	return g
}

func TestShortestPathToDomainAdmin(t *testing.T) {
	g := sample()
	p := g.ShortestPathToDomainAdmin("WS01")
	if p == nil {
		t.Fatal("expected a path from WS01 to Domain Admins")
	}
	if len(p) != 4 {
		t.Fatalf("expected 4 hops WS01→JUMP01→FILE01→alice→DA, got %d: %+v", len(p), p)
	}
	if p[0].To != "JUMP01" || p[1].To != "FILE01" || p[2].To != "alice" || p[3].To != "DA" {
		t.Fatalf("unexpected path: %+v", p)
	}
}

func TestBlastRadiusAndReachability(t *testing.T) {
	g := sample()
	if b := g.BlastRadius("WS01"); b != 4 {
		t.Fatalf("BlastRadius(WS01)=%d, want 4 (WS02,JUMP01,FILE01,DC01)", b)
	}
	r := g.Reachability("WS01")
	if r.Endpoints != 1 || r.Servers != 2 || r.DCs != 1 {
		t.Fatalf("reachability WS01 = %+v, want endpoints=1 servers=2 dcs=1", r)
	}
	// WS02 is a dead end.
	if b := g.BlastRadius("WS02"); b != 0 {
		t.Fatalf("BlastRadius(WS02)=%d, want 0", b)
	}
}

func TestSegmentationViolations(t *testing.T) {
	g := sample()
	v := g.SegmentationViolations()
	if len(v) != 2 {
		t.Fatalf("want 2 segmentation violations (WS01→JUMP01, JUMP01→FILE01), got %d: %+v", len(v), v)
	}
}

func TestCrownJewelExposure(t *testing.T) {
	g := sample()
	cjs := g.CrownJewelExposures()
	if len(cjs) != 1 {
		t.Fatalf("want 1 crown jewel, got %d", len(cjs))
	}
	cj := cjs[0]
	if cj.Node != "FILE01" || !cj.Reachable {
		t.Fatalf("FILE01 should be a reachable crown jewel: %+v", cj)
	}
	// reachable from WS01 (2 hops) and JUMP01 (1 hop).
	if cj.EntryHosts != 2 || cj.MinHops != 1 {
		t.Fatalf("FILE01 exposure = %+v, want entryHosts=2 minHops=1", cj)
	}
}

func TestChokePoints(t *testing.T) {
	g := sample()
	cp := g.ChokePoints()
	if len(cp) == 0 {
		t.Fatal("expected at least one choke point")
	}
	// JUMP01 funnels WS01's path into the server VLAN — the classic choke point.
	found := false
	for _, c := range cp {
		if c.Node == "JUMP01" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected JUMP01 to be a choke point, got %+v", cp)
	}
}

func TestPathDifficulty(t *testing.T) {
	if d := PathDifficulty(nil); d != DiffVeryHard {
		t.Fatalf("nil path should be Very Hard, got %s", d)
	}
	easy := []Edge{{Kind: EdgeSMB}, {Kind: EdgeSMB}}
	if d := PathDifficulty(easy); d != DiffEasy {
		t.Fatalf("2 reachability hops should be Easy, got %s", d)
	}
	// 3 hops, 1 of them a credential step = score 3 + 2 = 5 → Medium
	mixed := []Edge{{Kind: EdgeSMB}, {Kind: EdgeSMB}, {Kind: EdgeHasSession}}
	if d := PathDifficulty(mixed); d != DiffMedium {
		t.Fatalf("expected Medium, got %s", d)
	}
}

func TestAnalyzeScore(t *testing.T) {
	g := sample()
	s := g.Analyze()
	if !s.DomainCompromise {
		t.Fatal("sample graph must report domain compromise")
	}
	if s.Hosts != 5 || s.Users != 1 || s.Groups != 1 {
		t.Fatalf("node counts wrong: %+v", s)
	}
	if s.AttackPathScore >= 80 {
		t.Fatalf("a graph with DA compromise + crown jewel + segmentation violation should not score Low-risk; got %d", s.AttackPathScore)
	}
	if s.Band == "" {
		t.Fatal("band should be set")
	}
	if len(s.ShortestDAPath) == 0 {
		t.Fatal("representative DA path should be populated")
	}
}

func TestCleanGraphScoresHigh(t *testing.T) {
	// Two isolated endpoints, no DA, no crown jewels, no cross-segment edges.
	g := New()
	g.AddNode(Node{ID: "A", Kind: KindHost, Role: RoleEndpoint, Segment: "vlan1"})
	g.AddNode(Node{ID: "B", Kind: KindHost, Role: RoleEndpoint, Segment: "vlan1"})
	s := g.Analyze()
	if s.AttackPathScore != 100 {
		t.Fatalf("a clean isolated graph should score 100, got %d", s.AttackPathScore)
	}
	if s.Band != "Low" {
		t.Fatalf("clean graph band = %s, want Low", s.Band)
	}
}

func TestAddEdgeAutoCreatesNodes(t *testing.T) {
	g := New()
	g.AddEdge(Edge{From: "X", To: "Y", Kind: EdgeSMB})
	if g.NodeCount() != 2 {
		t.Fatalf("AddEdge should auto-create endpoints; nodes=%d", g.NodeCount())
	}
	if _, ok := g.Node("Y"); !ok {
		t.Fatal("Y should exist as a bare host node")
	}
}

func TestAnalyzeScoreDrivers_SumsToActualDeficit(t *testing.T) {
	g := sample()
	s := g.Analyze()
	if len(s.ScoreDrivers) != 4 {
		t.Fatalf("ScoreDrivers = %+v, want 4 entries", s.ScoreDrivers)
	}
	var total float64
	for _, d := range s.ScoreDrivers {
		if d.Label == "" {
			t.Errorf("driver has empty label: %+v", d)
		}
		total += d.Deficit
	}
	wantDeficit := float64(100 - s.AttackPathScore)
	if total < wantDeficit-1 || total > wantDeficit+1 {
		t.Fatalf("ScoreDrivers sum to %.2f, want ~%.2f (100 - AttackPathScore, allowing rounding)", total, wantDeficit)
	}
}

func TestAnalyzeScoreDrivers_CleanGraphAllZero(t *testing.T) {
	g := New()
	g.AddNode(Node{ID: "A", Kind: KindHost, Role: RoleEndpoint, Segment: "vlan1"})
	g.AddNode(Node{ID: "B", Kind: KindHost, Role: RoleEndpoint, Segment: "vlan1"})
	s := g.Analyze()
	for _, d := range s.ScoreDrivers {
		if d.Deficit != 0 {
			t.Errorf("driver %q deficit = %v, want 0 for a clean graph", d.Label, d.Deficit)
		}
	}
}

func TestAnalyzeRelationshipCounts(t *testing.T) {
	g := sample()
	s := g.Analyze()
	want := map[string]int{"smb": 2, "winrm": 1, "has-session": 1, "member-of": 1, "admin-to": 1}
	if len(s.RelationshipCounts) != len(want) {
		t.Fatalf("RelationshipCounts = %+v, want %+v", s.RelationshipCounts, want)
	}
	for k, v := range want {
		if s.RelationshipCounts[k] != v {
			t.Errorf("RelationshipCounts[%q] = %d, want %d", k, s.RelationshipCounts[k], v)
		}
	}
}
