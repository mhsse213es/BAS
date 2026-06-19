package attackpath

import "testing"

// TestReconcileBridgesReachabilityIntoAD is the core identity-reconciliation
// case: an endpoint reaches a file server over SMB (reachability, hostname-
// keyed), and SharpHound (SID-keyed) shows that same server has a session for a
// user who is a Domain Admin. Only after reconciling the two FILE01 identities
// can the endpoint's path reach Domain Admin.
func TestReconcileBridgesReachabilityIntoAD(t *testing.T) {
	const fileSID = "S-1-5-21-1-1-1-1002"
	reach := Collection{
		AgentID: "ws01", Source: "agent",
		Nodes: []Node{{ID: "WS01", Kind: KindHost, Role: RoleEndpoint, Segment: "user-vlan"}},
		Edges: []Edge{{From: "WS01", To: "FILE01", Kind: EdgeSMB}}, // bare "FILE01" host
	}
	ad := Collection{
		AgentID: "dc01", Source: "sharphound",
		Nodes: []Node{
			{ID: fileSID, Kind: KindHost, Label: "FILE01.CORP.LOCAL", Role: RoleServer},
			{ID: "S-1-5-21-1-1-1-1107", Kind: KindUser, Label: "svc@corp"},
			{ID: "S-1-5-21-1-1-1-512", Kind: KindGroup, Label: "Domain Admins", HighValue: true},
		},
		Edges: []Edge{
			{From: fileSID, To: "S-1-5-21-1-1-1-1107", Kind: EdgeHasSession},
			{From: "S-1-5-21-1-1-1-1107", To: "S-1-5-21-1-1-1-512", Kind: EdgeMemberOf},
		},
	}

	g := BuildGraph(reach, ad)

	// The two FILE01 representations must collapse into the SID-keyed node.
	if _, ok := g.Node("FILE01"); ok {
		t.Fatal("hostname node FILE01 should have been reconciled away")
	}
	fn, ok := g.Node(fileSID)
	if !ok {
		t.Fatal("canonical SID host should remain")
	}
	// Segment from reachability is gone (it was on the bare node, which had none);
	// the merged node keeps the AD role.
	if fn.Role != RoleServer {
		t.Fatalf("reconciled FILE01 should keep server role, got %q", fn.Role)
	}

	// WS01's SMB edge now lands on the SID node, so the AD path is reachable.
	p := g.ShortestPathToDomainAdmin("WS01")
	if p == nil {
		t.Fatal("after reconciliation WS01 must reach Domain Admin through FILE01")
	}

	s := g.Analyze()
	if !s.DomainCompromise {
		t.Fatalf("expected domain compromise after reconciliation: %+v", s)
	}
	// WS01 + FILE01 only (2 hosts) — not 3 from a duplicated FILE01.
	if s.Hosts != 2 {
		t.Fatalf("want 2 hosts after dedupe, got %d", s.Hosts)
	}
}

// TestReconcileKeepsSegmentFromReachability verifies the merge keeps the network
// segment (which only the reachability collector knows) on the canonical node.
func TestReconcileKeepsSegmentFromReachability(t *testing.T) {
	const sid = "S-1-5-21-9-9-9-1500"
	reach := Collection{AgentID: "a", Source: "agent",
		Nodes: []Node{{ID: "SRV9", Kind: KindHost, Role: RoleEndpoint, Segment: "dmz"}}}
	ad := Collection{AgentID: "b", Source: "sharphound",
		Nodes: []Node{{ID: sid, Kind: KindHost, Label: "SRV9.corp.local", Role: RoleServer}}}
	g := BuildGraph(reach, ad)
	n, ok := g.Node(sid)
	if !ok {
		t.Fatal("SID node should survive as canonical")
	}
	if n.Segment != "dmz" {
		t.Fatalf("segment from reachability must carry to canonical, got %q", n.Segment)
	}
	if n.Role != RoleServer {
		t.Fatalf("AD role should win over bare endpoint, got %q", n.Role)
	}
}

// TestReconcileNoSharpHoundIsNoOp ensures a pure-reachability graph (no SIDs) is
// untouched — reconciliation must never merge distinct hostname-keyed hosts.
func TestReconcileNoSharpHoundIsNoOp(t *testing.T) {
	c := Collection{AgentID: "a", Source: "agent", Edges: []Edge{
		{From: "WS01", To: "WS02", Kind: EdgeSMB},
		{From: "WS01", To: "WS03", Kind: EdgeRDP},
	}}
	g := BuildGraph(c)
	if g.NodeCount() != 3 {
		t.Fatalf("pure reachability graph should keep 3 hosts, got %d", g.NodeCount())
	}
}
