package attackpath

import "testing"

// TestApplyAssetTagsCrownJewel verifies an operator crown-jewel tag turns an
// otherwise-untagged reachable server into a tracked crown-jewel exposure.
func TestApplyAssetTagsCrownJewel(t *testing.T) {
	cols := []Collection{{
		AgentID: "ws01", Source: "agent",
		Nodes: []Node{{ID: "WS01", Kind: KindHost, Role: RoleEndpoint}},
		Edges: []Edge{{From: "WS01", To: "ERP01", Kind: EdgeRDP}},
	}}
	// No crown jewels before tagging.
	if base := BuildAndAnalyze(cols, nil); len(base.CrownJewels) != 0 {
		t.Fatalf("expected no crown jewels untagged, got %d", len(base.CrownJewels))
	}
	tags := []AssetTag{{HostKey: "erp01", CrownJewel: "ERP"}}
	s := BuildAndAnalyze(cols, tags)
	if len(s.CrownJewels) != 1 || s.CrownJewels[0].Tag != "ERP" {
		t.Fatalf("crown-jewel tag not applied: %+v", s.CrownJewels)
	}
	if !s.CrownJewels[0].Reachable {
		t.Fatal("ERP01 is reachable from WS01 over RDP and should report reachable")
	}
}

// TestApplyAssetTagsSurvivesReconciliation tags by hostname before SharpHound
// arrives; after reconciliation the tag must land on the SID-keyed node.
func TestApplyAssetTagsSurvivesReconciliation(t *testing.T) {
	const sid = "S-1-5-21-7-7-7-2001"
	cols := []Collection{
		{AgentID: "a", Source: "agent",
			Nodes: []Node{{ID: "FIN01", Kind: KindHost, Role: RoleEndpoint, Segment: "fin-vlan"}}},
		{AgentID: "b", Source: "sharphound",
			Nodes: []Node{{ID: sid, Kind: KindHost, Label: "FIN01.corp.local", Role: RoleServer}}},
	}
	tags := []AssetTag{{HostKey: "FIN01", CrownJewel: "FinanceDB", HighValue: true}}
	s := BuildAndAnalyze(cols, tags)

	if len(s.CrownJewels) != 1 || s.CrownJewels[0].Node != sid {
		t.Fatalf("tag should apply to the reconciled SID node: %+v", s.CrownJewels)
	}
	if s.CrownJewels[0].Tag != "FinanceDB" {
		t.Fatalf("tag value wrong: %+v", s.CrownJewels[0])
	}
}

func TestNormalizeHostKey(t *testing.T) {
	for in, want := range map[string]string{
		"DC01.corp.local": "DC01",
		"  file01  ":      "FILE01",
		"10.0.0.5":        "10.0.0.5", // IP literals are not truncated
	} {
		if got := NormalizeHostKey(in); got != want {
			t.Errorf("NormalizeHostKey(%q)=%q, want %q", in, got, want)
		}
	}
}

func TestHostInventory(t *testing.T) {
	g := BuildGraph(Collection{AgentID: "a", Edges: []Edge{{From: "A", To: "B", Kind: EdgeSMB}}})
	g.applyAssetTags([]AssetTag{{HostKey: "B", CrownJewel: "Backup"}})
	inv := g.HostInventory()
	if len(inv) != 2 {
		t.Fatalf("want 2 hosts in inventory, got %d", len(inv))
	}
	var tagged bool
	for _, h := range inv {
		if h.HostKey == "B" && h.CrownJewel == "Backup" {
			tagged = true
		}
	}
	if !tagged {
		t.Fatalf("inventory should reflect applied tag: %+v", inv)
	}
}

func TestApplyAssetTagsCriticalityFields(t *testing.T) {
	cols := []Collection{{
		AgentID: "ws01", Source: "agent",
		Nodes: []Node{{ID: "WS01", Kind: KindHost, Role: RoleEndpoint}},
	}}
	tags := []AssetTag{{
		HostKey: "WS01", CriticalityTier: "high", InternetFacing: true,
		IdentityExposed: true, Production: true, ComplianceScope: []string{"SEBI-CSCRF", "PCI-DSS"},
	}}
	g := BuildGraph(cols...)
	g.applyAssetTags(tags)
	n, ok := g.nodes["WS01"]
	if !ok {
		t.Fatalf("expected node WS01 in graph")
	}
	if n.CriticalityTier != "high" || !n.InternetFacing || !n.IdentityExposed || !n.Production {
		t.Fatalf("criticality fields not applied: %+v", n)
	}
	if len(n.ComplianceScope) != 2 || n.ComplianceScope[0] != "SEBI-CSCRF" {
		t.Fatalf("compliance scope not applied: %+v", n.ComplianceScope)
	}
}

func TestHostInventoryIncludesCriticalityFields(t *testing.T) {
	g := BuildGraph(Collection{AgentID: "a", Edges: []Edge{{From: "A", To: "B", Kind: EdgeSMB}}})
	g.applyAssetTags([]AssetTag{{HostKey: "B", CriticalityTier: "critical", Production: true}})
	inv := g.HostInventory()
	var found bool
	for _, h := range inv {
		if h.HostKey == "B" {
			if h.CriticalityTier != "critical" || !h.Production {
				t.Fatalf("inventory should reflect criticality fields: %+v", h)
			}
			found = true
		}
	}
	if !found {
		t.Fatalf("expected host B in inventory: %+v", inv)
	}
}

func TestBuildGraphAndAnalyze_ConfidenceLevels(t *testing.T) {
	agentOnly := []Collection{{AgentID: "a", Source: "agent", Nodes: []Node{{ID: "H1", Kind: KindHost}}}}
	_, s := BuildGraphAndAnalyze(agentOnly, nil)
	if s.Confidence.Level != "Medium" {
		t.Errorf("agent-only Confidence.Level = %q, want Medium", s.Confidence.Level)
	}
	found := false
	for _, m := range s.Confidence.Missing {
		if m == "Active Directory relationships" {
			found = true
		}
	}
	if !found {
		t.Errorf("agent-only Confidence.Missing = %+v, want it to include Active Directory relationships", s.Confidence.Missing)
	}

	both := []Collection{
		{AgentID: "a", Source: "agent", Nodes: []Node{{ID: "H1", Kind: KindHost}}},
		{AgentID: "a", Source: "sharphound", Nodes: []Node{{ID: "H1", Kind: KindHost}}},
	}
	_, s2 := BuildGraphAndAnalyze(both, nil)
	if s2.Confidence.Level != "High" {
		t.Errorf("agent+sharphound Confidence.Level = %q, want High", s2.Confidence.Level)
	}
	if len(s2.Confidence.Missing) != 0 {
		t.Errorf("agent+sharphound Confidence.Missing = %+v, want empty", s2.Confidence.Missing)
	}

	_, s3 := BuildGraphAndAnalyze(nil, nil)
	if s3.Confidence.Level != "Low" {
		t.Errorf("no collections Confidence.Level = %q, want Low", s3.Confidence.Level)
	}
}

func TestBuildGraphAndAnalyze_DomainCompromiseStatus(t *testing.T) {
	// Reachable: DomainCompromise true regardless of Source.
	reachableCols := []Collection{{AgentID: "a", Source: "agent",
		Nodes: []Node{
			{ID: "WS01", Kind: KindHost}, {ID: "alice", Kind: KindUser}, {ID: "DA", Kind: KindGroup, HighValue: true}, {ID: "DC01", Kind: KindHost},
		},
		Edges: []Edge{
			{From: "WS01", To: "alice", Kind: EdgeHasSession},
			{From: "alice", To: "DA", Kind: EdgeMemberOf},
			{From: "DA", To: "DC01", Kind: EdgeAdminTo},
		}}}
	_, s := BuildGraphAndAnalyze(reachableCols, nil)
	if s.DomainCompromiseStatus != DCStatusReachable {
		t.Errorf("DomainCompromiseStatus = %q, want %q", s.DomainCompromiseStatus, DCStatusReachable)
	}

	// Not-observed: sharphound ran, high-value target exists, but no path found.
	notObservedCols := []Collection{{AgentID: "a", Source: "sharphound",
		Nodes: []Node{{ID: "WS01", Kind: KindHost}, {ID: "DA", Kind: KindGroup, HighValue: true}}}}
	_, s2 := BuildGraphAndAnalyze(notObservedCols, nil)
	if s2.DomainCompromiseStatus != DCStatusNotObserved {
		t.Errorf("DomainCompromiseStatus = %q, want %q", s2.DomainCompromiseStatus, DCStatusNotObserved)
	}

	// Undetermined: no sharphound data at all, no path found.
	undeterminedCols := []Collection{{AgentID: "a", Source: "agent", Nodes: []Node{{ID: "WS01", Kind: KindHost}}}}
	_, s3 := BuildGraphAndAnalyze(undeterminedCols, nil)
	if s3.DomainCompromiseStatus != DCStatusUndetermined {
		t.Errorf("DomainCompromiseStatus = %q, want %q", s3.DomainCompromiseStatus, DCStatusUndetermined)
	}
}
