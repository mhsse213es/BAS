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
		"10.0.0.5":        "10",
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
