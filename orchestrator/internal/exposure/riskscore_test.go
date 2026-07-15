package exposure

import (
	"context"
	"testing"

	"github.com/audspect/bas/internal/attackpath"
	"github.com/audspect/bas/internal/pathcorrelation"
	"github.com/audspect/bas/internal/rulelib"
)

func daFixtureGraph() (*attackpath.Graph, attackpath.Summary) {
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

type nilRunLookup struct{}

func (nilRunLookup) VerifiedDetection(_ context.Context, _, _ string) (pathcorrelation.VerificationResult, bool, error) {
	return pathcorrelation.VerificationResult{}, false, nil
}

type nilRuleLibrary struct{}

func (nilRuleLibrary) RulesByTechnique(_ string) []rulelib.Rule { return nil }

func TestUnionAssets_DedupsGraphHostAndAgentByHostKey(t *testing.T) {
	g, _ := daFixtureGraph()
	agents := []AgentRow{{AgentID: "a1", Hostname: "WS01"}, {AgentID: "a2", Hostname: "UNRELATED"}}

	assets := unionAssets(g, agents)

	var sawWS01Merged, sawUnrelated, sawFile01Unmanaged bool
	for _, a := range assets {
		switch a.hostKey {
		case "WS01":
			if a.nodeID == "" || a.agent == nil {
				t.Fatalf("WS01 should have both a graph node and an agent, got %+v", a)
			}
			sawWS01Merged = true
		case "UNRELATED":
			if a.nodeID != "" {
				t.Fatalf("UNRELATED should have no graph node, got %+v", a)
			}
			sawUnrelated = true
		case "FILE01":
			if a.agent != nil {
				t.Fatalf("FILE01 should be unmanaged (no agent), got %+v", a)
			}
			sawFile01Unmanaged = true
		}
	}
	if !sawWS01Merged || !sawUnrelated || !sawFile01Unmanaged {
		t.Fatalf("expected WS01 merged, UNRELATED agent-only, FILE01 graph-only; got %+v", assets)
	}
}

func TestAttackPathContext_HostOnDAPathGetsMaxRisk(t *testing.T) {
	g, s := daFixtureGraph()
	// WS01 is the entry host; the DA path runs WS01->FILE01->svc->DA.
	ctx, risk := attackPathContext(g, s, "WS01")
	if !ctx.Reachable {
		t.Fatalf("WS01 should be reachable: %+v", ctx)
	}
	if risk != 100 {
		t.Fatalf("host on the shortest DA path should have risk 100, got %v", risk)
	}
}

func TestAttackPathContext_UnknownNodeIsNotReachable(t *testing.T) {
	g, s := daFixtureGraph()
	ctx, risk := attackPathContext(g, s, "")
	if ctx.Reachable || risk != 0 {
		t.Fatalf("empty nodeID should be unreachable with 0 risk, got ctx=%+v risk=%v", ctx, risk)
	}
}

func TestDetectionContext_AveragesAcrossTouchingEdgesOnly(t *testing.T) {
	g, s := daFixtureGraph()
	paths := pathcorrelation.DefaultPaths(g, s)
	corr, err := pathcorrelation.Correlate(context.Background(), g, s, paths, pathcorrelation.DefaultEdgeTechniqueMapper{},
		nilRunLookup{}, nilRuleLibrary{})
	if err != nil {
		t.Fatalf("Correlate: %v", err)
	}

	dc, risk := detectionContext(corr, "FILE01")
	if len(dc.Edges) == 0 {
		t.Fatalf("FILE01 should have at least one touching edge")
	}
	if risk <= 0 {
		t.Fatalf("with no verified detections anywhere, risk should be > 0, got %v", risk)
	}

	_, noEdgesRisk := detectionContext(corr, "does-not-exist")
	if noEdgesRisk != 0 {
		t.Fatalf("a node with zero touching edges should have risk 0, got %v", noEdgesRisk)
	}
}
