package exposure

import (
	"context"
	"testing"

	"github.com/audspect/bas/internal/attackpath"
	"github.com/audspect/bas/internal/pathcorrelation"
	"github.com/audspect/bas/internal/relationships"
)

func buildDaFixtureCorrelation(t *testing.T) (*attackpath.Graph, attackpath.Summary, pathcorrelation.AttackPathCorrelation) {
	t.Helper()
	g, s := daFixtureGraph()
	paths := pathcorrelation.DefaultPaths(g, s)
	corr, err := pathcorrelation.Correlate(context.Background(), g, s, paths, pathcorrelation.DefaultEdgeTechniqueMapper{},
		nilRunLookup{}, nilRuleLibrary{})
	if err != nil {
		t.Fatalf("Correlate: %v", err)
	}
	return g, s, corr
}

func TestBuild_EmptyInputsProduceNoAssets(t *testing.T) {
	g, s := attackpath.BuildGraphAndAnalyze(nil, nil)
	corr, err := pathcorrelation.Correlate(context.Background(), g, s, nil, pathcorrelation.DefaultEdgeTechniqueMapper{},
		nilRunLookup{}, nilRuleLibrary{})
	if err != nil {
		t.Fatalf("Correlate: %v", err)
	}
	ag, err := Build(context.Background(), g, s, corr, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if len(ag.Summaries()) != 0 {
		t.Fatalf("expected 0 assets, got %d", len(ag.Summaries()))
	}
}

// TestBuild_CriticalityTierRaisesExposureRisk isolates the new 4th term: two
// leaf hosts identical in every other respect (same distance from the entry
// point, same single SMB touching edge, zero CVEs) should differ ONLY in
// CriticalityRisk/ExposureScore once one is tagged critical.
func TestBuild_CriticalityTierRaisesExposureRisk(t *testing.T) {
	cols := []attackpath.Collection{
		{AgentID: "ws01", Source: "agent",
			Nodes: []attackpath.Node{{ID: "WS01", Kind: attackpath.KindHost, Role: attackpath.RoleEndpoint}},
			Edges: []attackpath.Edge{
				{From: "WS01", To: "PLAIN01", Kind: attackpath.EdgeSMB},
				{From: "WS01", To: "CRIT01", Kind: attackpath.EdgeSMB},
			}},
		{AgentID: "plain01", Source: "agent",
			Nodes: []attackpath.Node{{ID: "PLAIN01", Kind: attackpath.KindHost, Role: attackpath.RoleServer}}},
		{AgentID: "crit01", Source: "agent",
			Nodes: []attackpath.Node{{ID: "CRIT01", Kind: attackpath.KindHost, Role: attackpath.RoleServer, CriticalityTier: "critical"}}},
	}
	g, s := attackpath.BuildGraphAndAnalyze(cols, nil)
	paths := pathcorrelation.DefaultPaths(g, s)
	corr, err := pathcorrelation.Correlate(context.Background(), g, s, paths, pathcorrelation.DefaultEdgeTechniqueMapper{},
		nilRunLookup{}, nilRuleLibrary{})
	if err != nil {
		t.Fatalf("Correlate: %v", err)
	}
	ag, err := Build(context.Background(), g, s, corr,
		&fakeRelLookup{byTech: map[string][]relationships.Relationship{}}, &fakeEnricher{meta: map[string]CVEMeta{}}, nil, nil)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	plain, ok := ag.Profile("PLAIN01")
	if !ok {
		t.Fatalf("expected a profile for PLAIN01")
	}
	crit, ok := ag.Profile("CRIT01")
	if !ok {
		t.Fatalf("expected a profile for CRIT01")
	}
	if crit.Scores.CriticalityRisk <= plain.Scores.CriticalityRisk {
		t.Fatalf("CRIT01 (tier=critical) should have higher CriticalityRisk than untagged PLAIN01: crit=%d plain=%d",
			crit.Scores.CriticalityRisk, plain.Scores.CriticalityRisk)
	}
	if crit.Scores.ExposureScore >= plain.Scores.ExposureScore {
		t.Fatalf("with identical attack-path/detection/vulnerability posture, the critical-tagged asset should score lower (more exposed): crit=%d plain=%d",
			crit.Scores.ExposureScore, plain.Scores.ExposureScore)
	}
}

func TestBuild_HostOnDAPath_LowExposureScore(t *testing.T) {
	g, s, corr := buildDaFixtureCorrelation(t)
	rels := &fakeRelLookup{byTech: map[string][]relationships.Relationship{}}
	ag, err := Build(context.Background(), g, s, corr, rels, &fakeEnricher{meta: map[string]CVEMeta{}}, nil, nil)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	profile, ok := ag.Profile("WS01")
	if !ok {
		t.Fatalf("expected a profile for WS01")
	}
	if profile.Scores.AttackPathScore != 0 {
		t.Fatalf("host on the shortest DA path should have AttackPathScore 0, got %d", profile.Scores.AttackPathScore)
	}
	// Threshold recalibrated for SP6's reweighted formula (.40/.35/.25 ->
	// .30/.30/.20/.20): WS01 is untagged/non-DC but still picks up a +5
	// CriticalityRisk bump (T1021.002 has attributed ATT&CK groups in the
	// bundled data, so ThreatGroupCount>0), landing this fixture's score at
	// 51 instead of the pre-reweight 39. See ADR-009 and
	// docs/superpowers/specs/2026-07-17-sp6-asset-criticality-design.md for
	// why this shift is expected, not a regression.
	if profile.Scores.ExposureScore >= 52 {
		t.Fatalf("a host on the DA path with zero detection coverage should score low, got %d", profile.Scores.ExposureScore)
	}
}

func TestBuild_ManagedOnlyAsset_FindingsCollectedTrue(t *testing.T) {
	g, s, corr := buildDaFixtureCorrelation(t)
	agents := []AgentRow{{AgentID: "agent-x", Hostname: "STANDALONE-BOX"}}
	findingsLookup := &fakeFindingsLookup{byAgent: map[string][]FindingSummary{
		"agent-x": {{ID: "f1", TechniqueID: "T1059", Severity: "Critical"}},
	}}
	ag, err := Build(context.Background(), g, s, corr, nil, nil, findingsLookup, agents)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	profile, ok := ag.Profile("STANDALONE-BOX")
	if !ok {
		t.Fatalf("expected a profile for STANDALONE-BOX")
	}
	if !profile.Findings.Collected || profile.Findings.OpenCount != 1 || profile.Findings.CriticalCount != 1 {
		t.Fatalf("unexpected findings context: %+v", profile.Findings)
	}
	if profile.AttackPath.Reachable {
		t.Fatalf("a host never seen in the attack-path graph should not be marked reachable: %+v", profile.AttackPath)
	}

	unmanaged, ok := ag.Profile("FILE01")
	if !ok {
		t.Fatalf("expected a profile for FILE01")
	}
	if unmanaged.Findings.Collected {
		t.Fatalf("a discovered-only asset should have Findings.Collected=false, got %+v", unmanaged.Findings)
	}
}

func TestBuild_VulnerabilityWorstCVEDominates(t *testing.T) {
	g, s, corr := buildDaFixtureCorrelation(t)
	// EdgeSMB (WS01->FILE01) maps to T1021.002.
	rels := &fakeRelLookup{byTech: map[string][]relationships.Relationship{
		"T1021.002": {
			{CVEID: "CVE-MILD", Status: relationships.StatusActive, EffectiveConfidence: relationships.ConfidenceHigh},
			{CVEID: "CVE-SEVERE", Status: relationships.StatusActive, EffectiveConfidence: relationships.ConfidenceHigh},
		},
	}}
	enricher := &fakeEnricher{meta: map[string]CVEMeta{
		"CVE-MILD":   {CVSS: 2.0},
		"CVE-SEVERE": {CVSS: 9.8, KEV: true, EPSSScore: 0.95},
	}}
	ag, err := Build(context.Background(), g, s, corr, rels, enricher, nil, nil)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	profile, ok := ag.Profile("WS01")
	if !ok {
		t.Fatalf("expected a profile for WS01")
	}
	if len(profile.Vulnerabilities) != 2 {
		t.Fatalf("expected both CVEs listed, got %+v", profile.Vulnerabilities)
	}
	if profile.Scores.VulnerabilityScore > 20 {
		t.Fatalf("worst CVE (severe) should dominate VulnerabilityScore, got %d", profile.Scores.VulnerabilityScore)
	}
}

type fakeFindingsLookup struct{ byAgent map[string][]FindingSummary }

func (f *fakeFindingsLookup) AllOpenFindings(_ context.Context) (map[string][]FindingSummary, error) {
	return f.byAgent, nil
}

// TestBuild_UncollectedAssetScoresAreNotMeasurable pins a real defect. Every
// score here is a pure-deficit model (100 - risk), so an enrolled agent with
// nothing collected -- not in the attack-path graph, no correlated detection
// edges, no CVE lookup available -- scored a flawless 100 on exposure, attack
// path, detection AND vulnerability. Those fed endpoint health, where such a
// host reported HealthScore 100 on a "higher is safer" dashboard. The scores
// still compute, but the *Measurable flags mark them as not real results.
func TestBuild_UncollectedAssetScoresAreNotMeasurable(t *testing.T) {
	g := attackpath.BuildGraph()
	var s attackpath.Summary
	corr, err := pathcorrelation.Correlate(context.Background(), g, s, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("Correlate: %v", err)
	}
	if corr.Measurable {
		t.Fatal("correlation reported measurable with no paths at all")
	}

	agents := []AgentRow{{AgentID: "agent-1", Hostname: "HOST-1"}}
	// nil rels + nil enricher => no CVE lookup is even possible.
	ag, err := Build(context.Background(), g, s, corr, nil, nil, nil, agents)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	p, ok := ag.Profile("HOST-1")
	if !ok {
		t.Fatal("expected a profile for HOST-1")
	}

	if p.Scores.ExposureMeasurable || p.Scores.AttackPathMeasurable ||
		p.Scores.DetectionMeasurable || p.Scores.VulnerabilityMeasurable {
		t.Errorf("expected every *Measurable flag false for a fully-uncollected asset, got %+v", p.Scores)
	}
	// The trap itself: without the flags these read as a perfect endpoint.
	if p.Scores.ExposureScore != 100 || p.Scores.DetectionCoverageScore != 100 {
		t.Errorf("scores = %+v, want the documented 100s the flags exist to suppress", p.Scores)
	}
}

// TestBuild_CollectedAssetIsMeasurable is the counterpart: a host that IS in
// the graph must still report measurable attack-path/detection data, so the
// fix above cannot silently blank out real results.
func TestBuild_CollectedAssetIsMeasurable(t *testing.T) {
	g, s, corr := buildDaFixtureCorrelation(t)
	ag, err := Build(context.Background(), g, s, corr, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	var anyMeasurable bool
	for _, sum := range ag.Summaries() {
		p, ok := ag.Profile(sum.Asset.HostKey)
		if !ok {
			continue
		}
		if p.Scores.AttackPathMeasurable {
			anyMeasurable = true
		}
	}
	if !anyMeasurable {
		t.Error("no asset reported AttackPathMeasurable despite a real attack-path graph")
	}
}
