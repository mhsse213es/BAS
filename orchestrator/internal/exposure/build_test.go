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
	if profile.Scores.ExposureScore >= 50 {
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
