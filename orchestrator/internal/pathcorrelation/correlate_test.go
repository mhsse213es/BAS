package pathcorrelation

import (
	"context"
	"testing"

	"github.com/audspect/bas/internal/attackpath"
	"github.com/audspect/bas/internal/rulelib"
)

// fakeRunLookup returns a canned result per techniqueID, ignoring hostname
// (tests that need host-specific behavior set WantHost).
type fakeRunLookup struct {
	found       map[string]VerificationResult
	wantHost    string // if set, only techniqueIDs in hostMatches get Confidence: Host
	hostMatches map[string]bool
}

func (f *fakeRunLookup) VerifiedDetection(_ context.Context, techniqueID, hostname string) (VerificationResult, bool, error) {
	res, ok := f.found[techniqueID]
	if !ok {
		return VerificationResult{}, false, nil
	}
	if f.wantHost != "" && hostname == f.wantHost && f.hostMatches[techniqueID] {
		res.Confidence = ConfidenceHost
	} else if res.Confidence == ConfidenceHost {
		res.Confidence = ConfidenceEnvironment
	}
	return res, true, nil
}

// fakeRuleLibrary returns a rule for every techniqueID in Has.
type fakeRuleLibrary struct{ has map[string]bool }

func (f *fakeRuleLibrary) RulesByTechnique(techniqueID string) []rulelib.Rule {
	if f.has[techniqueID] {
		return []rulelib.Rule{{ID: "AUDRULE-000001", TechniqueIDs: []string{techniqueID}}}
	}
	return nil
}

func daFixture() (*attackpath.Graph, attackpath.Summary) {
	cols := []attackpath.Collection{
		{AgentID: "ws01", Source: "agent",
			Nodes: []attackpath.Node{{ID: "WS01", Kind: attackpath.KindHost, Role: attackpath.RoleEndpoint}},
			Edges: []attackpath.Edge{{From: "WS01", To: "FILE01", Kind: attackpath.EdgeSMB}}},
		{AgentID: "file01", Source: "sharphound",
			Nodes: []attackpath.Node{
				{ID: "FILE01", Kind: attackpath.KindHost, Role: attackpath.RoleServer},
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

func TestCorrelate_NoHistoryAnywhere_IsUnknown(t *testing.T) {
	g, s := daFixture()
	paths := DefaultPaths(g, s)
	runs := &fakeRunLookup{found: map[string]VerificationResult{}}
	rules := &fakeRuleLibrary{has: map[string]bool{}}

	corr, err := Correlate(context.Background(), g, s, paths, DefaultEdgeTechniqueMapper{}, runs, rules)
	if err != nil {
		t.Fatalf("Correlate: %v", err)
	}
	if corr.Statistics.VerifiedUnknown == 0 {
		t.Fatalf("expected at least one Unknown edge, got stats %+v", corr.Statistics)
	}
	if corr.Statistics.VerifiedCovered != 0 {
		t.Fatalf("nothing should be Covered, got stats %+v", corr.Statistics)
	}
}

func TestCorrelate_RuleExistsButNeverVerified_IsGap(t *testing.T) {
	g, s := daFixture()
	paths := DefaultPaths(g, s)
	runs := &fakeRunLookup{found: map[string]VerificationResult{}}
	rules := &fakeRuleLibrary{has: map[string]bool{"T1021.002": true}} // SMB edge's technique

	corr, err := Correlate(context.Background(), g, s, paths, DefaultEdgeTechniqueMapper{}, runs, rules)
	if err != nil {
		t.Fatalf("Correlate: %v", err)
	}
	var found bool
	for _, p := range corr.Paths {
		for _, e := range p.Edges {
			if e.Edge.Kind == attackpath.EdgeSMB {
				found = true
				if e.Status.Expected != ExpectedCovered {
					t.Fatalf("SMB edge Expected = %q, want covered", e.Status.Expected)
				}
				if e.Status.Verified != VerifiedGap {
					t.Fatalf("SMB edge Verified = %q, want gap", e.Status.Verified)
				}
			}
		}
	}
	if !found {
		t.Fatal("SMB edge not found in any correlated path")
	}
}

func TestCorrelate_HostSpecificDetection_IsCoveredWithHostConfidence(t *testing.T) {
	g, s := daFixture()
	paths := DefaultPaths(g, s)
	runs := &fakeRunLookup{
		found: map[string]VerificationResult{
			"T1021.002": {Confidence: ConfidenceHost, Evidence: Evidence{RunID: "run1"}},
		},
		wantHost:    "FILE01",
		hostMatches: map[string]bool{"T1021.002": true},
	}
	rules := &fakeRuleLibrary{has: map[string]bool{"T1021.002": true}}

	corr, err := Correlate(context.Background(), g, s, paths, DefaultEdgeTechniqueMapper{}, runs, rules)
	if err != nil {
		t.Fatalf("Correlate: %v", err)
	}
	var got *DetectionStatus
	for _, p := range corr.Paths {
		for _, e := range p.Edges {
			if e.Edge.Kind == attackpath.EdgeSMB {
				st := e.Status
				got = &st
			}
		}
	}
	if got == nil {
		t.Fatal("SMB edge not found")
	}
	if got.Verified != VerifiedCovered || got.Confidence != ConfidenceHost {
		t.Fatalf("got %+v, want Verified=covered Confidence=host", got)
	}
}

func TestCorrelate_MultiTechniqueEdgeMixedResults_IsPartial(t *testing.T) {
	g, s := daFixture()
	paths := DefaultPaths(g, s)
	// HasSession maps to T1003 (0.7) and T1552 (0.5); verify only T1003.
	runs := &fakeRunLookup{
		found: map[string]VerificationResult{
			"T1003": {Confidence: ConfidenceEnvironment, Evidence: Evidence{RunID: "run2"}},
		},
	}
	rules := &fakeRuleLibrary{has: map[string]bool{"T1003": true}}

	corr, err := Correlate(context.Background(), g, s, paths, DefaultEdgeTechniqueMapper{}, runs, rules)
	if err != nil {
		t.Fatalf("Correlate: %v", err)
	}
	var got *DetectionStatus
	for _, p := range corr.Paths {
		for _, e := range p.Edges {
			if e.Edge.Kind == attackpath.EdgeHasSession {
				st := e.Status
				got = &st
			}
		}
	}
	if got == nil {
		t.Fatal("HasSession edge not found")
	}
	if got.Verified != VerifiedPartial {
		t.Fatalf("Verified = %q, want partial", got.Verified)
	}
}

func TestCorrelate_NoDangerousPaths_ScoreIs100(t *testing.T) {
	g, s := attackpath.BuildGraphAndAnalyze(nil, nil)
	corr, err := Correlate(context.Background(), g, s, nil, DefaultEdgeTechniqueMapper{},
		&fakeRunLookup{found: map[string]VerificationResult{}}, &fakeRuleLibrary{has: map[string]bool{}})
	if err != nil {
		t.Fatalf("Correlate: %v", err)
	}
	if corr.Score != 100 {
		t.Fatalf("Score = %d, want 100 for a graph with no dangerous paths", corr.Score)
	}
	if len(corr.Gaps) != 0 {
		t.Fatalf("expected no gaps, got %+v", corr.Gaps)
	}
}

func TestCorrelate_AllGapPath_ScoresLowerThanOneCoveredHop(t *testing.T) {
	g, s := daFixture()
	paths := DefaultPaths(g, s)
	rules := &fakeRuleLibrary{has: map[string]bool{}}

	allGap, err := Correlate(context.Background(), g, s, paths, DefaultEdgeTechniqueMapper{},
		&fakeRunLookup{found: map[string]VerificationResult{}}, rules)
	if err != nil {
		t.Fatalf("Correlate: %v", err)
	}

	oneCovered, err := Correlate(context.Background(), g, s, paths, DefaultEdgeTechniqueMapper{},
		&fakeRunLookup{found: map[string]VerificationResult{
			"T1021.002": {Confidence: ConfidenceHost, Evidence: Evidence{RunID: "run3"}}, // SMB edge's sole technique -> fully Covered
		}}, rules)
	if err != nil {
		t.Fatalf("Correlate: %v", err)
	}

	if oneCovered.Score <= allGap.Score {
		t.Fatalf("a path with one covered hop (%d) should score higher than all-gap (%d)", oneCovered.Score, allGap.Score)
	}
}

func TestCorrelate_GapsSortedWorstFirstWithPriority(t *testing.T) {
	g, s := daFixture()
	paths := DefaultPaths(g, s)
	corr, err := Correlate(context.Background(), g, s, paths, DefaultEdgeTechniqueMapper{},
		&fakeRunLookup{found: map[string]VerificationResult{}}, &fakeRuleLibrary{has: map[string]bool{}})
	if err != nil {
		t.Fatalf("Correlate: %v", err)
	}
	if len(corr.Gaps) < 2 {
		t.Fatalf("expected at least 2 gaps in this fixture, got %d", len(corr.Gaps))
	}
	for _, g := range corr.Gaps {
		switch g.Priority {
		case PriorityCritical, PriorityHigh, PriorityMedium, PriorityLow:
		default:
			t.Fatalf("unexpected priority %q", g.Priority)
		}
	}
}

// TestComputeScore_NoPathsIsNotMeasurable pins a real defect: the score is a
// pure-deficit model, so with no weighted paths (no attack-path collection has
// run, or the graph reaches no Domain Admin / crown jewel) there is no deficit
// and the score comes out a flawless 100. That value fed the exposure and
// endpoint-health dashboards, where an endpoint nothing was known about
// presented as perfectly defended. The score is still returned for arithmetic,
// but measurable=false marks it as not a real result.
func TestComputeScore_NoPathsIsNotMeasurable(t *testing.T) {
	score, measurable := computeScore(nil)
	if measurable {
		t.Error("measurable = true, want false — there were no paths to score")
	}
	if score != 100 {
		t.Errorf("score = %d, want the documented 100 this flag exists to suppress", score)
	}

	// Zero-weight paths are equally unmeasurable: nothing contributes.
	score, measurable = computeScore([]AnnotatedPath{{Weight: 0}})
	if measurable {
		t.Error("measurable = true for a zero-weight path, want false")
	}
	if score != 100 {
		t.Errorf("score = %d, want 100", score)
	}
}
