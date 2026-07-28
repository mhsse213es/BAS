package reporting

import (
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/models"
	"github.com/audspect/bas/internal/reporting/attackdata"
)

func res(id, tactic, sev string, result models.CheckResult, events []string) models.SimulationResult {
	return models.SimulationResult{
		Technique: models.AttackTechnique{ID: id, Name: id, Tactic: tactic},
		Severity:  sev,
		Result:    result,
		Events:    events,
	}
}

func TestExposureLevel(t *testing.T) {
	cases := []struct {
		score float64
		want  string
	}{{95, "Low"}, {80, "Low"}, {70, "Medium"}, {50, "High"}, {39, "Critical"}, {0, "Critical"}}
	for _, c := range cases {
		if got := exposureLevel(c.score); got != c.want {
			t.Errorf("exposureLevel(%.0f)=%q want %q", c.score, got, c.want)
		}
	}
}

func TestDetectionScoreNAWhenNoTelemetry(t *testing.T) {
	// 4 unprevented, none detected, no telemetry observed → not measurable.
	d := DetectionSummary{ExecutedUnprevented: 4, Detected: 0, TelemetryObserved: false}
	if _, measured := detectionScore(d); measured {
		t.Fatal("detection must be unmeasurable when no telemetry observed")
	}
	// With telemetry: 1 of 4 detected → 25%, measured.
	d = DetectionSummary{ExecutedUnprevented: 4, Detected: 1, TelemetryObserved: true}
	score, measured := detectionScore(d)
	if !measured || score != 25 {
		t.Fatalf("detectionScore=%.0f measured=%v want 25 true", score, measured)
	}
	// Nothing executed unprevented → nothing to detect → not measurable.
	d = DetectionSummary{ExecutedUnprevented: 0, TelemetryObserved: true}
	if _, measured := detectionScore(d); measured {
		t.Fatal("detection must be unmeasurable when nothing executed unprevented")
	}
}

// TestScoreImpactMatchesPreventionScore proves the action-plan/top-driver
// attribution sums to exactly the prevention-score deficit (100 − score),
// using the same severity weighting as models.ComputeScore.
func TestScoreImpactMatchesPreventionScore(t *testing.T) {
	results := []models.SimulationResult{
		res("T1003", "credential-access", "Critical", models.ResultFail, nil), // weight 4
		res("T1055", "defense-evasion", "High", models.ResultFail, nil),       // weight 3
		res("T1059", "execution", "High", models.ResultPass, nil),             // weight 3
		res("T1082", "discovery", "Low", models.ResultPass, nil),              // weight 1
		res("T1190", "initial-access", "Medium", models.ResultError, nil),     // excluded
	}
	score := models.ComputeScore(results, nil)
	deficit := 100 - score.PreventionScore

	plan := buildActionPlan(results)
	var planSum float64
	for _, a := range plan {
		planSum += a.ScorePoints
	}
	if d := planSum - deficit; d > 0.2 || d < -0.2 {
		t.Errorf("action-plan points %.2f != prevention deficit %.2f", planSum, deficit)
	}

	drivers := buildTopRiskDrivers(results, 8)
	var drvSum float64
	for _, r := range drivers {
		drvSum += r.ScorePoints
	}
	if d := drvSum - deficit; d > 0.2 || d < -0.2 {
		t.Errorf("top-driver points %.2f != prevention deficit %.2f", drvSum, deficit)
	}
	// Highest-impact driver must be the Critical credential-access failure.
	if len(drivers) == 0 || drivers[0].TechniqueID != "T1003" {
		t.Errorf("expected T1003 as top risk driver, got %+v", drivers)
	}
}

func TestInsightsMostLeastProtected(t *testing.T) {
	heatmap := []TacticEntry{
		{Tactic: "credential-access", Total: 5, PassPct: 20},
		{Tactic: "privilege-escalation", Total: 4, PassPct: 90},
		{Tactic: "execution", Total: 0, PassPct: 0}, // untested — ignored
	}
	ins := buildInsights(heatmap, DetectionSummary{TelemetryObserved: true})
	if !ins.HasData || ins.Least == nil || ins.Most == nil {
		t.Fatal("expected insights with most/least")
	}
	if ins.Least.Tactic != "credential-access" {
		t.Errorf("least=%s want credential-access", ins.Least.Tactic)
	}
	if ins.Most.Tactic != "privilege-escalation" {
		t.Errorf("most=%s want privilege-escalation", ins.Most.Tactic)
	}
}

func TestReliabilityConfidence(t *testing.T) {
	// 107 errored of 165 attempted ⇒ Low confidence (Caldera-style).
	s := ExecutiveSummary{PassedTechniques: 30, FailedTechniques: 28, ErroredTechniques: 107}
	if r := buildReliability(s); r.Confidence != "Low" || r.Valid != 58 || r.Attempted != 165 {
		t.Errorf("reliability=%+v want Low/58/165", r)
	}
	// Clean run ⇒ High.
	s = ExecutiveSummary{PassedTechniques: 40, FailedTechniques: 10, ErroredTechniques: 2}
	if r := buildReliability(s); r.Confidence != "High" {
		t.Errorf("confidence=%s want High", r.Confidence)
	}
}

// ComputePriorityScore's documented weights: KEV +40; EPSS percentile
// tiers 90/70/50/30 → +30/+20/+10/+5; threat-actor tiers 5/2/1 → +20/+10/+5;
// verdict=="fail" bonus +10; clamped at 100.
func TestComputePriorityScore(t *testing.T) {
	cases := []struct {
		name           string
		kev            bool
		epssPercentile float64
		actors         int
		verdict        string
		want           int
	}{
		{"no signals", false, 0, 0, "pass", 0},
		{"kev only", true, 0, 0, "pass", 40},
		{"epss tier 90", false, 90, 0, "pass", 30},
		{"epss tier 70", false, 70, 0, "pass", 20},
		{"epss tier 50", false, 50, 0, "pass", 10},
		{"epss tier 30", false, 30, 0, "pass", 5},
		{"epss below 30", false, 29, 0, "pass", 0},
		{"actors tier 5", false, 0, 5, "pass", 20},
		{"actors tier 2", false, 0, 2, "pass", 10},
		{"actors tier 1", false, 0, 1, "pass", 5},
		{"actors 0", false, 0, 0, "pass", 0},
		{"fail bonus", false, 0, 0, "fail", 10},
		{"fail bonus does not apply to pass/blocked", false, 0, 0, "blocked", 0},
		{"everything maxes and clamps at 100", true, 95, 6, "fail", 100},
		{"kev+epss70+actors2, no fail bonus", true, 70, 2, "pass", 70}, // 40+20+10
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := ComputePriorityScore(c.kev, c.epssPercentile, c.actors, c.verdict, false); got != c.want {
				t.Errorf("ComputePriorityScore(kev=%v, epss=%.0f, actors=%d, verdict=%q, sectorRegionRelevant=false) = %d, want %d",
					c.kev, c.epssPercentile, c.actors, c.verdict, got, c.want)
			}
		})
	}
}

func TestComputePriorityScore_SectorRegionRelevant(t *testing.T) {
	if got := ComputePriorityScore(false, 0, 0, "pass", true); got != 10 {
		t.Errorf("sectorRegionRelevant alone = %d, want 10", got)
	}
	if got := ComputePriorityScore(true, 95, 6, "fail", true); got != 100 {
		t.Errorf("everything maxed + sectorRegionRelevant = %d, want 100 (clamped)", got)
	}
	if got := ComputePriorityScore(false, 0, 0, "pass", false); got != 0 {
		t.Errorf("sectorRegionRelevant=false with no other signals = %d, want 0", got)
	}
}

func TestResolveActorTechniques_ExactMatch(t *testing.T) {
	groupIdx := attackdata.GroupTechniqueIndex()
	if len(groupIdx) == 0 {
		t.Skip("no embedded ATT&CK group data available")
	}
	var knownGroup string
	for g := range groupIdx {
		knownGroup = g
		break
	}

	ids, group, ok := ResolveActorTechniques(knownGroup, nil)
	if !ok {
		t.Fatalf("expected a match for %q", knownGroup)
	}
	if group != knownGroup {
		t.Fatalf("canonicalGroup = %q, want %q", group, knownGroup)
	}
	if len(ids) == 0 {
		t.Fatal("expected at least one technique ID")
	}
}

func TestResolveActorTechniques_AliasMatch(t *testing.T) {
	groupIdx := attackdata.GroupTechniqueIndex()
	if len(groupIdx) == 0 {
		t.Skip("no embedded ATT&CK group data available")
	}
	var knownGroup string
	for g := range groupIdx {
		knownGroup = g
		break
	}

	// Pass a name that can't match directly, with the real canonical group
	// name as an alias -- exercises the alias branch specifically without
	// depending on real-world alias data being present in the bundle.
	ids, group, ok := ResolveActorTechniques("Definitely Not A Canonical Name", []string{knownGroup})
	if !ok {
		t.Fatalf("expected an alias match via %q", knownGroup)
	}
	if group != knownGroup {
		t.Fatalf("canonicalGroup = %q, want %q", group, knownGroup)
	}
	if len(ids) == 0 {
		t.Fatal("expected at least one technique ID")
	}
}

func TestResolveActorTechniques_NoMatch(t *testing.T) {
	_, _, ok := ResolveActorTechniques("Definitely Not A Real Group Name XYZ", nil)
	if ok {
		t.Fatal("expected no match")
	}
}

func TestSectorRegionRelevantTechniques_EmptyInputsSkipQuery(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		relevant, err := SectorRegionRelevantTechniques(t.Context(), pool, nil, nil)
		if err != nil {
			t.Fatalf("SectorRegionRelevantTechniques: %v", err)
		}
		if len(relevant) != 0 {
			t.Errorf("expected an empty map when sectors/regions are both empty, got %v", relevant)
		}
	})
}

func TestSectorRegionRelevantTechniques_MatchesByNameAndAlias(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		groupIdx := attackdata.GroupTechniqueIndex()
		if len(groupIdx) == 0 {
			t.Skip("no embedded ATT&CK group data available")
		}
		var knownGroup string
		for g := range groupIdx {
			knownGroup = g
			break
		}

		_, err := pool.Exec(t.Context(),
			`INSERT INTO threat_actor_profiles (name, aliases, sectors, regions, source)
			 VALUES ($1, '{}', $2, $3, 'bundle')`,
			knownGroup, []string{"government"}, []string{"south-asia"})
		if err != nil {
			t.Fatalf("seed: %v", err)
		}

		relevant, err := SectorRegionRelevantTechniques(t.Context(), pool, []string{"government"}, nil)
		if err != nil {
			t.Fatalf("SectorRegionRelevantTechniques: %v", err)
		}
		for _, tid := range groupIdx[knownGroup] {
			if !relevant[strings.ToUpper(tid)] {
				t.Errorf("expected technique %s (under group %q) to be marked relevant", tid, knownGroup)
			}
		}
	})
}

func TestPriorityTierFor(t *testing.T) {
	cases := []struct {
		score int
		want  string
	}{
		{100, "Critical"}, {70, "Critical"}, {69, "High"}, {40, "High"},
		{39, "Medium"}, {20, "Medium"}, {19, "Low"}, {0, "Low"},
	}
	for _, c := range cases {
		if got := PriorityTierFor(c.score); got != c.want {
			t.Errorf("PriorityTierFor(%d) = %q, want %q", c.score, got, c.want)
		}
	}
}

func TestBuildReadinessScores_EmptyMatrixReturnsNil(t *testing.T) {
	if got := BuildReadinessScores(nil); got != nil {
		t.Errorf("BuildReadinessScores(nil) = %+v, want nil", got)
	}
	if got := BuildReadinessScores([]TechniqueRow{}); got != nil {
		t.Errorf("BuildReadinessScores(empty) = %+v, want nil", got)
	}
}

// TestBuildReadinessScores_ExcludesGroupsUnderThreeTestedTechniques pins the
// documented "fewer than 3 tested techniques is too few data points" rule,
// using Wizard Spider's real technique attribution from the bundled STIX
// data (the same group internal/api's ti_suggest_pack_test.go relies on).
func TestBuildReadinessScores_ExcludesGroupsUnderThreeTestedTechniques(t *testing.T) {
	techs := attackdata.GroupTechniqueIndex()["Wizard Spider"]
	if len(techs) < 3 {
		t.Fatal("test fixture assumption broken: Wizard Spider has fewer than 3 known techniques in the bundled data")
	}
	matrix := []TechniqueRow{
		{TechniqueID: techs[0], ExecVerdict: "pass"},
		{TechniqueID: techs[1], ExecVerdict: "fail"},
	}
	for _, s := range BuildReadinessScores(matrix) {
		if s.GroupName == "Wizard Spider" {
			t.Fatalf("expected Wizard Spider excluded with only 2 tested techniques, got %+v", s)
		}
	}
}

// TestBuildReadinessScores_ComputesCountsAndBands pins the actual counting
// and banding math against a real group, using techniques whose IDs come
// from the bundled data (so the group lookup succeeds) but whose PASS/FAIL/
// detection outcome is entirely controlled by this test's own matrix.
func TestBuildReadinessScores_ComputesCountsAndBands(t *testing.T) {
	techs := attackdata.GroupTechniqueIndex()["Wizard Spider"]
	if len(techs) < 3 {
		t.Fatal("test fixture assumption broken: Wizard Spider has fewer than 3 known techniques in the bundled data")
	}
	matrix := []TechniqueRow{
		{TechniqueID: techs[0], ExecVerdict: "pass"},                               // prevented
		{TechniqueID: techs[1], ExecVerdict: "fail", DetectionVerdict: "detected"}, // detected
		{TechniqueID: techs[2], ExecVerdict: "fail"},                               // allowed
	}
	var got *ReadinessScore
	for _, s := range BuildReadinessScores(matrix) {
		if s.GroupName == "Wizard Spider" {
			s := s
			got = &s
		}
	}
	if got == nil {
		t.Fatal("expected a Wizard Spider entry with 3 tested techniques")
	}
	if got.TestedTechs != 3 || got.PreventedTechs != 1 || got.DetectedTechs != 1 || got.AllowedTechs != 1 {
		t.Fatalf("counts = %+v, want tested=3 prevented=1 detected=1 allowed=1", got)
	}
	// prevPct = 1/3*100 ≈ 33.3 → below 50 → Low band.
	if got.ReadinessBand != "Low" {
		t.Errorf("readinessBand = %q, want Low (prevention ~33%%)", got.ReadinessBand)
	}
	// detPct = (1+1)/3*100 ≈ 66.7.
	if got.DetectionReadiness < 66.6 || got.DetectionReadiness > 66.7 {
		t.Errorf("detectionReadiness = %.4f, want ~66.67", got.DetectionReadiness)
	}
	// tested=3 < 5 → Low confidence band.
	if got.ConfidenceBand != "Low" {
		t.Errorf("confidenceBand = %q, want Low (tested=3)", got.ConfidenceBand)
	}
}

// TestBuildReadinessScores_HighReadinessBand pins the >=80% prevention →
// High band boundary using an all-prevented matrix for a real group.
func TestBuildReadinessScores_HighReadinessBand(t *testing.T) {
	techs := attackdata.GroupTechniqueIndex()["Wizard Spider"]
	if len(techs) < 3 {
		t.Fatal("test fixture assumption broken: Wizard Spider has fewer than 3 known techniques in the bundled data")
	}
	matrix := make([]TechniqueRow, 0, 3)
	for _, tid := range techs[:3] {
		matrix = append(matrix, TechniqueRow{TechniqueID: tid, ExecVerdict: "pass"})
	}
	for _, s := range BuildReadinessScores(matrix) {
		if s.GroupName == "Wizard Spider" {
			if s.ReadinessBand != "High" {
				t.Errorf("readinessBand = %q, want High (100%% prevention)", s.ReadinessBand)
			}
			return
		}
	}
	t.Fatal("expected a Wizard Spider entry")
}

// TestBuildReadinessScores_SortedWorstPreventionFirst pins the general sort
// contract (worst prevention readiness first) against the real, full bundled
// dataset rather than a hand-picked pair of groups — every technique across
// every group gets a deterministic verdict so whichever groups clear the
// 3-tested-techniques threshold are exercised.
func TestBuildReadinessScores_SortedWorstPreventionFirst(t *testing.T) {
	idx := attackdata.GroupTechniqueIndex()
	seen := map[string]bool{}
	var matrix []TechniqueRow
	i := 0
	for _, techs := range idx {
		for _, tid := range techs {
			if seen[tid] {
				continue
			}
			seen[tid] = true
			verdict := "pass"
			if i%3 != 0 { // 1/3 pass, 2/3 fail — enough spread to produce varied readiness bands
				verdict = "fail"
			}
			matrix = append(matrix, TechniqueRow{TechniqueID: tid, ExecVerdict: verdict})
			i++
		}
	}
	scores := BuildReadinessScores(matrix)
	if len(scores) < 2 {
		t.Fatal("expected at least 2 qualifying groups from the full bundled dataset")
	}
	for i := 1; i < len(scores); i++ {
		if scores[i-1].PreventionReadiness > scores[i].PreventionReadiness {
			t.Fatalf("scores not sorted worst-first at index %d: %+v then %+v", i, scores[i-1], scores[i])
		}
	}
}

func TestBuildExecutiveConclusion_PolicySkipSentence(t *testing.T) {
	s := ExecutiveSummary{PassedTechniques: 20, FailedTechniques: 6, PreventionScore: 76.9}
	withPolicy := buildExecutiveConclusion(s, Insights{}, DetectionSummary{}, nil, SkipBreakdown{Policy: 14})
	if !strings.Contains(withPolicy, "14 techniques requiring administrative privileges were intentionally excluded") {
		t.Errorf("conclusion = %q, want a policy-skip sentence naming 14", withPolicy)
	}

	withoutPolicy := buildExecutiveConclusion(s, Insights{}, DetectionSummary{}, nil, SkipBreakdown{Content: 3, Platform: 2})
	if strings.Contains(withoutPolicy, "intentionally excluded") {
		t.Errorf("conclusion = %q, want no policy sentence when Policy=0 (Content/Platform skips get no narrative)", withoutPolicy)
	}
}
