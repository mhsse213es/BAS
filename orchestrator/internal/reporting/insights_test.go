package reporting

import (
	"testing"

	"github.com/audspect/bas/internal/models"
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
