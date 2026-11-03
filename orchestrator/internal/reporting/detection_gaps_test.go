package reporting

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/audspect/bas/internal/models"
	"github.com/audspect/bas/internal/rulelib"
	"github.com/audspect/bas/internal/verification"
)

type fakeRules map[string][]rulelib.Rule

func (f fakeRules) RulesByTechnique(id string) []rulelib.Rule { return f[id] }

func gapRes(tech string, r models.CheckResult) models.SimulationResult {
	return models.SimulationResult{Technique: models.AttackTechnique{ID: tech, Name: "Name " + tech}, Result: r}
}

func gapRule(id, sev string) rulelib.Rule {
	return rulelib.Rule{
		ID: id, Title: "Rule " + id, Severity: sev,
		Source: rulelib.Source{Name: "SigmaHQ", Commit: "0e3b749e", License: "DRL 1.1", Path: "rules/windows/x.yml"},
		Translations: []rulelib.Translation{
			{Backend: "splunk", Language: "SPL", Query: "EventCode=1 Image=\"*\\x.exe\"", Mapping: "pipeline", DataSource: "Sysmon event 1"},
			{Backend: "qradar", Language: "AQL", Query: "SELECT * FROM events", Mapping: "generic"},
		},
	}
}

func notDetected(tech string) map[string]verification.Record {
	return map[string]verification.Record{"e1": {TechniqueID: tech, Result: verification.ResultNotDetected, WorkflowState: verification.StateApproved}}
}

func TestBuildDetectionGaps_OnlyRealGapsGetRecommendationsAndEverythingIsLabelled(t *testing.T) {
	results := []models.SimulationResult{
		gapRes("T1059.001", models.ResultFail), gapRes("T1003", models.ResultFail), gapRes("T1070", models.ResultFail),
	}
	rules := fakeRules{"T1059.001": {gapRule("AUDRULE-000002", "low"), gapRule("AUDRULE-000001", "high")}}
	sec := BuildDetectionGaps(results, notDetected("T1059.001"), rules)

	if !sec.HasData || sec.Gaps != 1 || sec.Assessed != 3 {
		t.Fatalf("section = %+v, want data, 1 gap of 3 assessed", sec)
	}
	if len(sec.Rows) != 1 || sec.Rows[0].TechniqueID != "T1059.001" {
		t.Fatalf("rows = %+v, want only the gap", sec.Rows)
	}
	row := sec.Rows[0]
	if row.Availability != "Rule available" || row.Effectiveness != "Not validated" {
		t.Errorf("availability/effectiveness = %q/%q", row.Availability, row.Effectiveness)
	}
	if len(row.Rules) != 1 || row.Rules[0].ID != "AUDRULE-000001" {
		t.Fatalf("want the single highest-severity rule, got %+v", row.Rules)
	}
	q := row.Rules[0].Queries
	if len(q) != 2 || q[0].Backend != "IBM QRadar" && q[1].Backend != "IBM QRadar" {
		t.Fatalf("queries = %+v", q)
	}
	for _, x := range q {
		if x.Note == "" {
			t.Errorf("%s query has no mapped/generic note", x.Backend)
		}
	}
	if sec.Attribution == "" || !strings.Contains(sec.Attribution, "SigmaHQ") {
		t.Errorf("attribution = %q", sec.Attribution)
	}
}

func TestBuildDetectionGaps_NoLibraryOrNoGapsMeansNoSection(t *testing.T) {
	results := []models.SimulationResult{gapRes("T1059.001", models.ResultFail)}
	if sec := BuildDetectionGaps(results, nil, fakeRules{}); sec.HasData {
		t.Errorf("unverified run must not produce a gap section: %+v", sec)
	}
	if sec := BuildDetectionGaps(nil, nil, nil); sec.HasData {
		t.Errorf("empty run: %+v", sec)
	}
}

func TestBuildDetectionGaps_AGapWithNoRuleSaysSoAndInventsNothing(t *testing.T) {
	sec := BuildDetectionGaps([]models.SimulationResult{gapRes("T1003", models.ResultFail)}, notDetected("T1003"), fakeRules{})
	if !sec.HasData || len(sec.Rows) != 1 {
		t.Fatalf("%+v", sec)
	}
	if sec.Rows[0].Availability != "No rule available" || len(sec.Rows[0].Rules) != 0 {
		t.Errorf("row = %+v", sec.Rows[0])
	}
}

func TestBuildDetectionGaps_LongQueriesAreTruncatedHonestly(t *testing.T) {
	r := gapRule("AUDRULE-000001", "high")
	r.Translations[0].Query = strings.Repeat("a", 5000)
	sec := BuildDetectionGaps([]models.SimulationResult{gapRes("T1059.001", models.ResultFail)}, notDetected("T1059.001"), fakeRules{"T1059.001": {r}})
	for _, q := range sec.Rows[0].Rules[0].Queries {
		if q.Backend == "Splunk" && (!q.Truncated || len(q.Query) > 1500) {
			t.Errorf("splunk query not truncated: truncated=%v len=%d", q.Truncated, len(q.Query))
		}
	}
}

func TestGenerateHTML_DetectionGapSection(t *testing.T) {
	sec := BuildDetectionGaps([]models.SimulationResult{gapRes("T1059.001", models.ResultFail)}, notDetected("T1059.001"),
		fakeRules{"T1059.001": {gapRule("AUDRULE-000001", "high")}})
	rep := &FullReport{GeneratedAt: time.Now().UTC(), DetectionGaps: sec}
	var buf bytes.Buffer
	if err := GenerateHTML(&buf, rep, nil); err != nil {
		t.Fatal(err)
	}
	html := buf.String()
	for _, want := range []string{"Detection Engineering Recommendations", "T1059.001", "AUDRULE-000001", "Not validated",
		"Sysmon event 1", "adapt the field names", "SigmaHQ", "DRL"} {
		if !strings.Contains(html, want) {
			t.Errorf("report missing %q", want)
		}
	}
	var none bytes.Buffer
	if err := GenerateHTML(&none, &FullReport{GeneratedAt: time.Now().UTC()}, nil); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(none.String(), "Detection Engineering Recommendations") {
		t.Error("section must be absent when the run has no gaps")
	}
}
