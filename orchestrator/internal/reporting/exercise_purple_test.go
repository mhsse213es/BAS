package reporting

import (
	"strings"
	"testing"

	"github.com/audspect/bas/internal/exercise"
	"github.com/audspect/bas/internal/verification"
)

func rec(tech, prov, result, state string) verification.Record {
	return verification.Record{TechniqueID: tech, Provider: prov, Result: result, WorkflowState: state}
}

func TestPurpleDebrief_NothingJudgedHasNoRate(t *testing.T) {
	d := BuildPurpleDebrief([]verification.Record{rec("T1003", "sentinel", "Detected", verification.StatePending)}, exercise.TemplateMetadata{})
	if d.DetectionRate != nil {
		t.Fatalf("an unapproved verdict must not produce a rate, got %v", *d.DetectionRate)
	}
	if d.Unresolved != 1 || d.Detected != 0 || d.Techniques[0].Outcome != "unresolved" {
		t.Fatalf("got %+v", d)
	}
}

func TestPurpleDebrief_RateAndGaps(t *testing.T) {
	d := BuildPurpleDebrief([]verification.Record{
		rec("T1003", "defender", "Detected", verification.StateApproved),
		rec("T1558.003", "sentinel", "NotDetected", verification.StateApproved),
		rec("T1021", "x", "NotApplicable", verification.StateApproved),
	}, exercise.TemplateMetadata{ExpectedTechniques: []string{"T1003", "T1048"}})
	if d.DetectionRate == nil || *d.DetectionRate != 50 {
		t.Fatalf("rate: %v", d.DetectionRate)
	}
	if len(d.Gaps) != 1 || d.Gaps[0] != "T1558.003: sentinel did not detect it" {
		t.Fatalf("gaps: %v", d.Gaps)
	}
	if len(d.Techniques) != 2 {
		t.Fatalf("not-applicable must be left out: %+v", d.Techniques)
	}
	if len(d.NoExpectation) != 1 || d.NoExpectation[0] != "T1048" {
		t.Fatalf("no-expectation: %v", d.NoExpectation)
	}
}

func TestPurpleDebrief_MixedIsPartial(t *testing.T) {
	d := BuildPurpleDebrief([]verification.Record{
		rec("T1003", "a", "Detected", verification.StateApproved),
		rec("T1003", "b", "NotDetected", verification.StateApproved),
	}, exercise.TemplateMetadata{})
	if d.Techniques[0].Outcome != "partial" {
		t.Fatalf("got %s", d.Techniques[0].Outcome)
	}
}

func TestPurpleDebrief_RendersInHTMLReport(t *testing.T) {
	rep := minimalExerciseReport()
	rep.Purple = BuildPurpleDebrief([]verification.Record{
		rec("T1558.003", "sentinel", "NotDetected", verification.StateApproved),
	}, exercise.TemplateMetadata{DiscussionPrompts: []string{"Why was Kerberoasting silent?"}})
	var b strings.Builder
	if err := ExerciseReportHTML(&b, rep); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Purple-team debrief", "T1558.003", "missed", "sentinel did not detect it", "Why was Kerberoasting silent?", "0% (0 of 1)"} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("report lacks %q", want)
		}
	}
}

func TestPurpleDebrief_AbsentWhenNoRuns(t *testing.T) {
	var b strings.Builder
	if err := ExerciseReportHTML(&b, minimalExerciseReport()); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(b.String(), "Purple-team debrief") {
		t.Fatal("a report with no debrief data must not show the section")
	}
}

func minimalExerciseReport() *ExerciseReport {
	return &ExerciseReport{
		Execution: &exercise.Execution{ID: "e1", Name: "Purple drill", Status: "completed"},
		Plan:      &exercise.Plan{ID: "p1", Name: "Purple plan"},
		ChainOK:   true,
	}
}
