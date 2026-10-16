package reporting

import (
	"bytes"
	"strings"
	"testing"
)

func TestBuildAVScenarioReport_MatchesDirectEvaluation(t *testing.T) {
	rep, err := BuildAVScenarioReport("av-assessment")
	if err != nil {
		t.Fatalf("BuildAVScenarioReport: %v", err)
	}
	if rep.Outcome != "fail" {
		t.Errorf("Outcome = %q, want %q", rep.Outcome, "fail")
	}
	var sawGap bool
	for _, o := range rep.VectorOutcomes {
		if o.VectorID == "AV-PERSIST-002" && o.Finding == "confirmed_gap" {
			sawGap = true
		}
	}
	if !sawGap {
		t.Error("report VectorOutcomes missing AV-PERSIST-002 with finding confirmed_gap")
	}
	if len(rep.UntestedVectorIDs) != 2 {
		t.Errorf("UntestedVectorIDs = %v, want 2 entries", rep.UntestedVectorIDs)
	}
}

func TestBuildAVScenarioReport_UnknownSlug_ReturnsError(t *testing.T) {
	if _, err := BuildAVScenarioReport("does-not-exist"); err == nil {
		t.Fatal("want error for unknown slug, got nil")
	}
}

// Review Focus: the HTML report must surface every independent dimension
// (finding, response, telemetry, configuration) per vector, not just a
// single collapsed verdict -- so a verified prevention failure on one
// dimension can never be hidden by a clean result on another.
func TestAVScenarioReportHTML_RendersEveryDimensionAndDisclosure(t *testing.T) {
	rep, err := BuildAVScenarioReport("av-assessment")
	if err != nil {
		t.Fatalf("BuildAVScenarioReport: %v", err)
	}
	var buf bytes.Buffer
	if err := AVScenarioReportHTML(&buf, rep); err != nil {
		t.Fatalf("AVScenarioReportHTML: %v", err)
	}
	body := buf.String()
	for _, want := range []string{"AV-PERSIST-002", "confirmed_gap", "Finding:", "Response:", "Telemetry:", "Configuration:", "Detection latency:", "fixture-validated"} {
		if !strings.Contains(body, want) {
			t.Errorf("HTML body missing %q", want)
		}
	}
}
