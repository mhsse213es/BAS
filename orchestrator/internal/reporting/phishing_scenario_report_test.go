package reporting

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/audspect/bas/internal/phishcatalog"
	"github.com/audspect/bas/internal/phishingrun"
	"github.com/audspect/bas/internal/phishval"
)

func TestBuildPhishingScenarioReport_InferredEvidence_FlagsExperimental(t *testing.T) {
	outcome := phishval.Outcome{Response: phishval.DimensionResult{Verdict: phishval.VerdictNotTested, Evidence: phishval.EvidenceInferred}}
	resultJSON, _ := json.Marshal(outcome)
	run := &phishingrun.PhishingRun{ID: "run-1", ScenarioID: "PH-ID-004", Result: resultJSON, Status: phishingrun.StatusCompleted}
	rep, err := BuildPhishingScenarioReport(run, phishcatalog.Scenario{ID: "PH-ID-004", Coverage: phishcatalog.CoverageAdapterTested})
	if err != nil {
		t.Fatalf("BuildPhishingScenarioReport: %v", err)
	}
	if !rep.Experimental {
		t.Error("Experimental = false, want true for a dimension carrying EvidenceInferred")
	}
}

func TestBuildPhishingScenarioReport_VerifiedTelemetry_NotExperimental(t *testing.T) {
	outcome := phishval.Outcome{Response: phishval.DimensionResult{Verdict: phishval.VerdictPass, Evidence: phishval.EvidenceVerifiedTelemetry}}
	resultJSON, _ := json.Marshal(outcome)
	run := &phishingrun.PhishingRun{ID: "run-1", ScenarioID: "PH-DET-002", Result: resultJSON, Status: phishingrun.StatusCompleted}
	rep, err := BuildPhishingScenarioReport(run, phishcatalog.Scenario{ID: "PH-DET-002", Coverage: phishcatalog.CoverageFixtureTested})
	if err != nil {
		t.Fatalf("BuildPhishingScenarioReport: %v", err)
	}
	if rep.Experimental {
		t.Error("Experimental = true, want false for ordinary verified/fixture evidence")
	}
}

// TestBuildPhishingScenarioReport_OnlyNonNotApplicableDimensionsIncluded
// proves Dimensions never pads the report with the four other
// phishval.Outcome dimension fields PH-DET-002 never populates
// (Delivery/Enforcement/Detection/UserInteraction stay their zero
// value, Verdict == "" since json.Unmarshal leaves them unset -- the
// builder must treat that as "not applicable to this run", not render
// four empty rows).
func TestBuildPhishingScenarioReport_OnlyNonNotApplicableDimensionsIncluded(t *testing.T) {
	outcome := phishval.Outcome{Response: phishval.DimensionResult{Verdict: phishval.VerdictPass, Evidence: phishval.EvidenceVerifiedTelemetry, Confidence: phishval.ConfidenceHigh, Reason: "ticket created"}}
	resultJSON, _ := json.Marshal(outcome)
	run := &phishingrun.PhishingRun{ID: "run-1", ScenarioID: "PH-DET-002", Result: resultJSON, Status: phishingrun.StatusCompleted}
	rep, err := BuildPhishingScenarioReport(run, phishcatalog.Scenario{ID: "PH-DET-002", Coverage: phishcatalog.CoverageFixtureTested})
	if err != nil {
		t.Fatalf("BuildPhishingScenarioReport: %v", err)
	}
	if len(rep.Dimensions) != 1 {
		t.Fatalf("len(Dimensions) = %d, want 1 (only Response was populated)", len(rep.Dimensions))
	}
	if rep.Dimensions[0].Name != "Response" || rep.Dimensions[0].Verdict != string(phishval.VerdictPass) {
		t.Errorf("Dimensions[0] = %+v, want Response/pass", rep.Dimensions[0])
	}
}

func TestPhishingScenarioReportHTML_ExperimentalBanner_RenderedAboveLimitations(t *testing.T) {
	rep := PhishingScenarioReport{
		RunID: "run-1", ScenarioID: "PH-ID-004", ScenarioName: "MFA Fatigue Heuristic",
		RunStatus: "completed", Experimental: true, CatalogLimitations: "EXPERIMENTAL heuristic, not Microsoft-documented.",
		Dimensions: []PhishingReportDimension{{Name: "Response", Verdict: "not_tested", Reason: "no burst observed", Evidence: "inferred", Confidence: "low"}},
	}
	var buf bytes.Buffer
	if err := PhishingScenarioReportHTML(&buf, rep); err != nil {
		t.Fatalf("PhishingScenarioReportHTML: %v", err)
	}
	html := buf.String()
	if !strings.Contains(html, "EXPERIMENTAL") {
		t.Error("rendered HTML must contain an EXPERIMENTAL marker when Experimental is true")
	}
	bannerIdx := strings.Index(html, "EXPERIMENTAL")
	limitationsIdx := strings.Index(html, rep.CatalogLimitations)
	if bannerIdx == -1 || limitationsIdx == -1 || bannerIdx >= limitationsIdx {
		t.Error("EXPERIMENTAL banner must render above the catalog Limitations text, not buried after it")
	}
}

func TestPhishingScenarioReportHTML_NotExperimental_NoBanner(t *testing.T) {
	rep := PhishingScenarioReport{
		RunID: "run-1", ScenarioID: "PH-DET-002", ScenarioName: "Report Ticket",
		RunStatus: "completed", Experimental: false,
		Dimensions: []PhishingReportDimension{{Name: "Response", Verdict: "pass", Reason: "ticket created", Evidence: "verified_telemetry", Confidence: "high"}},
	}
	var buf bytes.Buffer
	if err := PhishingScenarioReportHTML(&buf, rep); err != nil {
		t.Fatalf("PhishingScenarioReportHTML: %v", err)
	}
	if strings.Contains(buf.String(), "EXPERIMENTAL") {
		t.Error("non-experimental report must not render the EXPERIMENTAL banner")
	}
}
