package reporting

import (
	"bytes"
	"strings"
	"testing"
)

func TestBuildExploitPreventionScenarioReport_MatchesDirectEvaluation(t *testing.T) {
	rep, err := BuildExploitPreventionScenarioReport()
	if err != nil {
		t.Fatalf("BuildExploitPreventionScenarioReport: %v", err)
	}
	if rep.Outcome != "fail" {
		t.Errorf("Outcome = %q, want %q", rep.Outcome, "fail")
	}
	var sawSQLI002 bool
	for _, a := range rep.Assertions {
		if a.VectorID == "SQLI-002" && a.Verdict == "missed" {
			sawSQLI002 = true
		}
	}
	if !sawSQLI002 {
		t.Error("report Assertions missing SQLI-002 with verdict missed")
	}
}

// Review Focus: the generic slug path must serve a SECOND, different
// scenario correctly, not just the one it was first built for.
func TestBuildScenarioReport_HTTPProtocolIntegrity_ReturnsRealFail(t *testing.T) {
	rep, err := BuildScenarioReport("http-protocol-integrity")
	if err != nil {
		t.Fatalf("BuildScenarioReport: %v", err)
	}
	if rep.ScenarioName != "HTTP Protocol Integrity and Parser Consistency" {
		t.Errorf("ScenarioName = %q, want %q", rep.ScenarioName, "HTTP Protocol Integrity and Parser Consistency")
	}
	if rep.Outcome != "fail" {
		t.Errorf("Outcome = %q, want %q", rep.Outcome, "fail")
	}
	var buf bytes.Buffer
	if err := WAFScenarioReportHTML(&buf, rep); err != nil {
		t.Fatalf("WAFScenarioReportHTML: %v", err)
	}
	body := buf.String()
	if !strings.Contains(body, "HTTPPARSE-001") {
		t.Error("HTML body missing HTTPPARSE-001")
	}
	if !strings.Contains(body, "HTTP Protocol Integrity and Parser Consistency") {
		t.Error("HTML body missing the scenario's own name, not hardcoded to a different scenario")
	}
}

func TestBuildScenarioReport_UnknownSlug_ReturnsError(t *testing.T) {
	if _, err := BuildScenarioReport("does-not-exist"); err == nil {
		t.Fatal("want error for unknown slug, got nil")
	}
}

func TestWAFExploitPreventionScenarioReportHTML_RendersFailureAndDisclosure(t *testing.T) {
	rep, err := BuildExploitPreventionScenarioReport()
	if err != nil {
		t.Fatalf("BuildExploitPreventionScenarioReport: %v", err)
	}
	var buf bytes.Buffer
	if err := WAFExploitPreventionScenarioReportHTML(&buf, rep); err != nil {
		t.Fatalf("WAFExploitPreventionScenarioReportHTML: %v", err)
	}
	body := buf.String()
	if !strings.Contains(body, "SQLI-002") {
		t.Error("HTML body missing SQLI-002")
	}
	if !strings.Contains(body, "fixture-validated") {
		t.Error("HTML body missing the fixture-only disclosure")
	}
}
