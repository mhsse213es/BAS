package reporting

import (
	"bytes"
	"strings"
	"testing"

	"github.com/audspect/bas/internal/emailgwefficacy"
)

func TestBuildEmailGWCoverageReport_IncludesEveryArea(t *testing.T) {
	rep, err := BuildEmailGWCoverageReport()
	if err != nil {
		t.Fatalf("BuildEmailGWCoverageReport: %v", err)
	}

	report, err := emailgwefficacy.AudspectEmailGWCoverageReport()
	if err != nil {
		t.Fatalf("AudspectEmailGWCoverageReport: %v", err)
	}
	if len(rep.Areas) != report.Denominator() {
		t.Fatalf("len(Areas) = %d, want %d (every area in the underlying report)", len(rep.Areas), report.Denominator())
	}
	if rep.Summary == "" {
		t.Error("Summary is empty, want the underlying report's Summary() text")
	}
	if rep.GeneratedAt.IsZero() {
		t.Error("GeneratedAt is zero, want it set")
	}
}

// TestBuildEmailGWCoverageReport_MatchesRealCoverageReport proves the
// report's Summary field is computed against Audspect's real,
// current coverage report, not a stale or synthetic value.
func TestBuildEmailGWCoverageReport_MatchesRealCoverageReport(t *testing.T) {
	rep, err := BuildEmailGWCoverageReport()
	if err != nil {
		t.Fatalf("BuildEmailGWCoverageReport: %v", err)
	}
	report, err := emailgwefficacy.AudspectEmailGWCoverageReport()
	if err != nil {
		t.Fatalf("AudspectEmailGWCoverageReport: %v", err)
	}
	if rep.Summary != report.Summary() {
		t.Errorf("Summary = %q, want %q", rep.Summary, report.Summary())
	}
}

func TestEmailGWCoverageReportHTML_RendersEveryArea(t *testing.T) {
	rep, err := BuildEmailGWCoverageReport()
	if err != nil {
		t.Fatalf("BuildEmailGWCoverageReport: %v", err)
	}
	var buf bytes.Buffer
	if err := EmailGWCoverageReportHTML(&buf, rep); err != nil {
		t.Fatalf("html: %v", err)
	}

	s := buf.String()
	if !strings.Contains(s, "<!DOCTYPE html>") {
		t.Error("output is not a full HTML document")
	}
	for _, a := range rep.Areas {
		if !strings.Contains(s, a.AreaID) {
			t.Errorf("HTML missing area ID %q", a.AreaID)
		}
	}
}

// TestEmailGWCoverageReportHTML_EscapesHostileContent proves
// html/template's auto-escaping is in effect -- an exclusion reason
// containing markup could never inject it into the page.
func TestEmailGWCoverageReportHTML_EscapesHostileContent(t *testing.T) {
	rep := EmailGWCoverageReport{
		Areas: []EmailGWCoverageAreaEntry{
			{AreaID: "X", AreaName: "test", Status: "excluded", ExclusionReason: "<script>alert(1)</script>"},
		},
	}
	var buf bytes.Buffer
	if err := EmailGWCoverageReportHTML(&buf, rep); err != nil {
		t.Fatalf("html: %v", err)
	}
	if strings.Contains(buf.String(), "<script>") {
		t.Error("output contains an unescaped <script> tag")
	}
}
