package reporting

import (
	"bytes"
	"strings"
	"testing"

	"github.com/audspect/bas/internal/phishcatalog"
)

func TestBuildPhishingIndustryProfileReport_IncludesEveryKnownProfile(t *testing.T) {
	rep, err := BuildPhishingIndustryProfileReport()
	if err != nil {
		t.Fatalf("BuildPhishingIndustryProfileReport: %v", err)
	}

	names := phishcatalog.IndustryProfileNames()
	if len(rep.Profiles) != len(names) {
		t.Fatalf("len(Profiles) = %d, want %d", len(rep.Profiles), len(names))
	}
	for i, name := range names {
		if rep.Profiles[i].Name != name {
			t.Errorf("Profiles[%d].Name = %q, want %q", i, rep.Profiles[i].Name, name)
		}
		if rep.Profiles[i].Describe == "" {
			t.Errorf("Profiles[%d].Describe is empty for %q", i, name)
		}
		if rep.Profiles[i].PrioritySummary == "" {
			t.Errorf("Profiles[%d].PrioritySummary is empty for %q", i, name)
		}
	}
	if rep.GeneratedAt.IsZero() {
		t.Error("GeneratedAt is zero, want it set")
	}
}

// TestBuildPhishingIndustryProfileReport_PrioritySummaryMatchesRealCatalog
// proves the report's PrioritySummary field is computed against
// Audspect's real, current scenario catalog, not a stale or synthetic
// value.
func TestBuildPhishingIndustryProfileReport_PrioritySummaryMatchesRealCatalog(t *testing.T) {
	rep, err := BuildPhishingIndustryProfileReport()
	if err != nil {
		t.Fatalf("BuildPhishingIndustryProfileReport: %v", err)
	}
	scenarios, err := phishcatalog.AudspectPhishingCatalog()
	if err != nil {
		t.Fatalf("AudspectPhishingCatalog: %v", err)
	}
	profile, err := phishcatalog.BFSINBFCProfile()
	if err != nil {
		t.Fatalf("BFSINBFCProfile: %v", err)
	}
	want := profile.PrioritySummary(scenarios)

	for _, p := range rep.Profiles {
		if p.Name == "bfsi" {
			if p.PrioritySummary != want {
				t.Errorf("bfsi PrioritySummary = %q, want %q", p.PrioritySummary, want)
			}
			return
		}
	}
	t.Fatal("bfsi entry not found in report")
}

func TestPhishingIndustryProfileReportHTML_RendersEveryProfile(t *testing.T) {
	rep, err := BuildPhishingIndustryProfileReport()
	if err != nil {
		t.Fatalf("BuildPhishingIndustryProfileReport: %v", err)
	}
	var buf bytes.Buffer
	if err := PhishingIndustryProfileReportHTML(&buf, rep); err != nil {
		t.Fatalf("html: %v", err)
	}

	s := buf.String()
	if !strings.Contains(s, "<!DOCTYPE html>") {
		t.Error("output is not a full HTML document")
	}
	for _, p := range rep.Profiles {
		if !strings.Contains(s, p.Name) {
			t.Errorf("HTML missing profile name %q", p.Name)
		}
		if !strings.Contains(s, p.Describe) {
			t.Errorf("HTML missing Describe() text for %q", p.Name)
		}
	}
}

func TestPhishingIndustryProfileReportHTML_EscapesHostileContent(t *testing.T) {
	rep := PhishingIndustryProfileReport{
		Profiles: []PhishingIndustryProfileEntry{
			{Name: "test", Describe: "<script>alert(1)</script>", PrioritySummary: "fine"},
		},
	}
	var buf bytes.Buffer
	if err := PhishingIndustryProfileReportHTML(&buf, rep); err != nil {
		t.Fatalf("html: %v", err)
	}
	if strings.Contains(buf.String(), "<script>") {
		t.Error("output contains an unescaped <script> tag")
	}
}
