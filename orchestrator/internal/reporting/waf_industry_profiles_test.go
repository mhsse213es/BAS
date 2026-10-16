package reporting

import (
	"bytes"
	"strings"
	"testing"
)

// Review Focus: every ComplianceReference's VerificationStatus and
// Note must survive into the built report verbatim -- this is the
// direct anti-regression test against the documented webgwefficacy
// stale-RBI-circular precedent (a compliance claim silently going
// stale or being summarized away).
func TestBuildWAFIndustryProfileReport_PreservesComplianceDetailVerbatim(t *testing.T) {
	rep, err := BuildWAFIndustryProfileReport()
	if err != nil {
		t.Fatalf("BuildWAFIndustryProfileReport: %v", err)
	}
	if len(rep.Profiles) != 8 {
		t.Fatalf("len(Profiles) = %d, want 8", len(rep.Profiles))
	}

	var found bool
	for _, p := range rep.Profiles {
		if p.ID != "WAFPROFILE-BFSI" {
			continue
		}
		found = true
		var sawUnverified bool
		var sawRealNote bool
		for _, c := range p.ComplianceReferences {
			if c.VerificationStatus == "unverified" {
				sawUnverified = true
			}
			if strings.Contains(c.Note, "no specific circular number or clause verified against RBI's own text") {
				sawRealNote = true
			}
		}
		if !sawUnverified {
			t.Error("WAFPROFILE-BFSI: no complianceReference has VerificationStatus \"unverified\"")
		}
		if !sawRealNote {
			t.Error("WAFPROFILE-BFSI: the real RBI Note text was not preserved verbatim")
		}
	}
	if !found {
		t.Fatal("WAFPROFILE-BFSI not found in built report")
	}
}

func TestWAFIndustryProfileReportHTML_RendersComplianceDetail(t *testing.T) {
	rep, err := BuildWAFIndustryProfileReport()
	if err != nil {
		t.Fatalf("BuildWAFIndustryProfileReport: %v", err)
	}
	var buf bytes.Buffer
	if err := WAFIndustryProfileReportHTML(&buf, rep); err != nil {
		t.Fatalf("WAFIndustryProfileReportHTML: %v", err)
	}
	body := buf.String()
	if !strings.Contains(body, "unverified") {
		t.Error("HTML body missing \"unverified\" status")
	}
	// html/template correctly escapes the apostrophe in "RBI's" to
	// &#39;, so the asserted substring stops just before it.
	if !strings.Contains(body, "no specific circular number or clause verified against RBI") {
		t.Error("HTML body missing the real RBI Note text")
	}
}
