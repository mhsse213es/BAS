package reporting

import (
	"bytes"
	"strings"
	"testing"
)

// Review Focus: every ComplianceReference's VerificationStatus and Note
// must survive into the built report verbatim -- the same
// anti-regression discipline as the WAF industry-profile report (a
// compliance claim silently going stale or being summarized away).
func TestBuildAVIndustryProfileReport_PreservesComplianceDetailVerbatim(t *testing.T) {
	rep, err := BuildAVIndustryProfileReport()
	if err != nil {
		t.Fatalf("BuildAVIndustryProfileReport: %v", err)
	}
	if len(rep.Profiles) != 7 {
		t.Fatalf("len(Profiles) = %d, want 7", len(rep.Profiles))
	}

	var found bool
	for _, p := range rep.Profiles {
		if p.ID != "AVPROFILE-BFSI" {
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
			t.Error("AVPROFILE-BFSI: no complianceReference has VerificationStatus \"unverified\"")
		}
		if !sawRealNote {
			t.Error("AVPROFILE-BFSI: the real RBI Note text was not preserved verbatim")
		}
	}
	if !found {
		t.Fatal("AVPROFILE-BFSI not found in built report")
	}
}

func TestAVIndustryProfileReportHTML_RendersComplianceDetail(t *testing.T) {
	rep, err := BuildAVIndustryProfileReport()
	if err != nil {
		t.Fatalf("BuildAVIndustryProfileReport: %v", err)
	}
	var buf bytes.Buffer
	if err := AVIndustryProfileReportHTML(&buf, rep); err != nil {
		t.Fatalf("AVIndustryProfileReportHTML: %v", err)
	}
	body := buf.String()
	if !strings.Contains(body, "unverified") {
		t.Error("HTML body missing \"unverified\" status")
	}
	if !strings.Contains(body, "no specific circular number or clause verified against RBI") {
		t.Error("HTML body missing the real RBI Note text")
	}
}
