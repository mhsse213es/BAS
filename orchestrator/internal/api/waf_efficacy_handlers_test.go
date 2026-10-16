package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/audspect/bas/internal/wafefficacy"
)

func TestGetWAFCoverage_ReturnsEveryDomain(t *testing.T) {
	h := &Handler{}
	rr := httptest.NewRecorder()
	h.GetWAFCoverage(rr, httptest.NewRequest(http.MethodGet, "/api/waf/coverage", nil))

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	if ct := rr.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("content-type = %q, want application/json", ct)
	}

	var got struct {
		Summary string                       `json:"summary"`
		Domains []wafefficacy.DomainCoverage `json:"domains"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}

	report, err := wafefficacy.AudspectWAFCoverageReport()
	if err != nil {
		t.Fatalf("AudspectWAFCoverageReport: %v", err)
	}
	if len(got.Domains) != report.Denominator() {
		t.Fatalf("len(Domains) = %d, want %d", len(got.Domains), report.Denominator())
	}
	if got.Summary != report.Summary() {
		t.Errorf("Summary = %q, want %q -- the handler must serve the real, current report", got.Summary, report.Summary())
	}
}

func TestGetWAFCoverageHTML_RendersEveryDomain(t *testing.T) {
	h := &Handler{}
	rr := httptest.NewRecorder()
	h.GetWAFCoverageHTML(rr, httptest.NewRequest(http.MethodGet, "/api/waf/coverage.html", nil))

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	if ct := rr.Header().Get("Content-Type"); ct != "text/html; charset=utf-8" {
		t.Fatalf("content-type = %q, want text/html; charset=utf-8", ct)
	}

	body := rr.Body.String()
	if !strings.Contains(body, "<!DOCTYPE html>") {
		t.Error("body is not a full HTML document")
	}

	report, err := wafefficacy.AudspectWAFCoverageReport()
	if err != nil {
		t.Fatalf("AudspectWAFCoverageReport: %v", err)
	}
	for _, d := range report.DomainsForDisplay() {
		if !strings.Contains(body, d.DomainID) {
			t.Errorf("body missing domain ID %q", d.DomainID)
		}
	}
}

func TestGetWAFIndustryProfiles_ReturnsEightProfilesWithComplianceDetail(t *testing.T) {
	h := &Handler{}
	rr := httptest.NewRecorder()
	h.GetWAFIndustryProfiles(rr, httptest.NewRequest(http.MethodGet, "/api/waf/industry-profiles", nil))

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	if ct := rr.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("content-type = %q, want application/json", ct)
	}

	body := rr.Body.String()
	if !strings.Contains(body, `"id":"WAFPROFILE-BFSI"`) {
		t.Error("body missing WAFPROFILE-BFSI")
	}
	if !strings.Contains(body, "unverified") {
		t.Error("body missing \"unverified\" status")
	}
	if !strings.Contains(body, "no specific circular number or clause verified against RBI's own text") {
		t.Error("body missing the real RBI Note text verbatim")
	}

	var got []map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got) != 8 {
		t.Fatalf("len(profiles) = %d, want 8", len(got))
	}
}

func TestGetWAFIndustryProfilesHTML_RendersComplianceDetail(t *testing.T) {
	h := &Handler{}
	rr := httptest.NewRecorder()
	h.GetWAFIndustryProfilesHTML(rr, httptest.NewRequest(http.MethodGet, "/api/waf/industry-profiles.html", nil))

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "<!DOCTYPE html>") {
		t.Error("body is not a full HTML document")
	}
	if !strings.Contains(body, "unverified") {
		t.Error("body missing \"unverified\" status")
	}
}

// Final review finding: wafefficacy.DomainCoverage had no json tags,
// so the wire format was PascalCase instead of this codebase's
// established camelCase convention (webgwefficacy.DomainCoverage,
// emailgwefficacy.AreaCoverage, and this plan's own
// wafIndustryProfileResponse all camelCase). The existing coverage
// test decodes case-insensitively, which masked this on the round
// trip -- this test asserts the raw wire bytes instead.
func TestGetWAFCoverage_JSONKeysAreCamelCase(t *testing.T) {
	h := &Handler{}
	rr := httptest.NewRecorder()
	h.GetWAFCoverage(rr, httptest.NewRequest(http.MethodGet, "/api/waf/coverage", nil))

	body := rr.Body.String()
	if !strings.Contains(body, `"domainId"`) {
		t.Error(`body missing "domainId" key (camelCase) -- found PascalCase "DomainID" instead?`)
	}
	if !strings.Contains(body, `"domainName"`) {
		t.Error(`body missing "domainName" key (camelCase)`)
	}
	if !strings.Contains(body, `"status"`) {
		t.Error(`body missing "status" key (camelCase)`)
	}
	if strings.Contains(body, `"DomainID"`) {
		t.Error(`body contains PascalCase "DomainID" -- json tags are missing`)
	}
}
