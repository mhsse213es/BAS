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
