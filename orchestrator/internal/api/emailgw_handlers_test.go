package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/audspect/bas/internal/emailgwefficacy"
)

func TestGetEmailGWCoverage_ReturnsEveryTaxonomyArea(t *testing.T) {
	h := &Handler{}
	rr := httptest.NewRecorder()
	h.GetEmailGWCoverage(rr, httptest.NewRequest(http.MethodGet, "/api/emailgw/coverage", nil))

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	if ct := rr.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("content-type = %q, want application/json", ct)
	}

	var got struct {
		Summary string                         `json:"summary"`
		Areas   []emailgwefficacy.AreaCoverage `json:"areas"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}

	report, err := emailgwefficacy.AudspectEmailGWCoverageReport()
	if err != nil {
		t.Fatalf("AudspectEmailGWCoverageReport: %v", err)
	}
	if len(got.Areas) != report.Denominator() {
		t.Fatalf("len(Areas) = %d, want %d", len(got.Areas), report.Denominator())
	}
	if got.Summary != report.Summary() {
		t.Errorf("Summary = %q, want %q -- the handler must serve the real, current report, not a stale or synthetic value", got.Summary, report.Summary())
	}
}

func TestGetEmailGWCoverageHTML_RendersEveryTaxonomyArea(t *testing.T) {
	h := &Handler{}
	rr := httptest.NewRecorder()
	h.GetEmailGWCoverageHTML(rr, httptest.NewRequest(http.MethodGet, "/api/emailgw/coverage.html", nil))

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

	report, err := emailgwefficacy.AudspectEmailGWCoverageReport()
	if err != nil {
		t.Fatalf("AudspectEmailGWCoverageReport: %v", err)
	}
	for _, a := range report.Areas() {
		if !strings.Contains(body, a.AreaID) {
			t.Errorf("body missing area ID %q", a.AreaID)
		}
	}
}
