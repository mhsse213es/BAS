package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/audspect/bas/internal/admatrix"
)

func TestGetADAssessmentJSON_IsBackedByTheMatrixReport(t *testing.T) {
	h := &Handler{}
	rr := httptest.NewRecorder()
	h.GetADAssessmentJSON(rr, httptest.NewRequest(http.MethodGet, "/api/ad/assessment.json", nil))

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	if ct := rr.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("content-type = %q, want application/json", ct)
	}
	var got struct {
		Report struct {
			CapabilityStateSummary struct {
				Total    int `json:"total"`
				Executed int `json:"executed"`
			} `json:"capabilityStateSummary"`
			CapabilityStates []map[string]any `json:"capabilityStates"`
		} `json:"report"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	want := admatrix.Report()
	if got.Report.CapabilityStateSummary.Total != want.CapabilityStateSummary.Total {
		t.Fatalf("report total %d != matrix %d (must not be hardcoded)", got.Report.CapabilityStateSummary.Total, want.CapabilityStateSummary.Total)
	}
	if len(got.Report.CapabilityStates) != len(want.CapabilityStates) {
		t.Fatalf("capability count %d != matrix %d", len(got.Report.CapabilityStates), len(want.CapabilityStates))
	}
	// Honest default: nothing executed in this build.
	if got.Report.CapabilityStateSummary.Executed != 0 {
		t.Fatalf("executed count = %d, want 0 (no real-AD execution in this build)", got.Report.CapabilityStateSummary.Executed)
	}
}

func TestGetADAssessmentHTML_RendersReport(t *testing.T) {
	h := &Handler{}
	rr := httptest.NewRecorder()
	h.GetADAssessmentHTML(rr, httptest.NewRequest(http.MethodGet, "/api/ad/assessment.html", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "Executive Summary") {
		t.Fatalf("HTML report missing Executive Summary section")
	}
}

func TestGetADAssessmentPDF_FallsBackToPDFDocument(t *testing.T) {
	t.Setenv("CHROME_WS_URL", "")
	h := &Handler{}
	rr := httptest.NewRecorder()
	h.GetADAssessmentPDF(rr, httptest.NewRequest(http.MethodGet, "/api/ad/assessment.pdf", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	if ct := rr.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/pdf") {
		t.Fatalf("content-type = %q, want application/pdf", ct)
	}
	if !strings.HasPrefix(rr.Body.String(), "%PDF") {
		t.Fatalf("body is not a PDF document")
	}
}
