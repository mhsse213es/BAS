package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/audspect/bas/internal/webgwefficacy"
)

func TestGetWebGWIndustryProfiles_ReturnsEveryKnownProfile(t *testing.T) {
	h := &Handler{}
	rr := httptest.NewRecorder()
	h.GetWebGWIndustryProfiles(rr, httptest.NewRequest(http.MethodGet, "/api/webgw/industry-profiles", nil))

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	if ct := rr.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("content-type = %q, want application/json", ct)
	}

	var got []struct {
		Name            string `json:"name"`
		Describe        string `json:"describe"`
		PrioritySummary string `json:"prioritySummary"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}

	names := webgwefficacy.IndustryProfileNames()
	if len(got) != len(names) {
		t.Fatalf("len(got) = %d, want %d (one entry per known profile)", len(got), len(names))
	}
	for i, name := range names {
		if got[i].Name != name {
			t.Errorf("got[%d].Name = %q, want %q", i, got[i].Name, name)
		}
		if got[i].Describe == "" {
			t.Errorf("got[%d].Describe is empty for profile %q", i, name)
		}
		if got[i].PrioritySummary == "" {
			t.Errorf("got[%d].PrioritySummary is empty for profile %q", i, name)
		}
	}
}

// TestGetWebGWIndustryProfiles_PrioritySummaryMatchesRealCoverageReport
// proves the handler's PrioritySummary field is genuinely computed
// against Audspect's real, current coverage report -- not a
// synthetic or stale value -- by cross-checking the BFSI/NBFC entry
// against a direct call to the same package function the handler
// itself must use.
func TestGetWebGWIndustryProfiles_PrioritySummaryMatchesRealCoverageReport(t *testing.T) {
	h := &Handler{}
	rr := httptest.NewRecorder()
	h.GetWebGWIndustryProfiles(rr, httptest.NewRequest(http.MethodGet, "/api/webgw/industry-profiles", nil))

	var got []struct {
		Name            string `json:"name"`
		PrioritySummary string `json:"prioritySummary"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}

	report, err := webgwefficacy.AudspectWebGWCoverageReport()
	if err != nil {
		t.Fatalf("AudspectWebGWCoverageReport: %v", err)
	}
	profile, err := webgwefficacy.BFSINBFCProfile()
	if err != nil {
		t.Fatalf("BFSINBFCProfile: %v", err)
	}
	want := profile.PrioritySummary(report)

	for _, entry := range got {
		if entry.Name == "bfsi" {
			if entry.PrioritySummary != want {
				t.Errorf("bfsi PrioritySummary = %q, want %q", entry.PrioritySummary, want)
			}
			return
		}
	}
	t.Fatal("bfsi entry not found in response")
}

func TestGetWebGWIndustryProfilesHTML_RendersEveryKnownProfile(t *testing.T) {
	h := &Handler{}
	rr := httptest.NewRecorder()
	h.GetWebGWIndustryProfilesHTML(rr, httptest.NewRequest(http.MethodGet, "/api/webgw/industry-profiles.html", nil))

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
	for _, name := range webgwefficacy.IndustryProfileNames() {
		if !strings.Contains(body, name) {
			t.Errorf("body missing profile name %q", name)
		}
	}
}
