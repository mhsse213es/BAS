package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/audspect/bas/internal/phishcatalog"
)

func TestGetPhishingIndustryProfiles_ReturnsEveryKnownProfile(t *testing.T) {
	h := &Handler{}
	rr := httptest.NewRecorder()
	h.GetPhishingIndustryProfiles(rr, httptest.NewRequest(http.MethodGet, "/api/phishing/industry-profiles", nil))

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

	names := phishcatalog.IndustryProfileNames()
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

func TestGetPhishingIndustryProfiles_PrioritySummaryMatchesRealCatalog(t *testing.T) {
	h := &Handler{}
	rr := httptest.NewRecorder()
	h.GetPhishingIndustryProfiles(rr, httptest.NewRequest(http.MethodGet, "/api/phishing/industry-profiles", nil))

	var got []struct {
		Name            string `json:"name"`
		PrioritySummary string `json:"prioritySummary"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
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

func TestGetPhishingIndustryProfilesHTML_RendersEveryKnownProfile(t *testing.T) {
	h := &Handler{}
	rr := httptest.NewRecorder()
	h.GetPhishingIndustryProfilesHTML(rr, httptest.NewRequest(http.MethodGet, "/api/phishing/industry-profiles.html", nil))

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
	for _, name := range phishcatalog.IndustryProfileNames() {
		if !strings.Contains(body, name) {
			t.Errorf("body missing profile name %q", name)
		}
	}
}
