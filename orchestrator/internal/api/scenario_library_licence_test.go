package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/audspect/bas/internal/license"
	"github.com/audspect/bas/internal/scenario"
)

// The scenario library lists phishing entries only when the licence includes phishing. A Core
// licence does not see the Advanced phishing catalogue at all.
func TestScenarioLibrary_PhishingOnlyWhenLicensed(t *testing.T) {
	defer license.SetInitial(license.Info{State: license.StateValid, Tier: license.TierEnterprise})
	h := &Handler{engine: scenario.NewEngine(t.TempDir())}

	count := func(tier license.Tier) int {
		license.SetInitial(license.Info{State: license.StateValid, Tier: tier})
		rec := httptest.NewRecorder()
		h.ListScenarioLibrary(rec, httptest.NewRequest(http.MethodGet, "/api/scenarios/library", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: status %d", tier, rec.Code)
		}
		var entries []struct {
			Type string `json:"type"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &entries); err != nil {
			t.Fatalf("bad JSON: %v", err)
		}
		n := 0
		for _, e := range entries {
			if e.Type == LibraryTypePhishing {
				n++
			}
		}
		return n
	}
	if n := count(license.TierCore); n != 0 {
		t.Fatalf("Core licence saw %d phishing entries, want 0", n)
	}
	if n := count(license.TierAdvanced); n == 0 {
		t.Fatal("Advanced licence saw no phishing entries")
	}
}
