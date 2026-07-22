package connector

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/audspect/bas/internal/reporting/attackdata"
)

// TestOTXSource_Stats_CountsSubscribedPulses is a basic single-page smoke
// test: verifies the request path/header and that a pulse with no adversary
// contributes to RawCount but not ActorCount. RawCount here means "pulses
// fetched this sync" (bounded by pagination), not the account's total
// subscribed-pulse count — see the RawCount semantics note in
// docs/superpowers/specs/2026-07-22-otx-technique-mapping-design.md.
func TestOTXSource_Stats_CountsSubscribedPulses(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/pulses/subscribed" {
			t.Fatalf("unexpected request path: %s", r.URL.Path)
		}
		if got := r.Header.Get("X-OTX-API-KEY"); got != "test-key" {
			t.Fatalf("X-OTX-API-KEY header = %q, want test-key", got)
		}
		json.NewEncoder(w).Encode(otxPulsesResponse{
			Count:   47,
			Results: []otxPulse{{Name: "some pulse", Modified: "2026-01-15T00:00:00Z"}},
		})
	}))
	defer server.Close()

	c := NewOTXSource("test-key")
	c.baseURL = server.URL

	actors, err := c.Fetch()
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(actors) != 0 {
		t.Fatalf("actors = %+v, want none (pulse has no adversary)", actors)
	}

	stat := c.Stats()
	if stat.Name != "otx" || stat.RawCount != 1 || stat.ActorCount != 0 || stat.Error != "" {
		t.Fatalf("Stats() = %+v, want Name=otx RawCount=1 ActorCount=0 Error=\"\"", stat)
	}
	if stat.FetchedAt.IsZero() {
		t.Fatal("Stats().FetchedAt should be set after a successful Fetch")
	}
}

func TestOTXSource_Stats_RecordsErrorOnFailedFetch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	c := NewOTXSource("test-key")
	c.baseURL = server.URL

	if _, err := c.Fetch(); err == nil {
		t.Fatal("expected error for HTTP 500")
	}
	stat := c.Stats()
	if stat.Name != "otx" || stat.Error == "" {
		t.Fatalf("Stats() = %+v, want Name=otx with Error set", stat)
	}
}

// TestOTXSource_Fetch_MatchesKnownGroupToAuthoritativeTechniques uses "Wizard
// Spider" — an established, real MITRE group name already relied on
// elsewhere in this codebase as a stable test fixture (see
// attackdata_test.go and ti_suggest_pack_test.go). The adversary field is
// deliberately lowercase-with-padding to exercise normalization; the actor's
// Name must come back in the index's canonical casing.
func TestOTXSource_Fetch_MatchesKnownGroupToAuthoritativeTechniques(t *testing.T) {
	wantTechs := attackdata.GroupTechniqueIndex()["Wizard Spider"]
	if len(wantTechs) == 0 {
		t.Fatal("test fixture assumption broken: \"Wizard Spider\" not found in GroupTechniqueIndex()")
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(otxPulsesResponse{
			Count: 1,
			Results: []otxPulse{
				{Name: "pulse one", Adversary: "  wizard spider  ", Modified: "2026-01-15T00:00:00Z"},
			},
		})
	}))
	defer server.Close()

	c := NewOTXSource("test-key")
	c.baseURL = server.URL

	actors, err := c.Fetch()
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(actors) != 1 {
		t.Fatalf("actors = %+v, want 1", actors)
	}
	a := actors[0]
	if a.Name != "Wizard Spider" || a.Source != "otx" || a.Confidence != "medium" {
		t.Fatalf("actor = %+v, want Name=\"Wizard Spider\" Source=otx Confidence=medium", a)
	}
	if len(a.Techniques) != len(wantTechs) {
		t.Fatalf("got %d techniques, want %d (from GroupTechniqueIndex)", len(a.Techniques), len(wantTechs))
	}
	if a.LastSeen.IsZero() {
		t.Fatal("LastSeen should be set from the pulse's Modified timestamp")
	}
}

func TestOTXSource_Fetch_SkipsUnmatchedAdversary(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(otxPulsesResponse{
			Count: 1,
			Results: []otxPulse{
				{Name: "pulse one", Adversary: "Some Made Up Actor Name Zzyzx", Modified: "2026-01-15T00:00:00Z"},
			},
		})
	}))
	defer server.Close()

	c := NewOTXSource("test-key")
	c.baseURL = server.URL

	actors, err := c.Fetch()
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(actors) != 0 {
		t.Fatalf("actors = %+v, want none (adversary name doesn't match any MITRE group)", actors)
	}
}

func TestOTXSource_Fetch_SkipsEmptyAdversary(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(otxPulsesResponse{
			Count:   1,
			Results: []otxPulse{{Name: "pulse one", Adversary: "", Modified: "2026-01-15T00:00:00Z"}},
		})
	}))
	defer server.Close()

	c := NewOTXSource("test-key")
	c.baseURL = server.URL

	actors, err := c.Fetch()
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(actors) != 0 {
		t.Fatalf("actors = %+v, want none (empty adversary)", actors)
	}
}

func TestOTXSource_Fetch_PaginatesUpToCap(t *testing.T) {
	var requestedPages []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestedPages = append(requestedPages, r.URL.Query().Get("page"))
		results := make([]otxPulse, 50)
		for i := range results {
			results[i] = otxPulse{Name: fmt.Sprintf("pulse %d", i), Modified: "2026-01-15T00:00:00Z"}
		}
		json.NewEncoder(w).Encode(otxPulsesResponse{Count: 550, Results: results})
	}))
	defer server.Close()

	c := NewOTXSource("test-key")
	c.baseURL = server.URL

	if _, err := c.Fetch(); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(requestedPages) != 10 {
		t.Fatalf("requested %d pages, want 10 (capped)", len(requestedPages))
	}
	if c.Stats().RawCount != 500 {
		t.Fatalf("RawCount = %d, want 500", c.Stats().RawCount)
	}
}

func TestOTXSource_Fetch_StopsOnShortPage(t *testing.T) {
	var requestCount int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		results := make([]otxPulse, 30)
		for i := range results {
			results[i] = otxPulse{Name: fmt.Sprintf("pulse %d", i), Modified: "2026-01-15T00:00:00Z"}
		}
		json.NewEncoder(w).Encode(otxPulsesResponse{Count: 30, Results: results})
	}))
	defer server.Close()

	c := NewOTXSource("test-key")
	c.baseURL = server.URL

	if _, err := c.Fetch(); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if requestCount != 1 {
		t.Fatalf("requested %d pages, want 1 (short page ends pagination)", requestCount)
	}
	if c.Stats().RawCount != 30 {
		t.Fatalf("RawCount = %d, want 30", c.Stats().RawCount)
	}
}

func TestOTXSource_Fetch_PartialFailureReturnsActorsGatheredSoFar(t *testing.T) {
	var page int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		page++
		if page == 1 {
			results := make([]otxPulse, 50)
			results[0] = otxPulse{Name: "pulse one", Adversary: "Wizard Spider", Modified: "2026-01-15T00:00:00Z"}
			for i := 1; i < 50; i++ {
				results[i] = otxPulse{Name: fmt.Sprintf("pulse %d", i), Modified: "2026-01-15T00:00:00Z"}
			}
			json.NewEncoder(w).Encode(otxPulsesResponse{Count: 100, Results: results})
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	c := NewOTXSource("test-key")
	c.baseURL = server.URL

	actors, err := c.Fetch()
	if err == nil {
		t.Fatal("expected error from page 2 failure")
	}
	if len(actors) != 1 || actors[0].Name != "Wizard Spider" {
		t.Fatalf("actors = %+v, want 1 actor (Wizard Spider, from page 1)", actors)
	}
	if c.Stats().Error == "" {
		t.Fatal("Stats().Error should be set")
	}
	if c.Stats().RawCount != 50 {
		t.Fatalf("RawCount = %d, want 50 (only page 1 succeeded)", c.Stats().RawCount)
	}
}
