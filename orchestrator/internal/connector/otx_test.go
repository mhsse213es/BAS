package connector

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/audspect/bas/internal/reporting/attackdata"
)

// TestOTXSource_Stats_CountsSubscribedPulses is a basic single-page smoke
// test: verifies the request path/header and that a pulse with no adversary
// contributes to RawCount but not ActorCount. RawCount here means "pulses
// fetched this sync" (bounded by pagination), not the account's total
// subscribed-pulse count.
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

	signals, err := c.FetchActivity()
	if err != nil {
		t.Fatalf("FetchActivity: %v", err)
	}
	if len(signals) != 0 {
		t.Fatalf("signals = %+v, want none (pulse has no adversary)", signals)
	}

	stat := c.Stats()
	if stat.Name != "otx" || stat.RawCount != 1 || stat.ActorCount != 0 || stat.Error != "" {
		t.Fatalf("Stats() = %+v, want Name=otx RawCount=1 ActorCount=0 Error=\"\"", stat)
	}
	if stat.FetchedAt.IsZero() {
		t.Fatal("Stats().FetchedAt should be set after a successful FetchActivity")
	}
}

func TestOTXSource_Stats_RecordsErrorOnFailedFetch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	c := NewOTXSource("test-key")
	c.baseURL = server.URL

	if _, err := c.FetchActivity(); err == nil {
		t.Fatal("expected error for HTTP 500")
	}
	stat := c.Stats()
	if stat.Name != "otx" || stat.Error == "" {
		t.Fatalf("Stats() = %+v, want Name=otx with Error set", stat)
	}
}

// TestOTXSource_FetchActivity_MatchesKnownGroup uses "Wizard Spider" -- an
// established, real MITRE group name already relied on elsewhere in this
// codebase as a stable test fixture (see attackdata_test.go and
// ti_suggest_pack_test.go). The adversary field is deliberately
// lowercase-with-padding to exercise normalization; the signal's ActorName
// must come back in the index's canonical casing.
func TestOTXSource_FetchActivity_MatchesKnownGroup(t *testing.T) {
	if len(attackdata.GroupTechniqueIndex()["Wizard Spider"]) == 0 {
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

	signals, err := c.FetchActivity()
	if err != nil {
		t.Fatalf("FetchActivity: %v", err)
	}
	if len(signals) != 1 {
		t.Fatalf("signals = %+v, want 1", signals)
	}
	sig := signals[0]
	if sig.ActorName != "Wizard Spider" {
		t.Fatalf("ActorName = %q, want \"Wizard Spider\"", sig.ActorName)
	}
	if sig.PulseCount != 1 {
		t.Fatalf("PulseCount = %d, want 1", sig.PulseCount)
	}
	wantTime := time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC)
	if !sig.FirstObserved.Equal(wantTime) || !sig.LastObserved.Equal(wantTime) {
		t.Fatalf("FirstObserved=%v LastObserved=%v, want both %v (single pulse)", sig.FirstObserved, sig.LastObserved, wantTime)
	}
}

// TestOTXSource_FetchActivity_AccumulatesPulseCountAndSpread is new
// behavior this rewrite introduces: today's Fetch() only ever tracked the
// latest Modified date per matched actor. FetchActivity must now count
// every matching pulse and track both the earliest and latest Modified
// date seen this sync.
func TestOTXSource_FetchActivity_AccumulatesPulseCountAndSpread(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(otxPulsesResponse{
			Count: 3,
			Results: []otxPulse{
				{Name: "pulse one", Adversary: "Wizard Spider", Modified: "2026-01-10T00:00:00Z"},
				{Name: "pulse two", Adversary: "Wizard Spider", Modified: "2026-01-20T00:00:00Z"},
				{Name: "pulse three", Adversary: "Wizard Spider", Modified: "2026-01-15T00:00:00Z"},
			},
		})
	}))
	defer server.Close()

	c := NewOTXSource("test-key")
	c.baseURL = server.URL

	signals, err := c.FetchActivity()
	if err != nil {
		t.Fatalf("FetchActivity: %v", err)
	}
	if len(signals) != 1 {
		t.Fatalf("signals = %+v, want 1 (all three pulses match the same actor)", signals)
	}
	sig := signals[0]
	if sig.PulseCount != 3 {
		t.Fatalf("PulseCount = %d, want 3", sig.PulseCount)
	}
	wantFirst := time.Date(2026, 1, 10, 0, 0, 0, 0, time.UTC)
	wantLast := time.Date(2026, 1, 20, 0, 0, 0, 0, time.UTC)
	if !sig.FirstObserved.Equal(wantFirst) {
		t.Errorf("FirstObserved = %v, want %v (the earliest of the three)", sig.FirstObserved, wantFirst)
	}
	if !sig.LastObserved.Equal(wantLast) {
		t.Errorf("LastObserved = %v, want %v (the latest of the three)", sig.LastObserved, wantLast)
	}
}

func TestOTXSource_FetchActivity_SkipsUnmatchedAdversary(t *testing.T) {
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

	signals, err := c.FetchActivity()
	if err != nil {
		t.Fatalf("FetchActivity: %v", err)
	}
	if len(signals) != 0 {
		t.Fatalf("signals = %+v, want none (adversary name doesn't match any MITRE group)", signals)
	}
}

func TestOTXSource_FetchActivity_SkipsEmptyAdversary(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(otxPulsesResponse{
			Count:   1,
			Results: []otxPulse{{Name: "pulse one", Adversary: "", Modified: "2026-01-15T00:00:00Z"}},
		})
	}))
	defer server.Close()

	c := NewOTXSource("test-key")
	c.baseURL = server.URL

	signals, err := c.FetchActivity()
	if err != nil {
		t.Fatalf("FetchActivity: %v", err)
	}
	if len(signals) != 0 {
		t.Fatalf("signals = %+v, want none (empty adversary)", signals)
	}
}

func TestOTXSource_FetchActivity_PaginatesUpToCap(t *testing.T) {
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

	if _, err := c.FetchActivity(); err != nil {
		t.Fatalf("FetchActivity: %v", err)
	}
	if len(requestedPages) != 10 {
		t.Fatalf("requested %d pages, want 10 (capped)", len(requestedPages))
	}
	if c.Stats().RawCount != 500 {
		t.Fatalf("RawCount = %d, want 500", c.Stats().RawCount)
	}
}

func TestOTXSource_FetchActivity_StopsOnShortPage(t *testing.T) {
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

	if _, err := c.FetchActivity(); err != nil {
		t.Fatalf("FetchActivity: %v", err)
	}
	if requestCount != 1 {
		t.Fatalf("requested %d pages, want 1 (short page ends pagination)", requestCount)
	}
	if c.Stats().RawCount != 30 {
		t.Fatalf("RawCount = %d, want 30", c.Stats().RawCount)
	}
}

func TestOTXSource_FetchActivity_PartialFailureReturnsSignalsGatheredSoFar(t *testing.T) {
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

	signals, err := c.FetchActivity()
	if err == nil {
		t.Fatal("expected error from page 2 failure")
	}
	if len(signals) != 1 || signals[0].ActorName != "Wizard Spider" {
		t.Fatalf("signals = %+v, want 1 signal (Wizard Spider, from page 1)", signals)
	}
	if c.Stats().Error == "" {
		t.Fatal("Stats().Error should be set")
	}
	if c.Stats().RawCount != 50 {
		t.Fatalf("RawCount = %d, want 50 (only page 1 succeeded)", c.Stats().RawCount)
	}
}
