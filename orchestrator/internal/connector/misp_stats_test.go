package connector

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestMISPClient_Stats_CountsRawEventsAndFilteredActors uses events with no
// "mitre-attack" tag, so extractActor short-circuits before its second HTTP
// call (getEvent) — this keeps the test to a single mocked endpoint while
// still exercising the real RawCount/ActorCount split: all 3 events count as
// RawCount, none pass the mitre-tag pre-filter, so ActorCount is 0.
func TestMISPClient_Stats_CountsRawEventsAndFilteredActors(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/events/index" {
			t.Fatalf("unexpected request path: %s", r.URL.Path)
		}
		events := []mispEventIndex{
			{ID: "1", Info: "event one", Tag: []mispTag{{Name: "tlp:amber"}}},
			{ID: "2", Info: "event two", Tag: nil},
			{ID: "3", Info: "event three", Tag: []mispTag{{Name: "some-other-tag"}}},
		}
		json.NewEncoder(w).Encode(events)
	}))
	defer server.Close()

	c := NewMISPClient(server.URL, "test-key", nil, nil)
	actors, err := c.Fetch()
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(actors) != 0 {
		t.Fatalf("actors = %+v, want none (no event has a mitre-attack tag)", actors)
	}

	stat := c.Stats()
	if stat.Name != "misp" || stat.RawCount != 3 || stat.ActorCount != 0 || stat.Error != "" {
		t.Fatalf("Stats() = %+v, want Name=misp RawCount=3 ActorCount=0 Error=\"\"", stat)
	}
	if stat.FetchedAt.IsZero() {
		t.Fatal("Stats().FetchedAt should be set after a successful Fetch")
	}
}

func TestMISPClient_Stats_RecordsErrorOnFailedFetch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	c := NewMISPClient(server.URL, "test-key", nil, nil)
	if _, err := c.Fetch(); err == nil {
		t.Fatal("expected error for HTTP 500")
	}
	stat := c.Stats()
	if stat.Name != "misp" || stat.Error == "" {
		t.Fatalf("Stats() = %+v, want Name=misp with Error set", stat)
	}
}
