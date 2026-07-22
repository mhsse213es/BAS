package connector

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestOTXSource_Stats_CountsSubscribedPulses mirrors
// TestMISPClient_Stats_CountsRawEventsAndFilteredActors /
// TestOpenCTIClient_Stats_CountsRawNodesAndFilteredActors: a single mocked
// endpoint, asserting Fetch()'s return value and the resulting Stats().
// OTX's Fetch never extracts actors (that's sub-project 4), so ActorCount
// is always 0 here — that's the correct, honest state for this sub-project,
// not a bug.
func TestOTXSource_Stats_CountsSubscribedPulses(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/pulses/subscribed" {
			t.Fatalf("unexpected request path: %s", r.URL.Path)
		}
		if got := r.Header.Get("X-OTX-API-KEY"); got != "test-key" {
			t.Fatalf("X-OTX-API-KEY header = %q, want test-key", got)
		}
		w.Write([]byte(`{"count": 47, "results": [{"name": "some pulse"}]}`))
	}))
	defer server.Close()

	c := NewOTXSource("test-key")
	c.baseURL = server.URL

	actors, err := c.Fetch()
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(actors) != 0 {
		t.Fatalf("actors = %+v, want none (OTX Fetch never extracts actors yet)", actors)
	}

	stat := c.Stats()
	if stat.Name != "otx" || stat.RawCount != 47 || stat.ActorCount != 0 || stat.Error != "" {
		t.Fatalf("Stats() = %+v, want Name=otx RawCount=47 ActorCount=0 Error=\"\"", stat)
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
