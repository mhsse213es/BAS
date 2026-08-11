package connector

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestOpenCTIClient_Stats_CountsRawNodesAndFilteredActors returns two threat-
// actor nodes with no attack-pattern edges, so convertActor builds an actor
// with 0 techniques and Fetch's "2+ techniques" filter drops both — RawCount
// is 2, ActorCount is 0. A single mocked GraphQL endpoint is enough since
// OpenCTI's Fetch, unlike MISP's, makes only one HTTP round trip.
func TestOpenCTIClient_Stats_CountsRawNodesAndFilteredActors(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/graphql" {
			t.Fatalf("unexpected request path: %s", r.URL.Path)
		}
		resp := octiThreatActorsResp{}
		resp.Data.ThreatActors.Edges = make([]octiActorEdge, 2)
		resp.Data.ThreatActors.Edges[0].Node = octiThreatActorNode{ID: "1", Name: "Actor One"}
		resp.Data.ThreatActors.Edges[1].Node = octiThreatActorNode{ID: "2", Name: "Actor Two"}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	c := NewOpenCTIClient(server.URL, "test-key", nil)
	actors, err := c.Fetch()
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(actors) != 0 {
		t.Fatalf("actors = %+v, want none (no node has 2+ techniques)", actors)
	}

	stat := c.Stats()
	if stat.Name != "opencti" || stat.RawCount != 2 || stat.ActorCount != 0 || stat.Error != "" {
		t.Fatalf("Stats() = %+v, want Name=opencti RawCount=2 ActorCount=0 Error=\"\"", stat)
	}
	if stat.FetchedAt.IsZero() {
		t.Fatal("Stats().FetchedAt should be set after a successful Fetch")
	}
}

func TestOpenCTIClient_Stats_RecordsErrorOnFailedFetch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	c := NewOpenCTIClient(server.URL, "test-key", nil)
	c.retryDelay = time.Millisecond // every request fails anyway; keep the test fast
	if _, err := c.Fetch(); err == nil {
		t.Fatal("expected error for HTTP 500")
	}
	stat := c.Stats()
	if stat.Name != "opencti" || stat.Error == "" {
		t.Fatalf("Stats() = %+v, want Name=opencti with Error set", stat)
	}
}

// TestOpenCTIClient_Fetch_RetriesOnceThenSucceeds simulates the exact
// failure class this hardening targets: the server errors on the first
// GraphQL round trip (a stand-in for a transient timeout/connection reset
// under the large nested query) and succeeds on the very next one. Before
// the retry was added, Fetch had no way to recover from this within a
// single sync cycle -- it would report a hard error and leave
// threat_actor_profiles untouched despite the server actually having data.
func TestOpenCTIClient_Fetch_RetriesOnceThenSucceeds(t *testing.T) {
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts == 1 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		resp := octiThreatActorsResp{}
		resp.Data.ThreatActors.Edges = make([]octiActorEdge, 1)
		resp.Data.ThreatActors.Edges[0].Node = octiThreatActorNode{ID: "1", Name: "Actor One"}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	c := NewOpenCTIClient(server.URL, "test-key", nil)
	c.retryDelay = time.Millisecond
	if _, err := c.Fetch(); err != nil {
		t.Fatalf("Fetch: %v, want the second attempt to succeed", err)
	}
	if attempts != 2 {
		t.Fatalf("attempts = %d, want exactly 2 (one failure, one retry)", attempts)
	}
	stat := c.Stats()
	if stat.Error != "" {
		t.Fatalf("Stats().Error = %q, want empty after a successful retry", stat.Error)
	}
}

// TestOpenCTIClient_Fetch_StopsAfterMaxAttempts confirms the retry is
// bounded -- a persistently-failing server still returns an error rather
// than retrying forever.
func TestOpenCTIClient_Fetch_StopsAfterMaxAttempts(t *testing.T) {
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	c := NewOpenCTIClient(server.URL, "test-key", nil)
	c.retryDelay = time.Millisecond
	if _, err := c.Fetch(); err == nil {
		t.Fatal("expected error after exhausting retries")
	}
	if attempts != 2 {
		t.Fatalf("attempts = %d, want exactly 2 (initial + 1 retry, then stop)", attempts)
	}
}
