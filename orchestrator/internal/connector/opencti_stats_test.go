package connector

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
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
		resp.Data.ThreatActors.Edges = make([]struct {
			Node octiThreatActorNode `json:"node"`
		}, 2)
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
	if _, err := c.Fetch(); err == nil {
		t.Fatal("expected error for HTTP 500")
	}
	stat := c.Stats()
	if stat.Name != "opencti" || stat.Error == "" {
		t.Fatalf("Stats() = %+v, want Name=opencti with Error set", stat)
	}
}
