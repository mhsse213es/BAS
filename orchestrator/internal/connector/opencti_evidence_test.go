package connector

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/audspect/bas/internal/evidence"
)

func TestOpenCTIClient_Fetch_TruncatedAtPageLimitAndCapturesRawClaims(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/graphql" {
			t.Fatalf("unexpected request path: %s", r.URL.Path)
		}
		resp := octiThreatActorsResp{}
		// Exactly openCTIPageLimit (100) top-level edges -- until cursor
		// pagination exists, this can never be distinguished from "there
		// were exactly 100 real results" (spec §5.2's OpenCTI row).
		resp.Data.ThreatActors.Edges = make([]octiActorEdge, openCTIPageLimit)
		for i := range resp.Data.ThreatActors.Edges {
			resp.Data.ThreatActors.Edges[i].Node = octiThreatActorNode{ID: "bulk", Name: "Bulk Actor"}
		}
		// One real actor with a single technique -- below the 2-technique
		// generation threshold, but a raw claim must still be captured
		// (spec §6.2).
		solo := octiThreatActorNode{ID: "solo-1", Name: "Solo Actor", Confidence: 70}
		solo.AttackPatterns.Edges = []octiRelationshipEdge{{Node: octiRelationshipNode{
			To: octiRelatedEntity{XMitreID: "T1059", Name: "Command Line"},
		}}}
		resp.Data.IntrusionSets.Edges = []octiActorEdge{{Node: solo}}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	c := NewOpenCTIClient(server.URL, "test-key", nil)
	actors, err := c.Fetch()
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(actors) != 0 {
		t.Fatalf("actors = %+v, want none (Solo Actor has only 1 technique)", actors)
	}

	claims := c.RawClaims()
	found := false
	for _, cl := range claims {
		if cl.ActorName == "Solo Actor" && cl.TechniqueID == "T1059" {
			found = true
		}
	}
	if !found {
		t.Fatalf("RawClaims() = %+v, want a claim for Solo Actor/T1059", claims)
	}

	report := c.Completeness()
	if report.Completeness != evidence.Truncated {
		t.Fatalf("Completeness() = %+v, want Truncated (ThreatActors hit the %d-edge page limit)", report, openCTIPageLimit)
	}
}
