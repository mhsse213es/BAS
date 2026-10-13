package connector

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/audspect/bas/internal/evidence"
)

func TestMISPClient_Fetch_CapturesRawClaimsBeforeFilterAndReportsPartial(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/events/index":
			events := []mispEventIndex{
				{ID: "1", Info: "event one", Tag: []mispTag{{Name: "mitre-attack-pattern"}}},
				{ID: "2", Info: "event two", Tag: []mispTag{{Name: "mitre-attack-pattern"}}},
			}
			json.NewEncoder(w).Encode(events)
		case "/events/1":
			// One technique only -- below the 2-technique generation
			// threshold, but a raw claim must still be captured (spec §6.2).
			var detail mispEventDetail
			detail.Event.Tag = []mispTag{{Name: `misp-galaxy:threat-actor="Solo Actor"`}}
			detail.Event.GalaxyCluster = []mispGalaxy{{
				Type: "mitre-attack-pattern",
				Meta: struct {
					ExternalID []string `json:"external_id"`
					KillChain  []string `json:"kill_chain"`
				}{ExternalID: []string{"T1059"}},
			}}
			json.NewEncoder(w).Encode(detail)
		case "/events/2":
			w.WriteHeader(http.StatusInternalServerError)
		default:
			t.Fatalf("unexpected request path: %s", r.URL.Path)
		}
	}))
	defer server.Close()

	c := NewMISPClient(server.URL, "test-key", nil, nil, false)
	actors, err := c.Fetch()
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(actors) != 0 {
		t.Fatalf("actors = %+v, want none (Solo Actor has only 1 technique, below the generation minimum)", actors)
	}

	claims := c.RawClaims()
	found := false
	for _, cl := range claims {
		if cl.ActorName == "Solo Actor" && cl.TechniqueID == "T1059" {
			found = true
		}
	}
	if !found {
		t.Fatalf("RawClaims() = %+v, want a claim for Solo Actor/T1059 even though it was filtered from Fetch()'s return value", claims)
	}

	report := c.Completeness()
	if report.Completeness != evidence.Partial {
		t.Fatalf("Completeness() = %+v, want Partial (event 2's detail fetch failed)", report)
	}
}
