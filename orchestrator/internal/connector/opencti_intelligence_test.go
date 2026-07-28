package connector

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestTechniqueRefsFrom_ExtractsValidATTACKIDs(t *testing.T) {
	conn := octiRelationshipConnection{
		Edges: []octiRelationshipEdge{
			{Node: struct {
				To   octiRelatedEntity `json:"to"`
				From octiRelatedEntity `json:"from"`
			}{To: octiRelatedEntity{XMitreID: "t1059.001", Name: "PowerShell"}}},
			{Node: struct {
				To   octiRelatedEntity `json:"to"`
				From octiRelatedEntity `json:"from"`
			}{To: octiRelatedEntity{XMitreID: "not-an-id", Name: "Junk"}}},
		},
	}
	refs := techniqueRefsFrom(conn)
	if len(refs) != 1 {
		t.Fatalf("techniqueRefsFrom() returned %d refs, want 1 (invalid ID should be filtered)", len(refs))
	}
	if refs[0].ID != "T1059.001" || refs[0].Name != "PowerShell" {
		t.Fatalf("techniqueRefsFrom()[0] = %+v, want ID=T1059.001 Name=PowerShell", refs[0])
	}
}

func TestTechniqueRefsFrom_UsesFirstKillChainPhaseAsTactic(t *testing.T) {
	conn := octiRelationshipConnection{
		Edges: []octiRelationshipEdge{
			{Node: struct {
				To   octiRelatedEntity `json:"to"`
				From octiRelatedEntity `json:"from"`
			}{To: octiRelatedEntity{
				XMitreID: "T1059",
				Name:     "Command Interpreter",
				KillChainPhases: []struct {
					PhaseName string `json:"phase_name"`
				}{{PhaseName: "execution"}},
			}}},
		},
	}
	refs := techniqueRefsFrom(conn)
	if len(refs) != 1 || refs[0].Tactic != "execution" {
		t.Fatalf("techniqueRefsFrom() = %+v, want one ref with Tactic=execution", refs)
	}
}

func TestCampaignEntitiesFrom_ReadsFromSide(t *testing.T) {
	conn := octiRelationshipConnection{
		Edges: []octiRelationshipEdge{
			{Node: struct {
				To   octiRelatedEntity `json:"to"`
				From octiRelatedEntity `json:"from"`
			}{From: octiRelatedEntity{ID: "campaign--1", Name: "Operation Ghost", Objective: "Espionage"}}},
		},
	}
	entities := campaignEntitiesFrom(conn)
	if len(entities) != 1 || entities[0].Name != "Operation Ghost" || entities[0].Objective != "Espionage" {
		t.Fatalf("campaignEntitiesFrom() = %+v, want one entity Name=Operation Ghost Objective=Espionage", entities)
	}
}

func TestMalwareEntitiesFrom_ReadsToSide(t *testing.T) {
	conn := octiRelationshipConnection{
		Edges: []octiRelationshipEdge{
			{Node: struct {
				To   octiRelatedEntity `json:"to"`
				From octiRelatedEntity `json:"from"`
			}{To: octiRelatedEntity{ID: "malware--1", Name: "TSCookie", MalwareTypes: []string{"backdoor"}}}},
		},
	}
	entities := malwareEntitiesFrom(conn)
	if len(entities) != 1 || entities[0].Name != "TSCookie" || len(entities[0].MalwareTypes) != 1 || entities[0].MalwareTypes[0] != "backdoor" {
		t.Fatalf("malwareEntitiesFrom() = %+v, want one entity Name=TSCookie MalwareTypes=[backdoor]", entities)
	}
}

func TestOpenCTIClient_Fetch_MergesThreatActorsAndIntrusionSets(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := octiThreatActorsResp{}
		resp.Data.ThreatActors.Edges = []octiActorEdge{
			{Node: octiThreatActorNode{ID: "ta-1", Name: "FromThreatActors", AttackPatterns: twoTechniqueConn()}},
		}
		resp.Data.IntrusionSets.Edges = []octiActorEdge{
			{Node: octiThreatActorNode{ID: "is-1", Name: "FromIntrusionSets", AttackPatterns: twoTechniqueConn()}},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	c := NewOpenCTIClient(server.URL, "test-key", nil)
	actors, err := c.Fetch()
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(actors) != 2 {
		t.Fatalf("Fetch() returned %d actors, want 2 (one from threatActors, one from intrusionSets)", len(actors))
	}
	names := map[string]bool{actors[0].Name: true, actors[1].Name: true}
	if !names["FromThreatActors"] || !names["FromIntrusionSets"] {
		t.Fatalf("Fetch() actors = %+v, want both FromThreatActors and FromIntrusionSets", actors)
	}
}

// twoTechniqueConn builds a relationship connection with 2 valid ATT&CK
// technique edges -- the minimum Fetch()'s "2+ techniques" filter requires
// to keep an actor.
func twoTechniqueConn() octiRelationshipConnection {
	return octiRelationshipConnection{Edges: []octiRelationshipEdge{
		{Node: struct {
			To   octiRelatedEntity `json:"to"`
			From octiRelatedEntity `json:"from"`
		}{To: octiRelatedEntity{XMitreID: "T1059", Name: "Command Interpreter"}}},
		{Node: struct {
			To   octiRelatedEntity `json:"to"`
			From octiRelatedEntity `json:"from"`
		}{To: octiRelatedEntity{XMitreID: "T1105", Name: "Ingress Tool Transfer"}}},
	}}
}
