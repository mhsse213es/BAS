package connector

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/audspect/bas/internal/intelligence"
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

func TestOpenCTIClient_ConvertCampaign_UsesOwnTechniquesAndObjective(t *testing.T) {
	c := NewOpenCTIClient("http://example.invalid", "test-key", nil)
	actor := &ThreatActor{Name: "APT29"}
	entity := octiRelatedEntity{
		ID: "campaign--1", Name: "SolarWinds Compromise", Description: "Supply chain compromise",
		Objective:      "Espionage",
		AttackPatterns: twoTechniqueConn(),
	}
	campaign := c.convertCampaign(entity, actor)
	if campaign.Name != "SolarWinds Compromise" || campaign.Objective != "Espionage" {
		t.Fatalf("convertCampaign() = %+v, want Name=SolarWinds Compromise Objective=Espionage", campaign)
	}
	if len(campaign.TechniqueIDs) != 2 {
		t.Fatalf("convertCampaign().TechniqueIDs = %v, want 2 (campaign's own techniques, not actor's)", campaign.TechniqueIDs)
	}
	if len(campaign.ThreatActorIDs) != 1 || campaign.ThreatActorIDs[0] != "APT29" {
		t.Fatalf("convertCampaign().ThreatActorIDs = %v, want [APT29]", campaign.ThreatActorIDs)
	}
	if campaign.Source.Provider != "opencti" || campaign.Source.ExternalID != "campaign--1" {
		t.Fatalf("convertCampaign().Source = %+v, want Provider=opencti ExternalID=campaign--1", campaign.Source)
	}
}

func TestOpenCTIClient_ConvertCampaign_IDIsNormalizedNameNotSTIXID(t *testing.T) {
	c := NewOpenCTIClient("http://example.invalid", "test-key", nil)
	actor := &ThreatActor{Name: "APT29"}
	entity := octiRelatedEntity{
		ID: "campaign--abc123", Name: "SolarWinds Compromise", Aliases: []string{"SUNBURST"},
		AttackPatterns: twoTechniqueConn(),
	}
	campaign := c.convertCampaign(entity, actor)
	if campaign.ID != intelligence.NormalizeKey("SolarWinds Compromise") {
		t.Fatalf("convertCampaign().ID = %q, want %q (NormalizeKey of the name, not the raw STIX id)", campaign.ID, intelligence.NormalizeKey("SolarWinds Compromise"))
	}
	if campaign.Source.ExternalID != "campaign--abc123" {
		t.Fatalf("convertCampaign().Source.ExternalID = %q, want the raw STIX id %q (still preserved as provenance, just not the primary ID)", campaign.Source.ExternalID, "campaign--abc123")
	}
	if len(campaign.Aliases) != 1 || campaign.Aliases[0] != "SUNBURST" {
		t.Fatalf("convertCampaign().Aliases = %v, want [SUNBURST]", campaign.Aliases)
	}
}

func TestOpenCTIClient_ConvertMalware_UsesOwnTechniquesAndTypes(t *testing.T) {
	c := NewOpenCTIClient("http://example.invalid", "test-key", nil)
	actor := &ThreatActor{Name: "BlackTech"}
	entity := octiRelatedEntity{
		ID: "malware--1", Name: "TSCookie", Aliases: []string{"PLEAD"},
		MalwareTypes:   []string{"backdoor"},
		AttackPatterns: twoTechniqueConn(),
	}
	malware := c.convertMalware(entity, actor)
	if malware.Name != "TSCookie" || len(malware.MalwareTypes) != 1 || malware.MalwareTypes[0] != "backdoor" {
		t.Fatalf("convertMalware() = %+v, want Name=TSCookie MalwareTypes=[backdoor]", malware)
	}
	if len(malware.TechniqueIDs) != 2 {
		t.Fatalf("convertMalware().TechniqueIDs = %v, want 2 (malware's own techniques)", malware.TechniqueIDs)
	}
	if malware.ID != intelligence.NormalizeKey("TSCookie") {
		t.Fatalf("convertMalware().ID = %q, want %q", malware.ID, intelligence.NormalizeKey("TSCookie"))
	}
}

func TestToolEntitiesFrom_ReadsToSide(t *testing.T) {
	conn := octiRelationshipConnection{
		Edges: []octiRelationshipEdge{
			{Node: struct {
				To   octiRelatedEntity `json:"to"`
				From octiRelatedEntity `json:"from"`
			}{To: octiRelatedEntity{ID: "tool--1", Name: "PsExec", Aliases: []string{"psexec.exe"}}}},
		},
	}
	entities := toolEntitiesFrom(conn)
	if len(entities) != 1 || entities[0].Name != "PsExec" || len(entities[0].Aliases) != 1 || entities[0].Aliases[0] != "psexec.exe" {
		t.Fatalf("toolEntitiesFrom() = %+v, want one entity Name=PsExec Aliases=[psexec.exe]", entities)
	}
}

func TestOpenCTIClient_ConvertTool_UsesOwnTechniques(t *testing.T) {
	c := NewOpenCTIClient("http://example.invalid", "test-key", nil)
	actor := &ThreatActor{Name: "BlackTech"}
	entity := octiRelatedEntity{
		ID: "tool--1", Name: "PsExec", Aliases: []string{"psexec.exe"},
		AttackPatterns: twoTechniqueConn(),
	}
	tool := c.convertTool(entity, actor)
	if tool.Name != "PsExec" || len(tool.Aliases) != 1 || tool.Aliases[0] != "psexec.exe" {
		t.Fatalf("convertTool() = %+v, want Name=PsExec Aliases=[psexec.exe]", tool)
	}
	if len(tool.TechniqueIDs) != 2 {
		t.Fatalf("convertTool().TechniqueIDs = %v, want 2 (tool's own techniques)", tool.TechniqueIDs)
	}
	if tool.ID != intelligence.NormalizeKey("PsExec") {
		t.Fatalf("convertTool().ID = %q, want %q", tool.ID, intelligence.NormalizeKey("PsExec"))
	}
	if len(tool.ThreatActorIDs) != 1 || tool.ThreatActorIDs[0] != "BlackTech" {
		t.Fatalf("convertTool().ThreatActorIDs = %v, want [BlackTech]", tool.ThreatActorIDs)
	}
	if tool.Source.Provider != "opencti" || tool.Source.ExternalID != "tool--1" {
		t.Fatalf("convertTool().Source = %+v, want Provider=opencti ExternalID=tool--1", tool.Source)
	}
}

func TestOpenCTIClient_FetchIntelligence_PopulatedAfterFetch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := octiThreatActorsResp{}
		resp.Data.ThreatActors.Edges = []octiActorEdge{
			{Node: octiThreatActorNode{
				ID: "ta-1", Name: "APT29", AttackPatterns: twoTechniqueConn(),
				Campaigns: octiRelationshipConnection{Edges: []octiRelationshipEdge{
					{Node: struct {
						To   octiRelatedEntity `json:"to"`
						From octiRelatedEntity `json:"from"`
					}{From: octiRelatedEntity{ID: "campaign--1", Name: "SolarWinds Compromise", AttackPatterns: twoTechniqueConn()}}},
				}},
				Malwares: octiRelationshipConnection{Edges: []octiRelationshipEdge{
					{Node: struct {
						To   octiRelatedEntity `json:"to"`
						From octiRelatedEntity `json:"from"`
					}{To: octiRelatedEntity{ID: "malware--1", Name: "TSCookie", AttackPatterns: twoTechniqueConn()}}},
				}},
				Tools: octiRelationshipConnection{Edges: []octiRelationshipEdge{
					{Node: struct {
						To   octiRelatedEntity `json:"to"`
						From octiRelatedEntity `json:"from"`
					}{To: octiRelatedEntity{ID: "tool--1", Name: "PsExec", AttackPatterns: twoTechniqueConn()}}},
				}},
			}},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	c := NewOpenCTIClient(server.URL, "test-key", nil)
	if _, err := c.Fetch(); err != nil {
		t.Fatalf("Fetch: %v", err)
	}

	campaigns, malware, tools, err := c.FetchIntelligence()
	if err != nil {
		t.Fatalf("FetchIntelligence: %v", err)
	}
	if len(campaigns) != 1 || campaigns[0].Name != "SolarWinds Compromise" {
		t.Fatalf("FetchIntelligence() campaigns = %+v, want one named SolarWinds Compromise", campaigns)
	}
	if len(malware) != 1 || malware[0].Name != "TSCookie" {
		t.Fatalf("FetchIntelligence() malware = %+v, want one named TSCookie", malware)
	}
	if len(tools) != 1 || tools[0].Name != "PsExec" {
		t.Fatalf("FetchIntelligence() tools = %+v, want one named PsExec", tools)
	}
}
