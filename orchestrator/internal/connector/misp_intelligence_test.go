package connector

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/audspect/bas/internal/intelligence"
)

// mispServer builds a mock MISP server serving both /events/index (the
// event list) and /events/{id} (per-event detail) from the given detail
// map, keyed by event ID -- the two-call flow extractIntelligence's tests
// need, matching the real listEvents+getEvent sequence Fetch() performs.
func mispServer(t *testing.T, index []mispEventIndex, details map[string]mispEventDetail) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/events/index" {
			json.NewEncoder(w).Encode(index)
			return
		}
		for id, d := range details {
			if r.URL.Path == "/events/"+id {
				json.NewEncoder(w).Encode(d)
				return
			}
		}
		t.Fatalf("unexpected request path: %s", r.URL.Path)
	}))
}

func MalwareKeyForTest(name string) string { return intelligence.NormalizeKey(name) }

func TestMISPClient_FetchIntelligence_OneCampaignNoMalware(t *testing.T) {
	index := []mispEventIndex{
		{ID: "1", Info: "APT36 Kill Chain", Timestamp: "1700000000", Tag: []mispTag{{Name: "mitre-attack-pattern"}}},
	}
	details := map[string]mispEventDetail{
		"1": {Event: struct {
			ID            string          `json:"id"`
			Info          string          `json:"info"`
			Timestamp     string          `json:"timestamp"`
			Tag           []mispTag       `json:"Tag"`
			GalaxyCluster []mispGalaxy    `json:"GalaxyCluster"`
			Attribute     []mispAttribute `json:"Attribute"`
		}{
			ID: "1", Info: "APT36 Kill Chain",
			Tag: []mispTag{{Name: "misp-galaxy:threat-actor=\"APT36\""}},
			GalaxyCluster: []mispGalaxy{
				{Type: "mitre-attack-pattern", Value: "PowerShell", Meta: struct {
					ExternalID []string `json:"external_id"`
					KillChain  []string `json:"kill_chain"`
				}{ExternalID: []string{"T1059.001"}, KillChain: []string{"mitre-attack:execution"}}},
				{Type: "mitre-attack-pattern", Value: "Phishing", Meta: struct {
					ExternalID []string `json:"external_id"`
					KillChain  []string `json:"kill_chain"`
				}{ExternalID: []string{"T1566.001"}, KillChain: []string{"mitre-attack:initial-access"}}},
			},
		}},
	}
	server := mispServer(t, index, details)
	defer server.Close()

	c := NewMISPClient(server.URL, "test-key", nil, nil)
	actors, err := c.Fetch()
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(actors) != 1 {
		t.Fatalf("actors = %+v, want 1", actors)
	}

	campaigns, malware, _, err := c.FetchIntelligence()
	if err != nil {
		t.Fatalf("FetchIntelligence: %v", err)
	}
	if len(campaigns) != 1 {
		t.Fatalf("campaigns = %+v, want 1", campaigns)
	}
	if campaigns[0].ID != MalwareKeyForTest("APT36 Kill Chain") || campaigns[0].Name != "APT36 Kill Chain" {
		t.Errorf("campaign = %+v, want ID=NormalizeKey(APT36 Kill Chain) Name=%q", campaigns[0], "APT36 Kill Chain")
	}
	if len(campaigns[0].TechniqueIDs) != 2 {
		t.Errorf("campaign TechniqueIDs = %v, want 2 entries", campaigns[0].TechniqueIDs)
	}
	if len(campaigns[0].ThreatActorIDs) != 1 || campaigns[0].ThreatActorIDs[0] != "APT36" {
		t.Errorf("campaign ThreatActorIDs = %v, want [APT36]", campaigns[0].ThreatActorIDs)
	}
	if len(malware) != 0 {
		t.Fatalf("malware = %+v, want none (no mitre-malware cluster in this event)", malware)
	}
}

func TestMISPClient_FetchIntelligence_MultipleMalwareClusters(t *testing.T) {
	index := []mispEventIndex{
		{ID: "2", Info: "Emotet/Trickbot Campaign", Timestamp: "1700000000", Tag: []mispTag{{Name: "mitre-attack-pattern"}}},
	}
	details := map[string]mispEventDetail{
		"2": {Event: struct {
			ID            string          `json:"id"`
			Info          string          `json:"info"`
			Timestamp     string          `json:"timestamp"`
			Tag           []mispTag       `json:"Tag"`
			GalaxyCluster []mispGalaxy    `json:"GalaxyCluster"`
			Attribute     []mispAttribute `json:"Attribute"`
		}{
			ID: "2", Info: "Emotet/Trickbot Campaign",
			GalaxyCluster: []mispGalaxy{
				{Type: "mitre-attack-pattern", Value: "PowerShell", Meta: struct {
					ExternalID []string `json:"external_id"`
					KillChain  []string `json:"kill_chain"`
				}{ExternalID: []string{"T1059.001"}}},
				{Type: "mitre-attack-pattern", Value: "Scheduled Task", Meta: struct {
					ExternalID []string `json:"external_id"`
					KillChain  []string `json:"kill_chain"`
				}{ExternalID: []string{"T1053.005"}}},
				{Type: "mitre-malware", Value: "Emotet"},
				{Type: "mitre-malware", Value: "Trickbot"},
				{Type: "mitre-intrusion-set", Value: "SomeIntrusionSet"}, // not mitre-malware -- must not become a Malware entry
			},
		}},
	}
	server := mispServer(t, index, details)
	defer server.Close()

	c := NewMISPClient(server.URL, "test-key", nil, nil)
	if _, err := c.Fetch(); err != nil {
		t.Fatalf("Fetch: %v", err)
	}

	_, malware, _, err := c.FetchIntelligence()
	if err != nil {
		t.Fatalf("FetchIntelligence: %v", err)
	}
	if len(malware) != 2 {
		t.Fatalf("malware = %+v, want 2 entries (Emotet, Trickbot)", malware)
	}
	names := map[string]bool{malware[0].Name: true, malware[1].Name: true}
	if !names["Emotet"] || !names["Trickbot"] {
		t.Errorf("malware names = %v, want Emotet and Trickbot", names)
	}
	for _, m := range malware {
		if m.ID != MalwareKeyForTest(m.Name) {
			t.Errorf("malware ID = %q, want normalized key of %q", m.ID, m.Name)
		}
		if len(m.TechniqueIDs) != 2 {
			t.Errorf("malware %q TechniqueIDs = %v, want the event's 2 techniques", m.Name, m.TechniqueIDs)
		}
		if len(m.CampaignIDs) != 1 || m.CampaignIDs[0] != MalwareKeyForTest("Emotet/Trickbot Campaign") {
			t.Errorf("malware %q CampaignIDs = %v, want [%q] (the campaign's own normalized ID, not the raw MISP event ID)", m.Name, m.CampaignIDs, MalwareKeyForTest("Emotet/Trickbot Campaign"))
		}
	}
}

// TestMISPClient_FetchIntelligence_ExtractsTools validates extraction against
// the "mitre-tool" galaxy cluster type -- confirmed live against a real MISP
// instance (2026-07-29): galaxy id 75, type "mitre-tool", namespace
// "mitre-attack" (same namespace as the already-used mitre-malware/
// mitre-attack-pattern/mitre-intrusion-set galaxies), with 97 real ATT&CK
// Software clusters loaded (e.g. "Windows Credential Editor - S0005",
// "Pass-The-Hash Toolkit - S0122"). Not a guess.
func TestMISPClient_FetchIntelligence_ExtractsTools(t *testing.T) {
	index := []mispEventIndex{
		{ID: "3", Info: "Living-off-the-Land Toolkit Event", Timestamp: "1700000000", Tag: []mispTag{{Name: "mitre-attack-pattern"}}},
	}
	details := map[string]mispEventDetail{
		"3": {Event: struct {
			ID            string          `json:"id"`
			Info          string          `json:"info"`
			Timestamp     string          `json:"timestamp"`
			Tag           []mispTag       `json:"Tag"`
			GalaxyCluster []mispGalaxy    `json:"GalaxyCluster"`
			Attribute     []mispAttribute `json:"Attribute"`
		}{
			ID: "3", Info: "Living-off-the-Land Toolkit Event",
			GalaxyCluster: []mispGalaxy{
				{Type: "mitre-attack-pattern", Value: "PowerShell", Meta: struct {
					ExternalID []string `json:"external_id"`
					KillChain  []string `json:"kill_chain"`
				}{ExternalID: []string{"T1059.001"}}},
				{Type: "mitre-attack-pattern", Value: "Remote System Discovery", Meta: struct {
					ExternalID []string `json:"external_id"`
					KillChain  []string `json:"kill_chain"`
				}{ExternalID: []string{"T1018"}}},
				{Type: "mitre-tool", Value: "PsExec"},
				{Type: "mitre-tool", Value: "AdFind"},
				{Type: "mitre-malware", Value: "NotATool"}, // wrong type -- must not become a Tool entry
			},
		}},
	}
	server := mispServer(t, index, details)
	defer server.Close()

	c := NewMISPClient(server.URL, "test-key", nil, nil)
	if _, err := c.Fetch(); err != nil {
		t.Fatalf("Fetch: %v", err)
	}

	_, _, tools, err := c.FetchIntelligence()
	if err != nil {
		t.Fatalf("FetchIntelligence: %v", err)
	}
	if len(tools) != 2 {
		t.Fatalf("tools = %+v, want 2 entries (PsExec, AdFind)", tools)
	}
	names := map[string]bool{tools[0].Name: true, tools[1].Name: true}
	if !names["PsExec"] || !names["AdFind"] {
		t.Errorf("tool names = %v, want PsExec and AdFind", names)
	}
	for _, tl := range tools {
		if tl.ID != MalwareKeyForTest(tl.Name) {
			t.Errorf("tool ID = %q, want normalized key of %q", tl.ID, tl.Name)
		}
		if len(tl.TechniqueIDs) != 2 {
			t.Errorf("tool %q TechniqueIDs = %v, want the event's 2 techniques", tl.Name, tl.TechniqueIDs)
		}
		if len(tl.CampaignIDs) != 1 || tl.CampaignIDs[0] != MalwareKeyForTest("Living-off-the-Land Toolkit Event") {
			t.Errorf("tool %q CampaignIDs = %v, want [%q] (the campaign's own normalized ID, not the raw MISP event ID)", tl.Name, tl.CampaignIDs, MalwareKeyForTest("Living-off-the-Land Toolkit Event"))
		}
	}
}

func TestMISPClient_FetchIntelligence_MalwareCampaignIDMatchesCampaignID(t *testing.T) {
	index := []mispEventIndex{
		{ID: "4", Info: "Consistency Check Event", Timestamp: "1700000000", Tag: []mispTag{{Name: "mitre-attack-pattern"}}},
	}
	details := map[string]mispEventDetail{
		"4": {Event: struct {
			ID            string          `json:"id"`
			Info          string          `json:"info"`
			Timestamp     string          `json:"timestamp"`
			Tag           []mispTag       `json:"Tag"`
			GalaxyCluster []mispGalaxy    `json:"GalaxyCluster"`
			Attribute     []mispAttribute `json:"Attribute"`
		}{
			ID: "4", Info: "Consistency Check Event",
			GalaxyCluster: []mispGalaxy{
				{Type: "mitre-attack-pattern", Value: "PowerShell", Meta: struct {
					ExternalID []string `json:"external_id"`
					KillChain  []string `json:"kill_chain"`
				}{ExternalID: []string{"T1059.001"}}},
				{Type: "mitre-attack-pattern", Value: "Phishing", Meta: struct {
					ExternalID []string `json:"external_id"`
					KillChain  []string `json:"kill_chain"`
				}{ExternalID: []string{"T1566.001"}}},
				{Type: "mitre-malware", Value: "ConsistencyMalware"},
			},
		}},
	}
	server := mispServer(t, index, details)
	defer server.Close()

	c := NewMISPClient(server.URL, "test-key", nil, nil)
	if _, err := c.Fetch(); err != nil {
		t.Fatalf("Fetch: %v", err)
	}

	campaigns, malware, _, err := c.FetchIntelligence()
	if err != nil {
		t.Fatalf("FetchIntelligence: %v", err)
	}
	if len(campaigns) != 1 || len(malware) != 1 {
		t.Fatalf("campaigns = %+v, malware = %+v, want 1 each", campaigns, malware)
	}
	if campaigns[0].ID != MalwareKeyForTest("Consistency Check Event") {
		t.Fatalf("Campaign.ID = %q, want NormalizeKey of the event title, %q", campaigns[0].ID, MalwareKeyForTest("Consistency Check Event"))
	}
	if len(malware[0].CampaignIDs) != 1 || malware[0].CampaignIDs[0] != campaigns[0].ID {
		t.Fatalf("Malware.CampaignIDs = %v, want [%q] (must match the sibling Campaign's own ID, not the raw MISP event ID)", malware[0].CampaignIDs, campaigns[0].ID)
	}
}
