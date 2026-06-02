package connector

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"
)

// MISPClient fetches threat-actor TTP profiles from a MISP instance.
type MISPClient struct {
	baseURL    string
	apiKey     string
	httpClient *http.Client
	sectors    []string
	regions    []string
}

// NewMISPClient creates a MISP client. Skips TLS verification for self-signed
// certs common in air-gapped MISP deployments.
func NewMISPClient(baseURL, apiKey string, sectors, regions []string) *MISPClient {
	return &MISPClient{
		baseURL: strings.TrimRight(baseURL, "/"),
		apiKey:  apiKey,
		sectors: sectors,
		regions: regions,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		},
	}
}

// Fetch returns all threat actors with MITRE ATT&CK technique mappings.
func (c *MISPClient) Fetch() ([]ThreatActor, error) {
	events, err := c.listEvents()
	if err != nil {
		return nil, fmt.Errorf("misp list events: %w", err)
	}
	log.Printf("[connector/misp] fetched %d events", len(events))

	actorMap := make(map[string]*ThreatActor)
	for _, ev := range events {
		actor := c.extractActor(ev)
		if actor == nil || len(actor.Techniques) < 2 {
			continue
		}
		// Merge by actor name (same actor may appear in multiple events)
		if existing, ok := actorMap[actor.Name]; ok {
			existing.Techniques = mergeTechniques(existing.Techniques, actor.Techniques)
			if actor.LastSeen.After(existing.LastSeen) {
				existing.LastSeen = actor.LastSeen
				existing.SourceID = actor.SourceID
			}
		} else {
			actorMap[actor.Name] = actor
		}
	}

	out := make([]ThreatActor, 0, len(actorMap))
	for _, a := range actorMap {
		if len(a.Techniques) >= 2 {
			out = append(out, *a)
		}
	}
	return out, nil
}

// ── MISP API types ────────────────────────────────────────────────────────────

type mispEventIndex struct {
	ID        string      `json:"id"`
	Info      string      `json:"info"`
	Timestamp string      `json:"timestamp"`
	Tag       []mispTag   `json:"Tag"`
}

type mispTag struct {
	Name string `json:"name"`
}

type mispEventDetail struct {
	Event struct {
		ID             string           `json:"id"`
		Info           string           `json:"info"`
		Timestamp      string           `json:"timestamp"`
		Tag            []mispTag        `json:"Tag"`
		GalaxyCluster  []mispGalaxy     `json:"GalaxyCluster"`
		Attribute      []mispAttribute  `json:"Attribute"`
	} `json:"Event"`
}

type mispGalaxy struct {
	Type  string `json:"type"`
	Value string `json:"value"`
	Meta  struct {
		ExternalID []string `json:"external_id"`
		KillChain  []string `json:"kill_chain"`
	} `json:"meta"`
}

type mispAttribute struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// ── helpers ───────────────────────────────────────────────────────────────────

func (c *MISPClient) listEvents() ([]mispEventIndex, error) {
	req, err := http.NewRequest("GET", c.baseURL+"/events/index", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", c.apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("MISP returned HTTP %d", resp.StatusCode)
	}

	var events []mispEventIndex
	if err := json.NewDecoder(resp.Body).Decode(&events); err != nil {
		return nil, fmt.Errorf("decode events: %w", err)
	}
	return events, nil
}

func (c *MISPClient) getEvent(id string) (*mispEventDetail, error) {
	req, err := http.NewRequest("GET", c.baseURL+"/events/"+id, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", c.apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("MISP event %s returned HTTP %d", id, resp.StatusCode)
	}
	var detail mispEventDetail
	if err := json.NewDecoder(resp.Body).Decode(&detail); err != nil {
		return nil, fmt.Errorf("decode event %s: %w", id, err)
	}
	return &detail, nil
}

// extractActor builds a ThreatActor from a MISP event index entry.
// Fetches the full event only when the index entry has ATT&CK-related tags.
func (c *MISPClient) extractActor(ev mispEventIndex) *ThreatActor {
	// Quick pre-filter: must have mitre tag
	hasMitre := false
	for _, t := range ev.Tag {
		if strings.Contains(t.Name, "mitre-attack-pattern") || strings.Contains(t.Name, "mitre-attack") {
			hasMitre = true
			break
		}
	}
	if !hasMitre {
		return nil
	}

	detail, err := c.getEvent(ev.ID)
	if err != nil {
		log.Printf("[connector/misp] fetch event %s: %v", ev.ID, err)
		return nil
	}

	actor := &ThreatActor{
		Source:   "misp",
		SourceID: ev.ID,
	}

	// Extract actor name and sectors from tags
	for _, tag := range detail.Event.Tag {
		name := tag.Name
		switch {
		case strings.HasPrefix(name, "misp-galaxy:threat-actor="):
			actor.Name = strings.Trim(strings.TrimPrefix(name, "misp-galaxy:threat-actor="), `"`)
		case strings.HasPrefix(name, "misp-galaxy:mitre-intrusion-set="):
			if actor.Name == "" {
				actor.Name = strings.Trim(strings.TrimPrefix(name, "misp-galaxy:mitre-intrusion-set="), `"`)
			}
		case strings.Contains(name, "sector:"):
			actor.Sectors = append(actor.Sectors, strings.TrimPrefix(name, "sector:"))
		case strings.Contains(name, "region:"):
			actor.Regions = append(actor.Regions, strings.TrimPrefix(name, "region:"))
		case strings.Contains(name, "confidence:"):
			actor.Confidence = strings.TrimPrefix(name, "confidence:")
		}
	}

	if actor.Name == "" {
		actor.Name = sanitiseEventName(detail.Event.Info)
	}
	if actor.Confidence == "" {
		actor.Confidence = "medium"
	}

	// Apply sector/region filter
	if len(c.sectors) > 0 && !intersects(actor.Sectors, c.sectors) {
		return nil
	}

	// Extract techniques from GalaxyCluster (preferred — structured)
	for _, gc := range detail.Event.GalaxyCluster {
		if gc.Type != "mitre-attack-pattern" {
			continue
		}
		for _, extID := range gc.Meta.ExternalID {
			extID = strings.ToUpper(strings.TrimSpace(extID))
			if isATTACKID(extID) {
				tactic := ""
				if len(gc.Meta.KillChain) > 0 {
					// kill_chain format: "mitre-attack:execution"
					parts := strings.SplitN(gc.Meta.KillChain[0], ":", 2)
					if len(parts) == 2 {
						tactic = parts[1]
					}
				}
				actor.Techniques = append(actor.Techniques, TechniqueRef{
					ID:     extID,
					Name:   gc.Value,
					Tactic: tactic,
				})
			}
		}
	}

	// Also extract from attributes with type mitre-attack-pattern
	for _, attr := range detail.Event.Attribute {
		if attr.Type == "mitre-attack-pattern" {
			id := strings.ToUpper(strings.TrimSpace(attr.Value))
			if isATTACKID(id) {
				actor.Techniques = append(actor.Techniques, TechniqueRef{ID: id})
			}
		}
	}

	actor.Techniques = dedupTechniques(actor.Techniques)
	actor.Description = detail.Event.Info

	ts := ev.Timestamp
	if t, err := parseTimestamp(ts); err == nil {
		actor.LastSeen = t
	}

	return actor
}

func sanitiseEventName(info string) string {
	// Use first word that looks like a threat actor
	words := strings.Fields(info)
	for _, w := range words {
		if len(w) >= 3 && !strings.ContainsAny(w, ".,;:!?") {
			return w
		}
	}
	return "Unknown"
}

func isATTACKID(s string) bool {
	if len(s) < 5 {
		return false
	}
	return s[0] == 'T' && s[1] >= '1' && s[1] <= '9'
}

func parseTimestamp(ts string) (time.Time, error) {
	// MISP timestamps are Unix epoch as string
	var epoch int64
	if _, err := fmt.Sscanf(ts, "%d", &epoch); err == nil {
		return time.Unix(epoch, 0), nil
	}
	return time.Parse(time.RFC3339, ts)
}

func dedupTechniques(techs []TechniqueRef) []TechniqueRef {
	seen := make(map[string]bool)
	var out []TechniqueRef
	for _, t := range techs {
		if !seen[t.ID] {
			seen[t.ID] = true
			out = append(out, t)
		}
	}
	return out
}

func mergeTechniques(a, b []TechniqueRef) []TechniqueRef {
	return dedupTechniques(append(a, b...))
}

func intersects(a, b []string) bool {
	for _, x := range a {
		for _, y := range b {
			if strings.EqualFold(x, y) {
				return true
			}
		}
	}
	return false
}
