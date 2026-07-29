package connector

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/audspect/bas/internal/intelligence"
)

// MISPClient fetches threat-actor TTP profiles from a MISP instance.
type MISPClient struct {
	baseURL       string
	apiKey        string
	httpClient    *http.Client
	sectors       []string
	regions       []string
	lastStat      SourceStat
	lastCampaigns []intelligence.Campaign
	lastMalware   []intelligence.Malware
	lastTools     []intelligence.Tool
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

// Name identifies this source. Implements Source.
func (c *MISPClient) Name() string { return "misp" }

// Fetch returns all threat actors with MITRE ATT&CK technique mappings.
func (c *MISPClient) Fetch() ([]ThreatActor, error) {
	events, err := c.listEvents()
	if err != nil {
		c.lastStat = SourceStat{Name: "misp", Error: err.Error(), FetchedAt: time.Now()}
		return nil, fmt.Errorf("misp list events: %w", err)
	}
	log.Printf("[connector/misp] fetched %d events", len(events))

	actorMap := make(map[string]*ThreatActor)
	var campaigns []intelligence.Campaign
	var malware []intelligence.Malware
	var tools []intelligence.Tool

	for _, ev := range events {
		hasMitre := false
		for _, t := range ev.Tag {
			if strings.Contains(t.Name, "mitre-attack-pattern") || strings.Contains(t.Name, "mitre-attack") {
				hasMitre = true
				break
			}
		}
		if !hasMitre {
			continue
		}

		detail, err := c.getEvent(ev.ID)
		if err != nil {
			log.Printf("[connector/misp] fetch event %s: %v", ev.ID, err)
			continue
		}

		actor := c.extractActor(ev, detail)
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

		campaign, eventMalware, eventTools := c.extractIntelligence(ev, detail, actor)
		if campaign != nil {
			campaigns = append(campaigns, *campaign)
		}
		malware = append(malware, eventMalware...)
		tools = append(tools, eventTools...)
	}

	out := make([]ThreatActor, 0, len(actorMap))
	for _, a := range actorMap {
		if len(a.Techniques) >= 2 {
			out = append(out, *a)
		}
	}
	c.lastStat = SourceStat{Name: "misp", RawCount: len(events), ActorCount: len(out), FetchedAt: time.Now()}
	c.lastCampaigns = campaigns
	c.lastMalware = malware
	c.lastTools = tools
	return out, nil
}

// Stats implements StatsSource.
func (c *MISPClient) Stats() SourceStat { return c.lastStat }

// ── MISP API types ────────────────────────────────────────────────────────────

type mispEventIndex struct {
	ID        string    `json:"id"`
	Info      string    `json:"info"`
	Timestamp string    `json:"timestamp"`
	Tag       []mispTag `json:"Tag"`
}

type mispTag struct {
	Name string `json:"name"`
}

type mispEventDetail struct {
	Event struct {
		ID            string          `json:"id"`
		Info          string          `json:"info"`
		Timestamp     string          `json:"timestamp"`
		Tag           []mispTag       `json:"Tag"`
		GalaxyCluster []mispGalaxy    `json:"GalaxyCluster"`
		Attribute     []mispAttribute `json:"Attribute"`
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

// extractActor builds a ThreatActor from a MISP event index entry and its
// already-fetched detail. detail is fetched once by Fetch()'s loop and
// shared with extractIntelligence to avoid a second per-event API call.
func (c *MISPClient) extractActor(ev mispEventIndex, detail *mispEventDetail) *ThreatActor {
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
	if !passesSectorRegionFilter(actor.Sectors, actor.Regions, c.sectors, c.regions) {
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

// extractIntelligence builds Intelligence Expansion data (Campaign +
// Malware + Tool) from an already-qualified, already-fetched MISP event --
// reuses the same event detail and actor name/techniques extractActor
// already derived, no second fetch. One Campaign per qualifying event (the
// event itself IS the campaign container). Zero or more Malware/Tool
// records, one per mitre-malware/mitre-tool GalaxyCluster entry
// respectively. Both inherit the SAME technique/actor association as the
// event's actor -- MISP's flat galaxy list doesn't support finer per-entry
// technique attribution without deeper relationship parsing, which this
// client deliberately doesn't attempt.
func (c *MISPClient) extractIntelligence(ev mispEventIndex, detail *mispEventDetail, actor *ThreatActor) (*intelligence.Campaign, []intelligence.Malware, []intelligence.Tool) {
	src := intelligence.SourceRef{
		Provider: "misp", ExternalID: ev.ID,
		LastUpdated: actor.LastSeen, Confidence: actor.Confidence,
	}
	if src.LastUpdated.IsZero() {
		src.LastUpdated = time.Now()
	}

	campaign := &intelligence.Campaign{
		ID: ev.ID, Name: detail.Event.Info, Description: detail.Event.Info,
		ThreatActorIDs: []string{actor.Name}, TechniqueIDs: techniqueIDs(actor.Techniques),
		Source: src,
	}

	var malware []intelligence.Malware
	var tools []intelligence.Tool
	for _, gc := range detail.Event.GalaxyCluster {
		name := strings.TrimSpace(gc.Value)
		if name == "" {
			continue
		}
		switch gc.Type {
		case "mitre-malware":
			malware = append(malware, intelligence.Malware{
				ID: intelligence.MalwareKey(name), Name: name,
				TechniqueIDs: techniqueIDs(actor.Techniques),
				ThreatActorIDs: []string{actor.Name}, CampaignIDs: []string{ev.ID},
				Source: src,
			})
		case "mitre-tool":
			tools = append(tools, intelligence.Tool{
				ID: intelligence.MalwareKey(name), Name: name,
				TechniqueIDs: techniqueIDs(actor.Techniques),
				ThreatActorIDs: []string{actor.Name}, CampaignIDs: []string{ev.ID},
				Source: src,
			})
		}
	}
	return campaign, malware, tools
}

func techniqueIDs(techs []TechniqueRef) []string {
	ids := make([]string, 0, len(techs))
	for _, t := range techs {
		ids = append(ids, t.ID)
	}
	return ids
}

// FetchIntelligence implements IntelligenceSource -- returns the Campaign/
// Malware data gathered during the most recent Fetch() call, the same
// after-the-fact-accessor pattern Stats() already uses for lastStat.
func (c *MISPClient) FetchIntelligence() ([]intelligence.Campaign, []intelligence.Malware, error) {
	return c.lastCampaigns, c.lastMalware, nil
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

// passesSectorRegionFilter reports whether an actor should be kept, given
// the client's configured sector/region filters. An empty filter on either
// axis means "no restriction" for that axis — this fixes a bug where the
// region filter was accepted (stored on MISPClient, passed via
// NewMISPClient) but never actually applied; only the sector filter was.
// See docs/superpowers/specs/2026-07-19-sp5-sector-region-weighting-design.md.
func passesSectorRegionFilter(actorSectors, actorRegions, filterSectors, filterRegions []string) bool {
	if len(filterSectors) > 0 && !intersects(actorSectors, filterSectors) {
		return false
	}
	if len(filterRegions) > 0 && !intersects(actorRegions, filterRegions) {
		return false
	}
	return true
}
