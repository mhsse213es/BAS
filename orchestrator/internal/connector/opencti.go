package connector

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/audspect/bas/internal/intelligence"
)

// OpenCTIClient fetches threat-actor TTP profiles from an OpenCTI instance.
type OpenCTIClient struct {
	baseURL    string
	apiKey     string
	httpClient *http.Client
	// sectors is currently unused: unlike MISP, OpenCTI's GraphQL query
	// (octiThreatActorNode) never fetches sector/region relationship data,
	// so ThreatActor.Sectors/Regions are always empty for OpenCTI-sourced
	// actors. Wiring a filter check against always-empty data here would
	// silently reject every OpenCTI actor once ThreatIntelSectors is
	// configured — a regression, not a fix. Left unused deliberately,
	// documented rather than silently fixed incorrectly. Properly
	// supporting this needs OpenCTI's actual sector/region GraphQL schema,
	// which can't be verified without a live instance. See
	// docs/superpowers/specs/2026-07-19-sp5-sector-region-weighting-design.md.
	sectors       []string
	lastStat      SourceStat
	lastCampaigns []intelligence.Campaign
	lastMalware   []intelligence.Malware
	lastTools     []intelligence.Tool
}

// NewOpenCTIClient creates an OpenCTI GraphQL client.
func NewOpenCTIClient(baseURL, apiKey string, sectors []string) *OpenCTIClient {
	return &OpenCTIClient{
		baseURL:    strings.TrimRight(baseURL, "/"),
		apiKey:     apiKey,
		sectors:    sectors,
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
}

// Name identifies this source. Implements Source.
func (c *OpenCTIClient) Name() string { return "opencti" }

// Fetch returns threat actors with their MITRE ATT&CK technique mappings.
func (c *OpenCTIClient) Fetch() ([]ThreatActor, error) {
	actorsRaw, err := c.queryThreatActors()
	if err != nil {
		c.lastStat = SourceStat{Name: "opencti", Error: err.Error(), FetchedAt: time.Now()}
		return nil, fmt.Errorf("opencti query actors: %w", err)
	}
	log.Printf("[connector/opencti] fetched %d threat actors", len(actorsRaw))

	var actors []ThreatActor
	var campaigns []intelligence.Campaign
	var malware []intelligence.Malware
	var tools []intelligence.Tool
	for _, raw := range actorsRaw {
		actor := c.convertActor(raw)
		if actor == nil || len(actor.Techniques) < 2 {
			continue
		}
		actors = append(actors, *actor)

		for _, entity := range campaignEntitiesFrom(raw.Campaigns) {
			campaigns = append(campaigns, c.convertCampaign(entity, actor))
		}
		for _, entity := range malwareEntitiesFrom(raw.Malwares) {
			malware = append(malware, c.convertMalware(entity, actor))
		}
		for _, entity := range toolEntitiesFrom(raw.Tools) {
			tools = append(tools, c.convertTool(entity, actor))
		}
	}
	c.lastStat = SourceStat{Name: "opencti", RawCount: len(actorsRaw), ActorCount: len(actors), FetchedAt: time.Now()}
	c.lastCampaigns = campaigns
	c.lastMalware = malware
	c.lastTools = tools
	return actors, nil
}

// Stats implements StatsSource.
func (c *OpenCTIClient) Stats() SourceStat { return c.lastStat }

// ── GraphQL types ─────────────────────────────────────────────────────────────

type octiGQLRequest struct {
	Query     string                 `json:"query"`
	Variables map[string]interface{} `json:"variables,omitempty"`
}

// octiRelatedEntity is the flat, polymorphic shape of one stixCoreRelationships
// edge's "to" (or "from") object -- a superset of AttackPattern/Campaign/
// Malware fields. Unused fields for a given target type are simply absent in
// that GraphQL response and stay zero-valued; this lets one Go type back
// every relationship extraction in this file instead of one per target type.
type octiRelatedEntity struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Aliases     []string `json:"aliases"`
	XMitreID    string   `json:"x_mitre_id"`
	KillChainPhases []struct {
		PhaseName string `json:"phase_name"`
	} `json:"killChainPhases"`
	Objective      string                     `json:"objective"`
	MalwareTypes   []string                   `json:"malware_types"`
	AttackPatterns octiRelationshipConnection `json:"attackPatterns"`
}

type octiRelationshipEdge struct {
	Node struct {
		To   octiRelatedEntity `json:"to"`
		From octiRelatedEntity `json:"from"`
	} `json:"node"`
}

type octiRelationshipConnection struct {
	Edges []octiRelationshipEdge `json:"edges"`
}

type octiThreatActorNode struct {
	ID             string                     `json:"id"`
	Name           string                     `json:"name"`
	Aliases        []string                   `json:"aliases"`
	Description    string                     `json:"description"`
	Confidence     int                        `json:"confidence"` // 0-100
	Modified       string                     `json:"modified"`
	AttackPatterns octiRelationshipConnection `json:"attackPatterns"`
	Campaigns      octiRelationshipConnection `json:"campaigns"`
	Malwares       octiRelationshipConnection `json:"malwares"`
	Tools          octiRelationshipConnection `json:"tools"`
}

// techniqueRefsFrom extracts TechniqueRef entries from a "uses"->Attack-Pattern
// connection -- shared by actor, campaign, and malware conversion so the
// ID-validation/tactic-parsing rule lives in exactly one place.
func techniqueRefsFrom(conn octiRelationshipConnection) []TechniqueRef {
	var out []TechniqueRef
	for _, e := range conn.Edges {
		id := strings.ToUpper(strings.TrimSpace(e.Node.To.XMitreID))
		if !isATTACKID(id) {
			continue
		}
		tactic := ""
		if len(e.Node.To.KillChainPhases) > 0 {
			tactic = e.Node.To.KillChainPhases[0].PhaseName
		}
		out = append(out, TechniqueRef{ID: id, Name: e.Node.To.Name, Tactic: tactic})
	}
	return out
}

// campaignEntitiesFrom extracts campaign identity from an "attributed-to"
// connection queried via fromTypes: ["Campaign"] -- the actor is the "to"
// side of this relationship, so the campaign is on "from". See the
// relationship-direction table in
// docs/superpowers/specs/2026-07-28-intelligence-expansion-phase2-design.md.
func campaignEntitiesFrom(conn octiRelationshipConnection) []octiRelatedEntity {
	out := make([]octiRelatedEntity, 0, len(conn.Edges))
	for _, e := range conn.Edges {
		out = append(out, e.Node.From)
	}
	return out
}

// malwareEntitiesFrom extracts malware identity from a "uses"->Malware
// connection -- the actor is the "from" side, malware is "to", same
// convention as techniqueRefsFrom's Attack-Pattern connections.
func malwareEntitiesFrom(conn octiRelationshipConnection) []octiRelatedEntity {
	out := make([]octiRelatedEntity, 0, len(conn.Edges))
	for _, e := range conn.Edges {
		out = append(out, e.Node.To)
	}
	return out
}

// toolEntitiesFrom extracts tool identity from a "uses"->Tool connection --
// the actor is the "from" side, tool is "to", same convention as
// malwareEntitiesFrom.
func toolEntitiesFrom(conn octiRelationshipConnection) []octiRelatedEntity {
	out := make([]octiRelatedEntity, 0, len(conn.Edges))
	for _, e := range conn.Edges {
		out = append(out, e.Node.To)
	}
	return out
}

type octiActorEdge struct {
	Node octiThreatActorNode `json:"node"`
}

type octiActorConnection struct {
	Edges []octiActorEdge `json:"edges"`
}

type octiThreatActorsResp struct {
	Data struct {
		ThreatActors  octiActorConnection `json:"threatActors"`
		IntrusionSets octiActorConnection `json:"intrusionSets"`
	} `json:"data"`
	Errors []struct {
		Message string `json:"message"`
	} `json:"errors"`
}

// ── query ─────────────────────────────────────────────────────────────────────

const actorFieldsFragment = `
        id
        name
        aliases
        description
        confidence
        modified
        attackPatterns: stixCoreRelationships(
          relationship_type: "uses"
          toTypes: ["Attack-Pattern"]
          first: 100
        ) {
          edges {
            node {
              to {
                ... on AttackPattern {
                  x_mitre_id
                  name
                  killChainPhases { phase_name }
                }
              }
            }
          }
        }
        campaigns: stixCoreRelationships(
          relationship_type: "attributed-to"
          fromTypes: ["Campaign"]
          first: 100
        ) {
          edges {
            node {
              from {
                ... on Campaign {
                  id
                  name
                  description
                  objective
                  attackPatterns: stixCoreRelationships(
                    relationship_type: "uses"
                    toTypes: ["Attack-Pattern"]
                    first: 100
                  ) {
                    edges {
                      node {
                        to {
                          ... on AttackPattern {
                            x_mitre_id
                            name
                            killChainPhases { phase_name }
                          }
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
        malwares: stixCoreRelationships(
          relationship_type: "uses"
          toTypes: ["Malware"]
          first: 100
        ) {
          edges {
            node {
              to {
                ... on Malware {
                  id
                  name
                  aliases
                  malware_types
                  attackPatterns: stixCoreRelationships(
                    relationship_type: "uses"
                    toTypes: ["Attack-Pattern"]
                    first: 100
                  ) {
                    edges {
                      node {
                        to {
                          ... on AttackPattern {
                            x_mitre_id
                            name
                            killChainPhases { phase_name }
                          }
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
        tools: stixCoreRelationships(
          relationship_type: "uses"
          toTypes: ["Tool"]
          first: 100
        ) {
          edges {
            node {
              to {
                ... on Tool {
                  id
                  name
                  aliases
                  attackPatterns: stixCoreRelationships(
                    relationship_type: "uses"
                    toTypes: ["Attack-Pattern"]
                    first: 100
                  ) {
                    edges {
                      node {
                        to {
                          ... on AttackPattern {
                            x_mitre_id
                            name
                            killChainPhases { phase_name }
                          }
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
`

var threatActorsQuery = `
query ThreatActorsAndIntrusionSets {
  threatActors(first: 100) {
    edges {
      node {
` + actorFieldsFragment + `
      }
    }
  }
  intrusionSets(first: 100) {
    edges {
      node {
` + actorFieldsFragment + `
      }
    }
  }
}
`

func (c *OpenCTIClient) queryThreatActors() ([]octiThreatActorNode, error) {
	body, err := json.Marshal(octiGQLRequest{Query: threatActorsQuery})
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", c.baseURL+"/graphql", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OpenCTI returned HTTP %d", resp.StatusCode)
	}

	var result octiThreatActorsResp
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	if len(result.Errors) > 0 {
		return nil, fmt.Errorf("graphql error: %s", result.Errors[0].Message)
	}

	nodes := make([]octiThreatActorNode, 0, len(result.Data.ThreatActors.Edges)+len(result.Data.IntrusionSets.Edges))
	for _, e := range result.Data.ThreatActors.Edges {
		nodes = append(nodes, e.Node)
	}
	for _, e := range result.Data.IntrusionSets.Edges {
		nodes = append(nodes, e.Node)
	}
	return nodes, nil
}

// ── conversion ────────────────────────────────────────────────────────────────

func (c *OpenCTIClient) convertActor(raw octiThreatActorNode) *ThreatActor {
	if raw.Name == "" {
		return nil
	}

	actor := &ThreatActor{
		Name:        raw.Name,
		Aliases:     raw.Aliases,
		Description: raw.Description,
		Source:      "opencti",
		SourceID:    raw.ID,
		Confidence:  confidenceLabel(raw.Confidence),
	}

	if t, err := time.Parse(time.RFC3339, raw.Modified); err == nil {
		actor.LastSeen = t
	}

	actor.Techniques = dedupTechniques(techniqueRefsFrom(raw.AttackPatterns))
	return actor
}

// convertCampaign builds an intelligence.Campaign from a campaign entity
// discovered under a specific actor's "attributed-to" relationship. Uses the
// campaign's OWN nested technique relationships (via techniqueRefsFrom), not
// the actor's -- a campaign is often more specifically scoped than its
// attributed actor's full profile.
func (c *OpenCTIClient) convertCampaign(entity octiRelatedEntity, actor *ThreatActor) intelligence.Campaign {
	return intelligence.Campaign{
		ID:             entity.ID,
		Name:           entity.Name,
		Description:    entity.Description,
		Objective:      entity.Objective,
		ThreatActorIDs: []string{actor.Name},
		TechniqueIDs:   techniqueIDs(techniqueRefsFrom(entity.AttackPatterns)),
		Source: intelligence.SourceRef{
			Provider: "opencti", ExternalID: entity.ID,
			LastUpdated: actor.LastSeen, Confidence: actor.Confidence,
		},
	}
}

// convertMalware builds an intelligence.Malware from a malware entity
// discovered under a specific actor's "uses" relationship. Uses the
// malware's OWN nested technique relationships, same reasoning as
// convertCampaign.
func (c *OpenCTIClient) convertMalware(entity octiRelatedEntity, actor *ThreatActor) intelligence.Malware {
	return intelligence.Malware{
		ID:             intelligence.MalwareKey(entity.Name),
		Name:           entity.Name,
		Aliases:        entity.Aliases,
		MalwareTypes:   entity.MalwareTypes,
		TechniqueIDs:   techniqueIDs(techniqueRefsFrom(entity.AttackPatterns)),
		ThreatActorIDs: []string{actor.Name},
		Source: intelligence.SourceRef{
			Provider: "opencti", ExternalID: entity.ID,
			LastUpdated: actor.LastSeen, Confidence: actor.Confidence,
		},
	}
}

// convertTool builds an intelligence.Tool from a tool entity discovered
// under a specific actor's "uses" relationship. Uses the tool's OWN nested
// technique relationships, same reasoning as convertCampaign/convertMalware.
func (c *OpenCTIClient) convertTool(entity octiRelatedEntity, actor *ThreatActor) intelligence.Tool {
	return intelligence.Tool{
		ID:             intelligence.MalwareKey(entity.Name),
		Name:           entity.Name,
		Aliases:        entity.Aliases,
		TechniqueIDs:   techniqueIDs(techniqueRefsFrom(entity.AttackPatterns)),
		ThreatActorIDs: []string{actor.Name},
		Source: intelligence.SourceRef{
			Provider: "opencti", ExternalID: entity.ID,
			LastUpdated: actor.LastSeen, Confidence: actor.Confidence,
		},
	}
}

// FetchIntelligence implements connector.IntelligenceSource -- returns the
// Campaign/Malware/Tool data gathered during the most recent Fetch() call,
// same after-the-fact-accessor pattern Stats() already uses.
func (c *OpenCTIClient) FetchIntelligence() ([]intelligence.Campaign, []intelligence.Malware, []intelligence.Tool, error) {
	return c.lastCampaigns, c.lastMalware, c.lastTools, nil
}

func confidenceLabel(n int) string {
	switch {
	case n >= 75:
		return "high"
	case n >= 40:
		return "medium"
	default:
		return "low"
	}
}
