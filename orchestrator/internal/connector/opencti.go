package connector

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"
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
	sectors  []string
	lastStat SourceStat
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
	for _, raw := range actorsRaw {
		actor := c.convertActor(raw)
		if actor == nil || len(actor.Techniques) < 2 {
			continue
		}
		actors = append(actors, *actor)
	}
	c.lastStat = SourceStat{Name: "opencti", RawCount: len(actorsRaw), ActorCount: len(actors), FetchedAt: time.Now()}
	return actors, nil
}

// Stats implements StatsSource.
func (c *OpenCTIClient) Stats() SourceStat { return c.lastStat }

// ── GraphQL types ─────────────────────────────────────────────────────────────

type octiGQLRequest struct {
	Query     string                 `json:"query"`
	Variables map[string]interface{} `json:"variables,omitempty"`
}

type octiThreatActorNode struct {
	ID             string   `json:"id"`
	Name           string   `json:"name"`
	Aliases        []string `json:"aliases"`
	Description    string   `json:"description"`
	Confidence     int      `json:"confidence"` // 0-100
	Modified       string   `json:"modified"`
	AttackPatterns struct {
		Edges []struct {
			Node struct {
				To struct {
					XMitreID        string `json:"x_mitre_id"`
					Name            string `json:"name"`
					KillChainPhases []struct {
						PhaseName string `json:"phase_name"`
					} `json:"killChainPhases"`
				} `json:"to"`
			} `json:"node"`
		} `json:"edges"`
	} `json:"attackPatterns"`
}

type octiThreatActorsResp struct {
	Data struct {
		ThreatActors struct {
			Edges []struct {
				Node octiThreatActorNode `json:"node"`
			} `json:"edges"`
		} `json:"threatActors"`
	} `json:"data"`
	Errors []struct {
		Message string `json:"message"`
	} `json:"errors"`
}

// ── query ─────────────────────────────────────────────────────────────────────

const threatActorsQuery = `
query ThreatActors {
  threatActors(first: 100) {
    edges {
      node {
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

	nodes := make([]octiThreatActorNode, 0, len(result.Data.ThreatActors.Edges))
	for _, e := range result.Data.ThreatActors.Edges {
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

	for _, edge := range raw.AttackPatterns.Edges {
		to := edge.Node.To
		id := strings.ToUpper(strings.TrimSpace(to.XMitreID))
		if !isATTACKID(id) {
			continue
		}
		tactic := ""
		if len(to.KillChainPhases) > 0 {
			tactic = to.KillChainPhases[0].PhaseName
		}
		actor.Techniques = append(actor.Techniques, TechniqueRef{
			ID:     id,
			Name:   to.Name,
			Tactic: tactic,
		})
	}

	actor.Techniques = dedupTechniques(actor.Techniques)
	return actor
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
