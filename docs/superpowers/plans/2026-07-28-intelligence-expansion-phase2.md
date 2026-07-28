# Intelligence Expansion Phase 2 (OpenCTI) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix `OpenCTIClient.Fetch()` to also query `intrusionSets` (real actor data lives there, not just `threatActors`) and extend it to extract Campaign/Malware intelligence, mirroring what `MISPClient` already does for Phase 1.

**Architecture:** One combined GraphQL query per `Fetch()` call (unchanged single-round-trip discipline) requests `threatActors` + `intrusionSets`, each actor node carrying its own techniques (existing), plus new nested `campaigns` (incoming `attributed-to` via `fromTypes`) and `malwares` (outgoing `uses`) relationship connections — each of which carries its own nested technique connection. A small set of reusable Go helpers (`techniqueRefsFrom`, `campaignEntitiesFrom`, `malwareEntitiesFrom`) parse the polymorphic `stixCoreRelationships` edge shape once, used by actor/campaign/malware conversion alike. `OpenCTIClient` gains `lastCampaigns`/`lastMalware` fields and a `FetchIntelligence()` method, making it implement `connector.IntelligenceSource` — `Scheduler.sync()` already picks this up automatically via its existing type assertion, no scheduler changes needed.

**Tech Stack:** Go, `internal/connector` package (GraphQL client, no library — raw `net/http` + `encoding/json`, matching existing style), `internal/intelligence` package (Campaign/Malware models + Postgres upsert, `pgx/v5`).

## Global Constraints

- No new package, no new DB tables, no schema changes to `Campaign`/`Malware`'s core shape — reuse everything Phase 1 (`internal/intelligence`) built. (Spec §Non-Goals)
- Do NOT add a `Malware.Platforms` field — verified live against OpenCTI's schema, no such field exists. (Spec §Non-Goals, §2)
- `MISPClient`'s extraction logic (`misp.go`) is not touched by this plan.
- Every GraphQL relationship direction must match the verified table in the spec exactly: `fromTypes` (not `toTypes`) for Campaign attribution, since the actor is the `to` side of `attributed-to`. (Spec §2)
- One HTTP round trip per `Fetch()` call, same as today — no per-entity follow-up queries.

---

## File Structure

- Modify `orchestrator/internal/connector/opencti.go` — GraphQL types, query text, `queryThreatActors()`, `convertActor()`, new `convertCampaign()`/`convertMalware()`, new relationship-extraction helpers, `FetchIntelligence()`.
- Modify `orchestrator/internal/connector/opencti_stats_test.go` — update the two existing tests' anonymous-struct edge construction to use the new named `octiActorEdge` type; this file's tests must keep passing unmodified in behavior.
- Create `orchestrator/internal/connector/opencti_intelligence_test.go` — new tests for the relationship helpers, actor/campaign/malware conversion, and `FetchIntelligence()`.
- Modify `orchestrator/internal/intelligence/models.go` — add `Campaign.Objective string` and `Malware.MalwareTypes []string`.
- Modify `orchestrator/internal/intelligence/store.go` — `UpsertCampaign` switches from overwrite to array-union-on-conflict for `actor_ids`/`technique_ids`.
- Modify `orchestrator/internal/intelligence/store_test.go` (create if it doesn't exist — check first) — test proving the union-merge behavior.

---

### Task 1: Relationship-extraction helpers + refactor `convertActor` to use them

**Files:**
- Modify: `orchestrator/internal/connector/opencti.go:76-96` (struct definitions), `:186-225` (`convertActor`)
- Test: `orchestrator/internal/connector/opencti_intelligence_test.go` (new)

**Interfaces:**
- Produces: `type octiRelatedEntity struct{...}`, `type octiRelationshipEdge struct{...}`, `type octiRelationshipConnection struct{ Edges []octiRelationshipEdge }`, `func techniqueRefsFrom(conn octiRelationshipConnection) []TechniqueRef`, `func campaignEntitiesFrom(conn octiRelationshipConnection) []octiRelatedEntity`, `func malwareEntitiesFrom(conn octiRelationshipConnection) []octiRelatedEntity` — all consumed by Task 2/3.

First, check if a test file for OpenCTI intelligence extraction already exists (it shouldn't, but confirm before creating):

```bash
ls orchestrator/internal/connector/opencti_intelligence_test.go 2>&1 || echo "does not exist, good"
```

- [ ] **Step 1: Write the failing tests for the three helpers**

Create `orchestrator/internal/connector/opencti_intelligence_test.go`:

```go
package connector

import "testing"

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
```

- [ ] **Step 2: Run tests to verify they fail (types don't exist yet)**

Run: `cd orchestrator && go test ./internal/connector/... -run 'TestTechniqueRefsFrom|TestCampaignEntitiesFrom|TestMalwareEntitiesFrom' -v`
Expected: FAIL — `undefined: octiRelationshipConnection` (and related undefined-type errors)

- [ ] **Step 3: Add the relationship types and helpers, refactor `convertActor`**

In `orchestrator/internal/connector/opencti.go`, replace the `octiThreatActorNode` struct (lines 76-96) with:

```go
// octiRelatedEntity is the flat, polymorphic shape of one stixCoreRelationships
// edge's "to" (or "from") object -- a superset of AttackPattern/Campaign/
// Malware fields. Unused fields for a given target type are simply absent in
// that GraphQL response and stay zero-valued; this lets one Go type back
// every relationship extraction in this file instead of one per target type.
type octiRelatedEntity struct {
	ID              string `json:"id"`
	Name            string `json:"name"`
	Description     string `json:"description"`
	Aliases         []string `json:"aliases"`
	XMitreID        string `json:"x_mitre_id"`
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
```

Then replace `convertActor`'s technique-extraction loop (lines 206-221 in the original file) so it calls the new helper instead of looping inline:

```go
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
```

(This drops the old inline loop and the trailing `actor.Techniques = dedupTechniques(actor.Techniques)` call, replaced by the one-line helper-based assignment above — behavior is identical.)

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/connector/... -run 'TestTechniqueRefsFrom|TestCampaignEntitiesFrom|TestMalwareEntitiesFrom' -v`
Expected: PASS (4 tests)

- [ ] **Step 5: Run the full connector package test suite to confirm `convertActor`'s refactor didn't change behavior**

Run: `cd orchestrator && go test ./internal/connector/... -v`
Expected: PASS — all existing tests, including `opencti_stats_test.go` and every MISP test, still pass unmodified (the refactor is behavior-preserving).

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/connector/opencti.go orchestrator/internal/connector/opencti_intelligence_test.go
git commit -m "refactor(connector): extract OpenCTI relationship-parsing into reusable helpers"
```

---

### Task 2: Merge `threatActors` + `intrusionSets`, add `campaigns`/`malwares` to the query

**Files:**
- Modify: `orchestrator/internal/connector/opencti.go:98-184` (response struct, query text, `queryThreatActors()`)
- Modify: `orchestrator/internal/connector/opencti_stats_test.go` (anonymous struct → named `octiActorEdge`)

**Interfaces:**
- Consumes: `octiThreatActorNode`, `octiRelationshipConnection` from Task 1.
- Produces: `queryThreatActors()` returns nodes from both `threatActors` and `intrusionSets`, each carrying populated `Campaigns`/`Malwares` connections in addition to `AttackPatterns`.

- [ ] **Step 1: Write the failing test for the merge behavior**

Add to `orchestrator/internal/connector/opencti_intelligence_test.go`:

```go
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
```

Add `"encoding/json"`, `"net/http"`, `"net/http/httptest"` to this test file's imports (needed for the new test).

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/connector/... -run TestOpenCTIClient_Fetch_MergesThreatActorsAndIntrusionSets -v`
Expected: FAIL — `undefined: octiActorEdge` and `resp.Data.IntrusionSets` field missing

- [ ] **Step 3: Update the response struct and query text**

Replace `octiThreatActorsResp` (original lines 98-109) with:

```go
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
```

Replace `threatActorsQuery` (original lines 113-145) with:

```go
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
```

(`threatActorsQuery` changes from `const` to `var` since it's now built via string concatenation — Go doesn't allow non-literal `const` string expressions.)

Update `queryThreatActors()` (original lines 147-184) to concatenate both collections:

```go
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
```

- [ ] **Step 4: Update the existing stats test file's anonymous-struct construction**

In `orchestrator/internal/connector/opencti_stats_test.go`, replace both occurrences of:

```go
			resp.Data.ThreatActors.Edges = make([]struct {
				Node octiThreatActorNode `json:"node"`
			}, 2)
```

with:

```go
			resp.Data.ThreatActors.Edges = make([]octiActorEdge, 2)
```

(one occurrence in `TestOpenCTIClient_Stats_CountsRawNodesAndFilteredActors`; `TestOpenCTIClient_Stats_RecordsErrorOnFailedFetch` doesn't construct edges and needs no change.)

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/connector/... -run 'TestOpenCTIClient' -v`
Expected: PASS — the new merge test plus both existing stats tests (now compiling against the named `octiActorEdge` type).

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/connector/opencti.go orchestrator/internal/connector/opencti_stats_test.go orchestrator/internal/connector/opencti_intelligence_test.go
git commit -m "fix(connector): OpenCTI actor query also reads intrusionSets, adds campaign/malware relationships"
```

---

### Task 3: New model fields + `convertCampaign`/`convertMalware` + `FetchIntelligence()`

**Files:**
- Modify: `orchestrator/internal/intelligence/models.go` — add `Campaign.Objective`, `Malware.MalwareTypes`
- Modify: `orchestrator/internal/connector/opencti.go` — add `lastCampaigns`/`lastMalware` fields, `convertCampaign`/`convertMalware`, wire into `Fetch()`, add `FetchIntelligence()`
- Test: `orchestrator/internal/connector/opencti_intelligence_test.go`

**Interfaces:**
- Consumes: `octiRelatedEntity`, `campaignEntitiesFrom`, `malwareEntitiesFrom`, `techniqueRefsFrom` from Task 1; `octiThreatActorNode.Campaigns`/`.Malwares` from Task 2.
- Produces: `func (c *OpenCTIClient) FetchIntelligence() ([]intelligence.Campaign, []intelligence.Malware, error)` — makes `*OpenCTIClient` implement `connector.IntelligenceSource`.

- [ ] **Step 1: Add the two new model fields**

In `orchestrator/internal/intelligence/models.go`, modify the `Campaign` struct:

```go
type Campaign struct {
	ID             string    `json:"id"` // = Source.ExternalID for MISP (event ID, already unique)
	Name           string    `json:"name"`
	Description    string    `json:"description"`
	ThreatActorIDs []string  `json:"threatActorIds"` // threat_actor_profiles.name values
	TechniqueIDs   []string  `json:"techniqueIds"`
	Objective      string    `json:"objective,omitempty"` // OpenCTI-only; empty for MISP-sourced campaigns
	Source         SourceRef `json:"source"`
}
```

And the `Malware` struct:

```go
type Malware struct {
	ID             string    `json:"id"` // = MalwareKey(Name) -- cross-event dedup key
	Name           string    `json:"name"`
	Aliases        []string  `json:"aliases"`
	TechniqueIDs   []string  `json:"techniqueIds"`
	ThreatActorIDs []string  `json:"threatActorIds"`
	CampaignIDs    []string  `json:"campaignIds"`
	MalwareTypes   []string  `json:"malwareTypes,omitempty"` // e.g. "ransomware", "trojan" -- OpenCTI-only
	Source         SourceRef `json:"source"`
}
```

- [ ] **Step 2: Write the failing tests for `convertCampaign`/`convertMalware`/`FetchIntelligence`**

Add to `orchestrator/internal/connector/opencti_intelligence_test.go`:

```go
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
	if malware.ID != intelligence.MalwareKey("TSCookie") {
		t.Fatalf("convertMalware().ID = %q, want %q", malware.ID, intelligence.MalwareKey("TSCookie"))
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
			}},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	c := NewOpenCTIClient(server.URL, "test-key", nil)
	if _, err := c.Fetch(); err != nil {
		t.Fatalf("Fetch: %v", err)
	}

	campaigns, malware, err := c.FetchIntelligence()
	if err != nil {
		t.Fatalf("FetchIntelligence: %v", err)
	}
	if len(campaigns) != 1 || campaigns[0].Name != "SolarWinds Compromise" {
		t.Fatalf("FetchIntelligence() campaigns = %+v, want one named SolarWinds Compromise", campaigns)
	}
	if len(malware) != 1 || malware[0].Name != "TSCookie" {
		t.Fatalf("FetchIntelligence() malware = %+v, want one named TSCookie", malware)
	}
}
```

Add `"github.com/audspect/bas/internal/intelligence"` to this test file's imports.

- [ ] **Step 3: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/connector/... -run 'TestOpenCTIClient_ConvertCampaign|TestOpenCTIClient_ConvertMalware|TestOpenCTIClient_FetchIntelligence' -v`
Expected: FAIL — `c.convertCampaign undefined`, `c.convertMalware undefined`, `c.FetchIntelligence undefined`

- [ ] **Step 4: Add `lastCampaigns`/`lastMalware` fields, conversion functions, and wire into `Fetch()`**

In `orchestrator/internal/connector/opencti.go`, add the import and struct fields:

```go
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

type OpenCTIClient struct {
	baseURL    string
	apiKey     string
	httpClient *http.Client
	sectors  []string
	lastStat SourceStat
	lastCampaigns []intelligence.Campaign
	lastMalware   []intelligence.Malware
}
```

Replace `Fetch()` to also extract campaigns/malware per actor:

```go
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
	}
	c.lastStat = SourceStat{Name: "opencti", RawCount: len(actorsRaw), ActorCount: len(actors), FetchedAt: time.Now()}
	c.lastCampaigns = campaigns
	c.lastMalware = malware
	return actors, nil
}
```

Add `convertCampaign`, `convertMalware`, and `FetchIntelligence` after `convertActor`:

```go
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

// FetchIntelligence implements connector.IntelligenceSource -- returns the
// Campaign/Malware data gathered during the most recent Fetch() call, same
// after-the-fact-accessor pattern Stats() and MISPClient.FetchIntelligence
// already use.
func (c *OpenCTIClient) FetchIntelligence() ([]intelligence.Campaign, []intelligence.Malware, error) {
	return c.lastCampaigns, c.lastMalware, nil
}
```

`techniqueIDs` already exists in `misp.go` (same package `connector`) — no need to redefine it.

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/connector/... -v`
Expected: PASS — all connector package tests, including every new test from Tasks 1-3.

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/connector/opencti.go orchestrator/internal/connector/opencti_intelligence_test.go orchestrator/internal/intelligence/models.go
git commit -m "feat(connector): OpenCTI Campaign/Malware extraction (Intelligence Expansion Phase 2)"
```

---

### Task 4: `UpsertCampaign` array-union-on-conflict

**Files:**
- Modify: `orchestrator/internal/intelligence/store.go:21-37`
- Modify/Test: `orchestrator/internal/intelligence/store_test.go` — already exists, uses `sharedDB *testutil.TestDB` (package-level, set up in this file's existing `TestMain`) and `sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {...})`. Do not add a second `TestMain` or invent a different pool helper.

**Interfaces:**
- Consumes: `Campaign` from `models.go` (unchanged shape apart from Task 3's new `Objective` field); `sharedDB.RunWithPool` from `testutil.TestDB` (already wired in this file).
- Produces: `UpsertCampaign` behavior changes from overwrite to union-merge for `actor_ids`/`technique_ids` — no signature change.

`store_test.go` already has a test named `TestUpsertCampaign_InsertThenOverwriteOnConflict` (lines 29-64) that exercises today's overwrite behavior with a *superset* second `TechniqueIDs` (`["T1059"]` → `["T1059","T1105"]`) — under union-merge this test still numerically passes (union of a superset equals the superset), but its name becomes misleading about what it actually proves once `UpsertCampaign` merges instead of overwrites. Rename it as part of this task.

- [ ] **Step 1: Rename the existing overwrite test and write the new failing union-merge test**

In `orchestrator/internal/intelligence/store_test.go`, rename `TestUpsertCampaign_InsertThenOverwriteOnConflict` to `TestUpsertCampaign_NameAndDescriptionOverwriteOnConflict` (its body is unchanged — it still correctly proves `Name`/`Description` overwrite on conflict, which remains true after this task; only the name was inaccurate about `TechniqueIDs`).

Then add a new test directly after it, using disjoint ID sets so overwrite and union-merge produce genuinely different, distinguishable results:

```go
func TestUpsertCampaign_MergesActorAndTechniqueIDsOnConflict(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		first := Campaign{
			ID: "evt-multi-actor", Name: "Multi-Actor Campaign", ThreatActorIDs: []string{"APT29"},
			TechniqueIDs: []string{"T1059"},
			Source:       SourceRef{Provider: "opencti", ExternalID: "campaign--1", LastUpdated: time.Now(), Confidence: "high"},
		}
		if err := UpsertCampaign(ctx, pool, first); err != nil {
			t.Fatalf("first UpsertCampaign: %v", err)
		}

		second := Campaign{
			ID: "evt-multi-actor", Name: "Multi-Actor Campaign", ThreatActorIDs: []string{"Cozy Bear"},
			TechniqueIDs: []string{"T1105"},
			Source:       SourceRef{Provider: "opencti", ExternalID: "campaign--1", LastUpdated: time.Now(), Confidence: "high"},
		}
		if err := UpsertCampaign(ctx, pool, second); err != nil {
			t.Fatalf("second UpsertCampaign: %v", err)
		}

		campaigns, err := ListCampaigns(ctx, pool)
		if err != nil {
			t.Fatalf("ListCampaigns: %v", err)
		}
		var got *Campaign
		for i := range campaigns {
			if campaigns[i].ID == "evt-multi-actor" {
				got = &campaigns[i]
				break
			}
		}
		if got == nil {
			t.Fatal("campaign evt-multi-actor not found after two upserts")
		}
		sort.Strings(got.ThreatActorIDs)
		if len(got.ThreatActorIDs) != 2 || got.ThreatActorIDs[0] != "APT29" || got.ThreatActorIDs[1] != "Cozy Bear" {
			t.Fatalf("ThreatActorIDs = %v, want union [APT29 Cozy Bear], not overwritten to just the second upsert's value", got.ThreatActorIDs)
		}
		sort.Strings(got.TechniqueIDs)
		if len(got.TechniqueIDs) != 2 || got.TechniqueIDs[0] != "T1059" || got.TechniqueIDs[1] != "T1105" {
			t.Fatalf("TechniqueIDs = %v, want union [T1059 T1105], not overwritten", got.TechniqueIDs)
		}
	})
}
```

(`sort` is already imported in this file for the existing `TestUpsertMalware_MergesArraysOnConflict` test; `time` is already imported too — no new imports needed.)

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/intelligence/... -run TestUpsertCampaign_MergesActorAndTechniqueIDsOnConflict -v`
Expected: FAIL — `ThreatActorIDs = [Cozy Bear], want union [APT29 Cozy Bear]` (today's overwrite behavior keeps only the second upsert's value)

- [ ] **Step 3: Change `UpsertCampaign` to union-merge**

In `orchestrator/internal/intelligence/store.go`, replace the `UpsertCampaign` function:

```go
// UpsertCampaign merges actor_ids/technique_ids on conflict (union,
// deduplicated) -- OpenCTI can legitimately attribute the same campaign to
// more than one actor, and Campaign extraction runs per-actor (see
// connector.OpenCTIClient.Fetch), so the same campaign ID can be upserted
// twice within one sync with different ThreatActorIDs. Overwriting would
// silently drop the first actor's attribution. name/description/source_*
// fields still overwrite -- those describe the same real-world campaign, no
// merge needed. Safe for MISP too: its campaigns never collide within a
// sync, so union-of-one-element equals the old overwrite behavior.
func UpsertCampaign(ctx context.Context, pool *pgxpool.Pool, c Campaign) error {
	c.ThreatActorIDs, c.TechniqueIDs = nonNil(c.ThreatActorIDs), nonNil(c.TechniqueIDs)
	_, err := pool.Exec(ctx,
		`INSERT INTO intelligence_campaigns
		   (id, name, description, actor_ids, technique_ids, source_provider, source_external_id, source_confidence, last_updated)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
		 ON CONFLICT (id) DO UPDATE SET
		   name = EXCLUDED.name, description = EXCLUDED.description,
		   actor_ids     = ARRAY(SELECT DISTINCT UNNEST(intelligence_campaigns.actor_ids || EXCLUDED.actor_ids)),
		   technique_ids = ARRAY(SELECT DISTINCT UNNEST(intelligence_campaigns.technique_ids || EXCLUDED.technique_ids)),
		   source_provider = EXCLUDED.source_provider, source_external_id = EXCLUDED.source_external_id,
		   source_confidence = EXCLUDED.source_confidence, last_updated = EXCLUDED.last_updated`,
		c.ID, c.Name, c.Description, c.ThreatActorIDs, c.TechniqueIDs,
		c.Source.Provider, c.Source.ExternalID, c.Source.Confidence, c.Source.LastUpdated)
	return err
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd orchestrator && go test ./internal/intelligence/... -v`
Expected: PASS — the new merge test plus every existing `intelligence` package test (including any existing `UpsertCampaign`/`UpsertMalware` tests, which must still pass since MISP's single-attribution case is unaffected).

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/intelligence/store.go orchestrator/internal/intelligence/store_test.go
git commit -m "fix(intelligence): UpsertCampaign merges actor/technique IDs on conflict instead of overwriting"
```

---

### Task 5: Full regression and OpenCTI live smoke check

**Files:** none (verification only)

- [ ] **Step 1: Full build**

Run: `cd orchestrator && go build ./...`
Expected: no errors

- [ ] **Step 2: Full vet**

Run: `cd orchestrator && go vet ./...`
Expected: no errors

- [ ] **Step 3: Full test suite**

Run: `cd orchestrator && go test ./... -count=1`
Expected: PASS across all packages (Docker Desktop must be running for `internal/api` and `internal/intelligence`'s DB-backed tests per this project's established testing convention — start it first if `docker info` fails).

- [ ] **Step 4: Confirm `OpenCTIClient` satisfies `IntelligenceSource`**

Run: `cd orchestrator && go build ./... 2>&1 | grep -i opencti || echo "no opencti build errors"`

This is a redundant confirmation (Step 1 already proves it compiles), included because `var _ connector.IntelligenceSource = (*OpenCTIClient)(nil)` is the kind of compile-time assertion worth having — add it directly to `opencti.go` near the type definition if not already implied by existing code style (check whether `misp.go` has an equivalent assertion for `MISPClient` first; if it does, add the same pattern for `OpenCTIClient` for consistency, if not, skip this and rely on the scheduler's existing type assertion working correctly per Task 3's test).

- [ ] **Step 5: Commit if Step 4 added anything**

```bash
git add orchestrator/internal/connector/opencti.go
git commit -m "chore(connector): compile-time IntelligenceSource assertion for OpenCTIClient"
```

(Skip this commit if Step 4 made no changes.)
