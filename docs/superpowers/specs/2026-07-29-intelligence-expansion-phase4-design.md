# Intelligence Expansion Phase 4 (Tools) — Design

**Status:** Draft for review
**Author:** Claude + user, brainstormed 2026-07-29, OpenCTI side verified against a live instance at 192.168.10.78:8080; MISP side unverified (no live MISP access this session — explicitly flagged below).
**Depends on:** [[Intelligence Expansion]] Phase 1 (`docs/superpowers/specs/2026-07-28-intelligence-expansion-design.md`) and Phase 2 (`docs/superpowers/specs/2026-07-28-intelligence-expansion-phase2-design.md`) — extends the same `internal/intelligence` package, `IntelligenceSource` interface, and per-entity extraction-helper pattern (`techniqueRefsFrom`/`campaignEntitiesFrom`/`malwareEntitiesFrom`) those phases built. No new package.

## Problem

Phase 2's design doc named Tool as one of the STIX types the relationship-extraction helpers were deliberately generalized to support later, without building it. This phase builds it: a `Tool` entity (ATT&CK Software objects typed `tool` rather than `malware` — e.g. PsExec, Mimikatz, AdFind, Impacket, Empire) sourced the same way Campaign/Malware are, from both OpenCTI (verified live) and MISP (unverified, flagged).

Verified live against the OpenCTI instance before writing anything below:
- The `Tool` STIX type exists with real fields: `id`, `name`, `description`, `aliases`, `tool_types`, `tool_version`, `killChainPhases`, `stixCoreRelationships`.
- `intrusionSets → Tool` via `relationship_type: "uses", toTypes: ["Tool"]` — the actor is the FROM/subject side, same convention as `Actor → Malware`. **No relationship-direction bug this time** (unlike Phase 2's `Actor ← Campaign` surprise) — confirmed by sampling: 19 of 30 sampled `intrusionSets` had real Tool relationships, 98 total edges, 50 unique tool names, all recognizable ATT&CK Software (PsExec, Mimikatz, AdFind, BloodHound, Impacket, Empire, PoshC2, Rclone, ngrok, etc.).
- Tools have their **own** nested technique relationships (`uses → toTypes: ["Attack-Pattern"]`), same pattern as Campaign/Malware — confirmed live: 23 of the 98 sampled tool edges had real nested technique data (e.g. `PsExec → T1136.002 Domain Account, T1570 Lateral Tool Transfer, T1569.002 Service Execution`).
- `tool_types` and `killChainPhases` **on the Tool node itself** are real schema fields but were empty (`null`/`[]`) in all 98 sampled edges — this OpenCTI deployment's ATT&CK connector never populates them. Decision (below, Non-Goals): not added to the Go model.
- `threatActors` (as opposed to `intrusionSets`) returned zero results for the same query — consistent with Phase 2's existing finding that this deployment's real Group data lives under `intrusionSets` only. Not a new bug; the existing Phase 2 merge already covers this.

## Non-Goals

- **No `Tool.ToolTypes` field.** `tool_types` exists in the OpenCTI schema but was 0/98 populated in live sampling — a strong signal this deployment's data source never sets it, not a small-sample fluke. Unlike `Malware.MalwareTypes` (Phase 2, genuinely populated), adding this field now would be dead weight. Can be added later in a follow-up if a future connector actually populates it — YAGNI.
- **No `killChainPhases`/tactic field on `Tool` itself.** Technique-level tactic data already flows through `TechniqueIDs` via the existing `techniqueRefsFrom` helper (each `TechniqueRef` already carries its own `Tactic`), exactly as it does for Campaign and Malware. A second, redundant tactic field on the container entity was never part of those two models either.
- **No new package, no schema redesign** — reuses `internal/intelligence`, `IntelligenceSource`, and the existing extraction-helper structure. One new table (`intelligence_tools`), one new Go type (`Tool`), one new relationship-extraction helper (`toolEntitiesFrom`), one new converter (`convertTool`) per provider.
- **Not extending to Infrastructure, Identity, Incident, Vulnerability, or Observed-Data STIX types.** Still out of scope, same as Phase 2's Non-Goals stated.
- **MISP's `mitre-tool` galaxy cluster type is assumed, not verified.** No live MISP instance was reachable this session. The assumption follows the same ATT&CK-galaxy convention already confirmed for `mitre-attack-pattern` (techniques) and `mitre-malware` (malware) in this codebase's existing MISP code — MISP's ATT&CK galaxy taxonomy separates Software into `mitre-malware` and `mitre-tool` clusters, parallel to how ATT&CK itself splits Software into `malware` and `tool` sub-types. This is a reasonable inference from an already-confirmed pattern, not a guess from nothing — but it is **not independently verified against live MISP data**, and the implementation plan must call this out as a checkpoint: verify against a real MISP instance before or during that task, the same way Phase 1 already carries an open issue that `mitre-malware` itself was "not independently verified against a live MISP instance." If verification during implementation shows the galaxy type name is wrong or doesn't exist, the MISP-side task should be adjusted or deferred — it must not ship guessed-and-wrong.

## Architecture

### 1. New `Tool` model (`internal/intelligence/models.go`)

```go
// Tool is one ATT&CK Software object typed "tool" (as opposed to "malware")
// -- e.g. PsExec, Mimikatz, AdFind. Same shape as Malware minus the
// OpenCTI-only MalwareTypes field, which has no Tool analog (ToolTypes
// exists in OpenCTI's schema but was never populated on live data --
// see the Phase 4 design doc's Non-Goals).
type Tool struct {
	ID             string    `json:"id"` // = MalwareKey(Name) -- same cross-provider dedup key Malware already uses
	Name           string    `json:"name"`
	Aliases        []string  `json:"aliases"`
	TechniqueIDs   []string  `json:"techniqueIds"`
	ThreatActorIDs []string  `json:"threatActorIds"`
	CampaignIDs    []string  `json:"campaignIds"`
	Source         SourceRef `json:"source"`
}
```

`MalwareKey` is reused as-is (not duplicated) — it's already a general name-normalization function, not malware-specific in its logic, despite the name. No new dedup-key function needed.

### 2. OpenCTI extraction — mirrors `Malwares` exactly

`actorFieldsFragment` (`internal/connector/opencti.go`) gains a `tools` relationship block, placed after the existing `malwares` block:

```graphql
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
```

`octiThreatActorNode` gains a `Tools octiRelationshipConnection` field alongside the existing `Campaigns`/`Malwares` fields. No changes needed to `octiRelatedEntity` — it already carries `ID`, `Name`, `Aliases`, and `AttackPatterns`, every field a Tool node needs; `tool_types`/`tool_version` are deliberately not requested in the query at all (Non-Goals).

New helper, mirroring `malwareEntitiesFrom` exactly (actor is the FROM side, tool is TO):

```go
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
```

New converter, mirroring `convertMalware` minus the `MalwareTypes` line:

```go
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
```

`Fetch()` gains a third accumulator alongside `campaigns`/`malware`:

```go
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
	c.lastCampaigns = campaigns
	c.lastMalware = malware
	c.lastTools = tools
```

`OpenCTIClient` gains a `lastTools []intelligence.Tool` field alongside `lastCampaigns`/`lastMalware`.

### 3. MISP extraction — parallel `mitre-tool` galaxy loop (unverified, see Non-Goals)

`extractIntelligence` (`internal/connector/misp.go`) gains a third loop over the same already-fetched `detail.Event.GalaxyCluster`, alongside the existing `mitre-malware` loop:

```go
	var tools []intelligence.Tool
	for _, gc := range detail.Event.GalaxyCluster {
		if gc.Type != "mitre-tool" {
			continue
		}
		name := strings.TrimSpace(gc.Value)
		if name == "" {
			continue
		}
		tools = append(tools, intelligence.Tool{
			ID: intelligence.MalwareKey(name), Name: name,
			TechniqueIDs: techniqueIDs(actor.Techniques),
			ThreatActorIDs: []string{actor.Name}, CampaignIDs: []string{ev.ID},
			Source: src,
		})
	}
```

Same technique/actor-inheritance limitation the existing `mitre-malware` loop already documents (MISP's flat galaxy list doesn't support finer per-tool technique attribution). `extractIntelligence`'s return signature widens from `(*intelligence.Campaign, []intelligence.Malware)` to `(*intelligence.Campaign, []intelligence.Malware, []intelligence.Tool)`; its one call site in `Fetch()` updates accordingly.

### 4. `IntelligenceSource` interface — widened signature (chosen: option a)

```go
// internal/connector/source.go
type IntelligenceSource interface {
	FetchIntelligence() ([]intelligence.Campaign, []intelligence.Malware, []intelligence.Tool, error)
}
```

Both `MISPClient.FetchIntelligence()` and `OpenCTIClient.FetchIntelligence()` widen to return `c.lastTools` as a third slice, same after-the-fact-accessor pattern already used for the other two. This is a breaking signature change to an interface with exactly two implementers, both inside this same package — chosen over a second optional `ToolSource` interface because Tools are conceptually a first-class sibling of Campaign/Malware (same struct shape, same store pattern, same API shape, same "things a sync run produces" grouping), not a separate optional capability like `StatsSource`.

`Scheduler.sync()` (`internal/connector/scheduler.go`) updates its one call site:

```go
	var allTools []intelligence.Tool
	// ...
	if is, ok := src.(IntelligenceSource); ok {
		campaigns, malware, tools, ierr := is.FetchIntelligence()
		if ierr != nil {
			log.Printf("[connector/%s] intelligence fetch error: %v", src.Name(), ierr)
		} else {
			allCampaigns = append(allCampaigns, campaigns...)
			allMalware = append(allMalware, malware...)
			allTools = append(allTools, tools...)
		}
	}
	// ...
	for _, tl := range allTools {
		if err := intelligence.UpsertTool(context.Background(), s.pool, tl); err != nil {
			log.Printf("[connector] upsert tool %q: %v", tl.ID, err)
		}
	}
```

### 5. Persistence — `intelligence_tools` table, union-merge on conflict

New migration adds `intelligence_tools` with the same column shape as `intelligence_malware` minus `malware_types`: `id text primary key, name text not null, aliases text[] not null, technique_ids text[] not null, actor_ids text[] not null, campaign_ids text[] not null, source_provider text not null, source_external_id text not null, source_confidence text not null, last_updated timestamptz not null`.

`UpsertTool`/`ListTools` (`internal/intelligence/store.go`) mirror `UpsertMalware`/`ListMalware` exactly, including the `nonNil` coalescing calls and the array-union `ON CONFLICT` clause — a tool can legitimately be discovered under multiple actors within one sync (OpenCTI's per-actor extraction design makes this a real occurrence, same reasoning as Malware, not hypothetical).

### 6. API — `GET /api/intelligence/tools`

`internal/api/intelligence_handlers.go` gains `IntelligenceTools`, mirroring `IntelligenceMalware`. Registered in `internal/api/routes.go` in the same block as the existing two intelligence routes, `tierAny`. RBAC matrix entry (`internal/api/rbac_matrix_test.go`) added in the same commit — this project's now-established habit (2/2 prior phases got this right the first time after Phase 1 of the *original* Threat Intel Center effort shipped RBAC as an afterthought once).

## Testing

- `internal/intelligence`: `TestUpsertTool_MergesArraysOnConflict` — same shape as `TestUpsertMalware_MergesArraysOnConflict`, two upserts of the same tool ID with different `ThreatActorIDs`/`CampaignIDs`, assert the union. `TestListTools_Empty_ReturnsEmptyNotNil`.
- `internal/connector`: `TestToolEntitiesFrom_ReadsToSide` — unit test against a hand-built `octiRelationshipConnection` fixture, mirroring `TestMalwareEntitiesFrom_ReadsToSide`. `TestOpenCTIClient_ConvertTool_UsesOwnTechniques` — mirrors `TestOpenCTIClient_ConvertMalware_UsesOwnTechniquesAndTypes` minus the types assertion. `TestOpenCTIClient_FetchIntelligence_ToolsPopulatedAfterFetch` — mirrors the existing campaigns/malware populated-after-fetch test, extended to also assert on the third return value. `TestMISPClient_FetchIntelligence_ExtractsTools` — mock MISP event with a `mitre-tool` GalaxyCluster entry, asserting extraction, **explicitly marked in the test comment as validating the assumed-not-verified galaxy type name**, so a future MISP-format change or verification finding surfaces here first. Existing `TestOpenCTIClient_Fetch_MergesThreatActorsAndIntrusionSets` and `TestMISPClient_FetchIntelligence_*` tests need their call sites updated for the widened `FetchIntelligence` signature (three slices, not two) — no behavioral change to those tests otherwise.
- `internal/api`: existing `rbac_matrix_test.go` pattern covers the new route once its entry is added — no new test file needed there.
- Full regression (`go build ./...`, `go vet ./...`, `go test ./... -count=1`) as the final plan task, matching Phase 2's closing step.
