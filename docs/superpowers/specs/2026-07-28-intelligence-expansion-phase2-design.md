# Intelligence Expansion Phase 2 (OpenCTI) — Design

**Status:** Draft for review
**Author:** Claude + user, brainstormed 2026-07-28, verified against a live OpenCTI instance (v7.260715.0)
**Depends on:** [[Intelligence Expansion Phase 1]] (`docs/superpowers/specs/2026-07-28-intelligence-expansion-design.md`) — extends the same `internal/intelligence` package and `IntelligenceSource` interface, no new package.

## Problem

Two problems, discovered together and fixed together because they touch the same file and the same query shape:

1. **`OpenCTIClient.Fetch()` likely returns zero actors on a standard OpenCTI deployment.** It queries only `threatActors`. Verified live: on an instance populated the standard way (the official MITRE ATT&CK connector), real Group/Actor data — with full technique relationships — lives under `intrusionSets`, not `threatActors`, which was empty. This is standard STIX/OpenCTI convention (MITRE's own STIX bundles type ATT&CK Groups as `intrusion-set`), not an artifact of this one instance. The existing production code has been silently missing this data since it shipped.
2. **OpenCTI's connector never extracts Campaign/Malware at all** — [[Intelligence Expansion]] Phase 1 built this capability for MISP only, per its own explicit Non-Goals.

Fixing both means: query both `threatActors` and `intrusionSets` in one combined request, merge them (Phase 1's existing `MergeActors` already dedupes — nothing there changes), and extend the same combined query to also pull Campaign/Malware relationships from each actor node.

## Non-Goals

- **No new package, no new tables, no schema changes to `Campaign`/`Malware`'s core shape** — this reuses everything Phase 1 built (`internal/intelligence`, `intelligence_campaigns`/`intelligence_malware`, `IntelligenceSource`). Two new *optional* fields are added (below), not a redesign.
- **Not extending to Tool, Infrastructure, Identity, Incident, Vulnerability, or Observed-Data STIX types.** OpenCTI supports all of these and the extraction-helper design below is deliberately built so adding them later doesn't require re-deriving the relationship-parsing logic — but none are built in this phase.
- **Not adding `Malware.Platforms`.** Checked live: no `platforms`-equivalent field exists on OpenCTI's `Malware` type in this schema version. The closest real field, `architecture_execution_envs`, is CPU architecture (x86-64, ARM), not OS platform (Windows/Linux/macOS) — a different concept than what BAS targeting would need. Not adding a field that doesn't hold what its name would promise.
- **Not touching MISP's extraction logic** — `misp.go`'s `extractIntelligence`/`FetchIntelligence` are unchanged. Only `opencti.go` and, for the one merge-on-conflict fix, `internal/intelligence/store.go`.

## Architecture

### 1. Actor query fix — merge `threatActors` + `intrusionSets`

`queryThreatActors()` becomes one GraphQL request with two aliased top-level fields instead of one:

```graphql
query ThreatActorsAndIntrusionSets {
  threatActors(first: 100) { edges { node { ...actorFields } } }
  intrusionSets(first: 100) { edges { node { ...actorFields } } }
}
```

Both node shapes need the identical field set (below), so the same Go struct (`octiThreatActorNode`, unchanged) deserializes either. `Fetch()` concatenates both result sets into one `[]octiThreatActorNode` before the existing per-node conversion loop runs — everything downstream (`convertActor`, `MergeActors`, the `<2 techniques` filter) is untouched.

### 2. Verified relationship model

Every relationship direction below was checked against real data on the live instance, not assumed — one of them (`Actor ← Campaign`) turned out to be the *opposite* direction from what the existing `attackPatterns`/`malwares` pattern would suggest, and would have silently returned empty if guessed:

| Relationship | Query (from the actor's own node) | Verified live example |
|---|---|---|
| Actor → Technique | `toTypes: ["Attack-Pattern"], relationship_type: "uses"` | *(already correct in existing code)* |
| Actor → Malware | `toTypes: ["Malware"], relationship_type: "uses"` | `BlackTech uses TSCookie/PLEAD/Kivars` |
| Actor ← Campaign | `fromTypes: ["Campaign"], relationship_type: "attributed-to"` — **actor is the `to` side; querying `toTypes` here returns nothing** | `APT29 ← SolarWinds Compromise, Operation Ghost` |
| Campaign → Technique | `toTypes: ["Attack-Pattern"], relationship_type: "uses"` (campaign's own techniques, not inherited from the actor) | `J-magic Campaign uses T1583.003/T1587.003/T1588.001` |
| Campaign → Actor | `toTypes: ["Intrusion-Set"], relationship_type: "attributed-to"` | `SolarWinds Compromise → APT29` |
| Malware → Technique | `toTypes: ["Attack-Pattern"], relationship_type: "uses"` (malware's own techniques) | 30/30 sampled malware entries had real technique data — richer than Campaign's coverage |

Both Campaign's and Malware's *own* technique relationships are used (not the actor's), per the earlier design discussion — a technique a campaign or malware family is independently known for is more accurate than inheriting whatever the broader actor/group profile claims.

### 3. Relationship extraction helpers (avoids duplicated parsing per entity type)

Every `stixCoreRelationships` connection returns the same JSON shape regardless of what's on the other end — `edges[].node.relationship_type` plus a polymorphic `to`/`from` object whose fields depend on which inline fragment (`... on AttackPattern`, `... on Campaign`, `... on Malware`, `... on IntrusionSet`) matched at runtime. GraphQL's inline-fragment syntax has to be written per type in the query text — that part can't be made generic — but the *Go-side* parsing can be: one flat struct requesting every field any of these fragments might carry (Go's `encoding/json` leaves fields absent in a given response as zero values, so one struct safely covers all four target types), plus small pure functions that extract a specific typed view from it:

```go
// octiRelatedEntity is the flat, polymorphic shape of one stixCoreRelationships
// edge's "to" (or "from") object -- a superset of AttackPattern/Campaign/
// Malware/IntrusionSet fields. Unused fields for a given target type are
// simply absent in that response and stay zero-valued; this lets one Go type
// back every relationship extraction in this file instead of one per target
// type, and lets a future Tool/Infrastructure/Identity extraction reuse it
// unchanged.
type octiRelatedEntity struct {
	Name            string   `json:"name"`
	Description     string   `json:"description"`
	Aliases         []string `json:"aliases"`
	XMitreID        string   `json:"x_mitre_id"`
	KillChainPhases []struct {
		PhaseName string `json:"phase_name"`
	} `json:"killChainPhases"`
	FirstSeen    string   `json:"first_seen"`
	LastSeen     string   `json:"last_seen"`
	Objective    string   `json:"objective"`
	MalwareTypes []string `json:"malware_types"`
}

type octiRelationshipEdge struct {
	Node struct {
		RelationshipType string            `json:"relationship_type"`
		To               octiRelatedEntity `json:"to"`
		From             octiRelatedEntity `json:"from"`
	} `json:"node"`
}

type octiRelationshipConnection struct {
	Edges []octiRelationshipEdge `json:"edges"`
}

// techniqueRefsFrom extracts TechniqueRef entries from a "uses"->Attack-Pattern
// connection, reusing the exact same ID-validation/tactic-parsing rules
// convertActor already applies to attackPatterns.
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

// campaignRefsFrom extracts campaign identity from an "attributed-to"<-Campaign
// connection (queried via fromTypes -- see the relationship-direction table).
func campaignRefsFrom(conn octiRelationshipConnection) []octiRelatedEntity {
	out := make([]octiRelatedEntity, 0, len(conn.Edges))
	for _, e := range conn.Edges {
		out = append(out, e.Node.From)
	}
	return out
}

// malwareRefsFrom extracts malware identity from a "uses"->Malware connection.
func malwareRefsFrom(conn octiRelationshipConnection) []octiRelatedEntity {
	out := make([]octiRelatedEntity, 0, len(conn.Edges))
	for _, e := range conn.Edges {
		out = append(out, e.Node.To)
	}
	return out
}
```

`convertActor`'s existing `attackPatterns` handling gets rewritten to call `techniqueRefsFrom` instead of its current inline loop (behavior-preserving — same `isATTACKID`/tactic logic, just factored out so `convertCampaign`/`convertMalware`-equivalents below reuse it instead of re-deriving it). This is the reusable-resolver structure requested — pure functions over already-fetched data rather than a stateful object issuing its own queries, since the actual fetch is still one combined round-trip per `Fetch()` call (matching this file's and MISP's existing single-round-trip discipline).

### 4. New shared model fields

Both genuinely populated by OpenCTI, unlike MISP:

```go
// internal/intelligence/models.go additions
type Campaign struct {
	// ... existing fields unchanged ...
	Objective string `json:"objective,omitempty"` // OpenCTI-only; empty for MISP-sourced campaigns
}

type Malware struct {
	// ... existing fields unchanged ...
	MalwareTypes []string `json:"malwareTypes,omitempty"` // e.g. "ransomware", "trojan" -- OpenCTI-only
}
```

Both `omitempty`/zero-cost for MISP-sourced records, matching the existing `SourceRef.Provider`-per-record pattern of "some fields are only ever populated by some sources."

### 5. Extraction flow in `Fetch()`

For each merged actor node (from step 1):
1. `convertActor` as today, now calling `techniqueRefsFrom(node.AttackPatterns)`.
2. `campaignRefsFrom(node.CampaignsAttributedFrom)` (the `fromTypes` query) → for each, build an `intelligence.Campaign` with `ID = standard_id`, `Name`, `Description`, `Objective`, `ThreatActorIDs: []string{actor.Name}`, `TechniqueIDs: techniqueRefsFrom(campaignNode.own AttackPatterns query)` — this requires the actor's nested `campaigns` field to itself carry a nested `attackPatterns` sub-selection (three levels of nesting: actor → campaign → technique — GraphQL supports this natively, already validated against the live instance during design).
3. `malwareRefsFrom(node.Malwares)` → for each, build an `intelligence.Malware` with `ID = intelligence.MalwareKey(name)`, `Name`, `Aliases`, `MalwareTypes`, `ThreatActorIDs: []string{actor.Name}`, `TechniqueIDs: techniqueRefsFrom(malwareNode's own nested attackPatterns)`.

Same `SourceRef{Provider: "opencti", ExternalID: <standard_id for Campaign, MalwareKey for Malware>, LastUpdated: <modified>, Confidence: confidenceLabel(...)}` shape as MISP's design.

### 6. `UpsertCampaign` needs the same array-union merge `UpsertMalware` already has

Because Campaign extraction is driven per-actor (step 2 above), the *same* campaign (same `standard_id`) can legitimately surface under two different actors within one `Fetch()` call if OpenCTI has it attributed to both — real data already shows multi-actor attribution is not hypothetical. Today's `UpsertCampaign` (Phase 1) **overwrites** `actor_ids`/`technique_ids` on conflict, which was safe for MISP (one campaign ID is always exactly one event, never re-attributed within a sync) but would silently drop the first actor's attribution when OpenCTI emits the second. Fix: change `UpsertCampaign`'s `ON CONFLICT` clause to union `actor_ids`/`technique_ids` the same way `UpsertMalware` already does, leaving `name`/`description`/`source_*`/`last_updated` as plain overwrites (those don't need merging — they describe the same real-world thing).

```sql
ON CONFLICT (id) DO UPDATE SET
  name = EXCLUDED.name, description = EXCLUDED.description,
  actor_ids     = ARRAY(SELECT DISTINCT UNNEST(intelligence_campaigns.actor_ids || EXCLUDED.actor_ids)),
  technique_ids = ARRAY(SELECT DISTINCT UNNEST(intelligence_campaigns.technique_ids || EXCLUDED.technique_ids)),
  source_provider = EXCLUDED.source_provider, source_external_id = EXCLUDED.source_external_id,
  source_confidence = EXCLUDED.source_confidence, last_updated = EXCLUDED.last_updated
```

This is a behavior-preserving change for MISP (its campaigns never collide within a sync, so union-of-one-element equals overwrite) and a real correctness fix for OpenCTI.

### 7. `FetchIntelligence()` — unchanged pattern

`OpenCTIClient` gains the identical `lastCampaigns []intelligence.Campaign` / `lastMalware []intelligence.Malware` fields and `FetchIntelligence()` method MISP already has, populated during `Fetch()`. `OpenCTIClient` now also implements `IntelligenceSource`. **Zero changes needed to `Scheduler.sync()`** — the `if is, ok := src.(IntelligenceSource); ok` type-assertion added in Phase 1 already picks up any source implementing the interface, MISP or OpenCTI alike.

## Non-Goals reiterated for the future (per the user's explicit direction)

The relationship-extraction-helper structure above is deliberately generic so that a future Tool/Infrastructure/Identity/Incident/Vulnerability extraction reuses `techniqueRefsFrom`-style helpers rather than each duplicating GraphQL response parsing — but none of those entity types are built in this phase. The `intelligence` package's core model (`Campaign`, `Malware`, `SourceRef`) is meant to keep growing entity-by-entity as real connector data justifies it, not to be redesigned wholesale — matching [[ADR-012 Intelligence Repository Scoped to MISP-Only Campaigns and Malware]]'s original framing of "grow the shared model, don't flatten everything into one entity."

## Testing

- `internal/connector`: `TestOpenCTIClient_Fetch_MergesThreatActorsAndIntrusionSets` — mock GraphQL server returning both collections, confirm merged output. `TestOpenCTIClient_FetchIntelligence_CampaignsUseOwnTechniques` — confirm a campaign's `TechniqueIDs` come from its own nested query, not the actor's. `TestOpenCTIClient_FetchIntelligence_MalwareHasOwnTechniques`. Unit tests for `techniqueRefsFrom`/`campaignRefsFrom`/`malwareRefsFrom` directly against hand-built `octiRelationshipConnection` fixtures (no HTTP mock needed for these three).
- `internal/intelligence`: `TestUpsertCampaign_MergesActorIDsOnConflict` — two upserts of the same campaign ID with different `ThreatActorIDs`, assert the union, mirroring `TestUpsertMalware_MergesArraysOnConflict` already in Phase 1.
- Full regression (`go test ./... -count=1`, `go build ./...`, `go vet ./...`) as the final plan task, plus a re-run of every existing OpenCTI test (`opencti_stats_test.go`) to confirm the query restructuring doesn't change actor-extraction behavior for callers that only care about `Fetch()`'s `[]ThreatActor` return.
