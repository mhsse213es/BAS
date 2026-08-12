# Per-Relationship Technique Evidence Layer — Design Spec

**Goal:** Surface OpenCTI's real per-relationship "uses → technique" evidence (confidence, start/stop dates, and which entity — the actor directly, or a campaign/malware/tool it's linked to — asserted it) instead of the flat, provenance-free technique list every actor currently has. This is the original sub-project #3 ask from the user's architecture-feedback document, taken up now that sub-project #1 (per-source provenance) and the connector-sourced technique fallback are both shipped.

**Why this is narrower than it sounds:** investigation (this session, both in the source-provenance spec's scope note and freshly re-verified here) found that real, non-fabricated per-relationship evidence is only obtainable from OpenCTI:

- **MISP** extracts techniques from `GalaxyCluster` tags at the *whole-event* level (`MISPClient.extractActor`, `internal/connector/misp.go`) — Confidence/Sectors/Regions are event-level tags, and every technique in that event shares its one `LastSeen` timestamp. There is no per-technique date/confidence in MISP's data as fetched. Worse, `MISPClient.Fetch()` (`misp.go:85-94`) already merges multiple events describing "the same actor" *inside the MISP client itself* — even per-event granularity never leaves `misp.go`, let alone per-technique.
- **Bundle** (`internal/connector/bundle.go`) reuses the exact same flat `ThreatActor`/`TechniqueRef` shape as every other source (`Bundle.Actors []ThreatActor`) — zero additional structure.
- **OpenCTI**'s GraphQL query (`internal/connector/opencti.go:216-345`, the `actorFieldsFragment`) queries `node { to { ...AttackPattern fields } }` for each `uses`→Attack-Pattern relationship edge — it never requests the edge's own STIX relationship properties (`confidence`, `start_time`/`stop_time`). OpenCTI's schema (a native STIX relationship-object graph) almost certainly exposes these; capturing them requires a real query change, not just restructuring data already in memory.

Given this, the feature covers OpenCTI-sourced actors only. MISP/bundle-sourced actors show no evidence — an honest absence, not a fake "no data" state papering over a real capability gap.

## Scope

**In scope:**
- Extend the OpenCTI GraphQL query fragment to also request `confidence`, `start_time`, `stop_time` on each of the 4 existing `stixCoreRelationships(relationship_type: "uses", toTypes: ["Attack-Pattern"])` edges: the actor's own, and the nested ones inside `campaigns`/`malwares`/`tools`.
- A new `TechniqueEvidenceSource` interface (`FetchTechniqueEvidence() []TechniqueEvidence`), implemented by `OpenCTIClient` alone, mirroring the existing `IntelligenceSource` pattern (`FetchIntelligence()` returning state gathered during the last `Fetch()` call — not a separate round trip).
- `Via`/`ViaName` on each evidence record distinguish the direct actor→technique assertion from one reached through a linked campaign, malware, or tool — per the user's explicit choice to include the nested relationships, not just the direct one.
- A new `technique_evidence` table, resolved against the merged actor roster the same way OTX's activity signals are (reusing `actorKey` exact-match, not reinventing it).
- A new "Technique Evidence" card on the actor detail view, populated only for actors with real OpenCTI evidence.

**Explicitly out of scope:**
- MISP/bundle per-relationship evidence — structurally unavailable, not a gap this spec can close.
- Any change to Threat Prioritization scoring. `internal/threatpriority`'s `Context.TechniqueIDs` stays a flat `[]string`; no `ScoreFactor` signature changes. This is a read-only display layer, exactly like the Sources card (sub-project #1) — evidence informs a human reading the actor detail page, not the composite score.
- Orphan-actor stub creation (unlike OTX's activity signals). Evidence for an actor with no existing curated profile is simply dropped — this is enrichment for an actor that must already exist via a curated source, not a standalone signal that can create one.
- Deduplicating/merging evidence across multiple paths to the same technique. A technique reached both directly and via a linked campaign gets two separate rows — that's two real, distinct pieces of evidence, not a single fact to collapse.

## Data model

**Go types** (`internal/connector`):

```go
// TechniqueEvidenceSource is implemented by connectors that can supply
// real per-relationship confidence/date evidence for a technique
// assertion -- today, only OpenCTI's STIX relationship-object graph
// carries this data.
type TechniqueEvidenceSource interface {
	FetchTechniqueEvidence() []TechniqueEvidence
}

// TechniqueEvidence is one "uses" relationship's own STIX evidence --
// Via/ViaName distinguish a technique asserted directly by the actor from
// one reached through a linked campaign/malware/tool. Confidence/dates
// are OpenCTI's own, not fabricated or inherited from the actor's overall
// Confidence/LastSeen.
type TechniqueEvidence struct {
	ActorName   string
	TechniqueID string
	Via         string // "" (direct) | "campaign" | "malware" | "tool"
	ViaName     string // the linked entity's name, "" when Via == ""
	Confidence  int    // OpenCTI's 0-100 scale, 0 if not returned
	StartTime   *time.Time
	StopTime    *time.Time
}
```

**Query change**: add `confidence`, `start_time`, `stop_time` as sibling fields to `to { ... }` inside each of the 4 `attackPatterns: stixCoreRelationships(...)` blocks in `actorFieldsFragment`. `octiRelationshipEdge.Node` (currently just `To`/`From`) gains matching `Confidence int`, `StartTime string`, `StopTime string` fields — shared by every relationship connection in this file, but only ever populated where the query actually requests them (the 4 attackPatterns blocks), zero-valued elsewhere.

**Stated uncertainty** (same discipline as the existing sector/region comment at `opencti.go:20-29`, itself flagged unverified without a live instance): `confidence`/`start_time`/`stop_time` are inferred as OpenCTI's GraphQL field names from STIX 2.1's standard Relationship-object properties, not confirmed against a live OpenCTI schema. If wrong, the query simply returns nothing for those fields (GraphQL fails the whole request on an unknown field name, so this needs verification against a real instance before shipping — flagged explicitly as a pre-merge verification step, not a "figure it out at runtime" fallback).

**Extraction**: a new function alongside `techniqueRefsFrom`, `techniqueEvidenceFrom(conn octiRelationshipConnection, actorName, via, viaName string) []TechniqueEvidence`, called at all 4 existing `techniqueRefsFrom` call sites (`convertActor`, `convertCampaign`, `convertMalware`, `convertTool`) — each already has the actor's name and (for the nested three) the linked entity's own name (`entity.Name`) available. `OpenCTIClient.Fetch()` accumulates these into a new `lastTechniqueEvidence []TechniqueEvidence` field, exposed via `FetchTechniqueEvidence()`.

**Table**:

```sql
CREATE TABLE IF NOT EXISTS technique_evidence (
	actor_name  text NOT NULL REFERENCES threat_actor_profiles(name) ON DELETE CASCADE,
	technique_id text NOT NULL,
	via         text NOT NULL DEFAULT '',
	via_name    text NOT NULL DEFAULT '',
	source      text NOT NULL,
	confidence  int  NOT NULL DEFAULT 0,
	start_time  timestamptz,
	stop_time   timestamptz,
	updated_at  timestamptz NOT NULL DEFAULT NOW(),
	PRIMARY KEY (actor_name, technique_id, via, via_name, source)
)
```

`source` is always `'opencti'` today but kept as a real column (not hardcoded) for the same reason `threat_actor_sources`/`threat_actor_activity` keep it — a second source could exist later without a schema change.

## Sync wiring

`Scheduler.sync()` gains a third post-merge step, alongside `upsertActorSources`/`upsertActivitySignals`: for each configured `Source` that also implements `TechniqueEvidenceSource` (type-asserted, same pattern as `IntelligenceSource`/`StatsSource` checks already in `sync()`), collect its `FetchTechniqueEvidence()` result, resolve each record's `ActorName` against the merged roster via `resolveActivitySignalActor` (generalized/reused from the OTX work — same exact-match discipline, no fuzzy matching), and upsert. A record that doesn't resolve to any existing merged actor is dropped and logged, not given a stub (see Scope).

## UI

A new "Technique Evidence" card on the actor detail view, positioned after the existing Sources card. Table: Technique | Via | Confidence | Since (StartTime, formatted, blank if absent). Rendered only when the API response's evidence list is non-empty — absent entirely for MISP/bundle-only actors, matching the Sources card's own "nothing to show" convention (no card-with-empty-state clutter).

**API**: `threatPriorityActorDetail` (`internal/api/threatpriority_handlers.go`) gains a `TechniqueEvidence []TechniqueEvidence` field (a small serving-layer type mirroring the table row, not `internal/connector`'s fetch-time type — same reasoning `ActorSource`/`ActivitySignal` already established: the API layer's shape is independent of the connector's in-memory shape) and a `loadTechniqueEvidence` function, following the exact precedent `loadActorSources` (sub-project #1, Task 3) set.

## Testing

- `internal/connector`: `techniqueEvidenceFrom` unit tests (confidence/dates extracted correctly, `Via`/`ViaName` set correctly per call site, empty connection → empty slice). `OpenCTIClient.Fetch()` integration test proving evidence accumulates across all 4 sites in one sync with real fixture JSON.
- `internal/connector` (scheduler): `upsertTechniqueEvidence`-equivalent tests mirroring `upsertActivitySignals`'s pattern — resolves against merged roster; a record for an actor with no curated profile is dropped, not stubbed; two evidence rows for the same technique via different paths both persist (composite PK proves it, doesn't collide).
- `internal/api`: `loadTechniqueEvidence` test + one assertion that `threatPriorityActorDetail` serializes the new field, following the `loadActorSources` test's exact shape.
- No new Threat Prioritization test needed — scoring is untouched by design.

## Self-review

- **Placeholder scan:** none — every section has concrete types/SQL/query fragments. The one open question (exact OpenCTI field names) is stated as a verification step, not left vague.
- **Internal consistency:** "no scoring impact" is stated in Scope and reiterated in the Sync/UI sections' framing — no section implies `TechniqueIDs` changes. The "narrower than it sounds" framing in the opening and the "MISP/bundle out of scope" line in Scope agree.
- **Scope check:** single implementation plan's worth of work, comparable in size to sub-project #1 (new query fields + new interface + new table + new sync step + new API field + new UI card) — a legitimately larger spec than the technique-evidence-fallback fix, flagged as such during brainstorming and confirmed by the user's choice to include nested relationships.
- **Ambiguity check:** the composite PK's exact 5 columns are spelled out once, referenced consistently in the sync-wiring and testing sections. "Dropped, not stubbed" for unresolved evidence is stated explicitly to avoid it being conflated with OTX's stub-creation behavior, which this deliberately does not replicate.
