# Source Provenance — Design

**Status:** Approved 2026-08-11
**Scope:** First of three related sub-projects the user decomposed from a single architecture-feedback proposal. This one covers per-source actor provenance only. Two deliberately deferred: OTX restructured as a distinct "Activity Signal" (not an Actor Profile peer), and a per-relationship (`actor uses technique`) evidence layer.

## Problem

`internal/connector.MergeActors` (built earlier today, commits `3e6d5e8`/`f0c8405`..`9266b48`) collapses every source's fetched `ThreatActor` for the same real-world actor into a single flattened `threat_actor_profiles` row. Its merge policy is first-arrival-wins on `Name`/`Description`/`Sectors`/`Regions`/`Source`/`SourceID`/`Confidence` — only `Techniques`/`Aliases`/`LastSeen`/`CanonicalGroupID` are actually merged across sources.

Concretely: if MISP (sectors=BFSI, confidence=high) and OpenCTI (aliases=[...], confidence=high) both describe the same actor in one sync cycle, and MISP happens to arrive first, the persisted row keeps MISP's `Sectors` and discards OpenCTI's `Aliases` contribution to that same field-selection decision (aliases specifically are folded in via union, but the *general pattern* — one source's assertion silently overwriting or never being recorded against another's, for every non-merged field — is real). There is no way today to answer "why does Audspect believe this actor is relevant" by source. `internal/connector/types.go`'s own package doc still says *"polls MISP and OpenCTI"*, and `ThreatActor.Source`'s comment still only documents `"misp" | "opencti" | "bundle"` — OTX (added later) was never acknowledged in the type system, though that specific restructuring is sub-project #2, not this one.

No existing pattern in this codebase solves this. `internal/intelligence.SourceRef` (used by Campaign/Malware/Tool records) looks like a candidate but has the identical problem — a single `source_provider`/`source_external_id`/`source_confidence` set of columns per record, with a `CASE WHEN id = $N THEN EXCLUDED.x ELSE existing.x` last-writer-wins pattern on conflict (`internal/intelligence/store.go:109-116`). This is genuinely new ground for the codebase, not a reuse of something already solved.

## Goal

Preserve every source's own raw, pre-merge assertions about an actor as a queryable, per-source record — without changing how the canonical/merged `threat_actor_profiles` row is computed. Surface it on the actor detail view so a user can see exactly which source said what.

## Non-goals

- **No change to `threat_actor_profiles`'s merge policy.** First-arrival-wins on non-merged fields stays exactly as today. This project is purely additive — it persists what's currently being discarded, it does not change what gets computed or scored.
- **No change to `internal/threatpriority`'s scoring factors.** They keep reading the single flattened `ActorProfile` exactly as today (including this morning's `RelevanceFactor` unknown-vs-none fix, commit `e8d110a`, which is unaffected either way). Making the scorer source-aware is real future work, not this project.
- **No new data fetched from any connector.** Every field this project persists is already fetched and already sitting in memory during `Scheduler.sync()` — this project stops discarding it, it does not add new API calls or new fields to any connector.
- **No OTX restructuring** (sub-project #2) and **no per-relationship (`uses -> technique`) evidence** (sub-project #3) — both explicitly deferred, own brainstorm cycles later.
- Consistent with the user's own "what I would not add now" list: no forced sector/region/alias enrichment, no new TI feeds, no coupling to OpenAEV.

## Design

### Data model

```sql
CREATE TABLE threat_actor_sources (
    actor_name      text NOT NULL REFERENCES threat_actor_profiles(name),
    source          text NOT NULL,                    -- "misp" | "opencti" | "otx"
    source_id       text NOT NULL DEFAULT '',
    name            text NOT NULL,                     -- this source's OWN name for the actor
    aliases         text[] NOT NULL DEFAULT '{}',
    sectors         text[] NOT NULL DEFAULT '{}',
    regions         text[] NOT NULL DEFAULT '{}',
    confidence      text NOT NULL DEFAULT '',
    technique_count int NOT NULL DEFAULT 0,
    last_seen       timestamptz,
    updated_at      timestamptz NOT NULL DEFAULT NOW(),
    PRIMARY KEY (actor_name, source)
);
```

One row per (canonical actor, source), upserted every sync cycle. `actor_name` is keyed the same way `threat_actor_profiles.name` already is (the canonical survivor's first-arrival-wins `Name`) — this carries the same pre-existing characteristic `threat_actor_profiles` already has (if arrival order changes between sync cycles, which source "wins" the canonical name could shift); this project doesn't introduce that risk, it's already how the table works today, and fixing it is out of scope here.

`last_seen` is naturally source-scoped in this model — MISP's event timestamp, OpenCTI's `Modified` timestamp, and OTX's pulse timestamp each land in their own row instead of one overwriting another via first-arrival-wins. This satisfies the user's freshness-semantics point (their point 5) with no additional work beyond the table existing.

`technique_count` (not the full technique list) is deliberately the minimal signal for "how much this source knows" — persisting each source's own full technique list with per-technique provenance is exactly sub-project #3's job, not this one.

### Sourcing the data: nothing new is fetched

`Scheduler.sync()` (`internal/connector/scheduler.go:178+`) already fetches every source's raw `ThreatActor` list into a local `actors []ThreatActor` before merging:

```go
actors = MergeActors(actors)                    // scheduler.go:232 -- overwrites the pre-merge list
s.upsertActorProfiles(actors)                    // scheduler.go:236
```

The pre-merge list is captured into its own variable before this reassignment (a one-line change) so it survives to be persisted afterward.

### The wiring problem: recovering which raw actor fed which survivor

`MergeActors`' public signature (`func MergeActors(actors []ThreatActor) []ThreatActor`) only returns the merged survivors — internally, `actor_merge.go`'s union-find already knows which raw input actors grouped into which survivor, but that grouping isn't exposed.

Add a new function, `MergeActorsWithProvenance(actors []ThreatActor) (merged []ThreatActor, groups [][]int)`, where `groups[i]` holds the indices into the input `actors` slice that merged into `merged[i]`. Make `MergeActors` a thin wrapper (`merged, _ := MergeActorsWithProvenance(actors); return merged`) so its existing signature, and every existing caller (`scheduler.go`, `build_bundle.go`, all of today's `actor_merge_test.go` tests), is completely unaffected.

`Scheduler.sync()` switches to calling `MergeActorsWithProvenance` directly, using `groups` to know, for each survivor, which raw pre-merge actors (and therefore which sources) contributed to it.

### Persistence

New `Store`-level function `upsertActorSources(rawActors []ThreatActor, merged []ThreatActor, groups [][]int)`, called from `Scheduler.sync()` right after `upsertActorProfiles`. For each survivor index `i`, for each raw actor index `j` in `groups[i]`, upsert one `threat_actor_sources` row keyed `(merged[i].Name, rawActors[j].Source)`.

### API & UI

`GET /api/threat-priority/actors/{name}`'s response (`threatPriorityActorDetail`, `internal/api/threatpriority_handlers.go`) gains a `sources []ActorSource` field, queried from the new table. A new "Sources" card on the Threat Prioritization actor detail view (`orchestrator/wwwroot/index.html`, same view Actor Coverage Breakdown already lives on) renders one block per source — name/aliases/sectors/regions/confidence/last-seen as that source itself reported them, matching the user's own example format.

## Testing

- `MergeActorsWithProvenance`: the grouping returned for a multi-source merge (e.g. MISP "Wizard Spider" + OpenCTI "Sangria Tempest" merging via alias/canonical-ID bridging) correctly maps back to both raw input indices; a merge with no bridging (single-source actor) returns a single-element group; `MergeActors` itself is unaffected (existing `actor_merge_test.go` suite must stay green unmodified).
- `upsertActorSources`: two sources describing the same canonical actor produce two distinct `threat_actor_sources` rows, each carrying that source's own raw values; re-running sync with unchanged data upserts idempotently (no duplicate rows, `updated_at` advances).
- API: `GET /api/threat-priority/actors/{name}` returns a `sources` array with one entry per contributing source, each showing that source's own name/aliases/sectors/regions/confidence — not the canonical row's flattened values.
- Regression: `threat_actor_profiles`'s own values (and everything in `internal/threatpriority`, including the `RelevanceFactor` fix from `e8d110a`) are provably unchanged by this project — no existing test in either package should need modification.

## Relationship to sub-projects #2 and #3

This project makes source-level provenance a real, queryable concept for the first time in this codebase. Sub-project #2 (OTX as Activity Signal) and #3 (per-relationship evidence, `actor uses technique`) both become natural extensions once this exists, rather than each needing to invent their own provenance-carrying shape from scratch. Neither is started by this project.
