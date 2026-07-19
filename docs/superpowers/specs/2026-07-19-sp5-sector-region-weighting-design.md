# SP5 — Sector/Region Weighting Design

**Status:** Approved, pending spec review.

## Goal

Close the last open item of SP5 (Threat Intelligence Pipeline): use a threat actor's targeted sectors/regions (already fetched by `internal/connector` from MISP/OpenCTI/bundle, currently barely used) to (1) tag auto-generated scenarios as sector/region-relevant, and (2) weight technique priority scores — in per-run reports, the EPSS Priority Index, and `internal/recommend`'s "best next simulation" ranking — so a technique tied to an actor that specifically targets the deployment's own industry/geography scores higher than an otherwise-identical one that doesn't.

## Current State (why this is a gap)

- `connector.ThreatActor` already carries `Sectors []string` and `Regions []string`, populated from MISP/OpenCTI/an air-gapped bundle.
- `generator.buildYAML` uses `Sectors` only as a cosmetic scenario tag; `Regions` is never referenced anywhere.
- `Scheduler.sync()` discards the fetched `[]ThreatActor` list once scenario YAMLs are written — nothing is persisted.
- `reporting.ComputePriorityScore` (used by per-run reports, the EPSS Priority Index, and `internal/recommend`) only knows an actor *count* per technique, sourced from the embedded ATT&CK STIX bundle (`attackdata.GroupTechniqueIndex()`) — it has no actor identity, and therefore no way to know whether any of those actors are sector/region-relevant even in principle.
- Nowhere in the system stores the deployment's own sector/region to weight against.

## Decisions

- **Both scenario generation and report/dashboard priority scoring are in scope** (not scenario generation alone) — a technique's priority score should reflect sector/region relevance everywhere the score is used, not just at generation time.
- **Sector/region data source: the live connector `ThreatActor` list** (MISP/OpenCTI/bundle), not a new curated overlay. This was an explicit, deliberate choice — accepted with its two known trade-offs (see below), not an oversight:
  - Core report/scoring today is fully embedded/offline (`attackdata`'s own doc comment states this explicitly). Wiring in live connector data means the sector/region *signal* — but not any other part of scoring — now depends on the connector having synced at least once from a live source or a manually-refreshed bundle. When it hasn't, the signal is simply absent (see "Fully additive" below) — scoring never breaks, it just doesn't get the bonus.
  - Actor names from MISP/OpenCTI don't always match ATT&CK's canonical STIX group names (aliasing). Matching is therefore deliberately conservative — exact normalized name/alias match only, never fuzzy — so a near-miss produces no bonus rather than a wrong one.
- **Deployment's own sector/region: a single global setting**, `THREAT_SECTOR`/`THREAT_REGION` env vars (comma-separated) — not per-tenant. `internal/connector` is architected entirely globally today (one shared scheduler, one shared `scenarios/intel/` output directory, no tenant awareness anywhere in it); making sector/region tenant-aware would require tenant-scoping the connector itself first, which is out of scope here and arguably belongs to the still-unscheduled Multi-Tenancy full-rollout instead.
- **No new admin UI/API** — env-var configuration only, consistent with other connector-level settings (`AGENT_SECRET`, `ART_DIR`, `KEV_FILE`, etc.).
- **Matching is exact, not fuzzy**, on both axes:
  - Actor name/alias → STIX group name: normalize (lowercase, strip spaces/hyphens — the same normalization `connector.actorKey()` already uses for merging actors across sources) and require an exact match against a group's canonical name or one of the actor's own aliases.
  - Sector/region tag overlap: case-insensitive exact string match on individual tags (e.g. `THREAT_SECTOR=financial-services` will not match an actor tagged `banking` unless the admin sets the env var to the taxonomy value their MISP/OpenCTI instance actually emits). A full taxonomy normalizer is out of scope — this is a precision limit, stated explicitly, not a bug.
- **Scenario generation is tag-only, not a filter** — a sector/region-relevant scenario gets an extra tag; nothing is excluded from generation based on sector/region. Filtering would silently hide legitimate scenarios for actors whose tags are merely missing or stale.
- **Fully additive and offline-safe by construction** — when `threat_actor_profiles` is empty (connector never synced) or `THREAT_SECTOR`/`THREAT_REGION` are unset, every score and tag behaves exactly as it does today. The feature can only add a signal, never remove or alter existing behavior in its absence.

## Architecture

- **New table `threat_actor_profiles`**, written by `internal/connector`, read by `internal/reporting` — DB-mediated, no new Go package dependency between the two (matches the existing pattern: KEV/EPSS/CVE enrichment is also produced by one subsystem and read via SQL by reporting).
- `attackdata` is untouched — it stays pure/embedded/offline-only, exactly as today.
- Two independent, small, local implementations of "does actor.Sectors/Regions overlap the deployment's configured sector/region" — one in `internal/connector` (scenario tagging), one in `internal/reporting` (score weighting). Too small a check to be worth a shared abstraction across packages that otherwise have no dependency on each other.

## Data Model

```sql
CREATE TABLE IF NOT EXISTS threat_actor_profiles (
    name       text        PRIMARY KEY,
    aliases    text[]      NOT NULL DEFAULT '{}',
    sectors    text[]      NOT NULL DEFAULT '{}',
    regions    text[]      NOT NULL DEFAULT '{}',
    source     text        NOT NULL DEFAULT '',
    last_seen  timestamptz,
    updated_at timestamptz NOT NULL DEFAULT NOW()
)
```

Upserted (`ON CONFLICT (name) DO UPDATE`) by `Scheduler.sync()` for every actor in the already-merged `[]ThreatActor` list, right before `generator.Write(actors)`. No pruning — a profile persists until the connector fetches that actor again with different data, or indefinitely if the connector is later disabled, mirroring how the connector's own generated scenario YAMLs already behave.

## Component Changes

### `internal/connector`

- `Scheduler.sync()`: after `MergeActors`, upsert each actor into `threat_actor_profiles` (new small DB call using the pool already available to the scheduler).
- `generator.buildYAML`: read `THREAT_SECTOR`/`THREAT_REGION` (comma-split, lowercased), compare against the actor's own `Sectors`/`Regions` (lowercased) for any overlap. On a match, append `sector-relevant` and/or `region-relevant` to the scenario's existing `tags:` list, alongside the sector tags it already adds.

### `internal/reporting`

- New function in `insights.go`:
  ```go
  func SectorRegionRelevantTechniques(ctx context.Context, db *pgxpool.Pool, sector, region string) (map[string]bool, error)
  ```
  Returns immediately with an empty map (no query issued) when both `sector` and `region` are empty. Otherwise queries `threat_actor_profiles`, normalizes each profile's `name`+`aliases`, matches against every STIX group name in `attackdata.GroupTechniqueIndex()`, and for each match whose `sectors`/`regions` overlap the given `sector`/`region`, adds every technique ID under that group to the returned set.
- `ComputePriorityScore` gains a 5th parameter:
  ```go
  func ComputePriorityScore(kev bool, epssPercentile float64, actors int, verdict string, sectorRegionRelevant bool) int
  ```
  `sectorRegionRelevant=true` contributes **+10** (same tier as the existing verdict==fail bonus), still capped at 100.
- `engine.go`: calls `SectorRegionRelevantTechniques` once per report build (passing the orchestrator's configured `THREAT_SECTOR`/`THREAT_REGION`), then passes `relevant[tid]` into each `ComputePriorityScore` call.
- `internal/recommend/recommend.go`: same pattern — one additional call, `ComputePriorityScore`'s new parameter threaded through, so "best next simulation" ranking also reflects sector/region relevance.

## Error Handling

- `SectorRegionRelevantTechniques` returning a DB error is treated the same way every other enrichment query failure in `engine.go` already is: logged, enrichment for that signal degraded to absent (empty map), report generation continues rather than failing outright — consistent with the existing "a connector/store error writes nothing, never fabricates a verdict" discipline used throughout this codebase's threat-intel enrichment.
- `Scheduler.sync()`'s upsert failing for one actor is logged and skipped, never aborting the rest of the sync — same "one source/actor failing never aborts others" discipline `sync()` already applies to source fetches.

## Testing Strategy

- `internal/connector`: unit test that `buildYAML` appends `sector-relevant`/`region-relevant` tags when an actor's Sectors/Regions overlap env-configured values, and omits them otherwise; a `Scheduler.sync()` test (in-memory fake `Source`) asserting `threat_actor_profiles` is upserted after a sync.
- `internal/reporting`: `ComputePriorityScore` table test extended with the new parameter's branches (adds exactly 10 when true, capped at 100 when combined with other max signals). Docker-backed test for `SectorRegionRelevantTechniques`: seed a profile whose name/alias matches a known embedded STIX group, assert the correct technique IDs come back; a second test asserts an empty map — and no DB query — when `sector`/`region` are both empty.
- `internal/recommend`: existing tests updated for `ComputePriorityScore`'s new parameter; one new test confirms a sector/region-relevant technique ranks above an otherwise-identical non-relevant one.

## Out of Scope

- Per-tenant sector/region (global-only for this slice).
- Fuzzy/taxonomy-normalized sector/region matching (exact tag match only).
- Fuzzy actor-name matching beyond exact normalized name/alias (no partial/similarity matching).
- Filtering scenario generation by sector/region relevance (tagging only).
- Any new admin UI/API for configuring sector/region (env vars only).
- Pruning stale `threat_actor_profiles` rows.
