# SP5 — Sector/Region Weighting Design

**Status:** Approved, corrected during grounding (see "Corrections made while grounding" at the end), pending spec review.

## Goal

Close the last open item of SP5 (Threat Intelligence Pipeline): use a threat actor's targeted sectors/regions (already fetched by `internal/connector` from MISP/OpenCTI/bundle, currently barely used) to (1) tag auto-generated scenarios as sector/region-relevant, and (2) weight technique priority scores — in per-run reports, the EPSS Priority Index, and `internal/recommend`'s "best next simulation" ranking — so a technique tied to an actor that specifically targets the deployment's own industry/geography scores higher than an otherwise-identical one that doesn't.

## Current State (why this is a gap)

- `connector.ThreatActor` already carries `Sectors []string` and `Regions []string`, populated from MISP/bundle (OpenCTI never populates them at all — see "OpenCTI gap" below).
- `generator.buildYAML` uses `Sectors` only as a cosmetic scenario tag; `Regions` is never referenced anywhere in scenario generation.
- `Scheduler.sync()` discards the fetched `[]ThreatActor` list once scenario YAMLs are written — nothing is persisted.
- `reporting.ComputePriorityScore` (used by per-run reports, the EPSS Priority Index, and `internal/recommend`) only knows an actor *count* per technique, sourced from the embedded ATT&CK STIX bundle (`attackdata.GroupTechniqueIndex()`) — it has no actor identity, and therefore no way to know whether any of those actors are sector/region-relevant even in principle.
- **The deployment's own sector/region already has a config home**: `config.Config.ThreatIntelSectors`/`ThreatIntelRegions` (`[]string`, JSON-config-driven, no env var loading today) already exist and are already threaded into `connector.NewMISPClient`/`NewOpenCTIClient` at startup (`cmd/server/main.go`). They're just underused — see the two bugs below.

## Two real bugs found while grounding, bundled into this slice

- **MISP's region filter is dead code**: `MISPClient.regions` is stored in the struct and passed into the constructor, but the actual filtering code (`misp.go`) only checks `c.sectors` — `c.regions` is never read anywhere. The comment above it ("Apply sector/region filter") is aspirational, not accurate. **Fixed as part of this slice**: extend the same `intersects()` check already used for sectors to also check regions.
- **OpenCTI's sector filter is unfixable in this slice, and stays a documented gap**: `OpenCTIClient.sectors` is stored but never read either — but unlike MISP, this isn't just a missing filter check. OpenCTI's GraphQL query (`octiThreatActorNode`) never fetches sector/region data from OpenCTI's schema at all, so `actor.Sectors`/`actor.Regions` are always empty for every OpenCTI-sourced actor. Naively wiring the same filter-check pattern in would be a **regression**, not a fix: an always-empty `actor.Sectors` never intersects a configured `c.sectors`, so turning the filter "on" would silently reject every OpenCTI actor the moment `ThreatIntelSectors` is set — worse than today's silent no-op. Properly fixing this requires extending the GraphQL query with OpenCTI's actual sector/region relationship fields, which can't be verified without a live OpenCTI instance and is explicitly out of scope here. `OpenCTIClient.sectors` gets a code comment explaining why it's unused, rather than being silently left to look like an oversight.

## Decisions

- **Both scenario generation and report/dashboard priority scoring are in scope** (not scenario generation alone) — a technique's priority score should reflect sector/region relevance everywhere the score is used, not just at generation time.
- **Sector/region data source: the live connector `ThreatActor` list** (MISP/bundle — OpenCTI doesn't populate these fields, see above), not a new curated overlay. This was an explicit, deliberate choice — accepted with its two known trade-offs, not an oversight:
  - Core report/scoring today is fully embedded/offline (`attackdata`'s own doc comment states this explicitly). Wiring in live connector data means the sector/region *signal* — but not any other part of scoring — now depends on the connector having synced at least once from MISP or a manually-refreshed bundle. When it hasn't, the signal is simply absent (see "Fully additive" below) — scoring never breaks, it just doesn't get the bonus.
  - Actor names from MISP don't always match ATT&CK's canonical STIX group names (aliasing). Matching is therefore deliberately conservative — exact normalized name/alias match only, never fuzzy — so a near-miss produces no bonus rather than a wrong one.
- **Deployment's own sector/region: reuse the existing `config.Config.ThreatIntelSectors`/`ThreatIntelRegions` (`[]string`)** — not new env vars. These already exist, are already JSON-config-driven, and are already threaded to the MISP/OpenCTI constructors at startup; this slice threads the same two slices to the two new consumers (the generator and the reporting engine) instead of duplicating config.
- **No new admin UI/API** — the config surface already exists (JSON config file); this slice doesn't add to it.
- **Matching is exact, not fuzzy**, on both axes:
  - Actor name/alias → STIX group name: normalize (lowercase, strip spaces/hyphens — the same normalization `connector.actorKey()` already uses for merging actors across sources) and require an exact match against a group's canonical name or one of the actor's own aliases.
  - Sector/region tag overlap: case-insensitive exact string match on individual tags, via the connector package's existing `intersects()` helper (already used for MISP's sector filter — reused here rather than reimplemented) — e.g. a `ThreatIntelSectors` value of `financial-services` will not match an actor tagged `banking` unless the config uses the taxonomy value the source actually emits. A full taxonomy normalizer is out of scope — this is a precision limit, stated explicitly, not a bug.
- **Scenario generation is tag-only, not a filter** — a sector/region-relevant scenario gets an extra tag; nothing is excluded from generation based on sector/region. Filtering would silently hide legitimate scenarios for actors whose tags are merely missing or stale.
- **Fully additive and offline-safe by construction** — when `threat_actor_profiles` is empty (connector never synced) or `ThreatIntelSectors`/`ThreatIntelRegions` are unset, every score and tag behaves exactly as it does today. The feature can only add a signal, never remove or alter existing behavior in its absence.

## Architecture

- **New table `threat_actor_profiles`**, written by `internal/connector`, read by `internal/reporting` — DB-mediated, no new Go package dependency between the two (matches the existing pattern: KEV/EPSS/CVE enrichment is also produced by one subsystem and read via SQL by reporting).
- `attackdata` is untouched — it stays pure/embedded/offline-only, exactly as today.
- The sector/region overlap check (`intersects()`) is a single existing helper in `internal/connector`, reused by both the scenario-tagging code (same package) and — since `internal/reporting` doesn't import `internal/connector` — a small local equivalent in `internal/reporting` for the scoring side. Two call sites, one simple rule, no shared package needed for something this small.

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

- `misp.go`: extend the existing sector filter to also check `c.regions` via `intersects()`, fixing the dead-code region filter.
- `opencti.go`: add a code comment on `OpenCTIClient.sectors` explaining it's currently unused because OpenCTI's GraphQL query doesn't fetch sector/region data — an honest documented gap, not a silent one.
- `Scheduler` gains a `pool *pgxpool.Pool` field (threaded through `NewScheduler`); `sync()` upserts each merged actor into `threat_actor_profiles` right before `generator.Write(actors)`.
- `Generator` gains `sectors, regions []string` fields (threaded through `NewGenerator`); `buildYAML` becomes a method on `*Generator` so it can read them, and appends `sector-relevant`/`region-relevant` tags via `intersects()` against the actor's own `Sectors`/`Regions`.
- `cmd/server/main.go`: `NewScheduler(...)` gains the DB pool argument; `NewGenerator(...)` gains `cfg.ThreatIntelSectors, cfg.ThreatIntelRegions`.

### `internal/reporting`

- New function in `insights.go`:
  ```go
  func SectorRegionRelevantTechniques(ctx context.Context, db *pgxpool.Pool, sectors, regions []string) (map[string]bool, error)
  ```
  Returns immediately with an empty map (no query issued) when both `sectors` and `regions` are empty. Otherwise queries `threat_actor_profiles`, normalizes each profile's `name`+`aliases`, matches against every STIX group name in `attackdata.GroupTechniqueIndex()`, and for each match whose `sectors`/`regions` overlap the given values, adds every technique ID under that group to the returned set.
- `ComputePriorityScore` gains a 5th parameter:
  ```go
  func ComputePriorityScore(kev bool, epssPercentile float64, actors int, verdict string, sectorRegionRelevant bool) int
  ```
  `sectorRegionRelevant=true` contributes **+10** (same tier as the existing verdict==fail bonus), still capped at 100.
- `Engine` gains `sectors, regions []string` fields, a `WithSectorRegion(sectors, regions []string) *Engine` builder (chained the same way `WithRuleLibrary` already is), and exported `Sectors() []string`/`Regions() []string` accessors so other packages holding an `*Engine` (like `internal/api`) can read the configured values without new storage of their own.
- `engine.go`'s `populatePriorityScores`: calls `SectorRegionRelevantTechniques(ctx, e.db, e.sectors, e.regions)` once, then passes `relevant[tid]` into each `ComputePriorityScore` call.
- `cmd/server/main.go`: `reporting.NewEngine(pool).With...` chain gains `.WithSectorRegion(cfg.ThreatIntelSectors, cfg.ThreatIntelRegions)`.

### `internal/recommend`

- `Build` gains two trailing parameters: `func Build(ctx context.Context, pool *pgxpool.Pool, g *attackpath.Graph, s attackpath.Summary, limit int, sectors, regions []string) (Recommendations, error)`. Calls `reporting.SectorRegionRelevantTechniques` once, threads `relevant[key]` into its own `reporting.ComputePriorityScore` call.
- `internal/api/recommend_handlers.go`: `GetRecommendedSimulations` passes `h.reportingEngine.Sectors(), h.reportingEngine.Regions()` into `recommend.Build` — no new `Handler` fields needed, reuses the reporting engine it already holds via `WithReporting`.

## Error Handling

- `SectorRegionRelevantTechniques` returning a DB error is treated the same way every other enrichment query failure in `engine.go` already is: logged, enrichment for that signal degraded to absent (empty map), report generation continues rather than failing outright — consistent with the existing "a connector/store error writes nothing, never fabricates a verdict" discipline used throughout this codebase's threat-intel enrichment.
- `Scheduler.sync()`'s upsert failing for one actor is logged and skipped, never aborting the rest of the sync — same "one source/actor failing never aborts others" discipline `sync()` already applies to source fetches.

## Testing Strategy

- `internal/connector`: unit test that MISP's fetch now filters on regions too (mirroring the existing sector-filter test, if one exists, or added alongside it); unit test that `buildYAML` appends `sector-relevant`/`region-relevant` tags when an actor's Sectors/Regions overlap the configured values, and omits them otherwise; a new Docker-backed `Scheduler.sync()` test (in-memory fake `Source` + a real test DB) asserting `threat_actor_profiles` is upserted after a sync — the first DB-backed test in this package, so it also adds the package's `TestMain`/`sharedDB` scaffolding.
- `internal/reporting`: `ComputePriorityScore` table test extended with the new parameter's branches (adds exactly 10 when true, capped at 100 when combined with other max signals). Docker-backed test for `SectorRegionRelevantTechniques`: seed a profile whose name/alias matches a known embedded STIX group, assert the correct technique IDs come back; a second test asserts an empty map — and no DB query — when `sectors`/`regions` are both empty.
- `internal/recommend`: existing `Build` call sites in tests updated for the two new trailing parameters; one new test confirms a sector/region-relevant technique ranks above an otherwise-identical non-relevant one.

## Out of Scope

- Per-tenant sector/region (global-only for this slice).
- Fuzzy/taxonomy-normalized sector/region matching (exact tag match only).
- Fuzzy actor-name matching beyond exact normalized name/alias (no partial/similarity matching).
- Filtering scenario generation by sector/region relevance (tagging only).
- Fixing OpenCTI's sector/region data gap (documented, not fixed — needs a verified live OpenCTI schema to do safely).
- Any new admin UI/API for configuring sector/region (existing JSON config only).
- Pruning stale `threat_actor_profiles` rows.

## Corrections made while grounding (before writing the implementation plan)

1. The original design invented new `THREAT_SECTOR`/`THREAT_REGION` env vars, believing "nowhere in the system stores the deployment's own sector/region." Grounding against the actual code found `config.Config.ThreatIntelSectors`/`ThreatIntelRegions` already exist and are already wired to the MISP/OpenCTI constructors — corrected to reuse them instead of adding duplicate config.
2. That same grounding surfaced two real, previously-unknown bugs (MISP's dead region filter, OpenCTI's non-functional sector filter) — presented to the user, who approved fixing the safe one (MISP) and documenting the other (OpenCTI, which can't be safely fixed without a live instance to verify its GraphQL schema against).
3. `SectorRegionRelevantTechniques`'s signature changed from `(sector, region string)` (comma-parsed) to `(sectors, regions []string)`, matching the existing config's native shape instead of requiring a parse step that was never actually needed.
