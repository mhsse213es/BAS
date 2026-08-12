# Connector-Sourced Technique Fallback — Design Spec

**Goal:** Threat Prioritization scoring currently gets an actor's technique list exclusively from `reporting.ResolveActorTechniques(name, aliases)` — a pure MITRE-name-match against `attackdata.GroupTechniqueIndex()`, with zero fallback. For any actor whose name (or aliases) doesn't exactly match a MITRE ATT&CK group name, Threat Prioritization scores it with **zero techniques** — empty coverage gap, empty uncovered list, empty everything — even when MISP or OpenCTI supplied real, specific technique evidence for that actor. This makes real connector-fetched technique data actually reach scoring, as a fallback behind MITRE's own (stronger) authority.

**Why now:** originally raised as sub-project #3 of the user's architecture-feedback document, framed as "a per-relationship `uses→technique` evidence layer." Investigating that scope surfaced this more fundamental gap first — decorating per-technique evidence with confidence/timestamps would be wasted work on top of a pipeline that, for non-MITRE-named actors, currently discards the technique list entirely before scoring ever sees it. The user chose to fix this gap now and defer per-relationship evidence to a later, separate sub-project.

**Architecture:** `threat_actor_profiles` gains a `techniques text[]` column, populated by `upsertActorProfiles` from the connector-merged `ThreatActor.Techniques` (already deduplicated across sources by `mergeActorGroup`, unmodified). `threatpriority.ActorProfile` gains a matching field. `scoreActor` tries `ResolveActorTechniques` first (MITRE-authoritative, stays primary — the strongest evidence) and only falls back to the connector-sourced list when MITRE has no match. A new `ActorPriority.TechniqueSource` field ("mitre" | "connector" | "") records which path won, surfaced as a small label in the UI so a connector-derived list is never mistaken for MITRE-grade evidence.

## Scope

**In scope:**
- `threat_actor_profiles.techniques text[] NOT NULL DEFAULT '{}'` column.
- `upsertActorProfiles` populates it: dedupe+uppercase the merged actor's `Techniques []TechniqueRef` into technique IDs (mirrors what `Generator.buildYAML` already does inline for the same purpose, kept as a small separate helper rather than imported cross-package, since `internal/connector` and `internal/threatpriority` don't currently import each other).
- `threatpriority.ActorProfile.Techniques []string`; `loadProfile`/`loadAllProfiles` select the new column.
- `scoreActor`'s technique resolution: MITRE-authoritative first, connector-sourced fallback second, recorded via a new `ActorPriority.TechniqueSource` field.
- A small, non-card UI label near the existing Technique Coverage Breakdown showing which source won.

**Explicitly out of scope:**
- Per-relationship (`uses→technique`) confidence/timestamp/source evidence — the original sub-project #3 ask. Deferred to a later, separate brainstorm. This fix establishes that real technique data reaches scoring at all; whether to enrich it per-relationship afterward is a distinct decision, informed by this investigation's finding that MISP's data model can't really support sub-relationship granularity below the event level anyway (see the brainstorming transcript this session), and that OpenCTI's per-relationship confidence/dates would require a new GraphQL query, not just restructuring in-memory data.
- Any change to `internal/connector/actor_merge.go`, `Generator.Write`/scenario generation, or `internal/reporting/insights.go`'s `ResolveActorTechniques` itself — it stays a pure, DB-free function, unmodified, exactly as every other caller of it already relies on.
- No backfill for existing `threat_actor_profiles` rows — the column defaults to `'{}'` and self-heals on each actor's next scheduled (or manually triggered) sync, same rollout pattern sub-project #1 (`threat_actor_sources`) already used.
- No change to Coverage/Validation factors — they already correctly treat a zero-technique actor as unavailable (not "zero gaps"), confirmed by existing tests (`TestSimulationCoverageFactor_NoTechniques_Unavailable` and siblings); this fix only changes how often they receive a real, non-empty list to begin with.

## Data model

```sql
ALTER TABLE threat_actor_profiles ADD COLUMN IF NOT EXISTS techniques text[] NOT NULL DEFAULT '{}';
```

`upsertActorProfiles` (`internal/connector/scheduler.go`) adds `techniques` to its existing `INSERT ... ON CONFLICT (name) DO UPDATE SET ...` for `a.Name`, deriving the value the same way `Generator.buildYAML` already does inline (uppercase, dedupe by ID) — extracted as a small shared helper in `internal/connector` (e.g. `techniqueIDs(techs []TechniqueRef) []string`) so the logic isn't duplicated between the generator and the new upsert path.

## Scoring change

```go
// internal/threatpriority/engine.go, scoreActor
techIDs, _, ok := reporting.ResolveActorTechniques(profile.Name, profile.Aliases)
techniqueSource := ""
switch {
case ok:
    techniqueSource = "mitre"
case len(profile.Techniques) > 0:
    techIDs = profile.Techniques
    techniqueSource = "connector"
}
```

`ActorPriority` gains `TechniqueSource string `json:"techniqueSource,omitempty"`` — set once per `scoreActor` call, threaded straight through `Score`/`ScoreAll` (both already return `ActorPriority`, no signature change needed). Every downstream consumer of `techIDs` (coverage-gap counting, `ValidatedCount`, every registered `ScoreFactor`, the API's `buildTechniqueCoverage`/`UncoveredTechniques`) is unchanged — they already operate generically on whatever `techIDs` contains, regardless of where it came from.

## UI

One small `class="tiny muted"` line near the existing Technique Coverage Breakdown card on the actor detail view (`orchestrator/wwwroot/index.html`'s `renderThreatPriorityDetail`), shown only when `d.techniqueSource` is non-empty:
- `"mitre"` → "Techniques: MITRE-authoritative"
- `"connector"` → "Techniques: connector-derived (not yet MITRE-confirmed)"
- empty/absent → nothing rendered (no techniques known from either source — the existing "No technique data." fallback in the coverage card already communicates this)

## Testing

- `internal/connector`: `upsertActorProfiles` test proving `techniques` persists correctly (dedupe/uppercase) and survives a re-sync unchanged when the actor's technique set is stable; `techniqueIDs` helper unit tests (empty input, duplicate IDs, mixed case).
- `internal/threatpriority`: `scoreActor` tests covering all three branches — MITRE match wins even when `profile.Techniques` is also populated (MITRE stays primary); MITRE has no match, `profile.Techniques` fills in, `TechniqueSource == "connector"`; neither present, `techIDs` empty, `TechniqueSource == ""`, and coverage/validation factors correctly report `Available=false` (regression guard against the exact bug class this whole session has been fixing).
- No new API test needed beyond confirming `TechniqueSource` round-trips through the existing `threatPriorityActorDetail` JSON response (it's embedded via `threatpriority.ActorPriority`, already serialized) — a one-line assertion added to an existing actor-detail test, not a new endpoint.

## Self-review

- **Placeholder scan:** none — every section has concrete types/SQL/code.
- **Internal consistency:** the "MITRE stays primary" rule is stated in Architecture, the Scoring Change code, and explicitly tested for in Testing — no contradiction between sections.
- **Scope check:** single, focused fix — one column, one upsert extension, one three-branch fallback, one UI label. Small enough for a single implementation-plan task, unlike sub-projects #1/#2's multi-task scope.
- **Ambiguity check:** the "connector-derived" label's exact wording is specified verbatim to avoid later bikeshedding; the no-backfill decision and its rationale (self-healing via next sync) is stated once, not left implicit.
