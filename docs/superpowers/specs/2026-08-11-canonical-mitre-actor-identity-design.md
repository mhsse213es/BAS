# Canonical MITRE ATT&CK Group-ID Identity Layer — Design

**Status:** Approved 2026-08-11
**Scope:** Second of two related projects. Project 1 (`docs/superpowers/specs/2026-08-11-alias-aware-actor-merge-design.md`, commit `3e6d5e8`) made `MergeActors` alias-aware using data connectors already fetch (OpenCTI's `Aliases` field). This project adds a genuinely new data source — MITRE ATT&CK's own authoritative Group-ID + alias dataset — as a second, independent identity signal, used to bridge actors across sources even when neither source directly supplies a shared name/alias token.

## Problem

Project 1's alias-token matching only merges actors when at least one *fetched* source's data bridges them — e.g. OpenCTI listing `"Wizard Spider"` as an alias of `"Sangria Tempest"`. It cannot merge two actors that MITRE's own data considers the same group but that arrived with no overlapping token at all in a given sync cycle — e.g. a MISP-only `"APT29"` and an OpenCTI actor whose own `Aliases` field (for whatever reason — a stale OpenCTI record, a sync where OpenCTI didn't return that particular relationship) never mentions `"APT29"`. MISP in particular never populates `Aliases` at all (`misp.go:222-226`), so any MISP-sourced actor's only path to merging with another source today is a lucky exact primary-name match.

There is no authoritative, source-independent identity reference in the pipeline today. `internal/reporting/attackdata`'s existing STIX-derived dataset already touches MITRE's `intrusion-set` objects (the `Groups []string` field on each technique's enrichment, populated from `uses` relationships), but discards both the group's canonical `G####` external ID and its `x_mitre_aliases` list — only the bare display name survives (`gen/main.go`'s `case "intrusion-set", "malware", "tool": names[o.ID] = o.Name`). No vendored copy of the raw MITRE alias data exists to build a canonical mapping from.

## Goal

Give the pipeline a MITRE-authoritative way to recognize that two differently-named source actors are the same real-world group, and use that as the primary cross-source merge signal — falling back to Project 1's alias-token matching where MITRE's data doesn't cover an actor. Persist the resolved canonical ID on the actor profile. Never force an identity onto an actor MITRE's data can't confidently resolve.

## Non-goals

- **No fuzzy or similarity-based matching**, anywhere. Resolving an actor's tokens against MITRE's dataset is exact string equality on the same normalized tokens Project 1 already uses (`actorKey`: lowercase, strip spaces and hyphens). This is the same hard constraint from Project 1, restated: *never merge solely because two strings look similar — canonical identity requires an explicit authoritative mapping.*
- **No live/runtime fetch of MITRE data.** The product ships air-gapped. Canonical group data is produced by the same build-time distillation step as technique enrichment — a raw STIX bundle fetched manually, run through `gen/main.go`, with only the derived JSON committed and shipped.
- **No changes to `GroupTechniqueIndex()` or its 20 existing consumers** (`correlation`, `threatpriority`, `threatgraph`, `recommend`, `reporting`, `connector/otx.go`, several `api` handlers) — that index stays name-keyed exactly as it is today. This project adds a separate, ID-keyed index alongside it; nothing about the existing name-based technique-attribution path changes.
- **No change to Project 1's core union-find mechanics or file.** This project extends `actor_merge.go`'s existing algorithm (adds a resolution pass before union-find, extends the merge policy), it does not replace it.
- **No forced identity on ambiguous or unmatched actors.** An actor whose own name/aliases don't cleanly resolve to exactly one MITRE group — because MITRE has no data on it, or because its tokens straddle two different groups — is left with an empty `CanonicalGroupID` and matches only via Project 1's alias-token fallback. This applies symmetrically when a *merged group* ends up with internally conflicting resolutions (see Design).

## Design

### Data model & sourcing

Extend `internal/reporting/attackdata/gen/main.go`:

- Add `Aliases []string \`json:"x_mitre_aliases"\`` to `stixObj` (currently unparsed).
- For `intrusion-set` objects, extract the `G####` external ID via `external_references` — the exact same pattern already used for `attack-pattern` → `T####` (`gen/main.go:169-176`), just applied to `SourceName == "mitre-attack"` refs on intrusion-set objects instead.
- Extract this into a standalone, unit-testable function: `parseGroups(objects []stixObj) []Group`, where `Group struct { ID, Name string; Aliases []string }`. This is a targeted improvement, scoped only to the new logic — the existing technique-parsing loop inside `main()` stays as-is (already untested today; not this project's concern to fix).
- Revoked/deprecated intrusion-sets are excluded, mirroring the existing technique filter.

This is group-keyed data, not technique-keyed, so it does not fit `attack_enrichment.json`'s `map[techniqueID]*enrichment` shape. It ships as a new sibling file, `attack_groups.json` (`[]Group`), embedded via `//go:embed` and loaded the same way (`sync.Once`) as the existing enrichment data.

`attackdata` gets one new accessor, mirroring the existing `GroupTechniqueIndex()` pattern:

```go
// GroupCanonicalTokenIndex returns normalized-token → G#### for every
// group name and alias in the embedded MITRE dataset. A token that maps
// to more than one distinct G#### in MITRE's own data is deliberately
// excluded (mapped to nothing) — an ambiguous token must never resolve.
func GroupCanonicalTokenIndex() map[string]string
```

### Persistence

- `threat_actor_profiles`: additive migration, `ALTER TABLE threat_actor_profiles ADD COLUMN IF NOT EXISTS canonical_group_id text NOT NULL DEFAULT ''` (same pattern as the existing `confidence` column in `content_schema.go`).
- `ThreatActor` (`internal/connector/types.go`): new field `CanonicalGroupID string \`json:"canonical_group_id,omitempty"\``.
- `upsertActorProfiles` persists it.
- `threatpriority.ActorPriority`: new field `CanonicalGroupID string \`json:"canonicalGroupId,omitempty"\``, threaded through the existing `SELECT ... FROM threat_actor_profiles` in `engine.go` (`Score`/`ScoreAll`).

### Matching algorithm (extends `actor_merge.go`)

**Per-actor resolution pass**, run before union-find: for each fetched actor, check its own tokens (`{actorKey(name)} ∪ {actorKey(alias) : alias ∈ Aliases}` — unchanged from Project 1) against `attackdata.GroupCanonicalTokenIndex()`.

- **Exactly one distinct `G####` matched** → the actor resolves to that group. A synthetic token `"canonical:"+G####` is added to its token set before union-find runs. This is the mechanism that makes canonical ID the *primary* cross-source merge key: two actors with zero direct alias-token overlap still merge if MITRE's data independently resolves both to the same group, because they now share the synthetic token. Where resolution fails, behavior is byte-identical to Project 1 — this is pure addition, not a replacement of the existing path.
- **Zero matches** → unresolved. No synthetic token. Falls through entirely to Project 1's alias-token matching.
- **More than one distinct `G####` matched** (the actor's own tokens straddle two different MITRE groups — e.g. a generic alias MITRE itself lists under two entries) → unresolved. No synthetic token, no `CanonicalGroupID`. Ambiguity never forces an identity.

**Merge-policy extension** (`mergeActorGroup`): among a merged group's members, collect the distinct non-empty resolved `G####`s from the resolution pass above.

- **Exactly one distinct value** (one member resolved, or several agree) → stamped as the survivor's `CanonicalGroupID`.
- **Zero** → survivor's `CanonicalGroupID` stays empty, unchanged from today.
- **More than one distinct value** — a genuine contradiction: members merged via a direct alias-token match (Project 1's mechanism), but MITRE's own data disagrees about which group they belong to. This is a real data-quality signal, not something to silently resolve: `CanonicalGroupID` stays empty on the survivor, and a warning is logged (`log.Printf`, same discipline used elsewhere in `internal/connector`) rather than arbitrarily picking one value.

**Active enrichment**: when the survivor ends up with a non-empty `CanonicalGroupID`, that group's full MITRE `Name` + `Aliases` are folded into the survivor's merged `Aliases` — through the same dedup-by-normalized-token logic Project 1 already uses for connector-sourced names/aliases (skip anything normalizing to the survivor's own `Name`, skip already-seen tokens). This means `Aliases` is no longer purely "what connectors reported this cycle" — once an actor is canonically resolved, it also carries MITRE's authoritative alias set forward, making future cycles more robust even if a bridging connector (e.g. OpenCTI) is absent or errors on that run. This is the one deliberate expansion beyond Project 1's non-goals, chosen explicitly over a more conservative "tag only" alternative because it directly closes the gap Project 1 flagged as unsolved.

### UI surface

Threat Prioritization actor **detail** view only (`renderThreatPriorityDetail` / `#tp-detail-title` in `index.html`): a small badge next to the actor name (e.g. `Wizard Spider  ·  MITRE G0102`), shown only when `canonicalGroupId` is present — nothing rendered when absent, no "unmapped" clutter. The list view (`#tp-list-body`, an already-dense 5-column table) is untouched; this is provenance detail, not a triage-level signal.

## Testing

- `gen`: fixture-based test for `parseGroups` — `G####` + `x_mitre_aliases` extracted correctly; revoked/deprecated intrusion-sets excluded.
- `attackdata`: test for `GroupCanonicalTokenIndex()` — normal single-group resolution, and the ambiguous-token-excluded case (a token appearing in two groups' name/alias sets resolves to nothing).
- `actor_merge.go`:
  1. Two actors with **zero direct token overlap**, both independently resolving to the same `G####` via MITRE data, merge into one.
  2. An actor whose own tokens match **two different** `G####`s stays unresolved; no forced merge occurs.
  3. A merged group whose members carry **internally conflicting** resolved IDs (merged via direct alias-token overlap, but MITRE disagrees) leaves the survivor unresolved, and the conflict is logged.
  4. A resolved survivor's `Aliases` gets MITRE's alias set folded in — deduped, own-name excluded (active enrichment).
  5. An actor with **no MITRE match at all** behaves byte-identical to Project 1 (regression — proves this project is additive, not a rewrite).
- Persistence: extend the existing `upsertActorProfiles` test to round-trip `canonical_group_id`.
- `threatpriority`: extend `Score`/`ScoreAll` tests to confirm `CanonicalGroupID` flows through to `ActorPriority`.

## Relationship to Project 1

Project 1 shipped exact-token alias matching using data already flowing through the pipeline (commit `3e6d5e8`). This project is additive on top of it: same file (`actor_merge.go`), same union-find mechanism, same exact-match-only discipline — it just adds a second, MITRE-authoritative source of tokens that can bridge actors Project 1's connector-sourced aliases alone cannot. Nothing in Project 1's test suite should change behavior; the regression test (`actor_merge_test.go`'s existing `TestMergeActors_*` suite) stays green throughout, and case 5 above explicitly locks in the no-MITRE-match path as unchanged.
