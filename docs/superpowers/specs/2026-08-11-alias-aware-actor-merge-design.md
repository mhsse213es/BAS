# Alias-Aware `MergeActors` — Design

**Status:** Approved 2026-08-11
**Scope:** First of two related projects. This one fixes in-cycle actor-identity matching using alias data the connectors already fetch. A separate follow-on project will add a MITRE ATT&CK canonical Group-ID identity layer — deliberately out of scope here (see "Non-goals" and "Relationship to the canonical MITRE layer" below).

## Problem

`internal/connector/scheduler.go`'s `MergeActors` deduplicates actors fetched from MISP/OpenCTI/OTX within a single sync cycle, but its matching key (`actorKey`, `scheduler.go:336-338`) only normalizes and compares each actor's primary `Name`. It never looks at the `Aliases` field.

That field is not empty data waiting to be added — it's already populated and already discarded:

- `ThreatActor.Aliases []string` exists on the struct (`internal/connector/types.go:12`) and `threat_actor_profiles.aliases` exists as a persisted column.
- OpenCTI's `convertActor` already copies `raw.Aliases` straight from OpenCTI's GraphQL response (`opencti.go:441`) — if OpenCTI's own database knows "Sangria Tempest" is aliased to "Wizard Spider," that fact is already flowing through the pipeline every sync.
- MISP never populates `Aliases` — it only extracts a single bare name off a `misp-galaxy:threat-actor=` / `misp-galaxy:mitre-intrusion-set=` tag (`misp.go:222-226`).
- `MergeActors` never consults `Aliases` when deciding whether two fetched actors are the same real-world group, so a MISP actor named "Wizard Spider" and an OpenCTI actor named "Sangria Tempest" (with "Wizard Spider" in its alias list) survive as two separate persisted profiles even though OpenCTI's own data says they're the same actor.

There is no existing canonical MITRE Group-ID (`G####`) dataset vendored in the repo to lean on instead — `internal/reporting/attackdata/gen/main.go` reads a raw `enterprise-attack.json` STIX bundle that isn't checked in (only its derived output `attack_enrichment.json` is), and even where it does touch `intrusion-set` STIX objects, it keeps only the plain `Name`, discarding both the group's `G####` external ID and its `x_mitre_aliases` list. Building that layer is a separate, larger effort (see below) — this project is scoped to using data the pipeline already has today.

## Goal

Make `MergeActors` treat two fetched actors as the same identity if **any** of their normalized name/alias tokens match exactly — not just their primary names — using only data already fetched by existing connectors. No new data source, no fuzzy/similarity matching.

## Non-goals

- **No fuzzy or similarity-based matching.** Every match is exact string equality on normalized tokens (same normalization `actorKey` already does: lowercase, strip spaces and hyphens). `"APT28"` and `"APT29"` must never match. Canonical identity work belongs to Project 2, not this one.
- **No cross-sync-cycle persistence fix.** `upsertActorProfiles` still upserts on exact `name` (`ON CONFLICT (name)`) and does not consult already-persisted rows for alias overlap. This project only fixes matching *within one sync cycle's combined fetch list* (all sources are re-fetched and re-merged together every cycle, so this covers the common case), not the case where a bridging source is disabled or errors on some future cycle while a bare-named duplicate from another source comes in. That gap is real, not silently absorbed by this fix, and is a natural fit for Project 2's canonical Group-ID (a G-number persisted directly on the row doesn't depend on which connector happened to run that cycle).
- **No change to which fields "win" on merge**, beyond `Aliases` itself (see below). `Name`, `Sectors`, `Regions`, `Source`, `SourceID`, `Confidence`, `Description` keep today's behavior: first-arrival wins, nothing else touches them.

## Design

### Matching algorithm

Replace `MergeActors`' single `map[normalizedName]→actor` lookup with a union-find (disjoint-set) over each actor's **identity-token set**:

```
tokens(a) = { actorKey(a.Name) } ∪ { actorKey(alias) : alias ∈ a.Aliases }
```

Two actors are merged into the same group if their token sets intersect at all — name-name, name-alias, alias-name, or alias-alias. This is inherently transitive: if actor A and actor B share a token, and actor B and actor C share a *different* token, then A, B, and C all end up in one group through B. This is intentional, not an accidental side effect, and is locked in by an explicit test (see Testing below) rather than left as emergent behavior.

Processing order: actors are processed in the order they appear in the combined (already-flattened, all-sources) input list, same as today. For each actor, look up whether any of its tokens already maps to an existing group; if so, union into that group (updating all of the actor's own tokens to point to the group's representative too, so later actors can chain through it); if not, start a new group with this actor as the sole (for now) member.

### Merge policy for the winning record

Extends today's actual behavior. Today, when two actors collide on name, only `Techniques` gets unioned and `LastSeen` takes the later value — every other field on the surviving `existing` struct is left untouched, keeping whatever the first-arriving actor had.

| Field | Policy | Change from today |
|---|---|---|
| `Techniques` | Union across the whole group | Unchanged |
| `LastSeen` | Max across the whole group | Unchanged |
| `Aliases` | Union across the whole group, **plus** every merged member's primary `Name` is folded in as an alias on the survivor (except the survivor's own name) | **New** |
| `Name`, `Sectors`, `Regions`, `Source`, `SourceID`, `Confidence`, `Description` | First-arrival wins | Unchanged |

The `Aliases` change means a MISP actor named "Wizard Spider" merging into an OpenCTI-sourced "Sangria Tempest" record leaves the persisted profile's `aliases` column recording `["Wizard Spider", ...any OpenCTI-supplied aliases]` — the fact that a merge happened, and why, is visible on the record itself rather than silently dropped.

### File structure

`MergeActors`, `actorKey`, and the new union-find logic move out of `scheduler.go` (currently 384 lines) into a new file, `internal/connector/actor_merge.go`. This is a self-contained, independently-testable unit of behavior that's about to grow a real algorithm — worth its own file rather than staying folded into the scheduler's sync-orchestration code. `scheduler.go` keeps calling `MergeActors` exactly as it does today; the exported signature (`func MergeActors(actors []ThreatActor) []ThreatActor`) does not change, so this is a pure internal move with no caller-visible impact.

## Testing

All exact-match, no-fuzzy-matching behavior, covering the cases explicitly requested plus regression coverage for today's pure-name-match behavior:

1. **Wizard Spider ↔ Sangria Tempest** — a bare-named actor (simulating MISP) and an actor whose `Aliases` includes the first actor's name (simulating OpenCTI) merge into one, with techniques unioned and the bare name folded into the survivor's `Aliases`.
2. **Order independence** — the same pair, but with arrival order reversed, produces the same merged result.
3. **Case/punctuation variants** — `"WIZARD-SPIDER"`, `"Wizard Spider"`, and `"wizardspider"` all normalize to the same token and match.
4. **Multiple aliases, single overlap** — an actor with three aliases where only one overlaps the other actor's name still merges.
5. **Transitive alias chain** — actor A (name X, alias Y), actor B (name Y, alias Z), actor C (name Z, no aliases) all merge into one group, proving the transitive-chaining behavior is real and intentional, not accidental.
6. **Similar-but-distinct names never merge** — e.g. two actors with clearly different names and no alias overlap (guards against any accidental fuzzy-matching regression).
7. **No-aliases regression** — actors with empty `Aliases` behave exactly as `MergeActors` does today (pure name-based matching, unchanged).

## Relationship to the canonical MITRE layer (Project 2, not started)

This project makes the pipeline use alias data it already has. It deliberately does not attempt to become a canonical identity system — it still depends on at least one fetched source supplying the bridging alias relationship in the same sync cycle, and MISP currently never does. The follow-on project, scoped separately, will:

- Ingest the authoritative ATT&CK intrusion-set Group ID (`G####`) and its full `x_mitre_aliases` set from the raw MITRE STIX bundle (not currently vendored in the repo — needs fetching).
- Map source-specific actor names/aliases to that canonical Group ID.
- Persist the canonical ID on the Audspect actor profile.
- Use the canonical ID as the primary cross-source merge key where available, falling back to this project's alias-token matching where it isn't.
- Retain MISP/OpenCTI source IDs and names for provenance.
- Explicitly handle actors that cannot be mapped to ATT&CK, without forcing an incorrect identity onto them.

That project gets its own brainstorm → spec → plan cycle.
