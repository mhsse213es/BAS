# OTX as a Distinct Activity Signal — Design Spec

**Goal:** Stop representing OTX's contribution as curated actor attribution. OTX pulses are activity/mention evidence about an already-known (MITRE-named) actor — fundamentally different from MISP's threat-actor events or OpenCTI's structured Threat-Actor/Intrusion-Set objects. Today `OTXSource` implements the same `Source` interface as MISP/OpenCTI and produces `ThreatActor` rows that merge into `threat_actor_profiles`/`threat_actor_sources` alongside curated intelligence, with a hardcoded `Confidence: "medium"`. This is sub-project #2 of the user's 5-point architecture-feedback document (sub-project #1, per-source provenance, shipped 2026-08-12 — see `docs/superpowers/specs/2026-08-11-source-provenance-design.md` and `project_source_provenance` memory).

**Why now — the concrete bug this causes today:** `mergeActorGroup` (`internal/connector/actor_merge.go:175-185`) unions `LastSeen` across every contributing raw actor in a merge group, taking the max. If OTX and MISP both match the same actor, OTX's most recent pulse activity can push the *merged* actor's `LastSeen` forward, making `IntelFreshnessFactor` report "fresh intel" even when MISP's real curated sighting is stale. Separately, every OTX-only actor gets a flat `Confidence: "medium"` that `ConfidenceFactor` scores identically to a MISP analyst's actual medium-confidence assessment — OTX never made that assessment; it's a fallback placeholder.

## Scope

**In scope:**
- A new `ActivitySource` interface, distinct from `Source`. `OTXSource` implements only this — it leaves `Source` entirely.
- `OTXSource.Fetch()` is replaced by `FetchActivity()`, returning `[]ActivitySignal` (actor name, pulse count, last-observed) instead of `[]ThreatActor`. No more `Techniques`/`Confidence` construction inside OTX.
- A new table, `threat_actor_activity`, and `Scheduler.upsertActivitySignals`, populated by a second sync pass that runs after the existing curated-source merge, resolving each signal against the merged roster via the **existing, unmodified** `actorTokens`/`actorKey` matching.
- An orphan path: an OTX-matched MITRE group name with no existing curated profile gets a minimal `threat_actor_profiles` stub (Name + MITRE's own technique list, no Confidence, no LastSeen) so the activity signal has somewhere to attach.
- A new `ActivityFactor` in `internal/threatpriority`, weighted lower than the three existing standalone factors (see Decisions below).
- UI: the actor detail view's Sources card naturally stops showing an "otx" entry (OTX no longer writes there); a new, visually distinct "Recent Activity" element shows pulse count + recency.
- Full removal of OTX's old `Source`-implementing code path — no dual-write period. `docs/superpowers/specs/2026-07-22-otx-technique-mapping-design.md` becomes superseded by this spec for everything concerning `OTXSource.Fetch()`.

**Explicitly out of scope:**
- Any change to `internal/connector/actor_merge.go` — the merge/provenance grouping code Task 1 of sub-project #1 shipped stays byte-for-byte as-is. This is a hard constraint of the design, not just a convenience.
- Any change to `IntelFreshnessFactor`/`ConfidenceFactor`/`RelevanceFactor` — removing OTX from the curated pipeline fixes the `LastSeen`-leak bug and the fake-confidence problem as a side effect of OTX no longer writing there at all; no defensive code is added to those factors.
- Sub-project #3 (per-relationship `uses→technique` evidence layer) — a separate, later brainstorm.
- Cumulative all-time pulse counting (deduplicating by pulse ID across syncs) — `PulseCount` is a snapshot of *currently subscribed* pulses matching an actor as of the latest sync, matching the existing `RawCount`/`technique_count` "examined this sync" convention already established for MISP/OpenCTI/OTX's own stats. Individual OTX pulses carry no stable ID in today's `otxPulse` struct, and adding cross-sync dedup is unrequested complexity.
- No changes to `internal/ioc/otx.go`'s `otxProvider` — that's a separate, already-distinct on-demand IOC-lookup client (a different package, a different concern) and is untouched by this work.

## Data model

```go
// internal/connector/source.go
type ActivitySource interface {
    Name() string
    FetchActivity() ([]ActivitySignal, error)
}

type ActivitySignal struct {
    ActorName    string    // exact MITRE group name -- same convention ThreatActor.Name already uses
    PulseCount   int       // currently-subscribed pulses matching this actor, this sync
    LastObserved time.Time
}
```

```sql
CREATE TABLE IF NOT EXISTS threat_actor_activity (
    actor_name     text        NOT NULL REFERENCES threat_actor_profiles(name) ON DELETE CASCADE,
    source         text        NOT NULL,
    pulse_count    int         NOT NULL DEFAULT 0,
    first_observed timestamptz,
    last_observed  timestamptz,
    updated_at     timestamptz NOT NULL DEFAULT NOW(),
    PRIMARY KEY (actor_name, source)
)
```

Shaped like `threat_actor_sources` (same `(actor_name, source)` PK convention) for consistency, even though only `otx` populates it today — a second activity-style source later fits this table without a redesign.

**Upsert semantics**, deliberately different from `threat_actor_sources`' plain overwrite:
- `pulse_count = EXCLUDED.pulse_count` — plain overwrite, a snapshot.
- `first_observed = LEAST(threat_actor_activity.first_observed, EXCLUDED.first_observed)` — preserved across syncs even if the original earliest pulse later rolls off OTX's subscription window.
- `last_observed = GREATEST(threat_actor_activity.last_observed, EXCLUDED.last_observed)` — never regresses due to subscription churn.

## Sync wiring

`OTXSource.Fetch()` → `FetchActivity()`: same pagination and `attackdata.GroupTechniqueIndex()`-based adversary matching as today, but now **counts** matching pulses per actor (not just tracks the latest date) and builds `ActivitySignal`, not `ThreatActor`. The technique-list/confidence-construction code is deleted — there's no `ThreatActor` to build.

`Scheduler` gains `activitySources []ActivitySource` (new `NewScheduler(...)` parameter). `sync()` gains a second pass, **after** the existing curated-source fetch/merge/persist completes:

```
for each activitySource:
    signals, err := activitySource.FetchActivity()
    for each signal:
        canonicalName, found := resolveAgainstMergedRoster(signal.ActorName, mergedActors)  // reuses actorTokens/actorKey, unmodified
        if found:
            upsert threat_actor_activity keyed to canonicalName
        else:
            create minimal threat_actor_profiles stub (Name=signal.ActorName, Techniques=attackdata.GroupTechniqueIndex()[signal.ActorName], no Confidence, no LastSeen)
            upsert threat_actor_activity keyed to that stub
```

`internal/connector/seed.go`'s `LoadSourcesFromDB` drops its `"otx"` case; a new `LoadActivitySourcesFromDB` builds `NewOTXSource(...)` as an `ActivitySource`. Both read `threat_intel_config` (unchanged table) — no config-schema change, just which Go slice a row's connector value routes into.

## Scoring: `ActivityFactor`

```go
type ActivityFactor struct{}
func (ActivityFactor) Name() string { return "OTX Activity" }
func (ActivityFactor) Weight(Context) float64 { return activityWeight } // see Decisions
func (ActivityFactor) Score(...) (float64, string, bool, error) {
    if tctx.Activity == nil { return 0, "No OTX activity recorded", false, nil }
    // recency-bucketed like IntelFreshnessFactor: <7d/<30d/older
    // explanation string includes PulseCount for context; score itself is recency-only
}
```

`Context` (`internal/threatpriority/models.go`) gains `Activity *ActivitySignal`. Loaded per-actor inside `scoreActor` (`engine.go`), mirroring how `previousScore` already does a per-actor round trip in the same function — no new batch/shared-index machinery needed.

## Decisions

- **Weight:** a new constant, not `flatWeight`. Recommended `activityWeight = 0.025` (half of the other standalone factors' `0.05`) — Activity is explicitly a weaker, noisier signal than curated Confidence/Relevance/Freshness; giving it equal weight would recreate the exact "OTX pretends to be curated intel" mismatch this whole sub-project exists to fix, just at the weighting layer. `Composite()` renormalizes proportionally across whatever's `Available` for a given actor, so this value can be tuned later without another migration.
- **Orphan actors:** get a real (if minimal) `threat_actor_profiles` stub rather than being held separately — approved by the user. Nothing is fabricated (MITRE itself validated the group name); the stub is simply uncurated by any real intel source yet, which `ConfidenceFactor`/`RelevanceFactor` already handle correctly (`Available=false`, not a fake zero).
- **Migration:** straight to Final, no Transition phase — approved by the user. No live OTX account has been verified against this connector yet (per the original technique-mapping spec's own open-assumption note), and nothing external depends on today's OTX-sourced `threat_actor_profiles`/`threat_actor_sources` rows, so there's no real migration risk to hedge with a dual-write period.

## UI

The Sources card (`orchestrator/wwwroot/index.html`, shipped 2026-08-12) needs no code change — it already renders whatever `d.sources` contains, and OTX will simply never appear there again once it stops writing `threat_actor_sources`. A new small element on the actor detail view (near the Sources card, visually distinct — not another Sources-card block) shows `pulseCount` + a recency phrase (e.g. "Mentioned in 4 pulses, most recently 3 days ago") when `threat_actor_activity` has a row for that actor, nothing when it doesn't.

## Testing

- `internal/connector/otx_test.go`: existing pagination/matching tests updated for the new return type (`FetchActivity() ([]ActivitySignal, error)`), asserting `PulseCount` now accumulates correctly across multiple matching pulses in one sync (a genuinely new behavior — today's `Fetch()` never counts, only tracks latest date).
- `internal/connector/scheduler_test.go`: new tests proving (a) a signal that matches an existing merged actor attaches to it without touching that actor's `Confidence`/`LastSeen`, (b) a signal matching nothing creates the minimal stub with `Confidence=""`/`LastSeen=nil`, (c) `first_observed`/`last_observed` use `LEAST`/`GREATEST` correctly across two syncs.
- `internal/threatpriority`: new `ActivityFactor` tests (available/unavailable, recency buckets) following `standalone_factors_test.go`'s existing pattern exactly.
- `internal/api`: existing `threatpriority_handlers_test.go`/actor-detail tests unaffected (no API shape change proposed here beyond what the UI section describes, which the plan will scope as its own task if needed).

## Self-review

- **Placeholder scan:** none — every section has concrete types/SQL/file references.
- **Internal consistency:** the "no changes to actor_merge.go" constraint (Scope) is upheld throughout — the sync-wiring section explicitly reuses `actorTokens`/`actorKey` rather than modifying the merge core, consistent with the approved structural-approach decision.
- **Scope check:** focused to a single implementation plan — one new interface, one new table, one new factor, one sync-loop addition, one UI element. Sub-project #3 stays explicitly deferred.
- **Ambiguity check:** `PulseCount`'s snapshot-not-cumulative semantics, the `LEAST`/`GREATEST` upsert behavior, and the orphan-stub's exact field values are all spelled out to avoid a later re-litigation during planning.
