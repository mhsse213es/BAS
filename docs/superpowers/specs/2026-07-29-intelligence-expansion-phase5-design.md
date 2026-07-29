# Intelligence Expansion Phase 5 (Cross-Provider Entity Reconciliation) — Design

**Status:** Draft for review
**Author:** Claude + user, brainstormed 2026-07-29. OpenCTI side verified live (`Campaign.aliases` field confirmed real, sparse: 1/5 sampled campaigns populated). No frontend or other Go package consumes `/api/intelligence/*` yet — confirmed by search — so this phase is free to change the JSON shape and ID scheme without a backward-compatibility constraint.
**Depends on:** [[Intelligence Expansion]] Phases 1, 2, 4 (`internal/intelligence`, `Campaign`/`Malware`/`Tool`, `IntelligenceSource`). Directly extends the existing `MalwareKey` dedup mechanism Malware/Tool already use.

## Problem

Two real, confirmed gaps in today's `internal/intelligence` package, found by reading `store.go` rather than assumed:

1. **Malware/Tool already silently cross-provider-merge, but their provenance becomes false once they do.** `UpsertMalware`/`UpsertTool`'s `ON CONFLICT` clause merges `actor_ids`/`technique_ids`/`campaign_ids` across providers (because both tables key on `MalwareKey(Name)`, a provider-independent normalized name), but `source_provider`/`source_external_id` are not in the `SET` clause — they silently keep whichever provider inserted the row first. A row genuinely fed by both MISP and OpenCTI reports `source_provider: "misp"` even after OpenCTI also contributed to it. This is a correctness bug in what the API already returns today, not a hypothetical.
2. **Campaign has zero cross-provider reconciliation.** `Campaign.ID` is always the provider's own external identifier (MISP event ID, OpenCTI STIX `standard_id`). Two providers describing the same real-world campaign (e.g. MISP's "SolarWinds Compromise" event and OpenCTI's "SolarWinds Compromise" Campaign object) never collide on that ID and sit forever as two unrelated rows — the opposite of what a "normalized Repository" is supposed to do.

## Non-Goals

- **No manual-override table/API.** The schema (`search_key`) is forward-compatible with one (an admin could insert directly into `search_key` to force a future match), but no UI/API is built for it this phase.
- **`search_key`/alias-based matching is Campaign-only this phase.** Malware/Tool already reconcile via exact `NormalizeKey(Name)` equality and keep that as their only reconciliation path — their existing `Aliases` field stays display-only, not wired into matching. The user's steer explicitly named Campaign reconciliation as "the larger missing capability"; extending alias-based matching to Malware/Tool (e.g. so a future "Heodo" report reconciles with an existing "Emotet" row) is a reasonable follow-up but not in this phase's scope.
- **No fuzzy/AI entity matching.** Reconciliation is deterministic: normalized-name equality, or membership in a `search_key` array built from name + aliases. Genuinely different names for the same real-world entity that neither provider lists as an alias of the other (e.g. two campaigns that are the same operation but share no name/alias string in common) will not reconcile. This is a known, accepted limitation, not a bug — matches the user's explicit "start with deterministic normalization, add fuzzy matching later" direction.
- **No relationship join tables** (`campaign_actors`, `malware_techniques`, etc.). `actor_ids`/`technique_ids`/`campaign_ids` stay as denormalized `[]string` arrays exactly as today — rebuilding this into real join tables was explicitly rejected as disproportionate scope for the current maturity/consumer-count of this package.
- **No entity-lineage/merge-audit log.** `intelligence_entity_sources` (below) already answers "which providers, which external IDs, when each was last synced, who was first" via its own row timestamps — a separate historical audit trail of merge *events* is left for a future phase.
- **No column removal from existing tables.** `internal/db/content_schema.go` has no precedent anywhere for `DROP COLUMN` — every existing schema evolution in this codebase is `ALTER TABLE ... ADD COLUMN IF NOT EXISTS`, additive only. `intelligence_campaigns`/`malware`/`tools`' existing `source_provider`/`source_external_id`/`source_confidence` columns are kept as-is (see Architecture §1 for what they now mean).
- **Not extending Objective/MalwareTypes semantics** — unrelated to this phase.

## Architecture

### 1. Provenance — new `intelligence_entity_sources` table, existing `source_*` columns stay as "first-seen convenience"

```sql
CREATE TABLE IF NOT EXISTS intelligence_entity_sources (
    id           bigserial   PRIMARY KEY,
    entity_type  text        NOT NULL,  -- 'campaign' | 'malware' | 'tool'
    entity_id    text        NOT NULL,  -- = intelligence_campaigns/malware/tools.id
    provider     text        NOT NULL,
    external_id  text        NOT NULL,
    first_seen   timestamptz NOT NULL DEFAULT NOW(),
    last_sync    timestamptz NOT NULL,
    confidence   text        NOT NULL,
    tenant_id    text        NOT NULL DEFAULT 'default',
    UNIQUE (entity_type, entity_id, provider)
)
```

`UpsertCampaign`/`UpsertMalware`/`UpsertTool` each gain a second statement (same transaction) upserting into this table:

```sql
INSERT INTO intelligence_entity_sources
  (entity_type, entity_id, provider, external_id, last_sync, confidence)
VALUES ($1,$2,$3,$4,$5,$6)
ON CONFLICT (entity_type, entity_id, provider) DO UPDATE SET
  external_id = EXCLUDED.external_id,
  last_sync   = EXCLUDED.last_sync,
  confidence  = EXCLUDED.confidence
```

`first_seen` is deliberately excluded from the `SET` clause — same pattern already used for `source_provider`/`source_external_id` on the parent tables today, just applied correctly this time (one row per provider, not one shared column per entity). This directly answers the four provenance questions: which providers (`SELECT DISTINCT provider WHERE entity_id = ...`), which external IDs (`external_id` per row), when each was last synced (`last_sync` per row), who was first (`MIN(first_seen)`'s provider, or simply whichever row has the earliest `first_seen`).

The existing `source_provider`/`source_external_id`/`source_confidence`/`last_updated` columns on `intelligence_campaigns`/`malware`/`tools` are **not removed** (no `DROP COLUMN` precedent in this codebase) and keep their current, already-correct-for-what-they-are semantics: "the first provider that ever created this row." `Campaign`/`Malware`/`Tool`'s existing `Source SourceRef` Go field keeps mapping to these columns unchanged. A new `Sources []SourceRef` field is added alongside it, populated by a join query in `ListCampaigns`/`ListMalware`/`ListTools`, carrying the full multi-provider picture. Both are in the JSON response — `source` (single, first-seen, unchanged shape) and `sources` (new, complete).

### 2. Campaign reconciliation — reuse `MalwareKey`, renamed `NormalizeKey`, generalized to all three entities

`MalwareKey` (`internal/intelligence/models.go`) is renamed to `NormalizeKey` — it was never malware-specific in its logic (lowercase, strip spaces/hyphens), only in its name, and it now backs reconciliation for all three entity types. All existing call sites (`internal/intelligence/models.go`'s doc comments, `internal/connector/misp.go`, `internal/connector/opencti.go`) update their references; behavior is unchanged, this is a pure rename.

`Campaign` gains an `Aliases []string` field (Malware/Tool already have this). OpenCTI's `campaigns` relationship block in `actorFieldsFragment` gains an `aliases` field (verified live: real STIX field, e.g. `Operation AkaiRyū → [AkaiRyū]`, sparse but real — same "some records have it, some don't" characteristic as `Malware.Aliases` today). `convertCampaign` maps `entity.Aliases` straight through (the field already exists on `octiRelatedEntity`, no struct changes needed there). MISP-sourced campaigns always have empty `Aliases` — MISP's event-as-campaign-container model has no alias concept, same "OpenCTI-only enrichment" pattern as `Campaign.Objective` already established in Phase 2.

`intelligence_campaigns` gains one new column:

```sql
ALTER TABLE intelligence_campaigns ADD COLUMN IF NOT EXISTS aliases text[] NOT NULL DEFAULT '{}'
ALTER TABLE intelligence_campaigns ADD COLUMN IF NOT EXISTS search_key text[] NOT NULL DEFAULT '{}'
```

`search_key` is maintained entirely by `UpsertCampaign` (Go-computed, not a Postgres generated column) — the deduplicated union of `NormalizeKey(Name)` and `NormalizeKey(a)` for every `a` in `Aliases`.

**`Campaign.ID` changes from the provider's external ID to `NormalizeKey(Name)`** — the exact same reconciliation scheme Malware/Tool already use. `UpsertCampaign`'s new reconciliation step, before the existing upsert:

```sql
SELECT id FROM intelligence_campaigns
WHERE id = $1 OR search_key && $2
LIMIT 1
```

(`$1` = the incoming campaign's own `NormalizeKey(Name)`; `$2` = its full candidate `search_key` array; `&&` is Postgres's array-overlap operator.) If a row is found, its `id` becomes the canonical ID this upsert targets (merging into the existing row via the same `ON CONFLICT (id) DO UPDATE` union pattern `UpsertMalware` already uses, extended to also union `aliases` and `search_key`). If no row is found, the incoming campaign's own `NormalizeKey(Name)` is the new canonical ID.

**Consistency fix required at both call sites**: `Malware.CampaignIDs`/`Tool.CampaignIDs` currently reference the *raw provider ID* (`ev.ID` in `misp.go`'s `extractIntelligence`) rather than the campaign's own `ID` field. Since `Campaign.ID` is no longer `ev.ID`, `extractIntelligence`'s `CampaignIDs: []string{ev.ID}` (both the `mitre-malware` and `mitre-tool` branches) must become `CampaignIDs: []string{intelligence.NormalizeKey(detail.Event.Info)}` — `detail.Event.Info` is exactly `campaign.Name` in the same function, so this is deriving the same value the campaign itself now uses as its ID, not a new computation. The provider's raw `ev.ID` still flows into `SourceRef.ExternalID` exactly as today — nothing about *that* changes. OpenCTI's `convertMalware`/`convertTool` never populate `CampaignIDs` today (confirmed in Phase 4) and continue not to — this fix is MISP-only.

### 3. Reconciliation is best-effort, not guaranteed — documented, not hidden

Two campaigns from different providers describing the same real event will only reconcile if their names normalize to the same key, or one lists the other's name as an alias. MISP's free-text event titles (`detail.Event.Info`, e.g. "APT36 Kill Chain") and OpenCTI's more structured Campaign names will often *not* share a common string even when describing the same activity — this phase does not attempt to bridge that gap (Non-Goals). What it does guarantee: the same campaign reported twice by the *same* provider under the *same* name, or a provider whose data genuinely includes alias overlap (like the verified `Malware`/`Tool` case, and now `Campaign` via OpenCTI's `aliases` field), reconciles correctly.

## Testing

- `internal/intelligence`:
  - `TestUpsertMalware_MergesArraysOnConflict`/`TestUpsertTool_MergesArraysOnConflict` (existing) extended to also assert `Sources` (not just the legacy `Source`) reflects both providers after two upserts from different `SourceRef.Provider` values.
  - `TestUpsertCampaign_ReconcilesByNormalizedName` — two campaigns with different provider-style IDs but identical normalized names (e.g. Name="SolarWinds Compromise" from both a `misp`-sourced and an `opencti`-sourced upsert) merge into one row; assert `len(ListCampaigns()) == 1` and both providers appear in `Sources`.
  - `TestUpsertCampaign_ReconcilesByAlias` — first upsert with `Name: "SolarWinds Compromise"`, second upsert with `Name: "SUNBURST"`, `Aliases: []string{"SolarWinds Compromise"}` — asserts these merge into one row (the second's alias matches the first's canonical name via `search_key`).
  - `TestUpsertCampaign_DoesNotReconcileUnrelatedNames` — two campaigns with genuinely unrelated names and no alias overlap stay as two separate rows (guards against over-eager matching).
  - `TestNormalizeKey_*` — rename existing `MalwareKey` tests if any exist; confirm behavior unchanged (pure rename).
- `internal/connector`:
  - `TestMISPClient_FetchIntelligence_CampaignIDReferencesNormalizedKey` — confirms a MISP-sourced `Malware`/`Tool`'s `CampaignIDs` value matches the sibling `Campaign.ID` from the same `FetchIntelligence()` call (catches the `ev.ID`-vs-`NormalizeKey` consistency bug directly, not just indirectly through row counts).
  - `TestOpenCTIClient_ConvertCampaign_MapsAliases` — `entity.Aliases` flows through to `Campaign.Aliases` unchanged, mirroring the existing `TestOpenCTIClient_ConvertMalware_UsesOwnTechniquesAndTypes` pattern.
- Full regression (`go build ./...`, `go vet ./...`, `go test ./... -count=1`) as the closing task, per this project's established pattern for every prior Intelligence Expansion phase.
