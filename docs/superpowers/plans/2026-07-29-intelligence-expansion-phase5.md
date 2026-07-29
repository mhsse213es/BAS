# Intelligence Expansion Phase 5 (Cross-Provider Entity Reconciliation) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix Malware/Tool's misleading single-provider `SourceRef` (a real correctness bug — merged rows silently claim single-provider origin) and give Campaign the same cross-provider reconciliation Malware/Tool already have, via a shared `intelligence_entity_sources` table and name/alias-based matching.

**Architecture:** `NormalizeKey` (renamed from `MalwareKey`) becomes the reconciliation key for all three entity types, not just Malware/Tool. A new `intelligence_entity_sources` table tracks every provider's contribution to every entity (one row per entity/provider pair), replacing the single `SourceRef` as the source of truth — `Sources []SourceRef` is added alongside the existing `Source SourceRef` field (kept, not removed, since this codebase has no `DROP COLUMN` precedent). Campaign gains `Aliases` (Malware/Tool already have it) and a Go-maintained `search_key` array for alias-aware matching; `UpsertCampaign` looks up an existing row by exact ID or `search_key` overlap before deciding whether to merge or insert. `UpsertCampaign`/`UpsertMalware`/`UpsertTool` become transaction-wrapped (parent row + entity_sources row must commit together).

**Tech Stack:** Go, `internal/intelligence` (Postgres via `pgx/v5`, `pgxpool.Pool.Begin` for transactions), `internal/connector` (MISP/OpenCTI extraction, two small consistency fixes).

## Global Constraints

- No `DROP COLUMN` anywhere — `internal/db/content_schema.go` has zero precedent for it; every schema change here is `CREATE TABLE IF NOT EXISTS` or `ALTER TABLE ... ADD COLUMN IF NOT EXISTS`. (Spec §Non-Goals)
- No relationship join tables (`campaign_actors`, etc.) — `actor_ids`/`technique_ids`/`campaign_ids` stay as denormalized `[]string` arrays. (Spec §Non-Goals)
- No fuzzy/AI matching — reconciliation is deterministic normalized-name/alias equality only. (Spec §Non-Goals)
- `search_key`/alias-based matching is Campaign-only this phase — Malware/Tool keep their existing exact-`NormalizeKey(Name)`-only reconciliation, unchanged. (Spec §Non-Goals)
- `first_seen` on `intelligence_entity_sources` is set once (`DEFAULT NOW()`, excluded from every `ON CONFLICT ... SET` clause) — never recomputed on a repeat sync. (Spec §Architecture 1)

---

## File Structure

- Modify `orchestrator/internal/intelligence/models.go` — rename `MalwareKey`→`NormalizeKey`, add `Campaign.Aliases`, add `Sources []SourceRef` to all three entity types, add `buildSearchKey`.
- Modify `orchestrator/internal/intelligence/models_test.go` — rename `TestMalwareKey_*`→`TestNormalizeKey_*`.
- Modify `orchestrator/internal/intelligence/store.go` — new `upsertEntitySource`/`loadSources` helpers, transaction-wrapped `UpsertCampaign`/`UpsertMalware`/`UpsertTool`, `UpsertCampaign` reconciliation rewrite, `List*` functions populate `Sources`.
- Modify `orchestrator/internal/intelligence/store_test.go` — replace `TestUpsertCampaign_NameAndDescriptionOverwriteOnConflict` (its premise no longer holds once `Campaign.ID` is name-derived) with two new tests; extend `UpsertMalware`/`UpsertTool` merge tests to assert `Sources`.
- Modify `orchestrator/internal/db/content_schema.go` — new `intelligence_entity_sources` table, two `ALTER TABLE intelligence_campaigns ADD COLUMN IF NOT EXISTS` statements.
- Modify `orchestrator/internal/connector/misp.go` — `extractIntelligence`'s `Campaign.ID`/`Malware.CampaignIDs`/`Tool.CampaignIDs` consistency fix.
- Modify `orchestrator/internal/connector/misp_intelligence_test.go` — `MalwareKeyForTest` body updates to call `NormalizeKey`.
- Modify `orchestrator/internal/connector/opencti.go` — `convertCampaign`'s `ID`/`Aliases` fix, `campaigns` GraphQL block gains `aliases`.
- Modify `orchestrator/internal/connector/opencti_intelligence_test.go` — `intelligence.MalwareKey(...)` call sites → `intelligence.NormalizeKey(...)`.

---

### Task 1: Rename `MalwareKey` → `NormalizeKey`

**Files:**
- Modify: `orchestrator/internal/intelligence/models.go:78-89`
- Modify: `orchestrator/internal/intelligence/models_test.go`
- Modify: `orchestrator/internal/connector/misp.go:330,337`
- Modify: `orchestrator/internal/connector/misp_intelligence_test.go:33`
- Modify: `orchestrator/internal/connector/opencti.go:455,473`
- Modify: `orchestrator/internal/connector/opencti_intelligence_test.go:166,167,200,201`

**Interfaces:**
- Produces: `func NormalizeKey(name string) string` (same signature/behavior as the old `MalwareKey`) — consumed by every later task in this plan.

This is a pure, behavior-preserving rename — no logic changes. Verified via existing tests still passing under the new name.

- [ ] **Step 1: Rewrite the test file under the new name**

Replace the full contents of `orchestrator/internal/intelligence/models_test.go`:

```go
package intelligence

import "testing"

func TestNormalizeKey_NormalizesCase(t *testing.T) {
	if got := NormalizeKey("Emotet"); got != "emotet" {
		t.Fatalf("NormalizeKey(%q) = %q, want %q", "Emotet", got, "emotet")
	}
}

func TestNormalizeKey_StripsSpacesAndHyphens(t *testing.T) {
	cases := []struct{ in, want string }{
		{"Cobalt Strike", "cobaltstrike"},
		{"BlackCat/ALPHV", "blackcat/alphv"}, // slash intentionally untouched -- only spaces/hyphens are stripped, matching connector.actorKey()'s exact scope
		{"Trickbot-v2", "trickbotv2"},
	}
	for _, c := range cases {
		if got := NormalizeKey(c.in); got != c.want {
			t.Errorf("NormalizeKey(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestNormalizeKey_SameKeyForDifferentCasing(t *testing.T) {
	if NormalizeKey("Emotet") != NormalizeKey("EMOTET") {
		t.Fatal("expected case-insensitive dedup key")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/intelligence/... -run TestNormalizeKey -v`
Expected: FAIL — `undefined: NormalizeKey`

- [ ] **Step 3: Rename the function**

In `orchestrator/internal/intelligence/models.go`, replace:

```go
// MalwareKey normalizes a malware name into a stable dedup key -- the same
// normalization connector.actorKey() already applies to actor names
// (lowercase, strip spaces/hyphens). Duplicated here (not exported from
// internal/connector) to keep the connector<->intelligence dependency
// strictly one-way: connector imports intelligence for types, never the
// reverse.
func MalwareKey(name string) string {
	s := strings.ToLower(name)
	s = strings.ReplaceAll(s, " ", "")
	s = strings.ReplaceAll(s, "-", "")
	return s
}
```

with:

```go
// NormalizeKey normalizes a name into a stable reconciliation key -- the
// same normalization connector.actorKey() already applies to actor names
// (lowercase, strip spaces/hyphens). Used as the primary ID for Malware/
// Tool (unchanged since Phase 1/4) and, as of Phase 5, Campaign too --
// renamed from MalwareKey since it backs reconciliation for all three
// entity types, not just Malware. Duplicated here (not exported from
// internal/connector) to keep the connector<->intelligence dependency
// strictly one-way: connector imports intelligence for types, never the
// reverse.
func NormalizeKey(name string) string {
	s := strings.ToLower(name)
	s = strings.ReplaceAll(s, " ", "")
	s = strings.ReplaceAll(s, "-", "")
	return s
}
```

Also update the two doc-comment references to `MalwareKey` earlier in the same file (on `Malware.ID` and `Tool.ID` field comments, and the `Malware` struct's doc comment) to say `NormalizeKey` instead — cosmetic, no behavior change:

```go
// Malware is one mitre-malware GalaxyCluster entry, deduplicated by
// normalized name across every event that references it (NormalizeKey).
type Malware struct {
	ID             string    `json:"id"` // = NormalizeKey(Name) -- cross-event dedup key
```

```go
type Tool struct {
	ID             string    `json:"id"` // = NormalizeKey(Name) -- same cross-provider dedup key Malware already uses
```

- [ ] **Step 4: Update every call site**

In `orchestrator/internal/connector/misp.go`, replace both occurrences of `intelligence.MalwareKey(name)` with `intelligence.NormalizeKey(name)` (lines 330 and 337, inside the `mitre-malware`/`mitre-tool` `switch` cases of `extractIntelligence`).

In `orchestrator/internal/connector/misp_intelligence_test.go`, replace:

```go
func MalwareKeyForTest(name string) string { return intelligence.MalwareKey(name) }
```

with:

```go
func MalwareKeyForTest(name string) string { return intelligence.NormalizeKey(name) }
```

(The wrapper function's own name stays `MalwareKeyForTest` — only its body changes — to avoid churning the two call sites in this file that reference it by that name.)

In `orchestrator/internal/connector/opencti.go`, replace both occurrences of `intelligence.MalwareKey(entity.Name)` with `intelligence.NormalizeKey(entity.Name)` (in `convertMalware` and `convertTool`).

In `orchestrator/internal/connector/opencti_intelligence_test.go`, replace all four occurrences of `intelligence.MalwareKey(...)` with `intelligence.NormalizeKey(...)` (in `TestOpenCTIClient_ConvertMalware_UsesOwnTechniquesAndTypes` and `TestOpenCTIClient_ConvertTool_UsesOwnTechniques`).

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd orchestrator && go build ./... && go test ./internal/intelligence/... ./internal/connector/... -v`
Expected: PASS across both packages — this rename touches many call sites but changes zero behavior, so every existing test (not just the renamed ones) must still pass.

- [ ] **Step 6: Commit**

```bash
git add internal/intelligence/models.go internal/intelligence/models_test.go internal/connector/misp.go internal/connector/misp_intelligence_test.go internal/connector/opencti.go internal/connector/opencti_intelligence_test.go
git commit -m "refactor(intelligence): rename MalwareKey to NormalizeKey (Intelligence Expansion Phase 5)"
```

---

### Task 2: `intelligence_entity_sources` table + multi-provider `Sources` for Malware/Tool

**Files:**
- Modify: `orchestrator/internal/db/content_schema.go` — new table, right after the `intelligence_tools` block.
- Modify: `orchestrator/internal/intelligence/models.go` — `Sources []SourceRef` field on `Malware`/`Tool`/`Campaign`.
- Modify: `orchestrator/internal/intelligence/store.go` — `upsertEntitySource`, `loadSources`, transaction-wrapped `UpsertMalware`/`UpsertTool`, `ListMalware`/`ListTools` populate `Sources`.
- Modify: `orchestrator/internal/intelligence/store_test.go` — extend the existing `UpsertMalware`/`UpsertTool` merge tests to assert `Sources`.

**Interfaces:**
- Produces: `func upsertEntitySource(ctx context.Context, tx pgx.Tx, entityType, entityID string, src SourceRef) error`, `func loadSources(ctx context.Context, pool *pgxpool.Pool, entityType string, ids []string) (map[string][]SourceRef, error)` — both consumed again by Task 3 (`UpsertCampaign`/`ListCampaigns`).
- Consumes: `NormalizeKey` from Task 1 (no direct call here, but Task 1 must be complete first since this task's diff sits on top of it).

- [ ] **Step 1: Write the failing test**

In `orchestrator/internal/intelligence/store_test.go`, find `TestUpsertMalware_MergesArraysOnConflict`. Add an assertion block right after the existing `Source.Confidence` check (before the closing `})`):

```go
		if len(m.Sources) != 2 {
			t.Fatalf("Sources = %+v, want 2 entries (one per provider)", m.Sources)
		}
		providers := map[string]bool{m.Sources[0].Provider: true, m.Sources[1].Provider: true}
		if !providers["misp"] {
			t.Errorf("Sources providers = %v, want to include misp (both upserts in this test used provider=misp -- see the next task for a genuinely multi-provider case)", m.Sources)
		}
```

(This test's two upserts both use `Provider: "misp"` today — it proves `Sources` has one row per *upsert*, not per distinct provider value, which is the correct behavior: `intelligence_entity_sources`' `UNIQUE (entity_type, entity_id, provider)` means two same-provider upserts should collapse to ONE `Sources` entry, not two. Re-read this after Step 4 below — this assertion as written would actually FAIL correctly-implemented code, since both upserts share `Provider: "misp"` and should collapse to 1 row, not 2. Fix: change the test's second upsert to use a different provider so this assertion is meaningful. Edit the existing test's `second` literal:)

Locate the `second` variable in `TestUpsertMalware_MergesArraysOnConflict` and change its `Source.Provider`:

```go
	second := Malware{
		ID: "emotet", Name: "Emotet",
		TechniqueIDs: []string{"T1059", "T1105"}, ThreatActorIDs: []string{"APT-B"}, CampaignIDs: []string{"evt-2"},
		Source: SourceRef{Provider: "opencti", ExternalID: "evt-2", LastUpdated: time.Now(), Confidence: "high"},
	}
```

(Only the `Provider` field changes, from `"misp"` to `"opencti"` — everything else in `second` stays as it already is.) Now the `Sources` assertion added above is meaningful: two *different* providers, so two distinct rows.

Also update the assertion to check for both providers:

```go
		if len(m.Sources) != 2 {
			t.Fatalf("Sources = %+v, want 2 entries (one per provider)", m.Sources)
		}
		providers := map[string]bool{m.Sources[0].Provider: true, m.Sources[1].Provider: true}
		if !providers["misp"] || !providers["opencti"] {
			t.Errorf("Sources providers = %v, want both misp and opencti", m.Sources)
		}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/intelligence/... -run TestUpsertMalware_MergesArraysOnConflict -v`
Expected: FAIL — `m.Sources undefined` (field doesn't exist yet)

- [ ] **Step 3: Add `Sources` to the three entity models**

In `orchestrator/internal/intelligence/models.go`, add a `Sources []SourceRef` field to `Campaign`, `Malware`, and `Tool` (right after each struct's existing `Source SourceRef` field):

```go
type Campaign struct {
	ID             string    `json:"id"`
	Name           string    `json:"name"`
	Description    string    `json:"description"`
	ThreatActorIDs []string  `json:"threatActorIds"`
	TechniqueIDs   []string  `json:"techniqueIds"`
	Objective      string    `json:"objective,omitempty"`
	Source         SourceRef `json:"source"`
	// Sources lists every provider that has contributed to this campaign --
	// Source above stays as the first-contributing provider only (see
	// docs/superpowers/specs/2026-07-29-intelligence-expansion-phase5-design.md),
	// populated via intelligence_entity_sources, oldest first_seen first.
	Sources []SourceRef `json:"sources"`
}
```

```go
type Malware struct {
	ID             string    `json:"id"`
	Name           string    `json:"name"`
	Aliases        []string  `json:"aliases"`
	TechniqueIDs   []string  `json:"techniqueIds"`
	ThreatActorIDs []string  `json:"threatActorIds"`
	CampaignIDs    []string  `json:"campaignIds"`
	MalwareTypes   []string  `json:"malwareTypes,omitempty"`
	Source         SourceRef `json:"source"`
	Sources        []SourceRef `json:"sources"`
}
```

```go
type Tool struct {
	ID             string    `json:"id"`
	Name           string    `json:"name"`
	Aliases        []string  `json:"aliases"`
	TechniqueIDs   []string  `json:"techniqueIds"`
	ThreatActorIDs []string  `json:"threatActorIds"`
	CampaignIDs    []string  `json:"campaignIds"`
	Source         SourceRef `json:"source"`
	Sources        []SourceRef `json:"sources"`
}
```

- [ ] **Step 4: Add the `intelligence_entity_sources` table**

In `orchestrator/internal/db/content_schema.go`, the `stmts` slice currently ends with the `intelligence_tools` entry (added in Phase 4). Add a new statement directly after it, before the closing `}`:

```go
		// Intelligence Expansion Phase 5 -- multi-provider provenance
		// (see docs/superpowers/specs/2026-07-29-intelligence-expansion-phase5-design.md).
		// Existing intelligence_campaigns/malware/tools.source_* columns are
		// kept unchanged (no DROP COLUMN precedent in this file) and now mean
		// "the first provider that ever created this row" -- this table is
		// the authoritative multi-provider record.
		`CREATE TABLE IF NOT EXISTS intelligence_entity_sources (
			id           bigserial   PRIMARY KEY,
			entity_type  text        NOT NULL,
			entity_id    text        NOT NULL,
			provider     text        NOT NULL,
			external_id  text        NOT NULL,
			first_seen   timestamptz NOT NULL DEFAULT NOW(),
			last_sync    timestamptz NOT NULL,
			confidence   text        NOT NULL,
			tenant_id    text        NOT NULL DEFAULT 'default',
			UNIQUE (entity_type, entity_id, provider)
		)`,
```

- [ ] **Step 5: Add `upsertEntitySource` and `loadSources` helpers, wire into `UpsertMalware`/`UpsertTool`/`ListMalware`/`ListTools`**

In `orchestrator/internal/intelligence/store.go`, add the `"github.com/jackc/pgx/v5"` import (for `pgx.Tx`):

```go
import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)
```

Add these two helpers right after `nonNil`:

```go
// upsertEntitySource records (or refreshes) one provider's contribution to
// a Campaign/Malware/Tool row. first_seen is intentionally excluded from
// the UPDATE SET clause -- it's set once at first insert (DEFAULT NOW())
// and never recomputed on a repeat sync from the same provider, so it
// stays a true "when did we first observe this from this provider" value.
func upsertEntitySource(ctx context.Context, tx pgx.Tx, entityType, entityID string, src SourceRef) error {
	_, err := tx.Exec(ctx,
		`INSERT INTO intelligence_entity_sources
		   (entity_type, entity_id, provider, external_id, last_sync, confidence)
		 VALUES ($1,$2,$3,$4,$5,$6)
		 ON CONFLICT (entity_type, entity_id, provider) DO UPDATE SET
		   external_id = EXCLUDED.external_id,
		   last_sync   = EXCLUDED.last_sync,
		   confidence  = EXCLUDED.confidence`,
		entityType, entityID, src.Provider, src.ExternalID, src.LastUpdated, src.Confidence)
	return err
}

// loadSources batch-loads every provider contribution for the given entity
// IDs in one query (avoids N+1) -- shared by ListCampaigns/ListMalware/
// ListTools. Ordered oldest-first_seen-first, so index 0 is always the
// first-contributing provider, matching the entity's legacy singular
// Source field.
func loadSources(ctx context.Context, pool *pgxpool.Pool, entityType string, ids []string) (map[string][]SourceRef, error) {
	out := map[string][]SourceRef{}
	if len(ids) == 0 {
		return out, nil
	}
	rows, err := pool.Query(ctx,
		`SELECT entity_id, provider, external_id, last_sync, confidence
		 FROM intelligence_entity_sources
		 WHERE entity_type = $1 AND entity_id = ANY($2)
		 ORDER BY first_seen ASC`,
		entityType, ids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		var s SourceRef
		if err := rows.Scan(&id, &s.Provider, &s.ExternalID, &s.LastUpdated, &s.Confidence); err != nil {
			return nil, err
		}
		out[id] = append(out[id], s)
	}
	return out, rows.Err()
}
```

Replace `UpsertMalware` to run inside a transaction and call `upsertEntitySource`:

```go
// UpsertMalware merges on conflict -- the same malware family is
// legitimately referenced by many different events, so technique/actor/
// campaign ID lists accumulate (deduplicated union) rather than overwrite.
// Runs in a transaction with the intelligence_entity_sources upsert so the
// parent row and its provenance record commit together.
func UpsertMalware(ctx context.Context, pool *pgxpool.Pool, m Malware) error {
	m.Aliases, m.TechniqueIDs = nonNil(m.Aliases), nonNil(m.TechniqueIDs)
	m.ThreatActorIDs, m.CampaignIDs = nonNil(m.ThreatActorIDs), nonNil(m.CampaignIDs)

	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	_, err = tx.Exec(ctx,
		`INSERT INTO intelligence_malware
		   (id, name, aliases, technique_ids, actor_ids, campaign_ids, source_provider, source_external_id, source_confidence, last_updated)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
		 ON CONFLICT (id) DO UPDATE SET
		   aliases       = ARRAY(SELECT DISTINCT UNNEST(intelligence_malware.aliases || EXCLUDED.aliases)),
		   technique_ids = ARRAY(SELECT DISTINCT UNNEST(intelligence_malware.technique_ids || EXCLUDED.technique_ids)),
		   actor_ids     = ARRAY(SELECT DISTINCT UNNEST(intelligence_malware.actor_ids || EXCLUDED.actor_ids)),
		   campaign_ids  = ARRAY(SELECT DISTINCT UNNEST(intelligence_malware.campaign_ids || EXCLUDED.campaign_ids)),
		   source_confidence = EXCLUDED.source_confidence,
		   last_updated  = GREATEST(intelligence_malware.last_updated, EXCLUDED.last_updated)`,
		m.ID, m.Name, m.Aliases, m.TechniqueIDs, m.ThreatActorIDs, m.CampaignIDs,
		m.Source.Provider, m.Source.ExternalID, m.Source.Confidence, m.Source.LastUpdated)
	if err != nil {
		return err
	}

	if err := upsertEntitySource(ctx, tx, "malware", m.ID, m.Source); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
```

Replace `UpsertTool` identically (same transaction wrapping, same `upsertEntitySource` call with `"tool"`):

```go
// UpsertTool merges on conflict -- the same tool is legitimately referenced
// by many different actors/events, so technique/actor/campaign ID lists
// accumulate (deduplicated union) rather than overwrite. Same reasoning as
// UpsertMalware, including the transaction wrapping.
func UpsertTool(ctx context.Context, pool *pgxpool.Pool, t Tool) error {
	t.Aliases, t.TechniqueIDs = nonNil(t.Aliases), nonNil(t.TechniqueIDs)
	t.ThreatActorIDs, t.CampaignIDs = nonNil(t.ThreatActorIDs), nonNil(t.CampaignIDs)

	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	_, err = tx.Exec(ctx,
		`INSERT INTO intelligence_tools
		   (id, name, aliases, technique_ids, actor_ids, campaign_ids, source_provider, source_external_id, source_confidence, last_updated)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
		 ON CONFLICT (id) DO UPDATE SET
		   aliases       = ARRAY(SELECT DISTINCT UNNEST(intelligence_tools.aliases || EXCLUDED.aliases)),
		   technique_ids = ARRAY(SELECT DISTINCT UNNEST(intelligence_tools.technique_ids || EXCLUDED.technique_ids)),
		   actor_ids     = ARRAY(SELECT DISTINCT UNNEST(intelligence_tools.actor_ids || EXCLUDED.actor_ids)),
		   campaign_ids  = ARRAY(SELECT DISTINCT UNNEST(intelligence_tools.campaign_ids || EXCLUDED.campaign_ids)),
		   source_confidence = EXCLUDED.source_confidence,
		   last_updated  = GREATEST(intelligence_tools.last_updated, EXCLUDED.last_updated)`,
		t.ID, t.Name, t.Aliases, t.TechniqueIDs, t.ThreatActorIDs, t.CampaignIDs,
		t.Source.Provider, t.Source.ExternalID, t.Source.Confidence, t.Source.LastUpdated)
	if err != nil {
		return err
	}

	if err := upsertEntitySource(ctx, tx, "tool", t.ID, t.Source); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
```

Update `ListTools` to populate `Sources`:

```go
// ListTools returns every tool record, newest-updated first. Always
// non-nil, same convention as ListCampaigns/ListMalware.
func ListTools(ctx context.Context, pool *pgxpool.Pool) ([]Tool, error) {
	rows, err := pool.Query(ctx,
		`SELECT id, name, aliases, technique_ids, actor_ids, campaign_ids, source_provider, source_external_id, source_confidence, last_updated
		 FROM intelligence_tools ORDER BY last_updated DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Tool{}
	ids := []string{}
	for rows.Next() {
		var t Tool
		if err := rows.Scan(&t.ID, &t.Name, &t.Aliases, &t.TechniqueIDs, &t.ThreatActorIDs, &t.CampaignIDs,
			&t.Source.Provider, &t.Source.ExternalID, &t.Source.Confidence, &t.Source.LastUpdated); err != nil {
			return nil, err
		}
		out = append(out, t)
		ids = append(ids, t.ID)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	sources, err := loadSources(ctx, pool, "tool", ids)
	if err != nil {
		return nil, err
	}
	for i := range out {
		out[i].Sources = sources[out[i].ID]
	}
	return out, nil
}
```

Update `ListMalware` the same way (mirrors `ListTools` exactly, entity type `"malware"`):

```go
// ListMalware returns every malware record, newest-updated first. Always
// non-nil, same convention as ListCampaigns.
func ListMalware(ctx context.Context, pool *pgxpool.Pool) ([]Malware, error) {
	rows, err := pool.Query(ctx,
		`SELECT id, name, aliases, technique_ids, actor_ids, campaign_ids, source_provider, source_external_id, source_confidence, last_updated
		 FROM intelligence_malware ORDER BY last_updated DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Malware{}
	ids := []string{}
	for rows.Next() {
		var m Malware
		if err := rows.Scan(&m.ID, &m.Name, &m.Aliases, &m.TechniqueIDs, &m.ThreatActorIDs, &m.CampaignIDs,
			&m.Source.Provider, &m.Source.ExternalID, &m.Source.Confidence, &m.Source.LastUpdated); err != nil {
			return nil, err
		}
		out = append(out, m)
		ids = append(ids, m.ID)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	sources, err := loadSources(ctx, pool, "malware", ids)
	if err != nil {
		return nil, err
	}
	for i := range out {
		out[i].Sources = sources[out[i].ID]
	}
	return out, nil
}
```

- [ ] **Step 6: Run test to verify it passes**

Run: `cd orchestrator && go test ./internal/intelligence/... -v`
Expected: PASS — the extended `TestUpsertMalware_MergesArraysOnConflict` plus every existing test in the package. (Docker Desktop must be running — check `docker info` first.)

- [ ] **Step 7: Commit**

```bash
git add internal/db/content_schema.go internal/intelligence/models.go internal/intelligence/store.go internal/intelligence/store_test.go
git commit -m "feat(intelligence): intelligence_entity_sources table, multi-provider Sources for Malware/Tool (Intelligence Expansion Phase 5)"
```

---

### Task 3: Campaign reconciliation — aliases, search_key, rewritten `UpsertCampaign`

**Files:**
- Modify: `orchestrator/internal/db/content_schema.go` — two `ALTER TABLE intelligence_campaigns ADD COLUMN IF NOT EXISTS` statements.
- Modify: `orchestrator/internal/intelligence/models.go` — `Campaign.Aliases`, `buildSearchKey`.
- Modify: `orchestrator/internal/intelligence/store.go` — `UpsertCampaign` rewrite, `ListCampaigns` update.
- Modify: `orchestrator/internal/intelligence/store_test.go` — replace `TestUpsertCampaign_NameAndDescriptionOverwriteOnConflict`, add two new tests.

**Interfaces:**
- Consumes: `NormalizeKey` (Task 1), `upsertEntitySource`/`loadSources` (Task 2).
- Produces: `func buildSearchKey(name string, aliases []string) []string` — used only inside `UpsertCampaign`, no other task depends on it.

**Important — why an existing test is being replaced, not just extended:** `TestUpsertCampaign_NameAndDescriptionOverwriteOnConflict` upserts the same literal `ID: "evt-1"` twice, the second time with a *different* `Name`. Under the old scheme (`Campaign.ID` = provider's own event ID, set independently of `Name`) that was a valid same-row update. Under this task's new scheme (`Campaign.ID` is always `NormalizeKey(Name)`, computed by the caller before calling `UpsertCampaign` — same convention `misp.go`/`opencti.go` already use for Malware/Tool) a real caller could never construct that scenario: changing `Name` changes what `ID` the caller would have computed for the struct in the first place. The test's premise is now internally inconsistent with the new design, not just differently named — it must be replaced.

- [ ] **Step 1: Write the three failing tests**

In `orchestrator/internal/intelligence/store_test.go`, delete `TestUpsertCampaign_NameAndDescriptionOverwriteOnConflict` entirely (its full current body, from `func TestUpsertCampaign_NameAndDescriptionOverwriteOnConflict(t *testing.T) {` through its closing `}`). Replace it with:

```go
func TestUpsertCampaign_SameNameResync_UpdatesDescription(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		key := NormalizeKey("Operation X")
		first := Campaign{
			ID: key, Name: "Operation X", Description: "first description",
			ThreatActorIDs: []string{"APT-TEST"}, TechniqueIDs: []string{"T1059"},
			Source: SourceRef{Provider: "misp", ExternalID: "evt-1", LastUpdated: time.Now(), Confidence: "medium"},
		}
		if err := UpsertCampaign(ctx, pool, first); err != nil {
			t.Fatalf("first UpsertCampaign: %v", err)
		}

		second := Campaign{
			ID: key, Name: "Operation X", Description: "updated description",
			ThreatActorIDs: []string{"APT-TEST"}, TechniqueIDs: []string{"T1059", "T1105"},
			Source: SourceRef{Provider: "misp", ExternalID: "evt-1", LastUpdated: time.Now(), Confidence: "medium"},
		}
		if err := UpsertCampaign(ctx, pool, second); err != nil {
			t.Fatalf("second UpsertCampaign: %v", err)
		}

		got, err := ListCampaigns(ctx, pool)
		if err != nil {
			t.Fatalf("ListCampaigns: %v", err)
		}
		if len(got) != 1 {
			t.Fatalf("got %d campaigns, want 1", len(got))
		}
		if got[0].Description != "updated description" {
			t.Fatalf("Description = %q, want %q (same-identity resync must update description)", got[0].Description, "updated description")
		}
		if len(got[0].TechniqueIDs) != 2 {
			t.Fatalf("TechniqueIDs = %v, want 2 entries", got[0].TechniqueIDs)
		}
	})
}

func TestUpsertCampaign_AliasMatch_PreservesCanonicalNameAndDescription(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		canonical := Campaign{
			ID: NormalizeKey("SolarWinds Compromise"), Name: "SolarWinds Compromise", Description: "original description",
			ThreatActorIDs: []string{"APT29"}, TechniqueIDs: []string{"T1059"},
			Source: SourceRef{Provider: "opencti", ExternalID: "campaign--1", LastUpdated: time.Now(), Confidence: "high"},
		}
		if err := UpsertCampaign(ctx, pool, canonical); err != nil {
			t.Fatalf("first UpsertCampaign: %v", err)
		}

		aliasMatch := Campaign{
			ID: NormalizeKey("SUNBURST"), Name: "SUNBURST", Description: "a different description",
			Aliases:        []string{"SolarWinds Compromise"},
			ThreatActorIDs: []string{"Cozy Bear"}, TechniqueIDs: []string{"T1105"},
			Source: SourceRef{Provider: "misp", ExternalID: "evt-9", LastUpdated: time.Now(), Confidence: "medium"},
		}
		if err := UpsertCampaign(ctx, pool, aliasMatch); err != nil {
			t.Fatalf("second UpsertCampaign: %v", err)
		}

		got, err := ListCampaigns(ctx, pool)
		if err != nil {
			t.Fatalf("ListCampaigns: %v", err)
		}
		if len(got) != 1 {
			t.Fatalf("got %d campaigns, want 1 (SUNBURST must reconcile into SolarWinds Compromise via alias)", len(got))
		}
		row := got[0]
		if row.Name != "SolarWinds Compromise" {
			t.Errorf("Name = %q, want %q (canonical name must not be overwritten by an alias-match merge)", row.Name, "SolarWinds Compromise")
		}
		if row.Description != "original description" {
			t.Errorf("Description = %q, want %q (canonical description must not be overwritten by an alias-match merge)", row.Description, "original description")
		}
		hasSolarWinds, hasSunburst := false, false
		for _, a := range row.Aliases {
			if a == "SolarWinds Compromise" {
				hasSolarWinds = true
			}
			if a == "SUNBURST" {
				hasSunburst = true
			}
		}
		if !hasSolarWinds || !hasSunburst {
			t.Errorf("Aliases = %v, want to contain both %q and %q", row.Aliases, "SolarWinds Compromise", "SUNBURST")
		}
		sort.Strings(row.ThreatActorIDs)
		if len(row.ThreatActorIDs) != 2 || row.ThreatActorIDs[0] != "APT29" || row.ThreatActorIDs[1] != "Cozy Bear" {
			t.Errorf("ThreatActorIDs = %v, want union [APT29 Cozy Bear] (alias-match must still merge relationship arrays)", row.ThreatActorIDs)
		}
		if len(row.Sources) != 2 {
			t.Fatalf("Sources = %+v, want 2 entries (opencti + misp, both contributed to the same canonical row)", row.Sources)
		}
	})
}

func TestUpsertCampaign_DoesNotReconcileUnrelatedNames(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		first := Campaign{
			ID: NormalizeKey("Operation Alpha"), Name: "Operation Alpha",
			ThreatActorIDs: []string{"APT-A"}, TechniqueIDs: []string{"T1059"},
			Source: SourceRef{Provider: "misp", ExternalID: "evt-alpha", LastUpdated: time.Now(), Confidence: "medium"},
		}
		if err := UpsertCampaign(ctx, pool, first); err != nil {
			t.Fatalf("first UpsertCampaign: %v", err)
		}

		second := Campaign{
			ID: NormalizeKey("Operation Beta"), Name: "Operation Beta",
			ThreatActorIDs: []string{"APT-B"}, TechniqueIDs: []string{"T1105"},
			Source: SourceRef{Provider: "opencti", ExternalID: "campaign--beta", LastUpdated: time.Now(), Confidence: "medium"},
		}
		if err := UpsertCampaign(ctx, pool, second); err != nil {
			t.Fatalf("second UpsertCampaign: %v", err)
		}

		got, err := ListCampaigns(ctx, pool)
		if err != nil {
			t.Fatalf("ListCampaigns: %v", err)
		}
		count := 0
		for _, c := range got {
			if c.Name == "Operation Alpha" || c.Name == "Operation Beta" {
				count++
			}
		}
		if count != 2 {
			t.Fatalf("found %d of Operation Alpha/Beta, want 2 separate rows (unrelated names/no alias overlap must not reconcile)", count)
		}
	})
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/intelligence/... -run 'TestUpsertCampaign_SameNameResync|TestUpsertCampaign_AliasMatch|TestUpsertCampaign_DoesNotReconcileUnrelatedNames' -v`
Expected: FAIL — `undefined: NormalizeKey` will already be fixed by Task 1, so the actual failure here is either a compile error on `Campaign.Aliases` (field doesn't exist yet) or a behavioral failure once it compiles (still overwriting name/description unconditionally, or not reconciling by alias at all — either way, red).

- [ ] **Step 3: Add `Campaign.Aliases` and `buildSearchKey`**

In `orchestrator/internal/intelligence/models.go`, add `Aliases` to the `Campaign` struct (between `Description` and `ThreatActorIDs`):

```go
type Campaign struct {
	ID             string    `json:"id"`
	Name           string    `json:"name"`
	Description    string    `json:"description"`
	Aliases        []string  `json:"aliases"`
	ThreatActorIDs []string  `json:"threatActorIds"`
	TechniqueIDs   []string  `json:"techniqueIds"`
	Objective      string    `json:"objective,omitempty"`
	Source         SourceRef `json:"source"`
	Sources        []SourceRef `json:"sources"`
}
```

Add `buildSearchKey` after `NormalizeKey`:

```go
// buildSearchKey returns the deduplicated union of NormalizeKey(name) and
// NormalizeKey(alias) for every alias -- used by UpsertCampaign to find an
// existing row that shares any name/alias with an incoming one, even under
// a different primary ID (e.g. "SUNBURST" reconciling into an existing
// "SolarWinds Compromise" row via a shared alias).
func buildSearchKey(name string, aliases []string) []string {
	seen := map[string]bool{}
	out := []string{}
	add := func(s string) {
		k := NormalizeKey(s)
		if k == "" || seen[k] {
			return
		}
		seen[k] = true
		out = append(out, k)
	}
	add(name)
	for _, a := range aliases {
		add(a)
	}
	return out
}
```

- [ ] **Step 4: Add the two new columns**

In `orchestrator/internal/db/content_schema.go`, add two statements directly after the `intelligence_entity_sources` table statement from Task 2 (still inside the `stmts` slice, before the closing `}`):

```go
		`ALTER TABLE intelligence_campaigns ADD COLUMN IF NOT EXISTS aliases text[] NOT NULL DEFAULT '{}'`,
		`ALTER TABLE intelligence_campaigns ADD COLUMN IF NOT EXISTS search_key text[] NOT NULL DEFAULT '{}'`,
```

- [ ] **Step 5: Rewrite `UpsertCampaign` and `ListCampaigns`**

In `orchestrator/internal/intelligence/store.go`, replace `UpsertCampaign` entirely:

```go
// UpsertCampaign reconciles by normalized name/alias (search_key) before
// upserting -- if an existing campaign shares any name/alias with the
// incoming one (regardless of provider-specific ID), the incoming data
// merges into that existing row instead of creating a duplicate. c.ID is
// trusted as already computed by the caller (NormalizeKey(c.Name), same
// convention connector.MISPClient/OpenCTIClient already use for
// Malware/Tool -- see internal/connector/misp.go's extractIntelligence and
// internal/connector/opencti.go's convertCampaign).
//
// actor_ids/technique_ids/aliases/search_key merge (union); name/
// description only overwrite when the upsert lands on its own natural ID
// (a same-identity resync, canonicalID == c.ID) -- an alias-match merge
// into a DIFFERENT existing row (canonicalID != c.ID) must not silently
// rewrite that row's canonical name/description. The incoming name always
// gets folded into aliases regardless, so it's never lost.
func UpsertCampaign(ctx context.Context, pool *pgxpool.Pool, c Campaign) error {
	c.ThreatActorIDs, c.TechniqueIDs = nonNil(c.ThreatActorIDs), nonNil(c.TechniqueIDs)
	c.Aliases = nonNil(c.Aliases)
	searchKey := buildSearchKey(c.Name, c.Aliases)
	aliasesToMerge := append([]string{c.Name}, c.Aliases...)

	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	canonicalID := c.ID
	var existingID string
	err = tx.QueryRow(ctx,
		`SELECT id FROM intelligence_campaigns WHERE id = $1 OR search_key && $2 LIMIT 1`,
		c.ID, searchKey).Scan(&existingID)
	if err == nil {
		canonicalID = existingID
	} else if err != pgx.ErrNoRows {
		return err
	}

	_, err = tx.Exec(ctx,
		`INSERT INTO intelligence_campaigns
		   (id, name, description, aliases, search_key, actor_ids, technique_ids, source_provider, source_external_id, source_confidence, last_updated)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
		 ON CONFLICT (id) DO UPDATE SET
		   name          = CASE WHEN intelligence_campaigns.id = $12 THEN EXCLUDED.name ELSE intelligence_campaigns.name END,
		   description   = CASE WHEN intelligence_campaigns.id = $12 THEN EXCLUDED.description ELSE intelligence_campaigns.description END,
		   aliases       = ARRAY(SELECT DISTINCT UNNEST(intelligence_campaigns.aliases || EXCLUDED.aliases)),
		   search_key    = ARRAY(SELECT DISTINCT UNNEST(intelligence_campaigns.search_key || EXCLUDED.search_key)),
		   actor_ids     = ARRAY(SELECT DISTINCT UNNEST(intelligence_campaigns.actor_ids || EXCLUDED.actor_ids)),
		   technique_ids = ARRAY(SELECT DISTINCT UNNEST(intelligence_campaigns.technique_ids || EXCLUDED.technique_ids)),
		   last_updated  = GREATEST(intelligence_campaigns.last_updated, EXCLUDED.last_updated)`,
		canonicalID, c.Name, c.Description, aliasesToMerge, searchKey,
		c.ThreatActorIDs, c.TechniqueIDs, c.Source.Provider, c.Source.ExternalID, c.Source.Confidence, c.Source.LastUpdated,
		c.ID)
	if err != nil {
		return err
	}

	if err := upsertEntitySource(ctx, tx, "campaign", canonicalID, c.Source); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
```

Replace `ListCampaigns` to select the new `aliases` column and populate `Sources`:

```go
// ListCampaigns returns every campaign, newest-updated first. Always
// non-nil (an empty slice, not null) so JSON callers can iterate without a
// guard -- same convention internal/recommend.Recommendations already uses.
func ListCampaigns(ctx context.Context, pool *pgxpool.Pool) ([]Campaign, error) {
	rows, err := pool.Query(ctx,
		`SELECT id, name, description, aliases, actor_ids, technique_ids, source_provider, source_external_id, source_confidence, last_updated
		 FROM intelligence_campaigns ORDER BY last_updated DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Campaign{}
	ids := []string{}
	for rows.Next() {
		var c Campaign
		if err := rows.Scan(&c.ID, &c.Name, &c.Description, &c.Aliases, &c.ThreatActorIDs, &c.TechniqueIDs,
			&c.Source.Provider, &c.Source.ExternalID, &c.Source.Confidence, &c.Source.LastUpdated); err != nil {
			return nil, err
		}
		out = append(out, c)
		ids = append(ids, c.ID)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	sources, err := loadSources(ctx, pool, "campaign", ids)
	if err != nil {
		return nil, err
	}
	for i := range out {
		out[i].Sources = sources[out[i].ID]
	}
	return out, nil
}
```

- [ ] **Step 6: Run all Campaign tests to verify they pass**

Run: `cd orchestrator && go test ./internal/intelligence/... -run TestUpsertCampaign -v`
Expected: PASS — the two new tests, plus the pre-existing `TestUpsertCampaign_MergesActorAndTechniqueIDsOnConflict` (from Phase 2 — unaffected by this rewrite, since it always used the same literal ID both times, which is exactly the "same-identity resync" path this task preserves).

- [ ] **Step 7: Run the full `internal/intelligence` package**

Run: `cd orchestrator && go test ./internal/intelligence/... -v`
Expected: PASS — everything in the package, confirming Tasks 1-3 compose correctly.

- [ ] **Step 8: Commit**

```bash
git add internal/db/content_schema.go internal/intelligence/models.go internal/intelligence/store.go internal/intelligence/store_test.go
git commit -m "feat(intelligence): Campaign cross-provider reconciliation via aliases/search_key (Intelligence Expansion Phase 5)"
```

---

### Task 4: MISP consistency fix — Campaign.ID/CampaignIDs use the campaign's own normalized key

**Files:**
- Modify: `orchestrator/internal/connector/misp.go:305-345` (`extractIntelligence`)
- Test: `orchestrator/internal/connector/misp_intelligence_test.go`

**Interfaces:**
- Consumes: `NormalizeKey` (Task 1).
- Produces: no new exported symbols — behavior-only fix inside `extractIntelligence`.

**Why this matters:** before this task, `extractIntelligence` sets `Campaign.ID: ev.ID` and separately sets `Malware.CampaignIDs`/`Tool.CampaignIDs` to `[]string{ev.ID}` too — so they agree with each other, but as of Task 3, `UpsertCampaign` reconciles Campaign rows by `NormalizeKey(Name)`/`search_key`, not by `ev.ID`. If a campaign genuinely reconciles into a *different* canonical row (a real alias match), that row's actual `id` in the database is no longer `ev.ID` — but Malware/Tool's `CampaignIDs` would still point at the stale `ev.ID`, a dangling reference. The fix: use `NormalizeKey(detail.Event.Info)` (the same value the campaign itself is keyed by) everywhere a campaign reference is needed.

- [ ] **Step 1: Write the failing test**

Add to `orchestrator/internal/connector/misp_intelligence_test.go`, after `TestMISPClient_FetchIntelligence_ExtractsTools`:

```go
func TestMISPClient_FetchIntelligence_MalwareCampaignIDMatchesCampaignID(t *testing.T) {
	index := []mispEventIndex{
		{ID: "4", Info: "Consistency Check Event", Timestamp: "1700000000", Tag: []mispTag{{Name: "mitre-attack-pattern"}}},
	}
	details := map[string]mispEventDetail{
		"4": {Event: struct {
			ID            string          `json:"id"`
			Info          string          `json:"info"`
			Timestamp     string          `json:"timestamp"`
			Tag           []mispTag       `json:"Tag"`
			GalaxyCluster []mispGalaxy    `json:"GalaxyCluster"`
			Attribute     []mispAttribute `json:"Attribute"`
		}{
			ID: "4", Info: "Consistency Check Event",
			GalaxyCluster: []mispGalaxy{
				{Type: "mitre-attack-pattern", Value: "PowerShell", Meta: struct {
					ExternalID []string `json:"external_id"`
					KillChain  []string `json:"kill_chain"`
				}{ExternalID: []string{"T1059.001"}}},
				{Type: "mitre-attack-pattern", Value: "Phishing", Meta: struct {
					ExternalID []string `json:"external_id"`
					KillChain  []string `json:"kill_chain"`
				}{ExternalID: []string{"T1566.001"}}},
				{Type: "mitre-malware", Value: "ConsistencyMalware"},
			},
		}},
	}
	server := mispServer(t, index, details)
	defer server.Close()

	c := NewMISPClient(server.URL, "test-key", nil, nil)
	if _, err := c.Fetch(); err != nil {
		t.Fatalf("Fetch: %v", err)
	}

	campaigns, malware, _, err := c.FetchIntelligence()
	if err != nil {
		t.Fatalf("FetchIntelligence: %v", err)
	}
	if len(campaigns) != 1 || len(malware) != 1 {
		t.Fatalf("campaigns = %+v, malware = %+v, want 1 each", campaigns, malware)
	}
	if campaigns[0].ID != MalwareKeyForTest("Consistency Check Event") {
		t.Fatalf("Campaign.ID = %q, want NormalizeKey of the event title, %q", campaigns[0].ID, MalwareKeyForTest("Consistency Check Event"))
	}
	if len(malware[0].CampaignIDs) != 1 || malware[0].CampaignIDs[0] != campaigns[0].ID {
		t.Fatalf("Malware.CampaignIDs = %v, want [%q] (must match the sibling Campaign's own ID, not the raw MISP event ID)", malware[0].CampaignIDs, campaigns[0].ID)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/connector/... -run TestMISPClient_FetchIntelligence_MalwareCampaignIDMatchesCampaignID -v`
Expected: FAIL — `Campaign.ID = "4"` (the raw `ev.ID`), not the expected normalized key of the event title.

- [ ] **Step 3: Fix `extractIntelligence`**

In `orchestrator/internal/connector/misp.go`, replace the `campaign` construction and the `CampaignIDs` references inside the `switch`:

```go
	campaign := &intelligence.Campaign{
		ID: intelligence.NormalizeKey(detail.Event.Info), Name: detail.Event.Info, Description: detail.Event.Info,
		ThreatActorIDs: []string{actor.Name}, TechniqueIDs: techniqueIDs(actor.Techniques),
		Source: src,
	}

	var malware []intelligence.Malware
	var tools []intelligence.Tool
	for _, gc := range detail.Event.GalaxyCluster {
		name := strings.TrimSpace(gc.Value)
		if name == "" {
			continue
		}
		switch gc.Type {
		case "mitre-malware":
			malware = append(malware, intelligence.Malware{
				ID: intelligence.NormalizeKey(name), Name: name,
				TechniqueIDs: techniqueIDs(actor.Techniques),
				ThreatActorIDs: []string{actor.Name}, CampaignIDs: []string{campaign.ID},
				Source: src,
			})
		case "mitre-tool":
			tools = append(tools, intelligence.Tool{
				ID: intelligence.NormalizeKey(name), Name: name,
				TechniqueIDs: techniqueIDs(actor.Techniques),
				ThreatActorIDs: []string{actor.Name}, CampaignIDs: []string{campaign.ID},
				Source: src,
			})
		}
	}
	return campaign, malware, tools
```

(`ev.ID` still flows into `src.ExternalID` unchanged, at the top of the function — that's the provider-specific identifier, correctly preserved. Only the *campaign reference* usages change, from `ev.ID` to `campaign.ID`.)

- [ ] **Step 4: Run test to verify it passes**

Run: `cd orchestrator && go test ./internal/connector/... -run TestMISPClient_FetchIntelligence_MalwareCampaignIDMatchesCampaignID -v`
Expected: PASS

- [ ] **Step 5: Run the full MISP intelligence test suite to confirm no regressions**

Run: `cd orchestrator && go test ./internal/connector/... -run TestMISPClient -v`
Expected: PASS — every existing `TestMISPClient_*` test, including `TestMISPClient_FetchIntelligence_OneCampaignNoMalware` (which never asserted on `Campaign.ID`'s exact value, only its `Name`/`TechniqueIDs`/`ThreatActorIDs`, so this ID-scheme change doesn't break it) and `TestMISPClient_FetchIntelligence_MultipleMalwareClusters`/`TestMISPClient_FetchIntelligence_ExtractsTools` (which assert `CampaignIDs == [ev.ID]` today via the literal event ID string, e.g. `"2"`/`"3"` — check these still pass: since `NormalizeKey` of a purely-numeric string like `"2"` returns `"2"` unchanged, `campaign.ID` and `ev.ID` happen to be identical for these two tests' fixtures, so no assertion changes are needed there. Confirm this by reading the test output rather than assuming.)

- [ ] **Step 6: Commit**

```bash
git add internal/connector/misp.go internal/connector/misp_intelligence_test.go
git commit -m "fix(connector): MISP Malware/Tool.CampaignIDs reference the campaign's own normalized ID (Intelligence Expansion Phase 5)"
```

---

### Task 5: OpenCTI consistency fix — Campaign.ID + Aliases

**Files:**
- Modify: `orchestrator/internal/connector/opencti.go` — `convertCampaign`, `campaigns` GraphQL block in `actorFieldsFragment`.
- Test: `orchestrator/internal/connector/opencti_intelligence_test.go`

**Interfaces:**
- Consumes: `NormalizeKey` (Task 1), `Campaign.Aliases` (Task 3).
- Produces: no new exported symbols.

- [ ] **Step 1: Write the failing test**

Add to `orchestrator/internal/connector/opencti_intelligence_test.go`, after `TestOpenCTIClient_ConvertCampaign_UsesOwnTechniquesAndObjective`:

```go
func TestOpenCTIClient_ConvertCampaign_IDIsNormalizedNameNotSTIXID(t *testing.T) {
	c := NewOpenCTIClient("http://example.invalid", "test-key", nil)
	actor := &ThreatActor{Name: "APT29"}
	entity := octiRelatedEntity{
		ID: "campaign--abc123", Name: "SolarWinds Compromise", Aliases: []string{"SUNBURST"},
		AttackPatterns: twoTechniqueConn(),
	}
	campaign := c.convertCampaign(entity, actor)
	if campaign.ID != intelligence.NormalizeKey("SolarWinds Compromise") {
		t.Fatalf("convertCampaign().ID = %q, want %q (NormalizeKey of the name, not the raw STIX id)", campaign.ID, intelligence.NormalizeKey("SolarWinds Compromise"))
	}
	if campaign.Source.ExternalID != "campaign--abc123" {
		t.Fatalf("convertCampaign().Source.ExternalID = %q, want the raw STIX id %q (still preserved as provenance, just not the primary ID)", campaign.Source.ExternalID, "campaign--abc123")
	}
	if len(campaign.Aliases) != 1 || campaign.Aliases[0] != "SUNBURST" {
		t.Fatalf("convertCampaign().Aliases = %v, want [SUNBURST]", campaign.Aliases)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/connector/... -run TestOpenCTIClient_ConvertCampaign_IDIsNormalizedNameNotSTIXID -v`
Expected: FAIL — `convertCampaign().ID = "campaign--abc123"` (still the raw STIX id), and `Aliases` is empty (field not mapped yet).

- [ ] **Step 3: Fix `convertCampaign` and the GraphQL query**

In `orchestrator/internal/connector/opencti.go`, replace `convertCampaign`:

```go
// convertCampaign builds an intelligence.Campaign from a campaign entity
// discovered under a specific actor's "attributed-to" relationship. Uses
// the campaign's OWN nested technique relationships (via techniqueRefsFrom),
// not the actor's -- a campaign is often more specifically scoped than its
// attributed actor's full profile. ID is NormalizeKey(entity.Name), not the
// raw STIX id -- see intelligence.UpsertCampaign's alias/name reconciliation
// (Intelligence Expansion Phase 5); the STIX id is preserved as
// Source.ExternalID, same separation MISP's extractIntelligence already
// uses (campaign.ID vs. the raw MISP event ID).
func (c *OpenCTIClient) convertCampaign(entity octiRelatedEntity, actor *ThreatActor) intelligence.Campaign {
	return intelligence.Campaign{
		ID:             intelligence.NormalizeKey(entity.Name),
		Name:           entity.Name,
		Description:    entity.Description,
		Aliases:        entity.Aliases,
		Objective:      entity.Objective,
		ThreatActorIDs: []string{actor.Name},
		TechniqueIDs:   techniqueIDs(techniqueRefsFrom(entity.AttackPatterns)),
		Source: intelligence.SourceRef{
			Provider: "opencti", ExternalID: entity.ID,
			LastUpdated: actor.LastSeen, Confidence: actor.Confidence,
		},
	}
}
```

In the `campaigns` relationship block inside `actorFieldsFragment`, add an `aliases` line to the `... on Campaign` inline fragment (right after `description`):

```graphql
        campaigns: stixCoreRelationships(
          relationship_type: "attributed-to"
          fromTypes: ["Campaign"]
          first: 100
        ) {
          edges {
            node {
              from {
                ... on Campaign {
                  id
                  name
                  description
                  aliases
                  objective
                  attackPatterns: stixCoreRelationships(
                    relationship_type: "uses"
                    toTypes: ["Attack-Pattern"]
                    first: 100
                  ) {
                    edges {
                      node {
                        to {
                          ... on AttackPattern {
                            x_mitre_id
                            name
                            killChainPhases { phase_name }
                          }
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
```

(`octiRelatedEntity` already has an `Aliases []string` field — used today by `convertMalware`/`convertTool` — so no struct changes are needed, only the query text and `convertCampaign`'s mapping.)

- [ ] **Step 4: Run test to verify it passes**

Run: `cd orchestrator && go test ./internal/connector/... -run TestOpenCTIClient_ConvertCampaign -v`
Expected: PASS — both the new test and the pre-existing `TestOpenCTIClient_ConvertCampaign_UsesOwnTechniquesAndObjective` (unaffected — it never asserted on `ID`'s exact value against the STIX id, only `Name`/`Objective`/`TechniqueIDs`/`ThreatActorIDs`/`Source.Provider`/`Source.ExternalID`, and `Source.ExternalID` still equals `entity.ID` unchanged).

- [ ] **Step 5: Run the full OpenCTI intelligence test suite**

Run: `cd orchestrator && go test ./internal/connector/... -v`
Expected: PASS across the whole `internal/connector` package.

- [ ] **Step 6: Commit**

```bash
git add internal/connector/opencti.go internal/connector/opencti_intelligence_test.go
git commit -m "fix(connector): OpenCTI Campaign.ID uses normalized name, maps Aliases (Intelligence Expansion Phase 5)"
```

---

### Task 6: Full regression

**Files:** none (verification only)

- [ ] **Step 1: Full build**

Run: `cd orchestrator && go build ./...`
Expected: no errors

- [ ] **Step 2: Full vet**

Run: `cd orchestrator && go vet ./...`
Expected: no errors

- [ ] **Step 3: Full test suite**

Run: `cd orchestrator && go test ./... -count=1`
Expected: PASS across all packages (Docker Desktop must be running for DB-backed tests — check `docker info` first, start Docker Desktop if needed). If `internal/recommend` (or any single unrelated package) fails with a `testcontainers`/Docker provider panic, re-run that package alone before treating it as a real regression — this project has hit transient Docker-provider flakes under full-suite load before (see Phase 4).

- [ ] **Step 4: Sweep for any remaining `MalwareKey` references**

```bash
cd orchestrator && grep -rn "MalwareKey" --include="*.go" . | grep -v "MalwareKeyForTest"
```

Expected: no output (every real call site renamed to `NormalizeKey` in Task 1; `MalwareKeyForTest` is an intentionally-unrenamed test helper *name*, per Task 1 Step 4 — its body already calls `NormalizeKey`).

- [ ] **Step 5: Confirm the API still serves all three entity types with the new `sources` field**

```bash
cd orchestrator && grep -n "IntelligenceCampaigns\|IntelligenceMalware\|IntelligenceTools" internal/api/routes.go
```

Expected: all three routes still registered (this task didn't touch `internal/api` — this is a final sanity check that Task 1-5's model/store changes didn't require any handler changes, since `respond(w, campaigns)` etc. already just JSON-marshals whatever `List*` returns, and the new `Sources`/`Aliases` fields are additive to the struct).
