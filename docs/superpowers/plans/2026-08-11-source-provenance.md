# Source Provenance Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Preserve every threat-intel source's own raw, pre-merge assertions about an actor as a queryable per-source record, and surface them on the Threat Prioritization actor detail view — so a user can see exactly which source said what, instead of only the flattened first-arrival-wins merged row.

**Architecture:** `mergeActorsWithCanonicalData` already computes the union-find grouping that maps each raw input actor to its merged survivor — it just discards it. Expose that grouping through a new `MergeActorsWithProvenance`, keep `MergeActors` as a thin wrapper so no existing caller or test changes, hold the pre-merge list alive in `Scheduler.sync()`, and persist one `threat_actor_sources` row per (canonical actor, source). The API and UI then read that table directly.

**Tech Stack:** Go (`internal/connector`, `internal/api`, `internal/db`), Postgres via pgx, vanilla JS in `orchestrator/wwwroot/index.html`.

## Global Constraints

- Purely additive. `threat_actor_profiles`' merge policy (first-arrival-wins on non-merged fields) does not change; `upsertActorProfiles` is not modified.
- No change to `internal/threatpriority`'s scoring factors — they keep reading the single flattened `ActorProfile` exactly as today (including the `RelevanceFactor` unknown-vs-none fix, commit `e8d110a`).
- No new data fetched from any connector. Every persisted field is already fetched and already in memory during `Scheduler.sync()`.
- The existing `actor_merge_test.go` suite must stay green **unmodified** — no edits to any existing test in it.
- No OTX restructuring (sub-project #2) and no per-relationship `uses -> technique` evidence (sub-project #3).
- No fuzzy/similarity matching anywhere — this plan does not touch matching logic at all.

---

### Task 1: Expose the merge grouping via `MergeActorsWithProvenance`

**Files:**
- Modify: `orchestrator/internal/connector/actor_merge.go:24-76`
- Test: `orchestrator/internal/connector/actor_merge_test.go` (append only — no existing test edited)

**Interfaces:**
- Consumes: `ThreatActor` (`internal/connector/types.go:10-26`), `attackdata.GroupCanonicalTokenIndex() map[string]string`, `attackdata.GroupByID(string) *attackdata.Group`, `mergeActorGroup` / `resolveCanonicalGroupID` / `actorTokens` / `tokenUnionFind` (all unchanged in `actor_merge.go`).
- Produces: `func MergeActorsWithProvenance(actors []ThreatActor) ([]ThreatActor, [][]int)` — `groups[i]` holds the indices into the input `actors` slice that merged into `merged[i]`, index-aligned by construction. Consumed by Task 2's `Scheduler.sync()`. `MergeActors(actors []ThreatActor) []ThreatActor` keeps its exact current signature.

**Why the core is renamed rather than re-signatured:** four existing tests call `mergeActorsWithCanonicalData(...)` expecting a single return value. Changing its signature would force edits to them, violating the "existing suite stays green unmodified" constraint. Instead the real core becomes `mergeActorsWithCanonicalDataAndProvenance`, and `mergeActorsWithCanonicalData` stays as a 1-return wrapper.

- [ ] **Step 1: Write the failing tests**

Append to `orchestrator/internal/connector/actor_merge_test.go`:

```go
// TestMergeActorsWithProvenance_GroupsMapBackToRawIndices is the core
// contract this whole project rests on: for each merged survivor, we must
// be able to recover exactly which raw input actors (and therefore which
// sources) collapsed into it. groups[i] is index-aligned with merged[i].
func TestMergeActorsWithProvenance_GroupsMapBackToRawIndices(t *testing.T) {
	raw := []ThreatActor{
		{Name: "Wizard Spider", Source: "misp", Techniques: []TechniqueRef{{ID: "T1059.001"}}},
		{Name: "Sangria Tempest", Aliases: []string{"Wizard Spider"}, Source: "opencti", Techniques: []TechniqueRef{{ID: "T1566.001"}}},
	}
	merged, groups := MergeActorsWithProvenance(raw)
	if len(merged) != 1 {
		t.Fatalf("want 1 merged actor, got %d: %+v", len(merged), merged)
	}
	if len(groups) != len(merged) {
		t.Fatalf("groups len %d != merged len %d -- must be index-aligned", len(groups), len(merged))
	}
	if len(groups[0]) != 2 {
		t.Fatalf("groups[0] = %v, want both raw indices [0 1]", groups[0])
	}
	seen := map[int]bool{}
	for _, idx := range groups[0] {
		seen[idx] = true
	}
	if !seen[0] || !seen[1] {
		t.Errorf("groups[0] = %v, want it to contain both 0 and 1", groups[0])
	}
	// The survivor must be the first-arriving member of its own group.
	if merged[0].Name != raw[groups[0][0]].Name {
		t.Errorf("merged[0].Name = %q, want it to match raw[groups[0][0]].Name = %q", merged[0].Name, raw[groups[0][0]].Name)
	}
}

// TestMergeActorsWithProvenance_UnrelatedActorsEachGetOwnGroup proves the
// single-source case: two actors that share nothing produce two merged
// actors, each with a one-element group pointing at its own raw index.
func TestMergeActorsWithProvenance_UnrelatedActorsEachGetOwnGroup(t *testing.T) {
	raw := []ThreatActor{
		{Name: "APT28", Source: "misp", Techniques: []TechniqueRef{{ID: "T1059.001"}}},
		{Name: "APT29", Source: "opencti", Techniques: []TechniqueRef{{ID: "T1566.001"}}},
	}
	merged, groups := MergeActorsWithProvenance(raw)
	if len(merged) != 2 || len(groups) != 2 {
		t.Fatalf("merged=%d groups=%d, want 2 and 2", len(merged), len(groups))
	}
	for i := range merged {
		if len(groups[i]) != 1 {
			t.Fatalf("groups[%d] = %v, want exactly one raw index", i, groups[i])
		}
		if merged[i].Name != raw[groups[i][0]].Name {
			t.Errorf("merged[%d].Name = %q, want %q", i, merged[i].Name, raw[groups[i][0]].Name)
		}
	}
}

func TestMergeActorsWithProvenance_EmptyInput(t *testing.T) {
	merged, groups := MergeActorsWithProvenance(nil)
	if merged != nil || groups != nil {
		t.Fatalf("merged=%v groups=%v, want nil/nil for empty input", merged, groups)
	}
}

// TestMergeActorsWithCanonicalDataAndProvenance_CanonicalBridgeGroupsBothRawActors
// covers the case the embedded (currently empty) MITRE dataset can't
// exercise: two actors with ZERO direct token overlap, bridged only by both
// resolving to the same canonical G####, must still land in one group with
// both raw indices recoverable.
func TestMergeActorsWithCanonicalDataAndProvenance_CanonicalBridgeGroupsBothRawActors(t *testing.T) {
	canonicalIndex := map[string]string{"apt29": "G0016", "cozybear": "G0016"}
	noGroups := func(string) *attackdata.Group { return nil }
	raw := []ThreatActor{
		{Name: "APT29", Source: "misp", Techniques: []TechniqueRef{{ID: "T1078"}}},
		{Name: "Cozy Bear", Source: "opencti", Techniques: []TechniqueRef{{ID: "T1566.001"}}},
	}
	merged, groups := mergeActorsWithCanonicalDataAndProvenance(raw, canonicalIndex, noGroups)
	if len(merged) != 1 || len(groups) != 1 {
		t.Fatalf("merged=%d groups=%d, want 1 and 1", len(merged), len(groups))
	}
	if len(groups[0]) != 2 {
		t.Fatalf("groups[0] = %v, want both raw indices", groups[0])
	}
	if merged[0].CanonicalGroupID != "G0016" {
		t.Errorf("CanonicalGroupID = %q, want G0016", merged[0].CanonicalGroupID)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/connector/... -run 'TestMergeActorsWithProvenance|TestMergeActorsWithCanonicalDataAndProvenance' -v`
Expected: FAIL to compile — `undefined: MergeActorsWithProvenance` and `undefined: mergeActorsWithCanonicalDataAndProvenance`.

- [ ] **Step 3: Implement**

In `orchestrator/internal/connector/actor_merge.go`, replace lines 24-76 (from `func MergeActors` through the end of `mergeActorsWithCanonicalData`) with:

```go
func MergeActors(actors []ThreatActor) []ThreatActor {
	merged, _ := MergeActorsWithProvenance(actors)
	return merged
}

// MergeActorsWithProvenance is MergeActors plus the provenance grouping it
// otherwise discards: groups[i] holds the indices into the input actors
// slice that merged into merged[i], index-aligned by construction. Callers
// that only need the merged result use MergeActors; Scheduler.sync uses
// this to persist each source's own pre-merge record (see
// upsertActorSources and
// docs/superpowers/specs/2026-08-11-source-provenance-design.md).
func MergeActorsWithProvenance(actors []ThreatActor) ([]ThreatActor, [][]int) {
	return mergeActorsWithCanonicalDataAndProvenance(actors, attackdata.GroupCanonicalTokenIndex(), attackdata.GroupByID)
}

// mergeActorsWithCanonicalData is MergeActors' testable core -- the
// canonical-MITRE-data sources are passed in explicitly so tests can
// exercise the resolution/merge/enrichment logic against small fixture
// data without depending on the embedded MITRE dataset (which, in this
// repo, ships empty until someone runs the gen tool against a real STIX
// bundle -- see internal/reporting/attackdata/attack_groups.json).
func mergeActorsWithCanonicalData(actors []ThreatActor, canonicalIndex map[string]string, groupByID func(string) *attackdata.Group) []ThreatActor {
	merged, _ := mergeActorsWithCanonicalDataAndProvenance(actors, canonicalIndex, groupByID)
	return merged
}

// mergeActorsWithCanonicalDataAndProvenance is the real core: identical
// matching/merge/enrichment logic as before, but it also returns the
// union-find grouping it already computes internally. groups[i] lists the
// input indices that produced merged[i].
func mergeActorsWithCanonicalDataAndProvenance(actors []ThreatActor, canonicalIndex map[string]string, groupByID func(string) *attackdata.Group) ([]ThreatActor, [][]int) {
	if len(actors) == 0 {
		return nil, nil
	}

	uf := newTokenUnionFind()
	tokensByActor := make([][]string, len(actors))
	canonicalByActor := make([]string, len(actors)) // resolved G#### per actor, "" if unresolved
	for i, a := range actors {
		toks := actorTokens(a)
		canonicalByActor[i] = resolveCanonicalGroupID(toks, canonicalIndex)
		if canonicalByActor[i] != "" {
			// A synthetic token, namespaced so it can never collide with a
			// real name/alias token. Sharing it is what lets two actors
			// merge purely on MITRE's say-so, even with no direct token
			// overlap between their own fetched data.
			toks = append(toks, "canonical:"+canonicalByActor[i])
		}
		tokensByActor[i] = toks
		for j := 1; j < len(toks); j++ {
			uf.union(toks[0], toks[j])
		}
	}

	groupOf := make(map[string]int) // union-find root token -> index into groups
	var groups [][]int              // groups[g] = indices into actors, in original arrival order
	for i := range actors {
		root := uf.find(tokensByActor[i][0])
		g, ok := groupOf[root]
		if !ok {
			g = len(groups)
			groupOf[root] = g
			groups = append(groups, nil)
		}
		groups[g] = append(groups[g], i)
	}

	out := make([]ThreatActor, 0, len(groups))
	for _, idxs := range groups {
		out = append(out, mergeActorGroup(actors, idxs, canonicalByActor, groupByID))
	}
	return out, groups
}
```

The `MergeActors` doc comment (lines 11-23) stays exactly where it is, immediately above `func MergeActors`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go build ./... && go vet ./internal/connector/... && go test ./internal/connector/... -run 'TestMergeActors' -v`
Expected: `go build` succeeds. All 4 new tests PASS, and every pre-existing `TestMergeActors_*` test (12 of them, from the alias-matching and canonical-ID projects) still PASSes with no modification.

- [ ] **Step 5: Commit**

```bash
cd /c/Users/Administrator/Downloads/Audspect_Cloud
git add orchestrator/internal/connector/actor_merge.go orchestrator/internal/connector/actor_merge_test.go
git commit -m "feat(connector): expose merge provenance grouping via MergeActorsWithProvenance"
git push
```

---

### Task 2: `threat_actor_sources` table + persistence + sync wiring

**Files:**
- Modify: `orchestrator/internal/db/content_schema.go` (append to the `stmts` slice, currently ending at line 411 with the `vex_sweeps` ALTER)
- Modify: `orchestrator/internal/connector/scheduler.go:230-236` (sync wiring) and `:312-313` (stale-comment cleanup); add `upsertActorSources` after `upsertActorProfiles` (which ends at line 359)
- Test: `orchestrator/internal/connector/scheduler_test.go` (append only)

**Interfaces:**
- Consumes: `MergeActorsWithProvenance(actors []ThreatActor) ([]ThreatActor, [][]int)` (Task 1). `nonNilStrings(s []string) []string` (`scheduler.go:328`, unchanged — coalesces nil to empty so pgx doesn't write SQL NULL into a `NOT NULL text[]` column).
- Produces: the `threat_actor_sources` table (read by Task 3) and `func (s *Scheduler) upsertActorSources(rawActors, merged []ThreatActor, groups [][]int)`.

**Schema-ordering note:** the `REFERENCES threat_actor_profiles(name)` clause requires that table to already exist when `EnsureContentSchema` runs. It does — `content_schema.go:269-270` already runs `ALTER TABLE threat_actor_profiles ADD COLUMN ...` against it, which would fail otherwise.

**Stale-comment cleanup (in scope because it's in a file this task edits and it is actively wrong):** `scheduler.go:312-313` carries an orphaned two-line `MergeActors` doc comment left behind when `MergeActors` moved to `actor_merge.go` (commit `3e6d5e8`). It now sits atop `nonNilStrings`, and its description ("combines actors with the same name (case-insensitive)") is doubly stale — the function both moved and changed behavior. Delete those two lines.

- [ ] **Step 1: Write the failing tests**

Append to `orchestrator/internal/connector/scheduler_test.go`:

```go
// TestUpsertActorSources_TwoSourcesSameActorProduceTwoRows is the core of
// this project: MISP and OpenCTI describing the same real-world actor
// collapse into ONE threat_actor_profiles row (first-arrival-wins), but
// each must keep its OWN record here -- its own name, its own sectors, its
// own confidence -- so "why does Audspect believe this actor is relevant"
// is answerable per source.
func TestUpsertActorSources_TwoSourcesSameActorProduceTwoRows(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		s := &Scheduler{pool: pool}
		raw := []ThreatActor{
			{Name: "PROV-Wizard Spider", Source: "misp", SourceID: "evt-1",
				Sectors: []string{"financial services"}, Confidence: "high",
				Techniques: []TechniqueRef{{ID: "T1059.001"}, {ID: "T1566.001"}}},
			{Name: "PROV-Sangria Tempest", Source: "opencti", SourceID: "ta-9",
				Aliases: []string{"PROV-Wizard Spider"}, Confidence: "medium",
				Techniques: []TechniqueRef{{ID: "T1078"}}},
		}
		merged, groups := MergeActorsWithProvenance(raw)
		if len(merged) != 1 {
			t.Fatalf("fixture precondition: want the two actors to merge, got %d", len(merged))
		}
		// The FK requires the parent profile row first -- same ordering
		// sync() itself uses.
		s.upsertActorProfiles(merged)
		s.upsertActorSources(raw, merged, groups)

		rows, err := pool.Query(t.Context(),
			`SELECT source, source_id, name, sectors, confidence, technique_count
			   FROM threat_actor_sources WHERE actor_name = $1 ORDER BY source`, merged[0].Name)
		if err != nil {
			t.Fatalf("query: %v", err)
		}
		defer rows.Close()
		type row struct {
			source, sourceID, name, confidence string
			sectors                            []string
			techniqueCount                     int
		}
		var got []row
		for rows.Next() {
			var r row
			if err := rows.Scan(&r.source, &r.sourceID, &r.name, &r.sectors, &r.confidence, &r.techniqueCount); err != nil {
				t.Fatalf("scan: %v", err)
			}
			got = append(got, r)
		}
		if len(got) != 2 {
			t.Fatalf("got %d source rows, want 2 (one per contributing source): %+v", len(got), got)
		}
		// ORDER BY source -> misp, opencti
		if got[0].source != "misp" || got[0].name != "PROV-Wizard Spider" ||
			got[0].confidence != "high" || got[0].techniqueCount != 2 ||
			len(got[0].sectors) != 1 || got[0].sectors[0] != "financial services" {
			t.Errorf("misp row = %+v, want its OWN name/sectors/confidence/technique count", got[0])
		}
		if got[1].source != "opencti" || got[1].name != "PROV-Sangria Tempest" ||
			got[1].confidence != "medium" || got[1].techniqueCount != 1 ||
			len(got[1].sectors) != 0 {
			t.Errorf("opencti row = %+v, want its OWN name/confidence/technique count and empty sectors", got[1])
		}
	})
}

// TestUpsertActorSources_Idempotent proves a second sync with unchanged
// data updates in place rather than accumulating duplicate rows.
func TestUpsertActorSources_Idempotent(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		s := &Scheduler{pool: pool}
		raw := []ThreatActor{
			{Name: "PROV-IDEMPOTENT", Source: "misp", Confidence: "high", Techniques: []TechniqueRef{{ID: "T1059.001"}}},
		}
		merged, groups := MergeActorsWithProvenance(raw)
		s.upsertActorProfiles(merged)
		s.upsertActorSources(raw, merged, groups)
		s.upsertActorSources(raw, merged, groups)

		var count int
		if err := pool.QueryRow(t.Context(),
			`SELECT COUNT(*) FROM threat_actor_sources WHERE actor_name = $1`, "PROV-IDEMPOTENT").Scan(&count); err != nil {
			t.Fatalf("query: %v", err)
		}
		if count != 1 {
			t.Fatalf("row count = %d after two upserts, want 1", count)
		}
	})
}

// TestScheduler_SyncPersistsPerSourceProvenance exercises the real sync()
// path end to end -- proving the pre-merge list actually survives to
// upsertActorSources rather than being flattened away by MergeActors.
func TestScheduler_SyncPersistsPerSourceProvenance(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		s := NewScheduler([]Source{
			fakeSource{name: "misp", actors: []ThreatActor{{
				Name: "SYNC-PROV-ACTOR", Source: "misp", Sectors: []string{"government"},
				Confidence: "high", Techniques: []TechniqueRef{{ID: "T1059.001"}, {ID: "T1566.001"}},
			}}},
			fakeSource{name: "opencti", actors: []ThreatActor{{
				Name: "SYNC-PROV-ALIAS", Aliases: []string{"SYNC-PROV-ACTOR"}, Source: "opencti",
				Confidence: "medium", Techniques: []TechniqueRef{{ID: "T1078"}},
			}}},
		}, NewGenerator(t.TempDir(), nil, nil, nil), scenario.NewEngine(t.TempDir()), 24, pool, nil)

		s.sync()

		var sources []string
		rows, err := pool.Query(t.Context(),
			`SELECT source FROM threat_actor_sources WHERE actor_name = $1 ORDER BY source`, "SYNC-PROV-ACTOR")
		if err != nil {
			t.Fatalf("query: %v", err)
		}
		defer rows.Close()
		for rows.Next() {
			var src string
			if err := rows.Scan(&src); err != nil {
				t.Fatalf("scan: %v", err)
			}
			sources = append(sources, src)
		}
		if len(sources) != 2 || sources[0] != "misp" || sources[1] != "opencti" {
			t.Fatalf("sources = %v, want [misp opencti] -- both contributing sources preserved through sync()", sources)
		}
	})
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/connector/... -run 'TestUpsertActorSources|TestScheduler_SyncPersistsPerSourceProvenance' -v`
Expected: FAIL to compile — `s.upsertActorSources undefined`.

- [ ] **Step 3: Add the table**

In `orchestrator/internal/db/content_schema.go`, append to the `stmts` slice immediately after the `vex_sweeps` ALTER (line 411), before the closing `}`:

```go
		// threat_actor_sources: one row per (canonical actor, source),
		// preserving each source's OWN raw pre-merge assertions. MergeActors
		// flattens every source into a single first-arrival-wins
		// threat_actor_profiles row, which cannot answer "why does Audspect
		// believe this actor is relevant" by source. last_seen is
		// deliberately per-source here -- MISP's event timestamp, OpenCTI's
		// Modified timestamp and OTX's pulse timestamp mean different things
		// and must not overwrite each other. See
		// docs/superpowers/specs/2026-08-11-source-provenance-design.md.
		`CREATE TABLE IF NOT EXISTS threat_actor_sources (
			actor_name      text        NOT NULL REFERENCES threat_actor_profiles(name) ON DELETE CASCADE,
			source          text        NOT NULL,
			source_id       text        NOT NULL DEFAULT '',
			name            text        NOT NULL,
			aliases         text[]      NOT NULL DEFAULT '{}',
			sectors         text[]      NOT NULL DEFAULT '{}',
			regions         text[]      NOT NULL DEFAULT '{}',
			confidence      text        NOT NULL DEFAULT '',
			technique_count int         NOT NULL DEFAULT 0,
			last_seen       timestamptz,
			updated_at      timestamptz NOT NULL DEFAULT NOW(),
			PRIMARY KEY (actor_name, source)
		)`,
```

No separate index — the composite primary key already indexes `actor_name` as its leading column, which is the only lookup pattern (Task 3 queries `WHERE actor_name = $1`).

- [ ] **Step 4: Add `upsertActorSources` and wire it into `sync()`**

In `orchestrator/internal/connector/scheduler.go`, replace lines 230-236:

```go
	// Merge actors with the same name across sources — bundle floor + live
	// overlay compose here, since MergeActors unions their techniques.
	actors = MergeActors(actors)

	// Persist actor profiles (sectors/regions) for reporting's priority-score
	// weighting — see docs/superpowers/specs/2026-07-19-sp5-sector-region-weighting-design.md.
	s.upsertActorProfiles(actors)
```

with:

```go
	// Merge actors with the same name across sources — bundle floor + live
	// overlay compose here, since MergeActors unions their techniques.
	// rawActors keeps the pre-merge list alive: the merged result
	// deliberately flattens away each source's own assertions, which
	// upsertActorSources below persists separately.
	rawActors := actors
	merged, groups := MergeActorsWithProvenance(rawActors)
	actors = merged

	// Persist actor profiles (sectors/regions) for reporting's priority-score
	// weighting — see docs/superpowers/specs/2026-07-19-sp5-sector-region-weighting-design.md.
	s.upsertActorProfiles(actors)
	// Per-source provenance. MUST run after upsertActorProfiles -- these rows
	// carry a foreign key to threat_actor_profiles(name).
	s.upsertActorSources(rawActors, actors, groups)
```

Then add `upsertActorSources` immediately after `upsertActorProfiles`' closing brace (line 359):

```go

// upsertActorSources persists each source's OWN raw, pre-merge assertions
// about an actor -- one row per (canonical actor, source). rawActors is the
// combined pre-merge list exactly as fetched; merged[i] is the survivor
// that groups[i]'s raw actors collapsed into (see
// MergeActorsWithProvenance). Purely additive provenance:
// upsertActorProfiles' own first-arrival-wins merged row is written
// separately and is unaffected by anything here.
//
// Two raw actors from the SAME source merging into one canonical actor
// (e.g. two MISP events about the same group) collide on the
// (actor_name, source) key, so the later one wins -- this row answers
// "what does this source say about this actor", not "every record this
// source holds". Per-record granularity is sub-project #3's job.
//
// A single row failing is logged and skipped, never aborting the rest --
// same discipline upsertActorProfiles already applies. No-op when pool is
// nil (e.g. a test that never calls sync()).
func (s *Scheduler) upsertActorSources(rawActors, merged []ThreatActor, groups [][]int) {
	if s.pool == nil {
		return
	}
	ctx := context.Background()
	for gi, idxs := range groups {
		if gi >= len(merged) {
			continue // defensive: groups is index-aligned with merged by construction
		}
		actorName := merged[gi].Name
		for _, ri := range idxs {
			if ri >= len(rawActors) {
				continue
			}
			raw := rawActors[ri]
			if raw.Source == "" {
				continue // nothing to attribute this record to
			}
			var lastSeen *time.Time
			if !raw.LastSeen.IsZero() {
				t := raw.LastSeen
				lastSeen = &t
			}
			_, err := s.pool.Exec(ctx,
				`INSERT INTO threat_actor_sources
				   (actor_name, source, source_id, name, aliases, sectors, regions, confidence, technique_count, last_seen, updated_at)
				 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,NOW())
				 ON CONFLICT (actor_name, source) DO UPDATE SET
				   source_id = EXCLUDED.source_id, name = EXCLUDED.name,
				   aliases = EXCLUDED.aliases, sectors = EXCLUDED.sectors, regions = EXCLUDED.regions,
				   confidence = EXCLUDED.confidence, technique_count = EXCLUDED.technique_count,
				   last_seen = EXCLUDED.last_seen, updated_at = NOW()`,
				actorName, raw.Source, raw.SourceID, raw.Name,
				nonNilStrings(raw.Aliases), nonNilStrings(raw.Sectors), nonNilStrings(raw.Regions),
				raw.Confidence, len(raw.Techniques), lastSeen)
			if err != nil {
				log.Printf("[connector] upsert actor source %q/%q: %v", actorName, raw.Source, err)
			}
		}
	}
}
```

Finally, delete the stale orphaned comment at lines 312-313 (the two lines immediately above `// upsertActorProfiles persists each actor's...`):

```go
// MergeActors combines actors with the same name (case-insensitive) from
// different sources into one actor with the union of their techniques.
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd orchestrator && go build ./... && go vet ./internal/connector/... && go test ./internal/connector/... -run 'TestUpsertActor|TestScheduler_Sync' -v`
Expected: all 3 new tests PASS, plus every pre-existing `TestUpsertActorProfiles_*` and `TestScheduler_Sync*` test still PASSes unmodified.

Then the whole package: `cd orchestrator && go test ./internal/connector/...`
Expected: `ok github.com/audspect/bas/internal/connector`.

- [ ] **Step 6: Commit**

```bash
cd /c/Users/Administrator/Downloads/Audspect_Cloud
git add orchestrator/internal/db/content_schema.go orchestrator/internal/connector/scheduler.go orchestrator/internal/connector/scheduler_test.go
git commit -m "feat(connector): persist per-source actor provenance"
git push
```

---

### Task 3: Serve `sources` on the actor detail endpoint

**Files:**
- Modify: `orchestrator/internal/api/threatpriority_handlers.go` (imports; `threatPriorityActorDetail` at lines 104-113; `ThreatPriorityActorDetail` at lines 115-160)
- Test: `orchestrator/internal/api/threatpriority_handlers_test.go` (append only)

**Interfaces:**
- Consumes: the `threat_actor_sources` table (Task 2). `h.db *pgxpool.Pool` (`internal/api/handlers.go:68`).
- Produces: `type ActorSource struct` with JSON keys `source`, `sourceId`, `name`, `aliases`, `sectors`, `regions`, `confidence`, `techniqueCount`, `lastSeen` — read by Task 4's frontend as `d.sources`.

- [ ] **Step 1: Write the failing test**

Append to `orchestrator/internal/api/threatpriority_handlers_test.go`:

```go
func TestThreatPriorityActorDetail_ReturnsPerSourceProvenance(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		if _, err := pool.Exec(ctx,
			`INSERT INTO threat_actor_profiles (name, aliases, sectors, regions, source, confidence)
			 VALUES ('API-PROV-ACTOR','{}','{}','{}','misp','high')
			 ON CONFLICT (name) DO NOTHING`); err != nil {
			t.Fatalf("seed profile: %v", err)
		}
		if _, err := pool.Exec(ctx,
			`INSERT INTO threat_actor_sources (actor_name, source, source_id, name, aliases, sectors, regions, confidence, technique_count)
			 VALUES ('API-PROV-ACTOR','misp','evt-1','API-PROV-ACTOR','{}','{"financial services"}','{}','high',2),
			        ('API-PROV-ACTOR','opencti','ta-9','API-PROV-Tempest','{"API-PROV-ACTOR"}','{}','{}','medium',1)
			 ON CONFLICT (actor_name, source) DO NOTHING`); err != nil {
			t.Fatalf("seed sources: %v", err)
		}

		engine := scenario.NewEngine(t.TempDir())
		if err := engine.Load(); err != nil {
			t.Fatalf("engine.Load: %v", err)
		}
		pe := threatpriority.NewEngine(pool, engine, nil, nil)
		h := New(pool, ws.NewHub(), engine, "").WithThreatPriority(pe)

		req := httptest.NewRequest("GET", "/api/threat-priority/actors/API-PROV-ACTOR", nil)
		req = withURLParams(req, map[string]string{"name": "API-PROV-ACTOR"})
		w := httptest.NewRecorder()
		h.ThreatPriorityActorDetail(w, req)

		if w.Code != 200 {
			t.Fatalf("status = %d, body: %s", w.Code, w.Body.String())
		}
		var got struct {
			Sources []ActorSource `json:"sources"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(got.Sources) != 2 {
			t.Fatalf("sources = %+v, want 2 entries", got.Sources)
		}
		// ORDER BY source -> misp, opencti
		if got.Sources[0].Source != "misp" || got.Sources[0].Confidence != "high" ||
			len(got.Sources[0].Sectors) != 1 || got.Sources[0].Sectors[0] != "financial services" {
			t.Errorf("misp entry = %+v, want its own sectors/confidence", got.Sources[0])
		}
		if got.Sources[1].Source != "opencti" || got.Sources[1].Name != "API-PROV-Tempest" ||
			got.Sources[1].TechniqueCount != 1 {
			t.Errorf("opencti entry = %+v, want its OWN name (not the canonical one)", got.Sources[1])
		}
	})
}
```

Add `"context"` and `"encoding/json"` to that file's import block if not already present (it currently imports `net/http/httptest`, `strings`, `testing`, `pgxpool`, `scenario`, `threatpriority`, `ws`).

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/api/... -run TestThreatPriorityActorDetail_ReturnsPerSourceProvenance -v`
Expected: FAIL to compile — `undefined: ActorSource`.

- [ ] **Step 3: Implement**

In `orchestrator/internal/api/threatpriority_handlers.go`, change the import block to:

```go
import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/coverage"
	"github.com/audspect/bas/internal/reporting/attackdata"
	"github.com/audspect/bas/internal/threatpriority"
)
```

Add above `threatPriorityActorDetail` (line 104):

```go
// ActorSource is one source's own raw, pre-merge assertions about an actor
// -- what MISP/OpenCTI/OTX each individually said, before MergeActors
// flattened them into a single first-arrival-wins profile row. Aliases/
// Sectors/Regions are always non-nil so the UI can distinguish "this source
// reported none" from a missing field. See
// docs/superpowers/specs/2026-08-11-source-provenance-design.md.
type ActorSource struct {
	Source         string     `json:"source"`
	SourceID       string     `json:"sourceId,omitempty"`
	Name           string     `json:"name"`
	Aliases        []string   `json:"aliases"`
	Sectors        []string   `json:"sectors"`
	Regions        []string   `json:"regions"`
	Confidence     string     `json:"confidence,omitempty"`
	TechniqueCount int        `json:"techniqueCount"`
	LastSeen       *time.Time `json:"lastSeen,omitempty"`
}

// loadActorSources returns every source's own record for one canonical
// actor, source-ordered for stable rendering.
func loadActorSources(ctx context.Context, db *pgxpool.Pool, actorName string) ([]ActorSource, error) {
	if db == nil {
		return []ActorSource{}, nil
	}
	rows, err := db.Query(ctx,
		`SELECT source, source_id, name, aliases, sectors, regions, confidence, technique_count, last_seen
		   FROM threat_actor_sources WHERE actor_name = $1 ORDER BY source`, actorName)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ActorSource{}
	for rows.Next() {
		var a ActorSource
		if err := rows.Scan(&a.Source, &a.SourceID, &a.Name, &a.Aliases, &a.Sectors,
			&a.Regions, &a.Confidence, &a.TechniqueCount, &a.LastSeen); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}
```

Add the field to `threatPriorityActorDetail`:

```go
type threatPriorityActorDetail struct {
	threatpriority.ActorPriority
	History             []threatpriority.ActorPriorityHistory `json:"history"`
	UncoveredTechniques []string                              `json:"uncoveredTechniques"`
	TechniqueCoverage   []TechniqueCoverage                    `json:"techniqueCoverage"`
	Sources             []ActorSource                          `json:"sources"`
}
```

Update the nil-engine early return (line 119) to:

```go
		respond(w, threatPriorityActorDetail{UncoveredTechniques: []string{}, TechniqueCoverage: []TechniqueCoverage{}, Sources: []ActorSource{}})
```

And in the handler body, immediately after `techCoverage := buildTechniqueCoverage(...)` (line 155), add:

```go
	sources, err := loadActorSources(r.Context(), h.db, name)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
```

Then add `Sources: sources,` to the final `respond` composite literal.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go build ./... && go vet ./internal/api/... && go test ./internal/api/... -run 'TestThreatPriorityActor|TestBuildTechniqueCoverage' -v`
Expected: the new test PASSes, and all pre-existing `TestThreatPriorityActor*` / `TestBuildTechniqueCoverage_*` tests still PASS unmodified.

- [ ] **Step 5: Commit**

```bash
cd /c/Users/Administrator/Downloads/Audspect_Cloud
git add orchestrator/internal/api/threatpriority_handlers.go orchestrator/internal/api/threatpriority_handlers_test.go
git commit -m "feat(api): serve per-source provenance on actor detail"
git push
```

---

### Task 4: Sources card on the actor detail view

**Files:**
- Modify: `orchestrator/wwwroot/index.html` — static drawer markup at lines 3452-3460, and `renderThreatPriorityDetail` at lines 5470-5487

**Interfaces:**
- Consumes: `d.sources` (Task 3's `[]ActorSource`) on the existing `renderThreatPriorityDetail(d)` parameter. Pre-existing helpers reused as-is: `x()` (HTML-escape), `fmtDate()` (`index.html:14032`).
- Produces: no new interface — terminal, UI-facing step.

- [ ] **Step 1: Add the static card**

In `orchestrator/wwwroot/index.html`, insert a new card between the "Technique Coverage Breakdown" card and the "History" card. Current (lines 3452-3460):

```html
          <div class="card" style="margin-bottom:1rem;padding:1rem 1.2rem">
            <div class="card-title">Technique Coverage Breakdown</div>
            <div id="tp-detail-coverage" class="tiny"></div>
          </div>

          <div class="card" style="margin-bottom:1rem;padding:1rem 1.2rem">
            <div class="card-title">History</div>
            <div id="tp-detail-history" class="tiny"></div>
          </div>
```

Replace with:

```html
          <div class="card" style="margin-bottom:1rem;padding:1rem 1.2rem">
            <div class="card-title">Technique Coverage Breakdown</div>
            <div id="tp-detail-coverage" class="tiny"></div>
          </div>

          <div class="card" style="margin-bottom:1rem;padding:1rem 1.2rem">
            <div class="card-title">Sources</div>
            <div id="tp-detail-sources" class="tiny"></div>
          </div>

          <div class="card" style="margin-bottom:1rem;padding:1rem 1.2rem">
            <div class="card-title">History</div>
            <div id="tp-detail-history" class="tiny"></div>
          </div>
```

- [ ] **Step 2: Render the per-source cards**

In `renderThreatPriorityDetail`, insert immediately after the `tp-detail-coverage` block ends (after the `: '<span class="muted">No technique data.</span>';` line, currently line 5485) and before `var hist = (d.history || []);`:

```js

  var sources = (d.sources || []);
  document.getElementById('tp-detail-sources').innerHTML = sources.length
    ? '<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:0.75rem">' +
      sources.map(function(s) {
        // "Unknown" (never "None"): an empty field here means this source
        // never supplied it -- e.g. OpenCTI never reports sectors/regions,
        // MISP never reports aliases. Rendering it as "None" would read as
        // a positive assertion the source never made.
        var unknown = '<span class="muted">Unknown</span>';
        function list(arr) {
          return (arr && arr.length)
            ? arr.map(function(v) { return '<span class="tool-tag">' + x(v) + '</span>'; }).join(' ')
            : unknown;
        }
        function row(label, val) {
          return '<div style="display:flex;gap:0.5rem;padding:0.14rem 0">' +
            '<span style="min-width:5.5rem;color:var(--muted);flex-shrink:0">' + label + '</span>' +
            '<span style="flex:1">' + val + '</span></div>';
        }
        return '<div style="border:1px solid var(--border);border-radius:var(--radius);padding:0.6rem 0.75rem">' +
          '<div style="font-weight:700;text-transform:uppercase;letter-spacing:.05em;color:var(--accent);margin-bottom:0.4rem">' + x(s.source) + '</div>' +
          row('Name', x(s.name)) +
          row('Aliases', list(s.aliases)) +
          row('Sectors', list(s.sectors)) +
          row('Regions', list(s.regions)) +
          row('Confidence', s.confidence ? x(s.confidence) : unknown) +
          row('Techniques', x(s.techniqueCount)) +
          row('Last seen', s.lastSeen ? x(fmtDate(s.lastSeen)) : unknown) +
          '</div>';
      }).join('') + '</div>'
    : '<span class="muted">No per-source records yet — populated by the next threat-intel sync.</span>';
```

- [ ] **Step 3: Verify manually**

This file has no automated frontend test suite (consistent with the rest of the codebase and every prior UI step this session). Verify by hand if a dev instance is reachable: open Threat Prioritization, click into an actor, confirm the new "Sources" card renders one block per contributing source with that source's own values, and that a field no source supplied shows "Unknown" rather than "None" or an empty gap. If no dev instance is reachable in this environment, say so explicitly rather than claiming it was checked, and add it to the standing Pending Manual QA Backlog.

- [ ] **Step 4: Commit**

```bash
cd /c/Users/Administrator/Downloads/Audspect_Cloud
git add orchestrator/wwwroot/index.html
git commit -m "feat(ui): show per-source provenance on actor detail"
git push
```

---

## Self-Review Notes

- **Spec coverage:** Data model (`threat_actor_sources`, exact columns + per-source `last_seen`) — Task 2 Step 3. "Nothing new is fetched" (`rawActors` captured before the merge overwrites it) — Task 2 Step 4. The wiring problem (`MergeActorsWithProvenance`, `MergeActors` unchanged as a wrapper) — Task 1. Persistence (`upsertActorSources`, keyed `(merged[i].Name, rawActors[j].Source)`, called right after `upsertActorProfiles`) — Task 2. API (`sources []ActorSource` on the detail response) — Task 3. UI (Sources card on the actor detail view) — Task 4. All four spec test cases have a named test: provenance grouping (Task 1, 4 tests incl. the canonical-bridge fixture case), two-sources-two-rows + idempotency (Task 2), API shape (Task 3), and the "existing suites unmodified" regression is enforced by every task's Step 4/5 running the pre-existing tests alongside the new ones.
- **Deviations from the spec, both deliberate and flagged:** (1) the core function is *renamed* to `mergeActorsWithCanonicalDataAndProvenance` with `mergeActorsWithCanonicalData` kept as a 1-return wrapper, rather than re-signaturing it — required to honor the spec's own "existing `actor_merge_test.go` stays green unmodified" constraint, since 4 existing tests call it expecting one return value. (2) `ON DELETE CASCADE` added to the FK, which the spec's SQL didn't specify — these rows are pure derived provenance, so cascading is the only sane behavior if a profile row is ever deleted; nothing deletes from `threat_actor_profiles` today, so this changes no current behavior. (3) One stale two-line comment deleted from `scheduler.go:312-313` (orphaned `MergeActors` docs, left behind by commit `3e6d5e8`, now misattached to `nonNilStrings` and describing behavior that is twice wrong) — in scope because it's in a file this plan edits and is actively misleading.
- **Placeholder scan:** No TBD/TODO; every step has literal, runnable code and exact commands. Task 4 Step 3's manual-verification framing is an honest limitation statement (no frontend test suite exists in this codebase), matching the pattern used for every prior UI task this session.
- **Type consistency:** `MergeActorsWithProvenance(actors []ThreatActor) ([]ThreatActor, [][]int)` — identical in Task 1's definition, Task 1's tests, and Task 2's `sync()` call site. `upsertActorSources(rawActors, merged []ThreatActor, groups [][]int)` — identical in Task 2's definition and all three of its tests. `ActorSource`'s JSON keys (`source`/`sourceId`/`name`/`aliases`/`sectors`/`regions`/`confidence`/`techniqueCount`/`lastSeen`) match exactly what Task 4's JS reads (`s.source`, `s.name`, `s.aliases`, `s.sectors`, `s.regions`, `s.confidence`, `s.techniqueCount`, `s.lastSeen`). Column names are identical across Task 2's `CREATE TABLE`, Task 2's `INSERT`, Task 2's test queries, and Task 3's `SELECT`.
