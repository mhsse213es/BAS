# Canonical MITRE ATT&CK Actor Identity Layer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give `MergeActors` a second, MITRE-authoritative identity signal — a canonical ATT&CK Group-ID (`G####`) resolved from each actor's name/aliases — so actors merge across sources even with zero direct alias-token overlap, while never forcing an identity onto an actor MITRE's data can't confidently resolve.

**Architecture:** A build-time-distilled MITRE group dataset (`G####` + `x_mitre_aliases`, same STIX-bundle-to-JSON pipeline as technique enrichment) feeds a new `attackdata.GroupCanonicalTokenIndex()`. `actor_merge.go` (from the prior alias-matching project) gets a resolution pass that checks each actor's tokens against that index before running its existing union-find, adding a synthetic bridging token on a clean single-group match. The resolved `G####` is persisted on the actor profile and threaded through to the Threat Prioritization API and UI.

**Tech Stack:** Go, standard library only for the new logic (`encoding/json`, `strings`, `sort`, `sync`), existing Postgres/pgx persistence layer, existing embedded-JSON pattern (`//go:embed`) for offline/air-gapped data, vanilla JS in `orchestrator/wwwroot/index.html`.

## Global Constraints

- Exact-match only, everywhere. Resolving an actor's tokens against MITRE's dataset is normalized-string equality (`actorKey`'s existing normalization: lowercase, strip spaces and hyphens) — never fuzzy/similarity matching.
- No live/runtime fetch of MITRE data. The product ships air-gapped; the group dataset is produced by the same build-time distillation step as technique enrichment (a manually-fetched, pinned STIX bundle run through the `gen` tool).
- No changes to `attackdata.GroupTechniqueIndex()` or any of its 20 existing consumers — this plan adds a separate, ID-keyed index alongside it.
- No change to `actor_merge.go`'s core union-find mechanics (`tokenUnionFind`, `newTokenUnionFind`, `find`, `union` from the prior project) — only extends the resolution/merge-policy logic around it.
- No forced identity on ambiguous or unmatched actors, at either the per-actor level (an actor's own tokens spanning two distinct MITRE groups) or the merged-group level (members that individually resolved to conflicting IDs).
- **Operational note, not a task in this plan:** `attack_groups.json` ships as an empty placeholder (`[]`) because no raw MITRE STIX bundle is available in this environment to distill from. Every piece of code in this plan is built and tested against that reality (via dependency-injected fixture data in unit tests) — but the *real* canonical-ID bridging behavior stays dormant in production until someone fetches the pinned bundle and re-runs the extended `gen` tool, exactly as `attack_enrichment.json` itself was originally produced. This is called out explicitly at the point it matters (Task 1) rather than silently glossed over.

---

### Task 1: Extract canonical Group-ID + aliases in the `gen` tool

**Files:**
- Modify: `orchestrator/internal/reporting/attackdata/gen/main.go`
- Test: `orchestrator/internal/reporting/attackdata/gen/main_test.go`

**Interfaces:**
- Consumes: `stixObj` (existing type in this file, gains one new field this task).
- Produces: `type Group struct { ID, Name string; Aliases []string }` and `func parseGroups(objects []stixObj) []Group` — both used by Task 2 (which defines the identically-shaped `attackdata.Group` that this task's JSON output must deserialize into) and by `main()`'s own new output-writing step, added in this task.

- [ ] **Step 1: Write the failing test for `parseGroups`**

Add to `orchestrator/internal/reporting/attackdata/gen/main_test.go` (add `"encoding/json"` to the existing `import` block first):

```go
func TestParseGroups(t *testing.T) {
	raw := `[
		{"type":"intrusion-set","name":"Wizard Spider","x_mitre_aliases":["Sangria Tempest","UNC1878"],
		 "external_references":[{"source_name":"mitre-attack","external_id":"G0102"}]},
		{"type":"intrusion-set","name":"Revoked Group","revoked":true,
		 "external_references":[{"source_name":"mitre-attack","external_id":"G9998"}]},
		{"type":"intrusion-set","name":"Deprecated Group","x_mitre_deprecated":true,
		 "external_references":[{"source_name":"mitre-attack","external_id":"G9997"}]},
		{"type":"intrusion-set","name":"No External ID Group"},
		{"type":"malware","name":"Some Malware",
		 "external_references":[{"source_name":"mitre-attack","external_id":"S0001"}]}
	]`
	var objects []stixObj
	if err := json.Unmarshal([]byte(raw), &objects); err != nil {
		t.Fatalf("unmarshal fixture: %v", err)
	}

	groups := parseGroups(objects)
	if len(groups) != 1 {
		t.Fatalf("want 1 group (revoked/deprecated/no-external-id/non-intrusion-set excluded), got %d: %+v", len(groups), groups)
	}
	g := groups[0]
	if g.ID != "G0102" || g.Name != "Wizard Spider" {
		t.Fatalf("got %+v, want ID=G0102 Name=Wizard Spider", g)
	}
	want := []string{"Sangria Tempest", "UNC1878"}
	if len(g.Aliases) != len(want) {
		t.Fatalf("Aliases = %v, want %v", g.Aliases, want)
	}
	for i, a := range want {
		if g.Aliases[i] != a {
			t.Errorf("Aliases[%d] = %q, want %q", i, g.Aliases[i], a)
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/reporting/attackdata/gen/... -run TestParseGroups -v`
Expected: FAIL — `parseGroups` (and `Group`, and `stixObj.Aliases`) don't exist yet: `undefined: parseGroups`.

- [ ] **Step 3: Implement `Group`, the `Aliases` field, and `parseGroups`**

In `orchestrator/internal/reporting/attackdata/gen/main.go`, add `Aliases` to `stixObj` (insert after the existing `DataSources` field, before `ExternalRefs`):

```go
	DataSources         []string `json:"x_mitre_data_sources"`
	Aliases             []string `json:"x_mitre_aliases"`
	ExternalRefs        []struct {
```

Add the `Group` type right after the existing `bundle` type (after line 118 `type bundle struct { ... }`):

```go
// Group is one MITRE ATT&CK intrusion-set (threat-actor group), keyed by
// its canonical external ID (G####). Output schema -- must match
// attackdata.Group's json tags.
type Group struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Aliases []string `json:"aliases,omitempty"`
}
```

Add `parseGroups` after `main()` (right after its closing brace, before `isoDate`):

```go
// parseGroups extracts canonical MITRE Group-ID + alias data from every
// intrusion-set object in a STIX bundle. Revoked/deprecated groups are
// excluded, mirroring the existing attack-pattern (technique) filter.
// Groups with no mitre-attack external_references entry (no G#### id) are
// also excluded -- they can never be used as a canonical merge key.
func parseGroups(objects []stixObj) []Group {
	var out []Group
	for _, o := range objects {
		if o.Type != "intrusion-set" {
			continue
		}
		if o.Revoked || o.Deprecated {
			continue
		}
		id := ""
		for _, r := range o.ExternalRefs {
			if r.SourceName == "mitre-attack" && r.ExternalID != "" {
				id = r.ExternalID
			}
		}
		if id == "" {
			continue
		}
		out = append(out, Group{ID: id, Name: o.Name, Aliases: dedupeSort(o.Aliases)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
```

Wire it into `main()` — add this right after the existing `fmt.Printf("wrote %d techniques to %s (%d bytes)\n", ...)` line, still inside `main()`, before its closing brace:

```go
	groups := parseGroups(b.Objects)
	groupsOut, err := json.MarshalIndent(groups, "", " ")
	must(err)
	groupsPath := filepath.Join(filepath.Dir(outPath), "attack_groups.json")
	must(os.WriteFile(groupsPath, groupsOut, 0o644))
	fmt.Printf("wrote %d groups to %s (%d bytes)\n", len(groups), groupsPath, len(groupsOut))
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd orchestrator && go test ./internal/reporting/attackdata/gen/... -v`
Expected: PASS — `TestParseGroups` and all pre-existing tests in this package (`TestIsoDate`, `TestCountSigma`, `TestLoadD3fend`) still pass.

- [ ] **Step 5: Commit**

```bash
cd orchestrator
git add internal/reporting/attackdata/gen/main.go internal/reporting/attackdata/gen/main_test.go
git commit -m "feat(attackdata/gen): extract canonical MITRE Group-ID + aliases"
```

---

### Task 2: `attackdata` canonical-group accessor layer

**Files:**
- Create: `orchestrator/internal/reporting/attackdata/attack_groups.json` (placeholder — see Global Constraints)
- Modify: `orchestrator/internal/reporting/attackdata/attackdata.go`
- Test: `orchestrator/internal/reporting/attackdata/attackdata_test.go`

**Interfaces:**
- Consumes: nothing from Task 1 directly at compile time (this is a separate Go package that only needs to agree on JSON shape with Task 1's `Group`/`parseGroups` output — verified structurally, not via a shared type).
- Produces: `type Group struct { ID, Name string; Aliases []string }`, `func GroupByID(id string) *Group`, `func GroupCanonicalTokenIndex() map[string]string`, and the unexported `func buildGroupCanonicalTokenIndex(gs []Group) map[string]string` — all consumed by Task 4 (`internal/connector/actor_merge.go`, already importing this package via `otx.go`'s existing `attackdata.GroupTechniqueIndex()` usage, so no new import-cycle risk).

- [ ] **Step 1: Create the placeholder embedded file**

Create `orchestrator/internal/reporting/attackdata/attack_groups.json`:

```json
[]
```

- [ ] **Step 2: Write the failing tests**

Add to `orchestrator/internal/reporting/attackdata/attackdata_test.go`:

```go
func TestBuildGroupCanonicalTokenIndex_ResolvesNameAndAliases(t *testing.T) {
	idx := buildGroupCanonicalTokenIndex([]Group{
		{ID: "G0016", Name: "APT29", Aliases: []string{"Cozy Bear", "The Dukes"}},
	})
	for _, tok := range []string{"apt29", "cozybear", "thedukes"} {
		if idx[tok] != "G0016" {
			t.Errorf("idx[%q] = %q, want G0016", tok, idx[tok])
		}
	}
}

// A token MITRE's own data lists under two different groups must resolve
// to nothing -- picking either arbitrarily would risk a false merge.
func TestBuildGroupCanonicalTokenIndex_AmbiguousTokenExcluded(t *testing.T) {
	idx := buildGroupCanonicalTokenIndex([]Group{
		{ID: "G0001", Name: "Group One", Aliases: []string{"Shared"}},
		{ID: "G0002", Name: "Group Two", Aliases: []string{"Shared"}},
	})
	if _, ok := idx["shared"]; ok {
		t.Errorf("ambiguous token %q should be excluded, got %q", "shared", idx["shared"])
	}
	if idx["groupone"] != "G0001" || idx["grouptwo"] != "G0002" {
		t.Errorf("unambiguous tokens should still resolve: %+v", idx)
	}
}

func TestGroupByID_UnknownReturnsNil(t *testing.T) {
	if g := GroupByID("G9999999"); g != nil {
		t.Errorf("GroupByID(unknown) = %+v, want nil", g)
	}
}

// The index is built once (sync.Once) and cached -- repeated calls must
// return consistent data, not silently recompute or drift.
func TestGroupCanonicalTokenIndex_Idempotent(t *testing.T) {
	first := GroupCanonicalTokenIndex()
	second := GroupCanonicalTokenIndex()
	if len(first) != len(second) {
		t.Fatalf("token counts differ across calls: %d vs %d", len(first), len(second))
	}
}
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/reporting/attackdata/... -run 'TestBuildGroupCanonicalTokenIndex|TestGroupByID|TestGroupCanonicalTokenIndex' -v`
Expected: FAIL to compile — `Group`, `buildGroupCanonicalTokenIndex`, `GroupByID`, `GroupCanonicalTokenIndex` don't exist yet.

- [ ] **Step 4: Implement the accessor layer**

In `orchestrator/internal/reporting/attackdata/attackdata.go`, add the embed directive right after the existing three (after `var rawSynonyms []byte`):

```go
//go:embed attack_groups.json
var rawGroups []byte
```

Add the `Group` type right after the existing `D3fendCM` type definition (after its closing brace, before `// Enrichment is...`):

```go
// Group is one MITRE ATT&CK intrusion-set (threat-actor group), keyed by
// its canonical external ID (G####). Authoritative -- distilled from the
// same STIX bundle as technique enrichment, by the same gen tool. See
// docs/superpowers/specs/2026-08-11-canonical-mitre-actor-identity-design.md.
type Group struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Aliases []string `json:"aliases,omitempty"`
}
```

Add the loading state, accessors, and pure index builder at the end of the file (after the existing `normalize` function):

```go
var (
	groupsOnce sync.Once
	groups     []Group
)

func loadGroups() {
	_ = json.Unmarshal(rawGroups, &groups) // malformed/missing -> groups stays nil, callers see an empty dataset
}

// GroupByID returns the canonical MITRE group for an ATT&CK G#### id, or
// nil if unknown. Linear scan -- the embedded dataset is on the order of a
// few hundred groups at most, not a hot path.
func GroupByID(id string) *Group {
	groupsOnce.Do(loadGroups)
	for i := range groups {
		if groups[i].ID == id {
			return &groups[i]
		}
	}
	return nil
}

var (
	groupTokenIdxOnce sync.Once
	groupTokenIdx     map[string]string
)

// GroupCanonicalTokenIndex returns normalized-token -> G#### for every
// group name and alias in the embedded MITRE dataset. A token that maps to
// more than one distinct G#### in MITRE's own data is deliberately
// excluded (mapped to nothing) -- an ambiguous token must never resolve.
// Computed once (sync.Once) and cached; safe for concurrent reads.
func GroupCanonicalTokenIndex() map[string]string {
	groupsOnce.Do(loadGroups)
	groupTokenIdxOnce.Do(func() {
		groupTokenIdx = buildGroupCanonicalTokenIndex(groups)
	})
	return groupTokenIdx
}

// buildGroupCanonicalTokenIndex is the pure core of GroupCanonicalTokenIndex,
// kept separate so tests can exercise the ambiguous-token-exclusion logic
// against small fixture data without depending on the embedded dataset.
func buildGroupCanonicalTokenIndex(gs []Group) map[string]string {
	tokenToIDs := map[string]map[string]bool{}
	add := func(token, id string) {
		if token == "" {
			return
		}
		if tokenToIDs[token] == nil {
			tokenToIDs[token] = map[string]bool{}
		}
		tokenToIDs[token][id] = true
	}
	for _, g := range gs {
		if g.ID == "" {
			continue
		}
		add(normalizeGroupToken(g.Name), g.ID)
		for _, alias := range g.Aliases {
			add(normalizeGroupToken(alias), g.ID)
		}
	}
	idx := make(map[string]string, len(tokenToIDs))
	for token, ids := range tokenToIDs {
		if len(ids) != 1 {
			continue
		}
		for id := range ids {
			idx[token] = id
		}
	}
	return idx
}

// normalizeGroupToken applies the same normalization internal/connector's
// actorKey uses (lowercase, strip spaces and hyphens) so tokens compare
// equal across packages. Duplicated rather than shared because attackdata
// must not import connector (connector already imports attackdata).
func normalizeGroupToken(s string) string {
	return strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(s, " ", ""), "-", ""))
}
```

No new imports needed — `encoding/json`, `strings`, and `sync` are already imported in this file.

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/reporting/attackdata/... -v`
Expected: PASS — the 4 new tests plus every pre-existing test in the package (`TestLookupAuthoritative`, `TestGroupTechniqueIndex_*`, etc. — all untouched by this change).

- [ ] **Step 6: Commit**

```bash
cd orchestrator
git add internal/reporting/attackdata/attack_groups.json internal/reporting/attackdata/attackdata.go internal/reporting/attackdata/attackdata_test.go
git commit -m "feat(attackdata): add canonical MITRE Group-ID token index"
```

---

### Task 3: Persist `CanonicalGroupID` on the actor profile

**Files:**
- Modify: `orchestrator/internal/db/content_schema.go`
- Modify: `orchestrator/internal/connector/types.go`
- Modify: `orchestrator/internal/connector/scheduler.go` (`upsertActorProfiles`, currently lines 335-358)
- Test: `orchestrator/internal/connector/scheduler_test.go`

**Interfaces:**
- Consumes: nothing new from Tasks 1-2.
- Produces: `ThreatActor.CanonicalGroupID string` (consumed by Task 4's merge logic, which sets it, and by Task 5's read path) and the `threat_actor_profiles.canonical_group_id` column (consumed by Task 5's `SELECT`s).

- [ ] **Step 1: Write the failing test**

Add to `orchestrator/internal/connector/scheduler_test.go` (mirrors the existing `TestUpsertActorProfiles_PersistsConfidence`):

```go
func TestUpsertActorProfiles_PersistsCanonicalGroupID(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		s := &Scheduler{pool: pool}
		s.upsertActorProfiles([]ThreatActor{{
			Name: "APT-CANONICAL-TEST", CanonicalGroupID: "G0016",
			Aliases: []string{}, Sectors: []string{}, Regions: []string{},
		}})

		var canonicalGroupID string
		err := pool.QueryRow(t.Context(),
			`SELECT canonical_group_id FROM threat_actor_profiles WHERE name=$1`, "APT-CANONICAL-TEST").Scan(&canonicalGroupID)
		if err != nil {
			t.Fatalf("query: %v", err)
		}
		if canonicalGroupID != "G0016" {
			t.Fatalf("canonical_group_id = %q, want %q", canonicalGroupID, "G0016")
		}
	})
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/connector/... -run TestUpsertActorProfiles_PersistsCanonicalGroupID -v`
Expected: FAIL to compile — `ThreatActor` has no field `CanonicalGroupID`.

- [ ] **Step 3: Add the migration, the struct field, and the upsert column**

In `orchestrator/internal/db/content_schema.go`, add a line right after the existing `confidence` migration (after line 269):

```go
		`ALTER TABLE threat_actor_profiles ADD COLUMN IF NOT EXISTS confidence text NOT NULL DEFAULT ''`,
		`ALTER TABLE threat_actor_profiles ADD COLUMN IF NOT EXISTS canonical_group_id text NOT NULL DEFAULT ''`,
```

In `orchestrator/internal/connector/types.go`, add the field to `ThreatActor` (after `Confidence`):

```go
	Confidence  string         `json:"confidence,omitempty"` // "high" | "medium" | "low"
	// CanonicalGroupID is the resolved MITRE ATT&CK Group-ID (G####, via
	// attackdata.GroupByID), or "" if MergeActors couldn't confidently
	// resolve one. See
	// docs/superpowers/specs/2026-08-11-canonical-mitre-actor-identity-design.md.
	CanonicalGroupID string `json:"canonical_group_id,omitempty"`
```

In `orchestrator/internal/connector/scheduler.go`, replace `upsertActorProfiles`'s body (currently lines 335-358) with:

```go
func (s *Scheduler) upsertActorProfiles(actors []ThreatActor) {
	if s.pool == nil {
		return
	}
	ctx := context.Background()
	for _, a := range actors {
		var lastSeen *time.Time
		if !a.LastSeen.IsZero() {
			t := a.LastSeen
			lastSeen = &t
		}
		_, err := s.pool.Exec(ctx,
			`INSERT INTO threat_actor_profiles (name, aliases, sectors, regions, source, last_seen, confidence, canonical_group_id, updated_at)
			 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,NOW())
			 ON CONFLICT (name) DO UPDATE SET
			   aliases = EXCLUDED.aliases, sectors = EXCLUDED.sectors, regions = EXCLUDED.regions,
			   source = EXCLUDED.source, last_seen = EXCLUDED.last_seen, confidence = EXCLUDED.confidence,
			   canonical_group_id = EXCLUDED.canonical_group_id,
			   updated_at = NOW()`,
			a.Name, nonNilStrings(a.Aliases), nonNilStrings(a.Sectors), nonNilStrings(a.Regions), a.Source, lastSeen, a.Confidence, a.CanonicalGroupID)
		if err != nil {
			log.Printf("[connector] upsert actor profile %q: %v", a.Name, err)
		}
	}
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd orchestrator && go test ./internal/connector/... -run 'TestUpsertActorProfiles' -v`
Expected: PASS for `TestUpsertActorProfiles_PersistsCanonicalGroupID`, `TestUpsertActorProfiles_PersistsConfidence`, and `TestUpsertActorProfiles_NilAliasesSectorsRegions_StillPersists` (unaffected).

- [ ] **Step 5: Commit**

```bash
cd orchestrator
git add internal/db/content_schema.go internal/connector/types.go internal/connector/scheduler.go internal/connector/scheduler_test.go
git commit -m "feat(connector): persist canonical MITRE Group-ID on actor profiles"
```

---

### Task 4: Canonical-ID resolution + active enrichment in `actor_merge.go`

**Files:**
- Modify: `orchestrator/internal/connector/actor_merge.go` (full current content shown below — this task rewrites it)
- Test: `orchestrator/internal/connector/actor_merge_test.go`

**Interfaces:**
- Consumes: `attackdata.Group`, `attackdata.GroupByID(id string) *attackdata.Group`, `attackdata.GroupCanonicalTokenIndex() map[string]string` (Task 2). `ThreatActor.CanonicalGroupID` (Task 3). `tokenUnionFind`/`newTokenUnionFind`/`find`/`union` (unchanged, prior project). `mergeTechniques` (`internal/connector/misp.go`, unchanged).
- Produces: `func MergeActors(actors []ThreatActor) []ThreatActor` (signature unchanged — callers in `scheduler.go`/`build_bundle.go` unaffected) and the new testable core `func mergeActorsWithCanonicalData(actors []ThreatActor, canonicalIndex map[string]string, groupByID func(string) *attackdata.Group) []ThreatActor`, used directly by this task's own tests.

This is one task: the resolution pass, the merge-policy consensus/conflict logic, and active enrichment are not independently reviewable — a resolution pass that never feeds the merge policy, or a merge policy with no way to get resolved IDs, isn't a coherent partial state.

- [ ] **Step 1: Write the failing tests**

Add to `orchestrator/internal/connector/actor_merge_test.go` (add `"github.com/audspect/bas/internal/reporting/attackdata"` to a new `import` block at the top of the file — it currently has none beyond `"testing"`, so add:
```go
import (
	"testing"

	"github.com/audspect/bas/internal/reporting/attackdata"
)
```
):

```go
// TestMergeActors_BridgesViaCanonicalMITREGroupID_ZeroDirectOverlap is the
// core scenario this project exists for: two actors with NO shared
// name/alias token at all still merge, because MITRE's own data
// independently resolves both to the same canonical group.
func TestMergeActors_BridgesViaCanonicalMITREGroupID_ZeroDirectOverlap(t *testing.T) {
	canonicalIndex := map[string]string{
		"apt29":    "G0016",
		"cozybear": "G0016",
	}
	noGroups := func(string) *attackdata.Group { return nil }
	merged := mergeActorsWithCanonicalData([]ThreatActor{
		{Name: "APT29", Source: "misp", Techniques: []TechniqueRef{{ID: "T1078"}}},
		{Name: "Cozy Bear", Source: "opencti", Techniques: []TechniqueRef{{ID: "T1566.001"}}},
	}, canonicalIndex, noGroups)
	if len(merged) != 1 {
		t.Fatalf("want 1 merged actor (bridged via canonical MITRE group ID, zero direct token overlap), got %d: %+v", len(merged), merged)
	}
	if merged[0].CanonicalGroupID != "G0016" {
		t.Errorf("CanonicalGroupID = %q, want G0016", merged[0].CanonicalGroupID)
	}
	if len(merged[0].Techniques) != 2 {
		t.Fatalf("want 2 unioned techniques, got %d", len(merged[0].Techniques))
	}
}

// TestMergeActors_ActorTokensSpanTwoDistinctMITREGroupsStaysUnresolved
// guards the per-actor ambiguity case: an actor's own name resolves to one
// MITRE group and its own alias resolves to a DIFFERENT one. Never force a
// pick.
func TestMergeActors_ActorTokensSpanTwoDistinctMITREGroupsStaysUnresolved(t *testing.T) {
	canonicalIndex := map[string]string{
		"apt29":  "G0016",
		"sofacy": "G0007",
	}
	noGroups := func(string) *attackdata.Group { return nil }
	merged := mergeActorsWithCanonicalData([]ThreatActor{
		{Name: "APT29", Aliases: []string{"Sofacy"}, Source: "misp", Techniques: []TechniqueRef{{ID: "T1078"}}},
	}, canonicalIndex, noGroups)
	if len(merged) != 1 {
		t.Fatalf("want 1 actor (nothing else to merge with), got %d", len(merged))
	}
	if merged[0].CanonicalGroupID != "" {
		t.Errorf("CanonicalGroupID = %q, want empty -- actor's own tokens span two distinct MITRE groups, must not force one", merged[0].CanonicalGroupID)
	}
}

// TestMergeActors_MergedGroupWithConflictingCanonicalIDsStaysUnresolved
// guards the merged-group ambiguity case: two actors merge via a direct
// alias-token match, but MITRE's own data disagrees about which group they
// belong to. The survivor must not arbitrarily pick one.
func TestMergeActors_MergedGroupWithConflictingCanonicalIDsStaysUnresolved(t *testing.T) {
	canonicalIndex := map[string]string{
		"actora": "G0001",
		"actorb": "G0002",
	}
	noGroups := func(string) *attackdata.Group { return nil }
	merged := mergeActorsWithCanonicalData([]ThreatActor{
		{Name: "Actor A", Aliases: []string{"Shared Alias"}, Source: "misp", Techniques: []TechniqueRef{{ID: "T1001"}}},
		{Name: "Actor B", Aliases: []string{"Shared Alias"}, Source: "opencti", Techniques: []TechniqueRef{{ID: "T1002"}}},
	}, canonicalIndex, noGroups)
	if len(merged) != 1 {
		t.Fatalf("want 1 merged actor (direct alias-token overlap on 'Shared Alias'), got %d: %+v", len(merged), merged)
	}
	if merged[0].CanonicalGroupID != "" {
		t.Errorf("CanonicalGroupID = %q, want empty -- members resolved to conflicting MITRE groups, must not force one", merged[0].CanonicalGroupID)
	}
}

// TestMergeActors_ActiveEnrichmentFoldsMITREAliasesIntoSurvivor proves that
// once an actor is canonically resolved, MITRE's own authoritative
// Name+Aliases for that group are folded into the survivor's Aliases too.
func TestMergeActors_ActiveEnrichmentFoldsMITREAliasesIntoSurvivor(t *testing.T) {
	canonicalIndex := map[string]string{"apt29": "G0016"}
	groupsByID := map[string]*attackdata.Group{
		"G0016": {ID: "G0016", Name: "APT29", Aliases: []string{"Cozy Bear", "The Dukes"}},
	}
	lookup := func(id string) *attackdata.Group { return groupsByID[id] }
	merged := mergeActorsWithCanonicalData([]ThreatActor{
		{Name: "APT29", Source: "misp", Techniques: []TechniqueRef{{ID: "T1078"}}},
	}, canonicalIndex, lookup)
	if len(merged) != 1 {
		t.Fatalf("want 1 actor, got %d", len(merged))
	}
	want := map[string]bool{"Cozy Bear": true, "The Dukes": true}
	if len(merged[0].Aliases) != len(want) {
		t.Fatalf("Aliases = %v, want exactly %v (MITRE's authoritative alias set folded in)", merged[0].Aliases, want)
	}
	for _, a := range merged[0].Aliases {
		if !want[a] {
			t.Errorf("unexpected alias %q", a)
		}
	}
}

// TestMergeActors_NoMITREDataLeavesCanonicalGroupIDEmpty uses the real,
// public MergeActors -- exercising the actual
// attackdata.GroupCanonicalTokenIndex(), which is empty in this repo until
// someone regenerates attack_groups.json from a real MITRE bundle.
// Confirms Project 1's alias-token matching is completely unaffected by
// this project's wiring when no MITRE data resolves.
func TestMergeActors_NoMITREDataLeavesCanonicalGroupIDEmpty(t *testing.T) {
	merged := MergeActors([]ThreatActor{
		{Name: "Wizard Spider", Source: "misp", Techniques: []TechniqueRef{{ID: "T1059.001"}}},
		{Name: "Sangria Tempest", Aliases: []string{"Wizard Spider"}, Source: "opencti", Techniques: []TechniqueRef{{ID: "T1566.001"}}},
	})
	if len(merged) != 1 {
		t.Fatalf("want 1 merged actor (Project 1 alias-token matching unaffected), got %d", len(merged))
	}
	if merged[0].CanonicalGroupID != "" {
		t.Errorf("CanonicalGroupID = %q, want empty (no real MITRE group data shipped yet)", merged[0].CanonicalGroupID)
	}
}
```

- [ ] **Step 2: Run tests to verify the new ones fail**

Run: `cd orchestrator && go test ./internal/connector/... -run 'TestMergeActors' -v`
Expected: the 7 pre-existing `TestMergeActors_*` tests (from Project 1) still PASS. The 5 new tests FAIL to compile — `mergeActorsWithCanonicalData` doesn't exist yet, and `ThreatActor` has no `CanonicalGroupID` field reference compiling against it in this file's context (it does exist from Task 3, but nothing sets it yet).

- [ ] **Step 3: Replace `actor_merge.go`**

Replace the full content of `orchestrator/internal/connector/actor_merge.go` with:

```go
package connector

import (
	"log"
	"sort"
	"strings"

	"github.com/audspect/bas/internal/reporting/attackdata"
)

// MergeActors deduplicates actors fetched from multiple sources within one
// sync cycle. Two actors are treated as the same identity if any of their
// normalized name/alias tokens match exactly -- primary name against
// primary name, primary name against alias, or alias against alias -- or if
// MITRE's own authoritative Group-ID dataset independently resolves both to
// the same canonical ATT&CK group, even with zero direct token overlap
// between them. This is transitive by construction: if actor A shares a
// token (direct or canonical) with actor B, and actor B shares a different
// token with actor C, then A, B, and C all merge into one group. Matching
// is exact-string-equality only on normalized tokens -- no fuzzy/similarity
// matching, anywhere. See
// docs/superpowers/specs/2026-08-11-alias-aware-actor-merge-design.md and
// docs/superpowers/specs/2026-08-11-canonical-mitre-actor-identity-design.md.
func MergeActors(actors []ThreatActor) []ThreatActor {
	return mergeActorsWithCanonicalData(actors, attackdata.GroupCanonicalTokenIndex(), attackdata.GroupByID)
}

// mergeActorsWithCanonicalData is MergeActors' testable core -- the
// canonical-MITRE-data sources are passed in explicitly so tests can
// exercise the resolution/merge/enrichment logic against small fixture
// data without depending on the embedded MITRE dataset (which, in this
// repo, ships empty until someone runs the gen tool against a real STIX
// bundle -- see internal/reporting/attackdata/attack_groups.json).
func mergeActorsWithCanonicalData(actors []ThreatActor, canonicalIndex map[string]string, groupByID func(string) *attackdata.Group) []ThreatActor {
	if len(actors) == 0 {
		return nil
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
	return out
}

// resolveCanonicalGroupID checks an actor's own normalized tokens against
// MITRE's canonical index. Exactly one distinct G#### match resolves; zero
// or more than one both resolve to "" (unresolved) -- ambiguity must never
// force an identity.
func resolveCanonicalGroupID(tokens []string, canonicalIndex map[string]string) string {
	matched := map[string]bool{}
	for _, tok := range tokens {
		if id, ok := canonicalIndex[tok]; ok {
			matched[id] = true
		}
	}
	if len(matched) != 1 {
		return ""
	}
	for id := range matched {
		return id
	}
	return ""
}

// actorTokens returns an actor's normalized identity tokens: its own name
// first, followed by each of its aliases. The name is always index 0 so
// callers can rely on tokens[0] as "this actor's own primary key" when
// registering it in the union-find.
func actorTokens(a ThreatActor) []string {
	toks := make([]string, 0, 1+len(a.Aliases))
	toks = append(toks, actorKey(a.Name))
	for _, alias := range a.Aliases {
		toks = append(toks, actorKey(alias))
	}
	return toks
}

func actorKey(name string) string {
	return strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(name, " ", ""), "-", ""))
}

// mergeActorGroup combines every actor at the given indices (already
// identified as the same real-world actor by mergeActorsWithCanonicalData)
// into one ThreatActor. idxs[0] -- the actor that arrived first in the
// original input order -- seeds Name/Description/Sectors/Regions/Source/
// SourceID/Confidence: first-arrival wins for those fields. Techniques are
// unioned and LastSeen takes the max. Aliases folds in every other member's
// own Aliases and Name, deduplicated by normalized token, excluding
// anything that normalizes to the survivor's own Name.
//
// CanonicalGroupID is resolved by consensus: if every member that resolved
// a canonical ID agrees, the survivor gets that ID; if none resolved, the
// survivor stays unresolved; if members resolved to DIFFERENT ids (a real
// contradiction -- they merged via a direct alias-token match, but MITRE's
// own data disagrees about which group they belong to), the survivor stays
// unresolved and the conflict is logged rather than silently picking one.
//
// When the survivor ends up with a resolved CanonicalGroupID, MITRE's own
// Name + Aliases for that group are folded into the survivor's Aliases too
// (active enrichment) -- so a canonically-resolved actor carries MITRE's
// authoritative alias set forward even in a future sync cycle where no
// connector happens to supply a bridging alias.
func mergeActorGroup(actors []ThreatActor, idxs []int, canonicalByActor []string, groupByID func(string) *attackdata.Group) ThreatActor {
	survivor := actors[idxs[0]]
	survivorKey := actorKey(survivor.Name)

	seenAliasTokens := make(map[string]bool, len(survivor.Aliases))
	mergedAliases := make([]string, 0, len(survivor.Aliases))
	fold := func(candidate string) {
		key := actorKey(candidate)
		if key == survivorKey || seenAliasTokens[key] {
			return
		}
		seenAliasTokens[key] = true
		mergedAliases = append(mergedAliases, candidate)
	}
	for _, alias := range survivor.Aliases {
		fold(alias)
	}

	for _, i := range idxs[1:] {
		member := actors[i]
		survivor.Techniques = mergeTechniques(survivor.Techniques, member.Techniques)
		if member.LastSeen.After(survivor.LastSeen) {
			survivor.LastSeen = member.LastSeen
		}
		fold(member.Name)
		for _, alias := range member.Aliases {
			fold(alias)
		}
	}

	resolved := map[string]bool{}
	for _, i := range idxs {
		if id := canonicalByActor[i]; id != "" {
			resolved[id] = true
		}
	}
	switch len(resolved) {
	case 1:
		for id := range resolved {
			survivor.CanonicalGroupID = id
		}
	case 0:
		survivor.CanonicalGroupID = ""
	default:
		ids := make([]string, 0, len(resolved))
		for id := range resolved {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		log.Printf("[connector] actor merge for %q: conflicting canonical MITRE group IDs %v -- leaving unresolved", survivor.Name, ids)
		survivor.CanonicalGroupID = ""
	}

	if survivor.CanonicalGroupID != "" {
		if g := groupByID(survivor.CanonicalGroupID); g != nil {
			fold(g.Name)
			for _, alias := range g.Aliases {
				fold(alias)
			}
		}
	}

	survivor.Aliases = mergedAliases
	return survivor
}

// tokenUnionFind is a simple disjoint-set over normalized identity tokens,
// used to group actors that share at least one name/alias/canonical token,
// transitively. Path compression keeps repeated find() calls cheap; no
// union-by-rank is needed at the actor-list sizes this runs over (dozens to
// a few hundred actors per sync, not millions).
type tokenUnionFind struct {
	parent map[string]string
}

func newTokenUnionFind() *tokenUnionFind {
	return &tokenUnionFind{parent: make(map[string]string)}
}

func (u *tokenUnionFind) find(token string) string {
	root, ok := u.parent[token]
	if !ok {
		u.parent[token] = token
		return token
	}
	if root == token {
		return token
	}
	root = u.find(root)
	u.parent[token] = root
	return root
}

func (u *tokenUnionFind) union(a, b string) {
	ra, rb := u.find(a), u.find(b)
	if ra != rb {
		u.parent[ra] = rb
	}
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go build ./... && go vet ./internal/connector/... && go test ./internal/connector/... -run 'TestMergeActors' -v`
Expected: `go build` succeeds. All 12 `TestMergeActors_*` tests pass (7 from Project 1, 5 new).

Then run the full package suite to catch any other regression:

Run: `cd orchestrator && go test ./internal/connector/... -v 2>&1 | tail -80`
Expected: `PASS`, `ok github.com/audspect/bas/internal/connector`.

- [ ] **Step 5: Commit**

```bash
cd orchestrator
git add internal/connector/actor_merge.go internal/connector/actor_merge_test.go
git commit -m "feat(connector): resolve canonical MITRE Group-ID as a primary merge key"
```

---

### Task 5: Thread `CanonicalGroupID` through Threat Prioritization

**Files:**
- Modify: `orchestrator/internal/threatpriority/models.go`
- Modify: `orchestrator/internal/threatpriority/engine.go`
- Test: `orchestrator/internal/threatpriority/engine_test.go`

**Interfaces:**
- Consumes: `threat_actor_profiles.canonical_group_id` (Task 3).
- Produces: `ActorProfile.CanonicalGroupID string` and `ActorPriority.CanonicalGroupID string \`json:"canonicalGroupId,omitempty"\`` — the latter consumed by Task 6 (frontend).

- [ ] **Step 1: Write the failing tests**

Add to `orchestrator/internal/threatpriority/engine_test.go`:

```go
// scoreActor must copy CanonicalGroupID straight through from the profile
// -- no DB involved (mirrors TestScoreActor_ComputesCompositeFromRealFactors's
// pattern of calling scoreActor directly with a hand-built profile).
func TestScoreActor_CopiesCanonicalGroupIDFromProfile(t *testing.T) {
	e := &Engine{factors: DefaultFactors()}
	shared := &sharedIndexes{
		simulation: map[string]bool{}, detection: map[string]bool{},
		purple: map[string]bool{}, compliance: map[string]bool{},
	}
	profile := &ActorProfile{Name: "TEST-ACTOR-CANON", CanonicalGroupID: "G0016"}
	ap, err := e.scoreActor(context.Background(), profile, shared)
	if err != nil {
		t.Fatalf("scoreActor: %v", err)
	}
	if ap.CanonicalGroupID != "G0016" {
		t.Errorf("CanonicalGroupID = %q, want G0016", ap.CanonicalGroupID)
	}
}

func TestLoadProfile_ReadsCanonicalGroupID(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExec(t, pool, `INSERT INTO threat_actor_profiles (name, canonical_group_id) VALUES ('TP-CANON-TEST', 'G0016')
			ON CONFLICT (name) DO UPDATE SET canonical_group_id = EXCLUDED.canonical_group_id`)
		e := &Engine{pool: pool}
		p, err := e.loadProfile(context.Background(), "TP-CANON-TEST")
		if err != nil {
			t.Fatalf("loadProfile: %v", err)
		}
		if p == nil {
			t.Fatal("expected a profile row")
		}
		if p.CanonicalGroupID != "G0016" {
			t.Errorf("CanonicalGroupID = %q, want G0016", p.CanonicalGroupID)
		}
	})
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/threatpriority/... -run 'TestScoreActor_CopiesCanonicalGroupIDFromProfile|TestLoadProfile_ReadsCanonicalGroupID' -v`
Expected: FAIL to compile — `ActorProfile`/`ActorPriority` have no `CanonicalGroupID` field yet.

- [ ] **Step 3: Add the fields and wire them through**

In `orchestrator/internal/threatpriority/models.go`, add to `ActorProfile` (after `Confidence`):

```go
type ActorProfile struct {
	Name       string
	Aliases    []string
	Sectors    []string
	Regions    []string
	Confidence string
	// CanonicalGroupID is the resolved MITRE ATT&CK Group-ID (G####), or ""
	// if internal/connector.MergeActors couldn't confidently resolve one.
	CanonicalGroupID string
	LastSeen         *time.Time
}
```

And to `ActorPriority` (after `TrendDelta`):

```go
	Trend            string         `json:"trend"`
	TrendDelta       int            `json:"trendDelta,omitempty"`

	// CanonicalGroupID surfaces the actor's resolved MITRE ATT&CK Group-ID
	// (G####), when one was resolved, so the UI can show provenance beyond
	// whatever name a connector happened to report it under.
	CanonicalGroupID string `json:"canonicalGroupId,omitempty"`

	// TechniqueIDs is this actor's resolved ATT&CK technique roster. Used by
```

(The existing `TechniqueIDs` field and its comment stay exactly as they are — this just inserts the new field above them.)

In `orchestrator/internal/threatpriority/engine.go`, update `loadProfile`:

```go
func (e *Engine) loadProfile(ctx context.Context, name string) (*ActorProfile, error) {
	row := e.pool.QueryRow(ctx,
		`SELECT name, aliases, sectors, regions, confidence, last_seen, canonical_group_id FROM threat_actor_profiles WHERE name=$1`, name)
	var p ActorProfile
	if err := row.Scan(&p.Name, &p.Aliases, &p.Sectors, &p.Regions, &p.Confidence, &p.LastSeen, &p.CanonicalGroupID); err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return &p, nil
}
```

And `loadAllProfiles`:

```go
func (e *Engine) loadAllProfiles(ctx context.Context) ([]ActorProfile, error) {
	rows, err := e.pool.Query(ctx,
		`SELECT name, aliases, sectors, regions, confidence, last_seen, canonical_group_id FROM threat_actor_profiles`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ActorProfile
	for rows.Next() {
		var p ActorProfile
		if err := rows.Scan(&p.Name, &p.Aliases, &p.Sectors, &p.Regions, &p.Confidence, &p.LastSeen, &p.CanonicalGroupID); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}
```

And in `scoreActor`, add `CanonicalGroupID` to the `ActorPriority` composite literal:

```go
	ap := ActorPriority{
		ActorName: profile.Name, Score: score, Tier: reporting.PriorityTierFor(score),
		Factors: results, TechniqueCount: len(techIDs), CoverageGapCount: coverageGap,
		TechniqueIDs: techIDs, CanonicalGroupID: profile.CanonicalGroupID,
	}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/threatpriority/... -v`
Expected: PASS — the 2 new tests plus every pre-existing test in the package.

- [ ] **Step 5: Commit**

```bash
cd orchestrator
git add internal/threatpriority/models.go internal/threatpriority/engine.go internal/threatpriority/engine_test.go
git commit -m "feat(threatpriority): surface canonical MITRE Group-ID on ActorPriority"
```

---

### Task 6: Frontend — canonical Group-ID badge on the actor detail view

**Files:**
- Modify: `orchestrator/wwwroot/index.html` (`renderThreatPriorityDetail`, currently at line 5448)

**Interfaces:**
- Consumes: `d.canonicalGroupId` and `d.actorName` on the `GET /api/threat-priority/actors/{name}` response (Task 5 adds `canonicalGroupId`; `actorName` already exists on `ActorPriority`).
- Produces: no new interface — this is the plan's terminal, UI-facing step.

- [ ] **Step 1: Add the badge**

In `orchestrator/wwwroot/index.html`, replace the start of `renderThreatPriorityDetail` (currently):

```js
function renderThreatPriorityDetail(d) {
  document.getElementById('tp-detail-summary').innerHTML =
```

with:

```js
function renderThreatPriorityDetail(d) {
  document.getElementById('tp-detail-title').innerHTML = x(d.actorName) +
    (d.canonicalGroupId ? '  <span class="tiny muted" style="font-weight:400">&middot; MITRE ' + x(d.canonicalGroupId) + '</span>' : '');

  document.getElementById('tp-detail-summary').innerHTML =
```

`showThreatPriorityDetail`'s existing `document.getElementById('tp-detail-title').textContent = actorName;` (line 5439) is left exactly as-is — it still gives an immediate title the instant the drawer opens, before the detail fetch resolves; this task's change simply overwrites it with the final (possibly badged) version once real data arrives, same pattern the rest of `renderThreatPriorityDetail` already uses for every other field.

- [ ] **Step 2: Verify manually**

This file has no automated frontend test suite (consistent with the rest of the codebase). Verify by hand:

1. Start the dev stack (`docker compose up` or however this environment's orchestrator is normally run for manual checks) and open the **Threat Prioritization** tab.
2. Click into any actor's detail view. Confirm the title renders exactly as before (no badge, no layout shift, no console error) — this is the only case that can be exercised today, since `attack_groups.json` ships as the empty placeholder (`[]`) from Task 2, so `canonicalGroupId` will be empty for every real actor in this environment until someone regenerates it from a real MITRE STIX bundle. Confirming the badge itself renders correctly requires that regeneration first — flag this to the user rather than silently skipping it.

- [ ] **Step 3: Commit**

```bash
git add orchestrator/wwwroot/index.html
git commit -m "feat(ui): show canonical MITRE Group-ID badge on actor detail"
```

---

## Self-Review Notes

- **Spec coverage:** Data model & sourcing (build-time `gen` extension, `attack_groups.json`, `GroupCanonicalTokenIndex`) — Tasks 1-2. Persistence (`canonical_group_id` column, `ThreatActor` field, upsert) — Task 3. Matching algorithm (resolution pass, synthetic bridging token, consensus/conflict merge policy) — Task 4. Active enrichment — Task 4 (`mergeActorGroup`'s `groupByID` fold-in). UI surface — Task 6. Every spec Testing-section case has a named test: zero-overlap bridging (Task 4, `TestMergeActors_BridgesViaCanonicalMITREGroupID_ZeroDirectOverlap`), per-actor ambiguity (`TestMergeActors_ActorTokensSpanTwoDistinctMITREGroupsStaysUnresolved`), merged-group conflict (`TestMergeActors_MergedGroupWithConflictingCanonicalIDsStaysUnresolved`), active enrichment (`TestMergeActors_ActiveEnrichmentFoldsMITREAliasesIntoSurvivor`), no-MITRE-match regression (`TestMergeActors_NoMITREDataLeavesCanonicalGroupIDEmpty`), `gen`-level extraction (Task 1, `TestParseGroups`), `attackdata`-level ambiguous-token exclusion (Task 2, `TestBuildGroupCanonicalTokenIndex_AmbiguousTokenExcluded`), persistence round-trip (Task 3, `TestUpsertActorProfiles_PersistsCanonicalGroupID`), `threatpriority` flow-through (Task 5, both new tests).
- **Non-goals respected:** No task touches `GroupTechniqueIndex()` or its consumers. No task modifies `tokenUnionFind`/`find`/`union`. No task introduces any similarity/fuzzy comparison — every match in every task is normalized-string equality via `actorKey`/`normalizeGroupToken` (which are kept in sync by comment, not by a shared function, since `attackdata` must not import `connector`). No task forces an identity on an ambiguous or unmatched actor, at either the per-actor (`resolveCanonicalGroupID`) or merged-group (`mergeActorGroup`'s consensus switch) level.
- **Placeholder scan:** No TBD/TODO; every step has literal, runnable code and exact commands. Task 6's Step 2 is manual verification, not a placeholder — the codebase genuinely has no frontend automated test suite (confirmed: no `*.test.js`/similar exists), and this is stated explicitly rather than glossed over, including the honest limitation that the positive-badge-rendering case can't be exercised until `attack_groups.json` is regenerated from a real bundle.
- **Type consistency:** `attackdata.Group{ID, Name string; Aliases []string}` is defined identically in Task 1 (`gen/main.go`, as the JSON-writing side) and Task 2 (`attackdata.go`, as the JSON-reading side) — same field names, same json tags, verified by inspection since the two are necessarily separate types in separate packages (`gen` is `package main`, not importable). `mergeActorsWithCanonicalData(actors []ThreatActor, canonicalIndex map[string]string, groupByID func(string) *attackdata.Group) []ThreatActor` — signature is identical everywhere it's declared (Task 4 Step 3) and called (Task 4 Step 3's `MergeActors`, and all 4 fixture-based tests in Task 4 Step 1). `ThreatActor.CanonicalGroupID` (Task 3) is read by `actor_merge.go` (Task 4) and by `upsertActorProfiles` (Task 3) with the same field name throughout. `ActorPriority.CanonicalGroupID` / `ActorProfile.CanonicalGroupID` (Task 5) match the `d.canonicalGroupId` JSON key Task 6's frontend reads.
