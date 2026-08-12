# Connector-Sourced Technique Fallback Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Threat Prioritization scoring falls back to connector-sourced technique data (`ThreatActor.Techniques`, persisted on `threat_actor_profiles`) when `ResolveActorTechniques`'s MITRE-name-match finds nothing, instead of silently scoring the actor as having zero techniques.

**Architecture:** `threat_actor_profiles` gains a `techniques text[]` column, populated by `upsertActorProfiles` from the merged actor's technique IDs (a small shared helper, reused by `Generator.buildYAML` too). `threatpriority.ActorProfile` gains a matching field. `scoreActor` tries MITRE first, connector-sourced second, and records which one won via a new `ActorPriority.TechniqueSource` field, shown as a small label in the UI.

**Tech Stack:** Go (`internal/connector`, `internal/threatpriority`), Postgres via pgx, vanilla JS in `orchestrator/wwwroot/index.html`.

## Global Constraints

- `ResolveActorTechniques` (`internal/reporting/insights.go`) stays a pure, DB-free function, completely unmodified — every other existing caller relies on its current contract.
- MITRE-authoritative technique resolution stays primary; connector-sourced data is a fallback only, never overrides a MITRE match.
- No backfill for existing `threat_actor_profiles` rows — self-heals on each actor's next sync (scheduled or manual), same rollout pattern as `threat_actor_sources`.
- No change to `internal/connector/actor_merge.go`, Coverage/Validation factors, or `Generator.Write`'s scenario-generation behavior.

---

### Task 1: Persist connector-sourced techniques and use them as a scoring fallback

**Files:**
- Modify: `orchestrator/internal/db/content_schema.go` (append to `stmts`)
- Modify: `orchestrator/internal/connector/generator.go` (extract shared `techniqueIDs` helper, use it in `buildYAML`)
- Modify: `orchestrator/internal/connector/scheduler.go` (`upsertActorProfiles` persists `techniques`)
- Modify: `orchestrator/internal/threatpriority/models.go` (`ActorProfile.Techniques`, `ActorPriority.TechniqueSource`)
- Modify: `orchestrator/internal/threatpriority/engine.go` (`loadProfile`/`loadAllProfiles` select the new column; `scoreActor`'s fallback logic)
- Modify: `orchestrator/wwwroot/index.html` (technique-source label near the Technique Coverage Breakdown card)
- Test: `orchestrator/internal/connector/scheduler_test.go` (append), `orchestrator/internal/connector/generator_test.go` (append, if it exists — otherwise create), `orchestrator/internal/threatpriority/engine_test.go` (append)

**Interfaces:**
- Produces: `func techniqueIDs(techs []TechniqueRef) []string` (`internal/connector`, uppercase+dedupe+sorted — exact behavior `Generator.buildYAML` already has inline, extracted verbatim). `ActorProfile.Techniques []string` and `ActorPriority.TechniqueSource string` (`internal/threatpriority`), consumed by the frontend as `d.techniqueSource`.

- [ ] **Step 1: Write the failing tests**

Append to `orchestrator/internal/connector/scheduler_test.go`:

```go

// TestUpsertActorProfiles_PersistsTechniques proves the merged actor's
// technique IDs survive into threat_actor_profiles.techniques -- the data
// Threat Prioritization's scoreActor falls back to when no MITRE-name
// match exists for this actor. Deduped and uppercased, same discipline
// Generator.buildYAML already applies for the generated scenario's
// art_techniques list.
func TestUpsertActorProfiles_PersistsTechniques(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		s := &Scheduler{pool: pool}
		s.upsertActorProfiles([]ThreatActor{{
			Name: "APT-TECH-PERSIST-TEST",
			Techniques: []TechniqueRef{
				{ID: "t1059.001"}, {ID: "T1566.001"}, {ID: "t1059.001"}, // duplicate, mixed case
			},
			Aliases: []string{}, Sectors: []string{}, Regions: []string{},
		}})

		var techs []string
		err := pool.QueryRow(t.Context(),
			`SELECT techniques FROM threat_actor_profiles WHERE name=$1`, "APT-TECH-PERSIST-TEST").Scan(&techs)
		if err != nil {
			t.Fatalf("query: %v", err)
		}
		if len(techs) != 2 {
			t.Fatalf("techniques = %v, want 2 deduped entries", techs)
		}
		want := map[string]bool{"T1059.001": true, "T1566.001": true}
		for _, id := range techs {
			if !want[id] {
				t.Errorf("unexpected technique %q in %v", id, techs)
			}
		}
	})
}

func TestUpsertActorProfiles_NoTechniques_PersistsEmptyArray(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		s := &Scheduler{pool: pool}
		s.upsertActorProfiles([]ThreatActor{{
			Name: "APT-NO-TECH-TEST", Aliases: []string{}, Sectors: []string{}, Regions: []string{},
		}})

		var techs []string
		err := pool.QueryRow(t.Context(),
			`SELECT techniques FROM threat_actor_profiles WHERE name=$1`, "APT-NO-TECH-TEST").Scan(&techs)
		if err != nil {
			t.Fatalf("query: %v", err)
		}
		if len(techs) != 0 {
			t.Fatalf("techniques = %v, want empty", techs)
		}
	})
}
```

Append to `orchestrator/internal/connector/generator_test.go` (create the file if it doesn't already exist -- check first with a directory listing; if it exists, append to it following its existing package/import style):

```go
func TestTechniqueIDs_DedupesAndUppercases(t *testing.T) {
	got := techniqueIDs([]TechniqueRef{{ID: "t1059.001"}, {ID: "T1566.001"}, {ID: "T1059.001"}})
	if len(got) != 2 {
		t.Fatalf("got %v, want 2 deduped entries", got)
	}
	want := map[string]bool{"T1059.001": true, "T1566.001": true}
	for _, id := range got {
		if !want[id] {
			t.Errorf("unexpected id %q in %v", id, got)
		}
	}
}

func TestTechniqueIDs_EmptyInput(t *testing.T) {
	if got := techniqueIDs(nil); len(got) != 0 {
		t.Fatalf("got %v, want empty", got)
	}
}
```

Append to `orchestrator/internal/threatpriority/engine_test.go`:

```go

// TestScoreActor_MITREMatchWinsOverConnectorTechniques proves MITRE stays
// primary: even when the profile also carries connector-sourced
// techniques, a real MITRE-name match must win, not merge or get
// overridden.
func TestScoreActor_MITREMatchWinsOverConnectorTechniques(t *testing.T) {
	e := &Engine{factors: DefaultFactors()}
	shared := &sharedIndexes{
		simulation: map[string]bool{}, detection: map[string]bool{},
		purple: map[string]bool{}, compliance: map[string]bool{},
	}
	// "Wizard Spider" is an established real MITRE group fixture already
	// relied on elsewhere in this codebase (attackdata_test.go,
	// otx_test.go). Give the profile a DIFFERENT connector-sourced
	// technique the MITRE list would never contain, so a test failure here
	// would be obvious (a mixed/merged list, not just a coincidental match).
	profile := &ActorProfile{Name: "Wizard Spider", Techniques: []string{"T9999"}}
	ap, err := e.scoreActor(context.Background(), profile, shared)
	if err != nil {
		t.Fatalf("scoreActor: %v", err)
	}
	if ap.TechniqueSource != "mitre" {
		t.Errorf("TechniqueSource = %q, want mitre", ap.TechniqueSource)
	}
	for _, id := range ap.TechniqueIDs {
		if id == "T9999" {
			t.Fatal("MITRE-authoritative result must not be mixed with connector-sourced techniques")
		}
	}
	if len(ap.TechniqueIDs) == 0 {
		t.Fatal("expected Wizard Spider's real MITRE technique list, got none")
	}
}

// TestScoreActor_FallsBackToConnectorTechniques_NoMITREMatch is the core
// regression guard for this whole fix: an actor MITRE doesn't recognize by
// name must still get scored against whatever real technique evidence a
// connector supplied, instead of silently zero.
func TestScoreActor_FallsBackToConnectorTechniques_NoMITREMatch(t *testing.T) {
	e := &Engine{factors: DefaultFactors()}
	shared := &sharedIndexes{
		simulation: map[string]bool{"T1059.001": true}, detection: map[string]bool{},
		purple: map[string]bool{}, compliance: map[string]bool{},
	}
	profile := &ActorProfile{
		Name:       "TEST-NOT-A-REAL-MITRE-GROUP-NAME-ZZYZX",
		Techniques: []string{"T1059.001", "T1566.001"},
	}
	ap, err := e.scoreActor(context.Background(), profile, shared)
	if err != nil {
		t.Fatalf("scoreActor: %v", err)
	}
	if ap.TechniqueSource != "connector" {
		t.Errorf("TechniqueSource = %q, want connector", ap.TechniqueSource)
	}
	if len(ap.TechniqueIDs) != 2 {
		t.Fatalf("TechniqueIDs = %v, want the 2 connector-sourced techniques", ap.TechniqueIDs)
	}
	if ap.CoverageGapCount != 1 {
		t.Fatalf("CoverageGapCount = %d, want 1 (T1566.001 has no coverage, T1059.001 does)", ap.CoverageGapCount)
	}
}

// TestScoreActor_NoMITREMatchNoConnectorTechniques_EmptyAndUnavailable
// proves the pre-existing "unknown, not none" discipline still holds when
// NEITHER source has anything: an empty TechniqueIDs list, not a fake
// zero-coverage-gap "fully covered" result. Coverage/Validation factors
// already handle this correctly (TestSimulationCoverageFactor_NoTechniques_Unavailable
// and siblings) -- this test guards that this fix doesn't regress it.
func TestScoreActor_NoMITREMatchNoConnectorTechniques_EmptyAndUnavailable(t *testing.T) {
	e := &Engine{factors: DefaultFactors()}
	shared := &sharedIndexes{
		simulation: map[string]bool{}, detection: map[string]bool{},
		purple: map[string]bool{}, compliance: map[string]bool{},
	}
	profile := &ActorProfile{Name: "TEST-NOT-A-REAL-MITRE-GROUP-NAME-ZZYZX-2"}
	ap, err := e.scoreActor(context.Background(), profile, shared)
	if err != nil {
		t.Fatalf("scoreActor: %v", err)
	}
	if ap.TechniqueSource != "" {
		t.Errorf("TechniqueSource = %q, want empty", ap.TechniqueSource)
	}
	if len(ap.TechniqueIDs) != 0 {
		t.Fatalf("TechniqueIDs = %v, want empty", ap.TechniqueIDs)
	}
	if ap.CoverageGapCount != 0 {
		t.Fatalf("CoverageGapCount = %d, want 0 (no techniques to have a gap in, not a false all-covered claim)", ap.CoverageGapCount)
	}
	for _, f := range ap.Factors {
		if f.Name == "Simulation Coverage" && f.Available {
			t.Error("Simulation Coverage must report Available=false with zero known techniques, not a false positive")
		}
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/connector/... -run 'TestUpsertActorProfiles_PersistsTechniques|TestUpsertActorProfiles_NoTechniques|TestTechniqueIDs' -v`
Expected: FAIL to compile — `undefined: techniqueIDs`, and the `techniques` column doesn't exist yet so the persistence tests would fail at the query step even if the helper existed.

Run: `cd orchestrator && go test ./internal/threatpriority/... -run 'TestScoreActor_MITREMatchWins|TestScoreActor_FallsBack|TestScoreActor_NoMITREMatchNoConnector' -v`
Expected: FAIL to compile — `unknown field Techniques in struct literal of type ActorProfile`, `ap.TechniqueSource undefined`.

- [ ] **Step 3: Add the column**

In `orchestrator/internal/db/content_schema.go`, append to the `stmts` slice immediately after the `threat_actor_activity` table (the last entry before the closing `}`):

```go

		// threat_actor_profiles.techniques: the connector-merged technique
		// roster (already deduped across sources by mergeActorGroup), used
		// as Threat Prioritization's fallback when ResolveActorTechniques
		// finds no MITRE-name match for this actor -- previously, such an
		// actor was silently scored with zero techniques even when real
		// connector evidence existed. See
		// docs/superpowers/specs/2026-08-12-technique-evidence-fallback-design.md.
		`ALTER TABLE threat_actor_profiles ADD COLUMN IF NOT EXISTS techniques text[] NOT NULL DEFAULT '{}'`,
```

- [ ] **Step 4: Extract the `techniqueIDs` helper and use it in `buildYAML`**

In `orchestrator/internal/connector/generator.go`, replace the inline block in `buildYAML`:

```go
	// Collect unique technique IDs
	techIDs := make([]string, 0, len(actor.Techniques))
	techSet := make(map[string]bool)
	for _, t := range actor.Techniques {
		up := strings.ToUpper(t.ID)
		if !techSet[up] {
			techSet[up] = true
			techIDs = append(techIDs, up)
		}
	}
	sort.Strings(techIDs)
```

with:

```go
	// Collect unique technique IDs
	techIDs := techniqueIDs(actor.Techniques)
```

Add the extracted helper near `actorFingerprint` in the same file (under the `// ── helpers ──` section):

```go

// techniqueIDs returns actor's technique IDs, uppercased, deduplicated,
// and sorted -- shared by buildYAML's art_techniques list and
// Scheduler.upsertActorProfiles' threat_actor_profiles.techniques column,
// so the two never drift into different dedup/casing behavior.
func techniqueIDs(techs []TechniqueRef) []string {
	out := make([]string, 0, len(techs))
	seen := make(map[string]bool)
	for _, t := range techs {
		up := strings.ToUpper(t.ID)
		if !seen[up] {
			seen[up] = true
			out = append(out, up)
		}
	}
	sort.Strings(out)
	return out
}
```

- [ ] **Step 5: Persist `techniques` in `upsertActorProfiles`**

In `orchestrator/internal/connector/scheduler.go`, replace:

```go
		_, err := s.pool.Exec(ctx,
			`INSERT INTO threat_actor_profiles (name, aliases, sectors, regions, source, last_seen, confidence, canonical_group_id, updated_at)
			 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,NOW())
			 ON CONFLICT (name) DO UPDATE SET
			   aliases = EXCLUDED.aliases, sectors = EXCLUDED.sectors, regions = EXCLUDED.regions,
			   source = EXCLUDED.source, last_seen = EXCLUDED.last_seen, confidence = EXCLUDED.confidence,
			   canonical_group_id = EXCLUDED.canonical_group_id,
			   updated_at = NOW()`,
			a.Name, nonNilStrings(a.Aliases), nonNilStrings(a.Sectors), nonNilStrings(a.Regions), a.Source, lastSeen, a.Confidence, a.CanonicalGroupID)
```

with:

```go
		_, err := s.pool.Exec(ctx,
			`INSERT INTO threat_actor_profiles (name, aliases, sectors, regions, source, last_seen, confidence, canonical_group_id, techniques, updated_at)
			 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,NOW())
			 ON CONFLICT (name) DO UPDATE SET
			   aliases = EXCLUDED.aliases, sectors = EXCLUDED.sectors, regions = EXCLUDED.regions,
			   source = EXCLUDED.source, last_seen = EXCLUDED.last_seen, confidence = EXCLUDED.confidence,
			   canonical_group_id = EXCLUDED.canonical_group_id, techniques = EXCLUDED.techniques,
			   updated_at = NOW()`,
			a.Name, nonNilStrings(a.Aliases), nonNilStrings(a.Sectors), nonNilStrings(a.Regions), a.Source, lastSeen, a.Confidence, a.CanonicalGroupID, techniqueIDs(a.Techniques))
```

- [ ] **Step 6: Add `ActorProfile.Techniques` and `ActorPriority.TechniqueSource`**

In `orchestrator/internal/threatpriority/models.go`, add to `ActorProfile`:

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
	// Techniques is the connector-merged technique roster (mirrors
	// threat_actor_profiles.techniques) -- scoreActor's fallback when
	// reporting.ResolveActorTechniques finds no MITRE-name match. See
	// docs/superpowers/specs/2026-08-12-technique-evidence-fallback-design.md.
	Techniques []string
}
```

Add to `ActorPriority` (after `TechniqueIDs`):

```go
	// TechniqueSource records which source scoreActor's TechniqueIDs came
	// from -- "mitre" (ResolveActorTechniques matched, the strongest
	// evidence) or "connector" (no MITRE match, fell back to
	// ActorProfile.Techniques) or "" (neither). Lets the UI avoid implying
	// MITRE-grade confidence for a connector-only actor.
	TechniqueSource string `json:"techniqueSource,omitempty"`
```

- [ ] **Step 7: Wire the fallback into `loadProfile`/`loadAllProfiles`/`scoreActor`**

In `orchestrator/internal/threatpriority/engine.go`, replace:

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

with:

```go
func (e *Engine) loadProfile(ctx context.Context, name string) (*ActorProfile, error) {
	row := e.pool.QueryRow(ctx,
		`SELECT name, aliases, sectors, regions, confidence, last_seen, canonical_group_id, techniques FROM threat_actor_profiles WHERE name=$1`, name)
	var p ActorProfile
	if err := row.Scan(&p.Name, &p.Aliases, &p.Sectors, &p.Regions, &p.Confidence, &p.LastSeen, &p.CanonicalGroupID, &p.Techniques); err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return &p, nil
}

func (e *Engine) loadAllProfiles(ctx context.Context) ([]ActorProfile, error) {
	rows, err := e.pool.Query(ctx,
		`SELECT name, aliases, sectors, regions, confidence, last_seen, canonical_group_id, techniques FROM threat_actor_profiles`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ActorProfile
	for rows.Next() {
		var p ActorProfile
		if err := rows.Scan(&p.Name, &p.Aliases, &p.Sectors, &p.Regions, &p.Confidence, &p.LastSeen, &p.CanonicalGroupID, &p.Techniques); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}
```

Then in `scoreActor`, replace:

```go
	techIDs, _, _ := reporting.ResolveActorTechniques(profile.Name, profile.Aliases)
```

with:

```go
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

And add `TechniqueSource: techniqueSource,` to the `ap := ActorPriority{...}` composite literal:

```go
	ap := ActorPriority{
		ActorName: profile.Name, Score: score, Tier: reporting.PriorityTierFor(score),
		Factors: results, TechniqueCount: len(techIDs), CoverageGapCount: coverageGap,
		TechniqueIDs: techIDs, CanonicalGroupID: profile.CanonicalGroupID, TechniqueSource: techniqueSource,
	}
```

- [ ] **Step 8: Run tests to verify they pass**

Run: `cd orchestrator && go build ./... && go vet ./internal/connector/... ./internal/threatpriority/... && go test ./internal/connector/... -run 'TestUpsertActorProfiles|TestTechniqueIDs' -v`
Expected: `go build` succeeds. All new tests PASS, plus every pre-existing `TestUpsertActorProfiles_*` test still PASSes unmodified.

Run: `cd orchestrator && go test ./internal/threatpriority/... -v 2>&1 | tail -80`
Expected: all 3 new `TestScoreActor_*` tests PASS, plus every pre-existing test in the package still PASSes unmodified.

Then the whole module: `cd orchestrator && go build ./... && go vet ./...`
Expected: no errors.

- [ ] **Step 9: Add the UI label**

In `orchestrator/wwwroot/index.html`, insert inside the Technique Coverage Breakdown card, immediately above the `tp-detail-coverage` div:

```html
          <div class="card" style="margin-bottom:1rem;padding:1rem 1.2rem">
            <div class="card-title">Technique Coverage Breakdown</div>
            <div id="tp-detail-technique-source" class="tiny muted" style="margin-bottom:0.4rem"></div>
            <div id="tp-detail-coverage" class="tiny"></div>
          </div>
```

In `renderThreatPriorityDetail`, immediately before the existing `var techCoverage = (d.techniqueCoverage || []);` line, add:

```js

  var techSourceLabel = {
    mitre: 'Techniques: MITRE-authoritative',
    connector: 'Techniques: connector-derived (not yet MITRE-confirmed)'
  }[d.techniqueSource] || '';
  document.getElementById('tp-detail-technique-source').textContent = techSourceLabel;
```

- [ ] **Step 10: Run the full connector and threatpriority + api suites once more**

Run: `cd orchestrator && go test ./internal/connector/... ./internal/threatpriority/... ./internal/api/...`
Expected: `ok` for all three packages — confirms `threatPriorityActorDetail`'s embedded `threatpriority.ActorPriority` (which the frontend reads as `d.techniqueSource`) serializes the new field correctly with no API-layer code change needed (it's already `respond(w, threatPriorityActorDetail{ActorPriority: ap, ...})`).

- [ ] **Step 11: Verify manually**

This file has no automated frontend test suite (consistent with the rest of the codebase). Verify by hand if a dev instance is reachable: open an actor whose name matches a real MITRE group, confirm "Techniques: MITRE-authoritative" shows; open a MISP/OpenCTI-only actor with no MITRE match but real connector techniques, confirm "Techniques: connector-derived (not yet MITRE-confirmed)" shows and the Coverage/Uncovered sections are no longer empty for it; open an actor with neither, confirm no label and the existing "No technique data." fallback still shows. If no dev instance is reachable in this environment, say so explicitly and add it to the standing Pending Manual QA Backlog.

- [ ] **Step 12: Commit**

```bash
cd /c/Users/Administrator/Downloads/Audspect_Cloud
git add orchestrator/internal/db/content_schema.go orchestrator/internal/connector/generator.go orchestrator/internal/connector/scheduler.go orchestrator/internal/connector/scheduler_test.go orchestrator/internal/connector/generator_test.go orchestrator/internal/threatpriority/models.go orchestrator/internal/threatpriority/engine.go orchestrator/internal/threatpriority/engine_test.go orchestrator/wwwroot/index.html
git commit -m "feat(threatpriority): fall back to connector-sourced techniques when MITRE has no name match"
git push
```

---

## Self-Review Notes

- **Spec coverage:** the `techniques` column + `upsertActorProfiles` persistence — Step 3/5. The shared `techniqueIDs` helper, reused by both `buildYAML` and the new upsert path (spec's explicit requirement) — Step 4. `ActorProfile.Techniques`/`ActorPriority.TechniqueSource` — Step 6. MITRE-primary/connector-fallback logic in `scoreActor` — Step 7. UI label with the spec's exact verbatim wording for both states — Step 9. No backfill (self-heals on next sync) — inherent in the design, no explicit migration step exists, matching the spec.
- **Placeholder scan:** no TBD/TODO; every step has literal, runnable code and exact commands. Step 1's `generator_test.go` step includes an explicit instruction to check whether the file already exists and match its style, rather than assuming — this is a scoped instruction (verify before appending), not a placeholder for missing logic.
- **Type consistency:** `techniqueIDs(techs []TechniqueRef) []string` defined once in Step 4, called identically from `buildYAML` (Step 4) and `upsertActorProfiles` (Step 5), tested identically in `generator_test.go`. `ActorProfile.Techniques []string` / `ActorPriority.TechniqueSource string` defined once in Step 6, consumed identically in Step 7's `scoreActor` and all three of Step 1's threatpriority tests. `d.techniqueSource` in the frontend (Step 9) matches the JSON tag (`techniqueSource,omitempty`) from Step 6 exactly.
- **A design question the spec left slightly open, resolved here:** the spec didn't specify exact column order in the INSERT — Step 5 appends `techniques` as the 9th positional column (after `canonical_group_id`), consistent with append-only schema evolution already used for `confidence`/`canonical_group_id` in this table's history (both added via later `ALTER TABLE` statements, per `content_schema.go`'s own comments).
