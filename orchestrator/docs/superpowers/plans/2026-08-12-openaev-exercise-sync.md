# OpenAEV Exercise Sync + Sync-Result Visibility Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make OpenAEV **Exercises** (a standalone simulation object, separate from and not requiring a Scenario) sync into Audspect alongside Scenarios, feeding the same existing Create-Exercise-Plan flow — and make sync results (created/updated/skipped/errored counts) visible instead of a bare "ok" that looks identical whether a sync imported real content or nothing at all.

**Architecture:** A new `ExerciseRESTProvider` talks to OpenAEV's `/api/exercises` API and internally converts its ZIP-wrapped, `exercise_*`-prefixed export format into the exact same wire format the existing `ParseBundle`/`Normalize`/`Upsert` pipeline already understands — so the sync/importer layer (`Importer.SyncAll`, `processOne`) needs zero changes. A `CompositeProvider` merges the Scenario and Exercise providers behind the single `ContentProvider` interface `SyncOpenAEV` and the background poller already use. Both content types land in the existing `openaev_scenarios`/`openaev_bundles` tables, distinguished by a new `source_type` column, and both drive the same unmodified `BuildPlan`/`CreateExercisePlanFromOpenAEV` flow.

**Tech Stack:** Go (backend, `internal/openaev`, `internal/api`, `internal/db`), Postgres (pgx), vanilla JS (`orchestrator/wwwroot/index.html`, no framework/bundler).

## Global Constraints

- OpenAEV Exercise export is a ZIP (`GET /api/exercises/{id}/export`) with an entry whose `zip.File.Comment == "Exercise"` (verified against `openaev-main/.../service/ImportService.java:37-38`, matching the existing Scenario path's `"Scenario"` comment convention already implemented in `internal/openaev/parser.go`).
- The Exercise manifest's JSON keys are `exercise_information`, `exercise_objectives`, `exercise_injects`, `exercise_tags`, `exercise_variables`, `export_version` — verified against `openaev-main/openaev-api/src/main/java/io/openaev/rest/exercise/exports/ExerciseFileExport.java`. The nested `Objective`/`Inject`/`Tag`/`Variable` shapes are the exact same Java model classes (and therefore the exact same JSON field names: `objective_id`/`objective_title`, `inject_id`/`inject_title`/`inject_attack_patterns`, `tag_name`) used by the Scenario export — verified against `openaev-main/openaev-model/src/main/java/io/openaev/database/model/{Objective,Tag,Inject}.java`. Only the top-level `Exercise` item's own fields (`exercise_id`, `exercise_name`, `exercise_description`, `exercise_category`, `exercise_severity`, `exercise_updated_at`) need their own struct — verified against `openaev-main/openaev-model/src/main/java/io/openaev/database/model/Exercise.java:53-220`.
- `GET /api/exercises` returns `List<ExerciseSimple>` (`exercise_id`, `exercise_name`, `exercise_updated_at`) — verified against `openaev-main/.../rest/exercise/output/ExerciseSimple.java`.
- Existing files this plan must NOT change: `internal/openaev/importer.go` (`SyncAll`/`processOne`/`ImportOne`), `internal/openaev/normalizer.go`'s public behavior for Scenario-origin bundles, `openaev.BuildPlan`, `CreateExercisePlanFromOpenAEV`. Both content types must reach these completely unmodified.
- Follow the existing test harness conventions exactly: `sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {...})` + `testing.Short()` skip guard for DB-backed tests (see `internal/openaev/store_test.go`, `internal/api/openaev_handlers_test.go`); `httptest.NewServer` for provider tests (see `internal/openaev/provider_test.go`); fixture-ZIP-building helpers with `t.Helper()` (see `internal/openaev/parser_test.go`).
- Migration convention: append `ALTER TABLE ... ADD COLUMN IF NOT EXISTS ...` statements to the existing `stmts []string` slices — `internal/db/content_schema.go` for `openaev_scenarios`, `internal/db/postgres.go` for `openaev_config`. Never restructure existing statements.

---

### Task 1: `source_type` column + `Scenario.SourceType` + store filtering

**Files:**
- Modify: `orchestrator/internal/db/content_schema.go` (end of the `stmts` slice, right before its closing `}`, ~line 494)
- Modify: `orchestrator/internal/openaev/types.go` (`ParsedBundle` struct ~line 31-38, `Scenario` struct ~line 79-90)
- Modify: `orchestrator/internal/openaev/normalizer.go` (`Normalize`, ~line 52-63)
- Modify: `orchestrator/internal/openaev/store.go` (`Upsert` ~line 38-109, `List` ~line 111-132, `Get` ~line 134-152)
- Modify: `orchestrator/internal/openaev/store_test.go` (add new tests)
- Modify: `orchestrator/internal/api/openaev_handlers.go` (`ListOpenAEVScenarios` call site, ~line 139-150 — update the one `store.List(ctx)` call to pass a sourceType argument; use `"scenario"` here for now, Task 6 makes it dynamic)

**Interfaces:**
- Produces: `ParsedBundle.SourceType string` (json tag `source_type,omitempty`) — set to `"exercise"` by the exercise parser (Task 2), left as Go zero-value `""` by the existing `ParseBundle`.
- Produces: `Scenario.SourceType string` — always non-empty after `Normalize` (defaults `""` → `"scenario"`).
- Produces: `(*SQLStore) List(ctx context.Context, sourceType string) ([]Scenario, error)` — **signature change** from today's `List(ctx context.Context)`. Empty string means unfiltered (all rows); a non-empty value filters `WHERE source_type = $1`.
- Consumes (later tasks): Task 2/3 set `ParsedBundle.SourceType = "exercise"`; Task 6 passes the HTTP query param through to `List`.

- [ ] **Step 1: Write the failing store test for source_type persistence and filtering**

Add to `orchestrator/internal/openaev/store_test.go`:

```go
func TestStore_UpsertPersistsSourceType(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		db.EnsureSchema(context.Background(), pool)
		db.EnsureContentSchema(context.Background(), pool)
		store := NewSQLStore(pool)

		scenario := Scenario{OpenAEVScenarioID: "sc-sourcetype-001", Name: "A", SourceType: "exercise"}
		if err := store.Upsert(context.Background(), scenario, Detail{}, "hash-a", 10, 1); err != nil {
			t.Fatalf("Upsert: %v", err)
		}

		got, _, found, err := store.Get(context.Background(), "sc-sourcetype-001")
		if err != nil || !found {
			t.Fatalf("Get: found=%v err=%v", found, err)
		}
		if got.SourceType != "exercise" {
			t.Errorf("SourceType = %q, want exercise", got.SourceType)
		}
	})
}

func TestStore_UpsertDefaultsEmptySourceTypeToScenario(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		db.EnsureSchema(context.Background(), pool)
		db.EnsureContentSchema(context.Background(), pool)
		store := NewSQLStore(pool)

		scenario := Scenario{OpenAEVScenarioID: "sc-sourcetype-002", Name: "A"} // SourceType left unset
		store.Upsert(context.Background(), scenario, Detail{}, "hash-b", 10, 1)

		got, _, _, _ := store.Get(context.Background(), "sc-sourcetype-002")
		if got.SourceType != "scenario" {
			t.Errorf("SourceType = %q, want scenario (default)", got.SourceType)
		}
	})
}

func TestStore_ListFiltersBySourceType(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		db.EnsureSchema(context.Background(), pool)
		db.EnsureContentSchema(context.Background(), pool)
		store := NewSQLStore(pool)

		store.Upsert(context.Background(), Scenario{OpenAEVScenarioID: "sc-list-scn", Name: "Scn", SourceType: "scenario"}, Detail{}, "h1", 10, 1)
		store.Upsert(context.Background(), Scenario{OpenAEVScenarioID: "sc-list-exc", Name: "Exc", SourceType: "exercise"}, Detail{}, "h2", 10, 1)

		scenarios, err := store.List(context.Background(), "scenario")
		if err != nil {
			t.Fatalf("List(scenario): %v", err)
		}
		for _, s := range scenarios {
			if s.OpenAEVScenarioID == "sc-list-exc" {
				t.Error("List(\"scenario\") must not include an exercise-sourced row")
			}
		}

		exercises, err := store.List(context.Background(), "exercise")
		if err != nil {
			t.Fatalf("List(exercise): %v", err)
		}
		found := false
		for _, s := range exercises {
			if s.OpenAEVScenarioID == "sc-list-exc" {
				found = true
			}
		}
		if !found {
			t.Error("List(\"exercise\") must include the exercise-sourced row")
		}

		all, err := store.List(context.Background(), "")
		if err != nil {
			t.Fatalf("List(\"\"): %v", err)
		}
		if len(all) < 2 {
			t.Errorf("List(\"\") = %d rows, want >= 2 (unfiltered)", len(all))
		}
	})
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/openaev/... -run TestStore_UpsertPersistsSourceType -run TestStore_UpsertDefaultsEmptySourceTypeToScenario -run TestStore_ListFiltersBySourceType -v`
Expected: compile error (`Scenario.SourceType` and `List`'s new parameter don't exist yet).

- [ ] **Step 3: Add the migration**

In `orchestrator/internal/db/content_schema.go`, immediately before the closing `}` of the `stmts` slice (after the `technique_evidence` table, ~line 493):

```go
		// source_type distinguishes an OpenAEV Scenario (reusable template)
		// from an OpenAEV Exercise (standalone simulation, does not require
		// a parent Scenario) synced into the same table. See
		// docs/superpowers/specs/2026-08-12-openaev-exercise-sync-design.md.
		`ALTER TABLE openaev_scenarios ADD COLUMN IF NOT EXISTS source_type text NOT NULL DEFAULT 'scenario'`,
```

- [ ] **Step 4: Add `SourceType` to `ParsedBundle` and `Scenario`**

In `orchestrator/internal/openaev/types.go`, add to `ParsedBundle` (after the `Variables` field):

```go
	// SourceType is not part of OpenAEV's wire format -- it is stamped by
	// ParseExerciseBundle ("exercise") and left as the zero value by
	// ParseBundle ("" -- Normalize treats this as "scenario"). Included with
	// a JSON tag (not json:"-") so it survives the exercise provider's
	// round-trip through marshalAsScenarioZip -> ParseBundle (see Task 3).
	SourceType string `json:"source_type,omitempty"`
```

Add to `Scenario` (after `SourceUpdatedAt`):

```go
	SourceType string // "scenario" or "exercise" -- see ParsedBundle.SourceType
```

- [ ] **Step 5: Set `SourceType` in `Normalize`**

In `orchestrator/internal/openaev/normalizer.go`, in the `scenario := Scenario{...}` literal, add:

```go
		SourceType:        parsed.SourceType,
```

Then immediately after the `scenario := Scenario{...}` block, before `detail := Detail{...}`:

```go
	if scenario.SourceType == "" {
		scenario.SourceType = "scenario"
	}
```

- [ ] **Step 6: Persist `source_type` in `Upsert`**

In `orchestrator/internal/openaev/store.go`, inside `Upsert`, after the existing `tags := scenario.Tags; if tags == nil {...}` block, add:

```go
	sourceType := scenario.SourceType
	if sourceType == "" {
		sourceType = "scenario"
	}
```

Then update the second `tx.Exec` (the `openaev_scenarios` upsert) to include `source_type`:

```go
	if _, err := tx.Exec(ctx,
		`INSERT INTO openaev_scenarios
		   (openaev_scenario_id, name, category, severity, platforms, technique_ids, tags,
		    objectives_count, injects_count, source_updated_at, content_hash, bundle_id,
		    sync_revision, updated_at, source_type)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $11, 1, NOW(), $12)
		 ON CONFLICT (openaev_scenario_id) DO UPDATE SET
		   name = EXCLUDED.name,
		   category = EXCLUDED.category,
		   severity = EXCLUDED.severity,
		   platforms = EXCLUDED.platforms,
		   technique_ids = EXCLUDED.technique_ids,
		   tags = EXCLUDED.tags,
		   objectives_count = EXCLUDED.objectives_count,
		   injects_count = EXCLUDED.injects_count,
		   source_updated_at = EXCLUDED.source_updated_at,
		   bundle_id = EXCLUDED.bundle_id,
		   sync_revision = CASE
		     WHEN openaev_scenarios.content_hash <> EXCLUDED.content_hash
		     THEN openaev_scenarios.sync_revision + 1
		     ELSE openaev_scenarios.sync_revision
		   END,
		   content_hash = EXCLUDED.content_hash,
		   source_type = EXCLUDED.source_type,
		   updated_at = NOW()`,
		scenario.OpenAEVScenarioID, scenario.Name, scenario.Category, scenario.Severity,
		platforms, techniqueIDs, tags,
		scenario.ObjectivesCount, scenario.InjectsCount, scenario.SourceUpdatedAt, contentHash,
		sourceType,
	); err != nil {
		return err
	}
```

- [ ] **Step 7: Add `source_type` filtering to `List` and reading to `Get`**

Replace `List` in `orchestrator/internal/openaev/store.go`:

```go
func (s *SQLStore) List(ctx context.Context, sourceType string) ([]Scenario, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT openaev_scenario_id, name, category, severity, platforms, technique_ids, tags,
		        objectives_count, injects_count, source_updated_at, source_type
		   FROM openaev_scenarios
		  WHERE ($1 = '' OR source_type = $1)
		  ORDER BY name`, sourceType)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Scenario
	for rows.Next() {
		var sc Scenario
		if err := rows.Scan(&sc.OpenAEVScenarioID, &sc.Name, &sc.Category, &sc.Severity,
			&sc.Platforms, &sc.TechniqueIDs, &sc.Tags, &sc.ObjectivesCount, &sc.InjectsCount,
			&sc.SourceUpdatedAt, &sc.SourceType); err != nil {
			continue
		}
		out = append(out, sc)
	}
	return out, rows.Err()
}
```

In `Get`, add `s.source_type` to the `SELECT` list and `&sc.SourceType` to the `Scan` call, in the same relative position as `List` above (right after `s.source_updated_at`, before the `bundle` join column).

- [ ] **Step 8: Update the one existing caller of `List`**

In `orchestrator/internal/api/openaev_handlers.go`, `ListOpenAEVScenarios` (~line 139-150), change:

```go
	scenarios, err := store.List(r.Context())
```

to:

```go
	scenarios, err := store.List(r.Context(), "scenario")
```

(This preserves today's behavior exactly — only scenario-sourced rows are returned. Task 6 makes this dynamic via a query param.)

- [ ] **Step 9: Run tests to verify they pass**

Run: `go test ./internal/openaev/... -run TestStore -v`
Expected: PASS (all `TestStore_*` tests, including the 3 new ones)

Run: `go build ./...`
Expected: no errors (confirms `ListOpenAEVScenarios`'s call site compiles)

- [ ] **Step 10: Commit**

```bash
git add orchestrator/internal/db/content_schema.go orchestrator/internal/openaev/types.go orchestrator/internal/openaev/normalizer.go orchestrator/internal/openaev/store.go orchestrator/internal/openaev/store_test.go orchestrator/internal/api/openaev_handlers.go
git commit -m "feat(openaev): add source_type column distinguishing Scenario vs Exercise rows"
```

---

### Task 2: Exercise manifest parsing (`ParseExerciseBundle`)

**Files:**
- Modify: `orchestrator/internal/openaev/parser.go`
- Modify: `orchestrator/internal/openaev/parser_test.go`

**Interfaces:**
- Consumes: `ParsedBundle`, `ParsedScenario`, `ParsedObjective`, `ParsedInject`, `ParsedTag`, `ParsedVariable` (all from Task 1 / existing `types.go`, unchanged shapes for the nested types).
- Produces: `func ParseExerciseBundle(data []byte) (*ParsedBundle, error)` — decodes an Exercise export ZIP into a `*ParsedBundle` with `SourceType: "exercise"` set.
- Produces: `func marshalAsScenarioZip(b *ParsedBundle) ([]byte, error)` — the inverse: re-encodes a `*ParsedBundle` as a synthetic in-memory ZIP with one entry commented `"Scenario"`, exactly what `ParseBundle` already decodes. Used by Task 3's `ExerciseRESTProvider.Fetch`.

- [ ] **Step 1: Write the failing tests**

Add to `orchestrator/internal/openaev/parser_test.go`:

```go
// buildFixtureExerciseZip mirrors buildFixtureZip but for an Exercise export
// -- entry commented "Exercise" (EXPORT_ENTRY_EXERCISE in openaev-main's
// ImportService.java), exercise_*-prefixed JSON keys.
func buildFixtureExerciseZip(t *testing.T, exerciseJSON string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	hdr := &zip.FileHeader{Name: "Live Fire Drill.json", Method: zip.Deflate}
	hdr.Comment = "Exercise"
	w, err := zw.CreateHeader(hdr)
	if err != nil {
		t.Fatalf("create zip entry: %v", err)
	}
	if _, err := w.Write([]byte(exerciseJSON)); err != nil {
		t.Fatalf("write zip entry: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close zip: %v", err)
	}
	return buf.Bytes()
}

const fixtureExerciseJSON = `{
  "export_version": 1,
  "exercise_information": {
    "exercise_id": "ex-openaev-001",
    "exercise_name": "Live Fire Drill",
    "exercise_description": "Standalone simulation, no parent scenario",
    "exercise_category": "redteam",
    "exercise_severity": "critical",
    "exercise_updated_at": "2026-08-01T09:00:00Z"
  },
  "exercise_objectives": [
    {"objective_id": "obj-e1", "objective_title": "Contain lateral movement", "objective_description": "within 30 minutes"}
  ],
  "exercise_injects": [
    {
      "inject_id": "inj-e1",
      "inject_title": "Credential dump",
      "inject_attack_patterns": [
        {"attack_pattern_external_id": "T1003", "attack_pattern_name": "OS Credential Dumping", "attack_pattern_platforms": ["windows"]}
      ]
    }
  ],
  "exercise_tags": [{"tag_name": "live-fire"}],
  "exercise_variables": [
    {"variable_key": "target_dc", "variable_description": "Domain controller hostname"}
  ]
}`

func TestParseExerciseBundle_DecodesExerciseAndTechniques(t *testing.T) {
	zipBytes := buildFixtureExerciseZip(t, fixtureExerciseJSON)

	parsed, err := ParseExerciseBundle(zipBytes)
	if err != nil {
		t.Fatalf("ParseExerciseBundle: %v", err)
	}
	if parsed.SourceType != "exercise" {
		t.Errorf("SourceType = %q, want exercise", parsed.SourceType)
	}
	if parsed.Scenario.ID != "ex-openaev-001" {
		t.Errorf("ID = %q, want ex-openaev-001", parsed.Scenario.ID)
	}
	if parsed.Scenario.Name != "Live Fire Drill" {
		t.Errorf("Name = %q, want Live Fire Drill", parsed.Scenario.Name)
	}
	if parsed.Scenario.Category != "redteam" || parsed.Scenario.Severity != "critical" {
		t.Errorf("Category/Severity = %q/%q", parsed.Scenario.Category, parsed.Scenario.Severity)
	}
	wantUpdated := time.Date(2026, 8, 1, 9, 0, 0, 0, time.UTC)
	if !parsed.Scenario.UpdatedAt.Equal(wantUpdated) {
		t.Errorf("UpdatedAt = %v, want %v", parsed.Scenario.UpdatedAt, wantUpdated)
	}
	if len(parsed.Injects) != 1 || parsed.Injects[0].AttackPatterns[0].ExternalID != "T1003" {
		t.Errorf("Injects = %+v", parsed.Injects)
	}
	if len(parsed.Tags) != 1 || parsed.Tags[0].Name != "live-fire" {
		t.Errorf("Tags = %+v", parsed.Tags)
	}
}

func TestParseExerciseBundle_MissingExerciseEntry_Errors(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, _ := zw.Create("readme.txt")
	w.Write([]byte("not an exercise"))
	zw.Close()

	if _, err := ParseExerciseBundle(buf.Bytes()); err == nil {
		t.Fatal("expected error for a bundle with no Exercise-commented entry, got nil")
	}
}

func TestParseExerciseBundle_RejectsScenarioEntry(t *testing.T) {
	// A Scenario-flavored zip (commented "Scenario") must not be silently
	// accepted by the Exercise parser -- the two are visually similar but
	// distinct wire formats, and ScenarioApi vs ExerciseApi are genuinely
	// different OpenAEV objects.
	zipBytes := buildFixtureZip(t, fixtureScenarioJSON)
	if _, err := ParseExerciseBundle(zipBytes); err == nil {
		t.Fatal("expected error when Exercise parser is given a Scenario-commented entry, got nil")
	}
}

func TestMarshalAsScenarioZip_RoundTripsThroughParseBundle(t *testing.T) {
	exerciseZip := buildFixtureExerciseZip(t, fixtureExerciseJSON)
	parsed, err := ParseExerciseBundle(exerciseZip)
	if err != nil {
		t.Fatalf("ParseExerciseBundle: %v", err)
	}
	parsed.Scenario.ID = "exercise:ex-openaev-001" // simulate the provider's ID re-stamp

	synthetic, err := marshalAsScenarioZip(parsed)
	if err != nil {
		t.Fatalf("marshalAsScenarioZip: %v", err)
	}

	roundTripped, err := ParseBundle(synthetic)
	if err != nil {
		t.Fatalf("ParseBundle(synthetic): %v", err)
	}
	if roundTripped.Scenario.ID != "exercise:ex-openaev-001" {
		t.Errorf("round-tripped ID = %q, want exercise:ex-openaev-001", roundTripped.Scenario.ID)
	}
	if roundTripped.Scenario.Name != "Live Fire Drill" {
		t.Errorf("round-tripped Name = %q", roundTripped.Scenario.Name)
	}
	if roundTripped.SourceType != "exercise" {
		t.Errorf("round-tripped SourceType = %q, want exercise (must survive the synthetic-zip round trip)", roundTripped.SourceType)
	}
	if len(roundTripped.Injects) != 1 || roundTripped.Injects[0].AttackPatterns[0].ExternalID != "T1003" {
		t.Errorf("round-tripped Injects = %+v", roundTripped.Injects)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/openaev/... -run TestParseExerciseBundle -run TestMarshalAsScenarioZip -v`
Expected: compile error (`ParseExerciseBundle`/`marshalAsScenarioZip` undefined)

- [ ] **Step 3: Implement `ParseExerciseBundle` and `marshalAsScenarioZip`**

Add to `orchestrator/internal/openaev/parser.go` (after the existing `ParseBundle` function):

```go
// exerciseEntryComment is how OpenAEV's own export marks the ZIP entry that
// holds the exercise JSON — see openaev-api's ImportService.EXPORT_ENTRY_EXERCISE
// ("Exercise"). Mirrors scenarioEntryComment above for the Scenario case.
const exerciseEntryComment = "Exercise"

// parsedExerciseItem is Exercise's own top-level fields (openaev-main's
// Exercise.java, JSON-tagged exercise_id/exercise_name/...) -- the Exercise
// equivalent of ParsedScenario. Kept separate because the tag prefix
// ("exercise_" vs "scenario_") differs; the VALUES map 1:1 onto ParsedScenario.
type parsedExerciseItem struct {
	ID          string    `json:"exercise_id"`
	Name        string    `json:"exercise_name"`
	Description string    `json:"exercise_description"`
	Category    string    `json:"exercise_category"`
	Severity    string    `json:"exercise_severity"`
	UpdatedAt   time.Time `json:"exercise_updated_at"`
}

// parsedExerciseManifest is the decoded contents of one OpenAEV Exercise
// export ZIP entry. Objectives/Injects/Tags/Variables reuse ParsedBundle's
// nested types unchanged -- OpenAEV's Objective/Inject/Tag/Variable are the
// same Java model classes (and therefore the same JSON field names) in both
// a Scenario export and an Exercise export; only the wrapper key prefix and
// the top-level item's own fields differ.
type parsedExerciseManifest struct {
	ExportVersion int                `json:"export_version"`
	Exercise      parsedExerciseItem `json:"exercise_information"`
	Objectives    []ParsedObjective  `json:"exercise_objectives"`
	Injects       []ParsedInject     `json:"exercise_injects"`
	Tags          []ParsedTag        `json:"exercise_tags"`
	Variables     []ParsedVariable   `json:"exercise_variables"`
}

// ParseExerciseBundle decodes a raw OpenAEV EXERCISE export ZIP (as returned
// by GET /api/exercises/{id}/export) into the same ParsedBundle shape
// ParseBundle produces for Scenarios, so every downstream step (Normalize,
// Upsert, the Importer) needs no knowledge that this content originated
// from an Exercise rather than a Scenario. SourceType is stamped "exercise"
// so Normalize can carry it through to the stored row (see types.go).
func ParseExerciseBundle(data []byte) (*ParsedBundle, error) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, fmt.Errorf("not a valid bundle ZIP: %w", err)
	}

	var entry *zip.File
	for _, f := range zr.File {
		if f.Comment == exerciseEntryComment {
			entry = f
			break
		}
	}
	if entry == nil {
		return nil, fmt.Errorf("bundle has no entry commented %q — not a valid OpenAEV exercise export", exerciseEntryComment)
	}

	rc, err := entry.Open()
	if err != nil {
		return nil, fmt.Errorf("open exercise entry: %w", err)
	}
	defer rc.Close()

	var m parsedExerciseManifest
	if err := json.NewDecoder(rc).Decode(&m); err != nil {
		return nil, fmt.Errorf("decode exercise JSON: %w", err)
	}

	return &ParsedBundle{
		ExportVersion: m.ExportVersion,
		SourceType:    "exercise",
		Scenario: ParsedScenario{
			ID:          m.Exercise.ID,
			Name:        m.Exercise.Name,
			Description: m.Exercise.Description,
			Category:    m.Exercise.Category,
			Severity:    m.Exercise.Severity,
			UpdatedAt:   m.Exercise.UpdatedAt,
		},
		Objectives: m.Objectives,
		Injects:    m.Injects,
		Tags:       m.Tags,
		Variables:  m.Variables,
	}, nil
}

// marshalAsScenarioZip re-encodes an already-normalized ParsedBundle
// (regardless of its original source) as a synthetic in-memory ZIP with one
// entry commented "Scenario" — exactly the wire format ParseBundle already
// knows how to decode. This lets a non-Scenario source (the Exercise
// provider, see provider_rest_exercise.go) hand its content back through the
// existing Fetch -> ParseBundle -> Normalize -> Upsert pipeline unchanged.
func marshalAsScenarioZip(b *ParsedBundle) ([]byte, error) {
	jsonBytes, err := json.Marshal(b)
	if err != nil {
		return nil, fmt.Errorf("marshal synthetic scenario bundle: %w", err)
	}

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	hdr := &zip.FileHeader{Name: b.Scenario.ID + ".json", Method: zip.Deflate}
	hdr.Comment = scenarioEntryComment
	w, err := zw.CreateHeader(hdr)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(jsonBytes); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
```

Add `"time"` to `orchestrator/internal/openaev/parser.go`'s import block (needed by `parsedExerciseItem.UpdatedAt`).

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/openaev/... -run TestParseExerciseBundle -run TestMarshalAsScenarioZip -run TestParseBundle -v`
Expected: PASS (new tests, and confirms `ParseBundle`'s existing tests are unaffected)

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/openaev/parser.go orchestrator/internal/openaev/parser_test.go
git commit -m "feat(openaev): parse OpenAEV Exercise exports into the existing ParsedBundle shape"
```

---

### Task 3: `ExerciseRESTProvider`

**Files:**
- Create: `orchestrator/internal/openaev/provider_rest_exercise.go`
- Create: `orchestrator/internal/openaev/provider_rest_exercise_test.go`

**Interfaces:**
- Consumes: `ContentProvider` interface (`types.go`), `ParseExerciseBundle`/`marshalAsScenarioZip` (Task 2).
- Produces: `type ExerciseRESTProvider struct{...}`, `func NewExerciseRESTProvider(baseURL, token string) *ExerciseRESTProvider`, satisfying `ContentProvider`. Produces the exported constant `exerciseIDPrefix = "exercise:"` — every ID this provider returns from `List` or accepts in `Fetch` carries this prefix; Task 4's `CompositeProvider` routes on it.

- [ ] **Step 1: Write the failing tests**

Create `orchestrator/internal/openaev/provider_rest_exercise_test.go`:

```go
package openaev

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestExerciseRESTProvider_List_PrefixesIDs(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Errorf("Authorization header = %q, want Bearer test-token", r.Header.Get("Authorization"))
		}
		if r.URL.Path != "/api/exercises" {
			t.Errorf("path = %q, want /api/exercises", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`[
			{"exercise_id": "ex-1", "exercise_name": "Drill One", "exercise_updated_at": "2026-08-01T09:00:00Z"}
		]`))
	}))
	defer srv.Close()

	p := NewExerciseRESTProvider(srv.URL, "test-token")
	refs, err := p.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(refs) != 1 {
		t.Fatalf("refs = %d, want 1", len(refs))
	}
	if refs[0].ID != "exercise:ex-1" {
		t.Errorf("refs[0].ID = %q, want exercise:ex-1", refs[0].ID)
	}
	if refs[0].Name != "Drill One" {
		t.Errorf("refs[0].Name = %q, want Drill One", refs[0].Name)
	}
}

func TestExerciseRESTProvider_Fetch_StripsPrefixForExportRequest(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/exercises/ex-1/export" {
			t.Errorf("path = %q, want /api/exercises/ex-1/export (prefix must be stripped)", r.URL.Path)
		}
		w.Write(buildFixtureExerciseZip(t, fixtureExerciseJSON))
	}))
	defer srv.Close()

	p := NewExerciseRESTProvider(srv.URL, "test-token")
	data, err := p.Fetch(context.Background(), "exercise:ex-1")
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}

	parsed, err := ParseBundle(data) // Fetch's output must already be ParseBundle-compatible
	if err != nil {
		t.Fatalf("ParseBundle(Fetch output): %v", err)
	}
	if parsed.Scenario.ID != "exercise:ex-1" {
		t.Errorf("parsed.Scenario.ID = %q, want exercise:ex-1 (full prefixed ID re-stamped)", parsed.Scenario.ID)
	}
	if parsed.Scenario.Name != "Live Fire Drill" {
		t.Errorf("parsed.Scenario.Name = %q", parsed.Scenario.Name)
	}
	if parsed.SourceType != "exercise" {
		t.Errorf("parsed.SourceType = %q, want exercise", parsed.SourceType)
	}
}

func TestExerciseRESTProvider_List_Unauthorized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	p := NewExerciseRESTProvider(srv.URL, "bad-token")
	if _, err := p.List(context.Background()); err == nil {
		t.Fatal("expected error for 401 response, got nil")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/openaev/... -run TestExerciseRESTProvider -v`
Expected: compile error (`ExerciseRESTProvider`/`NewExerciseRESTProvider` undefined)

- [ ] **Step 3: Implement `ExerciseRESTProvider`**

Create `orchestrator/internal/openaev/provider_rest_exercise.go`:

```go
package openaev

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// exerciseIDPrefix distinguishes exercise-origin IDs from scenario-origin
// IDs within the single ID namespace ContentProvider.Fetch operates on.
// CompositeProvider (see composite_provider.go) routes purely by checking
// this prefix. It is also stamped as the item's canonical stored ID
// (Scenario.OpenAEVScenarioID via ParsedBundle.Scenario.ID), so a re-sync's
// delta-check (Store.SyncState) looks up the same ID List() advertised --
// without this, every sync would see "not found" and treat already-synced
// Exercises as brand new every time.
const exerciseIDPrefix = "exercise:"

// ExerciseRESTProvider fetches OpenAEV Exercises -- a standalone simulation
// object that does not require a parent Scenario -- via OpenAEV's own
// /api/exercises REST API. Fetch's returned bytes are already
// ParseBundle-compatible (via ParseExerciseBundle + marshalAsScenarioZip),
// so the rest of the sync pipeline (Importer.SyncAll/processOne) needs no
// knowledge that an item originated from an Exercise rather than a Scenario.
type ExerciseRESTProvider struct {
	baseURL string
	token   string
	client  *http.Client
}

func NewExerciseRESTProvider(baseURL, token string) *ExerciseRESTProvider {
	return &ExerciseRESTProvider{baseURL: baseURL, token: token, client: &http.Client{Timeout: 30 * time.Second}}
}

func (p *ExerciseRESTProvider) Name() string { return "openaev-exercise-rest" }

type restExerciseListEntry struct {
	ID        string    `json:"exercise_id"`
	Name      string    `json:"exercise_name"`
	UpdatedAt time.Time `json:"exercise_updated_at"`
}

func (p *ExerciseRESTProvider) List(ctx context.Context) ([]ScenarioRef, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.baseURL+"/api/exercises", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+p.token)

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("openaev exercise list request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("openaev exercise list returned HTTP %d", resp.StatusCode)
	}

	var entries []restExerciseListEntry
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		return nil, fmt.Errorf("decode openaev exercise list: %w", err)
	}

	refs := make([]ScenarioRef, 0, len(entries))
	for _, e := range entries {
		refs = append(refs, ScenarioRef{ID: exerciseIDPrefix + e.ID, Name: e.Name, SourceUpdated: e.UpdatedAt})
	}
	return refs, nil
}

func (p *ExerciseRESTProvider) Fetch(ctx context.Context, id string) ([]byte, error) {
	rawID := strings.TrimPrefix(id, exerciseIDPrefix)
	url := p.baseURL + "/api/exercises/" + rawID + "/export"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+p.token)

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("openaev exercise export request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("openaev exercise export returned HTTP %d for exercise %s", resp.StatusCode, rawID)
	}

	zipBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read exercise export body: %w", err)
	}

	parsed, err := ParseExerciseBundle(zipBytes)
	if err != nil {
		return nil, err
	}
	parsed.Scenario.ID = id // re-stamp with the full prefixed ID List() advertised
	return marshalAsScenarioZip(parsed)
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/openaev/... -run TestExerciseRESTProvider -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/openaev/provider_rest_exercise.go orchestrator/internal/openaev/provider_rest_exercise_test.go
git commit -m "feat(openaev): add ExerciseRESTProvider for OpenAEV's /api/exercises"
```

---

### Task 4: `CompositeProvider`

**Files:**
- Create: `orchestrator/internal/openaev/composite_provider.go`
- Create: `orchestrator/internal/openaev/composite_provider_test.go`

**Interfaces:**
- Consumes: `ContentProvider` (any two implementations — tests use fakes, production uses `RESTProvider` + `ExerciseRESTProvider`), `exerciseIDPrefix` (Task 3).
- Produces: `type CompositeProvider struct{...}`, `func NewCompositeProvider(scenarios, exercises ContentProvider) *CompositeProvider`, satisfying `ContentProvider`.

- [ ] **Step 1: Write the failing tests**

Create `orchestrator/internal/openaev/composite_provider_test.go`:

```go
package openaev

import (
	"context"
	"errors"
	"testing"
)

// fakeProvider is a minimal ContentProvider for testing composition without
// real HTTP.
type fakeProvider struct {
	name    string
	refs    []ScenarioRef
	listErr error
	fetched []string // records every ID passed to Fetch, for routing assertions
	fetchFn func(id string) ([]byte, error)
}

func (f *fakeProvider) Name() string { return f.name }
func (f *fakeProvider) List(ctx context.Context) ([]ScenarioRef, error) {
	return f.refs, f.listErr
}
func (f *fakeProvider) Fetch(ctx context.Context, id string) ([]byte, error) {
	f.fetched = append(f.fetched, id)
	if f.fetchFn != nil {
		return f.fetchFn(id)
	}
	return []byte("data-for-" + id), nil
}

func TestCompositeProvider_List_MergesBothSources(t *testing.T) {
	scenarios := &fakeProvider{refs: []ScenarioRef{{ID: "sc-1", Name: "Scenario One"}}}
	exercises := &fakeProvider{refs: []ScenarioRef{{ID: "exercise:ex-1", Name: "Exercise One"}}}

	cp := NewCompositeProvider(scenarios, exercises)
	refs, err := cp.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(refs) != 2 {
		t.Fatalf("refs = %d, want 2", len(refs))
	}
	ids := map[string]bool{refs[0].ID: true, refs[1].ID: true}
	if !ids["sc-1"] || !ids["exercise:ex-1"] {
		t.Errorf("refs = %+v, want both sc-1 and exercise:ex-1", refs)
	}
}

func TestCompositeProvider_Fetch_RoutesByPrefix(t *testing.T) {
	scenarios := &fakeProvider{}
	exercises := &fakeProvider{}
	cp := NewCompositeProvider(scenarios, exercises)

	if _, err := cp.Fetch(context.Background(), "sc-1"); err != nil {
		t.Fatalf("Fetch(sc-1): %v", err)
	}
	if _, err := cp.Fetch(context.Background(), "exercise:ex-1"); err != nil {
		t.Fatalf("Fetch(exercise:ex-1): %v", err)
	}

	if len(scenarios.fetched) != 1 || scenarios.fetched[0] != "sc-1" {
		t.Errorf("scenarios provider fetched = %+v, want [sc-1]", scenarios.fetched)
	}
	if len(exercises.fetched) != 1 || exercises.fetched[0] != "exercise:ex-1" {
		t.Errorf("exercises provider fetched = %+v, want [exercise:ex-1]", exercises.fetched)
	}
}

func TestCompositeProvider_List_PropagatesScenarioListError(t *testing.T) {
	scenarios := &fakeProvider{listErr: errors.New("scenario list boom")}
	exercises := &fakeProvider{}
	cp := NewCompositeProvider(scenarios, exercises)

	if _, err := cp.List(context.Background()); err == nil {
		t.Fatal("expected error to propagate from the scenarios sub-provider")
	}
}

func TestCompositeProvider_List_PropagatesExerciseListError(t *testing.T) {
	scenarios := &fakeProvider{}
	exercises := &fakeProvider{listErr: errors.New("exercise list boom")}
	cp := NewCompositeProvider(scenarios, exercises)

	if _, err := cp.List(context.Background()); err == nil {
		t.Fatal("expected error to propagate from the exercises sub-provider")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/openaev/... -run TestCompositeProvider -v`
Expected: compile error (`CompositeProvider`/`NewCompositeProvider` undefined)

- [ ] **Step 3: Implement `CompositeProvider`**

Create `orchestrator/internal/openaev/composite_provider.go`:

```go
package openaev

import (
	"context"
	"strings"
)

// CompositeProvider merges a Scenario provider and an Exercise provider
// behind one ContentProvider, so Importer.SyncAll needs no knowledge that
// OpenAEV content comes from two distinct object types. List concatenates
// both sources' refs; Fetch routes to whichever sub-provider owns the given
// ID (see exerciseIDPrefix in provider_rest_exercise.go).
//
// If either sub-provider's List fails, the whole sync fails -- matching the
// existing single-provider behavior (SyncAll has always treated a List
// failure as fatal to the whole sync, not per-item). A partial-source
// degradation (e.g. only /api/exercises is down) is a deliberately
// unhandled edge case for this version; last_error still surfaces which
// source failed via the wrapped error message.
type CompositeProvider struct {
	scenarios ContentProvider
	exercises ContentProvider
}

func NewCompositeProvider(scenarios, exercises ContentProvider) *CompositeProvider {
	return &CompositeProvider{scenarios: scenarios, exercises: exercises}
}

func (p *CompositeProvider) Name() string { return "openaev-composite" }

func (p *CompositeProvider) List(ctx context.Context) ([]ScenarioRef, error) {
	scenarioRefs, err := p.scenarios.List(ctx)
	if err != nil {
		return nil, err
	}
	exerciseRefs, err := p.exercises.List(ctx)
	if err != nil {
		return nil, err
	}
	return append(scenarioRefs, exerciseRefs...), nil
}

func (p *CompositeProvider) Fetch(ctx context.Context, id string) ([]byte, error) {
	if strings.HasPrefix(id, exerciseIDPrefix) {
		return p.exercises.Fetch(ctx, id)
	}
	return p.scenarios.Fetch(ctx, id)
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/openaev/... -v`
Expected: PASS (full package — confirms Tasks 1-4 all still pass together)

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/openaev/composite_provider.go orchestrator/internal/openaev/composite_provider_test.go
git commit -m "feat(openaev): add CompositeProvider merging Scenario and Exercise sources"
```

---

### Task 5: Wire `CompositeProvider` into sync + persist sync-result counts

**Files:**
- Modify: `orchestrator/internal/db/postgres.go` (migration, ~line 1398, before the `stmts` slice's closing `}`)
- Modify: `orchestrator/internal/api/openaev_handlers.go` (`SyncOpenAEV` ~line 86-117, `GetOpenAEVConfig` ~line 12-32, `GetOpenAEVStatus` ~line 120-136)
- Modify: `orchestrator/cmd/server/main.go` (openaevScheduler block, ~line 332-366)
- Modify: `orchestrator/internal/api/openaev_handlers_test.go`

**Interfaces:**
- Consumes: `openaev.NewCompositeProvider`, `openaev.NewExerciseRESTProvider` (Tasks 3-4), `openaev.NewRESTProvider` (existing), `openaev.SyncResult` (existing, fields `Created`/`Updated`/`Skipped`/`Errored`).
- Produces: `openaev_config` columns `last_sync_created`, `last_sync_updated`, `last_sync_skipped`, `last_sync_errored` (all `int`). `GetOpenAEVConfig`/`GetOpenAEVStatus` responses gain `lastSyncCreated`/`lastSyncUpdated`/`lastSyncSkipped`/`lastSyncErrored` (all `int`, `0` when never synced).

- [ ] **Step 1: Write the failing handler test**

Add to `orchestrator/internal/api/openaev_handlers_test.go`:

```go
func TestGetOpenAEVStatus_ReturnsSyncCounts(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		db.EnsureSchema(context.Background(), pool)
		pool.Exec(context.Background(),
			`INSERT INTO openaev_config (id, enabled, last_sync_status, last_sync_created, last_sync_updated, last_sync_skipped, last_sync_errored)
			 VALUES (1, true, 'ok', 3, 2, 5, 1)
			 ON CONFLICT (id) DO UPDATE SET last_sync_status = EXCLUDED.last_sync_status,
			   last_sync_created = EXCLUDED.last_sync_created, last_sync_updated = EXCLUDED.last_sync_updated,
			   last_sync_skipped = EXCLUDED.last_sync_skipped, last_sync_errored = EXCLUDED.last_sync_errored`)

		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		rec := httptest.NewRecorder()
		h.GetOpenAEVStatus(rec, httptest.NewRequest(http.MethodGet, "/api/openaev/status", nil))

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var out map[string]any
		json.Unmarshal(rec.Body.Bytes(), &out)
		if int(out["lastSyncCreated"].(float64)) != 3 {
			t.Errorf("lastSyncCreated = %v, want 3", out["lastSyncCreated"])
		}
		if int(out["lastSyncSkipped"].(float64)) != 5 {
			t.Errorf("lastSyncSkipped = %v, want 5", out["lastSyncSkipped"])
		}
	})
}

func TestGetOpenAEVConfig_ReturnsSyncCountsDefaultZero(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		db.EnsureSchema(context.Background(), pool)
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		rec := httptest.NewRecorder()
		h.GetOpenAEVConfig(rec, httptest.NewRequest(http.MethodGet, "/api/openaev/config", nil))

		var out map[string]any
		json.Unmarshal(rec.Body.Bytes(), &out)
		if out["lastSyncCreated"] != float64(0) {
			t.Errorf("lastSyncCreated = %v, want 0 (never synced)", out["lastSyncCreated"])
		}
	})
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/api/... -run TestGetOpenAEVStatus_ReturnsSyncCounts -run TestGetOpenAEVConfig_ReturnsSyncCountsDefaultZero -v`
Expected: FAIL (fields absent from the response map — `out["lastSyncCreated"]` is `nil`, not `float64(3)`/`float64(0)`)

- [ ] **Step 3: Add the migration**

In `orchestrator/internal/db/postgres.go`, immediately before the `stmts` slice's closing `}` (after the "Live Runs" `ALTER TABLE scenario_runs` block, ~line 1398):

```go
		// OpenAEV sync-result visibility: last_sync_status alone can't
		// distinguish "genuinely imported nothing" from "imported real
		// content" -- both showed as a bare "ok". See
		// docs/superpowers/specs/2026-08-12-openaev-exercise-sync-design.md.
		`ALTER TABLE openaev_config ADD COLUMN IF NOT EXISTS last_sync_created int NOT NULL DEFAULT 0`,
		`ALTER TABLE openaev_config ADD COLUMN IF NOT EXISTS last_sync_updated int NOT NULL DEFAULT 0`,
		`ALTER TABLE openaev_config ADD COLUMN IF NOT EXISTS last_sync_skipped int NOT NULL DEFAULT 0`,
		`ALTER TABLE openaev_config ADD COLUMN IF NOT EXISTS last_sync_errored int NOT NULL DEFAULT 0`,
```

- [ ] **Step 4: Update `GetOpenAEVConfig` and `GetOpenAEVStatus` to return the counts**

In `orchestrator/internal/api/openaev_handlers.go`, replace `GetOpenAEVConfig`:

```go
func (h *Handler) GetOpenAEVConfig(w http.ResponseWriter, r *http.Request) {
	var baseURL, status, lastError string
	var pollHours int
	var enabled bool
	var created, updated, skipped, errored int
	err := h.db.QueryRow(r.Context(),
		`SELECT base_url, poll_interval_hours, enabled, last_sync_status, last_error,
		        last_sync_created, last_sync_updated, last_sync_skipped, last_sync_errored
		   FROM openaev_config WHERE id = 1`,
	).Scan(&baseURL, &pollHours, &enabled, &status, &lastError, &created, &updated, &skipped, &errored)
	if err != nil {
		// No row yet — defaults.
		respond(w, map[string]any{
			"baseUrl": "", "pollIntervalHours": 24, "enabled": false, "lastSyncStatus": "never", "lastError": "",
			"lastSyncCreated": 0, "lastSyncUpdated": 0, "lastSyncSkipped": 0, "lastSyncErrored": 0,
		})
		return
	}
	respond(w, map[string]any{
		"baseUrl":           baseURL,
		"pollIntervalHours": pollHours,
		"enabled":           enabled,
		"lastSyncStatus":    status,
		"lastError":         lastError,
		"lastSyncCreated":   created,
		"lastSyncUpdated":   updated,
		"lastSyncSkipped":   skipped,
		"lastSyncErrored":   errored,
	})
}
```

Replace `GetOpenAEVStatus`:

```go
func (h *Handler) GetOpenAEVStatus(w http.ResponseWriter, r *http.Request) {
	var lastSyncAt any
	var status, lastError string
	var created, updated, skipped, errored int
	h.db.QueryRow(r.Context(),
		`SELECT last_sync_at, last_sync_status, last_error,
		        last_sync_created, last_sync_updated, last_sync_skipped, last_sync_errored
		   FROM openaev_config WHERE id = 1`,
	).Scan(&lastSyncAt, &status, &lastError, &created, &updated, &skipped, &errored)

	var scenarioCount int
	h.db.QueryRow(r.Context(), `SELECT count(*) FROM openaev_scenarios`).Scan(&scenarioCount)

	respond(w, map[string]any{
		"lastSyncAt":      lastSyncAt,
		"lastSyncStatus":  status,
		"lastError":       lastError,
		"scenarioCount":   scenarioCount,
		"lastSyncCreated": created,
		"lastSyncUpdated": updated,
		"lastSyncSkipped": skipped,
		"lastSyncErrored": errored,
	})
}
```

- [ ] **Step 5: Wire `CompositeProvider` and persist counts in `SyncOpenAEV`**

Replace `SyncOpenAEV` in `orchestrator/internal/api/openaev_handlers.go`:

```go
func (h *Handler) SyncOpenAEV(w http.ResponseWriter, r *http.Request) {
	var baseURL, token string
	var enabled bool
	err := h.db.QueryRow(r.Context(), `SELECT base_url, bearer_token, enabled FROM openaev_config WHERE id = 1`).
		Scan(&baseURL, &token, &enabled)
	if err != nil || !enabled {
		jsonError(w, "openaev is not configured/enabled", http.StatusConflict)
		return
	}

	store := openaev.NewSQLStore(h.db)
	importer := openaev.NewImporter(store)
	provider := openaev.NewCompositeProvider(
		openaev.NewRESTProvider(baseURL, token),
		openaev.NewExerciseRESTProvider(baseURL, token),
	)

	result, syncErr := importer.SyncAll(r.Context(), provider)
	status := "ok"
	lastErr := ""
	created, updated, skipped, errored := 0, 0, 0, 0
	if syncErr != nil {
		status = "error"
		lastErr = syncErr.Error()
	} else {
		created, updated, skipped, errored = result.Created, result.Updated, result.Skipped, result.Errored
	}
	h.db.Exec(r.Context(),
		`UPDATE openaev_config SET last_sync_at = NOW(), last_sync_status = $1, last_error = $2,
		   last_sync_created = $3, last_sync_updated = $4, last_sync_skipped = $5, last_sync_errored = $6
		 WHERE id = 1`,
		status, lastErr, created, updated, skipped, errored)

	h.auditLog(r, "openaev.sync", "", map[string]any{"result": result}, "ok")
	if syncErr != nil {
		jsonError(w, syncErr.Error(), http.StatusInternalServerError)
		return
	}
	respond(w, result)
}
```

- [ ] **Step 6: Wire `CompositeProvider` and persist counts in the background poller**

In `orchestrator/cmd/server/main.go`, inside `openaevScheduler.Start`'s callback (~line 340-366), replace:

```go
		store := openaev.NewSQLStore(pool)
		importer := openaev.NewImporter(store)
		provider := openaev.NewRESTProvider(baseURL, token)
		result, syncErr := importer.SyncAll(ctx, provider)
		status := "ok"
		lastErr := ""
		if syncErr != nil {
			status = "error"
			lastErr = syncErr.Error()
		}
		pool.Exec(ctx, `UPDATE openaev_config SET last_sync_at = NOW(), last_sync_status = $1, last_error = $2 WHERE id = 1`, status, lastErr)
		log.Printf("[openaev] sync: created=%d updated=%d skipped=%d errored=%d", result.Created, result.Updated, result.Skipped, result.Errored)
```

with:

```go
		store := openaev.NewSQLStore(pool)
		importer := openaev.NewImporter(store)
		provider := openaev.NewCompositeProvider(
			openaev.NewRESTProvider(baseURL, token),
			openaev.NewExerciseRESTProvider(baseURL, token),
		)
		result, syncErr := importer.SyncAll(ctx, provider)
		status := "ok"
		lastErr := ""
		created, updated, skipped, errored := 0, 0, 0, 0
		if syncErr != nil {
			status = "error"
			lastErr = syncErr.Error()
		} else {
			created, updated, skipped, errored = result.Created, result.Updated, result.Skipped, result.Errored
		}
		pool.Exec(ctx,
			`UPDATE openaev_config SET last_sync_at = NOW(), last_sync_status = $1, last_error = $2,
			   last_sync_created = $3, last_sync_updated = $4, last_sync_skipped = $5, last_sync_errored = $6
			 WHERE id = 1`,
			status, lastErr, created, updated, skipped, errored)
		log.Printf("[openaev] sync: created=%d updated=%d skipped=%d errored=%d", created, updated, skipped, errored)
```

(Note: the original code referenced `result.Created` etc. directly in the `log.Printf` even on the `syncErr != nil` path, which would nil-pointer-panic since `SyncAll` returns `nil, err` on a `List` failure — the replacement above fixes this latent bug by using the same `created`/`updated`/`skipped`/`errored` locals throughout.)

- [ ] **Step 7: Run tests to verify they pass**

Run: `go test ./internal/api/... -run TestGetOpenAEVStatus -run TestGetOpenAEVConfig -run TestSyncOpenAEV -v`
Expected: PASS

Run: `go build ./...`
Expected: no errors (confirms `main.go` compiles with the corrected nil-safe locals)

- [ ] **Step 8: Commit**

```bash
git add orchestrator/internal/db/postgres.go orchestrator/internal/api/openaev_handlers.go orchestrator/internal/api/openaev_handlers_test.go orchestrator/cmd/server/main.go
git commit -m "feat(openaev): sync Exercises via CompositeProvider, persist sync-result counts"
```

---

### Task 6: `?type=` query param on `GET /api/openaev/scenarios`

**Files:**
- Modify: `orchestrator/internal/api/openaev_handlers.go` (`ListOpenAEVScenarios`, ~line 139-150)
- Modify: `orchestrator/internal/api/openaev_handlers_test.go`

**Interfaces:**
- Consumes: `(*SQLStore) List(ctx, sourceType string)` (Task 1).
- Produces: `GET /api/openaev/scenarios?type=exercise` — filters to exercise-sourced rows. `GET /api/openaev/scenarios` (no param) — defaults to `type=scenario`, identical to today's behavior.

- [ ] **Step 1: Write the failing tests**

Add to `orchestrator/internal/api/openaev_handlers_test.go`:

```go
func TestListOpenAEVScenarios_DefaultsToScenarioType(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		db.EnsureContentSchema(context.Background(), pool)
		store := openaev.NewSQLStore(pool)
		store.Upsert(context.Background(), openaev.Scenario{OpenAEVScenarioID: "sc-filter-1", Name: "Scn", SourceType: "scenario"}, openaev.Detail{}, "h1", 10, 1)
		store.Upsert(context.Background(), openaev.Scenario{OpenAEVScenarioID: "sc-filter-2", Name: "Exc", SourceType: "exercise"}, openaev.Detail{}, "h2", 10, 1)

		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		rec := httptest.NewRecorder()
		h.ListOpenAEVScenarios(rec, httptest.NewRequest(http.MethodGet, "/api/openaev/scenarios", nil))

		var out []map[string]any
		json.Unmarshal(rec.Body.Bytes(), &out)
		for _, sc := range out {
			if sc["OpenAEVScenarioID"] == "sc-filter-2" {
				t.Error("default (no ?type=) must not include an exercise-sourced row")
			}
		}
	})
}

func TestListOpenAEVScenarios_TypeExercise_FiltersToExercises(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		db.EnsureContentSchema(context.Background(), pool)
		store := openaev.NewSQLStore(pool)
		store.Upsert(context.Background(), openaev.Scenario{OpenAEVScenarioID: "sc-filter-3", Name: "Scn", SourceType: "scenario"}, openaev.Detail{}, "h3", 10, 1)
		store.Upsert(context.Background(), openaev.Scenario{OpenAEVScenarioID: "sc-filter-4", Name: "Exc", SourceType: "exercise"}, openaev.Detail{}, "h4", 10, 1)

		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		rec := httptest.NewRecorder()
		h.ListOpenAEVScenarios(rec, httptest.NewRequest(http.MethodGet, "/api/openaev/scenarios?type=exercise", nil))

		var out []map[string]any
		json.Unmarshal(rec.Body.Bytes(), &out)
		found := false
		for _, sc := range out {
			if sc["OpenAEVScenarioID"] == "sc-filter-4" {
				found = true
			}
			if sc["OpenAEVScenarioID"] == "sc-filter-3" {
				t.Error("?type=exercise must not include a scenario-sourced row")
			}
		}
		if !found {
			t.Error("?type=exercise must include the exercise-sourced row")
		}
	})
}
```

Add `"github.com/audspect/bas/internal/openaev"` to this test file's imports if not already present (check the existing import block first).

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/api/... -run TestListOpenAEVScenarios_DefaultsToScenarioType -run TestListOpenAEVScenarios_TypeExercise -v`
Expected: FAIL (both currently return every row — `ListOpenAEVScenarios` hardcodes `"scenario"` from Task 1 Step 8, ignoring any query param)

- [ ] **Step 3: Add the query param**

In `orchestrator/internal/api/openaev_handlers.go`, replace `ListOpenAEVScenarios`:

```go
// GET /api/openaev/scenarios — Viewer+. ?type=scenario|exercise filters by
// source; defaults to "scenario", preserving pre-Exercise-sync behavior for
// every existing caller.
func (h *Handler) ListOpenAEVScenarios(w http.ResponseWriter, r *http.Request) {
	sourceType := r.URL.Query().Get("type")
	if sourceType == "" {
		sourceType = "scenario"
	}
	store := openaev.NewSQLStore(h.db)
	scenarios, err := store.List(r.Context(), sourceType)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if scenarios == nil {
		scenarios = []openaev.Scenario{}
	}
	respond(w, scenarios)
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/api/... -run TestListOpenAEVScenarios -v`
Expected: PASS (all `TestListOpenAEVScenarios_*` tests, including the pre-existing `TestListOpenAEVScenarios_EmptyByDefault`)

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/api/openaev_handlers.go orchestrator/internal/api/openaev_handlers_test.go
git commit -m "feat(openaev): add ?type= filter to GET /api/openaev/scenarios"
```

---

### Task 7: Frontend — "OpenAEV Exercises" card + sync-count badge

**Files:**
- Modify: `orchestrator/wwwroot/index.html` (tab HTML ~line 3348-3380, `loadOpenAEVConfig`/`loadOpenAEVScenarios`/`loadExercisesTab` ~line 5716-5860)

**Interfaces:**
- Consumes: `GET /api/openaev/scenarios?type=exercise` (Task 6), `GET /api/openaev/status`'s new `lastSyncCreated`/`lastSyncUpdated`/`lastSyncSkipped`/`lastSyncErrored` fields (Task 5). Reuses existing `x()`, `openOpenAEVDetail(id)`, `createPlanFromOpenAEV(id)` unchanged.
- Produces: a second table `#openaev-exercises-body` / empty-state `#openaev-exercises-empty`, populated by a parametrized `loadOpenAEVScenarios`.

- [ ] **Step 1: Add the "OpenAEV Exercises" card to the tab HTML**

In `orchestrator/wwwroot/index.html`, immediately after the existing "OpenAEV Scenarios" card's closing `</div>` (~line 3359, right before the "Exercise Plans" card):

```html
        <div class="card" style="margin-bottom:1rem;padding:1rem 1.2rem">
          <div class="card-title">OpenAEV Exercises</div>
          <div class="tbl-wrap" style="margin-top:0.5rem">
            <table id="openaev-exercises-table">
              <thead><tr><th>Name</th><th>Category</th><th>Severity</th><th>Techniques</th><th>Injects</th><th>Synced</th></tr></thead>
              <tbody id="openaev-exercises-body"></tbody>
            </table>
          </div>
          <div id="openaev-exercises-empty" class="empty" style="display:none">No exercises synced yet.</div>
        </div>
```

- [ ] **Step 2: Parametrize `loadOpenAEVScenarios` and call it for both types**

In `orchestrator/wwwroot/index.html`, replace `loadOpenAEVScenarios`:

```js
function loadOpenAEVScenarios(type, bodyId, emptyId) {
  type = type || 'scenario';
  bodyId = bodyId || 'openaev-scenarios-body';
  emptyId = emptyId || 'openaev-scenarios-empty';
  apicall('/api/openaev/scenarios?type=' + encodeURIComponent(type)).then(function(list) {
    var body = document.getElementById(bodyId);
    var empty = document.getElementById(emptyId);
    if (!list || !list.length) {
      body.innerHTML = '';
      empty.style.display = 'block';
      return;
    }
    empty.style.display = 'none';
    body.innerHTML = list.map(function(sc) {
      return '<tr style="cursor:pointer" onclick="openOpenAEVDetail(\'' + x(sc.OpenAEVScenarioID) + '\')">' +
        '<td>' + x(sc.Name) + '</td>' +
        '<td>' + x(sc.Category) + '</td>' +
        '<td>' + x(sc.Severity) + '</td>' +
        '<td>' + (sc.TechniqueIDs || []).length + '</td>' +
        '<td>' + sc.InjectsCount + '</td>' +
        '<td class="tiny muted">' + x(sc.SourceUpdatedAt || '') + '</td>' +
        '</tr>';
    }).join('');
  }).catch(function() {});
}
```

Find `loadExercisesTab` (~line 5855) and update its call from `loadOpenAEVScenarios();` to:

```js
  loadOpenAEVScenarios('scenario', 'openaev-scenarios-body', 'openaev-scenarios-empty');
  loadOpenAEVScenarios('exercise', 'openaev-exercises-body', 'openaev-exercises-empty');
```

- [ ] **Step 3: Show sync-result counts in the status badge**

In `orchestrator/wwwroot/index.html`, inside `loadOpenAEVConfig` (~line 5743-5748), replace:

```js
  apicall('/api/openaev/status').then(function(s) {
    var badge = document.getElementById('openaev-status-badge');
    var color = s.lastSyncStatus === 'ok' ? apColor(100) : s.lastSyncStatus === 'error' ? apColor(0) : 'var(--muted)';
    badge.textContent = x(s.lastSyncStatus || 'never');
    badge.style.color = color;
  }).catch(function() {});
```

with:

```js
  apicall('/api/openaev/status').then(function(s) {
    var badge = document.getElementById('openaev-status-badge');
    var color = s.lastSyncStatus === 'ok' ? apColor(100) : s.lastSyncStatus === 'error' ? apColor(0) : 'var(--muted)';
    var label = s.lastSyncStatus || 'never';
    if (s.lastSyncStatus === 'ok') {
      label += ' — ' + (s.lastSyncCreated || 0) + ' created, ' + (s.lastSyncUpdated || 0) + ' updated';
      if (s.lastSyncSkipped) label += ', ' + s.lastSyncSkipped + ' skipped';
      if (s.lastSyncErrored) label += ', ' + s.lastSyncErrored + ' errored';
    }
    badge.textContent = x(label);
    badge.style.color = color;
  }).catch(function() {});
```

- [ ] **Step 4: Verify JS syntax**

Extract every `<script>` block from `orchestrator/wwwroot/index.html` and run `node --check` against the concatenated output (see this session's established convention — write the extraction to a scratch `.js` file first, since `node --check` requires a real file path).

Run (PowerShell, absolute paths — Windows `node.exe` misresolves `/c/...`-style unix paths):
```powershell
node -e "const fs=require('fs'); const html=fs.readFileSync('orchestrator/wwwroot/index.html','utf8'); const scripts=[...html.matchAll(/<script>([\s\S]*?)<\/script>/g)].map(m=>m[1]); fs.writeFileSync('<scratchpad>/check.js', scripts.join('\n;\n'));"
node --check "<scratchpad>/check.js"
```
Expected: no output (exit code 0)

- [ ] **Step 5: Commit**

```bash
git add orchestrator/wwwroot/index.html
git commit -m "feat(ui): add OpenAEV Exercises card and sync-result counts in status badge"
```

---

## Final Verification

- [ ] Run the full Go test suite: `go test ./... -v` (or `go test ./... -short` if Docker/Postgres isn't available in the execution environment — note which mode ran, since `-short` skips every DB-backed test added in Tasks 1, 5, 6)
- [ ] Run `go build ./...` — confirms `cmd/server/main.go` compiles with the `CompositeProvider` wiring
- [ ] Re-run the Step 4 JS syntax check from Task 7 one final time against the fully-edited file
- [ ] Push: `git push` (per this session's standing convention — push immediately after every commit; if committing task-by-task, push after each, not just at the end)
