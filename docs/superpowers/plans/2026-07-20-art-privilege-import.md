# ART Privilege-Tier Import Fix Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the ART content-import gap where Atomic Red Team's native `executor.elevation_required` field is silently dropped during ingestion, so every ART-sourced technique (the platform's largest technique source) currently reports as "Legacy (unannotated)" in privilege-tier coverage and executive reports regardless of whether it actually requires elevation.

**Architecture:** Map ART's raw boolean into the existing framework-agnostic `scenario.PrivSpec` model at the exact point this codebase already normalizes ART content (`normalizeAtomic` in `internal/scenario/content_import.go`) — via one small, clearly-named ART-specific mapping function (`mapARTElevation`), so nothing downstream of that boundary ever sees "elevation_required" again, only the normalized tier. Preserve the raw upstream signal alongside the normalized one as provenance (`original_elevation_required`), in case ART's semantics change later. Because this importer is idempotent via a per-technique content-hash skip, bump a per-technique `import_version` column so every already-seeded technique is automatically re-normalized exactly once on the next boot after this ships — no manual reseed, matching this codebase's existing convention of auto-applying idempotent migrations at startup.

**Tech Stack:** Go, `gopkg.in/yaml.v3` (ART YAML parsing), Postgres (`art_atomic_raw`/`art_atomic_tests`), `pgx/v5`.

## Global Constraints

- **Framework-agnostic core.** The engine (`ScenarioStep`, `scenario.PrivSpec`, reporting, variant coverage) must never learn about ART specifically. All ART-specific logic (the raw `elevation_required` field, the `mapARTElevation` function) stays inside `internal/scenario/art.go`/`content_import.go` — the ART-specific normalization boundary this codebase already has. A future importer for a different framework (a different raw signal — `required_integrity`, `requires_sudo`, `run_as`, etc.) gets its own `mapXyzElevation`-style function that converges on the same `PrivSpec`; nothing else changes.
- **Preserve provenance.** Store both the normalized tier (`requires_priv`) and the raw upstream signal (`original_elevation_required`) — never discard the original once normalized.
- **Auto-reimport, not a prompt.** This codebase's own convention (`EnsureSchema`/`EnsureContentSchema`) is to auto-apply idempotent migrations silently on every boot — never a "would you like to rebuild?" prompt anywhere in the app. The importer-versioning fix follows that same convention: bumping `currentARTImportVersion` makes stale rows re-import automatically on next boot, with zero admin action required.
- **`PreferredPriv` is intentionally not added as a new field.** The wire-facing runtime type (`ScenarioStep.RequiresPriv string`, `types.go:254`) already deliberately collapses `PrivSpec.Minimum`/`.Preferred` down to one effective tier via `PrivSpec.Effective()` before anything reaches the agent — this is pre-existing architecture, not something this fix changes. ART's own raw signal (`elevation_required`) is a single boolean anyway, so there is no minimum/preferred distinction to normalize from ART in the first place; `mapARTElevation` only ever sets `PrivSpec.Minimum`. `ExecutedAs` is also untouched — it's populated by the agent at run time from whatever `RequiresPriv` it was actually sent, entirely independent of where that value originated, so it already works correctly once `RequiresPriv` is populated (Task 4) — nothing to change there.
- **Provenance field mapping.** Of the three fields in the "keep the original metadata" example (`Source`, `OriginalExecutor`, `OriginalElevationRequired`), only `OriginalElevationRequired` is new. `art_atomic_tests.framework` already stores `'art'` (`Source`) and `art_atomic_tests.executor` already stores the resolved executor (`powershell`/`cmd`/`bash`) (`OriginalExecutor`) — both added unconditionally by the existing importer, unrelated to this fix. Duplicating them into new columns would be redundant; only the genuinely new raw signal (`original_elevation_required`) gets a new column.
- **No changes to the execution engine, agent wire protocol, reporting templates, or variant coverage system.** `ScenarioStep.RequiresPriv string` already exists and is already read by all of those; this plan only makes sure ART-sourced steps actually populate it.
- **Docker Desktop is available on Windows** (confirmed working this session — see the `project_docker_windows` memory). Container-backed tests run directly on Windows; no VM needed.
- Run all `go` commands from `orchestrator/`. Commit to both `orchestrator/wwwroot/index.html`-style hardlink pairs does NOT apply here — these are pure `.go` files, single tracked path each.

---

### Task 1: Schema migration — add the three new columns

**Files:**
- Modify: `orchestrator/internal/db/content_schema.go:45-67` (the `art_atomic_raw`/`art_atomic_tests` `CREATE TABLE` block)

**Interfaces:**
- Produces: `art_atomic_raw.import_version int NOT NULL DEFAULT 1` (existing rows are tagged version 1 — "before privilege mapping existed" — via the column default, satisfying the re-import trigger without a data backfill statement). `art_atomic_tests.requires_priv text NOT NULL DEFAULT ''` (normalized effective tier: `''` \| `'user'` \| `'admin'`). `art_atomic_tests.original_elevation_required boolean NOT NULL DEFAULT false` (raw upstream provenance).

- [ ] **Step 1: Add the idempotent `ALTER TABLE` statements**

Find the statement list in `EnsureContentSchema` (the `[]string` migration slice `content_schema.go` builds) and add three new entries immediately after the existing `art_atomic_tests` `CREATE TABLE` block (after the line `CREATE INDEX IF NOT EXISTS idx_atomic_tests_technique ON art_atomic_tests(technique_id)`, which follows the `CREATE TABLE IF NOT EXISTS art_atomic_tests (...)` statement):

```go
		`ALTER TABLE art_atomic_raw ADD COLUMN IF NOT EXISTS import_version int NOT NULL DEFAULT 1`,
		// requires_priv is the normalized effective privilege tier ('' | 'user' | 'admin'),
		// derived from the framework's raw elevation signal by the importer's
		// normalization layer (see mapARTElevation in internal/scenario/art.go).
		// original_elevation_required preserves ART's raw upstream boolean as
		// provenance, independent of how this platform currently interprets it.
		`ALTER TABLE art_atomic_tests ADD COLUMN IF NOT EXISTS requires_priv text NOT NULL DEFAULT ''`,
		`ALTER TABLE art_atomic_tests ADD COLUMN IF NOT EXISTS original_elevation_required boolean NOT NULL DEFAULT false`,
```

- [ ] **Step 2: Verify the migration applies cleanly**

Run: `cd orchestrator && go build ./... && go vet ./internal/db/...`
Expected: clean (no output).

- [ ] **Step 3: Commit**

```bash
git add orchestrator/internal/db/content_schema.go
git commit -m "feat(art): schema for privilege-tier import + importer versioning"
git push
```

---

### Task 2: Normalization layer — map ART's raw signal into PrivSpec

**Files:**
- Modify: `orchestrator/internal/scenario/art.go:26-41` (`artAtomicTest`/`artExecutor` structs)
- Modify: `orchestrator/internal/scenario/content_import.go:25-110` (`normalizedTest` struct, `normalizeAtomic`)
- Test: `orchestrator/internal/scenario/content_import_test.go`

**Interfaces:**
- Consumes: `scenario.PrivSpec` (already exists, `types.go:25-28`, fields `Minimum`/`Preferred string`, method `Effective() string`).
- Produces: `mapARTElevation(required bool) PrivSpec` — the ART-specific normalizer function. `normalizedTest.RequiresPriv PrivSpec` and `normalizedTest.OriginalElevationRequired bool` — consumed by Task 3.

- [ ] **Step 1: Write the failing unit tests**

Add to `orchestrator/internal/scenario/content_import_test.go` (same file as the existing `normalizeAtomic` tests, same package `scenario`, no new imports needed):

```go
func TestMapARTElevation(t *testing.T) {
	if got := mapARTElevation(true); got.Effective() != "admin" {
		t.Errorf("mapARTElevation(true) = %q, want admin", got.Effective())
	}
	if got := mapARTElevation(false); got.Effective() != "user" {
		t.Errorf("mapARTElevation(false) = %q, want user", got.Effective())
	}
}

const elevationAtomicYAML = `
attack_technique: T1548.002
display_name: Bypass UAC
atomic_tests:
  - name: Elevated test
    supported_platforms:
      - windows
    executor:
      name: powershell
      command: whoami
      elevation_required: true
  - name: Non-elevated test
    supported_platforms:
      - windows
    executor:
      name: powershell
      command: whoami
`

func TestNormalizeAtomic_ElevationRequired(t *testing.T) {
	_, _, tests, err := normalizeAtomic([]byte(elevationAtomicYAML))
	if err != nil {
		t.Fatalf("normalizeAtomic: %v", err)
	}
	if len(tests) != 2 {
		t.Fatalf("got %d tests, want 2", len(tests))
	}
	elevated, plain := tests[0], tests[1]
	if elevated.RequiresPriv.Effective() != "admin" {
		t.Errorf("elevated test RequiresPriv = %q, want admin", elevated.RequiresPriv.Effective())
	}
	if !elevated.OriginalElevationRequired {
		t.Error("elevated test OriginalElevationRequired = false, want true")
	}
	if plain.RequiresPriv.Effective() != "user" {
		t.Errorf("plain test RequiresPriv = %q, want user", plain.RequiresPriv.Effective())
	}
	if plain.OriginalElevationRequired {
		t.Error("plain test OriginalElevationRequired = true, want false")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/scenario/... -run 'TestMapARTElevation|TestNormalizeAtomic_ElevationRequired' -v`
Expected: FAIL — `mapARTElevation` and `normalizedTest.RequiresPriv`/`.OriginalElevationRequired` don't exist yet (compile error).

- [ ] **Step 3: Add `elevation_required` to the raw ART parser struct**

In `orchestrator/internal/scenario/art.go`, the current struct:

```go
type artExecutor struct {
	Name           string `yaml:"name"`
	Command        string `yaml:"command"`
	CleanupCommand string `yaml:"cleanup_command"`
}
```

becomes:

```go
type artExecutor struct {
	Name              string `yaml:"name"`
	Command           string `yaml:"command"`
	CleanupCommand    string `yaml:"cleanup_command"`
	ElevationRequired bool   `yaml:"elevation_required"`
}
```

- [ ] **Step 4: Add the normalization-layer mapping function**

Immediately after the `artExecutor` struct in `orchestrator/internal/scenario/art.go`, add:

```go
// mapARTElevation translates Atomic Red Team's raw executor.elevation_required
// boolean into this platform's framework-agnostic privilege tier (PrivSpec).
// This is the ART-specific half of the import normalization boundary —
// nothing downstream of normalizeAtomic ever sees "elevation_required" again,
// only PrivSpec. A future importer for a different framework (a different raw
// signal shape — required_integrity, requires_sudo, run_as, ...) gets its own
// mapXyzElevation function that converges on the same PrivSpec, keeping the
// rest of the engine source-agnostic.
func mapARTElevation(required bool) PrivSpec {
	if required {
		return PrivSpec{Minimum: "admin"}
	}
	return PrivSpec{Minimum: "user"}
}
```

- [ ] **Step 5: Add the two new fields to `normalizedTest`**

In `orchestrator/internal/scenario/content_import.go`, the current struct:

```go
type normalizedTest struct {
	Index            int
	Name             string
	Executor         string
	Command          string
	Cleanup          string
	Platform         string
	TimeoutSec       int
	RequiredPayloads []string
}
```

becomes:

```go
type normalizedTest struct {
	Index                      int
	Name                       string
	Executor                   string
	Command                    string
	Cleanup                    string
	Platform                   string
	TimeoutSec                 int
	RequiredPayloads           []string
	RequiresPriv               PrivSpec
	OriginalElevationRequired  bool
}
```

- [ ] **Step 6: Populate the new fields in both `normalizeAtomic` loops**

In the Windows loop:

```go
		tests = append(tests, normalizedTest{
			Index: i, Name: name, Executor: executor,
			Command: cmd, Cleanup: cleanup, Platform: "windows",
			TimeoutSec: 120, RequiredPayloads: required,
		})
```

becomes:

```go
		tests = append(tests, normalizedTest{
			Index: i, Name: name, Executor: executor,
			Command: cmd, Cleanup: cleanup, Platform: "windows",
			TimeoutSec: 120, RequiredPayloads: required,
			RequiresPriv:              mapARTElevation(test.Executor.ElevationRequired),
			OriginalElevationRequired: test.Executor.ElevationRequired,
		})
```

And in the Linux/macOS loop, the equivalent block:

```go
		tests = append(tests, normalizedTest{
			Index: i, Name: name, Executor: "bash",
			Command: cmd, Cleanup: cleanup, Platform: platform,
			TimeoutSec: 120, RequiredPayloads: required,
		})
```

becomes:

```go
		tests = append(tests, normalizedTest{
			Index: i, Name: name, Executor: "bash",
			Command: cmd, Cleanup: cleanup, Platform: platform,
			TimeoutSec: 120, RequiredPayloads: required,
			RequiresPriv:              mapARTElevation(test.Executor.ElevationRequired),
			OriginalElevationRequired: test.Executor.ElevationRequired,
		})
```

- [ ] **Step 7: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/scenario/... -run 'TestMapARTElevation|TestNormalizeAtomic_ElevationRequired|TestNormalizeAtomicAllPlatforms|TestNormalizeAtomicMissingTechnique' -v`
Expected: all 4 tests PASS (the two pre-existing tests must still pass unmodified — this step is a regression check).

- [ ] **Step 8: Commit**

```bash
git add orchestrator/internal/scenario/art.go orchestrator/internal/scenario/content_import.go orchestrator/internal/scenario/content_import_test.go
git commit -m "feat(art): normalize elevation_required into framework-agnostic PrivSpec"
git push
```

---

### Task 3: Importer versioning — auto-reimport already-seeded techniques

**Files:**
- Modify: `orchestrator/internal/scenario/content_import.go` (`upsertTechnique`, `importAtomics`)
- Test: `orchestrator/internal/scenario/content_import_test.go`

**Interfaces:**
- Consumes: `normalizedTest.RequiresPriv`/`.OriginalElevationRequired` (Task 2).
- Produces: `const currentARTImportVersion = 2`. `shouldReimportTechnique(existingHash, newHash string, existingVersion int) bool` — a small pure decision function, independently unit-testable without a database. `upsertTechnique` now writes `requires_priv`/`original_elevation_required` to `art_atomic_tests` and stamps `import_version` on `art_atomic_raw`.

**Why a pure function:** `internal/scenario` has no container-backed test infrastructure today (no `sharedDB`/`TestMain` — confirmed by grep, zero matches). Rather than add a new testcontainers harness to this package just to test one decision, the version/hash comparison is extracted into a small pure function that's fully unit-testable on its own; the actual SQL writes stay thin wrappers around it, covered by Task 4's DB-backed test (in `internal/api`, which already has this infrastructure) and the manual boot-smoke-test in Task 5.

- [ ] **Step 1: Write the failing test**

Add to `orchestrator/internal/scenario/content_import_test.go`:

```go
func TestShouldReimportTechnique(t *testing.T) {
	cases := []struct {
		name             string
		existingHash     string
		newHash          string
		existingVersion  int
		want             bool
	}{
		{"unseen technique", "", "abc", 0, true},
		{"content changed, version current", "abc", "def", currentARTImportVersion, true},
		{"content unchanged, version stale", "abc", "abc", currentARTImportVersion - 1, true},
		{"content unchanged, version current — skip", "abc", "abc", currentARTImportVersion, false},
		{"content unchanged, version newer than current — skip", "abc", "abc", currentARTImportVersion + 1, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := shouldReimportTechnique(c.existingHash, c.newHash, c.existingVersion)
			if got != c.want {
				t.Errorf("shouldReimportTechnique(%q,%q,%d) = %v, want %v",
					c.existingHash, c.newHash, c.existingVersion, got, c.want)
			}
		})
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/scenario/... -run TestShouldReimportTechnique -v`
Expected: FAIL — `shouldReimportTechnique` and `currentARTImportVersion` don't exist yet (compile error).

- [ ] **Step 3: Add the version constant and decision function**

In `orchestrator/internal/scenario/content_import.go`, immediately before `importAtomics`, add:

```go
// currentARTImportVersion identifies the ART importer's normalization format.
// Bump this whenever normalizeAtomic starts populating a new field from raw
// ART data — every already-seeded technique will then be automatically
// re-normalized and re-upserted on the next boot, even though its underlying
// YAML content hash hasn't changed. v1: original import (no privilege data).
// v2: adds requires_priv / original_elevation_required (this fix).
const currentARTImportVersion = 2

// shouldReimportTechnique reports whether a technique needs a fresh
// normalize-and-upsert pass: either its raw YAML content changed, or it was
// last imported by an older importer format and needs upgrading even though
// the content itself is unchanged.
func shouldReimportTechnique(existingHash, newHash string, existingVersion int) bool {
	return existingHash != newHash || existingVersion < currentARTImportVersion
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd orchestrator && go test ./internal/scenario/... -run TestShouldReimportTechnique -v`
Expected: PASS (all 5 subtests).

- [ ] **Step 5: Wire `shouldReimportTechnique` into `importAtomics`'s skip check**

The current check in `importAtomics`:

```go
		var existing string
		_ = pool.QueryRow(ctx,
			`SELECT content_hash FROM art_atomic_raw WHERE technique_id = $1`, techniqueID,
		).Scan(&existing)
		if existing == hash {
			count++ // present and current
			continue
		}
```

becomes:

```go
		var existingHash string
		var existingVersion int
		_ = pool.QueryRow(ctx,
			`SELECT content_hash, import_version FROM art_atomic_raw WHERE technique_id = $1`, techniqueID,
		).Scan(&existingHash, &existingVersion)
		if !shouldReimportTechnique(existingHash, hash, existingVersion) {
			count++ // present, current content, and imported at the current parser version
			continue
		}
```

- [ ] **Step 6: Write privilege data + stamp import_version in `upsertTechnique`**

The current `art_atomic_raw` upsert:

```go
	if _, err := tx.Exec(ctx,
		`INSERT INTO art_atomic_raw (technique_id, yaml, content_hash, updated_at)
		 VALUES ($1, $2, $3, NOW())
		 ON CONFLICT (technique_id) DO UPDATE SET
		   yaml = EXCLUDED.yaml, content_hash = EXCLUDED.content_hash, updated_at = NOW()`,
		techniqueID, rawYAML, hash,
	); err != nil {
		return fmt.Errorf("raw: %w", err)
	}
```

becomes:

```go
	if _, err := tx.Exec(ctx,
		`INSERT INTO art_atomic_raw (technique_id, yaml, content_hash, import_version, updated_at)
		 VALUES ($1, $2, $3, $4, NOW())
		 ON CONFLICT (technique_id) DO UPDATE SET
		   yaml = EXCLUDED.yaml, content_hash = EXCLUDED.content_hash,
		   import_version = EXCLUDED.import_version, updated_at = NOW()`,
		techniqueID, rawYAML, hash, currentARTImportVersion,
	); err != nil {
		return fmt.Errorf("raw: %w", err)
	}
```

And the `art_atomic_tests` insert (still inside `upsertTechnique`'s per-test loop):

```go
		if _, err := tx.Exec(ctx,
			`INSERT INTO art_atomic_tests
			   (technique_id, test_index, name, executor, command, cleanup, platform, timeout_sec, required_payloads, framework, updated_at)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'art', NOW())`,
			techniqueID, t.Index, t.Name, t.Executor, t.Command, t.Cleanup, t.Platform, t.TimeoutSec, payloads,
		); err != nil {
			return fmt.Errorf("insert test %d: %w", t.Index, err)
		}
```

becomes:

```go
		if _, err := tx.Exec(ctx,
			`INSERT INTO art_atomic_tests
			   (technique_id, test_index, name, executor, command, cleanup, platform, timeout_sec, required_payloads, framework, requires_priv, original_elevation_required, updated_at)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'art', $10, $11, NOW())`,
			techniqueID, t.Index, t.Name, t.Executor, t.Command, t.Cleanup, t.Platform, t.TimeoutSec, payloads,
			t.RequiresPriv.Effective(), t.OriginalElevationRequired,
		); err != nil {
			return fmt.Errorf("insert test %d: %w", t.Index, err)
		}
```

- [ ] **Step 7: Verify the package builds and all scenario tests pass**

Run: `cd orchestrator && go build ./... && go vet ./internal/scenario/... && go test ./internal/scenario/... -v`
Expected: clean build/vet; all tests PASS, including the pre-existing `TestNormalizeAtomicAllPlatforms`/`TestNormalizeAtomicMissingTechnique` (regression check) and the new ones from this task and Task 2.

- [ ] **Step 8: Commit**

```bash
git add orchestrator/internal/scenario/content_import.go orchestrator/internal/scenario/content_import_test.go
git commit -m "feat(art): auto-reimport stale techniques via per-technique import_version"
git push
```

---

### Task 4: Read path — flow `requires_priv` into runtime `ScenarioStep`

**Files:**
- Modify: `orchestrator/internal/scenario/art.go:80-118` (`NewARTStoreFromDB`)
- Test: `orchestrator/internal/api/variant_dispatch_test.go`

**Interfaces:**
- Consumes: `art_atomic_tests.requires_priv` (Task 1/3). `ScenarioStep.RequiresPriv string` (already exists, `types.go:254` — no change to its type).
- Produces: `NewARTStoreFromDB` now populates `ScenarioStep.RequiresPriv` from the DB row instead of leaving it at its zero value `""`.

**Why the test lives in `internal/api`:** `internal/scenario` has no testcontainers harness (see Task 3). `internal/api/variant_dispatch_test.go` already has one (`sharedDB.RunWithPool`) and already tests `NewARTStoreFromDB` end-to-end against a real Postgres (`TestGenerateVariants_FromARTStoreFallback`) — this task's test extends that exact, already-proven pattern.

- [ ] **Step 1: Write the failing test**

Add to `orchestrator/internal/api/variant_dispatch_test.go` (same package `api`, same imports already present — `context`, `pgxpool`, `scenario`, `testing`):

```go
// TestARTStoreFromDB_CarriesRequiresPriv pins the read side of the ART
// privilege-import fix: a technique seeded with requires_priv='admin' must
// produce a ScenarioStep with RequiresPriv == "admin", proving the value
// actually reaches the runtime step the agent receives, not just the DB row.
func TestARTStoreFromDB_CarriesRequiresPriv(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		if _, err := pool.Exec(ctx,
			`INSERT INTO techniques (technique_id, name, tactic) VALUES ('T1548.777','Privileged Test','privilege-escalation')
			 ON CONFLICT (technique_id) DO NOTHING`); err != nil {
			t.Fatalf("seed technique: %v", err)
		}
		if _, err := pool.Exec(ctx,
			`INSERT INTO art_atomic_tests (technique_id, test_index, name, executor, command, requires_priv, original_elevation_required)
			 VALUES ('T1548.777', 0, 'elevated-step', 'powershell', 'whoami', 'admin', true)`); err != nil {
			t.Fatalf("seed art_atomic_tests: %v", err)
		}

		store, err := scenario.NewARTStoreFromDB(ctx, pool, nil)
		if err != nil {
			t.Fatalf("NewARTStoreFromDB: %v", err)
		}
		steps := store.GetSteps("T1548.777")
		if len(steps) != 1 {
			t.Fatalf("got %d steps, want 1", len(steps))
		}
		if steps[0].RequiresPriv != "admin" {
			t.Errorf("RequiresPriv = %q, want admin", steps[0].RequiresPriv)
		}
	})
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/api/... -run TestARTStoreFromDB_CarriesRequiresPriv -v`
Expected: FAIL — `steps[0].RequiresPriv` is `""`, not `"admin"` (the read path doesn't select/scan/set it yet).

- [ ] **Step 3: Update `NewARTStoreFromDB` to select and set `RequiresPriv`**

The current function in `orchestrator/internal/scenario/art.go`:

```go
func NewARTStoreFromDB(ctx context.Context, pool *pgxpool.Pool, payloads *PayloadStore) (*ARTStore, error) {
	s := &ARTStore{steps: make(map[string][]ScenarioStep), payloads: payloads}
	rows, err := pool.Query(ctx,
		`SELECT technique_id, name, executor, command, cleanup, timeout_sec, required_payloads, platform
		   FROM art_atomic_tests
		  ORDER BY technique_id, test_index`)
	if err != nil {
		return nil, fmt.Errorf("load atomic tests: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var tech, name, executor, command, cleanup, platform string
		var timeout int
		var required []string
		if err := rows.Scan(&tech, &name, &executor, &command, &cleanup, &timeout, &required, &platform); err != nil {
			return nil, err
		}
		tech = strings.ToUpper(tech)
		if timeout <= 0 {
			timeout = 120
		}
		if platform == "" {
			platform = "windows"
		}
		s.steps[tech] = append(s.steps[tech], ScenarioStep{
			TaskID:           TaskID(tech, name),
			TechniqueID:      tech,
			Name:             name,
			Framework:        "art",
			Platform:         platform,
			Executor:         executor,
			Command:          command,
			TimeoutSec:       timeout,
			Cleanup:          cleanup,
			requiredPayloads: required,
		})
	}
	return s, rows.Err()
}
```

becomes:

```go
func NewARTStoreFromDB(ctx context.Context, pool *pgxpool.Pool, payloads *PayloadStore) (*ARTStore, error) {
	s := &ARTStore{steps: make(map[string][]ScenarioStep), payloads: payloads}
	rows, err := pool.Query(ctx,
		`SELECT technique_id, name, executor, command, cleanup, timeout_sec, required_payloads, platform, requires_priv
		   FROM art_atomic_tests
		  ORDER BY technique_id, test_index`)
	if err != nil {
		return nil, fmt.Errorf("load atomic tests: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var tech, name, executor, command, cleanup, platform, requiresPriv string
		var timeout int
		var required []string
		if err := rows.Scan(&tech, &name, &executor, &command, &cleanup, &timeout, &required, &platform, &requiresPriv); err != nil {
			return nil, err
		}
		tech = strings.ToUpper(tech)
		if timeout <= 0 {
			timeout = 120
		}
		if platform == "" {
			platform = "windows"
		}
		s.steps[tech] = append(s.steps[tech], ScenarioStep{
			TaskID:           TaskID(tech, name),
			TechniqueID:      tech,
			Name:             name,
			Framework:        "art",
			Platform:         platform,
			Executor:         executor,
			Command:          command,
			TimeoutSec:       timeout,
			Cleanup:          cleanup,
			RequiresPriv:     requiresPriv,
			requiredPayloads: required,
		})
	}
	return s, rows.Err()
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd orchestrator && go test ./internal/api/... -run TestARTStoreFromDB_CarriesRequiresPriv -v`
Expected: PASS.

- [ ] **Step 5: Run the full existing ART/variant-related test suite to confirm no regression**

Run: `cd orchestrator && go test ./internal/api/... -run 'TestGenerateVariants' -v`
Expected: all PASS, including `TestGenerateVariants_FromARTStoreFallback` and `TestGenerateVariants_ARTStoreNoStepsForTechnique` (both pre-existing, must be unaffected).

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/scenario/art.go orchestrator/internal/api/variant_dispatch_test.go
git commit -m "feat(art): NewARTStoreFromDB carries requires_priv into runtime ScenarioStep"
git push
```

---

### Task 5: Full verification

**Files:** none — verification only.

- [ ] **Step 1: Full build/vet/gofmt**

Run: `cd orchestrator && go build ./... && go vet ./... && gofmt -l internal/scenario/art.go internal/scenario/content_import.go internal/scenario/content_import_test.go internal/db/content_schema.go internal/api/variant_dispatch_test.go`
Expected: build/vet clean; `gofmt -l` prints nothing.

- [ ] **Step 2: Full `internal/scenario` and `internal/api` suites**

Run: `cd orchestrator && go test ./internal/scenario/... -v && go test ./internal/api/... 2>&1 | tail -20`
Expected: `internal/scenario` fully green (unit tests only, fast). `internal/api` ends with `ok` (this package takes several minutes — see the note in `project_docker_windows` memory about full-suite runs; if anything fails, re-run that specific test in isolation before concluding it's a real regression, per that same memory's documented flake pattern).

- [ ] **Step 3: Manual boot-smoke test — confirm the version-bump actually re-imports on a real boot**

This is the one thing no Go test proves end-to-end: that a server boot against a database seeded by the *old* importer format actually upgrades itself automatically. Using the throwaway dev Postgres container and license file already set up earlier this session:

```bash
docker start bas-dev-postgres 2>/dev/null || docker run -d --name bas-dev-postgres -p 5433:5432 -e POSTGRES_PASSWORD=devpass -e POSTGRES_USER=bas_user -e POSTGRES_DB=bas_platform postgres:16-alpine
```

Wait for it to become ready (`docker exec bas-dev-postgres pg_isready -U bas_user -d bas_platform`), then boot the orchestrator exactly as before:

```bash
cd orchestrator
DATABASE_URL="postgres://bas_user:devpass@localhost:5433/bas_platform?sslmode=disable" JWT_SECRET="devsecretdevsecretdevsecretdevs" BAS_LICENSE_PATH="/tmp/dev.lic" SCENARIOS_DIR="C:\Users\Administrator\Downloads\Audspect_Cloud\scenarios" go run ./cmd/server
```

Expected in the boot log: the `[+] ART content seed:` line no longer errors on a missing atomics dir the way it did earlier this session *if* `ART_DIR`/`ART_PAYLOAD_DIR` are set — if they're still unset, that specific warning is unrelated and pre-existing, not a regression from this plan. Confirm no new errors appear around content import.

Then, with the server running, spot-check the actual data:

```bash
docker exec bas-dev-postgres psql -U bas_user -d bas_platform -c "SELECT import_version, count(*) FROM art_atomic_raw GROUP BY import_version;"
docker exec bas-dev-postgres psql -U bas_user -d bas_platform -c "SELECT requires_priv, count(*) FROM art_atomic_tests GROUP BY requires_priv;"
```

Expected: every `art_atomic_raw` row shows `import_version = 2` (or empty result if `ART_DIR` wasn't configured for this throwaway run — in that case this check is inconclusive, not failing, and the Task 4 automated test is the authoritative proof). If ART content was imported, `requires_priv` should show a real split between `user` and `admin` (not 100% empty string).

Stop the server (`Ctrl+C` or `TaskStop` on its background task) and leave the Postgres container running or remove it (`docker rm -f bas-dev-postgres`) per whether further manual testing is planned.

- [ ] **Step 4: Report results to the user**

Summarize: test results, whether the manual boot-smoke check was inconclusive (no `ART_DIR`) or confirmed, and remind that the *production* re-import happens automatically the next time a real deployment boots with this code — no manual reseed action needed there either, per the Global Constraints.
