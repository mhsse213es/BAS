# OpenAEV Connector (Module 1) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Sync OpenAEV scenario definitions into Audspect as a version-tracked, browsable content library (no execution — that's a future Exercise Engine module).

**Architecture:** New `internal/openaev` package: `Parser` (ZIP+JSON → Go structs) → `Normalizer` (→ Audspect's own `Scenario`/`Detail` types) → `Store` (Postgres upsert, hash-based change detection) → `Importer` (orchestrates provider + the above, owns retries/logging/transactions) sitting above a `ContentProvider` interface with `RESTProvider` (live OpenAEV instance) and `BundleProvider` (air-gapped manual upload) implementations. Scheduling reuses the existing `internal/connector.Scheduler`. New API endpoints under `/api/openaev/*` and a UI tab under the existing "Integrations" nav placeholder.

**Tech Stack:** Go, PostgreSQL (pgx/pgxpool), chi router, `archive/zip` + `encoding/json` stdlib, `net/http` stdlib client.

## Global Constraints

- Garble-obfuscated binary: if this ever needs to render through `html/template`, use the json-tag-map pattern, not raw struct reflection (see `internal/reporting/html.go` for precedent). This plan's API responses are plain `respond(w, ...)` JSON, so this constraint doesn't bite here — noted for awareness only.
- `gofmt -w` the exact files each task touches, then `gofmt -l` to confirm — never a whole-directory sweep.
- Every task ends with `go build ./...` and `go vet ./...` passing, and a commit + push.
- Bearer token stored in plaintext in Postgres, redacted in every API response (never echo it back, including on `GET /api/openaev/config`).
- OpenAEV's real JSON field names (confirmed against `openaev-main/` source, not guessed): `scenario_id`, `scenario_name`, `scenario_category`, `scenario_severity`, `scenario_description`, `scenario_updated_at`, `scenario_objectives`, `scenario_injects`, `scenario_tags`, `scenario_variables`, `objective_id`/`objective_title`/`objective_description`, `inject_id`/`inject_title`/`inject_attack_patterns`, `attack_pattern_external_id`/`attack_pattern_name`/`attack_pattern_platforms`, `tag_name`, `variable_key`/`variable_description`. The ZIP's main JSON entry is identified by `ZipEntry.Comment == "Scenario"` (confirmed at `openaev-main/openaev-api/.../ImportService.java:38`), **not** by a fixed filename (the real filename is `<scenarioName>.json`, which varies).

---

### Task 1: Parser — decode a bundle ZIP into Go structs

**Files:**
- Create: `orchestrator/internal/openaev/types.go`
- Create: `orchestrator/internal/openaev/parser.go`
- Create: `orchestrator/internal/openaev/parser_test.go`

**Interfaces:**
- Produces: `ParsedBundle` struct and `ParseBundle(data []byte) (*ParsedBundle, error)`, used by Task 2 (Normalizer).

- [ ] **Step 1: Write `types.go` — the shared package types every later task imports**

```go
// Package openaev syncs scenario content from Filigran's OpenAEV (Adversary
// Emulation & Validation) platform into Audspect as a version-tracked content
// library. It does not execute synced scenarios — see
// docs/superpowers/specs/2026-07-15-openaev-connector-design.md.
package openaev

import (
	"context"
	"time"
)

// ScenarioRef is a lightweight listing entry from ContentProvider.List — cheap
// to fetch, used to decide which scenarios need a full Fetch this sync.
type ScenarioRef struct {
	ID            string
	Name          string
	SourceUpdated time.Time
}

// ContentProvider retrieves raw bundle bytes. It is transport-agnostic: a
// RESTProvider fetches over HTTP, a BundleProvider wraps an uploaded file —
// neither the Importer nor the Parser cares which.
type ContentProvider interface {
	Name() string
	List(ctx context.Context) ([]ScenarioRef, error)
	Fetch(ctx context.Context, id string) ([]byte, error)
}

// ParsedBundle is the decoded contents of one OpenAEV scenario export ZIP —
// only the fields this connector actually normalizes, not OpenAEV's full schema.
type ParsedBundle struct {
	ExportVersion int               `json:"export_version"`
	Scenario      ParsedScenario    `json:"scenario_information"`
	Objectives    []ParsedObjective `json:"scenario_objectives"`
	Injects       []ParsedInject    `json:"scenario_injects"`
	Tags          []ParsedTag       `json:"scenario_tags"`
	Variables     []ParsedVariable  `json:"scenario_variables"`
}

type ParsedScenario struct {
	ID          string    `json:"scenario_id"`
	Name        string    `json:"scenario_name"`
	Description string    `json:"scenario_description"`
	Category    string    `json:"scenario_category"`
	Severity    string    `json:"scenario_severity"`
	UpdatedAt   time.Time `json:"scenario_updated_at"`
}

type ParsedObjective struct {
	ID          string `json:"objective_id"`
	Title       string `json:"objective_title"`
	Description string `json:"objective_description"`
}

type ParsedInject struct {
	ID             string                `json:"inject_id"`
	Title          string                `json:"inject_title"`
	AttackPatterns []ParsedAttackPattern `json:"inject_attack_patterns"`
}

type ParsedAttackPattern struct {
	ExternalID string   `json:"attack_pattern_external_id"`
	Name       string   `json:"attack_pattern_name"`
	Platforms  []string `json:"attack_pattern_platforms"`
}

type ParsedTag struct {
	Name string `json:"tag_name"`
}

type ParsedVariable struct {
	Key         string `json:"variable_key"`
	Description string `json:"variable_description"`
}
```

- [ ] **Step 2: Write the failing test for `ParseBundle`**

```go
// orchestrator/internal/openaev/parser_test.go
package openaev

import (
	"archive/zip"
	"bytes"
	"testing"
	"time"
)

// buildFixtureZip constructs a minimal but realistic OpenAEV export ZIP: one
// entry named "<scenarioName>.json" whose ZipEntry.Comment is "Scenario" —
// matching openaev-main's ImportService.EXPORT_ENTRY_SCENARIO convention,
// which ParseBundle must key off (not the filename).
func buildFixtureZip(t *testing.T, scenarioJSON string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	hdr := &zip.FileHeader{Name: "Ransomware Drill.json", Method: zip.Deflate}
	hdr.Comment = "Scenario"
	w, err := zw.CreateHeader(hdr)
	if err != nil {
		t.Fatalf("create zip entry: %v", err)
	}
	if _, err := w.Write([]byte(scenarioJSON)); err != nil {
		t.Fatalf("write zip entry: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close zip: %v", err)
	}
	return buf.Bytes()
}

const fixtureScenarioJSON = `{
  "export_version": 1,
  "scenario_information": {
    "scenario_id": "sc-openaev-001",
    "scenario_name": "Ransomware Drill",
    "scenario_description": "Simulated ransomware kill chain",
    "scenario_category": "ransomware",
    "scenario_severity": "high",
    "scenario_updated_at": "2026-07-10T12:00:00Z"
  },
  "scenario_objectives": [
    {"objective_id": "obj-1", "objective_title": "Detect initial access", "objective_description": "SOC must alert within 15 minutes"}
  ],
  "scenario_injects": [
    {
      "inject_id": "inj-1",
      "inject_title": "Phishing delivery",
      "inject_attack_patterns": [
        {"attack_pattern_external_id": "T1566.001", "attack_pattern_name": "Spearphishing Attachment", "attack_pattern_platforms": ["windows"]}
      ]
    },
    {
      "inject_id": "inj-2",
      "inject_title": "Encrypt files",
      "inject_attack_patterns": [
        {"attack_pattern_external_id": "T1486", "attack_pattern_name": "Data Encrypted for Impact", "attack_pattern_platforms": ["windows", "linux"]}
      ]
    }
  ],
  "scenario_tags": [{"tag_name": "ransomware"}, {"tag_name": "critical-infra"}],
  "scenario_variables": [
    {"variable_key": "target_host", "variable_description": "Primary target hostname"}
  ]
}`

func TestParseBundle_DecodesScenarioAndTechniques(t *testing.T) {
	zipBytes := buildFixtureZip(t, fixtureScenarioJSON)

	parsed, err := ParseBundle(zipBytes)
	if err != nil {
		t.Fatalf("ParseBundle: %v", err)
	}

	if parsed.Scenario.ID != "sc-openaev-001" {
		t.Errorf("scenario ID = %q, want sc-openaev-001", parsed.Scenario.ID)
	}
	if parsed.Scenario.Name != "Ransomware Drill" {
		t.Errorf("scenario name = %q, want Ransomware Drill", parsed.Scenario.Name)
	}
	wantUpdated := time.Date(2026, 7, 10, 12, 0, 0, 0, time.UTC)
	if !parsed.Scenario.UpdatedAt.Equal(wantUpdated) {
		t.Errorf("updated at = %v, want %v", parsed.Scenario.UpdatedAt, wantUpdated)
	}
	if len(parsed.Injects) != 2 {
		t.Fatalf("injects = %d, want 2", len(parsed.Injects))
	}
	if parsed.Injects[0].AttackPatterns[0].ExternalID != "T1566.001" {
		t.Errorf("first inject technique = %q, want T1566.001", parsed.Injects[0].AttackPatterns[0].ExternalID)
	}
	if len(parsed.Tags) != 2 || parsed.Tags[0].Name != "ransomware" {
		t.Errorf("tags = %+v, want [ransomware critical-infra]", parsed.Tags)
	}
}

func TestParseBundle_MissingScenarioEntry_Errors(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	// An entry with no "Scenario" comment — e.g. a stray attachment — must not
	// be mistaken for the scenario JSON.
	w, _ := zw.Create("readme.txt")
	w.Write([]byte("not a scenario"))
	zw.Close()

	if _, err := ParseBundle(buf.Bytes()); err == nil {
		t.Fatal("expected error for a bundle with no Scenario-commented entry, got nil")
	}
}

func TestParseBundle_NotAZip_Errors(t *testing.T) {
	if _, err := ParseBundle([]byte("this is not a zip file")); err == nil {
		t.Fatal("expected error for non-ZIP input, got nil")
	}
}
```

- [ ] **Step 2b: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/openaev/... -run TestParseBundle -v`
Expected: FAIL — `ParseBundle` undefined (package doesn't compile yet, `types.go` has no `ParseBundle`).

- [ ] **Step 3: Write `parser.go`**

```go
package openaev

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
)

// scenarioEntryComment is how OpenAEV's own export marks the ZIP entry that
// holds the scenario JSON — see openaev-api's ImportService.EXPORT_ENTRY_SCENARIO.
// The entry's FILENAME varies (it's "<scenarioName>.json"), so this comment is
// the only reliable way to find it.
const scenarioEntryComment = "Scenario"

// ParseBundle decodes a raw OpenAEV scenario export ZIP (as returned by
// GET /api/scenarios/{id}/export, or an air-gapped manual upload of the same
// format) into a ParsedBundle. It does not touch the database.
func ParseBundle(data []byte) (*ParsedBundle, error) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, fmt.Errorf("not a valid bundle ZIP: %w", err)
	}

	var scenarioFile *zip.File
	for _, f := range zr.File {
		if f.Comment == scenarioEntryComment {
			scenarioFile = f
			break
		}
	}
	if scenarioFile == nil {
		return nil, fmt.Errorf("bundle has no entry commented %q — not a valid OpenAEV scenario export", scenarioEntryComment)
	}

	rc, err := scenarioFile.Open()
	if err != nil {
		return nil, fmt.Errorf("open scenario entry: %w", err)
	}
	defer rc.Close()

	var parsed ParsedBundle
	if err := json.NewDecoder(rc).Decode(&parsed); err != nil {
		return nil, fmt.Errorf("decode scenario JSON: %w", err)
	}
	return &parsed, nil
}
```

Also fix `types.go` now per the Step 1 note: use `context.Context`, not `context.CTX`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/openaev/... -run TestParseBundle -v`
Expected: PASS (all three tests)

- [ ] **Step 5: Format, vet, build**

Run: `cd orchestrator && gofmt -w internal/openaev/types.go internal/openaev/parser.go internal/openaev/parser_test.go && gofmt -l internal/openaev/types.go internal/openaev/parser.go internal/openaev/parser_test.go && go build ./... && go vet ./...`
Expected: `gofmt -l` prints nothing (clean); build and vet succeed.

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/openaev/types.go orchestrator/internal/openaev/parser.go orchestrator/internal/openaev/parser_test.go
git commit -m "feat(openaev): add bundle ZIP parser"
git push
```

---

### Task 2: Normalizer — map parsed OpenAEV data to Audspect's own types

**Files:**
- Create: `orchestrator/internal/openaev/normalizer.go`
- Create: `orchestrator/internal/openaev/normalizer_test.go`

**Interfaces:**
- Consumes: `ParsedBundle` and its sub-structs from Task 1.
- Produces: `Scenario` (summary — mirrors the `openaev_scenarios` table), `Detail` (richer — becomes the `openaev_bundles.bundle` jsonb), and `Normalize(parsed *ParsedBundle) (Scenario, Detail)`, used by Task 3 (Store) and Task 5 (Importer).

- [ ] **Step 1: Add the normalized types to `types.go`**

```go
// Scenario is the normalized summary of one OpenAEV scenario — mirrors the
// openaev_scenarios table row. Kept separate from Detail so list views never
// touch the (potentially large) full bundle content.
type Scenario struct {
	OpenAEVScenarioID string
	Name              string
	Category          string
	Severity          string
	Platforms         []string
	TechniqueIDs      []string
	Tags              []string
	ObjectivesCount   int
	InjectsCount      int
	SourceUpdatedAt   time.Time
}

// Detail is the richer normalized content stored in openaev_bundles.bundle —
// everything Scenario omits, kept even though nothing consumes it yet (the
// future Exercise Engine will).
type Detail struct {
	Description string             `json:"description"`
	Objectives  []DetailObjective  `json:"objectives"`
	Injects     []DetailInject     `json:"injects"`
	Variables   []DetailVariable   `json:"variables"`
}

type DetailObjective struct {
	Title       string `json:"title"`
	Description string `json:"description"`
}

type DetailInject struct {
	Title        string   `json:"title"`
	TechniqueIDs []string `json:"techniqueIds"`
}

type DetailVariable struct {
	Key         string `json:"key"`
	Description string `json:"description"`
}
```

- [ ] **Step 2: Write the failing test**

```go
// orchestrator/internal/openaev/normalizer_test.go
package openaev

import (
	"reflect"
	"sort"
	"testing"
	"time"
)

func TestNormalize_ExtractsTechniquesPlatformsAndCounts(t *testing.T) {
	parsed := &ParsedBundle{
		Scenario: ParsedScenario{
			ID:        "sc-openaev-001",
			Name:      "Ransomware Drill",
			Category:  "ransomware",
			Severity:  "high",
			UpdatedAt: time.Date(2026, 7, 10, 12, 0, 0, 0, time.UTC),
		},
		Objectives: []ParsedObjective{
			{Title: "Detect initial access", Description: "SOC must alert within 15 minutes"},
		},
		Injects: []ParsedInject{
			{
				Title: "Phishing delivery",
				AttackPatterns: []ParsedAttackPattern{
					{ExternalID: "T1566.001", Platforms: []string{"windows"}},
				},
			},
			{
				Title: "Encrypt files",
				AttackPatterns: []ParsedAttackPattern{
					{ExternalID: "T1486", Platforms: []string{"windows", "linux"}},
				},
			},
		},
		Tags: []ParsedTag{{Name: "ransomware"}, {Name: "critical-infra"}},
		Variables: []ParsedVariable{
			{Key: "target_host", Description: "Primary target hostname"},
		},
	}

	scenario, detail := Normalize(parsed)

	if scenario.OpenAEVScenarioID != "sc-openaev-001" {
		t.Errorf("ID = %q", scenario.OpenAEVScenarioID)
	}
	if scenario.InjectsCount != 2 {
		t.Errorf("InjectsCount = %d, want 2", scenario.InjectsCount)
	}
	if scenario.ObjectivesCount != 1 {
		t.Errorf("ObjectivesCount = %d, want 1", scenario.ObjectivesCount)
	}

	wantTechniques := []string{"T1486", "T1566.001"}
	gotTechniques := append([]string{}, scenario.TechniqueIDs...)
	sort.Strings(gotTechniques)
	if !reflect.DeepEqual(gotTechniques, wantTechniques) {
		t.Errorf("TechniqueIDs = %v, want %v", gotTechniques, wantTechniques)
	}

	wantPlatforms := []string{"linux", "windows"}
	gotPlatforms := append([]string{}, scenario.Platforms...)
	sort.Strings(gotPlatforms)
	if !reflect.DeepEqual(gotPlatforms, wantPlatforms) {
		t.Errorf("Platforms = %v, want %v", gotPlatforms, wantPlatforms)
	}

	if len(detail.Injects) != 2 || detail.Injects[0].Title != "Phishing delivery" {
		t.Errorf("detail.Injects = %+v", detail.Injects)
	}
	if len(detail.Injects[0].TechniqueIDs) != 1 || detail.Injects[0].TechniqueIDs[0] != "T1566.001" {
		t.Errorf("detail.Injects[0].TechniqueIDs = %v", detail.Injects[0].TechniqueIDs)
	}
}

func TestNormalize_DedupesTechniquesAcrossInjects(t *testing.T) {
	parsed := &ParsedBundle{
		Scenario: ParsedScenario{ID: "sc-x", Name: "X"},
		Injects: []ParsedInject{
			{AttackPatterns: []ParsedAttackPattern{{ExternalID: "T1059"}}},
			{AttackPatterns: []ParsedAttackPattern{{ExternalID: "T1059"}}},
		},
	}
	scenario, _ := Normalize(parsed)
	if len(scenario.TechniqueIDs) != 1 {
		t.Errorf("TechniqueIDs = %v, want exactly one T1059 (deduped)", scenario.TechniqueIDs)
	}
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/openaev/... -run TestNormalize -v`
Expected: FAIL — `Normalize` undefined.

- [ ] **Step 4: Write `normalizer.go`**

```go
package openaev

// Normalize maps a ParsedBundle into Audspect's own Scenario (summary) and
// Detail (full content) types. Pure function — no I/O, no database.
func Normalize(parsed *ParsedBundle) (Scenario, Detail) {
	techniqueSet := map[string]bool{}
	platformSet := map[string]bool{}
	detailInjects := make([]DetailInject, 0, len(parsed.Injects))

	for _, inj := range parsed.Injects {
		injTechniques := make([]string, 0, len(inj.AttackPatterns))
		for _, ap := range inj.AttackPatterns {
			if ap.ExternalID == "" {
				continue
			}
			techniqueSet[ap.ExternalID] = true
			injTechniques = append(injTechniques, ap.ExternalID)
			for _, p := range ap.Platforms {
				platformSet[p] = true
			}
		}
		detailInjects = append(detailInjects, DetailInject{
			Title:        inj.Title,
			TechniqueIDs: injTechniques,
		})
	}

	techniqueIDs := make([]string, 0, len(techniqueSet))
	for id := range techniqueSet {
		techniqueIDs = append(techniqueIDs, id)
	}
	platforms := make([]string, 0, len(platformSet))
	for p := range platformSet {
		platforms = append(platforms, p)
	}

	tags := make([]string, 0, len(parsed.Tags))
	for _, t := range parsed.Tags {
		tags = append(tags, t.Name)
	}

	detailObjectives := make([]DetailObjective, 0, len(parsed.Objectives))
	for _, o := range parsed.Objectives {
		detailObjectives = append(detailObjectives, DetailObjective{Title: o.Title, Description: o.Description})
	}

	detailVariables := make([]DetailVariable, 0, len(parsed.Variables))
	for _, v := range parsed.Variables {
		detailVariables = append(detailVariables, DetailVariable{Key: v.Key, Description: v.Description})
	}

	scenario := Scenario{
		OpenAEVScenarioID: parsed.Scenario.ID,
		Name:              parsed.Scenario.Name,
		Category:          parsed.Scenario.Category,
		Severity:          parsed.Scenario.Severity,
		Platforms:         platforms,
		TechniqueIDs:       techniqueIDs,
		Tags:              tags,
		ObjectivesCount:   len(parsed.Objectives),
		InjectsCount:      len(parsed.Injects),
		SourceUpdatedAt:   parsed.Scenario.UpdatedAt,
	}
	detail := Detail{
		Description: parsed.Scenario.Description,
		Objectives:  detailObjectives,
		Injects:     detailInjects,
		Variables:   detailVariables,
	}
	return scenario, detail
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/openaev/... -run TestNormalize -v`
Expected: PASS

- [ ] **Step 6: Format, vet, build, commit**

```bash
cd orchestrator
gofmt -w internal/openaev/types.go internal/openaev/normalizer.go internal/openaev/normalizer_test.go
gofmt -l internal/openaev/types.go internal/openaev/normalizer.go internal/openaev/normalizer_test.go
go build ./... && go vet ./...
git add internal/openaev/types.go internal/openaev/normalizer.go internal/openaev/normalizer_test.go
git commit -m "feat(openaev): add scenario normalizer"
git push
```

---

### Task 3: Store — Postgres schema + upsert

**Files:**
- Modify: `orchestrator/internal/db/postgres.go` (add `openaev_config` — operational/config table, same category as `detection_connectors`)
- Modify: `orchestrator/internal/db/content_schema.go` (add `openaev_bundles` and `openaev_scenarios` — synced content, same category as `art_content_meta`/`cves`)
- Create: `orchestrator/internal/openaev/store.go`
- Create: `orchestrator/internal/openaev/store_test.go`

**Interfaces:**
- Consumes: `Scenario`, `Detail` from Task 2.
- Produces: `SQLStore` type with `NewSQLStore(pool *pgxpool.Pool) *SQLStore`, `(*SQLStore) SyncState(ctx, openaevScenarioID string) (sourceUpdatedAt time.Time, contentHash string, found bool, err error)`, `(*SQLStore) Upsert(ctx, scenario Scenario, detail Detail, contentHash string, sizeBytes, sourceVersion int) error`, `(*SQLStore) List(ctx) ([]Scenario, error)`, `(*SQLStore) Get(ctx, openaevScenarioID string) (Scenario, Detail, bool, error)` — used by Task 5 (Importer) and Task 6 (API handlers).

- [ ] **Step 1: Add `openaev_config` to `postgres.go`**

Find the `detection_connectors` table definition (search for `CREATE TABLE IF NOT EXISTS detection_connectors`) inside the `stmts := []string{...}` slice in `EnsureSchema`, and add immediately after its closing `)`,`:

```sql
		`CREATE TABLE IF NOT EXISTS openaev_config (
			id                  int         PRIMARY KEY DEFAULT 1 CHECK (id = 1),
			base_url            text        NOT NULL DEFAULT '',
			bearer_token        text        NOT NULL DEFAULT '',
			poll_interval_hours int         NOT NULL DEFAULT 24,
			enabled             boolean     NOT NULL DEFAULT false,
			last_sync_at        timestamptz,
			last_sync_status    text        NOT NULL DEFAULT 'never',
			last_error          text        NOT NULL DEFAULT '',
			updated_at          timestamptz NOT NULL DEFAULT NOW()
		)`,
```

- [ ] **Step 2: Add `openaev_bundles` and `openaev_scenarios` to `content_schema.go`**

Find the `art_content_meta` table definition inside `EnsureContentSchema`'s statement list, and add immediately after it:

```sql
		`CREATE TABLE IF NOT EXISTS openaev_bundles (
			id                   text        PRIMARY KEY,
			openaev_scenario_id  text        NOT NULL,
			bundle               jsonb       NOT NULL,
			content_hash         text        NOT NULL,
			size_bytes           int         NOT NULL DEFAULT 0,
			source_version       int         NOT NULL DEFAULT 1,
			synced_at            timestamptz NOT NULL DEFAULT NOW()
		)`,

		`CREATE TABLE IF NOT EXISTS openaev_scenarios (
			openaev_scenario_id text        PRIMARY KEY,
			name                text        NOT NULL,
			category            text        NOT NULL DEFAULT '',
			severity            text        NOT NULL DEFAULT '',
			platforms           text[]      NOT NULL DEFAULT '{}',
			technique_ids       text[]      NOT NULL DEFAULT '{}',
			tags                text[]      NOT NULL DEFAULT '{}',
			objectives_count    int         NOT NULL DEFAULT 0,
			injects_count       int         NOT NULL DEFAULT 0,
			source_updated_at   timestamptz NOT NULL,
			content_hash        text        NOT NULL DEFAULT '',
			bundle_id           text        REFERENCES openaev_bundles(id),
			sync_revision       int         NOT NULL DEFAULT 1,
			imported_at         timestamptz NOT NULL DEFAULT NOW(),
			updated_at          timestamptz NOT NULL DEFAULT NOW()
		)`,
```

- [ ] **Step 3: Write the failing store test**

```go
// orchestrator/internal/openaev/store_test.go
package openaev

import (
	"context"
	"testing"

	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/testutil"
	"github.com/jackc/pgx/v5/pgxpool"
)

var sharedDB = testutil.MustSharedTestDB()

func TestMain(m *testing.M) { sharedDB.Main(m) }

func TestStore_UpsertThenGet(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		if err := db.EnsureSchema(context.Background(), pool); err != nil {
			t.Fatalf("EnsureSchema: %v", err)
		}
		if err := db.EnsureContentSchema(context.Background(), pool); err != nil {
			t.Fatalf("EnsureContentSchema: %v", err)
		}
		store := NewSQLStore(pool)

		scenario := Scenario{
			OpenAEVScenarioID: "sc-store-001",
			Name:              "Ransomware Drill",
			TechniqueIDs:      []string{"T1486"},
		}
		detail := Detail{Description: "test"}

		if err := store.Upsert(context.Background(), scenario, detail, "hash-a", 100, 1); err != nil {
			t.Fatalf("Upsert: %v", err)
		}

		got, gotDetail, found, err := store.Get(context.Background(), "sc-store-001")
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if !found {
			t.Fatal("expected scenario to be found after Upsert")
		}
		if got.Name != "Ransomware Drill" {
			t.Errorf("Name = %q", got.Name)
		}
		if gotDetail.Description != "test" {
			t.Errorf("Detail.Description = %q", gotDetail.Description)
		}
	})
}

func TestStore_UpsertSameHashDoesNotBumpRevision(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		db.EnsureSchema(context.Background(), pool)
		db.EnsureContentSchema(context.Background(), pool)
		store := NewSQLStore(pool)

		scenario := Scenario{OpenAEVScenarioID: "sc-store-002", Name: "A"}
		store.Upsert(context.Background(), scenario, Detail{}, "hash-same", 10, 1)
		store.Upsert(context.Background(), scenario, Detail{}, "hash-same", 10, 1)

		var revision int
		pool.QueryRow(context.Background(),
			`SELECT sync_revision FROM openaev_scenarios WHERE openaev_scenario_id = $1`, "sc-store-002").
			Scan(&revision)
		if revision != 1 {
			t.Errorf("sync_revision = %d, want 1 (unchanged hash must not bump it)", revision)
		}
	})
}

func TestStore_UpsertDifferentHashBumpsRevision(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		db.EnsureSchema(context.Background(), pool)
		db.EnsureContentSchema(context.Background(), pool)
		store := NewSQLStore(pool)

		scenario := Scenario{OpenAEVScenarioID: "sc-store-003", Name: "A"}
		store.Upsert(context.Background(), scenario, Detail{}, "hash-1", 10, 1)
		store.Upsert(context.Background(), scenario, Detail{}, "hash-2", 10, 1)

		var revision int
		pool.QueryRow(context.Background(),
			`SELECT sync_revision FROM openaev_scenarios WHERE openaev_scenario_id = $1`, "sc-store-003").
			Scan(&revision)
		if revision != 2 {
			t.Errorf("sync_revision = %d, want 2 (changed hash must bump it)", revision)
		}
	})
}

func TestStore_SyncState_NotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		db.EnsureSchema(context.Background(), pool)
		db.EnsureContentSchema(context.Background(), pool)
		store := NewSQLStore(pool)

		_, _, found, err := store.SyncState(context.Background(), "no-such-scenario")
		if err != nil {
			t.Fatalf("SyncState: %v", err)
		}
		if found {
			t.Error("expected found=false for a scenario never synced")
		}
	})
}
```

Check `internal/testutil` exposes `MustSharedTestDB` with `.Main(m)` and `.RunWithPool(t, fn)` matching this shape — confirm against an existing test file (e.g. `internal/api/cancel_run_test.go` uses `sharedDB.RunWithPool`; check its package's `TestMain` for the exact `MustSharedTestDB`/`.Main` call signature before writing this file, and match it exactly).

- [ ] **Step 4: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/openaev/... -run TestStore -v`
Expected: FAIL — `NewSQLStore` undefined (also confirms Docker Desktop is running; if the failure is instead a Docker/testcontainers error, start Docker Desktop first).

- [ ] **Step 5: Write `store.go`**

```go
package openaev

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type SQLStore struct {
	pool *pgxpool.Pool
}

func NewSQLStore(pool *pgxpool.Pool) *SQLStore {
	return &SQLStore{pool: pool}
}

// SyncState returns the last-known source_updated_at and content_hash for a
// scenario, so the Importer can decide whether a fresh Fetch is even needed.
func (s *SQLStore) SyncState(ctx context.Context, openaevScenarioID string) (time.Time, string, bool, error) {
	var updatedAt time.Time
	var hash string
	err := s.pool.QueryRow(ctx,
		`SELECT source_updated_at, content_hash FROM openaev_scenarios WHERE openaev_scenario_id = $1`,
		openaevScenarioID,
	).Scan(&updatedAt, &hash)
	if err != nil {
		return time.Time{}, "", false, nil // not found is not an error here
	}
	return updatedAt, hash, true, nil
}

// Upsert writes both the bundle (full detail, keyed by content hash) and the
// scenario summary row in one transaction. sync_revision only increments when
// the content actually changed, per the "OpenAEV always wins" sync policy —
// no merge, just replace.
func (s *SQLStore) Upsert(ctx context.Context, scenario Scenario, detail Detail, contentHash string, sizeBytes, sourceVersion int) error {
	detailJSON, err := json.Marshal(detail)
	if err != nil {
		return err
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx,
		`INSERT INTO openaev_bundles (id, openaev_scenario_id, bundle, content_hash, size_bytes, source_version)
		 VALUES ($1, $2, $3::jsonb, $1, $4, $5)
		 ON CONFLICT (id) DO NOTHING`,
		contentHash, scenario.OpenAEVScenarioID, detailJSON, sizeBytes, sourceVersion,
	); err != nil {
		return err
	}

	if _, err := tx.Exec(ctx,
		`INSERT INTO openaev_scenarios
		   (openaev_scenario_id, name, category, severity, platforms, technique_ids, tags,
		    objectives_count, injects_count, source_updated_at, content_hash, bundle_id,
		    sync_revision, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $11, 1, NOW())
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
		   updated_at = NOW()`,
		scenario.OpenAEVScenarioID, scenario.Name, scenario.Category, scenario.Severity,
		scenario.Platforms, scenario.TechniqueIDs, scenario.Tags,
		scenario.ObjectivesCount, scenario.InjectsCount, scenario.SourceUpdatedAt, contentHash,
	); err != nil {
		return err
	}

	return tx.Commit(ctx)
}

func (s *SQLStore) List(ctx context.Context) ([]Scenario, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT openaev_scenario_id, name, category, severity, platforms, technique_ids, tags,
		        objectives_count, injects_count, source_updated_at
		   FROM openaev_scenarios ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Scenario
	for rows.Next() {
		var sc Scenario
		if err := rows.Scan(&sc.OpenAEVScenarioID, &sc.Name, &sc.Category, &sc.Severity,
			&sc.Platforms, &sc.TechniqueIDs, &sc.Tags, &sc.ObjectivesCount, &sc.InjectsCount,
			&sc.SourceUpdatedAt); err != nil {
			continue
		}
		out = append(out, sc)
	}
	return out, rows.Err()
}

func (s *SQLStore) Get(ctx context.Context, openaevScenarioID string) (Scenario, Detail, bool, error) {
	var sc Scenario
	var bundleJSON []byte
	err := s.pool.QueryRow(ctx,
		`SELECT s.openaev_scenario_id, s.name, s.category, s.severity, s.platforms, s.technique_ids,
		        s.tags, s.objectives_count, s.injects_count, s.source_updated_at, COALESCE(b.bundle::text, '{}')::jsonb
		   FROM openaev_scenarios s
		   LEFT JOIN openaev_bundles b ON b.id = s.bundle_id
		  WHERE s.openaev_scenario_id = $1`,
		openaevScenarioID,
	).Scan(&sc.OpenAEVScenarioID, &sc.Name, &sc.Category, &sc.Severity, &sc.Platforms, &sc.TechniqueIDs,
		&sc.Tags, &sc.ObjectivesCount, &sc.InjectsCount, &sc.SourceUpdatedAt, &bundleJSON)
	if err != nil {
		return Scenario{}, Detail{}, false, nil
	}
	var detail Detail
	json.Unmarshal(bundleJSON, &detail)
	return sc, detail, true, nil
}
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/openaev/... -run TestStore -v`
Expected: PASS (all four tests)

- [ ] **Step 7: Format, vet, build, commit**

```bash
cd orchestrator
gofmt -w internal/db/postgres.go internal/db/content_schema.go internal/openaev/store.go internal/openaev/store_test.go
gofmt -l internal/db/postgres.go internal/db/content_schema.go internal/openaev/store.go internal/openaev/store_test.go
go build ./... && go vet ./...
git add internal/db/postgres.go internal/db/content_schema.go internal/openaev/store.go internal/openaev/store_test.go
git commit -m "feat(openaev): add Postgres schema and upsert store"
git push
```

---

### Task 4: ContentProvider implementations — REST and Bundle

**Files:**
- Create: `orchestrator/internal/openaev/provider_rest.go`
- Create: `orchestrator/internal/openaev/provider_bundle.go`
- Create: `orchestrator/internal/openaev/provider_test.go`

**Interfaces:**
- Consumes: `ContentProvider`, `ScenarioRef` from Task 1.
- Produces: `NewRESTProvider(baseURL, token string) *RESTProvider` and `NewBundleProvider(id string, data []byte) *BundleProvider`, both implementing `ContentProvider` — used by Task 5 (Importer) and Task 6 (API handlers, for the manual-upload path).

- [ ] **Step 1: Write the failing test**

```go
// orchestrator/internal/openaev/provider_test.go
package openaev

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRESTProvider_List_ParsesScenarios(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Errorf("Authorization header = %q, want Bearer test-token", r.Header.Get("Authorization"))
		}
		if r.URL.Path != "/api/scenarios" {
			t.Errorf("path = %q, want /api/scenarios", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`[
			{"scenario_id": "sc-1", "scenario_name": "One", "scenario_updated_at": "2026-07-10T12:00:00Z"},
			{"scenario_id": "sc-2", "scenario_name": "Two", "scenario_updated_at": "2026-07-11T12:00:00Z"}
		]`))
	}))
	defer srv.Close()

	p := NewRESTProvider(srv.URL, "test-token")
	refs, err := p.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(refs) != 2 {
		t.Fatalf("refs = %d, want 2", len(refs))
	}
	if refs[0].ID != "sc-1" || refs[0].Name != "One" {
		t.Errorf("refs[0] = %+v", refs[0])
	}
}

func TestRESTProvider_List_Unauthorized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	p := NewRESTProvider(srv.URL, "bad-token")
	if _, err := p.List(context.Background()); err == nil {
		t.Fatal("expected error for 401 response, got nil")
	}
}

func TestRESTProvider_Fetch_ReturnsBundleBytes(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/scenarios/sc-1/export" {
			t.Errorf("path = %q, want /api/scenarios/sc-1/export", r.URL.Path)
		}
		w.Write([]byte("fake-zip-bytes"))
	}))
	defer srv.Close()

	p := NewRESTProvider(srv.URL, "test-token")
	data, err := p.Fetch(context.Background(), "sc-1")
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if string(data) != "fake-zip-bytes" {
		t.Errorf("data = %q", data)
	}
}

func TestBundleProvider_ListAndFetch(t *testing.T) {
	p := NewBundleProvider("sc-uploaded", []byte("zip-content"))
	refs, err := p.List(context.Background())
	if err != nil || len(refs) != 1 || refs[0].ID != "sc-uploaded" {
		t.Fatalf("List = %+v, err = %v", refs, err)
	}
	data, err := p.Fetch(context.Background(), "sc-uploaded")
	if err != nil || string(data) != "zip-content" {
		t.Fatalf("Fetch = %q, err = %v", data, err)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/openaev/... -run 'TestRESTProvider|TestBundleProvider' -v`
Expected: FAIL — `NewRESTProvider`/`NewBundleProvider` undefined.

- [ ] **Step 3: Write `provider_rest.go`**

```go
package openaev

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// RESTProvider fetches scenarios from a live, reachable OpenAEV instance over
// its REST API. Auth is a Bearer Personal Access Token, same shape as the
// existing MISP/OpenCTI connectors (internal/connector).
type RESTProvider struct {
	baseURL string
	token   string
	client  *http.Client
}

func NewRESTProvider(baseURL, token string) *RESTProvider {
	return &RESTProvider{baseURL: baseURL, token: token, client: &http.Client{Timeout: 30 * time.Second}}
}

func (p *RESTProvider) Name() string { return "openaev-rest" }

type restScenarioListEntry struct {
	ID        string    `json:"scenario_id"`
	Name      string    `json:"scenario_name"`
	UpdatedAt time.Time `json:"scenario_updated_at"`
}

func (p *RESTProvider) List(ctx context.Context) ([]ScenarioRef, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.baseURL+"/api/scenarios", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+p.token)

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("openaev list request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("openaev list returned HTTP %d", resp.StatusCode)
	}

	var entries []restScenarioListEntry
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		return nil, fmt.Errorf("decode openaev scenario list: %w", err)
	}

	refs := make([]ScenarioRef, 0, len(entries))
	for _, e := range entries {
		refs = append(refs, ScenarioRef{ID: e.ID, Name: e.Name, SourceUpdated: e.UpdatedAt})
	}
	return refs, nil
}

func (p *RESTProvider) Fetch(ctx context.Context, id string) ([]byte, error) {
	url := p.baseURL + "/api/scenarios/" + id + "/export"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+p.token)

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("openaev export request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("openaev export returned HTTP %d for scenario %s", resp.StatusCode, id)
	}

	return io.ReadAll(resp.Body)
}
```

- [ ] **Step 4: Write `provider_bundle.go`**

```go
package openaev

import "context"

// BundleProvider wraps a single manually-uploaded bundle — the air-gapped
// path. List() returns exactly the one scenario it was constructed with;
// Fetch() ignores the id argument and returns the bytes it was given (there
// is only ever one bundle per BundleProvider instance).
type BundleProvider struct {
	id   string
	data []byte
}

func NewBundleProvider(id string, data []byte) *BundleProvider {
	return &BundleProvider{id: id, data: data}
}

func (p *BundleProvider) Name() string { return "openaev-bundle-upload" }

func (p *BundleProvider) List(ctx context.Context) ([]ScenarioRef, error) {
	return []ScenarioRef{{ID: p.id}}, nil
}

func (p *BundleProvider) Fetch(ctx context.Context, id string) ([]byte, error) {
	return p.data, nil
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/openaev/... -run 'TestRESTProvider|TestBundleProvider' -v`
Expected: PASS

- [ ] **Step 6: Format, vet, build, commit**

```bash
cd orchestrator
gofmt -w internal/openaev/provider_rest.go internal/openaev/provider_bundle.go internal/openaev/provider_test.go
gofmt -l internal/openaev/provider_rest.go internal/openaev/provider_bundle.go internal/openaev/provider_test.go
go build ./... && go vet ./...
git add internal/openaev/provider_rest.go internal/openaev/provider_bundle.go internal/openaev/provider_test.go
git commit -m "feat(openaev): add REST and Bundle content providers"
git push
```

---

### Task 5: Importer — orchestration, retries, sync policy

**Files:**
- Create: `orchestrator/internal/openaev/importer.go`
- Create: `orchestrator/internal/openaev/importer_test.go`

**Interfaces:**
- Consumes: `ContentProvider`, `ParseBundle`, `Normalize`, `SQLStore`'s `SyncState`/`Upsert` from Tasks 1-4. Defines its own narrow `contentStore` interface (not `*SQLStore` directly) so tests can fake it without a real database.
- Produces: `SyncResult{Created, Updated, Skipped, Errored int; Errors []string}`, `NewImporter(store contentStore) *Importer`, `(*Importer) SyncAll(ctx, provider ContentProvider) (*SyncResult, error)`, `(*Importer) ImportOne(ctx, data []byte) (*SyncResult, error)` — used by Task 6 (API handlers) and Task 7 (scheduler wiring).

- [ ] **Step 1: Write the failing test**

```go
// orchestrator/internal/openaev/importer_test.go
package openaev

import (
	"context"
	"errors"
	"testing"
	"time"
)

// fakeStore is an in-memory contentStore for Importer tests — no database.
type fakeStore struct {
	state map[string]struct {
		updatedAt time.Time
		hash      string
	}
	upserts []string // records openaev_scenario_id of each successful Upsert, in order
	failOn  string    // if set, Upsert for this scenario ID returns an error
}

func newFakeStore() *fakeStore {
	return &fakeStore{state: map[string]struct {
		updatedAt time.Time
		hash      string
	}{}}
}

func (f *fakeStore) SyncState(ctx context.Context, id string) (time.Time, string, bool, error) {
	s, ok := f.state[id]
	return s.updatedAt, s.hash, ok, nil
}

func (f *fakeStore) Upsert(ctx context.Context, scenario Scenario, detail Detail, contentHash string, sizeBytes, sourceVersion int) error {
	if f.failOn == scenario.OpenAEVScenarioID {
		return errors.New("simulated store failure")
	}
	f.state[scenario.OpenAEVScenarioID] = struct {
		updatedAt time.Time
		hash      string
	}{scenario.SourceUpdatedAt, contentHash}
	f.upserts = append(f.upserts, scenario.OpenAEVScenarioID)
	return nil
}

// fakeProvider serves fixed bundle bytes per scenario ID, built with the real
// buildFixtureZip helper from parser_test.go so Importer exercises the real
// Parser/Normalizer, not a shortcut.
type fakeProvider struct {
	refs    []ScenarioRef
	bundles map[string][]byte
}

func (f *fakeProvider) Name() string { return "fake" }
func (f *fakeProvider) List(ctx context.Context) ([]ScenarioRef, error) { return f.refs, nil }
func (f *fakeProvider) Fetch(ctx context.Context, id string) ([]byte, error) {
	b, ok := f.bundles[id]
	if !ok {
		return nil, errors.New("no such bundle")
	}
	return b, nil
}

func fixtureBundleFor(t *testing.T, id, name string, updatedAt time.Time) []byte {
	t.Helper()
	scenarioJSON := `{"export_version":1,"scenario_information":{"scenario_id":"` + id +
		`","scenario_name":"` + name + `","scenario_updated_at":"` + updatedAt.Format(time.RFC3339) + `"}}`
	return buildFixtureZip(t, scenarioJSON)
}

func TestImporter_SyncAll_CreatesNewScenarios(t *testing.T) {
	store := newFakeStore()
	imp := NewImporter(store)
	updated := time.Date(2026, 7, 10, 0, 0, 0, 0, time.UTC)
	provider := &fakeProvider{
		refs: []ScenarioRef{{ID: "sc-1", Name: "One", SourceUpdated: updated}},
		bundles: map[string][]byte{
			"sc-1": fixtureBundleFor(t, "sc-1", "One", updated),
		},
	}

	result, err := imp.SyncAll(context.Background(), provider)
	if err != nil {
		t.Fatalf("SyncAll: %v", err)
	}
	if result.Created != 1 || result.Skipped != 0 || result.Errored != 0 {
		t.Errorf("result = %+v, want Created=1", result)
	}
	if len(store.upserts) != 1 || store.upserts[0] != "sc-1" {
		t.Errorf("upserts = %v", store.upserts)
	}
}

func TestImporter_SyncAll_SkipsUnchangedTimestamp(t *testing.T) {
	store := newFakeStore()
	updated := time.Date(2026, 7, 10, 0, 0, 0, 0, time.UTC)
	store.state["sc-1"] = struct {
		updatedAt time.Time
		hash      string
	}{updated, "some-hash"}
	imp := NewImporter(store)
	provider := &fakeProvider{
		refs: []ScenarioRef{{ID: "sc-1", Name: "One", SourceUpdated: updated}},
		// No bundle registered for sc-1 — if the Importer tries to Fetch it,
		// the test fails with "no such bundle", proving the skip worked.
		bundles: map[string][]byte{},
	}

	result, err := imp.SyncAll(context.Background(), provider)
	if err != nil {
		t.Fatalf("SyncAll: %v", err)
	}
	if result.Skipped != 1 || result.Created != 0 {
		t.Errorf("result = %+v, want Skipped=1", result)
	}
}

func TestImporter_SyncAll_OneErrorDoesNotAbortTheRest(t *testing.T) {
	store := newFakeStore()
	store.failOn = "sc-bad"
	imp := NewImporter(store)
	updated := time.Date(2026, 7, 10, 0, 0, 0, 0, time.UTC)
	provider := &fakeProvider{
		refs: []ScenarioRef{
			{ID: "sc-bad", Name: "Bad", SourceUpdated: updated},
			{ID: "sc-good", Name: "Good", SourceUpdated: updated},
		},
		bundles: map[string][]byte{
			"sc-bad":  fixtureBundleFor(t, "sc-bad", "Bad", updated),
			"sc-good": fixtureBundleFor(t, "sc-good", "Good", updated),
		},
	}

	result, err := imp.SyncAll(context.Background(), provider)
	if err != nil {
		t.Fatalf("SyncAll: %v", err)
	}
	if result.Errored != 1 || result.Created != 1 {
		t.Errorf("result = %+v, want Errored=1 Created=1 (sc-good must still succeed)", result)
	}
}

func TestImporter_ImportOne_ParsesAndUpserts(t *testing.T) {
	store := newFakeStore()
	imp := NewImporter(store)
	updated := time.Date(2026, 7, 10, 0, 0, 0, 0, time.UTC)
	data := fixtureBundleFor(t, "sc-air-gapped", "Air Gapped Scenario", updated)

	result, err := imp.ImportOne(context.Background(), data)
	if err != nil {
		t.Fatalf("ImportOne: %v", err)
	}
	if result.Created != 1 {
		t.Errorf("result = %+v, want Created=1", result)
	}
	if len(store.upserts) != 1 || store.upserts[0] != "sc-air-gapped" {
		t.Errorf("upserts = %v", store.upserts)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/openaev/... -run TestImporter -v`
Expected: FAIL — `NewImporter` undefined.

- [ ] **Step 3: Write `importer.go`**

```go
package openaev

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"
)

// contentStore is the narrow slice of SQLStore the Importer needs — lets tests
// fake it without a real database. *SQLStore satisfies this.
type contentStore interface {
	SyncState(ctx context.Context, openaevScenarioID string) (sourceUpdatedAt time.Time, contentHash string, found bool, err error)
	Upsert(ctx context.Context, scenario Scenario, detail Detail, contentHash string, sizeBytes, sourceVersion int) error
}

type SyncResult struct {
	Created int
	Updated int
	Skipped int
	Errored int
	Errors  []string
}

type Importer struct {
	store contentStore
}

func NewImporter(store contentStore) *Importer {
	return &Importer{store: store}
}

// SyncAll runs a full sync against provider: list, delta-check each ref
// against stored state, fetch+parse+normalize+store only what changed. One
// failing scenario is logged and counted, never aborts the rest — matches the
// ART reseed pattern's error isolation.
func (im *Importer) SyncAll(ctx context.Context, provider ContentProvider) (*SyncResult, error) {
	refs, err := provider.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("list scenarios: %w", err)
	}

	result := &SyncResult{}
	for _, ref := range refs {
		storedUpdated, storedHash, found, _ := im.store.SyncState(ctx, ref.ID)
		if found && !ref.SourceUpdated.After(storedUpdated) {
			result.Skipped++
			continue
		}

		data, err := provider.Fetch(ctx, ref.ID)
		if err != nil {
			result.Errored++
			result.Errors = append(result.Errors, fmt.Sprintf("%s: fetch failed: %v", ref.ID, err))
			continue
		}

		hash := sha256Hex(data)
		if found && hash == storedHash {
			result.Skipped++
			continue
		}

		if err := im.processOne(ctx, data, hash, len(data)); err != nil {
			result.Errored++
			result.Errors = append(result.Errors, fmt.Sprintf("%s: %v", ref.ID, err))
			continue
		}
		if found {
			result.Updated++
		} else {
			result.Created++
		}
	}
	return result, nil
}

// ImportOne handles the air-gapped manual-upload path: no List/delta-check,
// the uploaded bytes are the one bundle to process.
func (im *Importer) ImportOne(ctx context.Context, data []byte) (*SyncResult, error) {
	result := &SyncResult{}
	hash := sha256Hex(data)
	if err := im.processOne(ctx, data, hash, len(data)); err != nil {
		result.Errored++
		result.Errors = append(result.Errors, err.Error())
		return result, nil
	}
	result.Created++
	return result, nil
}

func (im *Importer) processOne(ctx context.Context, data []byte, hash string, size int) error {
	parsed, err := ParseBundle(data)
	if err != nil {
		return fmt.Errorf("parse: %w", err)
	}
	scenario, detail := Normalize(parsed)
	if err := im.store.Upsert(ctx, scenario, detail, hash, size, parsed.ExportVersion); err != nil {
		return fmt.Errorf("store: %w", err)
	}
	return nil
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/openaev/... -run TestImporter -v`
Expected: PASS (all four tests)

- [ ] **Step 5: Confirm `*SQLStore` still satisfies `contentStore`**

Run: `cd orchestrator && go build ./...`
Expected: succeeds (if `SQLStore.SyncState`'s signature from Task 3 doesn't exactly match `contentStore`, this fails here — fix the mismatch, don't change the test).

- [ ] **Step 6: Format, vet, build, commit**

```bash
cd orchestrator
gofmt -w internal/openaev/importer.go internal/openaev/importer_test.go
gofmt -l internal/openaev/importer.go internal/openaev/importer_test.go
go build ./... && go vet ./...
git add internal/openaev/importer.go internal/openaev/importer_test.go
git commit -m "feat(openaev): add Importer orchestration layer"
git push
```

---

### Task 6: API handlers

**Files:**
- Create: `orchestrator/internal/api/openaev_handlers.go`
- Create: `orchestrator/internal/api/openaev_handlers_test.go`
- Modify: `orchestrator/internal/api/routes.go`
- Modify: `orchestrator/internal/api/rbac_matrix_test.go`

**Interfaces:**
- Consumes: `openaev.NewSQLStore`, `openaev.NewImporter`, `openaev.NewRESTProvider`, `openaev.NewBundleProvider` from Tasks 3-5.
- Produces: `Handler.GetOpenAEVConfig`, `.PutOpenAEVConfig`, `.TestOpenAEVConfig`, `.SyncOpenAEV`, `.GetOpenAEVStatus`, `.ListOpenAEVScenarios`, `.GetOpenAEVScenario`, `.ImportOpenAEVBundle` — registered in `routes.go`, used by Task 8 (UI).

- [ ] **Step 1: Check the existing `Handler` struct and `respond`/`jsonError`/`auditLog` helpers**

Read `orchestrator/internal/api/handlers.go`'s `Handler` struct definition and the `respond`/`jsonError` helper signatures (used throughout this file already, e.g. in `CancelRun`) before writing the new file — match them exactly, don't reinvent.

- [ ] **Step 2: Write the failing test**

```go
// orchestrator/internal/api/openaev_handlers_test.go
package api

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
	"github.com/jackc/pgx/v5/pgxpool"
)

// fixtureBundleForHandlerTest builds a minimal OpenAEV export ZIP the same
// way openaev.buildFixtureZip does — duplicated here (not imported) since
// that helper is unexported in another package.
func fixtureBundleForHandlerTest(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	hdr := &zip.FileHeader{Name: "Handler Test Scenario.json", Method: zip.Deflate}
	hdr.Comment = "Scenario"
	w, _ := zw.CreateHeader(hdr)
	w.Write([]byte(`{"export_version":1,"scenario_information":{"scenario_id":"sc-handler-test","scenario_name":"Handler Test Scenario","scenario_updated_at":"2026-07-10T00:00:00Z"}}`))
	zw.Close()
	return buf.Bytes()
}

func TestGetOpenAEVConfig_RedactsToken(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		db.EnsureSchema(context.Background(), pool)
		pool.Exec(context.Background(),
			`INSERT INTO openaev_config (id, base_url, bearer_token, enabled) VALUES (1, 'https://openaev.local', 'super-secret', true)
			 ON CONFLICT (id) DO UPDATE SET base_url = EXCLUDED.base_url, bearer_token = EXCLUDED.bearer_token, enabled = EXCLUDED.enabled`)

		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		rec := httptest.NewRecorder()
		h.GetOpenAEVConfig(rec, httptest.NewRequest(http.MethodGet, "/api/openaev/config", nil))

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var out map[string]any
		json.Unmarshal(rec.Body.Bytes(), &out)
		if out["baseUrl"] != "https://openaev.local" {
			t.Errorf("baseUrl = %v", out["baseUrl"])
		}
		if _, present := out["bearerToken"]; present {
			t.Error("bearerToken must never be present in the response")
		}
	})
}

func TestListOpenAEVScenarios_EmptyByDefault(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		db.EnsureContentSchema(context.Background(), pool)
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		rec := httptest.NewRecorder()
		h.ListOpenAEVScenarios(rec, httptest.NewRequest(http.MethodGet, "/api/openaev/scenarios", nil))

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var out []any
		json.Unmarshal(rec.Body.Bytes(), &out)
		if len(out) != 0 {
			t.Errorf("expected empty list, got %d entries", len(out))
		}
	})
}

func TestImportOpenAEVBundle_ParsesAndStores(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		db.EnsureSchema(context.Background(), pool)
		db.EnsureContentSchema(context.Background(), pool)
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")

		var body bytes.Buffer
		mw := multipart.NewWriter(&body)
		fw, _ := mw.CreateFormFile("file", "scenario.zip")
		fw.Write(fixtureBundleForHandlerTest(t))
		mw.Close()

		req := httptest.NewRequest(http.MethodPost, "/api/openaev/import", &body)
		req.Header.Set("Content-Type", mw.FormDataContentType())
		rec := httptest.NewRecorder()
		h.ImportOpenAEVBundle(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}

		var scenarioCount int
		pool.QueryRow(context.Background(), `SELECT count(*) FROM openaev_scenarios`).Scan(&scenarioCount)
		if scenarioCount != 1 {
			t.Errorf("openaev_scenarios rows = %d, want 1", scenarioCount)
		}
	})
}
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/api/... -run 'TestGetOpenAEVConfig|TestListOpenAEVScenarios|TestImportOpenAEVBundle' -v`
Expected: FAIL — handler methods undefined.

- [ ] **Step 4: Write `openaev_handlers.go`**

```go
package api

import (
	"encoding/json"
	"net/http"

	"github.com/audspect/bas/internal/openaev"
	"github.com/go-chi/chi/v5"
)

// GET /api/openaev/config — Admin. bearer_token is never included in the response.
func (h *Handler) GetOpenAEVConfig(w http.ResponseWriter, r *http.Request) {
	var baseURL, status, lastError string
	var pollHours int
	var enabled bool
	err := h.db.QueryRow(r.Context(),
		`SELECT base_url, poll_interval_hours, enabled, last_sync_status, last_error
		   FROM openaev_config WHERE id = 1`,
	).Scan(&baseURL, &pollHours, &enabled, &status, &lastError)
	if err != nil {
		// No row yet — defaults.
		respond(w, map[string]any{"baseUrl": "", "pollIntervalHours": 24, "enabled": false, "lastSyncStatus": "never", "lastError": ""})
		return
	}
	respond(w, map[string]any{
		"baseUrl":           baseURL,
		"pollIntervalHours": pollHours,
		"enabled":           enabled,
		"lastSyncStatus":    status,
		"lastError":         lastError,
	})
}

// PUT /api/openaev/config — Admin.
func (h *Handler) PutOpenAEVConfig(w http.ResponseWriter, r *http.Request) {
	var body struct {
		BaseURL           string `json:"baseUrl"`
		BearerToken       string `json:"bearerToken"`
		PollIntervalHours int    `json:"pollIntervalHours"`
		Enabled           bool   `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	_, err := h.db.Exec(r.Context(),
		`INSERT INTO openaev_config (id, base_url, bearer_token, poll_interval_hours, enabled, updated_at)
		 VALUES (1, $1, $2, $3, $4, NOW())
		 ON CONFLICT (id) DO UPDATE SET
		   base_url = EXCLUDED.base_url,
		   bearer_token = CASE WHEN EXCLUDED.bearer_token = '' THEN openaev_config.bearer_token ELSE EXCLUDED.bearer_token END,
		   poll_interval_hours = EXCLUDED.poll_interval_hours,
		   enabled = EXCLUDED.enabled,
		   updated_at = NOW()`,
		body.BaseURL, body.BearerToken, body.PollIntervalHours, body.Enabled,
	)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.auditLog(r, "openaev.config.update", "", map[string]any{"baseUrl": body.BaseURL, "enabled": body.Enabled}, "ok")
	respond(w, map[string]string{"status": "ok"})
}

// POST /api/openaev/config/test — Admin. Validates connectivity/credentials
// before the operator flips enabled=true.
func (h *Handler) TestOpenAEVConfig(w http.ResponseWriter, r *http.Request) {
	var body struct {
		BaseURL     string `json:"baseUrl"`
		BearerToken string `json:"bearerToken"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	provider := openaev.NewRESTProvider(body.BaseURL, body.BearerToken)
	refs, err := provider.List(r.Context())
	if err != nil {
		respond(w, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	respond(w, map[string]any{"ok": true, "scenarioCount": len(refs)})
}

// POST /api/openaev/sync — Admin. Manual sync trigger.
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
	provider := openaev.NewRESTProvider(baseURL, token)

	result, syncErr := importer.SyncAll(r.Context(), provider)
	status := "ok"
	lastErr := ""
	if syncErr != nil {
		status = "error"
		lastErr = syncErr.Error()
	}
	h.db.Exec(r.Context(),
		`UPDATE openaev_config SET last_sync_at = NOW(), last_sync_status = $1, last_error = $2 WHERE id = 1`,
		status, lastErr)

	h.auditLog(r, "openaev.sync", "", map[string]any{"result": result}, "ok")
	if syncErr != nil {
		jsonError(w, syncErr.Error(), http.StatusInternalServerError)
		return
	}
	respond(w, result)
}

// GET /api/openaev/status — Viewer+.
func (h *Handler) GetOpenAEVStatus(w http.ResponseWriter, r *http.Request) {
	var lastSyncAt any
	var status, lastError string
	h.db.QueryRow(r.Context(),
		`SELECT last_sync_at, last_sync_status, last_error FROM openaev_config WHERE id = 1`,
	).Scan(&lastSyncAt, &status, &lastError)

	var scenarioCount int
	h.db.QueryRow(r.Context(), `SELECT count(*) FROM openaev_scenarios`).Scan(&scenarioCount)

	respond(w, map[string]any{
		"lastSyncAt":     lastSyncAt,
		"lastSyncStatus": status,
		"lastError":      lastError,
		"scenarioCount":  scenarioCount,
	})
}

// GET /api/openaev/scenarios — Viewer+.
func (h *Handler) ListOpenAEVScenarios(w http.ResponseWriter, r *http.Request) {
	store := openaev.NewSQLStore(h.db)
	scenarios, err := store.List(r.Context())
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if scenarios == nil {
		scenarios = []openaev.Scenario{}
	}
	respond(w, scenarios)
}

// GET /api/openaev/scenarios/{id} — Viewer+.
func (h *Handler) GetOpenAEVScenario(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	store := openaev.NewSQLStore(h.db)
	scenario, detail, found, err := store.Get(r.Context(), id)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !found {
		jsonError(w, "scenario not found", http.StatusNotFound)
		return
	}
	respond(w, map[string]any{"scenario": scenario, "detail": detail})
}

// POST /api/openaev/import — Admin. Air-gapped manual bundle upload.
func (h *Handler) ImportOpenAEVBundle(w http.ResponseWriter, r *http.Request) {
	file, _, err := r.FormFile("file")
	if err != nil {
		jsonError(w, "missing file", http.StatusBadRequest)
		return
	}
	defer file.Close()

	buf := make([]byte, 0)
	chunk := make([]byte, 32*1024)
	for {
		n, readErr := file.Read(chunk)
		if n > 0 {
			buf = append(buf, chunk[:n]...)
		}
		if readErr != nil {
			break
		}
	}

	store := openaev.NewSQLStore(h.db)
	importer := openaev.NewImporter(store)
	result, err := importer.ImportOne(r.Context(), buf)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.auditLog(r, "openaev.import", "", map[string]any{"result": result}, "ok")
	respond(w, result)
}
```

- [ ] **Step 5: Register routes in `routes.go`**

Find where `/api/exposure/assets` routes were added (SP4, near the SP3 correlation route) and add nearby, grouped under a comment:

```go
	// ── OpenAEV Connector (Module 1) ──────────────────────────────────────
	r.Get("/api/openaev/config", h.GetOpenAEVConfig)             // Admin
	r.Put("/api/openaev/config", h.PutOpenAEVConfig)             // Admin
	r.Post("/api/openaev/config/test", h.TestOpenAEVConfig)      // Admin
	r.Post("/api/openaev/sync", h.SyncOpenAEV)                   // Admin
	r.Get("/api/openaev/status", h.GetOpenAEVStatus)             // Viewer+
	r.Get("/api/openaev/scenarios", h.ListOpenAEVScenarios)      // Viewer+
	r.Get("/api/openaev/scenarios/{id}", h.GetOpenAEVScenario)   // Viewer+
	r.Post("/api/openaev/import", h.ImportOpenAEVBundle)         // Admin
```

Check how existing routes enforce the Admin/Viewer+ tier (a wrapping middleware, or a `tierAny`/`tierAdmin` chi Group) by looking at how the SP1 `detection_connectors` CRUD routes are registered, and apply the same mechanism here — don't leave these routes unprotected.

- [ ] **Step 6: Add the new routes to `rbac_matrix_test.go`**

Find the table-driven RBAC matrix test's existing entries (e.g. the SP4 exposure routes added as `tierAny`) and add:

```go
	{"GET", "/api/openaev/config", tierAdmin},
	{"PUT", "/api/openaev/config", tierAdmin},
	{"POST", "/api/openaev/config/test", tierAdmin},
	{"POST", "/api/openaev/sync", tierAdmin},
	{"GET", "/api/openaev/status", tierAny},
	{"GET", "/api/openaev/scenarios", tierAny},
	{"GET", "/api/openaev/scenarios/{id}", tierAny},
	{"POST", "/api/openaev/import", tierAdmin},
```

Match the exact tier-constant names (`tierAdmin`/`tierAny` or whatever this file actually calls them — check the file first) and the exact table row shape (some matrices use named fields, not positional) before writing this.

- [ ] **Step 7: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/api/... -run 'TestGetOpenAEVConfig|TestListOpenAEVScenarios|TestImportOpenAEVBundle|TestRBAC' -v`
Expected: PASS

- [ ] **Step 8: Format, vet, build, commit**

```bash
cd orchestrator
gofmt -w internal/api/openaev_handlers.go internal/api/openaev_handlers_test.go internal/api/routes.go internal/api/rbac_matrix_test.go
gofmt -l internal/api/openaev_handlers.go internal/api/openaev_handlers_test.go internal/api/routes.go internal/api/rbac_matrix_test.go
go build ./... && go vet ./...
git add internal/api/openaev_handlers.go internal/api/openaev_handlers_test.go internal/api/routes.go internal/api/rbac_matrix_test.go
git commit -m "feat(api): add OpenAEV connector config, sync, and scenario endpoints"
git push
```

---

### Task 7: Scheduler wiring in `main.go`

**Files:**
- Modify: `orchestrator/cmd/server/main.go`

**Interfaces:**
- Consumes: `internal/connector.Scheduler`, `openaev.NewSQLStore`, `openaev.NewImporter`, `openaev.NewRESTProvider` from earlier tasks.

- [ ] **Step 1: Read how the existing MISP/OpenCTI scheduler is constructed and started in `main.go`**

Find the `connector.NewScheduler(...)` call and its `.Start()` invocation — match the same construction pattern (context, shutdown handling) for the OpenAEV job.

- [ ] **Step 2: Add the OpenAEV scheduled job**

```go
	// OpenAEV Connector scheduled sync — reads its own config from the DB each
	// tick (base_url/token/enabled can change via the Admin UI without a
	// restart), so the job function is a closure over the pool, not captured
	// config values.
	openaevScheduler := connector.NewScheduler(func(ctx context.Context) error {
		var baseURL, token string
		var enabled bool
		if err := pool.QueryRow(ctx, `SELECT base_url, bearer_token, enabled FROM openaev_config WHERE id = 1`).
			Scan(&baseURL, &token, &enabled); err != nil || !enabled {
			return nil // not configured / disabled — no-op, not an error
		}
		store := openaev.NewSQLStore(pool)
		importer := openaev.NewImporter(store)
		provider := openaev.NewRESTProvider(baseURL, token)
		result, err := importer.SyncAll(ctx, provider)
		status := "ok"
		lastErr := ""
		if err != nil {
			status = "error"
			lastErr = err.Error()
		}
		pool.Exec(ctx, `UPDATE openaev_config SET last_sync_at = NOW(), last_sync_status = $1, last_error = $2 WHERE id = 1`, status, lastErr)
		log.Printf("[openaev] sync: created=%d updated=%d skipped=%d errored=%d", result.Created, result.Updated, result.Skipped, result.Errored)
		return err
	}, 24) // default poll interval; actual interval is re-read from config each run via the closure above
	openaevScheduler.Start()
```

Check `connector.NewScheduler`'s exact signature (it may take the poll-hours differently, or expect a `func() error` without `ctx`, or return a value other than `*Scheduler`) against `internal/connector/scheduler.go` before writing this — match it exactly rather than guessing.

- [ ] **Step 3: Build**

Run: `cd orchestrator && go build ./... && go vet ./...`
Expected: succeeds.

- [ ] **Step 4: Commit**

```bash
cd orchestrator
gofmt -w cmd/server/main.go
git add cmd/server/main.go
git commit -m "feat(openaev): wire scheduled sync into main.go"
git push
```

---

### Task 8: UI — Integrations tab

**Files:**
- Modify: `orchestrator/wwwroot/index.html`
- Modify: `orchestrator/cmd/server/wwwroot/index.html` (hardlinked mirror — both must be committed together; run `git status` on both paths after editing, per the repo quirk documented from SP4)

**Interfaces:**
- Consumes: `GET /api/openaev/status`, `GET /api/openaev/config`, `PUT /api/openaev/config`, `POST /api/openaev/config/test`, `POST /api/openaev/sync`, `GET /api/openaev/scenarios`, `GET /api/openaev/scenarios/{id}` from Task 6.

- [ ] **Step 1: Verify the exact real UI conventions before writing any markup**

Before touching HTML/JS, grep the actual file for: `activateTab(` (its hardcoded tab-name array — a new tab invisible if missing here, this exact bug shipped once already in SP4 before being caught), `TAB_TITLES`, `apicall(`, `function x(`, the `.kpi-row`/`.kpi-card`/`.tbl-wrap`/`.badge`/`.empty`/`.tiny.muted` CSS classes, and the `{name}-overlay` > `.drawer` > `.drawer-header`/`.drawer-body` multi-instance drawer pattern (see the SP4 Exposure Explorer tab in this same file for a working example of every one of these conventions together — copy its structure, don't invent new patterns).

- [ ] **Step 2: Find and update the existing "Integrations" placeholder nav item**

It currently exists as a greyed-out/disabled placeholder under the Infrastructure nav group (per this session's earlier note that Agents/Integrations\*/Assets\* were placeholders). Locate it (search for `Integrations` in the nav markup) and make it a real, clickable `data-tab="openaev"` item (or `data-tab="integrations"` if that's the id already reserved — check which id the placeholder already uses and reuse it rather than introducing a second one).

- [ ] **Step 3: Add `'openaev'` (or the placeholder's existing id) to `activateTab()`'s hardcoded array**

This is the step SP4 nearly shipped broken — a tab missing from this array never displays regardless of correct markup elsewhere.

- [ ] **Step 4: Add a `TAB_TITLES` entry**

```js
openaev: 'OpenAEV Connector',
```

(or whatever key matches the id chosen in Step 2 — keep it consistent throughout.)

- [ ] **Step 5: Add the tab content block**

Insert after an existing tab's closing `</div>` (e.g. after `tab-exposure`, following SP4's placement convention):

```html
<div id="tab-openaev" style="display:none">
  <div class="card" style="margin-bottom:1rem;padding:1rem 1.2rem">
    <div class="card-title" style="display:flex;justify-content:space-between;align-items:center">
      <span>OpenAEV Connector</span>
      <span id="openaev-status-badge" class="badge"></span>
    </div>
    <div id="openaev-config-panel" style="margin-top:0.75rem"></div>
  </div>
  <div class="tbl-wrap">
    <table id="openaev-scenarios-table">
      <thead><tr><th>Name</th><th>Category</th><th>Severity</th><th>Techniques</th><th>Injects</th><th>Synced</th></tr></thead>
      <tbody id="openaev-scenarios-body"></tbody>
    </table>
  </div>
  <div id="openaev-scenarios-empty" class="empty" style="display:none">No scenarios synced yet.</div>
</div>
```

- [ ] **Step 6: Add the detail overlay**

Insert after an existing overlay's closing `</div>` (e.g. after `exposure-detail-overlay`):

```html
<div id="openaev-detail-overlay" class="drawer-overlay">
  <div class="drawer">
    <div class="drawer-header">
      <span id="openaev-detail-title"></span>
      <button class="btn btn-outline btn-sm" onclick="closeOpenAEVDetail()">Close</button>
    </div>
    <div class="drawer-body" id="openaev-detail-body"></div>
  </div>
</div>
```

- [ ] **Step 7: Add the JS functions**

Insert after `apCard()` (the SP4 precedent's insertion point), using only the verified real helpers from Step 1:

```js
function loadOpenAEVTab() {
  apicall('/api/openaev/status').then(function(s) {
    var badge = document.getElementById('openaev-status-badge');
    var color = s.lastSyncStatus === 'ok' ? apColor(100) : s.lastSyncStatus === 'error' ? apColor(0) : 'var(--muted)';
    badge.textContent = x(s.lastSyncStatus || 'never');
    badge.style.color = color;
  }).catch(function() {});

  apicall('/api/openaev/scenarios').then(function(list) {
    var body = document.getElementById('openaev-scenarios-body');
    var empty = document.getElementById('openaev-scenarios-empty');
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

function openOpenAEVDetail(id) {
  apicall('/api/openaev/scenarios/' + encodeURIComponent(id)).then(function(d) {
    document.getElementById('openaev-detail-title').textContent = d.scenario.Name;
    var body = document.getElementById('openaev-detail-body');
    var injectsHtml = (d.detail.injects || []).map(function(inj) {
      return '<div class="kpi-row"><span>' + x(inj.title) + '</span><span class="tiny muted">' + (inj.techniqueIds || []).join(', ') + '</span></div>';
    }).join('');
    body.innerHTML = '<div class="tiny muted">' + x(d.detail.description || '') + '</div>' + injectsHtml;
    document.getElementById('openaev-detail-overlay').classList.add('open');
  }).catch(function() {});
}

function closeOpenAEVDetail() {
  document.getElementById('openaev-detail-overlay').classList.remove('open');
}

function syncOpenAEVNow() {
  apicall('/api/openaev/sync', { method: 'POST' }).then(function() {
    showToast('OpenAEV sync started', 'ok');
    loadOpenAEVTab();
  }).catch(function(e) { showToast('Sync failed: ' + (e.message || 'error'), 'err'); });
}
```

- [ ] **Step 8: Wire `showTab()`**

Find the `if (name === 'exposure') loadExposureAssets();` line and add immediately after:

```js
if (name === 'openaev') loadOpenAEVTab();
```

- [ ] **Step 9: Static verification (no browser tool assumed available — confirm what actually is before claiming a manual check)**

Run (adjust the grep targets to whatever ids/function names were actually used in Steps 2-8):

```bash
cd orchestrator/wwwroot
grep -c "id=\"tab-openaev\"" index.html          # expect exactly 1
grep -c "id=\"openaev-detail-overlay\"" index.html  # expect exactly 1
grep -c "function loadOpenAEVTab" index.html      # expect exactly 1
grep -c "function openOpenAEVDetail" index.html   # expect exactly 1
grep -c "function closeOpenAEVDetail" index.html  # expect exactly 1
grep -c "'openaev'" index.html                    # expect >= 2 (activateTab array + showTab wiring)
```

Expected: every count matches its comment. If a browser tool is available in this session, additionally load the dashboard, click the tab, and confirm the table/drawer render — do not claim this was done if it wasn't.

- [ ] **Step 10: Sync the hardlinked mirror and commit both paths**

```bash
cd "C:\Users\Administrator\Downloads\Audspect_Cloud"
git status --short orchestrator/wwwroot/index.html orchestrator/cmd/server/wwwroot/index.html
diff -q orchestrator/wwwroot/index.html orchestrator/cmd/server/wwwroot/index.html
git add orchestrator/wwwroot/index.html orchestrator/cmd/server/wwwroot/index.html
git commit -m "feat(ui): add OpenAEV Connector tab"
git push
```

---

### Task 9: Full validation

**Files:** none new — validates everything from Tasks 1-8.

- [ ] **Step 1: Full build and vet**

Run: `cd orchestrator && go build ./... && go vet ./...`
Expected: no errors.

- [ ] **Step 2: gofmt check on every file this plan touched**

Run:
```bash
cd orchestrator
gofmt -l internal/openaev/*.go internal/api/openaev_handlers.go internal/api/openaev_handlers_test.go internal/api/routes.go internal/api/rbac_matrix_test.go internal/db/postgres.go internal/db/content_schema.go cmd/server/main.go
```
Expected: no output (clean).

- [ ] **Step 3: Full package test suite**

Run: `cd orchestrator && go test ./internal/openaev/... ./internal/api/... -v 2>&1 | tail -100`
Expected: all PASS, zero FAIL.

- [ ] **Step 4: Confirm the working tree is clean**

Run: `cd "C:\Users\Administrator\Downloads\Audspect_Cloud" && git status --short`
Expected: no uncommitted changes related to this plan (unrelated pre-existing untracked files in the repo root are expected — not a regression).

- [ ] **Step 5: Update memory**

Update `project_platform_roadmap_2026h2` and `project_openaev_exercise_vision` memory files: mark Module 1 DONE with the commit range, note the "content library only" scope was honored, and confirm SP5 is still the next item to resume once this and Module 2/3 planning settle.
