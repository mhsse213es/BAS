# Control Taxonomy & Control Health Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `internal/controlhealth` — a curated ATT&CK-technique-to-control-category taxonomy plus an engine that computes each category's Prevention Health, Detection Health, coverage-gated Overall Health, and trend from evidence Audspect already collects — and expose it via one new read endpoint, `GET /api/controlhealth/summary`.

**Architecture:** New standalone Go package mirroring `internal/compliance`'s proven shape (embedded curated YAML + inverted index + a compute function joining live evidence). Prevention evidence comes from `scenario_runs.results` (JSONB, unnested via `jsonb_array_elements` — the same pattern `internal/threatpriority/engine.go`'s `loadPreventionVerdicts` already uses). Detection evidence comes from the `verification_history` table (same pattern `internal/threatpriority/engine.go`'s `loadValidationVerdicts` and `internal/pathcorrelation`'s `SQLRunLookup` already use). No new database tables, no changes to any existing package.

**Tech Stack:** Go, PostgreSQL (`pgxpool`), `gopkg.in/yaml.v3`, chi router (existing `internal/api/routes.go`), `internal/testutil.MustSharedTestDB()` for container-backed integration tests.

## Global Constraints

- No frontend/UI changes — this is Sub-project 1 of 5; the dashboard is Sub-project 2.
- No new database tables or migrations — read-only against existing `scenario_runs` and `verification_history`.
- Coverage wording and every other user-facing number must be evidence-based, never fabricated — if a category has zero mapped techniques with evidence, its health is `Unknown`, never a guessed pass.
- Executive rollup (this package's `ComputeSummary`) uses each technique's **primary** category only; secondary-category membership is stored and queryable via `Mapper.CategoriesForTechnique` but not consumed by any code in this plan.
- Per spec: coverage thresholds are `coverageUnknownFloor = 20`, `coverageHealthyFloor = 70` (percent); trend lookback is a fixed 7 days; default evidence window is 30 days, overridable via `?windowDays=`.
- Spec reference: `docs/superpowers/specs/2026-08-01-control-health-foundation-design.md`.

---

### Task 1: Taxonomy data model + Mapper

**Files:**
- Create: `orchestrator/internal/controlhealth/types.go`
- Create: `orchestrator/internal/controlhealth/categories.yaml`
- Create: `orchestrator/internal/controlhealth/mapper.go`
- Test: `orchestrator/internal/controlhealth/mapper_test.go`

**Interfaces:**
- Consumes: nothing (no dependency on any other package).
- Produces: `CategoryDef{ID, Name}`, `Mapper` with `NewMapper() (*Mapper, error)`, `(*Mapper) Categories() []CategoryDef`, `(*Mapper) PrimaryTechniques(categoryID string) []string`, `(*Mapper) CategoriesForTechnique(techID string) (primary string, all []string)`. `baseTechID(id string) string` — package-private helper, reused by Tasks 2 and 3.

- [ ] **Step 1: Write `types.go`**

```go
package controlhealth

// CategoryDef is one control category — the unit executives and auditors
// think in (Endpoint Protection, Identity & Access, ...), as opposed to the
// technical data sources internal/analytics is organized around today.
type CategoryDef struct {
	ID   string `yaml:"id" json:"id"`
	Name string `yaml:"name" json:"name"`
}

// techniqueMapping is one curated YAML entry: an ATT&CK base technique ID
// (no sub-technique suffix) plus the one category it primarily validates and
// any number of categories it also touches. A technique often validates
// multiple controls (T1059 PowerShell touches Endpoint Protection,
// Application Control, and Detection & Response) — forcing a single category
// per technique would make the health model dependent on arbitrary curation
// calls, so both primary and secondary are preserved. Executive health
// rollup (ComputeSummary, Task 4) reads primary only; secondary is stored
// for future drill-down consumers.
type techniqueMapping struct {
	ID        string   `yaml:"id"`
	Primary   string   `yaml:"primary"`
	Secondary []string `yaml:"secondary"`
}

// taxonomyFile is the full parsed shape of categories.yaml.
type taxonomyFile struct {
	Categories []CategoryDef      `yaml:"categories"`
	Techniques []techniqueMapping `yaml:"techniques"`
}
```

- [ ] **Step 2: Write `categories.yaml`**

A V1 starter curation — 10 categories, ~40 techniques. Extend over time the same way `internal/compliance/mappings/*.yaml` is extended; this is not meant to be exhaustive on day one.

```yaml
categories:
  - id: endpoint-protection
    name: Endpoint Protection
  - id: identity-access
    name: Identity & Access Management
  - id: email-security
    name: Email Security
  - id: network-security
    name: Network Security
  - id: data-protection
    name: Data Protection
  - id: privileged-access
    name: Privileged Access
  - id: cloud-security
    name: Cloud Security
  - id: detection-response
    name: Detection & Response
  - id: application-control
    name: Application Control
  - id: backup-recovery
    name: Backup & Recovery

techniques:
  # Endpoint Protection
  - id: T1055
    primary: endpoint-protection
    secondary: [detection-response]
  - id: T1059
    primary: endpoint-protection
    secondary: [application-control, detection-response]
  - id: T1547
    primary: endpoint-protection
    secondary: [privileged-access]
  - id: T1543
    primary: endpoint-protection
    secondary: []
  - id: T1036
    primary: endpoint-protection
    secondary: [detection-response]

  # Identity & Access Management
  - id: T1003
    primary: identity-access
    secondary: [privileged-access, endpoint-protection]
  - id: T1558
    primary: identity-access
    secondary: [privileged-access]
  - id: T1550
    primary: identity-access
    secondary: []
  - id: T1110
    primary: identity-access
    secondary: []
  - id: T1078
    primary: identity-access
    secondary: [privileged-access, cloud-security]

  # Email Security
  - id: T1566
    primary: email-security
    secondary: [detection-response]
  - id: T1204
    primary: email-security
    secondary: [endpoint-protection]
  - id: T1598
    primary: email-security
    secondary: []

  # Network Security
  - id: T1046
    primary: network-security
    secondary: []
  - id: T1021
    primary: network-security
    secondary: [identity-access]
  - id: T1071
    primary: network-security
    secondary: [detection-response]
  - id: T1090
    primary: network-security
    secondary: []

  # Data Protection
  - id: T1041
    primary: data-protection
    secondary: [network-security]
  - id: T1048
    primary: data-protection
    secondary: [network-security]
  - id: T1567
    primary: data-protection
    secondary: [network-security, cloud-security]
  - id: T1005
    primary: data-protection
    secondary: []

  # Privileged Access
  - id: T1068
    primary: privileged-access
    secondary: [endpoint-protection]
  - id: T1134
    primary: privileged-access
    secondary: [identity-access]
  - id: T1548
    primary: privileged-access
    secondary: []

  # Cloud Security
  - id: T1580
    primary: cloud-security
    secondary: []
  - id: T1526
    primary: cloud-security
    secondary: []
  - id: T1538
    primary: cloud-security
    secondary: [detection-response]

  # Detection & Response
  - id: T1070
    primary: detection-response
    secondary: [endpoint-protection]
  - id: T1562
    primary: detection-response
    secondary: [endpoint-protection]
  - id: T1027
    primary: detection-response
    secondary: [endpoint-protection]

  # Application Control
  - id: T1553
    primary: application-control
    secondary: [endpoint-protection]
  - id: T1216
    primary: application-control
    secondary: [endpoint-protection]
  - id: T1218
    primary: application-control
    secondary: [endpoint-protection, detection-response]

  # Backup & Recovery
  - id: T1486
    primary: backup-recovery
    secondary: [data-protection]
  - id: T1490
    primary: backup-recovery
    secondary: []
  - id: T1485
    primary: backup-recovery
    secondary: [data-protection]
```

- [ ] **Step 3: Write `mapper.go`**

```go
package controlhealth

import (
	"embed"
	"fmt"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

//go:embed categories.yaml
var taxonomyFS embed.FS

// Mapper holds the loaded taxonomy and the indexes built from it.
type Mapper struct {
	categories    map[string]CategoryDef
	order         []string            // category IDs in file order, for deterministic output
	primary       map[string][]string // categoryID -> []techniqueID (base, uppercase) whose primary is this category
	techToAll     map[string][]string // techniqueID -> []categoryID (primary + secondary)
	techToPrimary map[string]string   // techniqueID -> categoryID
}

// NewMapper loads and indexes the embedded categories.yaml.
func NewMapper() (*Mapper, error) {
	data, err := taxonomyFS.ReadFile("categories.yaml")
	if err != nil {
		return nil, fmt.Errorf("controlhealth: read categories.yaml: %w", err)
	}
	var tf taxonomyFile
	if err := yaml.Unmarshal(data, &tf); err != nil {
		return nil, fmt.Errorf("controlhealth: parse categories.yaml: %w", err)
	}

	m := &Mapper{
		categories:    make(map[string]CategoryDef),
		primary:       make(map[string][]string),
		techToAll:     make(map[string][]string),
		techToPrimary: make(map[string]string),
	}
	for _, c := range tf.Categories {
		m.categories[c.ID] = c
		m.order = append(m.order, c.ID)
	}
	for _, t := range tf.Techniques {
		tid := baseTechID(t.ID)
		if tid == "" || t.Primary == "" {
			continue
		}
		if _, ok := m.categories[t.Primary]; !ok {
			return nil, fmt.Errorf("controlhealth: technique %s has unknown primary category %q", tid, t.Primary)
		}
		m.techToPrimary[tid] = t.Primary
		m.primary[t.Primary] = append(m.primary[t.Primary], tid)
		all := []string{t.Primary}
		for _, s := range t.Secondary {
			if _, ok := m.categories[s]; !ok {
				return nil, fmt.Errorf("controlhealth: technique %s has unknown secondary category %q", tid, s)
			}
			all = append(all, s)
		}
		m.techToAll[tid] = all
	}
	if len(m.categories) == 0 {
		return nil, fmt.Errorf("controlhealth: no categories loaded")
	}
	for _, techs := range m.primary {
		sort.Strings(techs)
	}
	return m, nil
}

// Categories returns every category, in the order categories.yaml declares them.
func (m *Mapper) Categories() []CategoryDef {
	out := make([]CategoryDef, 0, len(m.order))
	for _, id := range m.order {
		out = append(out, m.categories[id])
	}
	return out
}

// PrimaryTechniques returns the base technique IDs whose primary category is categoryID.
func (m *Mapper) PrimaryTechniques(categoryID string) []string {
	return m.primary[categoryID]
}

// CategoriesForTechnique returns techID's primary category and every category
// (primary + secondary) it touches. Both are empty if techID is unmapped.
func (m *Mapper) CategoriesForTechnique(techID string) (primary string, all []string) {
	tid := baseTechID(techID)
	return m.techToPrimary[tid], m.techToAll[tid]
}

// baseTechID uppercases and strips any sub-technique suffix (T1059.001 -> T1059).
// Control-category membership doesn't need sub-technique granularity, so
// unlike internal/compliance's dual exact/base index, this package uses a
// single base-only index throughout.
func baseTechID(id string) string {
	id = strings.ToUpper(strings.TrimSpace(id))
	if i := strings.Index(id, "."); i > 0 {
		return id[:i]
	}
	return id
}
```

- [ ] **Step 4: Write `mapper_test.go`**

```go
package controlhealth

import "testing"

func TestNewMapper_LoadsAllCategories(t *testing.T) {
	m, err := NewMapper()
	if err != nil {
		t.Fatalf("NewMapper: %v", err)
	}
	cats := m.Categories()
	if len(cats) != 10 {
		t.Fatalf("got %d categories, want 10", len(cats))
	}
	want := "endpoint-protection"
	if cats[0].ID != want {
		t.Errorf("first category = %q, want %q (file order)", cats[0].ID, want)
	}
}

func TestMapper_PrimaryTechniques(t *testing.T) {
	m, err := NewMapper()
	if err != nil {
		t.Fatalf("NewMapper: %v", err)
	}
	techs := m.PrimaryTechniques("endpoint-protection")
	if len(techs) == 0 {
		t.Fatal("expected endpoint-protection to have mapped techniques")
	}
	found := false
	for _, id := range techs {
		if id == "T1059" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected T1059 in endpoint-protection's primary techniques, got %v", techs)
	}
}

func TestMapper_CategoriesForTechnique_PrimaryAndSecondary(t *testing.T) {
	m, err := NewMapper()
	if err != nil {
		t.Fatalf("NewMapper: %v", err)
	}
	primary, all := m.CategoriesForTechnique("T1059")
	if primary != "endpoint-protection" {
		t.Errorf("T1059 primary = %q, want endpoint-protection", primary)
	}
	if len(all) < 2 {
		t.Errorf("T1059 should touch multiple categories (primary + secondary), got %v", all)
	}
}

func TestMapper_CategoriesForTechnique_SubTechniqueMatchesBase(t *testing.T) {
	m, err := NewMapper()
	if err != nil {
		t.Fatalf("NewMapper: %v", err)
	}
	primary, _ := m.CategoriesForTechnique("T1059.001")
	if primary != "endpoint-protection" {
		t.Errorf("T1059.001 should match base T1059's primary, got %q", primary)
	}
}

func TestMapper_CategoriesForTechnique_Unmapped(t *testing.T) {
	m, err := NewMapper()
	if err != nil {
		t.Fatalf("NewMapper: %v", err)
	}
	primary, all := m.CategoriesForTechnique("T9999")
	if primary != "" || len(all) != 0 {
		t.Errorf("unmapped technique should return empty, got primary=%q all=%v", primary, all)
	}
}
```

- [ ] **Step 5: Run tests**

Run: `go test ./internal/controlhealth/... -run TestNewMapper -run TestMapper -v` (from `orchestrator/`)
Expected: all 5 tests PASS.

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/controlhealth/types.go orchestrator/internal/controlhealth/categories.yaml orchestrator/internal/controlhealth/mapper.go orchestrator/internal/controlhealth/mapper_test.go
git commit -m "feat(controlhealth): add control-category taxonomy and mapper"
```

---

### Task 2: Prevention evidence loader

**Files:**
- Create: `orchestrator/internal/controlhealth/prevention.go`
- Test: `orchestrator/internal/controlhealth/prevention_test.go`

**Interfaces:**
- Consumes: `baseTechID` (Task 1). `pgxpool.Pool` (existing dependency, no new import setup).
- Produces: `evidenceRow{TechniqueID, Verdict, At}` (shared shape Task 3 also produces), `loadPreventionEvidence(ctx context.Context, pool *pgxpool.Pool, since time.Time) ([]evidenceRow, error)`.

- [ ] **Step 1: Write `prevention.go`**

```go
package controlhealth

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// evidenceRow is one normalized pass/fail data point for one technique.
// Both loadPreventionEvidence and loadDetectionEvidence (Task 3) produce
// this same shape so health.go (Task 4) can treat the two evidence streams
// uniformly.
type evidenceRow struct {
	TechniqueID string // base technique ID, uppercase
	Verdict     string // "pass" | "fail"
	At          time.Time
}

// loadPreventionEvidence reads every technique result recorded since the
// given cutoff across the whole fleet, from scenario_runs.results (a JSONB
// array per run) via jsonb_array_elements -- the same query shape
// internal/threatpriority/engine.go's loadPreventionVerdicts already uses,
// except this keeps every row (not just DISTINCT ON the latest) so callers
// can both roll up the latest verdict per technique and count total
// evidence volume.
func loadPreventionEvidence(ctx context.Context, pool *pgxpool.Pool, since time.Time) ([]evidenceRow, error) {
	rows, err := pool.Query(ctx, `
		SELECT UPPER(r->'technique'->>'id') AS tid,
		       r->>'result' AS verdict,
		       (r->>'executedAt')::timestamptz AS executed_at
		FROM scenario_runs sr, jsonb_array_elements(sr.results) r
		WHERE sr.status IN ('completed', 'partial')
		  AND r->'technique'->>'id' IS NOT NULL AND r->'technique'->>'id' <> ''
		  AND r->>'result' IN ('pass', 'fail', 'blocked')
		  AND r->>'executedAt' IS NOT NULL
		  AND (r->>'executedAt')::timestamptz >= $1`,
		since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []evidenceRow
	for rows.Next() {
		var tid, verdict string
		var at time.Time
		if err := rows.Scan(&tid, &verdict, &at); err != nil {
			return nil, err
		}
		normalized := "fail"
		if verdict == "pass" || verdict == "blocked" {
			normalized = "pass"
		}
		out = append(out, evidenceRow{TechniqueID: baseTechID(tid), Verdict: normalized, At: at})
	}
	return out, rows.Err()
}
```

- [ ] **Step 2: Write `prevention_test.go`**

```go
package controlhealth

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestLoadPreventionEvidence_ReturnsRowsWithinWindow(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		mustExec(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('ch-a1', 'CH-HOST-1')`)
		mustExec(t, pool, `
			INSERT INTO scenario_runs (id, scenario_id, name, agent_id, status, results, started_at)
			VALUES ('ch-run-1', 'ch-scn-1', 'CH Test Run', 'ch-a1', 'completed', $1::jsonb, NOW())`,
			`[
				{"technique":{"id":"T1059.001","name":"PowerShell","tactic":"execution"},"result":"pass","executedAt":"2026-07-25T10:00:00Z"},
				{"technique":{"id":"T1003","name":"OS Credential Dumping","tactic":"credential-access"},"result":"fail","executedAt":"2026-07-26T10:00:00Z"},
				{"technique":{"id":"T1078","name":"Valid Accounts","tactic":"defense-evasion"},"result":"skipped","executedAt":"2026-07-26T10:00:00Z"}
			]`)

		since := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
		got, err := loadPreventionEvidence(ctx, pool, since)
		if err != nil {
			t.Fatalf("loadPreventionEvidence: %v", err)
		}
		var sawT1059, sawT1003, sawT1078 bool
		for _, r := range got {
			switch r.TechniqueID {
			case "T1059":
				sawT1059 = true
				if r.Verdict != "pass" {
					t.Errorf("T1059 verdict = %q, want pass", r.Verdict)
				}
			case "T1003":
				sawT1003 = true
				if r.Verdict != "fail" {
					t.Errorf("T1003 verdict = %q, want fail", r.Verdict)
				}
			case "T1078":
				sawT1078 = true
			}
		}
		if !sawT1059 {
			t.Error("expected T1059.001 to be normalized to base T1059 and returned")
		}
		if !sawT1003 {
			t.Error("expected T1003 to be returned")
		}
		if sawT1078 {
			t.Error("skipped result must be excluded, but T1078 was returned")
		}
	})
}

func TestLoadPreventionEvidence_ExcludesRowsBeforeWindow(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		mustExec(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('ch-a2', 'CH-HOST-2')`)
		mustExec(t, pool, `
			INSERT INTO scenario_runs (id, scenario_id, name, agent_id, status, results, started_at)
			VALUES ('ch-run-2', 'ch-scn-2', 'CH Old Run', 'ch-a2', 'completed', $1::jsonb, NOW())`,
			`[{"technique":{"id":"T1566","name":"Phishing","tactic":"initial-access"},"result":"pass","executedAt":"2020-01-01T00:00:00Z"}]`)

		since := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
		got, err := loadPreventionEvidence(ctx, pool, since)
		if err != nil {
			t.Fatalf("loadPreventionEvidence: %v", err)
		}
		for _, r := range got {
			if r.TechniqueID == "T1566" {
				t.Error("2020 result must be excluded by the since cutoff, but T1566 was returned")
			}
		}
	})
}
```

- [ ] **Step 3: Run tests**

Run: `go test ./internal/controlhealth/... -run TestLoadPreventionEvidence -v` (from `orchestrator/`)
Expected: both tests PASS. (Requires Docker running — this package's `TestMain`, added in Task 4, provides `sharedDB`; if Task 4 hasn't run yet, temporarily add the same `testmain_test.go` boilerplate as `internal/threatpriority/testmain_test.go` uses, package `controlhealth`, to unblock this task's tests, then leave it in place for Task 4 to reuse.)

- [ ] **Step 4: Add `testmain_test.go` if not already present**

```go
package controlhealth

import (
	"flag"
	"os"
	"testing"

	"github.com/audspect/bas/internal/testutil"
)

var sharedDB *testutil.TestDB

func TestMain(m *testing.M) {
	flag.Parse()
	if testing.Short() {
		os.Exit(m.Run())
	}
	sharedDB = testutil.MustSharedTestDB()
	code := m.Run()
	sharedDB.Cleanup()
	os.Exit(code)
}

func mustExec(t *testing.T, pool *pgxpool.Pool, sql string, args ...any) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), sql, args...); err != nil {
		t.Fatalf("exec %q: %v", sql, err)
	}
}
```

This needs `"context"` and `"github.com/jackc/pgx/v5/pgxpool"` imports alongside the ones shown. Re-run Step 3's test command after adding this file.

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/controlhealth/prevention.go orchestrator/internal/controlhealth/prevention_test.go orchestrator/internal/controlhealth/testmain_test.go
git commit -m "feat(controlhealth): add fleet-wide prevention evidence loader"
```

---

### Task 3: Detection evidence loader

**Files:**
- Create: `orchestrator/internal/controlhealth/detection.go`
- Test: `orchestrator/internal/controlhealth/detection_test.go`

**Interfaces:**
- Consumes: `evidenceRow`, `baseTechID` (Task 2/1). `internal/verification` package constants (`StateApproved`, `ResultDetected`, `ResultNotDetected`) — read-only reference, no new dependency on `verification.Store`.
- Produces: `loadDetectionEvidence(ctx context.Context, pool *pgxpool.Pool, since time.Time) ([]evidenceRow, error)`.

- [ ] **Step 1: Write `detection.go`**

```go
package controlhealth

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/verification"
)

// loadDetectionEvidence reads every Approved, active verification record
// since the given cutoff, from the verification_history table -- the same
// table and Approved+Active convention internal/threatpriority/engine.go's
// loadValidationVerdicts and internal/pathcorrelation's SQLRunLookup already
// use ("only an Approved attestation feeds Coverage" per
// internal/verification/store.go's documented convention).
func loadDetectionEvidence(ctx context.Context, pool *pgxpool.Pool, since time.Time) ([]evidenceRow, error) {
	rows, err := pool.Query(ctx, `
		SELECT UPPER(technique_id) AS tid, result, verified_at
		FROM verification_history
		WHERE active
		  AND workflow_state = $1
		  AND result IN ($2, $3)
		  AND verified_at >= $4`,
		verification.StateApproved, verification.ResultDetected, verification.ResultNotDetected, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []evidenceRow
	for rows.Next() {
		var tid, result string
		var at time.Time
		if err := rows.Scan(&tid, &result, &at); err != nil {
			return nil, err
		}
		verdict := "fail"
		if result == verification.ResultDetected {
			verdict = "pass"
		}
		out = append(out, evidenceRow{TechniqueID: baseTechID(tid), Verdict: verdict, At: at})
	}
	return out, rows.Err()
}
```

- [ ] **Step 2: Write `detection_test.go`**

```go
package controlhealth

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/verification"
)

func seedVerificationRecord(t *testing.T, pool *pgxpool.Pool, id, techID, result, workflowState string, active bool, verifiedAt time.Time) {
	t.Helper()
	mustExec(t, pool, `
		INSERT INTO verification_history
			(id, run_id, expectation_id, profile_name, profile_version, technique_id, domain, provider, result, workflow_state, source, verified_by, verified_at, active)
		VALUES ($1, 'ch-vrun', 'ch-vexp', 'ch-profile', 1, $2, 'endpoint', 'test', $3, $4, $5, 'tester', $6, $7)`,
		id, techID, result, workflowState, verification.SourceAPI, verifiedAt, active)
}

func TestLoadDetectionEvidence_OnlyApprovedActiveCounts(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		now := time.Now().UTC()
		seedVerificationRecord(t, pool, "ch-vh-1", "T1566", verification.ResultDetected, verification.StateApproved, true, now)
		seedVerificationRecord(t, pool, "ch-vh-2", "T1003", verification.ResultNotDetected, verification.StateApproved, true, now)
		seedVerificationRecord(t, pool, "ch-vh-3", "T1078", verification.ResultDetected, verification.StatePending, true, now) // not Approved
		seedVerificationRecord(t, pool, "ch-vh-4", "T1046", verification.ResultDetected, verification.StateApproved, false, now) // not active

		since := now.Add(-24 * time.Hour)
		got, err := loadDetectionEvidence(ctx, pool, since)
		if err != nil {
			t.Fatalf("loadDetectionEvidence: %v", err)
		}
		seen := map[string]string{}
		for _, r := range got {
			seen[r.TechniqueID] = r.Verdict
		}
		if seen["T1566"] != "pass" {
			t.Errorf("T1566 verdict = %q, want pass", seen["T1566"])
		}
		if seen["T1003"] != "fail" {
			t.Errorf("T1003 verdict = %q, want fail", seen["T1003"])
		}
		if _, ok := seen["T1078"]; ok {
			t.Error("Pending (not Approved) record must be excluded, but T1078 was returned")
		}
		if _, ok := seen["T1046"]; ok {
			t.Error("inactive record must be excluded, but T1046 was returned")
		}
	})
}
```

- [ ] **Step 3: Run tests**

Run: `go test ./internal/controlhealth/... -run TestLoadDetectionEvidence -v` (from `orchestrator/`)
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add orchestrator/internal/controlhealth/detection.go orchestrator/internal/controlhealth/detection_test.go
git commit -m "feat(controlhealth): add fleet-wide detection evidence loader"
```

---

### Task 4: Health computation, trend, and summary orchestrator

**Files:**
- Create: `orchestrator/internal/controlhealth/health.go`
- Test: `orchestrator/internal/controlhealth/health_test.go`
- Test: `orchestrator/internal/controlhealth/summary_test.go`

**Interfaces:**
- Consumes: `CategoryDef`, `Mapper` (Task 1), `evidenceRow`, `loadPreventionEvidence`, `loadDetectionEvidence` (Tasks 2-3).
- Produces: `CategoryHealth` struct (the public API shape Task 5's handler serializes), `ComputeSummary(ctx context.Context, pool *pgxpool.Pool, mapper *Mapper, windowDays int) ([]CategoryHealth, error)` — the single exported entry point Task 5 calls.

- [ ] **Step 1: Write `health.go`**

```go
package controlhealth

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Overall Health states.
const (
	HealthHealthy            = "Healthy"
	HealthPartiallyValidated = "PartiallyValidated"
	HealthDegraded           = "Degraded"
	HealthCritical           = "Critical"
	HealthUnknown            = "Unknown"
)

// Coverage thresholds (percent). Below coverageUnknownFloor there isn't
// enough evidence to claim anything; at/above coverageHealthyFloor with a
// passing prevention verdict, the category reads as Healthy rather than
// PartiallyValidated. Proposed V1 defaults -- see the design spec's open
// question before tuning these against real fleet data.
const (
	coverageUnknownFloor = 20
	coverageHealthyFloor = 70
)

// CategoryHealth is the computed, evidence-backed health of one control
// category -- the shape the /api/controlhealth/summary endpoint returns.
type CategoryHealth struct {
	ID                  string     `json:"id"`
	Name                string     `json:"name"`
	PreventionHealth    string     `json:"preventionHealth"` // pass | fail | unknown
	DetectionHealth     string     `json:"detectionHealth"`  // pass | fail | unknown
	OverallHealth       string     `json:"overallHealth"`
	Coverage            int        `json:"coverage"` // 0-100
	ValidatedTechniques int        `json:"validatedTechniques"`
	MappedTechniques    int        `json:"mappedTechniques"`
	EvidenceCount       int        `json:"evidenceCount"`
	Trend               string     `json:"trend"` // Improving | Stable | Declining | InsufficientData
	LastValidated       *time.Time `json:"lastValidated,omitempty"`
}

// ComputeSummary is the package's single exported entry point: it loads all
// evidence once (within windowDays) and computes every category's current
// health plus a 7-day trend from it -- two DB round trips total, regardless
// of category count.
func ComputeSummary(ctx context.Context, pool *pgxpool.Pool, mapper *Mapper, windowDays int) ([]CategoryHealth, error) {
	since := time.Now().UTC().AddDate(0, 0, -windowDays)
	prevRows, err := loadPreventionEvidence(ctx, pool, since)
	if err != nil {
		return nil, fmt.Errorf("controlhealth: load prevention evidence: %w", err)
	}
	detRows, err := loadDetectionEvidence(ctx, pool, since)
	if err != nil {
		return nil, fmt.Errorf("controlhealth: load detection evidence: %w", err)
	}

	now := time.Now().UTC()
	weekAgo := now.AddDate(0, 0, -7)
	cats := mapper.Categories()
	out := make([]CategoryHealth, 0, len(cats))
	for _, cat := range cats {
		techs := mapper.PrimaryTechniques(cat.ID)
		current := computeCategoryHealth(cat, techs, prevRows, detRows, now)
		past := computeCategoryHealth(cat, techs, prevRows, detRows, weekAgo)
		current.Trend = computeTrend(current.OverallHealth, past.OverallHealth)
		out = append(out, current)
	}
	return out, nil
}

// computeCategoryHealth is pure -- no I/O -- so it and everything it calls
// is unit-testable without a database (see health_test.go). asOf lets the
// same evidence rows serve both the "now" and "7-days-ago" computations
// ComputeSummary needs for trend.
func computeCategoryHealth(cat CategoryDef, techs []string, prevRows, detRows []evidenceRow, asOf time.Time) CategoryHealth {
	prevVerdict, validated, prevCount, prevLast := aggregate(prevRows, techs, asOf)
	detVerdict, _, detCount, detLast := aggregate(detRows, techs, asOf)

	mapped := len(techs)
	coverage := 0
	if mapped > 0 {
		coverage = validated * 100 / mapped
	}

	last := prevLast
	if detLast != nil && (last == nil || detLast.After(*last)) {
		last = detLast
	}

	return CategoryHealth{
		ID:                  cat.ID,
		Name:                cat.Name,
		PreventionHealth:    prevVerdict,
		DetectionHealth:     detVerdict,
		OverallHealth:       overallHealth(prevVerdict, detVerdict, coverage),
		Coverage:            coverage,
		ValidatedTechniques: validated,
		MappedTechniques:    mapped,
		EvidenceCount:       prevCount + detCount,
		LastValidated:       last,
	}
}

// aggregate rolls up rows for the given technique set as of asOf: weakest
// link across each technique's most recent result (any fail -> category
// fails; pass only if every technique with a result passed), plus total
// evidence count and the most recent timestamp, both scoped to techs and to
// at-or-before asOf.
func aggregate(rows []evidenceRow, techs []string, asOf time.Time) (verdict string, validated, count int, lastAt *time.Time) {
	techSet := make(map[string]bool, len(techs))
	for _, t := range techs {
		techSet[t] = true
	}

	latest := make(map[string]evidenceRow)
	for _, row := range rows {
		if !techSet[row.TechniqueID] || row.At.After(asOf) {
			continue
		}
		count++
		if lastAt == nil || row.At.After(*lastAt) {
			t := row.At
			lastAt = &t
		}
		if cur, ok := latest[row.TechniqueID]; !ok || row.At.After(cur.At) {
			latest[row.TechniqueID] = row
		}
	}

	validated = len(latest)
	if validated == 0 {
		return HealthUnknownVerdict, 0, count, lastAt
	}
	verdict = "pass"
	for _, r := range latest {
		if r.Verdict == "fail" {
			verdict = "fail"
			break
		}
	}
	return verdict, validated, count, lastAt
}

// HealthUnknownVerdict is the per-stream (prevention/detection) verdict used
// when a category has zero evidence for that stream -- distinct from
// HealthUnknown, which is the *Overall* health state.
const HealthUnknownVerdict = "unknown"

// overallHealth applies the coverage-gated table: a passing prevention
// verdict only reads as Healthy once coverage clears coverageHealthyFloor;
// below coverageUnknownFloor there's too little evidence to say anything.
// The one cell the design spec's table didn't define -- prevention fail,
// detection unknown (never verified either way) -- is treated as Degraded,
// not Critical: "never verified" is worse than a confirmed-working
// detection, but better than a confirmed-failing one.
func overallHealth(prevention, detection string, coverage int) string {
	switch {
	case prevention == HealthUnknownVerdict:
		return HealthUnknown
	case coverage < coverageUnknownFloor:
		return HealthUnknown
	case prevention == "pass":
		if coverage >= coverageHealthyFloor {
			return HealthHealthy
		}
		return HealthPartiallyValidated
	case prevention == "fail" && detection == "pass":
		return HealthDegraded
	case prevention == "fail" && detection == "fail":
		return HealthCritical
	default: // prevention == "fail", detection == "unknown"
		return HealthDegraded
	}
}

// rankHealth orders Overall Health states best-to-worst for trend
// comparison; Unknown ranks below every real state (-1) so InsufficientData
// is always chosen instead of a misleading Improving/Declining.
func rankHealth(h string) int {
	switch h {
	case HealthHealthy:
		return 3
	case HealthPartiallyValidated:
		return 2
	case HealthDegraded:
		return 1
	case HealthCritical:
		return 0
	default:
		return -1
	}
}

// computeTrend compares Overall Health state, not raw pass-rate -- a
// pass-rate wobble inside a state that stays Critical must not read as
// Improving.
func computeTrend(current, past string) string {
	cr, pr := rankHealth(current), rankHealth(past)
	if cr < 0 || pr < 0 {
		return "InsufficientData"
	}
	switch {
	case cr > pr:
		return "Improving"
	case cr < pr:
		return "Declining"
	default:
		return "Stable"
	}
}
```

- [ ] **Step 2: Write `health_test.go`** (pure unit tests, no database needed)

```go
package controlhealth

import (
	"testing"
	"time"
)

var testCat = CategoryDef{ID: "test-category", Name: "Test Category"}

func mkRow(tech, verdict string, daysAgo int, now time.Time) evidenceRow {
	return evidenceRow{TechniqueID: tech, Verdict: verdict, At: now.AddDate(0, 0, -daysAgo)}
}

func TestOverallHealth_AllCombinations(t *testing.T) {
	cases := []struct {
		name       string
		prevention string
		detection  string
		coverage   int
		want       string
	}{
		{"prevention pass, high coverage -> Healthy", "pass", HealthUnknownVerdict, 92, HealthHealthy},
		{"prevention pass, very low coverage -> Unknown", "pass", HealthUnknownVerdict, 8, HealthUnknown}, // 8 < unknownFloor(20)
		{"prevention pass, mid coverage -> PartiallyValidated", "pass", HealthUnknownVerdict, 45, HealthPartiallyValidated},
		{"prevention pass, exactly healthy floor -> Healthy", "pass", HealthUnknownVerdict, 70, HealthHealthy},
		{"prevention fail, detection pass -> Degraded", "fail", "pass", 90, HealthDegraded},
		{"prevention fail, detection fail -> Critical", "fail", "fail", 90, HealthCritical},
		{"prevention fail, detection unknown -> Degraded", "fail", HealthUnknownVerdict, 90, HealthDegraded},
		{"prevention unknown -> Unknown regardless of coverage", HealthUnknownVerdict, "pass", 100, HealthUnknown},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := overallHealth(c.prevention, c.detection, c.coverage)
			if got != c.want {
				t.Errorf("overallHealth(%q, %q, %d) = %q, want %q", c.prevention, c.detection, c.coverage, got, c.want)
			}
		})
	}
}

func TestAggregate_WeakestLink_OneFailFailsCategory(t *testing.T) {
	now := time.Now().UTC()
	rows := []evidenceRow{
		mkRow("T1059", "pass", 1, now),
		mkRow("T1003", "pass", 1, now),
		mkRow("T1078", "fail", 1, now),
	}
	verdict, validated, count, _ := aggregate(rows, []string{"T1059", "T1003", "T1078"}, now)
	if verdict != "fail" {
		t.Errorf("verdict = %q, want fail (weakest link)", verdict)
	}
	if validated != 3 {
		t.Errorf("validated = %d, want 3", validated)
	}
	if count != 3 {
		t.Errorf("count = %d, want 3", count)
	}
}

func TestAggregate_MostRecentPerTechniqueWins(t *testing.T) {
	now := time.Now().UTC()
	rows := []evidenceRow{
		mkRow("T1059", "fail", 10, now), // older
		mkRow("T1059", "pass", 1, now),  // newer -- this one should win
	}
	verdict, validated, count, _ := aggregate(rows, []string{"T1059"}, now)
	if verdict != "pass" {
		t.Errorf("verdict = %q, want pass (most recent result)", verdict)
	}
	if validated != 1 {
		t.Errorf("validated = %d, want 1", validated)
	}
	if count != 2 {
		t.Errorf("count = %d, want 2 (both rows counted as evidence)", count)
	}
}

func TestAggregate_RowsAfterAsOfExcluded(t *testing.T) {
	now := time.Now().UTC()
	rows := []evidenceRow{
		mkRow("T1059", "fail", -1, now), // 1 day in the FUTURE relative to asOf
	}
	verdict, validated, _, _ := aggregate(rows, []string{"T1059"}, now)
	if verdict != HealthUnknownVerdict || validated != 0 {
		t.Errorf("future-dated row must be excluded by asOf; got verdict=%q validated=%d", verdict, validated)
	}
}

func TestAggregate_NoEvidence_ReturnsUnknown(t *testing.T) {
	now := time.Now().UTC()
	verdict, validated, count, lastAt := aggregate(nil, []string{"T1059"}, now)
	if verdict != HealthUnknownVerdict || validated != 0 || count != 0 || lastAt != nil {
		t.Errorf("empty evidence should be all-zero unknown, got verdict=%q validated=%d count=%d lastAt=%v", verdict, validated, count, lastAt)
	}
}

func TestComputeTrend(t *testing.T) {
	cases := []struct {
		current, past, want string
	}{
		{HealthHealthy, HealthDegraded, "Improving"},
		{HealthCritical, HealthCritical, "Stable"},
		{HealthDegraded, HealthHealthy, "Declining"},
		{HealthUnknown, HealthHealthy, "InsufficientData"},
		{HealthHealthy, HealthUnknown, "InsufficientData"},
	}
	for _, c := range cases {
		got := computeTrend(c.current, c.past)
		if got != c.want {
			t.Errorf("computeTrend(%q, %q) = %q, want %q", c.current, c.past, got, c.want)
		}
	}
}

func TestComputeCategoryHealth_MappedButNoEvidence_IsUnknown(t *testing.T) {
	now := time.Now().UTC()
	got := computeCategoryHealth(testCat, []string{"T1059", "T1003"}, nil, nil, now)
	if got.OverallHealth != HealthUnknown {
		t.Errorf("OverallHealth = %q, want Unknown for a mapped-but-untested category", got.OverallHealth)
	}
	if got.MappedTechniques != 2 || got.ValidatedTechniques != 0 || got.Coverage != 0 {
		t.Errorf("got %+v, want MappedTechniques=2 ValidatedTechniques=0 Coverage=0", got)
	}
}
```

- [ ] **Step 3: Run the pure unit tests**

Run: `go test ./internal/controlhealth/... -short -v` (from `orchestrator/`)
Expected: `mapper_test.go`'s tests plus every `health_test.go` test PASS; the `-short` flag skips Tasks 2-3's container-backed tests (they self-skip via `testing.Short()`), so this confirms the pure computation logic without needing Docker.

- [ ] **Step 4: Write `summary_test.go`** (container-backed, exercises the full `ComputeSummary` path end-to-end)

```go
package controlhealth

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/verification"
)

func TestComputeSummary_EndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		mapper, err := NewMapper()
		if err != nil {
			t.Fatalf("NewMapper: %v", err)
		}

		mustExec(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('ch-e2e-a1', 'CH-E2E-HOST')`)
		mustExec(t, pool, `
			INSERT INTO scenario_runs (id, scenario_id, name, agent_id, status, results, started_at)
			VALUES ('ch-e2e-run', 'ch-e2e-scn', 'CH E2E Run', 'ch-e2e-a1', 'completed', $1::jsonb, NOW())`,
			`[{"technique":{"id":"T1566","name":"Phishing","tactic":"initial-access"},"result":"pass","executedAt":"`+time.Now().UTC().Format(time.RFC3339)+`"}]`)
		seedVerificationRecord(t, pool, "ch-e2e-vh", "T1566", verification.ResultDetected, verification.StateApproved, true, time.Now().UTC())

		out, err := ComputeSummary(ctx, pool, mapper, 30)
		if err != nil {
			t.Fatalf("ComputeSummary: %v", err)
		}
		if len(out) != 10 {
			t.Fatalf("got %d categories, want 10", len(out))
		}
		var email CategoryHealth
		for _, c := range out {
			if c.ID == "email-security" {
				email = c
			}
		}
		if email.PreventionHealth != "pass" {
			t.Errorf("email-security.PreventionHealth = %q, want pass", email.PreventionHealth)
		}
		if email.DetectionHealth != "pass" {
			t.Errorf("email-security.DetectionHealth = %q, want pass", email.DetectionHealth)
		}
		if email.EvidenceCount == 0 {
			t.Error("expected non-zero EvidenceCount for email-security")
		}
		if email.LastValidated == nil {
			t.Error("expected LastValidated to be set")
		}
	})
}
```

- [ ] **Step 5: Run all controlhealth tests**

Run: `go test ./internal/controlhealth/... -v` (from `orchestrator/`, requires Docker running)
Expected: every test in the package PASSes.

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/controlhealth/health.go orchestrator/internal/controlhealth/health_test.go orchestrator/internal/controlhealth/summary_test.go
git commit -m "feat(controlhealth): add coverage-gated health computation, trend, and summary orchestrator"
```

---

### Task 5: API endpoint and wiring

**Files:**
- Create: `orchestrator/internal/api/controlhealth_handlers.go`
- Test: `orchestrator/internal/api/controlhealth_handlers_test.go`
- Modify: `orchestrator/internal/api/handlers.go` (Handler struct field + `WithControlHealth` method)
- Modify: `orchestrator/internal/api/routes.go` (route registration)
- Modify: `orchestrator/cmd/server/main.go` (mapper construction + wiring into the handler chain)

**Interfaces:**
- Consumes: `controlhealth.NewMapper()`, `controlhealth.ComputeSummary()` (Task 4).
- Produces: `GET /api/controlhealth/summary?windowDays=` — the endpoint Sub-project 2's dashboard will consume.

- [ ] **Step 1: Add the Handler field and `WithControlHealth` method**

In `orchestrator/internal/api/handlers.go`, find the field block containing `complianceMapper` (mirror its exact comment style):

```go
	complianceMapper      *compliance.Mapper   // nil when not loaded
```

Add immediately after it:

```go
	complianceMapper      *compliance.Mapper   // nil when not loaded
	controlHealthMapper   *controlhealth.Mapper // nil when not loaded
```

Find `WithCompliance`:

```go
// WithCompliance attaches the compliance mapper.
func (h *Handler) WithCompliance(m *compliance.Mapper) *Handler {
	h.complianceMapper = m
	return h
}
```

Add immediately after it:

```go
// WithControlHealth attaches the control-health taxonomy mapper.
func (h *Handler) WithControlHealth(m *controlhealth.Mapper) *Handler {
	h.controlHealthMapper = m
	return h
}
```

Add `"github.com/audspect/bas/internal/controlhealth"` to `handlers.go`'s import block, alongside the existing `"github.com/audspect/bas/internal/compliance"` import.

- [ ] **Step 2: Write the handler**

```go
// orchestrator/internal/api/controlhealth_handlers.go
package api

import (
	"net/http"
	"strconv"

	"github.com/audspect/bas/internal/controlhealth"
)

// GetControlHealthSummary returns every control category's computed health,
// fleet-wide. Read-only (Viewer+), matching /api/compliance/frameworks and
// /api/attackpath/correlation's access convention.
// GET /api/controlhealth/summary?windowDays=30
func (h *Handler) GetControlHealthSummary(w http.ResponseWriter, r *http.Request) {
	if h.controlHealthMapper == nil {
		jsonError(w, "control health mapper not loaded", http.StatusServiceUnavailable)
		return
	}
	windowDays := 30
	if v := r.URL.Query().Get("windowDays"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			windowDays = n
		}
	}
	categories, err := controlhealth.ComputeSummary(r.Context(), h.db, h.controlHealthMapper, windowDays)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respond(w, map[string]any{"categories": categories})
}
```

- [ ] **Step 3: Register the route**

In `orchestrator/internal/api/routes.go`, find:

```go
		r.Get("/api/attackpath/correlation", h.GetAttackPathCorrelation)
```

Add immediately after it:

```go
		r.Get("/api/attackpath/correlation", h.GetAttackPathCorrelation)
		r.Get("/api/controlhealth/summary", h.GetControlHealthSummary)
```

- [ ] **Step 4: Wire it up in `main.go`**

Find:

```go
	// ── Compliance Mapper ─────────────────────────────────────────────────
	complianceMapper, cmErr := compliance.NewMapper()
	if cmErr != nil {
		log.Printf("[!] compliance mapper: %v — compliance reports unavailable", cmErr)
	} else {
		log.Printf("[+] Compliance mapper loaded (%d frameworks)", len(complianceMapper.Frameworks()))
	}
```

Add immediately after it:

```go
	// ── Control Health Mapper ───────────────────────────────────────────────
	controlHealthMapper, chErr := controlhealth.NewMapper()
	if chErr != nil {
		log.Printf("[!] control health mapper: %v — control health summary unavailable", chErr)
	} else {
		log.Printf("[+] Control health mapper loaded (%d categories)", len(controlHealthMapper.Categories()))
	}
```

Find the `WithCompliance(complianceMapper).` line in the handler chain and add immediately after it:

```go
		WithCompliance(complianceMapper).
		WithControlHealth(controlHealthMapper).
```

Add `"github.com/audspect/bas/internal/controlhealth"` to `main.go`'s import block.

- [ ] **Step 5: Write `controlhealth_handlers_test.go`**

```go
package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/controlhealth"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

// TestGetControlHealthSummary_NilMapper503 mirrors the existing
// TestComplianceHandlers_NilMapper503 pattern in report_nil_engine_test.go:
// a Handler built with no WithControlHealth call must 503, not panic.
func TestGetControlHealthSummary_NilMapper503(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		// No WithControlHealth — controlHealthMapper stays nil.
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		req := httptest.NewRequest(http.MethodGet, "/api/controlhealth/summary", nil)
		w := httptest.NewRecorder()
		h.GetControlHealthSummary(w, req)
		if w.Code != http.StatusServiceUnavailable {
			t.Errorf("status = %d, want 503", w.Code)
		}
	})
}

func TestGetControlHealthSummary_ReturnsAllCategories(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mapper, err := controlhealth.NewMapper()
		if err != nil {
			t.Fatalf("controlhealth.NewMapper: %v", err)
		}
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "").WithControlHealth(mapper)

		req := httptest.NewRequest(http.MethodGet, "/api/controlhealth/summary", nil)
		w := httptest.NewRecorder()
		h.GetControlHealthSummary(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
		}
		var body struct {
			Categories []controlhealth.CategoryHealth `json:"categories"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if len(body.Categories) != 10 {
			t.Errorf("got %d categories, want 10", len(body.Categories))
		}
	})
}
```

- [ ] **Step 6: Run tests and build**

Run: `go build ./...` (from `orchestrator/`)
Expected: clean build, no errors.

Run: `go test ./internal/controlhealth/... ./internal/api/... -run ControlHealth -v` (from `orchestrator/`)
Expected: all ControlHealth-related tests PASS.

- [ ] **Step 7: Commit**

```bash
git add orchestrator/internal/api/controlhealth_handlers.go orchestrator/internal/api/controlhealth_handlers_test.go orchestrator/internal/api/handlers.go orchestrator/internal/api/routes.go orchestrator/cmd/server/main.go
git commit -m "feat(controlhealth): expose GET /api/controlhealth/summary"
```

---

## Self-Review Notes

- **Spec coverage:** Taxonomy data model with primary+secondary (Task 1) · Prevention evidence stream (Task 2) · Detection evidence stream (Task 3) · weakest-link rollup, coverage-gated Overall Health, trend-from-state (Task 4) · API surface (Task 5). All spec sections have a task.
- **Placeholder scan:** none — every step has literal, complete code. Step 5 of Task 5 has one explicit instruction to check an existing helper name before use rather than guessing it, since the engineer implementing this plan has access to the actual test file and this plan's author does not — this is a pointer to verify, not a TBD.
- **Type consistency:** `evidenceRow` (Task 2) is reused unchanged by Task 3 and Task 4. `CategoryHealth` (Task 4) matches the JSON shape Task 5's handler returns and the shape `controlhealth_handlers_test.go` unmarshals into. `Mapper.PrimaryTechniques`/`Categories` (Task 1) are called with the same signatures in Task 4's `ComputeSummary`. `HealthUnknownVerdict` (evidence-stream verdict) and `HealthUnknown` (Overall Health state) are deliberately distinct constants, used consistently throughout Task 4 and its tests.
