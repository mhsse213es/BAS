# Global Search Phase 5 (Long-Tail Entity Expansion) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Index 4 new real doc types (`rule`, `compliance_control`, `detection_connector`, `action_connector`) into the existing `search_documents` table, and add Search's first RBAC-aware result filtering so connector documents are only visible to callers with the matching list permission.

**Architecture:** Four new builder functions feed `internal/search.ReindexAll` exactly like the existing 8 (Phase 1); `ReindexAll`'s signature grows two params (`*rulelib.Engine`, `*compliance.Mapper`) so the new builders have data to read. `compliance.Mapper` gets one small new accessor (`AllControls()`) since it has no flat cross-framework control list today. `internal/search/query_parse.go`'s `knownDocTypes` grows 4 entries so `type:` filtering and browse mode work for the new types too. RBAC filtering is a new step in the `Search` HTTP handler (not in the `search` package, which stays free of any `auth` dependency) — two explicit permission checks, since only 2 of the 12 total doc types need gating. Two small frontend edits (`CMDK_SEARCH_LABELS`, `searchFlat()`'s type list) let the palette render and group the new result types; no new frontend navigation code, since `cmdkOpenResult`'s existing fallback branch already handles any unrecognized `docType`.

**Tech Stack:** Go, Postgres (pgx), `go:embed`, vanilla JS (no framework) in `cmd/server/wwwroot/index.html`.

## Global Constraints

- Connector builders must `SELECT` only `id, name, provider` — never `client_secret`/`api_token`/`tenant_id`/`base_url`/`workspace_id`/any other credential or config column, matching the existing admin-UI queries' own restraint (`ListDetectionConnectors`/`ListResponseConnectors`).
- `detection_connector` and `action_connector` stay two separate doc types, never merged, since they're gated by two independently-grantable permissions (`CanListDetectionConnectors` / `CanListResponseConnectors`).
- No new frontend navigation/dispatch code — all 4 new types render via the existing `cmdkResultFallback` drawer.
- `internal/search` package must not import `internal/auth` — RBAC filtering is handler-level only.
- Every SQL/JSON test that seeds `search_documents` directly must explicitly set `Tags` (or the seeded row violates the column's `NOT NULL` constraint) — matches the recurring nil-slice-to-NULL pgx gotcha this codebase has hit repeatedly.

---

### Task 1: `compliance.Mapper.AllControls()` accessor

**Files:**
- Modify: `orchestrator/internal/compliance/mapper.go` (add method after `Frameworks()`, currently ending around line 86)
- Test: `orchestrator/internal/compliance/mapper_test.go`

**Interfaces:**
- Produces: `type ControlWithFramework struct { FrameworkID string; Control ControlDef }` and `func (m *Mapper) AllControls() []ControlWithFramework` — consumed by Task 3's `complianceControlsFrom`.

- [ ] **Step 1: Write the failing test**

Append to `orchestrator/internal/compliance/mapper_test.go`:

```go
func TestAllControls_FlattensEveryFrameworkSortedDeterministically(t *testing.T) {
	m, err := NewMapper()
	if err != nil {
		t.Fatalf("NewMapper: %v", err)
	}
	all := m.AllControls()

	wantTotal := 0
	for _, fw := range m.Frameworks() {
		wantTotal += fw.TotalControls
	}
	if len(all) != wantTotal {
		t.Fatalf("AllControls() returned %d controls, want %d (sum of every framework's TotalControls)", len(all), wantTotal)
	}

	for i, cwf := range all {
		if cwf.FrameworkID == "" || cwf.Control.ID == "" {
			t.Fatalf("all[%d] = %+v, want non-empty FrameworkID and Control.ID", i, cwf)
		}
		if i > 0 {
			prev := all[i-1]
			if cwf.FrameworkID < prev.FrameworkID {
				t.Fatalf("all[%d].FrameworkID = %q sorts before all[%d].FrameworkID = %q, want non-decreasing", i, cwf.FrameworkID, i-1, prev.FrameworkID)
			}
			if cwf.FrameworkID == prev.FrameworkID && cwf.Control.ID < prev.Control.ID {
				t.Fatalf("within framework %q, all[%d].Control.ID = %q sorts before all[%d].Control.ID = %q, want non-decreasing", cwf.FrameworkID, i, cwf.Control.ID, i-1, prev.Control.ID)
			}
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/compliance/... -run TestAllControls_FlattensEveryFrameworkSortedDeterministically -v`
Expected: FAIL with `m.AllControls undefined (type *Mapper has no field or method AllControls)`

- [ ] **Step 3: Implement `AllControls()`**

In `orchestrator/internal/compliance/mapper.go`, immediately after the existing `Frameworks()` method (which ends with `return out` / `}` around line 86), add:

```go
// ControlWithFramework pairs a control with the ID of the framework that
// defines it -- AllControls flattens every loaded framework's controls
// into one slice for consumers (Global Search Phase 5) that don't care
// about per-framework grouping.
type ControlWithFramework struct {
	FrameworkID string
	Control     ControlDef
}

// AllControls returns every control across every loaded framework, sorted
// by FrameworkID then control ID for deterministic output.
func (m *Mapper) AllControls() []ControlWithFramework {
	out := make([]ControlWithFramework, 0)
	for _, fw := range m.frameworks {
		for _, ctrl := range fw.Controls {
			out = append(out, ControlWithFramework{FrameworkID: fw.ID, Control: ctrl})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].FrameworkID != out[j].FrameworkID {
			return out[i].FrameworkID < out[j].FrameworkID
		}
		return out[i].Control.ID < out[j].Control.ID
	})
	return out
}
```

`sort` is already imported in `mapper.go` (used by `Frameworks()`) — no new import needed.

- [ ] **Step 4: Run test to verify it passes**

Run: `cd orchestrator && go test ./internal/compliance/... -run TestAllControls_FlattensEveryFrameworkSortedDeterministically -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/compliance/mapper.go orchestrator/internal/compliance/mapper_test.go
git commit -m "feat(compliance): add Mapper.AllControls() flat cross-framework accessor"
git push
```

---

### Task 2: `rulesFrom` and `complianceControlsFrom` search builders

**Files:**
- Modify: `orchestrator/internal/search/builders.go` (add two functions after the existing `techniquesFrom`, which ends around line 180)
- Test: `orchestrator/internal/search/builders_test.go`

**Interfaces:**
- Consumes: `*rulelib.Engine` with `Search(rulelib.SearchFilter) []rulelib.Rule` (existing, `internal/rulelib/search.go:17`); `rulelib.Rule{ID, Title, Description, TechniqueIDs, Severity, Status string/[]string}` (existing, `internal/rulelib/model.go`). `*compliance.Mapper` with `AllControls() []compliance.ControlWithFramework` (Task 1). `compliance.ControlDef{ID, Name, Domain, Category string; Techniques []string}` (existing).
- Produces: `func rulesFrom(engine *rulelib.Engine) []Document` and `func complianceControlsFrom(mapper *compliance.Mapper) []Document` — consumed by Task 4's `ReindexAll`.

- [ ] **Step 1: Write the failing tests**

Append to `orchestrator/internal/search/builders_test.go`:

```go
func TestRulesFrom_MapsRealEmbeddedRules(t *testing.T) {
	engine := rulelib.NewEngine()
	docs := rulesFrom(engine)
	if len(docs) != engine.RuleCount() {
		t.Fatalf("rulesFrom() returned %d documents, want %d (engine.RuleCount())", len(docs), engine.RuleCount())
	}

	var found bool
	for _, d := range docs {
		if d.SourceID != "AUDRULE-000001" {
			continue
		}
		found = true
		if d.DocType != "rule" {
			t.Errorf("DocType = %q, want %q", d.DocType, "rule")
		}
		if d.Title != "Suspicious PowerShell Encoded Command" {
			t.Errorf("Title = %q, want %q", d.Title, "Suspicious PowerShell Encoded Command")
		}
		if d.Description != "Detects encoded PowerShell command execution" {
			t.Errorf("Description = %q, want %q", d.Description, "Detects encoded PowerShell command execution")
		}
		hasTechnique, hasSeverity := false, false
		for _, tag := range d.Tags {
			if tag == "T1059.001" {
				hasTechnique = true
			}
			if tag == "medium" {
				hasSeverity = true
			}
		}
		if !hasTechnique {
			t.Errorf("Tags = %v, want to include technique %q", d.Tags, "T1059.001")
		}
		if !hasSeverity {
			t.Errorf("Tags = %v, want to include severity %q", d.Tags, "medium")
		}
	}
	if !found {
		t.Fatal("rulesFrom() did not include AUDRULE-000001 -- check the embedded rule bundle in internal/rulelib/ruledata/rules.json")
	}
}

func TestComplianceControlsFrom_NilMapperReturnsNoDocuments(t *testing.T) {
	docs := complianceControlsFrom(nil)
	if len(docs) != 0 {
		t.Fatalf("complianceControlsFrom(nil) = %+v, want no documents", docs)
	}
}

func TestComplianceControlsFrom_MapsRealFrameworkControls(t *testing.T) {
	mapper, err := compliance.NewMapper()
	if err != nil {
		t.Fatalf("compliance.NewMapper: %v", err)
	}
	docs := complianceControlsFrom(mapper)
	if len(docs) != len(mapper.AllControls()) {
		t.Fatalf("complianceControlsFrom() returned %d documents, want %d (len(mapper.AllControls()))", len(docs), len(mapper.AllControls()))
	}

	first := mapper.AllControls()[0]
	wantSourceID := first.FrameworkID + ":" + first.Control.ID
	var found bool
	for _, d := range docs {
		if d.SourceID != wantSourceID {
			continue
		}
		found = true
		if d.DocType != "compliance_control" {
			t.Errorf("DocType = %q, want %q", d.DocType, "compliance_control")
		}
		if d.Title != first.Control.Name {
			t.Errorf("Title = %q, want %q", d.Title, first.Control.Name)
		}
		hasFramework := false
		for _, tag := range d.Tags {
			if tag == first.FrameworkID {
				hasFramework = true
			}
		}
		if !hasFramework {
			t.Errorf("Tags = %v, want to include framework ID %q", d.Tags, first.FrameworkID)
		}
	}
	if !found {
		t.Fatalf("complianceControlsFrom() did not include namespaced SourceID %q", wantSourceID)
	}
}
```

Add `"github.com/audspect/bas/internal/compliance"` and `"github.com/audspect/bas/internal/rulelib"` to `builders_test.go`'s import block.

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/search/... -run 'TestRulesFrom_MapsRealEmbeddedRules|TestComplianceControlsFrom' -v`
Expected: FAIL with `undefined: rulesFrom` / `undefined: complianceControlsFrom`

- [ ] **Step 3: Implement the builders**

In `orchestrator/internal/search/builders.go`, add `"github.com/audspect/bas/internal/compliance"` and `"github.com/audspect/bas/internal/rulelib"` to the import block, then append after `techniquesFrom`:

```go
// rulesFrom maps every embedded Sigma rule into a Document. engine may be
// nil if the caller never attached a rule library (mirrors h.rules'
// nil-when-unloaded convention in internal/api.Handler) -- returns no
// documents rather than panicking.
func rulesFrom(engine *rulelib.Engine) []Document {
	if engine == nil {
		return nil
	}
	rules := engine.Search(rulelib.SearchFilter{}) // empty filter = every rule, same call ListRules already makes
	out := make([]Document, 0, len(rules))
	for _, r := range rules {
		out = append(out, Document{
			DocType: "rule", SourceID: r.ID, Title: r.Title,
			Description: r.Description,
			Tags:        append([]string{r.Severity, r.Status}, r.TechniqueIDs...),
		})
	}
	return out
}

// complianceControlsFrom maps every control across every loaded compliance
// framework into a Document. mapper may be nil (WithCompliance was never
// called, or compliance.NewMapper() failed at startup) -- returns no
// documents rather than erroring, matching how h.complianceMapper == nil is
// already handled throughout internal/api's compliance handlers.
func complianceControlsFrom(mapper *compliance.Mapper) []Document {
	if mapper == nil {
		return nil
	}
	out := []Document{}
	for _, cwf := range mapper.AllControls() {
		tags := append([]string{cwf.FrameworkID, cwf.Control.Domain, cwf.Control.Category}, cwf.Control.Techniques...)
		out = append(out, Document{
			DocType:     "compliance_control",
			SourceID:    cwf.FrameworkID + ":" + cwf.Control.ID, // namespaced -- the same control ID can recur across frameworks
			Title:       cwf.Control.Name,
			Description: cwf.Control.Domain + " · " + cwf.Control.Category,
			Tags:        tags,
		})
	}
	return out
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/search/... -run 'TestRulesFrom_MapsRealEmbeddedRules|TestComplianceControlsFrom' -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/search/builders.go orchestrator/internal/search/builders_test.go
git commit -m "feat(search): add rulesFrom and complianceControlsFrom document builders"
git push
```

---

### Task 3: `detectionConnectorsFrom` and `actionConnectorsFrom` search builders

**Files:**
- Modify: `orchestrator/internal/search/builders.go` (append after Task 2's two functions)
- Test: `orchestrator/internal/search/builders_test.go`

**Interfaces:**
- Consumes: `detection_connectors` table (`id, name, provider` columns, existing schema at `orchestrator/internal/db/postgres.go:857`); `action_connectors` table (`id, name, provider` columns, existing schema at `orchestrator/internal/db/postgres.go:884`).
- Produces: `func detectionConnectorsFrom(ctx context.Context, pool *pgxpool.Pool) ([]Document, error)` and `func actionConnectorsFrom(ctx context.Context, pool *pgxpool.Pool) ([]Document, error)` — consumed by Task 4's `ReindexAll`.

- [ ] **Step 1: Write the failing tests**

Append to `orchestrator/internal/search/builders_test.go` (these are Postgres-backed, following the `sharedDB.RunWithPool` pattern already used in `store_test.go`):

```go
func TestDetectionConnectorsFrom_MapsNameProviderNeverSecrets(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		if _, err := pool.Exec(ctx,
			`INSERT INTO detection_connectors (id, name, provider, client_secret, api_token)
			 VALUES ('dc-1', 'Prod Sentinel', 'microsoft_sentinel', 'super-secret-value', 'super-secret-token')`); err != nil {
			t.Fatalf("seed detection_connectors: %v", err)
		}

		docs, err := detectionConnectorsFrom(ctx, pool)
		if err != nil {
			t.Fatalf("detectionConnectorsFrom: %v", err)
		}
		if len(docs) != 1 {
			t.Fatalf("detectionConnectorsFrom() = %+v, want 1 document", docs)
		}
		d := docs[0]
		if d.DocType != "detection_connector" || d.SourceID != "dc-1" || d.Title != "Prod Sentinel" {
			t.Fatalf("document = %+v, want DocType=detection_connector SourceID=dc-1 Title=%q", d, "Prod Sentinel")
		}
		if strings.Contains(d.Description, "super-secret") || strings.Contains(strings.Join(d.Tags, " "), "super-secret") {
			t.Fatalf("document leaked a secret value: %+v", d)
		}
		if d.Description != "provider: microsoft_sentinel" {
			t.Errorf("Description = %q, want %q", d.Description, "provider: microsoft_sentinel")
		}
	})
}

func TestActionConnectorsFrom_MapsNameProviderNeverSecrets(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		if _, err := pool.Exec(ctx,
			`INSERT INTO action_connectors (id, name, provider, client_secret)
			 VALUES ('ac-1', 'Prod CrowdStrike', 'crowdstrike', 'super-secret-value')`); err != nil {
			t.Fatalf("seed action_connectors: %v", err)
		}

		docs, err := actionConnectorsFrom(ctx, pool)
		if err != nil {
			t.Fatalf("actionConnectorsFrom: %v", err)
		}
		if len(docs) != 1 {
			t.Fatalf("actionConnectorsFrom() = %+v, want 1 document", docs)
		}
		d := docs[0]
		if d.DocType != "action_connector" || d.SourceID != "ac-1" || d.Title != "Prod CrowdStrike" {
			t.Fatalf("document = %+v, want DocType=action_connector SourceID=ac-1 Title=%q", d, "Prod CrowdStrike")
		}
		if strings.Contains(d.Description, "super-secret") || strings.Contains(strings.Join(d.Tags, " "), "super-secret") {
			t.Fatalf("document leaked a secret value: %+v", d)
		}
	})
}
```

Add `"context"` and `"strings"` to `builders_test.go`'s import block if not already present (the file currently imports `"os"`, `"path/filepath"`, `"testing"`, and `"github.com/audspect/bas/internal/scenario"` — `context` and `strings` and `github.com/jackc/pgx/v5/pgxpool` are new).

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/search/... -run 'TestDetectionConnectorsFrom|TestActionConnectorsFrom' -v`
Expected: FAIL with `undefined: detectionConnectorsFrom` / `undefined: actionConnectorsFrom`

- [ ] **Step 3: Implement the builders**

Append to `orchestrator/internal/search/builders.go`:

```go
// detectionConnectorsFrom maps every detection_connectors row into a
// Document. Selects only id/name/provider -- never client_secret/api_token/
// tenant_id/base_url/workspace_id, matching the same restraint
// ListDetectionConnectors's own SELECT already exercises.
func detectionConnectorsFrom(ctx context.Context, pool *pgxpool.Pool) ([]Document, error) {
	rows, err := pool.Query(ctx, `SELECT id, name, provider FROM detection_connectors`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Document
	for rows.Next() {
		var id, name, provider string
		if err := rows.Scan(&id, &name, &provider); err != nil {
			return nil, err
		}
		out = append(out, Document{
			DocType: "detection_connector", SourceID: id, Title: name,
			Description: "provider: " + provider, Tags: []string{provider},
		})
	}
	return out, rows.Err()
}

// actionConnectorsFrom mirrors detectionConnectorsFrom for action_connectors
// (EPP response-action connectors) -- deliberately a separate function
// since the two tables are gated by different RBAC permissions at the
// Search handler layer (CanListResponseConnectors vs
// CanListDetectionConnectors) and may diverge in columns later.
func actionConnectorsFrom(ctx context.Context, pool *pgxpool.Pool) ([]Document, error) {
	rows, err := pool.Query(ctx, `SELECT id, name, provider FROM action_connectors`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Document
	for rows.Next() {
		var id, name, provider string
		if err := rows.Scan(&id, &name, &provider); err != nil {
			return nil, err
		}
		out = append(out, Document{
			DocType: "action_connector", SourceID: id, Title: name,
			Description: "provider: " + provider, Tags: []string{provider},
		})
	}
	return out, rows.Err()
}
```

`context` and `github.com/jackc/pgx/v5/pgxpool` are already imported in `builders.go` (used by `runsFrom` etc.) — no new import needed there.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/search/... -run 'TestDetectionConnectorsFrom|TestActionConnectorsFrom' -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/search/builders.go orchestrator/internal/search/builders_test.go
git commit -m "feat(search): add detectionConnectorsFrom and actionConnectorsFrom builders"
git push
```

---

### Task 4: Wire the 4 new builders into `ReindexAll`, update every call site

**Files:**
- Modify: `orchestrator/internal/search/store.go:99` (`ReindexAll` signature and `steps` table)
- Modify: `orchestrator/cmd/server/main.go:262` and `:267` (the two `ReindexAll` call sites)
- Modify: `orchestrator/internal/api/search_handlers.go:34` (`SearchReindex` handler's `ReindexAll` call)
- Modify: `orchestrator/internal/search/store_test.go` (update the two existing `ReindexAll(ctx, pool, engine)` calls at lines 89 and 137 to the new signature)
- Test: `orchestrator/internal/search/store_test.go` (new test)

**Interfaces:**
- Consumes: `rulesFrom(*rulelib.Engine) []Document` and `complianceControlsFrom(*compliance.Mapper) []Document` (Task 2); `detectionConnectorsFrom`/`actionConnectorsFrom(ctx, pool) ([]Document, error)` (Task 3).
- Produces: `func ReindexAll(ctx context.Context, pool *pgxpool.Pool, engine *scenario.Engine, rules *rulelib.Engine, mapper *compliance.Mapper) error` — consumed by Task 6 (no changes there, just confirms the handler compiles) and by production wiring in `main.go`.

- [ ] **Step 1: Write the failing test**

Append to `orchestrator/internal/search/store_test.go`:

```go
func TestReindexAll_PopulatesRuleComplianceConnectorDocuments(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		if _, err := pool.Exec(ctx,
			`INSERT INTO detection_connectors (id, name, provider) VALUES ('dc-reindex-1', 'Reindex Sentinel', 'microsoft_sentinel')`); err != nil {
			t.Fatalf("seed detection_connectors: %v", err)
		}
		if _, err := pool.Exec(ctx,
			`INSERT INTO action_connectors (id, name, provider) VALUES ('ac-reindex-1', 'Reindex CrowdStrike', 'crowdstrike')`); err != nil {
			t.Fatalf("seed action_connectors: %v", err)
		}

		engine := scenario.NewEngine(t.TempDir())
		rulesEngine := rulelib.NewEngine()
		mapper, err := compliance.NewMapper()
		if err != nil {
			t.Fatalf("compliance.NewMapper: %v", err)
		}

		if err := ReindexAll(ctx, pool, engine, rulesEngine, mapper); err != nil {
			t.Fatalf("ReindexAll: %v", err)
		}

		var ruleCount, controlCount int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM search_documents WHERE doc_type = 'rule'`).Scan(&ruleCount); err != nil {
			t.Fatalf("count rule docs: %v", err)
		}
		if ruleCount != rulesEngine.RuleCount() {
			t.Errorf("rule doc count = %d, want %d", ruleCount, rulesEngine.RuleCount())
		}
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM search_documents WHERE doc_type = 'compliance_control'`).Scan(&controlCount); err != nil {
			t.Fatalf("count compliance_control docs: %v", err)
		}
		if controlCount != len(mapper.AllControls()) {
			t.Errorf("compliance_control doc count = %d, want %d", controlCount, len(mapper.AllControls()))
		}

		var dcTitle, acTitle string
		if err := pool.QueryRow(ctx, `SELECT title FROM search_documents WHERE doc_type = 'detection_connector' AND source_id = 'dc-reindex-1'`).Scan(&dcTitle); err != nil {
			t.Fatalf("query detection_connector document: %v", err)
		}
		if dcTitle != "Reindex Sentinel" {
			t.Errorf("detection_connector title = %q, want %q", dcTitle, "Reindex Sentinel")
		}
		if err := pool.QueryRow(ctx, `SELECT title FROM search_documents WHERE doc_type = 'action_connector' AND source_id = 'ac-reindex-1'`).Scan(&acTitle); err != nil {
			t.Fatalf("query action_connector document: %v", err)
		}
		if acTitle != "Reindex CrowdStrike" {
			t.Errorf("action_connector title = %q, want %q", acTitle, "Reindex CrowdStrike")
		}
	})
}

func TestReindexAll_NilComplianceMapperIndexesZeroControlsNotError(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		engine := scenario.NewEngine(t.TempDir())
		rulesEngine := rulelib.NewEngine()

		if err := ReindexAll(ctx, pool, engine, rulesEngine, nil); err != nil {
			t.Fatalf("ReindexAll with nil compliance mapper: %v", err)
		}

		var controlCount int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM search_documents WHERE doc_type = 'compliance_control'`).Scan(&controlCount); err != nil {
			t.Fatalf("count compliance_control docs: %v", err)
		}
		if controlCount != 0 {
			t.Errorf("compliance_control doc count = %d, want 0 (nil mapper)", controlCount)
		}
	})
}
```

Add `"github.com/audspect/bas/internal/compliance"` and `"github.com/audspect/bas/internal/rulelib"` to `store_test.go`'s import block.

Also update the two existing calls in `store_test.go` (they'll fail to compile otherwise, so this must happen in this same step):
- Line 89, inside `TestReindexAll_PopulatesScenarioRunFindingDocuments`: change `if err := ReindexAll(ctx, pool, engine); err != nil {` to `if err := ReindexAll(ctx, pool, engine, rulelib.NewEngine(), nil); err != nil {`
- Line 137, inside `TestReindexAll_PopulatesActorCampaignMalwareToolTechniqueDocuments`: same change, `if err := ReindexAll(ctx, pool, engine, rulelib.NewEngine(), nil); err != nil {`

(Passing `nil` for the mapper in both is correct — neither test cares about compliance controls, and Task 2 already proved `complianceControlsFrom(nil)` is safe.)

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go build ./...`
Expected: FAIL — compile error, `not enough arguments in call to ReindexAll` (the two updated call sites in `store_test.go` now expect 5 args but `store.go`'s `ReindexAll` still only takes 3).

- [ ] **Step 3: Update `ReindexAll`'s signature and `steps` table**

In `orchestrator/internal/search/store.go`, add `"github.com/audspect/bas/internal/compliance"` and `"github.com/audspect/bas/internal/rulelib"` to the import block. Replace the `ReindexAll` function (currently lines 98-123):

```go
// ReindexAll rebuilds every indexed entity type, one type at a time. rules
// and mapper may be nil (see rulesFrom/complianceControlsFrom for the
// nil-safety each provides).
func ReindexAll(ctx context.Context, pool *pgxpool.Pool, engine *scenario.Engine, rules *rulelib.Engine, mapper *compliance.Mapper) error {
	steps := []struct {
		docType string
		build   func() ([]Document, error)
	}{
		{"scenario", func() ([]Document, error) { return scenariosFrom(engine), nil }},
		{"run", func() ([]Document, error) { return runsFrom(ctx, pool) }},
		{"finding", func() ([]Document, error) { return findingsFrom(ctx, pool) }},
		{"actor", func() ([]Document, error) { return actorsFrom(ctx, pool) }},
		{"campaign", func() ([]Document, error) { return campaignsFrom(ctx, pool) }},
		{"malware", func() ([]Document, error) { return malwareFrom(ctx, pool) }},
		{"tool", func() ([]Document, error) { return toolsFrom(ctx, pool) }},
		{"technique", func() ([]Document, error) { return techniquesFrom(ctx, pool) }},
		{"rule", func() ([]Document, error) { return rulesFrom(rules), nil }},
		{"compliance_control", func() ([]Document, error) { return complianceControlsFrom(mapper), nil }},
		{"detection_connector", func() ([]Document, error) { return detectionConnectorsFrom(ctx, pool) }},
		{"action_connector", func() ([]Document, error) { return actionConnectorsFrom(ctx, pool) }},
	}
	for _, s := range steps {
		docs, err := s.build()
		if err != nil {
			return fmt.Errorf("build %s documents: %w", s.docType, err)
		}
		if err := reindexOneType(ctx, pool, s.docType, docs); err != nil {
			return fmt.Errorf("reindex %s: %w", s.docType, err)
		}
	}
	return nil
}
```

- [ ] **Step 4: Update production call sites**

In `orchestrator/cmd/server/main.go`:
- Line 262: `if err := search.ReindexAll(context.Background(), pool, engine); err != nil {` → `if err := search.ReindexAll(context.Background(), pool, engine, rulesEngine, complianceMapper); err != nil {`
- Line 267: `if err := search.ReindexAll(ctx, pool, engine); err != nil {` → `if err := search.ReindexAll(ctx, pool, engine, rulesEngine, complianceMapper); err != nil {`

Both `rulesEngine` (line 212) and `complianceMapper` (line 181) are already in scope at these call sites — confirmed during design.

In `orchestrator/internal/api/search_handlers.go`, the `SearchReindex` handler (line 34): `if err := search.ReindexAll(r.Context(), h.db, h.engine); err != nil {` → `if err := search.ReindexAll(r.Context(), h.db, h.engine, h.rules, h.complianceMapper); err != nil {`. `h.rules` and `h.complianceMapper` are existing `Handler` struct fields (`internal/api/handlers.go:80,90`), both already nil-safe per Task 2/3's builders.

- [ ] **Step 5: Run full build and the new tests**

Run: `cd orchestrator && go build ./... && go test ./internal/search/... -run 'TestReindexAll' -v`
Expected: build succeeds; all `TestReindexAll_*` tests PASS, including the two new ones.

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/search/store.go orchestrator/internal/search/store_test.go orchestrator/cmd/server/main.go orchestrator/internal/api/search_handlers.go
git commit -m "feat(search): wire rule/compliance_control/connector builders into ReindexAll"
git push
```

---

### Task 5: `type:` operator support for the 4 new doc types

**Files:**
- Modify: `orchestrator/internal/search/query_parse.go:36-39` (`knownDocTypes`)
- Test: `orchestrator/internal/search/query_parse_test.go`

**Interfaces:**
- Consumes: nothing new — `knownDocTypes` is a package-private map already read by `ParseQuery`.
- Produces: nothing new — same `ParseQuery(raw string) ParsedQuery` signature, now recognizing 4 more values for `DocType`.

- [ ] **Step 1: Write the failing tests**

Append to `orchestrator/internal/search/query_parse_test.go`:

```go
func TestParseQuery_NewDocTypesRecognized(t *testing.T) {
	cases := []struct {
		raw      string
		wantType string
	}{
		{"type:rule sigma", "rule"},
		{"type:compliance_control", "compliance_control"},
		{"type:detection_connector", "detection_connector"},
		{"type:action_connector", "action_connector"},
	}
	for _, tc := range cases {
		got := ParseQuery(tc.raw)
		if got.DocType != tc.wantType {
			t.Errorf("ParseQuery(%q).DocType = %q, want %q", tc.raw, got.DocType, tc.wantType)
		}
		if len(got.InvalidFilters) != 0 {
			t.Errorf("ParseQuery(%q).InvalidFilters = %+v, want none", tc.raw, got.InvalidFilters)
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/search/... -run TestParseQuery_NewDocTypesRecognized -v`
Expected: FAIL — each case's `DocType` comes back `""` with an `InvalidFilter{Name: "type", Value: ...}` instead, since none of the 4 new values are in `knownDocTypes` yet.

- [ ] **Step 3: Extend `knownDocTypes`**

In `orchestrator/internal/search/query_parse.go`, replace:

```go
var knownDocTypes = map[string]bool{
	"scenario": true, "run": true, "finding": true, "actor": true,
	"campaign": true, "malware": true, "tool": true, "technique": true,
}
```

with:

```go
var knownDocTypes = map[string]bool{
	"scenario": true, "run": true, "finding": true, "actor": true,
	"campaign": true, "malware": true, "tool": true, "technique": true,
	"rule": true, "compliance_control": true, "detection_connector": true, "action_connector": true,
}
```

Also update the comment immediately above it (currently "matches the 8 doc_types ReindexAll builds") to "matches the 12 doc_types ReindexAll builds".

- [ ] **Step 4: Run test to verify it passes**

Run: `cd orchestrator && go test ./internal/search/... -run TestParseQuery_NewDocTypesRecognized -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/search/query_parse.go orchestrator/internal/search/query_parse_test.go
git commit -m "feat(search): recognize rule/compliance_control/connector types in type: operator"
git push
```

---

### Task 6: RBAC filtering for connector search results

**Files:**
- Modify: `orchestrator/internal/api/search_handlers.go` (the `Search` handler, currently lines 13-30)
- Test: `orchestrator/internal/api/search_handlers_test.go`

**Interfaces:**
- Consumes: `auth.ClaimsFrom(ctx) (*auth.Claims, bool)` (existing, already used in this file); `auth.HasPermission(role auth.Role, perm auth.Permission) bool` (existing, `internal/auth/permissions.go:259`); `auth.CanListDetectionConnectors`/`auth.CanListResponseConnectors` (existing constants, `internal/auth/permissions.go:129` and nearby); `search.Document{DocType string, ...}` (existing).
- Produces: `func filterByPermission(docs []search.Document, hasClaims bool, c *auth.Claims) []search.Document` — used only within `search_handlers.go`, not exported for other packages.

- [ ] **Step 1: Write the failing tests**

Append to `orchestrator/internal/api/search_handlers_test.go`:

```go
func seedSearchDocsForRBACTest(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO search_documents (doc_type, source_id, title, description, tags, search_vector) VALUES
		   ('scenario', 'rbac-scn-1', 'RBAC Test Scenario', '', '{}', to_tsvector('english','RBAC Test Scenario')),
		   ('detection_connector', 'rbac-dc-1', 'RBAC Test Detection Connector', 'provider: splunk', '{splunk}', to_tsvector('english','RBAC Test Detection Connector')),
		   ('action_connector', 'rbac-ac-1', 'RBAC Test Action Connector', 'provider: crowdstrike', '{crowdstrike}', to_tsvector('english','RBAC Test Action Connector'))`); err != nil {
		t.Fatalf("seed search_documents: %v", err)
	}
}

func hasDocType(docs []search.Document, docType string) bool {
	for _, d := range docs {
		if d.DocType == docType {
			return true
		}
	}
	return false
}

func TestSearch_NonAdminNeverSeesConnectorResults(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedSearchDocsForRBACTest(t, pool)
		h := New(pool, ws.NewHub(), nil, testJWTSecret)
		userID := seedUser(t, pool, "rbac-viewer", "password123", "viewer", true)

		req := authedRequest(t, http.MethodGet, "/api/search?q=RBAC+Test", nil, auth.RoleViewer, userID)
		rec := callAuthed(h.Search, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body: %s", rec.Code, rec.Body.String())
		}
		var results []search.Document
		if err := json.Unmarshal(rec.Body.Bytes(), &results); err != nil {
			t.Fatalf("decode response: %v", err)
		}
		if hasDocType(results, "detection_connector") {
			t.Errorf("results %+v included a detection_connector doc for a viewer without CanListDetectionConnectors", results)
		}
		if hasDocType(results, "action_connector") {
			t.Errorf("results %+v included an action_connector doc for a viewer without CanListResponseConnectors", results)
		}
		if !hasDocType(results, "scenario") {
			t.Errorf("results %+v dropped the unrestricted scenario doc -- filtering must not over-filter", results)
		}
	})
}

func TestSearch_AdminSeesConnectorResults(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedSearchDocsForRBACTest(t, pool)
		h := New(pool, ws.NewHub(), nil, testJWTSecret)
		userID := seedUser(t, pool, "rbac-admin", "password123", "admin", true)

		req := authedRequest(t, http.MethodGet, "/api/search?q=RBAC+Test", nil, auth.RoleAdmin, userID)
		rec := callAuthed(h.Search, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body: %s", rec.Code, rec.Body.String())
		}
		var results []search.Document
		if err := json.Unmarshal(rec.Body.Bytes(), &results); err != nil {
			t.Fatalf("decode response: %v", err)
		}
		if !hasDocType(results, "detection_connector") {
			t.Errorf("results %+v missing detection_connector doc for an admin", results)
		}
		if !hasDocType(results, "action_connector") {
			t.Errorf("results %+v missing action_connector doc for an admin", results)
		}
	})
}

func TestSearch_BrowseModeConnectorTypeEmptyForNonAdmin(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedSearchDocsForRBACTest(t, pool)
		h := New(pool, ws.NewHub(), nil, testJWTSecret)
		userID := seedUser(t, pool, "rbac-viewer-browse", "password123", "viewer", true)

		req := authedRequest(t, http.MethodGet, "/api/search?q=type:detection_connector", nil, auth.RoleViewer, userID)
		rec := callAuthed(h.Search, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body: %s", rec.Code, rec.Body.String())
		}
		var results []search.Document
		if err := json.Unmarshal(rec.Body.Bytes(), &results); err != nil {
			t.Fatalf("decode response: %v", err)
		}
		if len(results) != 0 {
			t.Fatalf("results = %+v, want empty (non-admin browsing type:detection_connector)", results)
		}
	})
}
```

Add `"net/http"` is already imported; add `"github.com/audspect/bas/internal/auth"` — already imported. No new imports needed beyond what the file already has (`bytes`, `context`, `encoding/json`, `net/http`, `net/http/httptest`, `reflect`, `testing`, `auth`, `search`, `ws`, `pgxpool`).

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/api/... -run 'TestSearch_NonAdminNeverSeesConnectorResults|TestSearch_AdminSeesConnectorResults|TestSearch_BrowseModeConnectorTypeEmptyForNonAdmin' -v`
Expected: FAIL — `detection_connector`/`action_connector` docs are present for the viewer too (no filtering exists yet).

- [ ] **Step 3: Implement `filterByPermission` and wire it into `Search`**

In `orchestrator/internal/api/search_handlers.go`, replace the `Search` function (currently lines 13-30):

```go
// GET /api/search?q=<term>&limit=<n>
func (h *Handler) Search(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	results, err := search.Query(r.Context(), h.db, q, limit)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	c, hasClaims := auth.ClaimsFrom(r.Context())
	results = filterByPermission(results, hasClaims, c)

	// Personalization is best-effort: if it fails, fall back to
	// unpersonalized relevance-only results rather than erroring the whole
	// search -- a degraded ranking beats no results.
	if hasClaims && c != nil {
		if personalized, perr := search.Personalize(r.Context(), h.db, c.UserID, results); perr == nil {
			results = personalized
		}
	}
	respond(w, results)
}

// filterByPermission drops connector-type documents the caller's role
// can't see via their own dedicated list endpoints -- the first RBAC-aware
// filtering Search has needed (Phase 5, see design doc §Architecture 4).
// Every other doc type stays visible to any authenticated user, unchanged
// from Phase 1-4. Two explicit checks, not a generic per-type permission
// map: only 2 of 12 doc types need gating today.
func filterByPermission(docs []search.Document, hasClaims bool, c *auth.Claims) []search.Document {
	canDetection := hasClaims && c != nil && auth.HasPermission(c.Role, auth.CanListDetectionConnectors)
	canAction := hasClaims && c != nil && auth.HasPermission(c.Role, auth.CanListResponseConnectors)
	if canDetection && canAction {
		return docs // fast path: nothing to filter
	}
	out := docs[:0]
	for _, d := range docs {
		if d.DocType == "detection_connector" && !canDetection {
			continue
		}
		if d.DocType == "action_connector" && !canAction {
			continue
		}
		out = append(out, d)
	}
	return out
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/api/... -run 'TestSearch_NonAdminNeverSeesConnectorResults|TestSearch_AdminSeesConnectorResults|TestSearch_BrowseModeConnectorTypeEmptyForNonAdmin' -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/api/search_handlers.go orchestrator/internal/api/search_handlers_test.go
git commit -m "feat(search): filter connector results by CanListDetectionConnectors/CanListResponseConnectors"
git push
```

---

### Task 7: Frontend — palette labels and grouping for the 4 new types

**Files:**
- Modify: `orchestrator/cmd/server/wwwroot/index.html:11809-11813` (`CMDK_SEARCH_LABELS`)
- Modify: `orchestrator/cmd/server/wwwroot/index.html:11974` (`searchFlat()`'s doc-type iteration array)

**Interfaces:**
- Consumes: `r.docType` values now including `rule`/`compliance_control`/`detection_connector`/`action_connector`, returned by `GET /api/search` after Task 4-6.
- Produces: nothing new for other code — `cmdkOpenResult`'s existing `else` branch (line 11850-11852) already dispatches any unrecognized `docType` to `cmdkResultFallback`, so no changes there.

This task has no automated test — `index.html` has no frontend test harness in this codebase (confirmed by every prior Global Search phase). Verified by manual inspection plus the existing full Go test suite (which would fail to build/vet if this were Go code, but this is plain JS in a static HTML file).

- [ ] **Step 1: Update `CMDK_SEARCH_LABELS`**

In `orchestrator/cmd/server/wwwroot/index.html`, replace (currently lines 11809-11813):

```javascript
var CMDK_SEARCH_LABELS = {
  scenario: 'Scenarios', run: 'Runs', finding: 'Findings',
  actor: 'Threat Actors', campaign: 'Threat Campaigns',
  malware: 'Malware', tool: 'Tools', technique: 'Techniques'
};
```

with:

```javascript
var CMDK_SEARCH_LABELS = {
  scenario: 'Scenarios', run: 'Runs', finding: 'Findings',
  actor: 'Threat Actors', campaign: 'Threat Campaigns',
  malware: 'Malware', tool: 'Tools', technique: 'Techniques',
  rule: 'Detection Rules', compliance_control: 'Compliance Controls',
  detection_connector: 'Detection Connectors', action_connector: 'Response Connectors'
};
```

- [ ] **Step 2: Update `searchFlat()`'s type list**

In the same file, inside `searchFlat()` (currently around line 11974), replace:

```javascript
    ['scenario', 'run', 'finding', 'actor', 'campaign', 'malware', 'tool', 'technique'].forEach(function(dt) {
```

with:

```javascript
    ['scenario', 'run', 'finding', 'actor', 'campaign', 'malware', 'tool', 'technique',
     'rule', 'compliance_control', 'detection_connector', 'action_connector'].forEach(function(dt) {
```

- [ ] **Step 3: Manual verification (deferred, matching this project's established pattern)**

Note in the commit message that manual browser QA is deferred, consistent with every prior Global Search phase and Run Workspace Sub-project A. When it happens: confirm the palette shows "Detection Rules"/"Compliance Controls"/"Detection Connectors"/"Response Connectors" section headers for matching queries, and that clicking a result opens the fallback drawer with a real title/description (not "undefined").

- [ ] **Step 4: Commit**

```bash
git add orchestrator/cmd/server/wwwroot/index.html
git commit -m "feat(search-ui): render rule/compliance_control/connector results in the palette"
git push
```

---

### Task 8: Full regression and finishing

**Files:** none (verification only)

- [ ] **Step 1: Run the full Go test suite**

Run: `cd orchestrator && go build ./... && go vet ./... && go test ./... -count=1 > "$env:TEMP\phase5-full-suite.log" 2>&1; echo "EXIT_CODE:$LASTEXITCODE"` (PowerShell) — or in Bash: `cd orchestrator && go build ./... && go vet ./... && go test ./... -count=1 > /tmp/phase5-full-suite.log 2>&1; echo "EXIT_CODE:$?"`

Expected: `EXIT_CODE:0`, every package `ok`. If a single package fails under Docker load with a testcontainers connection error, re-run that package in isolation before concluding it's the known transient flake — do not assume, confirm (see this session's established Docker-flake-vs-Docker-outage distinction: if many/most packages fail identically, check `docker info` first).

- [ ] **Step 2: Invoke finishing-a-development-branch**

This plan executes directly on `main` (matching every prior phase this session, per the user's established inline-execution-on-main convention) — no branch/worktree/PR decision is actually needed, but confirm with the user before considering Phase 5 complete, and update the `[[Global Search]]` memory/vault entries the same way every prior phase's completion was recorded.
