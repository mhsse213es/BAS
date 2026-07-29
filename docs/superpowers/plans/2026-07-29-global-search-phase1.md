# Global Search Phase 1 (Search Index Core + API) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A maintained, ranked, multi-entity search index (`search_documents`) covering the 8 entity types that already exist as real backend objects (Scenarios, Runs, Findings, Threat Actors, Campaigns, Malware, Tools, Techniques), plus one query API and one admin reindex-trigger API.

**Architecture:** One Postgres table with a generated `tsvector` column (title/description/tags, weighted A/B/C) gives real relevance ranking via `ts_rank` with zero custom ranking code. Eight builder functions map each source into a shared `Document` shape; a full per-type rebuild (`DELETE` + re-insert, one transaction per type) runs on a 60s timer (reusing the existing `exercise.PollScheduler` abstraction, not a new one) plus on-demand via an admin-gated endpoint. `GET /api/search` returns a flat ranked list; grouping/rendering is left to a future UI phase.

**Tech Stack:** Go, `internal/search` (new package, `pgx/v5` direct SQL, no ORM), Postgres full-text search (`tsvector`/`ts_rank`/GIN index), `internal/api` (chi routes), `internal/auth` (new permission).

## Global Constraints

- No frontend changes — this phase is backend-only. (Spec §Non-Goals)
- No personalization/popularity ranking, no search-operator query language, no long-tail entity types beyond the 8 listed, no per-result instant actions, no rich preview data beyond title/description/tags. (Spec §Non-Goals)
- No `url` field on `Document` — results carry `docType`+`sourceId` only; navigation-action mapping is a future phase's problem. (Spec §Architecture 1)
- Reindexing is full per-type rebuild (`DELETE` + re-insert in one transaction per type), never incremental diffing, never per-entity-write hooks. (Spec §Architecture 2)
- Reuse `exercise.PollScheduler` for the timer — do not write a new ticker/goroutine abstraction. (Spec §Architecture 2, confirmed during planning: `internal/exercise/scheduler.go`)
- Reuse `internal/intelligence`'s existing `ListCampaigns`/`ListMalware`/`ListTools` for those three builders — never re-derive that query logic with raw SQL. (Spec §Architecture 3)

---

## File Structure

- Modify `orchestrator/internal/db/content_schema.go` — `search_documents` table + GIN index.
- Create `orchestrator/internal/search/document.go` — `Document` type.
- Create `orchestrator/internal/search/builders.go` — 8 builder functions.
- Create `orchestrator/internal/search/store.go` — `reindexOneType`, `ReindexAll`, `Query`.
- Create `orchestrator/internal/search/builders_test.go`, `orchestrator/internal/search/store_test.go`.
- Modify `orchestrator/internal/auth/permissions.go` — new `CanReindexSearch` permission.
- Modify `orchestrator/internal/auth/permissions_test.go` — mirror the new permission in test assertions.
- Create `orchestrator/internal/api/search_handlers.go` — `Search`, `SearchReindex` handlers.
- Modify `orchestrator/internal/api/routes.go` — register both routes.
- Modify `orchestrator/internal/api/rbac_matrix_test.go` — RBAC entries.
- Modify `orchestrator/cmd/server/main.go` — startup reindex + poll-scheduler wiring.

---

### Task 1: Schema + `Document` type + reindex pipeline + first 3 builders (scenario/run/finding)

**Files:**
- Modify: `orchestrator/internal/db/content_schema.go`
- Create: `orchestrator/internal/search/document.go`, `orchestrator/internal/search/builders.go`, `orchestrator/internal/search/store.go`
- Create: `orchestrator/internal/search/builders_test.go`, `orchestrator/internal/search/store_test.go`

**Interfaces:**
- Produces: `type Document struct{DocType, SourceID, Title, Description string; Tags []string}`, `func reindexOneType(ctx, pool, docType string, docs []Document) error`, `func ReindexAll(ctx context.Context, pool *pgxpool.Pool, engine *scenario.Engine) error`, `func scenariosFrom(engine *scenario.Engine) []Document`, `func runsFrom(ctx, pool) ([]Document, error)`, `func findingsFrom(ctx, pool) ([]Document, error)` — `ReindexAll`'s signature is final; Task 2 only adds more builder calls inside it.

- [ ] **Step 1: Write the failing tests**

Create `orchestrator/internal/search/store_test.go`:

```go
package search

import (
	"context"
	"flag"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

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

func TestReindex_RebuildsOneTypeWithoutTouchingOthers(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		if err := reindexOneType(ctx, pool, "scenario", []Document{
			{DocType: "scenario", SourceID: "s1", Title: "Scenario One"},
		}); err != nil {
			t.Fatalf("seed scenario type: %v", err)
		}
		if err := reindexOneType(ctx, pool, "actor", []Document{
			{DocType: "actor", SourceID: "a1", Title: "Actor One"},
		}); err != nil {
			t.Fatalf("seed actor type: %v", err)
		}

		// Rebuild only "scenario" with a different document set.
		if err := reindexOneType(ctx, pool, "scenario", []Document{
			{DocType: "scenario", SourceID: "s2", Title: "Scenario Two"},
		}); err != nil {
			t.Fatalf("rebuild scenario type: %v", err)
		}

		var scenarioCount, actorCount int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM search_documents WHERE doc_type = 'scenario'`).Scan(&scenarioCount); err != nil {
			t.Fatalf("count scenario docs: %v", err)
		}
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM search_documents WHERE doc_type = 'actor'`).Scan(&actorCount); err != nil {
			t.Fatalf("count actor docs: %v", err)
		}
		if scenarioCount != 1 {
			t.Errorf("scenario doc count = %d, want 1 (old s1 replaced by new s2, not accumulated)", scenarioCount)
		}
		if actorCount != 1 {
			t.Errorf("actor doc count = %d, want 1 (untouched by the scenario rebuild)", actorCount)
		}
	})
}

func TestReindexAll_PopulatesScenarioRunFindingDocuments(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		if _, err := pool.Exec(ctx, `INSERT INTO agents (agent_id) VALUES ('agent-search-1')`); err != nil {
			t.Fatalf("seed agent: %v", err)
		}
		if _, err := pool.Exec(ctx,
			`INSERT INTO scenario_runs (id, scenario_id, agent_id, name, status) VALUES ('run-search-1', 'scn-1', 'agent-search-1', 'Search Test Run', 'completed')`); err != nil {
			t.Fatalf("seed scenario_runs: %v", err)
		}
		if _, err := pool.Exec(ctx,
			`INSERT INTO findings (agent_id, technique_id, control_class, technique_name, severity) VALUES ('agent-search-1', 'T1059', 'prevention', 'Command and Scripting Interpreter', 'High')`); err != nil {
			t.Fatalf("seed findings: %v", err)
		}

		tmpDir := t.TempDir()
		engine := scenario.NewEngine(tmpDir)

		if err := ReindexAll(ctx, pool, engine); err != nil {
			t.Fatalf("ReindexAll: %v", err)
		}

		var runTitle, findingTitle string
		if err := pool.QueryRow(ctx, `SELECT title FROM search_documents WHERE doc_type = 'run' AND source_id = 'run-search-1'`).Scan(&runTitle); err != nil {
			t.Fatalf("query run document: %v", err)
		}
		if runTitle != "Search Test Run" {
			t.Errorf("run title = %q, want %q", runTitle, "Search Test Run")
		}
		if err := pool.QueryRow(ctx, `SELECT title FROM search_documents WHERE doc_type = 'finding' AND source_id != ''`).Scan(&findingTitle); err != nil {
			t.Fatalf("query finding document: %v", err)
		}
		if findingTitle != "Command and Scripting Interpreter" {
			t.Errorf("finding title = %q, want %q", findingTitle, "Command and Scripting Interpreter")
		}
	})
}
```

Add to `orchestrator/internal/search/builders_test.go`:

```go
package search

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/audspect/bas/internal/scenario"
)

func TestScenariosFrom_MapsNameTagsDescription(t *testing.T) {
	tmpDir := t.TempDir()
	customDir := filepath.Join(tmpDir, "custom")
	if err := os.MkdirAll(customDir, 0o755); err != nil {
		t.Fatalf("mkdir custom: %v", err)
	}
	yaml := `id: test-art-scenario
name: Atomic Red Team PowerShell
description: Runs ART PowerShell techniques
tags: [art, powershell]
mitre_phases: [execution]
`
	if err := os.WriteFile(filepath.Join(customDir, "test.yaml"), []byte(yaml), 0o644); err != nil {
		t.Fatalf("write test scenario: %v", err)
	}

	engine := scenario.NewEngine(tmpDir)
	if err := engine.Load(); err != nil {
		t.Fatalf("engine.Load: %v", err)
	}

	docs := scenariosFrom(engine)
	if len(docs) != 1 {
		t.Fatalf("scenariosFrom() = %+v, want 1 document", docs)
	}
	d := docs[0]
	if d.DocType != "scenario" || d.SourceID != "test-art-scenario" || d.Title != "Atomic Red Team PowerShell" {
		t.Fatalf("document = %+v, want DocType=scenario SourceID=test-art-scenario Title=%q", d, "Atomic Red Team PowerShell")
	}
	if d.Description != "Runs ART PowerShell techniques" {
		t.Errorf("Description = %q, want %q", d.Description, "Runs ART PowerShell techniques")
	}
	hasArt, hasExecution := false, false
	for _, tag := range d.Tags {
		if tag == "art" {
			hasArt = true
		}
		if tag == "execution" {
			hasExecution = true
		}
	}
	if !hasArt || !hasExecution {
		t.Errorf("Tags = %v, want to include both %q (from tags:) and %q (from mitre_phases:)", d.Tags, "art", "execution")
	}
}
```

(Scenario placed under `custom/` so `Engine.sourceForPath` classifies it `"custom"`, skipping the signature-verification path that only applies to `"builtin"`-sourced files — a hand-written test fixture would otherwise fail to load.)

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/search/... -v 2>&1 | head -20`
Expected: FAIL — `no Go files in ...` (the package doesn't exist yet)

- [ ] **Step 3: Add the `search_documents` schema**

In `orchestrator/internal/db/content_schema.go`, add to the `stmts` slice, after the `intelligence_campaigns`/`ALTER` block added by earlier Intelligence Expansion work:

```go
		// Global Search Phase 1 -- maintained multi-entity search index
		// (see docs/superpowers/specs/2026-07-29-global-search-phase1-design.md).
		// Rebuilt by internal/search.ReindexAll on a timer + on-demand; never
		// written to by per-entity create/update code paths directly.
		//
		// search_vector is a plain column, NOT a GENERATED ALWAYS AS ...
		// STORED column -- to_tsvector(regconfig, text) is only STABLE, not
		// IMMUTABLE, so Postgres rejects it inside a generated-column
		// expression. Two wrapper-function workarounds (LANGUAGE sql
		// IMMUTABLE, then LANGUAGE plpgsql IMMUTABLE) were both tried
		// against a real Postgres instance and both failed identically with
		// "generation expression is not immutable" -- computing
		// search_vector explicitly in each INSERT (see Step 5's
		// reindexOneType) sidesteps this entirely.
		`CREATE TABLE IF NOT EXISTS search_documents (
			id            bigserial   PRIMARY KEY,
			doc_type      text        NOT NULL,
			source_id     text        NOT NULL,
			title         text        NOT NULL,
			description   text        NOT NULL DEFAULT '',
			tags          text[]      NOT NULL DEFAULT '{}',
			search_vector tsvector    NOT NULL,
			updated_at    timestamptz NOT NULL DEFAULT NOW(),
			tenant_id     text        NOT NULL DEFAULT 'default',
			UNIQUE (doc_type, source_id)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_search_documents_vector ON search_documents USING GIN (search_vector)`,
```

- [ ] **Step 4: Create `document.go`**

```go
// Package search provides a maintained, ranked, multi-entity search index
// over the platform's real backend objects -- Scenarios, Runs, Findings,
// Threat Actors, Campaigns, Malware, Tools, and Techniques as of Phase 1.
// The index is a materialized Postgres table (search_documents), rebuilt
// on a timer and on-demand, never written to directly by each entity's own
// create/update code paths. See
// docs/superpowers/specs/2026-07-29-global-search-phase1-design.md.
package search

// Document is one indexed, searchable object -- the shape both the
// reindex-side builders (below) and the query-side results share.
type Document struct {
	DocType     string   `json:"docType"`
	SourceID    string   `json:"sourceId"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Tags        []string `json:"tags"`
}
```

- [ ] **Step 5: Create `store.go` with `reindexOneType` and `ReindexAll`**

```go
package search

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/scenario"
)

// reindexOneType replaces every search_documents row of the given docType
// with docs, in one transaction -- a full rebuild, not incremental
// diffing. Rebuilding one type never empties or blocks queries against any
// other type, since each type's rebuild is its own transaction.
func reindexOneType(ctx context.Context, pool *pgxpool.Pool, docType string, docs []Document) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx, `DELETE FROM search_documents WHERE doc_type = $1`, docType); err != nil {
		return err
	}
	for _, d := range docs {
		// pgx encodes a nil Go []string as SQL NULL, not an empty array --
		// violates tags' NOT NULL constraint for any Document built without
		// explicitly setting Tags. Same recurring gotcha internal/intelligence
		// already coalesces against.
		if d.Tags == nil {
			d.Tags = []string{}
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO search_documents (doc_type, source_id, title, description, tags, search_vector)
			 VALUES ($1,$2,$3,$4,$5,
			   setweight(to_tsvector('english', $3::text), 'A') ||
			   setweight(to_tsvector('english', coalesce($4::text, '')), 'B') ||
			   setweight(to_tsvector('english', array_to_string($5::text[], ' ')), 'C'))`,
			docType, d.SourceID, d.Title, d.Description, d.Tags); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

// ReindexAll rebuilds every indexed entity type, one type at a time.
func ReindexAll(ctx context.Context, pool *pgxpool.Pool, engine *scenario.Engine) error {
	steps := []struct {
		docType string
		build   func() ([]Document, error)
	}{
		{"scenario", func() ([]Document, error) { return scenariosFrom(engine), nil }},
		{"run", func() ([]Document, error) { return runsFrom(ctx, pool) }},
		{"finding", func() ([]Document, error) { return findingsFrom(ctx, pool) }},
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

- [ ] **Step 6: Create `builders.go` with the first 3 builders**

```go
package search

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/scenario"
)

// scenariosFrom maps every loaded scenario into a Document. Scenarios are
// file-backed (scenario.Engine), not a Postgres table -- no query needed,
// engine.List() is already in memory.
func scenariosFrom(engine *scenario.Engine) []Document {
	list := engine.List()
	out := make([]Document, 0, len(list))
	for _, s := range list {
		tags := make([]string, 0, len(s.Tags)+len(s.MITREPhases)+len(s.ARTTechniques))
		tags = append(tags, s.Tags...)
		tags = append(tags, s.MITREPhases...)
		tags = append(tags, s.ARTTechniques...)
		out = append(out, Document{
			DocType: "scenario", SourceID: s.ID, Title: s.Name,
			Description: s.Description, Tags: tags,
		})
	}
	return out
}

// runsFrom maps every scenario_runs row into a Document. Title falls back
// to scenario_id when name is empty, matching the existing UI convention
// (e.g. cmd/server/wwwroot/index.html's `r.name || r.scenarioId`).
func runsFrom(ctx context.Context, pool *pgxpool.Pool) ([]Document, error) {
	rows, err := pool.Query(ctx, `SELECT id, scenario_id, name, status FROM scenario_runs`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Document
	for rows.Next() {
		var id, scenarioID, name, status string
		if err := rows.Scan(&id, &scenarioID, &name, &status); err != nil {
			return nil, err
		}
		title := name
		if title == "" {
			title = scenarioID
		}
		out = append(out, Document{
			DocType: "run", SourceID: id, Title: title,
			Description: status, Tags: []string{status},
		})
	}
	return out, rows.Err()
}

// findingsFrom maps every findings row into a Document. Title falls back
// to technique_id when technique_name is empty.
func findingsFrom(ctx context.Context, pool *pgxpool.Pool) ([]Document, error) {
	rows, err := pool.Query(ctx,
		`SELECT id, technique_id, technique_name, control_class, severity, exposure_state, status FROM findings`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Document
	for rows.Next() {
		var id, techID, techName, controlClass, severity, exposureState, status string
		if err := rows.Scan(&id, &techID, &techName, &controlClass, &severity, &exposureState, &status); err != nil {
			return nil, err
		}
		title := techName
		if title == "" {
			title = techID
		}
		out = append(out, Document{
			DocType: "finding", SourceID: id, Title: title,
			Description: severity + " " + exposureState,
			Tags:        []string{controlClass, severity, status},
		})
	}
	return out, rows.Err()
}
```

- [ ] **Step 7: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/search/... -v`
Expected: PASS — all tests in Task 1. Docker Desktop must be running — check `docker info` first.

- [ ] **Step 8: Commit**

```bash
git add internal/db/content_schema.go internal/search/
git commit -m "feat(search): search_documents schema + reindex pipeline + scenario/run/finding builders (Global Search Phase 1)"
```

---

### Task 2: Remaining 5 builders (actor/campaign/malware/tool/technique)

**Files:**
- Modify: `orchestrator/internal/search/builders.go`
- Modify: `orchestrator/internal/search/store.go` (extend `ReindexAll`'s `steps` slice)
- Modify: `orchestrator/internal/search/builders_test.go`

**Interfaces:**
- Consumes: `intelligence.ListCampaigns`/`ListMalware`/`ListTools` (already exist, from Intelligence Expansion Phases 1-5).
- Produces: `func actorsFrom`, `func campaignsFrom`, `func malwareFrom`, `func toolsFrom`, `func techniquesFrom` (all `(ctx, pool) ([]Document, error)`) — `ReindexAll` now covers all 8 types.

- [ ] **Step 1: Write the failing test**

Add to `orchestrator/internal/search/store_test.go`:

```go
func TestReindexAll_PopulatesActorCampaignMalwareToolTechniqueDocuments(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		if _, err := pool.Exec(ctx,
			`INSERT INTO threat_actor_profiles (name, aliases, sectors, regions, source) VALUES ('SearchTestActor', '{}', '{}', '{}', 'test')`); err != nil {
			t.Fatalf("seed threat_actor_profiles: %v", err)
		}
		if _, err := pool.Exec(ctx,
			`INSERT INTO intelligence_campaigns (id, name, description, actor_ids, technique_ids, source_provider) VALUES ('search-campaign-1', 'Search Test Campaign', '', '{}', '{}', 'test')`); err != nil {
			t.Fatalf("seed intelligence_campaigns: %v", err)
		}
		if _, err := pool.Exec(ctx,
			`INSERT INTO intelligence_malware (id, name, aliases, technique_ids, actor_ids, campaign_ids, source_provider) VALUES ('search-malware-1', 'Search Test Malware', '{}', '{}', '{}', '{}', 'test')`); err != nil {
			t.Fatalf("seed intelligence_malware: %v", err)
		}
		if _, err := pool.Exec(ctx,
			`INSERT INTO intelligence_tools (id, name, aliases, technique_ids, actor_ids, campaign_ids, source_provider) VALUES ('search-tool-1', 'Search Test Tool', '{}', '{}', '{}', '{}', 'test')`); err != nil {
			t.Fatalf("seed intelligence_tools: %v", err)
		}
		if _, err := pool.Exec(ctx,
			`INSERT INTO techniques (technique_id, name, tactic, description) VALUES ('T1059.001', 'PowerShell', 'execution', 'Adversaries may abuse PowerShell')`); err != nil {
			t.Fatalf("seed techniques: %v", err)
		}

		engine := scenario.NewEngine(t.TempDir())
		if err := ReindexAll(ctx, pool, engine); err != nil {
			t.Fatalf("ReindexAll: %v", err)
		}

		for _, tc := range []struct {
			docType, sourceID, wantTitle string
		}{
			{"actor", "SearchTestActor", "SearchTestActor"},
			{"campaign", "search-campaign-1", "Search Test Campaign"},
			{"malware", "search-malware-1", "Search Test Malware"},
			{"tool", "search-tool-1", "Search Test Tool"},
			{"technique", "T1059.001", "T1059.001 PowerShell"},
		} {
			var title string
			err := pool.QueryRow(ctx,
				`SELECT title FROM search_documents WHERE doc_type = $1 AND source_id = $2`,
				tc.docType, tc.sourceID).Scan(&title)
			if err != nil {
				t.Errorf("query %s document: %v", tc.docType, err)
				continue
			}
			if title != tc.wantTitle {
				t.Errorf("%s title = %q, want %q", tc.docType, title, tc.wantTitle)
			}
		}
	})
}
```

Add `"github.com/audspect/bas/internal/scenario"` to `store_test.go`'s imports.

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/search/... -run TestReindexAll_PopulatesActorCampaignMalwareToolTechniqueDocuments -v`
Expected: FAIL — the test compiles (all functions it calls already exist via `ReindexAll`), but no `actor`/`campaign`/`malware`/`tool`/`technique` rows are found, since `ReindexAll`'s `steps` slice doesn't build them yet.

- [ ] **Step 3: Add the 5 remaining builders**

In `orchestrator/internal/search/builders.go`, add the import and the 5 functions:

```go
	"github.com/audspect/bas/internal/intelligence"
```

```go
// actorsFrom maps every threat_actor_profiles row into a Document.
func actorsFrom(ctx context.Context, pool *pgxpool.Pool) ([]Document, error) {
	rows, err := pool.Query(ctx, `SELECT name, aliases, sectors, regions FROM threat_actor_profiles`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Document
	for rows.Next() {
		var name string
		var aliases, sectors, regions []string
		if err := rows.Scan(&name, &aliases, &sectors, &regions); err != nil {
			return nil, err
		}
		tags := make([]string, 0, len(aliases)+len(sectors)+len(regions))
		tags = append(tags, aliases...)
		tags = append(tags, sectors...)
		tags = append(tags, regions...)
		out = append(out, Document{DocType: "actor", SourceID: name, Title: name, Tags: tags})
	}
	return out, rows.Err()
}

// campaignsFrom reuses internal/intelligence.ListCampaigns rather than
// re-deriving its query logic.
func campaignsFrom(ctx context.Context, pool *pgxpool.Pool) ([]Document, error) {
	campaigns, err := intelligence.ListCampaigns(ctx, pool)
	if err != nil {
		return nil, err
	}
	out := make([]Document, 0, len(campaigns))
	for _, c := range campaigns {
		out = append(out, Document{
			DocType: "campaign", SourceID: c.ID, Title: c.Name,
			Description: c.Description, Tags: c.Aliases,
		})
	}
	return out, nil
}

// malwareFrom reuses internal/intelligence.ListMalware.
func malwareFrom(ctx context.Context, pool *pgxpool.Pool) ([]Document, error) {
	malware, err := intelligence.ListMalware(ctx, pool)
	if err != nil {
		return nil, err
	}
	out := make([]Document, 0, len(malware))
	for _, m := range malware {
		tags := make([]string, 0, len(m.Aliases)+len(m.MalwareTypes))
		tags = append(tags, m.Aliases...)
		tags = append(tags, m.MalwareTypes...)
		out = append(out, Document{DocType: "malware", SourceID: m.ID, Title: m.Name, Tags: tags})
	}
	return out, nil
}

// toolsFrom reuses internal/intelligence.ListTools.
func toolsFrom(ctx context.Context, pool *pgxpool.Pool) ([]Document, error) {
	tools, err := intelligence.ListTools(ctx, pool)
	if err != nil {
		return nil, err
	}
	out := make([]Document, 0, len(tools))
	for _, t := range tools {
		out = append(out, Document{DocType: "tool", SourceID: t.ID, Title: t.Name, Tags: t.Aliases})
	}
	return out, nil
}

// techniquesFrom maps every techniques row into a Document. Title includes
// both the ID and the name (e.g. "T1059.001 PowerShell") so either
// independently matches a search query.
func techniquesFrom(ctx context.Context, pool *pgxpool.Pool) ([]Document, error) {
	rows, err := pool.Query(ctx, `SELECT technique_id, name, tactic, description FROM techniques`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Document
	for rows.Next() {
		var id, name, tactic, description string
		if err := rows.Scan(&id, &name, &tactic, &description); err != nil {
			return nil, err
		}
		title := id
		if name != "" {
			title = id + " " + name
		}
		out = append(out, Document{
			DocType: "technique", SourceID: id, Title: title,
			Description: description, Tags: []string{tactic},
		})
	}
	return out, rows.Err()
}
```

In `orchestrator/internal/search/store.go`, extend `ReindexAll`'s `steps` slice:

```go
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
	}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd orchestrator && go test ./internal/search/... -v`
Expected: PASS — every test in the package.

- [ ] **Step 5: Commit**

```bash
git add internal/search/
git commit -m "feat(search): actor/campaign/malware/tool/technique builders (Global Search Phase 1)"
```

---

### Task 3: `Query` function + ranking tests

**Files:**
- Modify: `orchestrator/internal/search/store.go`
- Modify: `orchestrator/internal/search/store_test.go`

**Interfaces:**
- Produces: `func Query(ctx context.Context, pool *pgxpool.Pool, q string, limit int) ([]Document, error)` — consumed by Task 5's API handler.

- [ ] **Step 1: Write the failing tests**

Add to `orchestrator/internal/search/store_test.go`:

```go
func TestQuery_RanksTitleMatchAboveDescriptionMatch(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		if err := reindexOneType(ctx, pool, "scenario", []Document{
			{DocType: "scenario", SourceID: "title-match", Title: "Ransomware Simulation", Description: "generic description"},
			{DocType: "scenario", SourceID: "desc-match", Title: "Unrelated Name", Description: "involves ransomware behavior"},
		}); err != nil {
			t.Fatalf("seed: %v", err)
		}

		results, err := Query(ctx, pool, "ransomware", 10)
		if err != nil {
			t.Fatalf("Query: %v", err)
		}
		if len(results) != 2 {
			t.Fatalf("Query() = %+v, want 2 results", results)
		}
		if results[0].SourceID != "title-match" {
			t.Errorf("results[0].SourceID = %q, want %q (title match must rank above description-only match)", results[0].SourceID, "title-match")
		}
	})
}

func TestQuery_EmptyQueryReturnsEmptyNotFullTable(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		if err := reindexOneType(ctx, pool, "scenario", []Document{
			{DocType: "scenario", SourceID: "s1", Title: "Anything"},
		}); err != nil {
			t.Fatalf("seed: %v", err)
		}

		results, err := Query(ctx, pool, "   ", 10)
		if err != nil {
			t.Fatalf("Query: %v", err)
		}
		if len(results) != 0 {
			t.Fatalf("Query(\"   \") = %+v, want empty (guard against an accidental full-table dump)", results)
		}
	})
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/search/... -run TestQuery -v`
Expected: FAIL — `undefined: Query`

- [ ] **Step 3: Add `Query`**

In `orchestrator/internal/search/store.go`, add:

```go
// Query full-text-searches search_documents and returns a flat, ranked
// list -- never pre-grouped by type, see the design doc's Architecture §4.
// An empty/whitespace-only q returns an empty slice, not an error and not
// the full table.
func Query(ctx context.Context, pool *pgxpool.Pool, q string, limit int) ([]Document, error) {
	q = strings.TrimSpace(q)
	if q == "" {
		return []Document{}, nil
	}
	if limit <= 0 || limit > 100 {
		limit = 25
	}

	rows, err := pool.Query(ctx,
		`SELECT doc_type, source_id, title, description, tags
		 FROM search_documents, plainto_tsquery('english', $1) query
		 WHERE search_vector @@ query
		 ORDER BY ts_rank(search_vector, query) DESC
		 LIMIT $2`,
		q, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []Document{}
	for rows.Next() {
		var d Document
		if err := rows.Scan(&d.DocType, &d.SourceID, &d.Title, &d.Description, &d.Tags); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}
```

Add `"strings"` to `store.go`'s import block.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/search/... -v`
Expected: PASS — every test in the package.

- [ ] **Step 5: Commit**

```bash
git add internal/search/
git commit -m "feat(search): ranked Query function (Global Search Phase 1)"
```

---

### Task 4: `CanReindexSearch` permission

**Files:**
- Modify: `orchestrator/internal/auth/permissions.go`
- Modify: `orchestrator/internal/auth/permissions_test.go`

**Interfaces:**
- Produces: `auth.CanReindexSearch Permission` — consumed by Task 5's route registration.

This follows the exact existing pattern for admin-only actions (e.g. `CanReseedARTContent`) — three touch points in `permissions.go`, mirrored in `permissions_test.go`.

- [ ] **Step 1: Write the failing test**

In `orchestrator/internal/auth/permissions_test.go`, there are three occurrences to update. First, at line 76 (map-literal form):

```go
		CanViewARTContentStatus: true, CanReseedARTContent: true, CanViewTamperEvents: true,
```

Replace with:

```go
		CanViewARTContentStatus: true, CanReseedARTContent: true, CanReindexSearch: true, CanViewTamperEvents: true,
```

Second and third, at line 126 and again (identically) at line 226 (both slice-literal form — this exact line appears twice in the file, in two different permission-list assertions):

```go
		CanReseedARTContent, CanViewTamperEvents, CanAcknowledgeTamperEvent, CanAcknowledgeAllTamperEvents,
```

Replace **both** occurrences with:

```go
		CanReseedARTContent, CanReindexSearch, CanViewTamperEvents, CanAcknowledgeTamperEvent, CanAcknowledgeAllTamperEvents,
```

(Use a find-and-replace-all for this exact line, since it's byte-for-byte identical in both places — do not replace only the first match.)

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/auth/... -v 2>&1 | head -20`
Expected: FAIL — `undefined: CanReindexSearch`

- [ ] **Step 3: Add the permission**

In `orchestrator/internal/auth/permissions.go`, add the constant near `CanReseedARTContent`:

```go
	// Admin-only: attack-path schedule, ART content management.
	CanSetAttackPathSchedule Permission = "attackpath:schedule:set"
	CanViewARTContentStatus  Permission = "art-content:status:view"
	CanReseedARTContent      Permission = "art-content:reseed"

	// Admin-only: global search reindex trigger.
	CanReindexSearch Permission = "search:reindex"
```

Add it to the admin permission grant map (the `rolePermissions[RoleAdmin]` literal, near where `CanReseedARTContent: true` already appears):

```go
		CanViewARTContentStatus: true, CanReseedARTContent: true, CanReindexSearch: true, CanViewTamperEvents: true,
```

(Replace the existing `CanViewARTContentStatus: true, CanReseedARTContent: true, CanViewTamperEvents: true,` line with the above — inserting `CanReindexSearch: true,` between the other two.)

Add it to the `Permissions(role)` function's ordered slice, in the same spot:

```go
		CanReseedARTContent, CanReindexSearch, CanViewTamperEvents, CanAcknowledgeTamperEvent, CanAcknowledgeAllTamperEvents,
```

(Replace the existing `CanReseedARTContent, CanViewTamperEvents, CanAcknowledgeTamperEvent, CanAcknowledgeAllTamperEvents,` line similarly.)

- [ ] **Step 4: Run test to verify it passes**

Run: `cd orchestrator && go test ./internal/auth/... -v`
Expected: PASS — every test in the package.

- [ ] **Step 5: Commit**

```bash
git add internal/auth/permissions.go internal/auth/permissions_test.go
git commit -m "feat(auth): CanReindexSearch permission (Global Search Phase 1)"
```

---

### Task 5: API — `GET /api/search` + `POST /api/search/reindex` + RBAC

**Files:**
- Create: `orchestrator/internal/api/search_handlers.go`
- Modify: `orchestrator/internal/api/routes.go`
- Modify: `orchestrator/internal/api/rbac_matrix_test.go`

**Interfaces:**
- Consumes: `search.Query` (Task 3), `search.ReindexAll` (Task 1-2), `auth.CanReindexSearch` (Task 4).
- Produces: `func (h *Handler) Search`, `func (h *Handler) SearchReindex`, routes `GET /api/search`, `POST /api/search/reindex`.

- [ ] **Step 1: Write the failing RBAC matrix test entries**

In `orchestrator/internal/api/rbac_matrix_test.go`, find:

```go
	{http.MethodGet, "/api/knowledge-graph/{type}/{id}", tierAny, ""},
```

Add directly after:

```go
	{http.MethodGet, "/api/search", tierAny, ""},
	{http.MethodPost, "/api/search/reindex", tierPermission, auth.CanReindexSearch},
```

- [ ] **Step 2: Run the RBAC matrix test to verify it fails**

Run: `cd orchestrator && go test ./internal/api/... -run TestRBACMatrix -v`
Expected: FAIL — neither route registered

- [ ] **Step 3: Add the handlers**

Create `orchestrator/internal/api/search_handlers.go`:

```go
package api

import (
	"net/http"
	"strconv"

	"github.com/audspect/bas/internal/search"
)

// GET /api/search?q=<term>&limit=<n>
func (h *Handler) Search(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	results, err := search.Query(r.Context(), h.db, q, limit)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respond(w, results)
}

// POST /api/search/reindex
func (h *Handler) SearchReindex(w http.ResponseWriter, r *http.Request) {
	if err := search.ReindexAll(r.Context(), h.db, h.engine); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respond(w, map[string]string{"status": "ok"})
}
```

(`h.engine *scenario.Engine` and `h.db *pgxpool.Pool` already exist on `Handler` — confirmed via `internal/api/handlers.go` during planning, no `Handler` struct changes needed.)

- [ ] **Step 4: Register the routes**

In `orchestrator/internal/api/routes.go`, find:

```go
		r.Get("/api/knowledge-graph/{type}/{id}", h.KnowledgeGraphNeighborhood)
```

Add directly after:

```go
		r.Get("/api/search", h.Search)
		r.With(auth.RequirePermission(auth.CanReindexSearch)).Post("/api/search/reindex", h.SearchReindex)
```

(This file already imports `"github.com/audspect/bas/internal/auth"` — confirmed via the existing `auth.RequirePermission(...)` call sites at e.g. line 381 — no new import needed.)

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/api/... -run TestRBACMatrix -v`
Expected: PASS

- [ ] **Step 6: Run the full `internal/api` test suite**

Run: `cd orchestrator && go test ./internal/api/... -v` (run in background if it exceeds the interactive timeout — this package is large)
Expected: PASS across the whole package.

- [ ] **Step 7: Commit**

```bash
git add internal/api/search_handlers.go internal/api/routes.go internal/api/rbac_matrix_test.go
git commit -m "feat(api): GET /api/search + POST /api/search/reindex (Global Search Phase 1)"
```

---

### Task 6: Wire into `main.go` — startup reindex + poll scheduler

**Files:**
- Modify: `orchestrator/cmd/server/main.go`

**Interfaces:**
- Consumes: `search.ReindexAll` (Task 1-2), `exercise.NewPollScheduler` (already exists).

`time.NewTicker`-based schedulers (including `exercise.PollScheduler`) only fire *after* the first interval elapses — without an explicit startup call, `search_documents` would sit empty for the first 60 seconds after every server boot.

- [ ] **Step 1: Add the import**

In `orchestrator/cmd/server/main.go`, add `"github.com/audspect/bas/internal/search"` to the import block.

- [ ] **Step 2: Add the startup call + poll scheduler**

Find:

```go
	scheduler := connector.NewScheduler(tiSources, gen, engine, cfg.ThreatIntelPollHours, pool, priorityEngine)
	scheduler.Start()
	defer scheduler.Stop()
```

Add directly after:

```go
	// Global Search Phase 1 -- maintained multi-entity search index.
	// Reindex once synchronously at startup (a ticker-based scheduler only
	// fires after its first interval elapses, which would otherwise leave
	// search_documents empty for the first tick) then keep it fresh on a
	// 60s timer, reusing the same exercise.PollScheduler abstraction the
	// OpenAEV connector below already uses rather than a new one.
	if err := search.ReindexAll(context.Background(), pool, engine); err != nil {
		log.Printf("[!] search: initial reindex failed: %v", err)
	}
	searchScheduler := exercise.NewPollScheduler(60 * time.Second)
	searchScheduler.Start(func(ctx context.Context) {
		if err := search.ReindexAll(ctx, pool, engine); err != nil {
			log.Printf("[!] search: reindex failed: %v", err)
		}
	})
	defer searchScheduler.Stop()
```

(`"context"`, `"log"`, `"time"`, and `exercise` are already imported in `main.go` — confirmed via the existing `openaevScheduler := exercise.NewPollScheduler(1 * time.Hour)` call a few lines below this insertion point.)

- [ ] **Step 3: Run build to verify it compiles**

Run: `cd orchestrator && go build ./...`
Expected: no errors

- [ ] **Step 4: Commit**

```bash
git add cmd/server/main.go
git commit -m "feat(server): wire Global Search reindex into startup + poll scheduler (Global Search Phase 1)"
```

---

### Task 7: Full regression

**Files:** none (verification only)

- [ ] **Step 1: Full build**

Run: `cd orchestrator && go build ./...`
Expected: no errors

- [ ] **Step 2: Full vet**

Run: `cd orchestrator && go vet ./...`
Expected: no errors

- [ ] **Step 3: Full test suite**

Run: `cd orchestrator && go test ./... -count=1` (run in background — this project's full suite takes several minutes)
Expected: PASS across all packages (Docker Desktop must be running). If a single unrelated package fails with a `testcontainers`/Docker provider connection error under full-suite load, re-run that package alone before treating it as a real regression — this project has hit this exact transient flake repeatedly (Phase 4, Phase 5, Knowledge Graph), always confirmed harmless by isolation re-run.

- [ ] **Step 4: Manual smoke check of the reindex + query round trip**

Since this task wires a real server startup path (`main.go`), a build-only check doesn't prove the reindex/query cycle actually works end-to-end. Run the server locally against the test/dev database (whatever this project's existing local-run convention is — check `README.md` or existing dev-run scripts if unsure) and confirm:

```bash
curl -s "http://localhost:PORT/api/search?q=ART" | head -c 2000
```

returns a non-empty JSON array once at least one scenario/actor/etc. containing "ART" exists in the loaded data. This is a one-time manual confirmation, not a new automated test — the automated tests already cover the reindex and query logic in isolation.
