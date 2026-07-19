# SP5 — Sector/Region Weighting Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Use a threat actor's sectors/regions (already fetched by `internal/connector`, currently barely used) to tag sector/region-relevant auto-generated scenarios and to weight technique priority scores across per-run reports, the EPSS Priority Index, and `internal/recommend`'s ranking.

**Architecture:** A new `threat_actor_profiles` table, upserted by `internal/connector`'s scheduler after every sync, is read by a new `internal/reporting.SectorRegionRelevantTechniques` function that matches persisted actor names/aliases against ATT&CK's canonical STIX group names and checks sector/region overlap against the deployment's already-existing `config.Config.ThreatIntelSectors`/`ThreatIntelRegions`. `ComputePriorityScore` gains a boolean parameter fed by that lookup, consumed by both `internal/reporting/engine.go` and `internal/recommend`. A bundled side-fix wires MISP's dead region filter to the same pattern already used for sectors.

**Tech Stack:** Go, PostgreSQL/pgx (no new dependencies).

## Global Constraints

- **Reuse `config.Config.ThreatIntelSectors`/`ThreatIntelRegions`** (`[]string`, already exists, already wired to MISP/OpenCTI) — no new env vars or config surface.
- **Matching is exact, never fuzzy** — actor name/alias vs. STIX group name via the same normalization `connector.actorKey()` uses; sector/region tag overlap via case-insensitive exact match.
- **Scenario generation is tag-only** — no scenario is excluded from generation based on sector/region.
- **Fully additive and offline-safe** — when `threat_actor_profiles` is empty or `ThreatIntelSectors`/`ThreatIntelRegions` are unset, every score and tag behaves exactly as today.
- **OpenCTI's sector filter is a documented gap, not fixed** — its GraphQL query never fetches sector/region data; only MISP's dead region filter gets fixed in this plan.
- **`attackdata` stays untouched** — pure, embedded, offline-only, exactly as today.

---

### Task 1: Database schema — `threat_actor_profiles`

**Files:**
- Modify: `orchestrator/internal/db/postgres.go` (append to the `stmts` slice, before its closing `}`)

**Interfaces:**
- Produces: `threat_actor_profiles` table (`name PRIMARY KEY, aliases text[], sectors text[], regions text[], source, last_seen, updated_at`).

- [ ] **Step 1: Ground the current end of the migration slice**

Run: `cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator && grep -n "CREATE TABLE IF NOT EXISTS scim_configs" internal/db/postgres.go`
Expected: one match — this is the last table in the existing `stmts` slice. Confirm the `UNIQUE (tenant_id)\n\t\t)\`,` block closing it is immediately followed by `\t}` closing the slice.

- [ ] **Step 2: Add `threat_actor_profiles`**

Using Edit, replace:

```go
			UNIQUE (tenant_id)
		)`,
	}
```

with:

```go
			UNIQUE (tenant_id)
		)`,

		// Sector/region weighting — SP5's last item. Upserted by
		// internal/connector's scheduler after every sync; read by
		// internal/reporting to weight technique priority scores. See
		// docs/superpowers/specs/2026-07-19-sp5-sector-region-weighting-design.md.
		`CREATE TABLE IF NOT EXISTS threat_actor_profiles (
			name       text        PRIMARY KEY,
			aliases    text[]      NOT NULL DEFAULT '{}',
			sectors    text[]      NOT NULL DEFAULT '{}',
			regions    text[]      NOT NULL DEFAULT '{}',
			source     text        NOT NULL DEFAULT '',
			last_seen  timestamptz,
			updated_at timestamptz NOT NULL DEFAULT NOW()
		)`,
	}
```

- [ ] **Step 3: Build and run the DB regression**

Run: `cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator && go build ./...`
Expected: clean build.

Run: `cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator && go test ./internal/db/... -v`
Expected: all PASS — proves the new `CREATE TABLE` statement is valid alongside every prior migration statement.

- [ ] **Step 4: Commit**

```bash
cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator
git add internal/db/postgres.go
git commit -m "feat(sp5): add threat_actor_profiles table

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
git push
```

---

### Task 2: `internal/connector` — fix MISP's dead region filter; document OpenCTI's gap

**Files:**
- Modify: `orchestrator/internal/connector/misp.go`
- Modify: `orchestrator/internal/connector/opencti.go`
- Create: `orchestrator/internal/connector/misp_filter_test.go`

**Interfaces:**
- Produces: `passesSectorRegionFilter(actorSectors, actorRegions, filterSectors, filterRegions []string) bool`, consumed by `MISPClient.extractActor`.

**Why this exists:** `MISPClient.regions` (stored, passed via `NewMISPClient`) was never actually read — the filtering code at `misp.go:219` only checked `c.sectors`, despite a comment claiming "Apply sector/region filter". `OpenCTIClient.sectors` has the same "stored but unread" symptom, but its root cause is different and unfixable here: OpenCTI's GraphQL query never fetches sector/region data at all, so `actor.Sectors` is always empty for OpenCTI actors — wiring the same filter in would silently reject every OpenCTI actor once `ThreatIntelSectors` is set, a regression, not a fix. OpenCTI gets a documenting comment instead.

- [ ] **Step 1: Ground the current MISP filter code**

Run: `cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator && grep -n "Apply sector/region filter" -A 3 internal/connector/misp.go`
Expected: one match, inside `MISPClient.extractActor`:
```go
	// Apply sector/region filter
	if len(c.sectors) > 0 && !intersects(actor.Sectors, c.sectors) {
		return nil
	}
```

- [ ] **Step 2: Write the failing test**

Create `orchestrator/internal/connector/misp_filter_test.go`:

```go
package connector

import "testing"

func TestPassesSectorRegionFilter(t *testing.T) {
	cases := []struct {
		name                         string
		actorSectors, actorRegions  []string
		filterSectors, filterRegions []string
		want                         bool
	}{
		{"no filters configured", []string{"banking"}, []string{"apac"}, nil, nil, true},
		{"sector matches, no region filter", []string{"banking"}, nil, []string{"banking"}, nil, true},
		{"sector filter set, no overlap", []string{"retail"}, nil, []string{"banking"}, nil, false},
		{"region matches, no sector filter", nil, []string{"apac"}, nil, []string{"apac"}, true},
		{"region filter set, no overlap", nil, []string{"emea"}, nil, []string{"apac"}, false},
		{"both filters set, sector matches but region does not", []string{"banking"}, []string{"emea"}, []string{"banking"}, []string{"apac"}, false},
		{"both filters set, both match", []string{"banking"}, []string{"apac"}, []string{"banking"}, []string{"apac"}, true},
		{"case-insensitive match", []string{"Banking"}, nil, []string{"banking"}, nil, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := passesSectorRegionFilter(c.actorSectors, c.actorRegions, c.filterSectors, c.filterRegions)
			if got != c.want {
				t.Errorf("passesSectorRegionFilter(%v,%v,%v,%v) = %v, want %v",
					c.actorSectors, c.actorRegions, c.filterSectors, c.filterRegions, got, c.want)
			}
		})
	}
}
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator && go test ./internal/connector/... -run TestPassesSectorRegionFilter -v`
Expected: FAIL to build — `undefined: passesSectorRegionFilter`.

- [ ] **Step 4: Implement the fix**

In `orchestrator/internal/connector/misp.go`, using Edit, replace:

```go
	// Apply sector/region filter
	if len(c.sectors) > 0 && !intersects(actor.Sectors, c.sectors) {
		return nil
	}
```

with:

```go
	// Apply sector/region filter
	if !passesSectorRegionFilter(actor.Sectors, actor.Regions, c.sectors, c.regions) {
		return nil
	}
```

Then, at the end of `orchestrator/internal/connector/misp.go` (after the existing `intersects` function), add:

```go

// passesSectorRegionFilter reports whether an actor should be kept, given
// the client's configured sector/region filters. An empty filter on either
// axis means "no restriction" for that axis — this fixes a bug where the
// region filter was accepted (stored on MISPClient, passed via
// NewMISPClient) but never actually applied; only the sector filter was.
// See docs/superpowers/specs/2026-07-19-sp5-sector-region-weighting-design.md.
func passesSectorRegionFilter(actorSectors, actorRegions, filterSectors, filterRegions []string) bool {
	if len(filterSectors) > 0 && !intersects(actorSectors, filterSectors) {
		return false
	}
	if len(filterRegions) > 0 && !intersects(actorRegions, filterRegions) {
		return false
	}
	return true
}
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator && go test ./internal/connector/... -run TestPassesSectorRegionFilter -v`
Expected: all 8 cases PASS.

- [ ] **Step 6: Document OpenCTI's gap**

In `orchestrator/internal/connector/opencti.go`, using Edit, replace:

```go
// OpenCTIClient fetches threat-actor TTP profiles from an OpenCTI instance.
type OpenCTIClient struct {
	baseURL    string
	apiKey     string
	httpClient *http.Client
	sectors    []string
}
```

with:

```go
// OpenCTIClient fetches threat-actor TTP profiles from an OpenCTI instance.
type OpenCTIClient struct {
	baseURL    string
	apiKey     string
	httpClient *http.Client
	// sectors is currently unused: unlike MISP, OpenCTI's GraphQL query
	// (octiThreatActorNode) never fetches sector/region relationship data,
	// so ThreatActor.Sectors/Regions are always empty for OpenCTI-sourced
	// actors. Wiring a filter check against always-empty data here would
	// silently reject every OpenCTI actor once ThreatIntelSectors is
	// configured — a regression, not a fix. Left unused deliberately,
	// documented rather than silently fixed incorrectly. Properly
	// supporting this needs OpenCTI's actual sector/region GraphQL schema,
	// which can't be verified without a live instance. See
	// docs/superpowers/specs/2026-07-19-sp5-sector-region-weighting-design.md.
	sectors []string
}
```

- [ ] **Step 7: Build and run the package regression**

Run: `cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator && go build ./... && go test ./internal/connector/... -v`
Expected: clean build; all tests PASS (including the pre-existing `TestNewScheduler_StatusFlags`/`TestMergeActors_UnionsTechniques`, unaffected by this task).

- [ ] **Step 8: Commit**

```bash
cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator
git add internal/connector/misp.go internal/connector/opencti.go internal/connector/misp_filter_test.go
git commit -m "fix(connector): wire MISP's dead region filter; document OpenCTI's sector gap

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
git push
```

---

### Task 3: `internal/connector` — persist actor profiles after sync

**Files:**
- Modify: `orchestrator/internal/connector/scheduler.go`
- Modify: `orchestrator/internal/connector/scheduler_test.go`
- Create: `orchestrator/internal/connector/testmain_test.go`
- Modify: `orchestrator/cmd/server/main.go`

**Interfaces:**
- Consumes: `threat_actor_profiles` table (Task 1).
- Produces: `Scheduler.pool *pgxpool.Pool` field, `NewScheduler`'s new 5th parameter, `(s *Scheduler) upsertActorProfiles(actors []ThreatActor)`. Consumed by Task 6's DB-backed tests indirectly (they seed this table directly, not through the scheduler).

- [ ] **Step 1: Add the package's Docker TestMain**

This is the first DB-backed test in `internal/connector` — it needs the same `TestMain`/`sharedDB` scaffolding every other Docker-backed package already has.

Create `orchestrator/internal/connector/testmain_test.go`:

```go
package connector

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
```

- [ ] **Step 2: Write the failing test**

Create a new test in `orchestrator/internal/connector/scheduler_test.go` — using Edit, append after `TestMergeActors_UnionsTechniques`:

```go

func TestScheduler_SyncUpsertsActorProfiles(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		s := NewScheduler([]Source{
			fakeSource{name: "bundle", actors: []ThreatActor{{
				Name:       "APT36",
				Aliases:    []string{"Transparent Tribe"},
				Sectors:    []string{"government"},
				Regions:    []string{"south-asia"},
				Source:     "bundle",
				Techniques: []TechniqueRef{{ID: "T1059.001"}, {ID: "T1566.001"}},
			}}},
		}, NewGenerator(t.TempDir(), nil, nil), nil, 24, pool)

		s.sync()

		var aliases, sectors, regions []string
		err := pool.QueryRow(t.Context(),
			`SELECT aliases, sectors, regions FROM threat_actor_profiles WHERE name = 'APT36'`,
		).Scan(&aliases, &sectors, &regions)
		if err != nil {
			t.Fatalf("expected APT36 profile to be persisted: %v", err)
		}
		if len(aliases) != 1 || aliases[0] != "Transparent Tribe" {
			t.Errorf("aliases = %v, want [Transparent Tribe]", aliases)
		}
		if len(sectors) != 1 || sectors[0] != "government" {
			t.Errorf("sectors = %v, want [government]", sectors)
		}
		if len(regions) != 1 || regions[0] != "south-asia" {
			t.Errorf("regions = %v, want [south-asia]", regions)
		}
	})
}
```

Also update the file's imports (top of `orchestrator/internal/connector/scheduler_test.go`) — using Edit, replace:

```go
package connector

import "testing"
```

with:

```go
package connector

import (
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)
```

And update the two existing `NewScheduler`/`NewGenerator` call sites in the same file — using Edit, replace:

```go
	s := NewScheduler([]Source{
		fakeSource{name: "misp"},
		fakeSource{name: "bundle"},
	}, NewGenerator(t.TempDir()), nil, 24)
```

with:

```go
	s := NewScheduler([]Source{
		fakeSource{name: "misp"},
		fakeSource{name: "bundle"},
	}, NewGenerator(t.TempDir(), nil, nil), nil, 24, sharedDB.Pool)
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator && go test ./internal/connector/... -v`
Expected: FAIL to build — `too many arguments in call to NewScheduler`, `too many arguments in call to NewGenerator` (Task 4 hasn't changed `NewGenerator`'s signature yet, so this step's `NewGenerator(t.TempDir(), nil, nil)` calls will also fail to build until Task 4 lands — that's expected; both signature changes need to compile together. Proceed to Step 4, which fixes `NewScheduler` only; Task 4 fixes `NewGenerator`).

- [ ] **Step 4: Implement `Scheduler`'s DB pool + upsert**

In `orchestrator/internal/connector/scheduler.go`, using Edit, replace the imports:

```go
import (
	"log"
	"strings"
	"sync"
	"time"

	"github.com/audspect/bas/internal/scenario"
)
```

with:

```go
import (
	"context"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/scenario"
)
```

Replace the `Scheduler` struct and `NewScheduler`:

```go
// Scheduler polls MISP and OpenCTI on a configurable interval and
// regenerates intel scenarios into the scenarios/intel/ directory.
type Scheduler struct {
	sources   []Source
	generator *Generator
	engine    *scenario.Engine
	interval  time.Duration

	mu     sync.RWMutex
	status ConnectorStatus
	syncCh chan struct{} // manual trigger
	stopCh chan struct{}
}

// NewScheduler creates a Scheduler over the given threat-intel sources (any of
// MISP, OpenCTI, BundleSource). An empty slice leaves the connector idle.
func NewScheduler(
	sources []Source,
	generator *Generator,
	engine *scenario.Engine,
	pollHours int,
) *Scheduler {
```

with:

```go
// Scheduler polls MISP and OpenCTI on a configurable interval and
// regenerates intel scenarios into the scenarios/intel/ directory.
type Scheduler struct {
	sources   []Source
	generator *Generator
	engine    *scenario.Engine
	interval  time.Duration
	// pool persists fetched actor profiles (sectors/regions) for
	// internal/reporting's priority-score weighting. See
	// docs/superpowers/specs/2026-07-19-sp5-sector-region-weighting-design.md.
	pool *pgxpool.Pool

	mu     sync.RWMutex
	status ConnectorStatus
	syncCh chan struct{} // manual trigger
	stopCh chan struct{}
}

// NewScheduler creates a Scheduler over the given threat-intel sources (any of
// MISP, OpenCTI, BundleSource). An empty slice leaves the connector idle.
func NewScheduler(
	sources []Source,
	generator *Generator,
	engine *scenario.Engine,
	pollHours int,
	pool *pgxpool.Pool,
) *Scheduler {
```

Find the line inside `NewScheduler` that constructs `s := &Scheduler{...}` and, using Edit, replace:

```go
	s := &Scheduler{
		sources:   sources,
		generator: generator,
		engine:    engine,
		interval:  time.Duration(pollHours) * time.Hour,
		syncCh:    make(chan struct{}, 1),
		stopCh:    make(chan struct{}),
	}
```

with:

```go
	s := &Scheduler{
		sources:   sources,
		generator: generator,
		engine:    engine,
		interval:  time.Duration(pollHours) * time.Hour,
		pool:      pool,
		syncCh:    make(chan struct{}, 1),
		stopCh:    make(chan struct{}),
	}
```

In `func (s *Scheduler) sync()`, using Edit, replace:

```go
	// Merge actors with the same name across sources — bundle floor + live
	// overlay compose here, since MergeActors unions their techniques.
	actors = MergeActors(actors)

	// ── Generate scenarios ────────────────────────────────────────────────
	result, err := s.generator.Write(actors)
```

with:

```go
	// Merge actors with the same name across sources — bundle floor + live
	// overlay compose here, since MergeActors unions their techniques.
	actors = MergeActors(actors)

	// Persist actor profiles (sectors/regions) for reporting's priority-score
	// weighting — see docs/superpowers/specs/2026-07-19-sp5-sector-region-weighting-design.md.
	s.upsertActorProfiles(actors)

	// ── Generate scenarios ────────────────────────────────────────────────
	result, err := s.generator.Write(actors)
```

Finally, at the end of `orchestrator/internal/connector/scheduler.go`, add:

```go

// upsertActorProfiles persists each actor's sectors/regions/aliases so
// internal/reporting can weight technique priority scores by sector/region
// relevance. A single actor's upsert failing is logged and skipped, never
// aborting the rest — same discipline sync() already applies to source
// fetches. No-op when pool is nil (e.g. a test that never calls sync()).
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
			`INSERT INTO threat_actor_profiles (name, aliases, sectors, regions, source, last_seen, updated_at)
			 VALUES ($1,$2,$3,$4,$5,$6,NOW())
			 ON CONFLICT (name) DO UPDATE SET
			   aliases = EXCLUDED.aliases, sectors = EXCLUDED.sectors, regions = EXCLUDED.regions,
			   source = EXCLUDED.source, last_seen = EXCLUDED.last_seen, updated_at = NOW()`,
			a.Name, a.Aliases, a.Sectors, a.Regions, a.Source, lastSeen)
		if err != nil {
			log.Printf("[connector] upsert actor profile %q: %v", a.Name, err)
		}
	}
}
```

- [ ] **Step 5: Update the `main.go` call site**

In `orchestrator/cmd/server/main.go`, using Edit, replace:

```go
	scheduler := connector.NewScheduler(tiSources, gen, engine, cfg.ThreatIntelPollHours)
```

with:

```go
	scheduler := connector.NewScheduler(tiSources, gen, engine, cfg.ThreatIntelPollHours, pool)
```

- [ ] **Step 6: Run the tests to verify they pass**

Note: this step will still fail until Task 4 also updates `NewGenerator`'s signature (both changes must land together for the package to build, per Step 3's note). If executing tasks strictly in order, run this verification as part of Task 4's Step 6 instead — do not attempt to get `internal/connector` green until both `NewScheduler` and `NewGenerator` signatures are updated.

- [ ] **Step 7: Commit** (only after Task 4 is also complete and the package builds — see Task 4's commit step, which commits both tasks' changes together if executed back-to-back, or commit now if a partial, deliberately-broken intermediate state is acceptable to your workflow. This plan recommends completing Task 4 immediately after this step before committing either.)

```bash
cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator
git add internal/connector/scheduler.go internal/connector/scheduler_test.go internal/connector/testmain_test.go cmd/server/main.go
git commit -m "feat(sp5): persist threat-actor profiles after each connector sync

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
git push
```

---

### Task 4: `internal/connector` — tag sector/region-relevant scenarios

**Files:**
- Modify: `orchestrator/internal/connector/generator.go`
- Create: `orchestrator/internal/connector/generator_test.go`
- Modify: `orchestrator/cmd/server/main.go`

**Interfaces:**
- Produces: `NewGenerator`'s new 2nd/3rd parameters (`sectors, regions []string`), `Generator.buildYAML` becomes a method.

**Note:** This task must be completed together with Task 3 for `internal/connector` to build — both change constructor signatures the same test/main files call.

- [ ] **Step 1: Write the failing test**

Create `orchestrator/internal/connector/generator_test.go`:

```go
package connector

import (
	"strings"
	"testing"
)

func TestBuildYAML_TagsSectorAndRegionRelevance(t *testing.T) {
	g := NewGenerator(t.TempDir(), []string{"government"}, []string{"south-asia"})
	actor := ThreatActor{
		Name:       "APT36",
		Sectors:    []string{"government"},
		Regions:    []string{"south-asia"},
		Techniques: []TechniqueRef{{ID: "T1059.001"}, {ID: "T1566.001"}},
	}
	yaml := g.buildYAML(actor, "abc123")
	if !strings.Contains(yaml, "sector-relevant") {
		t.Error("expected sector-relevant tag when actor sector matches configured sector")
	}
	if !strings.Contains(yaml, "region-relevant") {
		t.Error("expected region-relevant tag when actor region matches configured region")
	}
}

func TestBuildYAML_NoTagsWhenNoOverlap(t *testing.T) {
	g := NewGenerator(t.TempDir(), []string{"financial-services"}, []string{"emea"})
	actor := ThreatActor{
		Name:       "SomeOtherActor",
		Sectors:    []string{"government"},
		Regions:    []string{"south-asia"},
		Techniques: []TechniqueRef{{ID: "T1059.001"}, {ID: "T1566.001"}},
	}
	yaml := g.buildYAML(actor, "def456")
	if strings.Contains(yaml, "sector-relevant") {
		t.Error("did not expect sector-relevant tag when no sector overlap")
	}
	if strings.Contains(yaml, "region-relevant") {
		t.Error("did not expect region-relevant tag when no region overlap")
	}
}

func TestBuildYAML_NoTagsWhenNotConfigured(t *testing.T) {
	g := NewGenerator(t.TempDir(), nil, nil)
	actor := ThreatActor{
		Name:       "APT36",
		Sectors:    []string{"government"},
		Regions:    []string{"south-asia"},
		Techniques: []TechniqueRef{{ID: "T1059.001"}, {ID: "T1566.001"}},
	}
	yaml := g.buildYAML(actor, "ghi789")
	if strings.Contains(yaml, "sector-relevant") || strings.Contains(yaml, "region-relevant") {
		t.Error("did not expect relevance tags when deployment sector/region is unconfigured")
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator && go test ./internal/connector/... -run TestBuildYAML -v`
Expected: FAIL to build — `not enough arguments in call to NewGenerator`, `g.buildYAML undefined` (still a free function).

- [ ] **Step 3: Convert `Generator`/`buildYAML` and add tagging**

In `orchestrator/internal/connector/generator.go`, using Edit, replace:

```go
// Generator converts ThreatActor profiles into BAS scenario YAML files.
type Generator struct {
	intelDir string // e.g. "scenarios/intel"
}

// NewGenerator creates a Generator that writes to intelDir.
func NewGenerator(scenariosDir string) *Generator {
	return &Generator{intelDir: filepath.Join(scenariosDir, "intel")}
}
```

with:

```go
// Generator converts ThreatActor profiles into BAS scenario YAML files.
type Generator struct {
	intelDir string // e.g. "scenarios/intel"
	// sectors/regions are the deployment's own configured values
	// (config.Config.ThreatIntelSectors/ThreatIntelRegions) — when a
	// generated actor's own Sectors/Regions overlap these, the scenario
	// gets an extra relevance tag. Empty means no tags are ever added. See
	// docs/superpowers/specs/2026-07-19-sp5-sector-region-weighting-design.md.
	sectors []string
	regions []string
}

// NewGenerator creates a Generator that writes to intelDir, tagging
// generated scenarios as sector/region-relevant when a threat actor's own
// Sectors/Regions overlap the given values.
func NewGenerator(scenariosDir string, sectors, regions []string) *Generator {
	return &Generator{intelDir: filepath.Join(scenariosDir, "intel"), sectors: sectors, regions: regions}
}
```

Then, using Edit, replace:

```go
		yaml := buildYAML(actor, fp)
```

with:

```go
		yaml := g.buildYAML(actor, fp)
```

Then, using Edit, replace:

```go
func buildYAML(actor ThreatActor, fingerprint string) string {
```

with:

```go
func (g *Generator) buildYAML(actor ThreatActor, fingerprint string) string {
```

Then, using Edit, replace:

```go
	// Tags
	tags := []string{"intel", "auto-generated", strings.ToLower(strings.ReplaceAll(actor.Name, " ", "-"))}
	if len(actor.Sectors) > 0 {
		tags = append(tags, actor.Sectors...)
	}
```

with:

```go
	// Tags
	tags := []string{"intel", "auto-generated", strings.ToLower(strings.ReplaceAll(actor.Name, " ", "-"))}
	if len(actor.Sectors) > 0 {
		tags = append(tags, actor.Sectors...)
	}
	if intersects(actor.Sectors, g.sectors) {
		tags = append(tags, "sector-relevant")
	}
	if intersects(actor.Regions, g.regions) {
		tags = append(tags, "region-relevant")
	}
```

- [ ] **Step 4: Update the `main.go` call site**

In `orchestrator/cmd/server/main.go`, using Edit, replace:

```go
	gen := connector.NewGenerator(cfg.ScenariosDir)
```

with:

```go
	gen := connector.NewGenerator(cfg.ScenariosDir, cfg.ThreatIntelSectors, cfg.ThreatIntelRegions)
```

- [ ] **Step 5: Run the full package test suite (Tasks 3+4 together)**

Run: `cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator && go build ./...`
Expected: clean build — this is the first point both `NewScheduler` and `NewGenerator` signature changes are complete together.

Run: `cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator && go test ./internal/connector/... -v`
Expected: all tests PASS, including `TestPassesSectorRegionFilter` (Task 2), `TestScheduler_SyncUpsertsActorProfiles` (Task 3), `TestBuildYAML_*` (this task), and the pre-existing `TestNewScheduler_StatusFlags`/`TestMergeActors_UnionsTechniques`.

- [ ] **Step 6: Commit Task 3 and Task 4 together**

```bash
cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator
git add internal/connector/scheduler.go internal/connector/scheduler_test.go internal/connector/testmain_test.go internal/connector/generator.go internal/connector/generator_test.go cmd/server/main.go
git commit -m "feat(sp5): persist threat-actor profiles and tag sector/region-relevant scenarios

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
git push
```

---

### Task 5: `internal/reporting` — sector/region-weighted priority scoring

**Files:**
- Modify: `orchestrator/internal/reporting/insights.go`
- Modify: `orchestrator/internal/reporting/insights_test.go`
- Modify: `orchestrator/internal/reporting/engine.go`
- Modify: `orchestrator/cmd/server/main.go`

**Interfaces:**
- Consumes: `threat_actor_profiles` table (Task 1).
- Produces: `SectorRegionRelevantTechniques(ctx, db, sectors, regions []string) (map[string]bool, error)`, `ComputePriorityScore`'s new 5th parameter, `Engine.WithSectorRegion`/`Sectors()`/`Regions()`. Consumed by Task 6.

- [ ] **Step 1: Write the failing tests for `ComputePriorityScore`'s new parameter**

In `orchestrator/internal/reporting/insights_test.go`, using Edit, replace the entire `TestComputePriorityScore` function:

```go
func TestComputePriorityScore(t *testing.T) {
	cases := []struct {
		name           string
		kev            bool
		epssPercentile float64
		actors         int
		verdict        string
		want           int
	}{
		{"no signals", false, 0, 0, "pass", 0},
		{"kev only", true, 0, 0, "pass", 40},
		{"epss tier 90", false, 90, 0, "pass", 30},
		{"epss tier 70", false, 70, 0, "pass", 20},
		{"epss tier 50", false, 50, 0, "pass", 10},
		{"epss tier 30", false, 30, 0, "pass", 5},
		{"epss below 30", false, 29, 0, "pass", 0},
		{"actors tier 5", false, 0, 5, "pass", 20},
		{"actors tier 2", false, 0, 2, "pass", 10},
		{"actors tier 1", false, 0, 1, "pass", 5},
		{"actors 0", false, 0, 0, "pass", 0},
		{"fail bonus", false, 0, 0, "fail", 10},
		{"fail bonus does not apply to pass/blocked", false, 0, 0, "blocked", 0},
		{"everything maxes and clamps at 100", true, 95, 6, "fail", 100},
		{"kev+epss70+actors2, no fail bonus", true, 70, 2, "pass", 70}, // 40+20+10
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := ComputePriorityScore(c.kev, c.epssPercentile, c.actors, c.verdict, false); got != c.want {
				t.Errorf("ComputePriorityScore(kev=%v, epss=%.0f, actors=%d, verdict=%q, sectorRegionRelevant=false) = %d, want %d",
					c.kev, c.epssPercentile, c.actors, c.verdict, got, c.want)
			}
		})
	}
}

func TestComputePriorityScore_SectorRegionRelevant(t *testing.T) {
	if got := ComputePriorityScore(false, 0, 0, "pass", true); got != 10 {
		t.Errorf("sectorRegionRelevant alone = %d, want 10", got)
	}
	if got := ComputePriorityScore(true, 95, 6, "fail", true); got != 100 {
		t.Errorf("everything maxed + sectorRegionRelevant = %d, want 100 (clamped)", got)
	}
	if got := ComputePriorityScore(false, 0, 0, "pass", false); got != 0 {
		t.Errorf("sectorRegionRelevant=false with no other signals = %d, want 0", got)
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator && go test ./internal/reporting/... -run TestComputePriorityScore -v`
Expected: FAIL to build — `not enough arguments in call to ComputePriorityScore`.

- [ ] **Step 3: Update `ComputePriorityScore`**

In `orchestrator/internal/reporting/insights.go`, using Edit, replace:

```go
// ComputePriorityScore derives a 0–100 composite from threat signals.
// KEV: +40; EPSS percentile ≥90: +30, ≥70: +20, ≥50: +10, ≥30: +5;
// ThreatActors ≥5: +20, ≥2: +10, ≥1: +5; Verdict==fail: +10 bonus.
// Exported so internal/recommend can score never-tested techniques with the
// same weights the per-run report already uses.
func ComputePriorityScore(kev bool, epssPercentile float64, actors int, verdict string) int {
	s := 0
	if kev {
		s += 40
	}
	switch {
	case epssPercentile >= 90:
		s += 30
	case epssPercentile >= 70:
		s += 20
	case epssPercentile >= 50:
		s += 10
	case epssPercentile >= 30:
		s += 5
	}
	switch {
	case actors >= 5:
		s += 20
	case actors >= 2:
		s += 10
	case actors >= 1:
		s += 5
	}
	if verdict == "fail" {
		s += 10
	}
	if s > 100 {
		s = 100
	}
	return s
}
```

with:

```go
// ComputePriorityScore derives a 0–100 composite from threat signals.
// KEV: +40; EPSS percentile ≥90: +30, ≥70: +20, ≥50: +10, ≥30: +5;
// ThreatActors ≥5: +20, ≥2: +10, ≥1: +5; Verdict==fail: +10 bonus;
// sectorRegionRelevant: +10 bonus (see SectorRegionRelevantTechniques).
// Exported so internal/recommend can score never-tested techniques with the
// same weights the per-run report already uses.
func ComputePriorityScore(kev bool, epssPercentile float64, actors int, verdict string, sectorRegionRelevant bool) int {
	s := 0
	if kev {
		s += 40
	}
	switch {
	case epssPercentile >= 90:
		s += 30
	case epssPercentile >= 70:
		s += 20
	case epssPercentile >= 50:
		s += 10
	case epssPercentile >= 30:
		s += 5
	}
	switch {
	case actors >= 5:
		s += 20
	case actors >= 2:
		s += 10
	case actors >= 1:
		s += 5
	}
	if verdict == "fail" {
		s += 10
	}
	if sectorRegionRelevant {
		s += 10
	}
	if s > 100 {
		s = 100
	}
	return s
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator && go test ./internal/reporting/... -run TestComputePriorityScore -v`
Expected: FAIL again — this time on other packages' now-stale call sites (`internal/reporting/engine.go`, `internal/recommend/recommend.go`) failing to build. Proceed to Step 5 before re-running.

- [ ] **Step 5: Add the package's Docker TestMain**

`internal/reporting` has no Docker-backed tests today (verified: no `sharedDB`/`pgxpool` reference in any of its `_test.go` files) — this is the first one, so it needs the same `TestMain`/`sharedDB` scaffolding every other Docker-backed package already has.

Create `orchestrator/internal/reporting/testmain_test.go`:

```go
package reporting

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
```

- [ ] **Step 6: Write the failing test for `SectorRegionRelevantTechniques`**

In `orchestrator/internal/reporting/insights_test.go`, using Edit, replace the imports:

```go
import (
	"testing"

	"github.com/audspect/bas/internal/models"
	"github.com/audspect/bas/internal/reporting/attackdata"
)
```

with:

```go
import (
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/models"
	"github.com/audspect/bas/internal/reporting/attackdata"
)
```

Then add the tests:

```go

func TestSectorRegionRelevantTechniques_EmptyInputsSkipQuery(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		relevant, err := SectorRegionRelevantTechniques(t.Context(), pool, nil, nil)
		if err != nil {
			t.Fatalf("SectorRegionRelevantTechniques: %v", err)
		}
		if len(relevant) != 0 {
			t.Errorf("expected an empty map when sectors/regions are both empty, got %v", relevant)
		}
	})
}

func TestSectorRegionRelevantTechniques_MatchesByNameAndAlias(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		groupIdx := attackdata.GroupTechniqueIndex()
		if len(groupIdx) == 0 {
			t.Skip("no embedded ATT&CK group data available")
		}
		var knownGroup string
		for g := range groupIdx {
			knownGroup = g
			break
		}

		_, err := pool.Exec(t.Context(),
			`INSERT INTO threat_actor_profiles (name, aliases, sectors, regions, source)
			 VALUES ($1, '{}', $2, $3, 'bundle')`,
			knownGroup, []string{"government"}, []string{"south-asia"})
		if err != nil {
			t.Fatalf("seed: %v", err)
		}

		relevant, err := SectorRegionRelevantTechniques(t.Context(), pool, []string{"government"}, nil)
		if err != nil {
			t.Fatalf("SectorRegionRelevantTechniques: %v", err)
		}
		for _, tid := range groupIdx[knownGroup] {
			if !relevant[strings.ToUpper(tid)] {
				t.Errorf("expected technique %s (under group %q) to be marked relevant", tid, knownGroup)
			}
		}
	})
}
```

- [ ] **Step 7: Run the tests to verify they fail**

Run: `cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator && go test ./internal/reporting/... -run TestSectorRegionRelevantTechniques -v`
Expected: FAIL to build — `undefined: SectorRegionRelevantTechniques`.

- [ ] **Step 8: Implement `SectorRegionRelevantTechniques`**

In `orchestrator/internal/reporting/insights.go`, using Edit, replace the imports:

```go
import (
	"fmt"
	"sort"
	"strings"

	"github.com/audspect/bas/internal/models"
	"github.com/audspect/bas/internal/reporting/attackdata"
)
```

with:

```go
import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/models"
	"github.com/audspect/bas/internal/reporting/attackdata"
)
```

Then, at the end of the file, add:

```go

// SectorRegionRelevantTechniques returns the set of technique IDs backed by
// at least one persisted threat_actor_profiles row whose sectors/regions
// overlap the given values. Matching is exact-normalized name/alias against
// ATT&CK's canonical STIX group names — no fuzzy matching, so a near-miss
// produces no bonus rather than a wrong one. Returns an empty map (no query
// issued) when both sectors and regions are empty. See
// docs/superpowers/specs/2026-07-19-sp5-sector-region-weighting-design.md.
func SectorRegionRelevantTechniques(ctx context.Context, db *pgxpool.Pool, sectors, regions []string) (map[string]bool, error) {
	relevant := map[string]bool{}
	if len(sectors) == 0 && len(regions) == 0 {
		return relevant, nil
	}

	rows, err := db.Query(ctx, `SELECT name, aliases, sectors, regions FROM threat_actor_profiles`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	type profile struct {
		name    string
		aliases []string
		sectors []string
		regions []string
	}
	var profiles []profile
	for rows.Next() {
		var p profile
		if rows.Scan(&p.name, &p.aliases, &p.sectors, &p.regions) != nil {
			continue
		}
		profiles = append(profiles, p)
	}

	groupIdx := attackdata.GroupTechniqueIndex()
	for groupName, techIDs := range groupIdx {
		normGroup := normalizeActorName(groupName)
		for _, p := range profiles {
			if !sectorRegionOverlap(p.sectors, sectors) && !sectorRegionOverlap(p.regions, regions) {
				continue
			}
			matched := normalizeActorName(p.name) == normGroup
			if !matched {
				for _, alias := range p.aliases {
					if normalizeActorName(alias) == normGroup {
						matched = true
						break
					}
				}
			}
			if matched {
				for _, tid := range techIDs {
					relevant[strings.ToUpper(tid)] = true
				}
				break
			}
		}
	}
	return relevant, nil
}

// normalizeActorName mirrors internal/connector's actorKey() normalization
// (lowercase, strip spaces/hyphens) so actor names/aliases can be matched
// against ATT&CK's canonical STIX group names without importing
// internal/connector for one small helper.
func normalizeActorName(name string) string {
	return strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(name, " ", ""), "-", ""))
}

// sectorRegionOverlap is a case-insensitive set-intersection check —
// internal/reporting's own small equivalent of internal/connector's
// intersects(), kept local since reporting has no other dependency on
// connector.
func sectorRegionOverlap(a, b []string) bool {
	for _, x := range a {
		for _, y := range b {
			if strings.EqualFold(x, y) {
				return true
			}
		}
	}
	return false
}
```

- [ ] **Step 9: Run the tests to verify they pass**

Run: `cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator && go test ./internal/reporting/... -run 'TestSectorRegionRelevantTechniques|TestComputePriorityScore' -v`
Expected: `TestSectorRegionRelevantTechniques_*` PASS. `TestComputePriorityScore*` still FAIL to build — `engine.go`'s call site is fixed in the next step.

- [ ] **Step 10: Wire `Engine` and `populatePriorityScores`**

In `orchestrator/internal/reporting/engine.go`, using Edit, replace:

```go
type Engine struct {
	db            *pgxpool.Pool
	scenarios     ScenarioResolver     // nil until WithScenarios is called; Detection Validation stays inactive while nil
	verifications VerificationResolver // nil until WithVerifications is called; only automatic verdicts contribute while nil
	rules         RuleLibraryResolver  // nil until WithRuleLibrary is called; Attack Path Detection Coverage stays inactive while nil
}
```

with:

```go
type Engine struct {
	db            *pgxpool.Pool
	scenarios     ScenarioResolver     // nil until WithScenarios is called; Detection Validation stays inactive while nil
	verifications VerificationResolver // nil until WithVerifications is called; only automatic verdicts contribute while nil
	rules         RuleLibraryResolver  // nil until WithRuleLibrary is called; Attack Path Detection Coverage stays inactive while nil
	// sectors/regions are the deployment's own configured values
	// (config.Config.ThreatIntelSectors/ThreatIntelRegions), set via
	// WithSectorRegion. Empty means priority scores never get the
	// sector/region bonus. See
	// docs/superpowers/specs/2026-07-19-sp5-sector-region-weighting-design.md.
	sectors []string
	regions []string
}
```

Then, using Edit, replace:

```go
// WithRuleLibrary attaches the Rule Library resolver used by the Attack Path
// Detection Coverage section. Returns the engine for chaining.
func (e *Engine) WithRuleLibrary(r RuleLibraryResolver) *Engine {
	e.rules = r
	return e
}
```

with:

```go
// WithRuleLibrary attaches the Rule Library resolver used by the Attack Path
// Detection Coverage section. Returns the engine for chaining.
func (e *Engine) WithRuleLibrary(r RuleLibraryResolver) *Engine {
	e.rules = r
	return e
}

// WithSectorRegion attaches the deployment's own sector/region, used to
// weight technique priority scores toward actors that target them. Returns
// the engine for chaining.
func (e *Engine) WithSectorRegion(sectors, regions []string) *Engine {
	e.sectors = sectors
	e.regions = regions
	return e
}

// Sectors returns the configured deployment sectors, for callers (like
// internal/api's recommend handler) that hold an *Engine and need the same
// values without duplicating storage.
func (e *Engine) Sectors() []string { return e.sectors }

// Regions returns the configured deployment regions, mirroring Sectors.
func (e *Engine) Regions() []string { return e.regions }
```

Then, in `populatePriorityScores`, using Edit, replace:

```go
	// Threat actor count per technique from embedded STIX (already loaded)
	actorIdx := attackdata.GroupTechniqueIndex()
	actorCount := make(map[string]int, len(ids))
	for _, techIDs := range actorIdx {
		for _, tid := range techIDs {
			actorCount[strings.ToUpper(tid)]++
		}
	}
```

with:

```go
	// Threat actor count per technique from embedded STIX (already loaded)
	actorIdx := attackdata.GroupTechniqueIndex()
	actorCount := make(map[string]int, len(ids))
	for _, techIDs := range actorIdx {
		for _, tid := range techIDs {
			actorCount[strings.ToUpper(tid)]++
		}
	}

	// Sector/region relevance — see
	// docs/superpowers/specs/2026-07-19-sp5-sector-region-weighting-design.md.
	// Returns an empty map immediately (no query) when neither is configured.
	sectorRegionRelevant, err := SectorRegionRelevantTechniques(ctx, e.db, e.sectors, e.regions)
	if err != nil {
		log.Printf("[reporting] sector/region relevance lookup: %v", err)
		sectorRegionRelevant = map[string]bool{}
	}
```

Then, using Edit, replace:

```go
		score := ComputePriorityScore(kevCnt > 0, ep.pct, actors, verdict)
```

with:

```go
		score := ComputePriorityScore(kevCnt > 0, ep.pct, actors, verdict, sectorRegionRelevant[tid])
```

- [ ] **Step 11: Update the `main.go` call site**

In `orchestrator/cmd/server/main.go`, using Edit, replace:

```go
	reportingEngine := reporting.NewEngine(pool).
		WithScenarios(engine).
		WithVerifications(verificationStore).
		WithRuleLibrary(rulesEngine)
```

with:

```go
	reportingEngine := reporting.NewEngine(pool).
		WithScenarios(engine).
		WithVerifications(verificationStore).
		WithRuleLibrary(rulesEngine).
		WithSectorRegion(cfg.ThreatIntelSectors, cfg.ThreatIntelRegions)
```

- [ ] **Step 12: Run the full package test suite**

Run: `cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator && go build ./...`
Expected: still FAILS — `internal/recommend` isn't updated yet (Task 6). This is expected; proceed there next.

Run: `cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator && go test ./internal/reporting/... -run 'TestComputePriorityScore|TestSectorRegionRelevantTechniques' -v`
Expected: all PASS (this specific package's own tests don't depend on `internal/recommend` building).

- [ ] **Step 13: Commit**

```bash
cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator
git add internal/reporting/insights.go internal/reporting/insights_test.go internal/reporting/engine.go internal/reporting/testmain_test.go cmd/server/main.go
git commit -m "feat(sp5): weight technique priority scores by sector/region relevance

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
git push
```

---

### Task 6: `internal/recommend` + `internal/api` — wire the ranking

**Files:**
- Modify: `orchestrator/internal/recommend/recommend.go`
- Modify: `orchestrator/internal/recommend/recommend_test.go`
- Modify: `orchestrator/internal/api/recommend_handlers.go`

**Interfaces:**
- Consumes: `reporting.SectorRegionRelevantTechniques`, `reporting.ComputePriorityScore`'s new parameter (Task 5), `Engine.Sectors()`/`Regions()` (Task 5).
- Produces: `recommend.Build`'s 2 new trailing parameters.

- [ ] **Step 1: Ground the current `Build` signature and call sites**

Run: `cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator && grep -n "func Build(" internal/recommend/recommend.go && grep -n "Build(context.Background()" internal/recommend/recommend_test.go`
Expected: one function definition, 7 test call sites, all of the form `Build(context.Background(), pool, <g>, attackpath.Summary{}, <limit>)`.

- [ ] **Step 2: Update `recommend.Build`**

In `orchestrator/internal/recommend/recommend.go`, using Edit, replace:

```go
func Build(ctx context.Context, pool *pgxpool.Pool, g *attackpath.Graph, s attackpath.Summary, limit int) (Recommendations, error) {
```

with:

```go
func Build(ctx context.Context, pool *pgxpool.Pool, g *attackpath.Graph, s attackpath.Summary, limit int, sectors, regions []string) (Recommendations, error) {
```

Then, using Edit, replace:

```go
	actors := actorCounts()
	env := buildEnvIndex(g, s, pathcorrelation.DefaultEdgeTechniqueMapper{})
```

with:

```go
	actors := actorCounts()
	sectorRegionRelevant, err := reporting.SectorRegionRelevantTechniques(ctx, pool, sectors, regions)
	if err != nil {
		sectorRegionRelevant = map[string]bool{}
	}
	env := buildEnvIndex(g, s, pathcorrelation.DefaultEdgeTechniqueMapper{})
```

Then, using Edit, replace:

```go
		t.ThreatPriority = reporting.ComputePriorityScore(t.KEV, t.EPSSPercentile, t.ThreatActors, verdict)
```

with:

```go
		t.ThreatPriority = reporting.ComputePriorityScore(t.KEV, t.EPSSPercentile, t.ThreatActors, verdict, sectorRegionRelevant[key])
```

- [ ] **Step 3: Update the 7 test call sites**

In `orchestrator/internal/recommend/recommend_test.go`, using Edit with `replace_all: true`, replace:

```go
attackpath.Summary{}, 20)
```

with:

```go
attackpath.Summary{}, 20, nil, nil)
```

Run: `cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator && grep -n "attackpath.Summary{}, " internal/recommend/recommend_test.go`
Expected: one remaining unconverted call site — `Build(context.Background(), pool, nil, attackpath.Summary{}, 2)` (the `TestBuild_SuggestedScenarioCarriesTopN` test uses limit `2`, not `20`, so the broad replace above won't have touched it). Using Edit, replace:

```go
		recs, err := Build(context.Background(), pool, nil, attackpath.Summary{}, 2)
```

with:

```go
		recs, err := Build(context.Background(), pool, nil, attackpath.Summary{}, 2, nil, nil)
```

- [ ] **Step 4: Add a test confirming sector/region-relevant ranking**

In `orchestrator/internal/recommend/recommend_test.go`, add (after `TestBuild_KEVOutranksNoSignal`, using the file's existing `seedTechnique`/`rankOf` helpers exactly as `TestBuild_KEVOutranksNoSignal` itself does):

```go
func TestBuild_SectorRegionRelevantOutranksNonRelevant(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		groupIdx := attackdata.GroupTechniqueIndex()
		if len(groupIdx) == 0 {
			t.Skip("no embedded ATT&CK group data available")
		}
		var relevantGroup, relevantTech string
		for g, techs := range groupIdx {
			if len(techs) > 0 {
				relevantGroup, relevantTech = g, techs[0]
				break
			}
		}

		seedTechnique(t, pool, relevantTech, "Relevant Technique", "execution")
		seedTechnique(t, pool, "T9999", "Non-Relevant Technique", "execution")

		_, err := pool.Exec(context.Background(),
			`INSERT INTO threat_actor_profiles (name, aliases, sectors, regions, source)
			 VALUES ($1, '{}', $2, '{}', 'bundle')`,
			relevantGroup, []string{"government"})
		if err != nil {
			t.Fatalf("seed profile: %v", err)
		}

		recs, err := Build(context.Background(), pool, nil, attackpath.Summary{}, 20, []string{"government"}, nil)
		if err != nil {
			t.Fatalf("Build: %v", err)
		}

		relevantRank, nonRelevantRank := rankOf(recs, relevantTech), rankOf(recs, "T9999")
		if relevantRank == -1 || nonRelevantRank == -1 {
			t.Fatalf("expected both techniques ranked, got %+v", recs.Techniques)
		}
		if relevantRank >= nonRelevantRank {
			t.Errorf("sector-relevant technique (rank %d) did not outrank non-relevant one (rank %d)", relevantRank, nonRelevantRank)
		}
	})
}
```

This new test uses `attackdata.GroupTechniqueIndex()`, which `recommend_test.go` doesn't currently import — using Edit, replace:

```go
import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/attackpath"
	"github.com/audspect/bas/internal/testutil"
)
```

with:

```go
import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/attackpath"
	"github.com/audspect/bas/internal/reporting/attackdata"
	"github.com/audspect/bas/internal/testutil"
)
```

- [ ] **Step 5: Update `internal/api/recommend_handlers.go`**

In `orchestrator/internal/api/recommend_handlers.go`, using Edit, replace:

```go
	recs, err := recommend.Build(r.Context(), h.db, g, s, limit)
```

with:

```go
	var sectors, regions []string
	if h.reportingEngine != nil {
		sectors = h.reportingEngine.Sectors()
		regions = h.reportingEngine.Regions()
	}
	recs, err := recommend.Build(r.Context(), h.db, g, s, limit, sectors, regions)
```

- [ ] **Step 6: Run the full regression**

Run: `cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator && go build ./...`
Expected: clean build — this is the first point the entire repo builds again since Task 5.

Run: `cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator && go test ./internal/recommend/... -v`
Expected: all PASS, including the new `TestBuild_SectorRegionRelevantOutranksNonRelevant`.

Run: `cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator && go test ./internal/api/... -run TestGetRecommendedSimulations -v`
Expected: all PASS (pre-existing tests, unaffected — `h.reportingEngine` nil-safe fallback).

- [ ] **Step 7: Commit**

```bash
cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator
git add internal/recommend/recommend.go internal/recommend/recommend_test.go internal/api/recommend_handlers.go
git commit -m "feat(sp5): rank sector/region-relevant techniques higher in recommendations

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
git push
```

---

### Task 7: Full regression + capture

**Files:** none (verification + vault/memory).

- [ ] **Step 1: Full repo test suite**

Run: `cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator && go test ./...`
Expected: PASS across every package. If a package fails with a Docker connection error unrelated to this plan's changes, retry that package alone before treating it as a real failure — this environment has shown transient container-teardown flakes on long full-suite runs, unrelated to code correctness.

- [ ] **Step 2: Whole-build + vet + gofmt**

Run: `cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator && go build ./... && go vet ./...`
Expected: clean.

Run: `cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator && gofmt -l internal/db/postgres.go internal/connector/misp.go internal/connector/opencti.go internal/connector/misp_filter_test.go internal/connector/scheduler.go internal/connector/scheduler_test.go internal/connector/testmain_test.go internal/connector/generator.go internal/connector/generator_test.go internal/reporting/insights.go internal/reporting/insights_test.go internal/reporting/engine.go internal/recommend/recommend.go internal/recommend/recommend_test.go internal/api/recommend_handlers.go cmd/server/main.go`
Expected: no output. If anything is listed, `gofmt -w` it and commit as a dedicated `style:` commit.

- [ ] **Step 3: Update the vault (outside the git repo)**

The vault at `C:\Users\Administrator\Audspect-Vault` is NOT in the repo — update it directly, do not `git add` it.
- Create `04 Features/Sector-Region Weighting.md` (feature note: architecture, the config-field-reuse correction, the two bug findings and their resolutions, the offline-safety guarantee).
- Edit `11 Roadmaps/Roadmap.md`: mark SP5 fully complete (the sector/region weighting item was its last open piece).
- Append to the current daily note: this session's work.

- [ ] **Step 4: Update Claude memory**

Edit `C:\Users\Administrator\.claude\projects\C--Users-Administrator-Downloads-Audspect-Cloud\memory\project_platform_roadmap_2026h2.md`: mark SP5 fully complete. Update the `MEMORY.md` index line.

- [ ] **Step 5: Report completion**

Announce the feature is done, list the commits, and state plainly: this closes SP5 (Threat Intelligence Pipeline) entirely. Note explicitly what's still a known limitation, not a bug: OpenCTI actors never carry sector/region data (documented gap, not fixed); matching is exact-only (no fuzzy taxonomy normalization or alias fuzzy-matching); sector/region config remains global, not per-tenant.

---

## Self-Review

**Spec coverage:**
- Both scenario generation and priority scoring in scope → Tasks 4, 5, 6. ✓
- Reuse `config.Config.ThreatIntelSectors`/`ThreatIntelRegions`, no new env vars → Tasks 3, 4, 5 (`main.go` wiring threads existing `cfg` fields). ✓
- `threat_actor_profiles` table → Task 1. ✓
- MISP region-filter fix; OpenCTI documented gap → Task 2. ✓
- Exact (non-fuzzy) name/alias and sector/region matching → Task 5 (`normalizeActorName`, `sectorRegionOverlap`, no partial matching anywhere). ✓
- Scenario generation tag-only, not a filter → Task 4 (`buildYAML` only appends tags, `Write`'s `minTechniques` gate is untouched). ✓
- Fully additive/offline-safe → Task 5's early-return in `SectorRegionRelevantTechniques`, Task 4's `intersects(x, nil)` always-false behavior. ✓
- `ComputePriorityScore` +10 bonus, capped at 100 → Task 5. ✓
- `attackdata` untouched → confirmed no task modifies any file under `internal/reporting/attackdata/`. ✓
- Testing strategy (connector unit + Docker tests, reporting Docker tests, recommend ranking test) → Tasks 2, 3, 4, 5, 6. ✓
- Out-of-scope items (per-tenant, fuzzy matching, OpenCTI fix, new admin UI, pruning) → none touched by any task, restated in Task 7 Step 5's completion report. ✓

**Placeholder scan:** no TBD/TODO; every code step shows complete code, using `recommend_test.go`'s real existing helpers (`seedTechnique`, `rankOf`) verified by reading the file directly, not inferred.

**Type consistency:** `passesSectorRegionFilter` (Task 2) signature matches its one call site. `Scheduler.pool`/`NewScheduler`'s 5th param (Task 3) and `Generator.sectors/regions`/`NewGenerator`'s 2nd/3rd params (Task 4) are used identically in `scheduler_test.go`, `generator_test.go`, and `main.go`. `SectorRegionRelevantTechniques`/`ComputePriorityScore`'s new signatures (Task 5) match their call sites in `engine.go` (Task 5) and `recommend.go` (Task 6) exactly. `Engine.Sectors()`/`Regions()` (Task 5) match their use in `recommend_handlers.go` (Task 6).

**Task-ordering note:** Tasks 3 and 4 both change `internal/connector` constructor signatures that the same test/main files call — the plan explicitly calls out that the package won't build until both are done, and recommends completing them back-to-back before committing (Task 4's Step 6 commits both). Similarly, Task 5 leaves `internal/recommend` non-building until Task 6 updates its call site — explicitly noted in Task 5 Step 11 rather than presented as a surprise failure.
