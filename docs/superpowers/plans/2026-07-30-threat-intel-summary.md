# Threat Intel Summary Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a fleet-wide threat-intel posture summary (top prioritized actors + KEV exposure) that doesn't exist today, and surface it on the Operational dashboard's existing `dash-ti-section` widget.

**Architecture:** `internal/analytics.ThreatIntelSummary` takes `*threatpriority.Engine` as a parameter (unlike every prior category, which only needs `*pgxpool.Pool`) since the Engine is a pre-constructed, nilable instance already injected onto `Handler`. A new handler exposes it at `GET /api/analytics/threat-intel-summary`. The frontend's existing `loadKEVWidget()` calls it alongside the existing KEV pack call and renders a "Top Threat Actors" list using the tier-badge styling the standalone Threat Prioritization tab already uses.

**Tech Stack:** Go (`internal/analytics`, `internal/api`), `*threatpriority.Engine`, `*pgxpool.Pool`, vanilla JS/HTML (`orchestrator/wwwroot/index.html`).

## Global Constraints

- `internal/threatgraph` and `internal/intelligence` are out of scope — confirmed genuinely irrelevant/unintegrated, not touched by any task here.
- No new field on `dashboard.Snapshot` / no change to `GET /api/dashboard/current` or the Executive dashboard.
- No changes to `GetSuggestPack`/`kevPackTechs` or the pack-generation feature — only a new, separate, minimal query for summary counts.
- `tpEngine == nil` must never error — `TopActors` comes back empty, matching the existing "nil when not loaded" contract `h.threatPriorityEngine` already follows everywhere else.
- Frontend verification: a Node syntax check that every inline `<script>` block still parses, plus DOM id-uniqueness checks — no automated test harness exists for this file (matching Sub-project B's convention).
- Every task ends with a commit + `git push`.

---

### Task 1: `internal/analytics.ThreatIntelSummary`

**Files:**
- Create: `orchestrator/internal/analytics/threatintel.go`
- Test: `orchestrator/internal/analytics/threatintel_test.go`

**Interfaces:**
- Consumes: `threatpriority.Engine.ScoreAll(ctx) ([]ActorPriority, error)` (`internal/threatpriority/engine.go:274`, already sorted score descending), `threatpriority.NewEngine(pool, scenarioEngine, sectors, regions)` (test-only), `scenario.NewEngine(dir)` (test-only).
- Produces: `type ThreatIntelSummary struct { TopActors []threatpriority.ActorPriority; KEVExposedTechniques int; TotalKEVCVEs int }`, `func ThreatIntelSummary(ctx context.Context, pool *pgxpool.Pool, tpEngine *threatpriority.Engine) (ThreatIntelSummary, error)`. Task 2's handler calls this directly.

- [x] **Step 1: Write the failing tests**

Create `orchestrator/internal/analytics/threatintel_test.go`:

```go
package analytics

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/threatpriority"
)

func TestThreatIntelSummary_NilEngine_ReturnsEmptyActors(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		got, err := ThreatIntelSummary(context.Background(), pool, nil)
		if err != nil {
			t.Fatalf("ThreatIntelSummary: %v", err)
		}
		if len(got.TopActors) != 0 {
			t.Errorf("TopActors = %+v, want empty when tpEngine is nil", got.TopActors)
		}
	})
}

func TestThreatIntelSummary_TopActorsClampedToFive(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		names := []string{"Actor A", "Actor B", "Actor C", "Actor D", "Actor E", "Actor F"}
		for _, n := range names {
			mustExec(t, pool, `
				INSERT INTO threat_actor_profiles (name, aliases, sectors, regions, confidence)
				VALUES ($1, '{}', '{}', '{}', 'medium')`, n)
		}
		eng := threatpriority.NewEngine(pool, scenario.NewEngine(t.TempDir()), nil, nil)

		got, err := ThreatIntelSummary(context.Background(), pool, eng)
		if err != nil {
			t.Fatalf("ThreatIntelSummary: %v", err)
		}
		if len(got.TopActors) != 5 {
			t.Errorf("TopActors = %d actors, want exactly 5 (clamped from 6 seeded profiles)", len(got.TopActors))
		}
	})
}

func TestThreatIntelSummary_FewerThanFiveActors_ReturnsAll(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExec(t, pool, `
			INSERT INTO threat_actor_profiles (name, aliases, sectors, regions, confidence)
			VALUES ('Solo Actor', '{}', '{}', '{}', 'high')`)
		eng := threatpriority.NewEngine(pool, scenario.NewEngine(t.TempDir()), nil, nil)

		got, err := ThreatIntelSummary(context.Background(), pool, eng)
		if err != nil {
			t.Fatalf("ThreatIntelSummary: %v", err)
		}
		if len(got.TopActors) != 1 {
			t.Errorf("TopActors = %d actors, want 1 (only 1 profile seeded)", len(got.TopActors))
		}
	})
}

func TestThreatIntelSummary_KEVCounts(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExec(t, pool, `INSERT INTO techniques (technique_id, name, tactic) VALUES ('T1059', 'Command and Scripting Interpreter', 'execution')`)
		mustExec(t, pool, `INSERT INTO art_atomic_tests (technique_id, test_index, name, executor, command) VALUES ('T1059', 1, 'Test 1', 'powershell', 'whoami')`)
		mustExec(t, pool, `INSERT INTO cves (cve_id, source, known_ransomware) VALUES ('CVE-2024-0001', 'cisa-kev', false)`)
		mustExec(t, pool, `INSERT INTO cves (cve_id, source, known_ransomware) VALUES ('CVE-2024-0002', 'cisa-kev', false)`)
		mustExec(t, pool, `INSERT INTO technique_cves (technique_id, cve_id) VALUES ('T1059', 'CVE-2024-0001')`)
		mustExec(t, pool, `INSERT INTO technique_cves (technique_id, cve_id) VALUES ('T1059', 'CVE-2024-0002')`)

		got, err := ThreatIntelSummary(context.Background(), pool, nil)
		if err != nil {
			t.Fatalf("ThreatIntelSummary: %v", err)
		}
		if got.KEVExposedTechniques != 1 {
			t.Errorf("KEVExposedTechniques = %d, want 1 (one technique, two CVEs)", got.KEVExposedTechniques)
		}
		if got.TotalKEVCVEs != 2 {
			t.Errorf("TotalKEVCVEs = %d, want 2", got.TotalKEVCVEs)
		}
	})
}
```

`sharedDB`/`mustExec` are already declared in `internal/analytics/risk_test.go` (Sub-project A) — shared across every test file in this package.

- [x] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/analytics/... -run TestThreatIntelSummary -v`
Expected: FAIL — `undefined: ThreatIntelSummary` (compile error).

- [x] **Step 3: Implement `ThreatIntelSummary`**

Create `orchestrator/internal/analytics/threatintel.go`:

```go
package analytics

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/threatpriority"
)

// ThreatIntelSummary is the fleet-wide threat-intel posture: the most
// urgent actors to validate against, plus exposure to actively-exploited
// (CISA KEV) vulnerabilities.
type ThreatIntelSummary struct {
	TopActors            []threatpriority.ActorPriority `json:"topActors"`
	KEVExposedTechniques int                             `json:"kevExposedTechniques"`
	TotalKEVCVEs         int                              `json:"totalKevCves"`
}

// ThreatIntelSummary computes the fleet-wide threat-intel posture.
// tpEngine may be nil (threat prioritization not configured) -- TopActors
// comes back empty rather than erroring, matching the "nil when not
// loaded" contract h.threatPriorityEngine already follows elsewhere.
func ThreatIntelSummary(ctx context.Context, pool *pgxpool.Pool, tpEngine *threatpriority.Engine) (ThreatIntelSummary, error) {
	var topActors []threatpriority.ActorPriority
	if tpEngine != nil {
		all, err := tpEngine.ScoreAll(ctx)
		if err != nil {
			return ThreatIntelSummary{}, err
		}
		if len(all) > 5 {
			all = all[:5]
		}
		topActors = all
	}

	var kevTechCount, kevCveCount int
	err := pool.QueryRow(ctx, `
		SELECT COUNT(DISTINCT tc.technique_id), COUNT(*)
		FROM technique_cves tc
		JOIN cves c ON c.cve_id = tc.cve_id AND c.source = 'cisa-kev'
		WHERE EXISTS (SELECT 1 FROM art_atomic_tests a WHERE a.technique_id = tc.technique_id)`,
	).Scan(&kevTechCount, &kevCveCount)
	if err != nil {
		return ThreatIntelSummary{}, err
	}

	return ThreatIntelSummary{
		TopActors:            topActors,
		KEVExposedTechniques: kevTechCount,
		TotalKEVCVEs:         kevCveCount,
	}, nil
}
```

- [x] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go build ./... && go test ./internal/analytics/... -run TestThreatIntelSummary -v`
Expected: build succeeds; all 4 tests PASS.

- [x] **Step 5: Commit**

```bash
git add orchestrator/internal/analytics/threatintel.go orchestrator/internal/analytics/threatintel_test.go
git commit -m "feat(analytics): add ThreatIntelSummary (top prioritized actors + KEV exposure)

Fills a genuine gap -- neither threatpriority.Engine.ScoreAll() nor any
KEV-exposure count has ever been surfaced on a dashboard. Takes
*threatpriority.Engine as a parameter (nilable) rather than a bare pool,
since the Engine is a pre-constructed instance carrying its own
sectors/regions config, unlike every prior analytics category."
git push
```

---

### Task 2: `GET /api/analytics/threat-intel-summary`

**Files:**
- Modify: `orchestrator/internal/api/ti_handlers.go` (new handler, appended)
- Modify: `orchestrator/internal/api/routes.go:197-198` (route registration)
- Test: `orchestrator/internal/api/threatintel_summary_handler_test.go` (new)

**Interfaces:**
- Consumes: `analytics.ThreatIntelSummary` (Task 1), `h.db`, `h.threatPriorityEngine` (`internal/api/handlers.go:93`).
- Produces: nothing new for later tasks — Task 3 calls this route directly from JS, not any Go symbol.

- [x] **Step 1: Write the failing test**

Create `orchestrator/internal/api/threatintel_summary_handler_test.go`:

```go
package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

type threatIntelSummaryResponse struct {
	TopActors            []map[string]any `json:"topActors"`
	KEVExposedTechniques int              `json:"kevExposedTechniques"`
	TotalKEVCVEs         int              `json:"totalKevCves"`
}

func TestGetThreatIntelSummary_NoEngineConfigured_ReturnsEmptyActors(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		rec := httptest.NewRecorder()
		h.GetThreatIntelSummary(rec, httptest.NewRequest(http.MethodGet, "/api/analytics/threat-intel-summary", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body: %s", rec.Code, rec.Body.String())
		}
		var got threatIntelSummaryResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatalf("unmarshal response: %v", err)
		}
		if len(got.TopActors) != 0 {
			t.Errorf("TopActors = %+v, want empty -- New() doesn't wire threatPriorityEngine by default in this test helper", got.TopActors)
		}
	})
}
```

`sharedDB` is already declared in `internal/api`'s existing test suite. This test confirms the handler doesn't panic or error when `h.threatPriorityEngine` is nil (its default state from `New()`, confirmed by reading `internal/api/handlers.go` — nothing in the existing constructor sets it).

- [x] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/api/... -run TestGetThreatIntelSummary -v`
Expected: FAIL — `h.GetThreatIntelSummary undefined` (compile error).

- [x] **Step 3: Implement the handler**

In `orchestrator/internal/api/ti_handlers.go`, find:

```go
	"github.com/audspect/bas/internal/reporting"
	"github.com/audspect/bas/internal/reporting/attackdata"
)
```

Replace with:

```go
	"github.com/audspect/bas/internal/analytics"
	"github.com/audspect/bas/internal/reporting"
	"github.com/audspect/bas/internal/reporting/attackdata"
)
```

Then append this new function at the end of the file:

```go
// GET /api/analytics/threat-intel-summary — fleet-wide threat-intel posture:
// top prioritized actors plus CISA KEV exposure. Viewer+.
func (h *Handler) GetThreatIntelSummary(w http.ResponseWriter, r *http.Request) {
	result, err := analytics.ThreatIntelSummary(r.Context(), h.db, h.threatPriorityEngine)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respond(w, result)
}
```

- [x] **Step 4: Register the route**

In `orchestrator/internal/api/routes.go`, find:

```go
		r.Get("/api/threat-priority/actors", h.ThreatPriorityActors)
		r.Get("/api/threat-priority/actors/{name}", h.ThreatPriorityActorDetail)
```

Replace with:

```go
		r.Get("/api/threat-priority/actors", h.ThreatPriorityActors)
		r.Get("/api/threat-priority/actors/{name}", h.ThreatPriorityActorDetail)

		// Threat Intel Summary -- fleet-wide posture combining the above
		// per-actor scoring with KEV exposure, for dashboard consumption.
		r.Get("/api/analytics/threat-intel-summary", h.GetThreatIntelSummary)
```

- [x] **Step 5: Run tests to verify they pass**

Run: `cd orchestrator && go build ./... && go vet ./... && go test ./internal/api/... -run TestGetThreatIntelSummary -v`
Expected: build and vet clean; test PASSES.

- [x] **Step 6: Commit**

```bash
git add orchestrator/internal/api/ti_handlers.go orchestrator/internal/api/routes.go orchestrator/internal/api/threatintel_summary_handler_test.go
git commit -m "feat(api): add GET /api/analytics/threat-intel-summary"
git push
```

---

### Task 3: Wire the summary into the dashboard's existing KEV widget

**Files:**
- Modify: `orchestrator/wwwroot/index.html` (HTML: `dash-ti-section`; JS: `loadKEVWidget()`, new `renderTIActors()`)

**Interfaces:**
- Consumes: `GET /api/analytics/threat-intel-summary` (Task 2), `tpTierBadge(tier)` (`index.html:4834-4837`, existing), `showTab`/`showThreatPriorityDetail` (existing, for click-through).
- Produces: `function renderTIActors(actors)`, a new `#dash-ti-actors` container.

- [x] **Step 1: Add the `#dash-ti-actors` container**

Find:

```html
          <div class="kpi-row" id="dash-ti-tiles"></div>
        </div>
```

Replace with:

```html
          <div class="kpi-row" id="dash-ti-tiles"></div>
          <div id="dash-ti-actors"></div>
        </div>
```

- [x] **Step 2: Extend `loadKEVWidget()` and add `renderTIActors()`**

Find:

```js
function loadKEVWidget() {
  if (_kevWidgetLoaded) return;
  apicall('/api/ti/suggest-pack?type=kev').then(function(pack) {
    if (!pack || !pack.hasData) return;
    _kevWidgetLoaded = true;
    document.getElementById('dash-ti-section').style.display = '';
    var tiles = document.getElementById('dash-ti-tiles');
    tiles.innerHTML =
      '<div class="kpi-card stat-tile" title="Techniques with CISA KEV CVEs — create a pack to validate them">' +
      '<div class="stat-top"><div><div class="kpi-label">KEV-Linked Techniques</div><div class="kpi-value" style="color:var(--danger)">' + pack.techniqueCount + '</div></div>' +
      '<div class="stat-icon" style="background:rgba(218,54,51,0.10);color:var(--danger)">&#9760;</div></div>' +
      '<div class="kpi-sub">' + (pack.totalKevCves||0) + ' CVEs · ' + (pack.ransomwareCount||0) + ' ransomware-linked</div></div>' +
      '<div class="kpi-card stat-tile" title="CISA Known Exploited Vulnerabilities under active real-world exploitation">' +
      '<div class="stat-top"><div><div class="kpi-label">Total KEV CVEs</div><div class="kpi-value" style="color:var(--warning)">' + (pack.totalKevCves||0) + '</div></div>' +
      '<div class="stat-icon" style="background:rgba(210,153,34,0.10);color:var(--warning)"><svg width="16" height="16" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4"><path d="M8 2l1.5 3.5H13l-2.75 2 1 3.5L8 9 4.75 11l1-3.5L3 5.5h3.5z"/></svg></div></div>' +
      '<div class="kpi-sub">from CISA KEV catalog</div></div>';
  }).catch(function() {});
}
```

Replace with:

```js
function loadKEVWidget() {
  if (_kevWidgetLoaded) return;
  Promise.all([
    apicall('/api/ti/suggest-pack?type=kev').catch(function() { return null; }),
    apicall('/api/analytics/threat-intel-summary').catch(function() { return null; })
  ]).then(function(res) {
    var pack = res[0];
    var summary = res[1];
    var hasKev = pack && pack.hasData;
    var actors = (summary && summary.topActors) || [];
    if (!hasKev && !actors.length) return;
    _kevWidgetLoaded = true;
    document.getElementById('dash-ti-section').style.display = '';
    var tiles = document.getElementById('dash-ti-tiles');
    tiles.innerHTML = hasKev ?
      '<div class="kpi-card stat-tile" title="Techniques with CISA KEV CVEs — create a pack to validate them">' +
      '<div class="stat-top"><div><div class="kpi-label">KEV-Linked Techniques</div><div class="kpi-value" style="color:var(--danger)">' + pack.techniqueCount + '</div></div>' +
      '<div class="stat-icon" style="background:rgba(218,54,51,0.10);color:var(--danger)">&#9760;</div></div>' +
      '<div class="kpi-sub">' + (pack.totalKevCves||0) + ' CVEs · ' + (pack.ransomwareCount||0) + ' ransomware-linked</div></div>' +
      '<div class="kpi-card stat-tile" title="CISA Known Exploited Vulnerabilities under active real-world exploitation">' +
      '<div class="stat-top"><div><div class="kpi-label">Total KEV CVEs</div><div class="kpi-value" style="color:var(--warning)">' + (pack.totalKevCves||0) + '</div></div>' +
      '<div class="stat-icon" style="background:rgba(210,153,34,0.10);color:var(--warning)"><svg width="16" height="16" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4"><path d="M8 2l1.5 3.5H13l-2.75 2 1 3.5L8 9 4.75 11l1-3.5L3 5.5h3.5z"/></svg></div></div>' +
      '<div class="kpi-sub">from CISA KEV catalog</div></div>' : '';
    renderTIActors(actors);
  });
}

// renderTIActors shows the fleet's top-priority threat actors below the KEV
// tiles, reusing tpTierBadge (index.html:4834) for the same tier coloring
// the standalone Threat Prioritization tab already uses. Clicking an actor
// jumps to its detail view there rather than duplicating it here.
function renderTIActors(actors) {
  var el = document.getElementById('dash-ti-actors');
  if (!el) return;
  if (!actors.length) { el.innerHTML = ''; return; }
  el.innerHTML =
    '<div style="font-size:0.68rem;font-weight:600;letter-spacing:0.05em;color:var(--muted);text-transform:uppercase;margin:0.75rem 0 0.4rem">Top Threat Actors</div>' +
    actors.map(function(a) {
      return '<div style="display:flex;justify-content:space-between;align-items:center;padding:0.35rem 0;border-bottom:1px solid var(--border)">' +
        '<span style="font-weight:600;cursor:pointer" onclick="showTab(\'threat-priority\');setTimeout(function(){ showThreatPriorityDetail(' + JSON.stringify(a.actorName) + '); }, 150)">' + x(a.actorName) + '</span>' +
        '<span style="display:flex;align-items:center;gap:0.5rem">' + tpTierBadge(a.tier) + '<strong>' + x(a.score) + '</strong></span>' +
        '</div>';
    }).join('');
}
```

`x()` is the existing HTML-escaping helper used throughout this file. The `hasKev ? ... : ''` ternary means the KEV tiles disappear (rather than show stale/wrong data) on a day with zero KEV-linked techniques while actors still render — the two halves of the widget are now independent, matching the parallel `Promise.all` fetch. This is a deliberate, minor behavior change from today (previously the whole widget only ever showed with KEV data present) — call it out to the user during manual QA.

- [x] **Step 3: Verify — syntax check**

Run from the repo root:

```bash
node -e "
const fs = require('fs');
const html = fs.readFileSync('orchestrator/wwwroot/index.html', 'utf8');
const scripts = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)].map(m => m[1]);
scripts.forEach((s, i) => { try { new Function(s); } catch (e) { console.error('Script block ' + i + ' failed:', e.message); process.exit(1); } });
console.log('All script blocks parse OK');
"
```

Expected: `All script blocks parse OK`.

- [x] **Step 4: Verify — id uniqueness**

Run:

```bash
node -e "
const fs = require('fs');
const html = fs.readFileSync('orchestrator/wwwroot/index.html', 'utf8');
['dash-ti-actors'].forEach(id => {
  const n = (html.match(new RegExp('id=\"' + id + '\"', 'g')) || []).length;
  console.log(id + ': ' + n);
});
"
```

Expected: `dash-ti-actors: 1`.

- [x] **Step 5: Commit**

```bash
git add orchestrator/wwwroot/index.html
git commit -m "feat(dashboard): show top threat actors alongside the existing KEV widget

loadKEVWidget() now fetches /api/analytics/threat-intel-summary
alongside the existing KEV pack call and renders a Top Threat Actors
list, reusing tpTierBadge for the same tier coloring the standalone
Threat Prioritization tab already uses. The two halves of the widget
are independent -- either can render with data while the other is
empty, a minor behavior change from today's KEV-data-only gate."
git push
```

---

### Task 4: Full regression

**Files:** none (verification only)

- [x] **Step 1: Confirm Docker is running**

Run: `docker info 2>&1 | grep -iE "server|error"`
Expected: a `Server:` block with no error. If down, start Docker Desktop and poll until ready:

```bash
timeout 180 bash -c 'until docker info >/dev/null 2>&1; do sleep 5; done' && echo "DOCKER_READY"
```

- [x] **Step 2: Run the full Go test suite**

Run: `cd orchestrator && go build ./... && go vet ./... && go test ./... -count=1`
Expected: `go build`/`go vet` clean, every package `ok`.

- [x] **Step 3: Report completion**

Executes directly on `main`, no branch/worktree/PR decision needed. Confirm with the user that Sub-project D is complete, and that Sub-project E (Endpoint Posture) is the last remaining sub-project.

---

## Execution Notes

All 4 tasks completed and pushed (`09730a3`, `6259604`, `38dac37`, plus `ed1c316` — a real bug caught during Task 4 regression, see below).

**Real bugs found during execution (not anticipated by the plan):**

1. **Task 1 — `ThreatIntelSummary` type/function name collision.** The plan's own code sample named both the returned struct type and the computing function `ThreatIntelSummary`, which Go rejects (`ThreatIntelSummary redeclared in this block`). Fixed by renaming the type to `ThreatIntelPosture`; the function keeps the plan's name since all downstream call sites use the function, not the type, by name.
2. **Task 3 — stray unmatched `</div>` in `renderTIActors`.** Self-caught by re-reading the just-written code before running the syntax-check step, not by a tool. Fixed in both `index.html` and this plan's Step 2 code sample.
3. **Task 4 — missing RBAC matrix entry.** `TestRBACMatrix_NoDrift` failed: `registered route "GET /api/analytics/threat-intel-summary" has no routeMatrix entry`. The plan didn't anticipate this drift-detection test. Fixed by adding `{http.MethodGet, "/api/analytics/threat-intel-summary", tierAny, ""}` to `internal/api/rbac_matrix_test.go`, matching every other read-only analytics endpoint. Committed separately as `ed1c316`.

**Task 4 regression — two interrupted/misleading runs before a clean one:**
- First full-suite attempt was interrupted by a user "pause" mid-run (background task came back `status: stopped`, no completion record, empty output file) — re-launched from scratch rather than trusting any partial state.
- Second attempt completed but every DB-backed package failed identically with `rootless Docker is not supported on Windows` — Docker Desktop was down when the run executed even though it had been polled ready earlier in the session. Confirmed via `docker info`, restarted, and re-ran a third time.
- Third attempt: only `internal/api` failed, with `panic: test timed out after 10m0s` at 656s under full-suite load — the same timeout artifact documented in Sub-project A's Task 8 (not a real regression). Confirmed clean by running `internal/api` alone with `-timeout 20m`: `ok  	github.com/audspect/bas/internal/api	515.230s`. Full suite is clean.

Sub-project D (Threat Intel Summary) is complete. Sub-project E (Endpoint Posture) is the last remaining sub-project of the Unified Analytics Layer initiative.
