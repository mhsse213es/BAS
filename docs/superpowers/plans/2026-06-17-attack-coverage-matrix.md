# ATT&CK Coverage Matrix Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans (inline; no subagents per user preference). Steps use checkbox (`- [ ]`) syntax.

**Goal:** Add an "ATT&CK Coverage" page mirroring the `audspect.html` mockup — the full enterprise matrix (14 tactics × all techniques) coloured by our *validated* control results (Prevented / Detected / Missed / Untested), with a filter toolbar, per-tactic counts, and a click-through technique detail drawer.

**Architecture:** A small read-only backend exposes the authoritative matrix structure and per-technique enrichment from the bundled ATT&CK data (`internal/reporting/attackdata`, 656 techniques each carrying `id`/`name`/`tactics`). The frontend overlays our coverage by reusing the run-results + `detectedTechs` aggregation already built for the dashboard donut — each technique's *most-recent* verdict decides its colour; everything untouched is Untested. No new data is fabricated; the matrix is authoritative and the overlay is real.

**Tech Stack:** Go (chi, embedded JSON via `attackdata`), vanilla JS matrix view in `orchestrator/wwwroot/index.html`.

**Mockup reference:** `audspect.html` `PAGES.matrix` (line ~1073). Status taxonomy maps 1:1 to our donut split (prevented/detected/missed/not-tested).

---

## Key facts (verified)

- `internal/reporting/attackdata/attack_enrichment.json` holds **656 techniques**, each with `id`, `name`, `tactics` (slug array), plus platforms/groups/mitigations/dataSources. Loaded once into `data map[string]*Enrichment`; only `Lookup(id)` is exported today.
- No matrix/coverage/tactics API exists yet. `/api/art/techniques` is the ART catalog (a subset), not the matrix.
- Enterprise tactic order (14, kill-chain order) — bake as a canonical slug→name list in the handler:
  reconnaissance, resource-development, initial-access, execution, persistence, privilege-escalation, defense-evasion, credential-access, discovery, lateral-movement, collection, command-and-control, exfiltration, impact.
- A technique may list multiple tactics → it appears under each (matches ATT&CK Navigator).
- Coverage overlay source: `GET /api/scenarios/runs` already returns `results` + per-run `detectedTechs` (added in the dashboard donut task). Reuse the same classification.
- Frontend: `showTab(name)` array + `TAB_TITLES`; nav groups Operations/Visibility; helpers `apicall`, `x`, `showToast`; the results-drawer overlay (`results-overlay`) is reusable for the technique detail.

---

## File Structure

| File | Responsibility | Change |
|---|---|---|
| `orchestrator/internal/reporting/attackdata/attackdata.go` | export the full technique list | Modify (add `All()`) |
| `orchestrator/internal/api/attack_handlers.go` | matrix + technique-detail handlers | Create |
| `orchestrator/internal/api/routes.go` | register 2 read routes | Modify |
| `orchestrator/wwwroot/index.html` | nav + Coverage tab + matrix + filter + detail drawer + CSS | Modify |

Frontend validation after each FE task:
```
node -e "const fs=require('fs');const h=fs.readFileSync('orchestrator/wwwroot/index.html','utf8');const m=h.match(/<script>([\s\S]*)<\/script>/);new Function(m[1]);console.log('OK');"
```

---

## Part A — Backend (matrix + technique APIs)

### Task A1: expose the technique list from attackdata

**Files:** Modify `orchestrator/internal/reporting/attackdata/attackdata.go`

- [ ] **Step 1:** Add an exported accessor (after `Lookup`):

```go
// TechniqueRef is the minimal matrix projection of a technique.
type TechniqueRef struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Tactics []string `json:"tactics"`
}

// All returns every loaded technique (authoritative ATT&CK set), id-sorted.
// Used to build the coverage matrix; coverage status is overlaid by the caller.
func All() []TechniqueRef {
	once.Do(load)
	out := make([]TechniqueRef, 0, len(data))
	for _, e := range data {
		if e == nil || e.TechniqueID == "" || e.Name == "" {
			continue
		}
		out = append(out, TechniqueRef{ID: e.TechniqueID, Name: e.Name, Tactics: e.Tactics})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
```
(add `"sort"` to imports if absent)

- [ ] **Step 2:** Build: `cd orchestrator && go build ./...` → clean.
- [ ] **Step 3:** Commit: `feat(attackdata): export All() technique list for the coverage matrix`.

### Task A2: matrix + technique-detail endpoints

**Files:** Create `orchestrator/internal/api/attack_handlers.go`; modify `orchestrator/internal/api/routes.go`

- [ ] **Step 1: Handlers** `attack_handlers.go`:

```go
package api

import (
	"net/http"

	"github.com/audspect/bas/internal/reporting/attackdata"
	"github.com/go-chi/chi/v5"
)

// enterpriseTactics is the canonical kill-chain ordering + display names.
var enterpriseTactics = []struct{ ID, Name string }{
	{"reconnaissance", "Reconnaissance"}, {"resource-development", "Resource Development"},
	{"initial-access", "Initial Access"}, {"execution", "Execution"},
	{"persistence", "Persistence"}, {"privilege-escalation", "Privilege Escalation"},
	{"defense-evasion", "Defense Evasion"}, {"credential-access", "Credential Access"},
	{"discovery", "Discovery"}, {"lateral-movement", "Lateral Movement"},
	{"collection", "Collection"}, {"command-and-control", "Command and Control"},
	{"exfiltration", "Exfiltration"}, {"impact", "Impact"},
}

// GET /api/attack/matrix — authoritative enterprise matrix: tactics (kill-chain
// order) each with their techniques {id,name}. Coverage status is overlaid by
// the client from run data (kept out of here so the structure stays cacheable).
func (h *Handler) AttackMatrix(w http.ResponseWriter, r *http.Request) {
	byTactic := map[string][]map[string]string{}
	for _, t := range attackdata.All() {
		for _, tac := range t.Tactics {
			byTactic[tac] = append(byTactic[tac], map[string]string{"id": t.ID, "name": t.Name})
		}
	}
	tactics := make([]map[string]any, 0, len(enterpriseTactics))
	for _, tac := range enterpriseTactics {
		techs := byTactic[tac.ID]
		if techs == nil {
			techs = []map[string]string{}
		}
		tactics = append(tactics, map[string]any{"id": tac.ID, "name": tac.Name, "techniques": techs})
	}
	respond(w, map[string]any{"tactics": tactics})
}

// GET /api/attack/technique/{id} — authoritative enrichment for one technique.
func (h *Handler) AttackTechnique(w http.ResponseWriter, r *http.Request) {
	e := attackdata.Lookup(chi.URLParam(r, "id"))
	if e == nil {
		jsonError(w, "technique not found", http.StatusNotFound)
		return
	}
	respond(w, e)
}
```

- [ ] **Step 2: Routes** in the outer authed read group (near `/api/art/techniques`):

```go
		r.Get("/api/attack/matrix", h.AttackMatrix)
		r.Get("/api/attack/technique/{id}", h.AttackTechnique)
```

- [ ] **Step 3:** Build + vet + test: `cd orchestrator && go build ./... && go vet ./internal/api/ && go test ./internal/api/`.
- [ ] **Step 4:** Commit: `feat(api): ATT&CK matrix + technique-detail endpoints`.

---

## Part B — Frontend (`orchestrator/wwwroot/index.html`)

### Task B1: nav + tab scaffold + matrix CSS

- [ ] **Step 1: Nav item** in the Operations group (after Campaigns):

```html
        <div class="nav-item" data-tab="coverage" onclick="showTab('coverage')">
          <svg class="nav-icon" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4"><circle cx="8" cy="8" r="6"/><circle cx="8" cy="8" r="2.4"/></svg>
          Coverage
        </div>
```

- [ ] **Step 2:** Register in `showTab` array (`...,'campaigns','coverage',...`), add `if (name === 'coverage') loadCoverage();`, and `TAB_TITLES` entry `coverage: 'ATT&CK Coverage'`.

- [ ] **Step 3: Tab markup** after `#tab-campaigns`:

```html
      <div id="tab-coverage" style="display:none">
        <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:1rem;margin-bottom:1rem;flex-wrap:wrap">
          <div>
            <h1 style="font-family:var(--font-display);font-size:1.5rem;font-weight:700;letter-spacing:-0.02em;margin:0 0 0.3rem;color:var(--text)">MITRE ATT&amp;CK Coverage</h1>
            <div style="font-size:0.8rem;color:var(--muted)">Enterprise matrix coloured by your validated control effectiveness — last result per technique, not theoretical inventory.</div>
          </div>
          <div style="display:flex;gap:0.5rem;flex-shrink:0">
            <button class="btn btn-outline btn-sm dash-soon" style="position:relative" title="ATT&CK Navigator export — coming soon">Export layer</button>
            <button class="btn btn-primary btn-sm" onclick="openModal()">&#9654; Test coverage gaps</button>
          </div>
        </div>
        <div id="cov-toolbar" style="display:flex;align-items:center;gap:0.75rem;margin-bottom:0.9rem;flex-wrap:wrap"></div>
        <div class="dash-panel"><div class="dash-panel-body" id="cov-matrix" style="overflow-x:auto;padding:0.75rem"><div class="empty" style="padding:2rem">Loading matrix…</div></div></div>
        <div class="tiny muted" id="cov-foot" style="margin-top:0.75rem"></div>
      </div>
```

- [ ] **Step 4: CSS** (near the dashboard primitives):

```css
.mx { display:flex; gap:7px; min-width:max-content; align-items:flex-start; }
.mx-col { width:150px; flex-shrink:0; }
.mx-col-h { font-size:0.66rem; padding:0.4rem 0.5rem; border-bottom:2px solid var(--border); margin-bottom:0.4rem; }
.mx-col-h .tac-name { font-weight:600; color:var(--text); }
.mx-col-h .tac-cnt { color:var(--muted); margin-top:0.15rem; }
.mx-cell { position:relative; font-size:0.6rem; line-height:1.25; padding:0.3rem 0.4rem; margin-bottom:3px; border-radius:4px; border:1px solid var(--border); cursor:pointer; background:var(--elevated); transition:opacity .12s; }
.mx-cell .mc-id { display:block; font-family:var(--font-mono); font-size:0.56rem; color:var(--muted); }
.mx-cell.cov  { border-left:3px solid var(--success); }
.mx-cell.part { border-left:3px solid var(--warning); }
.mx-cell.gap  { border-left:3px solid var(--danger); }
.mx-cell.none { border-left:3px solid var(--border); opacity:0.7; }
.cov-seg { display:inline-flex; border:1px solid var(--border); border-radius:var(--radius); overflow:hidden; }
.cov-seg button { background:var(--surface); color:var(--muted); border:none; padding:0.3rem 0.7rem; font-size:0.72rem; cursor:pointer; font-family:inherit; }
.cov-seg button.on { background:var(--accent); color:#fff; }
```

- [ ] **Step 5:** Validate (node) + commit: `feat(coverage): ATT&CK Coverage nav, tab scaffold, matrix CSS`.

### Task B2: render the matrix + per-tactic counts

- [ ] **Step 1:** Add `var COV_VIEW='all';` and `loadCoverage()` (near `loadDashboard`):

```js
function covStatusMap(runs) {
  // most-recent verdict per technique → cov | part | gap (runs are newest-first)
  var st = {};
  (runs || []).forEach(function(r) {
    var det = r.detectedTechs || {};
    (r.results || []).forEach(function(c) {
      var id = c.technique && c.technique.id; if (!id || st[id]) return;
      if (c.result === 'pass' || c.result === 'blocked') st[id] = 'cov';
      else if (c.result === 'fail') st[id] = det[id] ? 'part' : 'gap';
    });
  });
  return st;
}
function loadCoverage() {
  Promise.all([apicall('/api/attack/matrix'), apicall('/api/scenarios/runs')]).then(function(res) {
    var tactics = (res[0] && res[0].tactics) || [], st = covStatusMap(res[1] || []);
    var counts = { cov:0, part:0, gap:0, none:0, total:0 }, seen = {};
    tactics.forEach(function(t) { (t.techniques||[]).forEach(function(x) {
      if (seen[x.id]) return; seen[x.id] = true; var s = st[x.id] || 'none'; counts[s]++; counts.total++;
    }); });
    window._covCounts = counts; window._covTactics = tactics; window._covSt = st;
    renderCovToolbar(); renderCovMatrix();
    document.getElementById('cov-foot').textContent = 'Showing ' + counts.total + ' techniques across ' + tactics.length + ' tactics · coverage = last validated result per technique.';
  }).catch(function(e) { document.getElementById('cov-matrix').innerHTML = '<div class="empty" style="padding:2rem">'+x(e.message)+'</div>'; });
}
function renderCovMatrix() {
  var st = window._covSt || {}, view = COV_VIEW;
  document.getElementById('cov-matrix').innerHTML = '<div class="mx">' + (window._covTactics||[]).map(function(t) {
    var techs = t.techniques || [], cov = techs.filter(function(x){ return st[x.id]==='cov'; }).length;
    var cells = techs.map(function(c) {
      var s = st[c.id] || 'none', dim = view !== 'all' && view !== s;
      return '<div class="mx-cell ' + s + '" onclick="openTechnique(\'' + x(c.id) + '\')" style="' + (dim?'opacity:.15':'') + '">' +
        '<span class="mc-id">' + x(c.id) + '</span>' + x(c.name) + '</div>';
    }).join('');
    return '<div class="mx-col"><div class="mx-col-h"><div class="tac-name">' + x(t.name) + '</div><div class="tac-cnt">' + cov + '/' + techs.length + ' prevented</div></div>' + cells + '</div>';
  }).join('') + '</div>';
}
```

- [ ] **Step 2:** Validate + commit: `feat(coverage): render enterprise matrix with per-technique coverage`.

### Task B3: filter toolbar + counts

- [ ] **Step 1:** Add `renderCovToolbar()` (segmented filter + count badges):

```js
function renderCovToolbar() {
  var c = window._covCounts || { cov:0, part:0, gap:0, none:0 };
  var seg = [['all','All'],['cov','Prevented'],['part','Detected'],['gap','Missed'],['none','Untested']]
    .map(function(o){ return '<button class="' + (COV_VIEW===o[0]?'on':'') + '" onclick="setCovView(\'' + o[0] + '\')">' + o[1] + '</button>'; }).join('');
  var badge = function(col,l,v){ return '<span class="sbadge" style="background:transparent;border:1px solid var(--border);color:'+col+'">'+v+' '+l+'</span>'; };
  document.getElementById('cov-toolbar').innerHTML =
    '<div class="cov-seg">' + seg + '</div><span style="flex:1"></span>' +
    badge('var(--success)','Prevented',c.cov) + badge('var(--warning)','Detected',c.part) +
    badge('var(--danger)','Missed',c.gap) + badge('var(--muted)','Untested',c.none);
}
function setCovView(v) { COV_VIEW = v; renderCovToolbar(); renderCovMatrix(); }
```

- [ ] **Step 2:** Validate + commit: `feat(coverage): status filter toolbar + tactic counts`.

### Task B4: technique detail drawer

- [ ] **Step 1:** `openTechnique(id)` reuses the results drawer; fetches enrichment + overlays our status:

```js
function openTechnique(id) {
  var st = (window._covSt || {})[id] || 'none';
  var stMeta = { cov:['Prevented','var(--success)'], part:['Detected only','var(--warning)'], gap:['Missed','var(--danger)'], none:['Untested','var(--muted)'] }[st];
  apicall('/api/attack/technique/' + encodeURIComponent(id)).then(function(e) {
    e = e || {};
    document.getElementById('results-title').textContent = id + ' — ' + (e.name || 'Technique');
    document.getElementById('results-export').innerHTML = '';
    var row = function(k, v) { return v && v.length ? '<div style="display:flex;gap:0.6rem;padding:0.35rem 0;border-bottom:1px solid var(--border);font-size:0.8rem"><span style="color:var(--muted);min-width:120px">' + k + '</span><span style="flex:1">' + v + '</span></div>' : ''; };
    var list = function(a) { return (a||[]).map(x).join(', '); };
    var body = '<div style="margin-bottom:0.9rem"><span class="sbadge" style="background:transparent;border:1px solid ' + stMeta[1] + ';color:' + stMeta[1] + '">' + stMeta[0] + '</span></div>' +
      row('Tactics', list(e.tactics)) + row('Platforms', list(e.platforms)) +
      row('Known actors', list(e.groups)) + row('Data sources', list(e.dataSources)) +
      (e.description ? '<div style="margin-top:0.8rem;font-size:0.8rem;color:var(--text-dim);line-height:1.5">' + x(e.description) + '</div>' : '') +
      (e.url ? '<div style="margin-top:0.8rem"><a href="' + x(e.url) + '" target="_blank" style="color:var(--accent);font-size:0.78rem">View on attack.mitre.org →</a></div>' : '');
    document.getElementById('results-body').innerHTML = body;
    document.getElementById('results-overlay').classList.add('open');
  }).catch(function(err) { showToast(err.message, 'err'); });
}
```

- [ ] **Step 2:** Validate + commit: `feat(coverage): technique detail drawer (authoritative enrichment + our status)`.

---

## Self-Review

**Coverage:** matrix structure (A1/A2) ✓; full enterprise scope ✓; coverage overlay reuses dashboard logic ✓; filter + counts (B3) ✓; technique detail w/ authoritative enrichment (B4) ✓; Export layer greyed (B1) ✓; honest caveat in footer ✓.

**Type/consistency:** status codes `cov|part|gap|none` map to prevented/detected/missed/untested everywhere (toolbar, matrix, detail). `covStatusMap` mirrors the donut's classification (most-recent verdict + `detectedTechs`). `attackdata.All()` (A1) feeds `AttackMatrix` (A2) feeds `loadCoverage` (B2). Drawer reuses `results-overlay`.

**Risk notes:** the matrix endpoint returns ~656 techniques across 14 tactics — large but static and cacheable; client overlays from the runs it already fetches. A technique in multiple tactics appears in multiple columns (Navigator-consistent); counts de-dupe by technique id. No backend writes; degrades to all-Untested when there are no runs.
