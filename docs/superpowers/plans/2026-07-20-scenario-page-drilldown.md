# Scenario Page Drill-Down Redesign Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the Scenarios tab's two full-detail card grids with a two-level drill-down (category landing → compact tiles grouped by source) where full detail appears in a click-pinned hover-preview overlay, per `docs/superpowers/specs/2026-07-20-scenario-page-drilldown-design.md`.

**Architecture:** Pure frontend change to one file, `orchestrator/wwwroot/index.html` (a single-page vanilla-JS app with inline `<style>`/`<script>`). Built incrementally so every task leaves the page in a genuinely clickable, demoable state: fix hidden OS data → extract the reusable detail-body renderer → add CSS → ship compact tiles with the click-pinned overlay (still in the old two-section layout) → add the category landing + drill-down navigation → add the explicit search-results view → add collapsible source groups → final polish/verification.

**Tech Stack:** Vanilla JS (ES5-style, no framework), inline CSS, `history.pushState`/`popstate` for in-tab back navigation. No build step — the file is served as-is.

## Global Constraints

- **Single file, two tracked paths, one physical file.** `orchestrator/wwwroot/index.html` and `orchestrator/cmd/server/wwwroot/index.html` are an NTFS hardlink (same inode, confirmed byte-identical) — editing one edits both on disk automatically. Git tracks them as two separate blobs that have drifted before. **Every commit in this plan must `git add` both paths** even though only one was edited, so their history stays in sync.
- **No backend/API/schema changes.** The only "new" data (`supportedOs`) already exists in the API response (`scenario/types.go:194`, `json:"supportedOs"`) — only the client-side mapper is missing it.
- **Preserve every existing action handler verbatim** — `openModal`, `openPicker`, `openBuilder`, `cloneScenario`, `deleteCustomScenario`, `deleteIntelScenario` keep their exact signatures and `onclick` wiring. Only *where* their HTML renders changes.
- **No automated browser-test harness exists for this SPA** (consistent with prior UI work in this codebase — see the Exposure Explorer and Asset Criticality precedents). Verification is: static checks (balanced markup, no duplicate IDs, referenced functions/classes confirmed to exist) after every task, plus one full manual browser walkthrough in the final task.
- **`x(s)`** (line ~10527) is the existing HTML-escaping helper — use it for all interpolated text, matching existing convention.
- Run all edits against `orchestrator/wwwroot/index.html`; the hardlink keeps the twin in sync automatically.

---

### Task 1: Fix hidden OS data + add the OS filter control

**Files:**
- Modify: `orchestrator/wwwroot/index.html:5531-5551` (`loadScenarios` field map)
- Modify: `orchestrator/wwwroot/index.html:1998-2004` (header filter controls)
- Modify: `orchestrator/wwwroot/index.html:5580-5590` (`renderScenarios` match filter)

**Interfaces:**
- Produces: `scenario.supportedOs: string[]` now populated client-side (the API already returns it; only the JS mapper was dropping it). `#sc-filter-os` `<select>` element, values `all|windows|linux|darwin`.

**Context:** The Go API already serializes `supportedOs` (`orchestrator/internal/scenario/types.go:194`). `scenarioCardHTML` already reads `s.supportedOs` to build the OS badge (`index.html:5744-5760`), but `loadScenarios`'s field map never copies it from the API response, so the badge has always rendered empty. This task fixes that and adds a filter — a real, visible bug fix as its own checkpoint.

- [ ] **Step 1: Add `supportedOs` to the scenario field map**

In `loadScenarios()`, the object literal currently ends `...artTechniques: s.artTechniques || []`. Add one field:

```js
        artTechniques:      s.artTechniques       || [],
        supportedOs:        s.supportedOs         || []
```

- [ ] **Step 2: Add the OS filter `<select>` to the header controls**

In the `.sec-hdr` controls block, immediately after the `#sc-filter-source` `</select>` (line 2004), insert:

```html
            <select id="sc-filter-os" onchange="renderScenarios()"
                    style="padding:0.45rem 0.6rem;background:var(--elevated);border:1px solid var(--border);border-radius:var(--radius);color:var(--text);font-size:0.82rem;font-family:inherit">
              <option value="all">All OS</option>
              <option value="windows">Windows</option>
              <option value="linux">Linux</option>
              <option value="darwin">macOS</option>
            </select>
```

- [ ] **Step 3: Wire the OS filter into the existing match filter**

In `renderScenarios()`, the `matches` computation currently reads:

```js
  var matches = scenarios.filter(function(s) {
    if (src !== 'all') {
      var srcVal = s.intelSource ? 'intel' : (s.source || 'builtin');
      if (srcVal !== src) return false;
    }
    if (!q) return true;
```

Add the OS read alongside the existing `src`/`q` reads just above it, and an OS check as the first line inside the filter:

```js
  var osEl = document.getElementById('sc-filter-os');
  var osFilter = osEl ? osEl.value : 'all';

  var matches = scenarios.filter(function(s) {
    if (osFilter !== 'all' && (s.supportedOs || []).indexOf(osFilter) === -1) return false;
    if (src !== 'all') {
      var srcVal = s.intelSource ? 'intel' : (s.source || 'builtin');
      if (srcVal !== src) return false;
    }
    if (!q) return true;
```

(This whole block — including the OS check — gets replaced wholesale by Task 5's dispatcher rewrite; it's a real, working filter in the meantime, not throwaway code.)

- [ ] **Step 4: Manual checkpoint**

Reload the dashboard in a browser, open the Scenarios tab. Confirm: (a) OS badges now appear on existing cards where they were previously blank, (b) selecting "Linux" in the new filter hides Windows-only scenarios and the header count (`#sc-cnt`) updates accordingly.

- [ ] **Step 5: Commit**

```bash
git add orchestrator/wwwroot/index.html orchestrator/cmd/server/wwwroot/index.html
git commit -m "fix(ui): populate scenario supportedOs client-side; add OS filter"
git push
```

---

### Task 2: Extract `scenarioDetailHTML` from `scenarioCardHTML`

**Files:**
- Modify: `orchestrator/wwwroot/index.html:5672-5788` (`scenarioCardHTML`)

**Interfaces:**
- Produces: `scenarioDetailHTML(s) → string` — the full card body (intel badge/custom badge, `<h3>` name, description, tags, footer with all action buttons) **without** the outer `.card` wrapper or stripe. This is what Task 4's overlay renders.
- Consumes: nothing new — same locals (`color`, `tags`, `intelBadge`, `customBadge`, `modeMeta`, `osBadge`, `editBtns`, `customizeBtn`) computed exactly as today.

**Why this task exists on its own:** a pure, byte-identical refactor is a clean, independently-verifiable checkpoint before any new UI is built on top of it — if the old grid stops rendering identically, the bug is isolated to this one function.

- [ ] **Step 1: Split the function**

Replace the whole `scenarioCardHTML` function (5672-5788) with two functions. `scenarioDetailHTML` contains everything that's currently *inside* each `return '<div class="card">'…'</div>'`, minus the outer wrapper and stripe div; `scenarioCardHTML` becomes a thin wrapper kept for now (Task 4 will retire it once nothing calls it):

```js
function scenarioDetailHTML(s) {
      var color = stripeColor(s.id);
      var visibleTags = (s.tags || []).filter(function(t) {
        return t !== 'intel' && t !== 'auto-generated';
      });
      var tags = visibleTags.map(function(t) { return '<span class="tag">' + x(t) + '</span>'; }).join('');
      var intelBadge = '';
      if (s.intelSource) {
        var confColor = s.intelConfidence === 'high' ? '#5cead8' : s.intelConfidence === 'medium' ? '#d29922' : '#9aa9bc';
        intelBadge = '<span style="display:inline-flex;align-items:center;gap:4px;background:rgba(47,129,247,0.12);' +
          'border:1px solid rgba(47,129,247,0.35);border-radius:4px;padding:2px 7px;font-size:0.72rem;color:#58a6ff;font-weight:600;margin-bottom:6px">' +
          '&#128268; Intel &nbsp;·&nbsp; ' + x(s.intelActor) +
          ' &nbsp;<span style="color:' + confColor + '">' + x(s.intelConfidence) + '</span>' +
          ' &nbsp;·&nbsp; ' + x(s.intelSource.toUpperCase()) + '</span><br>';
        var techCount = (s.artTechniques || []).length;
        var deleteBtn = (ROLE === 'admin')
          ? ' <button class="btn btn-sm" style="background:rgba(218,54,51,0.12);color:#f85149;margin-left:4px" ' +
            'onclick="deleteIntelScenario(\'' + x(s.id) + '\')" title="Delete intel scenario">&#10005;</button>'
          : '';
        var footerMeta = techCount + ' techniques' + deleteBtn;
        return '<div>' + intelBadge + '</div>' +
          '<h3>' + x(s.name) + '</h3>' +
          descHtml(s.description, s.id, {limit:120, style:'font-size:0.78rem;color:var(--muted)'}) +
          '<div class="tags">' + tags + '</div>' +
          '<div class="card-footer">' +
            '<div class="card-meta">' + footerMeta + '</div>' +
            '<button class="btn btn-outline-green btn-sm" onclick="openModal(\'' + x(s.id) + '\',null)">&#9654; Run</button>' +
          '</div>';
      }
      var canEdit = (ROLE === 'admin' || ROLE === 'analyst');
      var customBadge = s.source === 'custom'
        ? '<span class="tag" style="background:rgba(47,216,195,0.15);color:#5cead8;border-color:rgba(47,216,195,0.4)">custom</span> '
        : '';
      var editBtns = '';
      if (canEdit) {
        editBtns += '<button class="btn btn-outline btn-sm" onclick="cloneScenario(\'' + x(s.id) + '\')" title="Clone into an editable custom scenario">&#9112; Clone</button> ';
        if (s.source === 'custom') {
          editBtns += '<button class="btn btn-outline btn-sm" onclick="openBuilder(\'' + x(s.id) + '\')" title="Edit">&#9998; Edit</button> ';
          editBtns += '<button class="btn btn-sm" style="background:rgba(218,54,51,0.12);color:#f85149" onclick="deleteCustomScenario(\'' + x(s.id) + '\')" title="Delete">&#10005;</button> ';
        }
      }
      var modeMeta;
      var stepN = (s.steps || []).length;
      if (s.localCheck) {
        modeMeta = '<a href="javascript:void(0)" class="desc-toggle" title="Choose which posture checks to run" ' +
          'onclick="openModal(\'' + x(s.id) + '\',null);return false;">Posture check &#9881;</a>';
      } else if (s.artAllWindows) {
        modeMeta = 'Full ART sweep' + (artCatalog.length ? ' · ' + artCatalog.length + ' techniques' : '');
      } else if (s.calderaAllWindows) {
        modeMeta = 'Full Caldera sweep' + (calderaCatalog.length ? ' · ' + calderaCatalog.length + ' abilities' : '');
      } else if ((s.artTechniques || []).length) {
        modeMeta = s.artTechniques.length + ' ART techniques';
      } else if ((s.calderaAbilities || []).length) {
        modeMeta = s.calderaAbilities.length + ' Caldera abilities';
      } else if (stepN) {
        modeMeta = '<a href="javascript:void(0)" class="desc-toggle" title="Choose which steps to run" ' +
          'onclick="openPicker(\'' + x(s.id) + '\',\'steps\');return false;">' +
          stepN + (stepN === 1 ? ' step' : ' steps') + '</a>';
      } else {
        modeMeta = '—';
      }

      var osArr = s.supportedOs || [];
      var osBadge = '';
      if (osArr.length > 0) {
        var osIcons = { windows: '⊞', linux: '🐧', darwin: '⌘' };
        var osColors = {
          windows: 'rgba(47,129,247,0.15);color:#58a6ff;border-color:rgba(47,129,247,0.4)',
          linux:   'rgba(47,216,195,0.15);color:#5cead8;border-color:rgba(47,216,195,0.4)',
          darwin:  'rgba(154,169,188,0.15);color:#9aa9bc;border-color:rgba(154,169,188,0.35)'
        };
        var osOnly = (osArr.length === 1);
        osBadge = osArr.map(function(os) {
          var lc = os.toLowerCase();
          var col = osColors[lc] || 'rgba(154,169,188,0.12);color:#9aa9bc;border-color:rgba(154,169,188,0.35)';
          var label = osOnly ? (os === 'darwin' ? 'macOS' : os.charAt(0).toUpperCase() + os.slice(1)) : (osIcons[lc] || os);
          return '<span class="tag" style="background:' + col + ';font-size:0.62rem;padding:1px 6px" title="Supported OS: ' + os + '">' + label + '</span>';
        }).join('') + ' ';
      }

      var fw = (s.artAllWindows || (s.artTechniques || []).length) ? 'art'
             : (s.calderaAllWindows || (s.calderaAbilities || []).length) ? 'caldera'
             : (!s.localCheck && stepN) ? 'steps'
             : '';
      var fwNoun = fw === 'art' ? 'techniques' : fw === 'caldera' ? 'abilities' : 'steps';
      var customizeBtn = fw
        ? '<button class="btn btn-outline btn-sm" onclick="openPicker(\'' + x(s.id) + '\',\'' + fw + '\')" ' +
          'title="Choose which ' + fwNoun + ' to run">&#9881; Customize</button> '
        : '';

      return '<div>' + customBadge + '</div>' +
        '<h3>' + x(s.name) + '</h3>' +
        descHtml(s.description, s.id, {limit:140}) +
        '<div class="tags">' + osBadge + tags + '</div>' +
        '<div class="card-footer">' +
          '<div class="card-meta">' + modeMeta + '</div>' +
          '<div style="display:flex;gap:0.3rem;flex-wrap:wrap;justify-content:flex-end">' +
            editBtns + customizeBtn +
            '<button class="btn btn-outline-green btn-sm" onclick="openModal(\'' + x(s.id) + '\',null)">&#9654; Run</button>' +
          '</div>' +
        '</div>';
}

function scenarioCardHTML(s) {
  var color = s.intelSource ? '#2f81f7' : stripeColor(s.id);
  return '<div class="card"><div class="card-stripe" style="background:' + color + '"></div>' + scenarioDetailHTML(s) + '</div>';
}
```

Note: the original intel branch hardcoded the stripe to `#2f81f7` regardless of `stripeColor(s.id)`; `scenarioCardHTML`'s wrapper above preserves that exact distinction so output stays byte-identical.

- [ ] **Step 2: Manual checkpoint**

Reload the Scenarios tab. The grid must look and behave **exactly** as before this task (same card layout, same badges, same buttons) — this is a pure refactor.

- [ ] **Step 3: Commit**

```bash
git add orchestrator/wwwroot/index.html orchestrator/cmd/server/wwwroot/index.html
git commit -m "refactor(ui): extract scenarioDetailHTML from scenarioCardHTML (no behavior change)"
git push
```

---

### Task 3: CSS scaffold for landing, tiles, overlay, and fade transitions

**Files:**
- Modify: `orchestrator/wwwroot/index.html:506` (insert new block immediately after the existing `.cards`/`.card` rules)

**Interfaces:**
- Produces new CSS classes consumed by later tasks: `.sc-fade`, `.sc-landing`, `.sc-cat-card`, `.sc-cat-count`, `.sc-cat-breakdown`, `.sc-backbar`, `.sc-back-btn`, `.sc-src-group`, `.sc-src-hdr` (+ `.collapsed`), `.sc-src-body` (+ `.collapsed`), `.sc-tile`, `.sc-tile-stripe`, `.sc-tile-name`, `.sc-tile-badges`, `.sc-tile-detail` (+ `.show`), `.pinned`.

No JS references any of these classes yet — this task is CSS-only and produces no visible change (all classes are unused until Task 4+).

- [ ] **Step 1: Insert the new CSS block**

Immediately after the existing line `.desc-toggle:hover { text-decoration: underline; }` (line 506), insert:

```css

/* Scenario drill-down: landing, tiles, click-pinned overlay */
@keyframes scFadeIn { from { opacity:0; } to { opacity:1; } }
.sc-fade { animation: scFadeIn 0.18s ease; }

.sc-landing { display:grid; grid-template-columns:repeat(auto-fill,minmax(260px,1fr)); gap:1rem; }
.sc-cat-card {
  background:var(--surface); border:1px solid var(--border); border-radius:var(--radius-lg);
  padding:1.1rem 1.2rem; cursor:pointer; transition:border-color 0.15s, box-shadow 0.15s;
}
.sc-cat-card:hover, .sc-cat-card:focus-visible { border-color: rgba(47,129,247,0.4); box-shadow: 0 2px 12px rgba(0,0,0,0.2); outline:none; }
.sc-cat-card h3 { font-size:1rem; font-weight:600; margin-bottom:0.4rem; display:flex; align-items:center; gap:8px; }
.sc-cat-count { font-size:0.8rem; color:var(--text); margin-bottom:0.25rem; }
.sc-cat-breakdown { font-size:0.72rem; color:var(--muted); }

.sc-backbar { display:flex; align-items:center; gap:0.6rem; margin-bottom:1.2rem; }
.sc-back-btn { background:none; border:1px solid var(--border); border-radius:var(--radius); color:var(--text); padding:0.35rem 0.7rem; font-size:0.8rem; cursor:pointer; }
.sc-back-btn:hover { border-color:var(--accent); }
.sc-backbar h2 { font-size:1.05rem; margin:0; }

.sc-src-group { margin-bottom:1.4rem; }
.sc-src-hdr { display:flex; align-items:center; gap:0.5rem; cursor:pointer; user-select:none; margin-bottom:0.7rem; font-size:0.85rem; font-weight:600; color:var(--muted); }
.sc-src-hdr .chev { transition:transform 0.15s; display:inline-block; }
.sc-src-hdr.collapsed .chev { transform:rotate(-90deg); }
.sc-src-body { display:grid; grid-template-columns:repeat(auto-fill,minmax(190px,1fr)); gap:0.7rem; }
.sc-src-body.collapsed { display:none; }

.sc-tile {
  position:relative; background:var(--surface); border:1px solid var(--border); border-radius:var(--radius);
  padding:0.7rem 0.7rem 0.7rem 0.9rem; cursor:pointer; min-height:64px;
  display:flex; flex-direction:column; justify-content:center; gap:0.3rem;
  transition:border-color 0.15s;
}
.sc-tile:hover, .sc-tile:focus-visible { border-color:rgba(47,129,247,0.4); outline:none; }
.sc-tile.pinned { border-color:var(--accent); }
.sc-tile-stripe { position:absolute; left:0; top:0; bottom:0; width:3px; border-radius:var(--radius) 0 0 var(--radius); }
.sc-tile-name { font-size:0.82rem; font-weight:600; line-height:1.3; }
.sc-tile-badges { display:flex; flex-wrap:wrap; gap:0.25rem; }
.sc-tile-detail {
  display:none; position:absolute; left:0; top:100%; width:420px; max-width:90vw; z-index:20;
  background:var(--surface); border:1px solid var(--border); border-radius:var(--radius-lg);
  box-shadow:0 8px 28px rgba(0,0,0,0.35); padding:1rem 1rem 1rem 1.2rem; margin-top:4px;
}
.sc-tile-detail.show { display:block; animation:scFadeIn 0.18s ease; }
```

- [ ] **Step 2: Manual checkpoint**

Reload the dashboard. Open browser devtools console — confirm zero errors/warnings. Visually confirm the Scenarios tab is unchanged (all new classes are currently unused).

- [ ] **Step 3: Commit**

```bash
git add orchestrator/wwwroot/index.html orchestrator/cmd/server/wwwroot/index.html
git commit -m "style(ui): CSS scaffold for scenario landing/tile/overlay drill-down (unused pending wiring)"
git push
```

---

### Task 4: Compact tiles with click-pinned hover-preview overlay

**Files:**
- Modify: `orchestrator/wwwroot/index.html:5560-5639` (`renderScenarios`)
- Modify: `orchestrator/wwwroot/index.html:3672` (add state vars near `var scenarios = [];`)

**Interfaces:**
- Consumes: `scenarioDetailHTML(s)` (Task 2), CSS classes from Task 3.
- Produces: `scenarioTileHTML(s) → string`, `scenarioSourceOf(s) → 'builtin'|'custom'|'intel'`, `SCENARIO_SOURCE_LABELS`, `SCENARIO_SOURCE_ORDER`, `renderScenarioTileGroup(list) → string` (groups by source, no collapse yet — Task 7 adds that), and the overlay engine: `previewScenarioOverlay(id)`, `unpreviewScenarioOverlay(id)`, `toggleScenarioPin(event,id)`, `closeScenarioOverlay()`, plus module-level `overlayPinned`.
- This task **replaces what renders inside the existing two sections** (`#sc-grid-em`, `#sc-grid`) — the section titles/containers themselves are untouched here; Task 5 restructures those into the landing/drill-down.

**Overlay design (locked with user):** hover previews (unpinned, dismissed by mouse-leave); click / tap / Enter / Space pins it (persists regardless of mouse movement); a second activation, outside-click, or ESC closes it. A genuine bug caught while designing this: since the detail panel is a DOM child of the tile, a click on a button *inside* the overlay (e.g. "Run") bubbles up through the tile's own `onclick`, which would immediately re-toggle/close the very overlay the user just clicked into. Fixed by having `toggleScenarioPin` bail out early when the click originated inside `.sc-tile-detail` (`event.target.closest('.sc-tile-detail')`, already a pattern used elsewhere in this file at lines 8682/8685/9384).

- [ ] **Step 1: Add module-level overlay state**

Immediately after `var scenarios = [];` (line 3672), add:

```js
var overlayPinned = null; // scenario id of the pinned tile's overlay, or null
```

- [ ] **Step 2: Add the tile-badge helpers, source classifier, and tile renderer**

Add these new functions immediately before `scenarioDetailHTML` (i.e. just above where Task 2 placed it):

```js
function scenarioSourceOf(s) {
  return s.intelSource ? 'intel' : (s.source || 'builtin');
}
var SCENARIO_SOURCE_LABELS = { builtin: 'Built-in', custom: 'Custom', intel: 'Threat-Intel' };
var SCENARIO_SOURCE_ORDER = ['builtin', 'custom', 'intel'];

function scenarioTileOSBadges(s) {
  var osArr = s.supportedOs || [];
  if (!osArr.length) return '';
  var osIcons = { windows: '⊞', linux: '🐧', darwin: '⌘' };
  var osColors = {
    windows: 'rgba(47,129,247,0.15);color:#58a6ff;border-color:rgba(47,129,247,0.4)',
    linux:   'rgba(47,216,195,0.15);color:#5cead8;border-color:rgba(47,216,195,0.4)',
    darwin:  'rgba(154,169,188,0.15);color:#9aa9bc;border-color:rgba(154,169,188,0.35)'
  };
  return osArr.map(function(os) {
    var lc = os.toLowerCase();
    var col = osColors[lc] || 'rgba(154,169,188,0.12);color:#9aa9bc;border-color:rgba(154,169,188,0.35)';
    return '<span class="tag" style="background:' + col + ';font-size:0.6rem;padding:1px 5px" title="Supported OS: ' + x(os) + '">' + (osIcons[lc] || x(os)) + '</span>';
  }).join('');
}

function scenarioTileMitreBadge(s) {
  var phases = s.mitrePhases || [];
  if (!phases.length) return '';
  var extra = phases.length > 1 ? ' <span style="opacity:0.7">+' + (phases.length - 1) + '</span>' : '';
  return '<span class="tag" style="font-size:0.6rem;padding:1px 5px" title="' + x(phases.join(', ')) + '">' + x(phases[0]) + extra + '</span>';
}

function scenarioTileHTML(s) {
  var color = s.intelSource ? '#2f81f7' : stripeColor(s.id);
  var sid = x(s.id);
  return '<div class="sc-tile" tabindex="0" role="button" aria-expanded="false" data-sid="' + sid + '" ' +
    'onmouseenter="previewScenarioOverlay(\'' + sid + '\')" onmouseleave="unpreviewScenarioOverlay(\'' + sid + '\')" ' +
    'onclick="toggleScenarioPin(event,\'' + sid + '\')" ' +
    'onkeydown="if(event.key===\'Enter\'||event.key===\' \'){event.preventDefault();toggleScenarioPin(event,\'' + sid + '\');}">' +
    '<div class="sc-tile-stripe" style="background:' + color + '"></div>' +
    '<div class="sc-tile-name">' + x(s.name) + '</div>' +
    '<div class="sc-tile-badges">' + scenarioTileOSBadges(s) + scenarioTileMitreBadge(s) + '</div>' +
    '<div class="sc-tile-detail" id="scd-' + sid + '">' + scenarioDetailHTML(s) + '</div>' +
  '</div>';
}

function renderScenarioTileGroup(list) {
  var bySrc = { builtin: [], custom: [], intel: [] };
  list.forEach(function(s) { bySrc[scenarioSourceOf(s)].push(s); });
  return SCENARIO_SOURCE_ORDER.map(function(k) {
    if (!bySrc[k].length) return '';
    return '<div class="sc-src-group">' +
      '<div class="sc-src-hdr"><span class="chev">&#9660;</span>' + x(SCENARIO_SOURCE_LABELS[k]) + ' (' + bySrc[k].length + ')</div>' +
      '<div class="sc-src-body">' + bySrc[k].map(scenarioTileHTML).join('') + '</div>' +
    '</div>';
  }).join('');
}
```

- [ ] **Step 3: Add the overlay engine**

Add these functions immediately after the group above (still before `scenarioDetailHTML`):

```js
function _scOverlayEl(id) { return document.getElementById('scd-' + id); }
function _scTileEl(id) {
  var d = _scOverlayEl(id);
  return d ? d.parentElement : null;
}

// Keeps the 420px overlay from clipping past the right edge of the viewport
// for tiles that aren't in the leftmost grid column.
function _scPositionOverlay(id) {
  var detail = _scOverlayEl(id);
  var tile = _scTileEl(id);
  if (!detail || !tile) return;
  detail.style.left = '';
  detail.style.right = '';
  var rect = tile.getBoundingClientRect();
  if (rect.left + 420 > window.innerWidth - 16) {
    detail.style.left = 'auto';
    detail.style.right = '0';
  }
}

function previewScenarioOverlay(id) {
  if (overlayPinned) return; // a pinned overlay is never disturbed by hovering elsewhere
  var detail = _scOverlayEl(id);
  if (!detail) return;
  _scPositionOverlay(id);
  detail.classList.add('show');
}
function unpreviewScenarioOverlay(id) {
  if (overlayPinned === id) return; // pinned overlays only close via toggle/ESC/outside-click
  var detail = _scOverlayEl(id);
  if (detail) detail.classList.remove('show');
}
function toggleScenarioPin(event, id) {
  // A click on a button/link inside the already-open detail panel must not
  // re-toggle the tile's own pin state — the panel is a DOM child of the
  // tile, so such clicks bubble up to this same handler.
  if (event.target.closest && event.target.closest('.sc-tile-detail')) return;
  event.stopPropagation();
  if (overlayPinned === id) { closeScenarioOverlay(); return; }
  closeScenarioOverlay();
  overlayPinned = id;
  var tile = _scTileEl(id);
  var detail = _scOverlayEl(id);
  if (tile) { tile.classList.add('pinned'); tile.setAttribute('aria-expanded', 'true'); }
  if (detail) { _scPositionOverlay(id); detail.classList.add('show'); }
}
function closeScenarioOverlay() {
  if (!overlayPinned) return;
  var tile = _scTileEl(overlayPinned);
  var detail = _scOverlayEl(overlayPinned);
  if (tile) { tile.classList.remove('pinned'); tile.setAttribute('aria-expanded', 'false'); }
  if (detail) detail.classList.remove('show');
  overlayPinned = null;
}
document.addEventListener('click', function(e) {
  if (!overlayPinned) return;
  var detail = _scOverlayEl(overlayPinned);
  var tile = _scTileEl(overlayPinned);
  if ((detail && detail.contains(e.target)) || (tile && tile.contains(e.target))) return;
  closeScenarioOverlay();
});
document.addEventListener('keydown', function(e) {
  if (e.key === 'Escape' && overlayPinned) {
    var tile = _scTileEl(overlayPinned);
    closeScenarioOverlay();
    if (tile) tile.focus();
  }
});
```

- [ ] **Step 4: Wire the two existing grids to render tile groups instead of full cards**

In `renderScenarios()`, the two lines that currently paint the grids:

```js
    gridEm.innerHTML = emMatches.map(scenarioCardHTML).join('');
```
and
```js
    grid.innerHTML = otherMatches.map(scenarioCardHTML).join('');
```

Replace both call sites' mapper with the new grouped renderer:

```js
    gridEm.innerHTML = '<div class="sc-fade">' + renderScenarioTileGroup(emMatches) + '</div>';
```
```js
    grid.innerHTML = '<div class="sc-fade">' + renderScenarioTileGroup(otherMatches) + '</div>';
```

(`scenarioCardHTML` itself is left intact for now — nothing else calls it after this step, but removing it isn't necessary until a later cleanup; leaving unused code out of scope here keeps this diff focused.)

- [ ] **Step 5: Manual checkpoint**

Reload the Scenarios tab. Confirm: both sections now show small tiles (name + stripe + OS/MITRE badges only) grouped under "Built-in (n)" / "Custom (n)" / "Threat-Intel (n)" headers. Hover a tile → detail overlay appears below it. Move the mouse away → it disappears. Click a tile → overlay stays open even after moving the mouse elsewhere; click the same tile (or anywhere outside) → it closes. Press Tab to focus a tile, press Enter → overlay pins; press Escape → it closes and focus returns to the tile. Click "Run" inside an open overlay → the run modal opens (overlay does not simultaneously auto-close from the click). Hover/click a tile near the right edge of the window → the overlay does not get clipped off-screen.

- [ ] **Step 6: Commit**

```bash
git add orchestrator/wwwroot/index.html orchestrator/cmd/server/wwwroot/index.html
git commit -m "feat(ui): compact scenario tiles with click-pinned hover-preview overlay"
git push
```

---

### Task 5: Category landing page + drill-down navigation

**Files:**
- Modify: `orchestrator/wwwroot/index.html:2012-2027` (replace `#em-section`/`#other-section` static markup)
- Modify: `orchestrator/wwwroot/index.html:5560-5639` (`renderScenarios` — becomes the landing/category dispatcher)
- Modify: `orchestrator/wwwroot/index.html:3804-3822` (`showTab`, add scenarios-tab reset)

**Interfaces:**
- Consumes: `renderScenarioTileGroup` (Task 4).
- Produces: module-level `scenarioView` (`'landing'|'em'|'other'`), `SCENARIO_CATEGORIES`, `scenarioCategoryOf(s)`, `scenarioCategoryCounts(list,key)`, `renderScenarioLanding(list)`, `openScenarioCategory(key)`, `closeScenarioCategoryView()`, a `popstate` listener.

- [ ] **Step 1: Add `scenarioView` state**

Immediately after `var overlayPinned = null;` (added in Task 4 Step 1), add:

```js
var scenarioView = 'landing'; // 'landing' | 'em' | 'other'
```

- [ ] **Step 2: Replace the static section markup**

Replace lines 2012-2027 (the `<!-- Endpoint Mastery Section -->` and `<!-- Other Scenarios Section -->` blocks, from `<div id="em-section"...>` through the closing `</div>` of `#other-section`) with:

```html
        <!-- Scenario Library: category landing + drill-down tile view -->
        <div id="sc-landing" class="sc-landing"></div>

        <div id="sc-category-view" style="display:none">
          <div class="sc-backbar">
            <button class="sc-back-btn" onclick="closeScenarioCategoryView()">&larr; Back</button>
            <h2 id="sc-backbar-title"></h2>
          </div>
          <div id="sc-tile-grid"></div>
        </div>
```

- [ ] **Step 3: Add category metadata + landing renderer**

Add these functions immediately before `renderScenarios()`:

```js
var SCENARIO_CATEGORIES = {
  em:    { label: 'Endpoint Mastery',
           icon: '<svg style="width:18px;height:18px;stroke:var(--accent)" viewBox="0 0 24 24" fill="none"><path d="M12 2L4 5v6c0 5 3.5 9 8 11 4.5-2 8-6 8-11V5l-8-3z" stroke-width="2" fill="none"/></svg>' },
  other: { label: 'Standard & Custom',
           icon: '<svg style="width:18px;height:18px;stroke:var(--muted)" viewBox="0 0 24 24" fill="none"><rect x="3" y="3" width="18" height="18" rx="2" stroke-width="2"/><path d="M3 9h18M9 21V9" stroke-width="2"/></svg>' }
};

function scenarioCategoryOf(s) {
  return ((s.id || '').indexOf('em-') === 0 || (s.tags || []).indexOf('endpoint-mastery') !== -1) ? 'em' : 'other';
}

function scenarioCategoryCounts(list, key) {
  var inCat = list.filter(function(s) { return scenarioCategoryOf(s) === key; });
  var counts = { total: inCat.length, builtin: 0, custom: 0, intel: 0 };
  inCat.forEach(function(s) { counts[scenarioSourceOf(s)]++; });
  return counts;
}

function renderScenarioLanding(list) {
  var el = document.getElementById('sc-landing');
  if (!el) return;
  var html = ['em', 'other'].map(function(key) {
    var cat = SCENARIO_CATEGORIES[key];
    var c = scenarioCategoryCounts(list, key);
    if (c.total === 0) return '';
    var breakdown = [c.builtin ? c.builtin + ' Built-in' : '', c.custom ? c.custom + ' Custom' : '', c.intel ? c.intel + ' Intel' : '']
      .filter(Boolean).join(' · ');
    return '<div class="sc-cat-card sc-fade" tabindex="0" role="button" ' +
      'onclick="openScenarioCategory(\'' + key + '\')" ' +
      'onkeydown="if(event.key===\'Enter\'||event.key===\' \'){event.preventDefault();openScenarioCategory(\'' + key + '\');}">' +
      '<h3>' + cat.icon + x(cat.label) + '</h3>' +
      '<div class="sc-cat-count">' + c.total + ' scenario' + (c.total === 1 ? '' : 's') + '</div>' +
      '<div class="sc-cat-breakdown">' + x(breakdown) + '</div>' +
    '</div>';
  }).join('');
  el.innerHTML = html || '<p class="empty">No scenarios loaded.</p>';
}
```

- [ ] **Step 4: Add navigation + history**

```js
function openScenarioCategory(key) {
  scenarioView = key;
  closeScenarioOverlay();
  history.pushState({ scenarioView: key }, '', '#tab-scenarios/' + key);
  renderScenarios();
}
function closeScenarioCategoryView() {
  scenarioView = 'landing';
  closeScenarioOverlay();
  history.pushState({ scenarioView: 'landing' }, '', '#tab-scenarios');
  renderScenarios();
}
window.addEventListener('popstate', function(e) {
  var tab = document.getElementById('tab-scenarios');
  if (!tab || tab.style.display === 'none') return;
  scenarioView = (e.state && e.state.scenarioView) || 'landing';
  closeScenarioOverlay();
  renderScenarios();
});
```

- [ ] **Step 5: Rewrite `renderScenarios()` as the landing/category dispatcher**

Replace the entire function body (lines 5560-5639, from `function renderScenarios() {` through its closing `}`) with:

```js
function renderScenarios() {
  var landingEl = document.getElementById('sc-landing');
  var catEl = document.getElementById('sc-category-view');
  if (!landingEl || !catEl) return;

  if (!scenarios.length) {
    catEl.style.display = 'none';
    landingEl.style.display = 'block';
    landingEl.innerHTML = '<p class="empty">No scenarios loaded.</p>';
    document.getElementById('sc-cnt').textContent = 0;
    return;
  }

  var searchEl = document.getElementById('sc-search');
  var srcEl = document.getElementById('sc-filter-source');
  var osEl = document.getElementById('sc-filter-os');
  var q = (searchEl ? searchEl.value : '').trim().toLowerCase();
  var src = srcEl ? srcEl.value : 'all';
  var osFilter = osEl ? osEl.value : 'all';

  var filtered = scenarios.filter(function(s) {
    if (osFilter !== 'all' && (s.supportedOs || []).indexOf(osFilter) === -1) return false;
    if (src !== 'all' && scenarioSourceOf(s) !== src) return false;
    return true;
  });
  document.getElementById('sc-cnt').textContent = filtered.length;

  if (scenarioView === 'landing') {
    catEl.style.display = 'none';
    landingEl.style.display = 'block';
    renderScenarioLanding(filtered);
    return;
  }

  landingEl.style.display = 'none';
  catEl.style.display = 'block';
  var cat = SCENARIO_CATEGORIES[scenarioView];
  var inCat = filtered.filter(function(s) { return scenarioCategoryOf(s) === scenarioView; });
  document.getElementById('sc-backbar-title').textContent = cat.label + ' (' + inCat.length + ')';
  var grid = document.getElementById('sc-tile-grid');
  grid.innerHTML = inCat.length
    ? '<div class="sc-fade">' + renderScenarioTileGroup(inCat) + '</div>'
    : '<p class="empty">No scenarios match your filter.</p>';
}
```

Note: this rewrite drops the old empty-state "No Threat Intel scenarios yet" explainer block and the `#em-cnt`/`#other-cnt` per-section counters (those elements no longer exist after Step 2's markup replacement) — the landing page's per-category breakdown line is their replacement. Search-specific behavior and its own empty state are added in Task 6.

- [ ] **Step 6: Reset to landing whenever the Scenarios tab is (re)entered**

In `showTab()`, add a case alongside the existing `if (name === 'em') loadEmTab();` line:

```js
  if (name === 'scenarios') { scenarioView = 'landing'; closeScenarioOverlay(); if (scenarios.length) renderScenarios(); }
```

- [ ] **Step 7: Manual checkpoint**

Reload the dashboard, open the Scenarios tab. Confirm: you land on two category cards ("Endpoint Mastery — N scenarios — X Built-in · Y Custom · Z Intel", "Standard & Custom — ..."). Click a category card → back bar + tile grid for that category appears, with a working "← Back" button. Click a tile → overlay opens; click Run → modal opens as before. Click the browser's native Back button → also returns to the landing (not the previous page/tab). Switch to another tab and back to Scenarios → lands on the category landing again, not wherever you left off.

- [ ] **Step 8: Commit**

```bash
git add orchestrator/wwwroot/index.html orchestrator/cmd/server/wwwroot/index.html
git commit -m "feat(ui): category landing page + drill-down navigation for scenarios"
git push
```

---

### Task 6: Explicit cross-category search-results view

**Files:**
- Modify: `orchestrator/wwwroot/index.html:1996-1997` (search input)
- Modify: `orchestrator/wwwroot/index.html` (`renderScenarios`, `closeScenarioCategoryView`, `popstate` listener — all added/modified in Task 5)

**Interfaces:**
- Produces: `scenarioView === 'search'` as a first-class dispatcher branch with an explicit "Search results for: …" header, reusing `#sc-category-view`/`#sc-tile-grid`.

**Behavior (locked with user):** typing a non-empty query, from *any* view, switches to a flat cross-category search-results view (never silently hides categories without saying why). Clearing the query — or clicking Back from the results view — deterministically returns to the landing page, and explicitly clears the search box so a stale query can't immediately re-trigger the search view on the next render.

- [ ] **Step 1: Update the search input's `oninput` handler**

Replace the search `<input>`'s `oninput="renderScenarios()"` with one that resets `scenarioView` to `landing` the moment the box becomes empty (so clearing search doesn't leave you stranded on whatever view was showing):

```html
            <input type="search" id="sc-search" placeholder="Search name, tag, technique…"
                   oninput="if (!this.value.trim() && scenarioView === 'search') { scenarioView = 'landing'; } renderScenarios()"
                   style="padding:0.45rem 0.7rem;background:var(--elevated);border:1px solid var(--border);border-radius:var(--radius);color:var(--text);font-size:0.82rem;font-family:inherit;min-width:200px">
```

- [ ] **Step 2: Make `closeScenarioCategoryView` clear a stale search query**

Update the function added in Task 5 Step 4 so leaving the search-results view via Back actually leaves search mode, not just the visible view:

```js
function closeScenarioCategoryView() {
  if (scenarioView === 'search') {
    var se = document.getElementById('sc-search');
    if (se) se.value = '';
  }
  scenarioView = 'landing';
  closeScenarioOverlay();
  history.pushState({ scenarioView: 'landing' }, '', '#tab-scenarios');
  renderScenarios();
}
```

- [ ] **Step 3: Same fix for the browser-Back path**

Update the `popstate` listener from Task 5 Step 4:

```js
window.addEventListener('popstate', function(e) {
  var tab = document.getElementById('tab-scenarios');
  if (!tab || tab.style.display === 'none') return;
  var view = (e.state && e.state.scenarioView) || 'landing';
  if (view === 'landing') {
    var se = document.getElementById('sc-search');
    if (se) se.value = '';
  }
  scenarioView = view;
  closeScenarioOverlay();
  renderScenarios();
});
```

- [ ] **Step 4: Add the search branch to the dispatcher**

In `renderScenarios()` (rewritten in Task 5 Step 5), insert a query check right after `filtered` is computed and the `#sc-cnt` count is set, before the `if (scenarioView === 'landing')` branch:

```js
  if (q) { scenarioView = 'search'; }

  if (scenarioView === 'search') {
    landingEl.style.display = 'none';
    catEl.style.display = 'block';
    var results = filtered.filter(function(s) {
      var hay = [s.id, s.name, s.description, (s.tags || []).join(' '),
                 (s.mitrePhases || []).join(' '), (s.artTechniques || []).join(' '),
                 s.intelActor].join(' ').toLowerCase();
      return hay.indexOf(q) !== -1;
    });
    document.getElementById('sc-backbar-title').textContent = 'Search results for: "' + x(searchEl.value.trim()) + '" (' + results.length + ')';
    var sgrid = document.getElementById('sc-tile-grid');
    sgrid.innerHTML = results.length
      ? '<div class="sc-fade">' + renderScenarioTileGroup(results) + '</div>'
      : '<p class="empty">No scenarios match your search.</p>';
    return;
  }
```

(Place this immediately before the existing `if (scenarioView === 'landing') { ... }` block from Task 5 — both branches now live in the same dispatcher, `search` simply takes priority whenever `q` is non-empty.)

- [ ] **Step 5: Manual checkpoint**

From the landing page, type a query → an explicit "Search results for: "…" (N)" header appears with matching tiles across both categories. Clear the search box → returns to the landing page. Drill into a category, then type a query → search results view still appears (overriding the category view) with the same header. Click Back from search results → search box clears and you land on the category landing. Click the browser Back button while search results are showing → same clear-and-return-to-landing behavior.

- [ ] **Step 6: Commit**

```bash
git add orchestrator/wwwroot/index.html orchestrator/cmd/server/wwwroot/index.html
git commit -m "feat(ui): explicit cross-category search-results view for scenarios"
git push
```

---

### Task 7: Collapsible source sub-sections

**Files:**
- Modify: `orchestrator/wwwroot/index.html` (`renderScenarioTileGroup`, added in Task 4)

**Interfaces:**
- Produces: module-level `scenarioSrcCollapsed` (per-view, per-source collapse state), `toggleScenarioSrcGroup(viewKey, srcKey)`. `renderScenarioTileGroup` gains a `viewKey` parameter so collapse state is tracked separately per category/search view.

- [ ] **Step 1: Add collapse state**

Immediately after `var scenarioView = 'landing';` (Task 5 Step 1), add:

```js
var scenarioSrcCollapsed = { em: {}, other: {}, search: {} };
```

- [ ] **Step 2: Give `renderScenarioTileGroup` a `viewKey` and make headers collapsible**

Replace the function added in Task 4 Step 2:

```js
function renderScenarioTileGroup(viewKey, list) {
  var bySrc = { builtin: [], custom: [], intel: [] };
  list.forEach(function(s) { bySrc[scenarioSourceOf(s)].push(s); });
  return SCENARIO_SOURCE_ORDER.map(function(k) {
    if (!bySrc[k].length) return '';
    var collapsed = !!(scenarioSrcCollapsed[viewKey] && scenarioSrcCollapsed[viewKey][k]);
    return '<div class="sc-src-group">' +
      '<div class="sc-src-hdr' + (collapsed ? ' collapsed' : '') + '" onclick="toggleScenarioSrcGroup(\'' + viewKey + '\',\'' + k + '\')">' +
        '<span class="chev">&#9660;</span>' + x(SCENARIO_SOURCE_LABELS[k]) + ' (' + bySrc[k].length + ')' +
      '</div>' +
      '<div class="sc-src-body' + (collapsed ? ' collapsed' : '') + '">' + bySrc[k].map(scenarioTileHTML).join('') + '</div>' +
    '</div>';
  }).join('');
}

function toggleScenarioSrcGroup(viewKey, srcKey) {
  if (!scenarioSrcCollapsed[viewKey]) scenarioSrcCollapsed[viewKey] = {};
  scenarioSrcCollapsed[viewKey][srcKey] = !scenarioSrcCollapsed[viewKey][srcKey];
  renderScenarios();
}
```

- [ ] **Step 3: Update the three call sites to pass `viewKey`**

In `renderScenarios()`, the category branch (Task 5 Step 5) call:

```js
  grid.innerHTML = inCat.length
    ? '<div class="sc-fade">' + renderScenarioTileGroup(inCat) + '</div>'
```

becomes:

```js
  grid.innerHTML = inCat.length
    ? '<div class="sc-fade">' + renderScenarioTileGroup(scenarioView, inCat) + '</div>'
```

and the search branch (Task 6 Step 4) call:

```js
    sgrid.innerHTML = results.length
      ? '<div class="sc-fade">' + renderScenarioTileGroup(results) + '</div>'
```

becomes:

```js
    sgrid.innerHTML = results.length
      ? '<div class="sc-fade">' + renderScenarioTileGroup('search', results) + '</div>'
```

- [ ] **Step 4: Manual checkpoint**

Drill into a category with more than one source represented. Click a source header ("Built-in (n)") → its tile grid collapses, the chevron rotates. Click again → expands. Change the OS filter (which re-renders) → the collapsed state you set persists for that view. Switch categories and back → each category remembers its own collapse state independently (per `viewKey`).

- [ ] **Step 5: Commit**

```bash
git add orchestrator/wwwroot/index.html orchestrator/cmd/server/wwwroot/index.html
git commit -m "feat(ui): collapsible source sub-sections in scenario category view"
git push
```

---

### Task 8: Final polish, full manual verification, cleanup

**Files:**
- Modify: `orchestrator/wwwroot/index.html` (remove now-dead `scenarioCardHTML`, if confirmed unused)

**Interfaces:** none new — this task verifies and tidies what Tasks 1-7 built.

- [ ] **Step 1: Confirm `scenarioCardHTML` is dead code and remove it**

Search the file for remaining calls to `scenarioCardHTML(` outside its own definition:

Run: search the file (e.g. your editor's find, or `grep -n "scenarioCardHTML(" orchestrator/wwwroot/index.html`) — expect only the function's own `function scenarioCardHTML(s) {` definition line as a match.

If confirmed unused, delete the wrapper function (added in Task 2 Step 1):

```js
function scenarioCardHTML(s) {
  var color = s.intelSource ? '#2f81f7' : stripeColor(s.id);
  return '<div class="card"><div class="card-stripe" style="background:' + color + '"></div>' + scenarioDetailHTML(s) + '</div>';
}
```

If anything else still calls it, leave it in place and note where.

- [ ] **Step 2: Static verification**

- Confirm no duplicate element IDs were introduced (`sc-landing`, `sc-category-view`, `sc-backbar-title`, `sc-tile-grid` each appear exactly once in the static markup).
- Confirm every `onclick`/`onmouseenter`/`onmouseleave`/`onkeydown` handler referenced in generated HTML (`openScenarioCategory`, `closeScenarioCategoryView`, `toggleScenarioSrcGroup`, `previewScenarioOverlay`, `unpreviewScenarioOverlay`, `toggleScenarioPin`, plus the untouched `openModal`/`openPicker`/`openBuilder`/`cloneScenario`/`deleteCustomScenario`/`deleteIntelScenario`) is a defined function in the file.
- Confirm `git status` shows **both** `orchestrator/wwwroot/index.html` and `orchestrator/cmd/server/wwwroot/index.html` as modified after each of this plan's edits (hardlink sync check) — if only one shows changed at this final checkpoint, investigate before committing (the hardlink may have been broken by an editor that does copy-on-write instead of in-place edit).

- [ ] **Step 3: Full manual browser walkthrough**

Using the running dashboard (dev server or deployed instance), on the Scenarios tab:

1. Landing shows both category cards with correct total counts and Built-in/Custom/Intel breakdowns matching what the old flat grids showed.
2. Click each category card → correct tiles appear, grouped and labeled by source.
3. Hover a tile (mouse) → preview overlay appears; move mouse away → disappears without a click.
4. Click a tile → overlay pins; move the mouse anywhere (including diagonally off the tile) → overlay stays open.
5. Click the pinned tile again, or click elsewhere on the page → overlay closes.
6. Tab to a tile via keyboard, press Enter → overlay pins; press Escape → closes, focus returns to the tile.
7. Every button inside an open overlay (Run, Clone, Edit, Delete, Customize, posture-check/step-picker links) performs its original action and does not itself close the overlay as a side effect.
8. Overlay never clips off the right edge of the viewport, at any tile position/window width.
9. OS filter and source filter narrow both the landing counts and the category/search tile grids correctly.
10. Typing a query from the landing page, and separately from inside a category, both land on the same explicit "Search results for…" view; clearing the box (or clicking Back) returns cleanly to the landing.
11. Browser Back/Forward buttons move correctly between landing and a drilled-in category/search view.
12. Leaving the Scenarios tab and returning always resets to the landing page.
13. Collapse/expand works per source group and is remembered per view during the session.
14. Threat Actor Library section (untouched) still renders and behaves exactly as before.
15. 150-200ms fade is visible on landing → category and category → landing transitions, and on overlay open.

- [ ] **Step 4: Final commit**

```bash
git add orchestrator/wwwroot/index.html orchestrator/cmd/server/wwwroot/index.html
git commit -m "chore(ui): remove dead scenarioCardHTML after drill-down migration"
git push
```

(Skip this commit if Step 1 found `scenarioCardHTML` still in use — in that case this task has nothing left to commit.)
