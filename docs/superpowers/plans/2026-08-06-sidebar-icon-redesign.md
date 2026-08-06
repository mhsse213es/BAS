# Sidebar Icon Redesign Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace 11 duplicate/near-duplicate sidebar nav icons in `orchestrator/wwwroot/index.html` with distinct, semantically-relevant ones, so no two of the 24 left-nav items share a look-alike icon.

**Architecture:** Pure inline-SVG markup swap inside the existing `<nav class="sidebar-nav">` block — each changed item's `<svg class="nav-icon">`'s inner shape content is replaced with new path/rect/circle data. No JS, no CSS, no structural/attribute changes.

**Tech Stack:** Static HTML/inline SVG, no build step.

## Global Constraints

- Only the 11 items named in the spec change. Everything else in the sidebar (labels, `data-tab`, `onclick`, grouping, the 13 icons already kept) stays byte-identical.
- Every replacement icon uses the exact SVG shape data already finalized and visually approved in the spec — no re-designing icons during implementation.
- The `<svg class="nav-icon" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4">` wrapper attributes are unchanged for every item — only the shapes inside it change.

---

### Task 1: Replace the 11 icons

**Files:**
- Modify: `orchestrator/wwwroot/index.html:1291-1421` (11 separate edits within this range, exact current line numbers per item given in each step below)

**Interfaces:** None — this is a leaf UI change with no other code depending on icon shapes.

- [ ] **Step 1: Coverage** (currently line 1291-1296)

Replace:
```html
        <div class="nav-item" data-tab="coverage" onclick="showTab('coverage')">
          <svg class="nav-icon" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4">
            <circle cx="8" cy="8" r="6"/><circle cx="8" cy="8" r="2.4"/>
          </svg>
          Coverage
        </div>
```
with:
```html
        <div class="nav-item" data-tab="coverage" onclick="showTab('coverage')">
          <svg class="nav-icon" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4">
            <path d="M2 12a6 6 0 0 1 12 0"/><path d="M8 12L11 7"/><circle cx="8" cy="12" r="1" fill="currentColor" stroke="none"/>
          </svg>
          Coverage
        </div>
```

- [ ] **Step 2: Variants** (currently line 1297-1303)

Replace:
```html
        <div class="nav-item" data-tab="variants" onclick="showTab('variants')">
          <svg class="nav-icon" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4">
            <rect x="1" y="1" width="6" height="6" rx="1"/><rect x="9" y="1" width="6" height="6" rx="1"/>
            <rect x="1" y="9" width="6" height="6" rx="1"/><rect x="9" y="9" width="6" height="6" rx="1"/>
          </svg>
          Variants
        </div>
```
with:
```html
        <div class="nav-item" data-tab="variants" onclick="showTab('variants')">
          <svg class="nav-icon" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4">
            <path d="M8 1.5 14.5 5.2 8 8.9 1.5 5.2z"/><path d="M1.5 8.2 8 11.9 14.5 8.2"/><path d="M1.5 11.2 8 14.9 14.5 11.2"/>
          </svg>
          Variants
        </div>
```

- [ ] **Step 3: Endpoint Mastery** (currently line 1304-1310)

Replace:
```html
        <div class="nav-item" data-tab="em" onclick="showTab('em')">
          <svg class="nav-icon" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4">
            <path d="M8 1.5l5 2v4c0 3-2 5.2-5 6.5C5 12.7 3 10.5 3 7.5v-4z"/>
            <path d="M5.5 8l1.5 1.5 3-3"/>
          </svg>
          Endpoint Mastery
        </div>
```
with:
```html
        <div class="nav-item" data-tab="em" onclick="showTab('em')">
          <svg class="nav-icon" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4">
            <circle cx="8" cy="6" r="4.2"/><path d="M8 3.8l.7 1.6 1.7.2-1.3 1.1.4 1.7L8 7.5l-1.5.9.4-1.7-1.3-1.1 1.7-.2z" fill="currentColor" stroke="none"/><path d="M5.5 9.7L4 15l4-2 4 2-1.5-5.3"/>
          </svg>
          Endpoint Mastery
        </div>
```

- [ ] **Step 4: Findings** (currently line 1314-1319)

Replace:
```html
        <div class="nav-item" data-tab="findings" onclick="showTab('findings')">
          <svg class="nav-icon" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4">
            <path d="M3 14V2.5h8L9.5 5.5 11 8.5H3"/>
          </svg>
          Findings
        </div>
```
with:
```html
        <div class="nav-item" data-tab="findings" onclick="showTab('findings')">
          <svg class="nav-icon" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4">
            <path d="M3 1.5v13"/><path d="M3 2h9l-2 2.5L12 7H3z"/>
          </svg>
          Findings
        </div>
```

- [ ] **Step 5: IOC Registry** (currently line 1320-1325)

Replace:
```html
        <div class="nav-item" data-tab="iocs" onclick="showTab('iocs')">
          <svg class="nav-icon" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4">
            <circle cx="8" cy="8" r="5.5"/><circle cx="8" cy="8" r="1.6"/><path d="M8 1v2.2M8 12.8V15M1 8h2.2M12.8 8H15"/>
          </svg>
          IOC Registry
        </div>
```
with:
```html
        <div class="nav-item" data-tab="iocs" onclick="showTab('iocs')">
          <svg class="nav-icon" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4">
            <path d="M9 2h4.5c.3 0 .5.2.5.5V7L6.5 14.5 1.5 9.5 9 2z"/><circle cx="11" cy="5" r="1" fill="currentColor" stroke="none"/>
          </svg>
          IOC Registry
        </div>
```

- [ ] **Step 6: Remediation** (currently line 1326-1331)

Replace:
```html
        <div class="nav-item" data-tab="remediation" onclick="showTab('remediation')">
          <svg class="nav-icon" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4">
            <path d="M6.5 2.5l3 3-4.5 4.5-3-3z"/><path d="M9 6l3.5-3.5a2 2 0 0 0-2.8-2.8L6 3"/><path d="M4.5 11.5l-2.5 2.5"/>
          </svg>
          Remediation
        </div>
```
with:
```html
        <div class="nav-item" data-tab="remediation" onclick="showTab('remediation')">
          <svg class="nav-icon" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4">
            <path d="M11 2.5a3 3 0 0 0-3.9 3.9L2 11.5 4.5 14l5.1-5.1A3 3 0 0 0 13.5 5l-2.1 2.1-1.5-1.5z"/>
          </svg>
          Remediation
        </div>
```

- [ ] **Step 7: Exposure Explorer** (currently line 1352-1357)

Replace:
```html
        <div class="nav-item" data-tab="exposure" onclick="showTab('exposure')">
          <svg class="nav-icon" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4">
            <circle cx="8" cy="8" r="6"/><circle cx="8" cy="8" r="2.2"/>
          </svg>
          Exposure Explorer
        </div>
```
with:
```html
        <div class="nav-item" data-tab="exposure" onclick="showTab('exposure')">
          <svg class="nav-icon" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4">
            <rect x="3" y="7" width="10" height="7" rx="1"/><path d="M5 7V4.5a3 3 0 0 1 5.6-1.5"/><circle cx="8" cy="10.3" r="1" fill="currentColor" stroke="none"/>
          </svg>
          Exposure Explorer
        </div>
```

- [ ] **Step 8: Recommendations** (currently line 1358-1363)

Replace:
```html
        <div class="nav-item" data-tab="recommendations" onclick="showTab('recommendations')">
          <svg class="nav-icon" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4">
            <path d="M8 1.5l1.8 4.1 4.2.4-3.2 2.8 1 4.2L8 10.8 4.2 13l1-4.2L2 6l4.2-.4z"/>
          </svg>
          Recommendations
        </div>
```
with:
```html
        <div class="nav-item" data-tab="recommendations" onclick="showTab('recommendations')">
          <svg class="nav-icon" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4">
            <path d="M8 1.8a4 4 0 0 0-2.3 7.3c.5.4.8 1 .8 1.6v.3h3v-.3c0-.6.3-1.2.8-1.6A4 4 0 0 0 8 1.8z"/><path d="M6.3 13.2h3.4M6.7 14.8h2.6"/>
          </svg>
          Recommendations
        </div>
```

- [ ] **Step 9: Evidence** (disabled item, currently line 1364-1369 — the first of the two `nav-item disabled` divs in this group, distinguish it from Detections' block below it by the `<!--Evidence` comment)

Replace:
```html
        <div class="nav-item disabled">
          <svg class="nav-icon" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4">
            <path d="M1 8s2.5-5 7-5 7 5 7 5-2.5 5-7 5-7-5-7-5z"/><circle cx="8" cy="8" r="2"/>
          </svg>
          <!--Evidence <span class="coming-tag">Soon</span>-->
        </div>
```
with:
```html
        <div class="nav-item disabled">
          <svg class="nav-icon" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4">
            <path d="M1.5 4.5h4l1 1.3H14.5v7.7h-13z"/><circle cx="10" cy="9.5" r="2.3"/><path d="M11.7 11.2 13.3 12.8"/>
          </svg>
          <!--Evidence <span class="coming-tag">Soon</span>-->
        </div>
```

(The `<!--Evidence...-->` comment itself is unchanged — it's currently-inactive markup for when this feature ships, not part of the icon change.)

- [ ] **Step 10: Integrations** (currently line 1386-1392)

Replace:
```html
        <div class="nav-item" id="nav-integrations" data-tab="integrations" onclick="showTab('integrations')" style="display:none">
          <svg class="nav-icon" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4">
            <circle cx="8" cy="8" r="2.5"/>
            <path d="M8 1v2M8 13v2M1 8h2M13 8h2M3.2 3.2l1.4 1.4M11.4 11.4l1.4 1.4M3.2 12.8l1.4-1.4M11.4 4.6l1.4-1.4"/>
          </svg>
          Integrations
        </div>
```
with:
```html
        <div class="nav-item" id="nav-integrations" data-tab="integrations" onclick="showTab('integrations')" style="display:none">
          <svg class="nav-icon" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4">
            <path d="M5.5 1.5v3M10.5 1.5v3M4 4.5h8v3a4 4 0 0 1-8 0z"/><path d="M8 11.5v3"/>
          </svg>
          Integrations
        </div>
```

- [ ] **Step 11: Exercises** (currently line 1393-1398)

Replace:
```html
        <div class="nav-item" data-tab="exercises" onclick="showTab('exercises')">
          <svg class="nav-icon" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4">
            <path d="M2 8h3l2-5 2 10 2-5h3"/>
          </svg>
          Exercises
        </div>
```
with:
```html
        <div class="nav-item" data-tab="exercises" onclick="showTab('exercises')">
          <svg class="nav-icon" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4">
            <path d="M3 1.5v13"/><path d="M3 2.2h9l-2.2 2.3L12 6.8H3z"/><path d="M6.5 2.2v4.6M9.5 2.2v4.6"/>
          </svg>
          Exercises
        </div>
```

- [ ] **Step 12: Technique Coverage** (currently line 1399-1404)

Replace:
```html
        <div class="nav-item" data-tab="attack-coverage" onclick="showTab('attack-coverage')">
          <svg class="nav-icon" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4">
            <path d="M1 1h6v6H1zM9 1h6v6H9zM1 9h6v6H1zM9 9h6v6H9z"/>
          </svg>
          Technique Coverage
        </div>
```
with:
```html
        <div class="nav-item" data-tab="attack-coverage" onclick="showTab('attack-coverage')">
          <svg class="nav-icon" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4">
            <rect x="1" y="1" width="4" height="4"/><rect x="6" y="1" width="4" height="4"/><rect x="11" y="1" width="4" height="4"/><rect x="1" y="6" width="4" height="4"/><rect x="6" y="6" width="4" height="4"/><rect x="11" y="6" width="4" height="4"/><rect x="1" y="11" width="4" height="4"/><rect x="6" y="11" width="4" height="4"/><rect x="11" y="11" width="4" height="4"/>
          </svg>
          Technique Coverage
        </div>
```

- [ ] **Step 13: Verify the syntax is still valid**

Run:

```bash
node -e "
  const fs = require('fs');
  const html = fs.readFileSync('orchestrator/wwwroot/index.html', 'utf8');
  const m = html.match(/<script>([\s\S]*)<\/script>/);
  new Function(m[1]);
  console.log('script block parses OK');
"
```

Expected: `script block parses OK`. (This is a formality — none of the 12 edits above touch anything inside `<script>` — but it's a cheap, fast confirmation nothing else was accidentally disturbed.)

- [ ] **Step 14: Confirm no icon shape is duplicated anymore**

Run: `grep -c 'rect x="1" y="1" width="6" height="6" rx="1"' orchestrator/wwwroot/index.html`
Expected: `0` (the old 2×2-grid shape that Dashboard, Variants, and Technique Coverage all shared is now gone from Variants and Technique Coverage — only Dashboard's own, unchanged, should remain if this pattern existed uniquely there, but Dashboard's grid uses the identical rect pattern too, so this specific grep will still find Dashboard's copy — that's correct and expected, not a bug).

Run instead, to directly confirm each replaced shape is gone from its old location and the new one is present:

```bash
grep -n 'data-tab="coverage"' -A 3 orchestrator/wwwroot/index.html
grep -n 'data-tab="variants"' -A 3 orchestrator/wwwroot/index.html
grep -n 'data-tab="em"' -A 4 orchestrator/wwwroot/index.html
grep -n 'data-tab="findings"' -A 3 orchestrator/wwwroot/index.html
grep -n 'data-tab="iocs"' -A 3 orchestrator/wwwroot/index.html
grep -n 'data-tab="remediation"' -A 3 orchestrator/wwwroot/index.html
grep -n 'data-tab="exposure"' -A 3 orchestrator/wwwroot/index.html
grep -n 'data-tab="recommendations"' -A 3 orchestrator/wwwroot/index.html
grep -n 'data-tab="integrations"' -A 4 orchestrator/wwwroot/index.html
grep -n 'data-tab="exercises"' -A 3 orchestrator/wwwroot/index.html
grep -n 'data-tab="attack-coverage"' -A 3 orchestrator/wwwroot/index.html
```

Expected: each block's SVG inner content visually matches the "with" version from its corresponding step above, not the "Replace" (old) version.

- [ ] **Step 15: Manual browser verification**

No automated frontend test framework exists for this file. Open the dashboard in a browser and confirm:

1. All 24 sidebar items still render an icon (nothing went blank/broken).
2. Visually scan the sidebar top to bottom — no two icons look alike anymore (Dashboard's grid vs. Technique Coverage's denser grid should read as clearly different; Coverage's gauge vs. Exposure Explorer's padlock should read as clearly different; etc.).
3. Click through a few of the changed items (Coverage, Variants, Remediation, Exercises) — confirm each still navigates to its correct tab (this change never touched `onclick`/`data-tab`, but a quick click-through catches any accidental markup corruption from the edits).
4. If `nav-integrations` or `nav-settings` are visible for your test user's role, confirm those two still render correctly too (they're hidden by default via inline `style="display:none"` and only shown by role-gating JS elsewhere — unaffected by this change, but worth a glance if visible).

If any of these fail, stop and report — do not proceed to commit with a visibly broken sidebar.

- [ ] **Step 16: Commit**

```bash
git add orchestrator/wwwroot/index.html
git commit -m "$(cat <<'EOF'
fix(dashboard): redesign 11 sidebar nav icons to remove duplicates

Comparing against a competitor screenshot surfaced 4 groups of
duplicate/near-duplicate sidebar icons (Dashboard/Variants/Technique
Coverage all sharing a grid icon, Coverage/Exposure Explorer sharing
a circle icon, Endpoint Mastery/Verification sharing a shield-check
icon, Settings/Integrations sharing a gear icon) plus a 5th near-dup
(Recommendations/Threat Prioritization both using a star). Redesigned
the 11 losing icons to distinct, semantically-relevant shapes -- same
inline-SVG style as the rest of the sidebar, no new CSS/JS, no
changes to labels or navigation wiring. Reviewed and approved as a
full before/after mockup via the visual-companion brainstorming tool
before implementation.
EOF
)"
git push
```

---

## Self-Review Notes

- **Spec coverage:** all 11 redesigned icons from the spec's table are covered, one step each (Steps 1-12, with Step 9 covering the disabled Evidence item explicitly called out in the spec). The 13 kept-unchanged icons are untouched by any step. Non-goals (icon system change, nav structure change, competitor glyph copying, disabled-item behavior change) are not implemented anywhere in this plan.
- **Placeholder scan:** none — every step has the exact literal old/new HTML.
- **Type consistency:** N/A — this is markup only, no functions/types crossing task boundaries. Every replacement SVG string matches verbatim what's recorded in the spec's Implementation section.
