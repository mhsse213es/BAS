# G1e — Strict style CSP Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Serve the Audspect dashboard with `style-src 'self'` by moving every inline style into stylesheet classes or validated CSS custom properties, without changing rendered appearance, proven by a dual-build computed-style and screenshot comparison.

**Architecture:** A codemod converts each literal inline style into a deterministic generated class (`g1-s-<sha8>`, declarations verbatim) in an unlayered `styles/inline-equivalent.css`, while `app.css` moves into `@layer app`, so generated rules hold the cascade position inline styles held. Data-driven declarations become one-declaration classes (`g1-v-<sha8>`) whose value is a custom property set by a trusted hydrator after type and `CSS.supports` validation. JS that read or cleared inline styles goes through small helpers (`setDisplay`, `displayOf`, `replaceClasses`, `setCssText`, `clearInlineStyle`) that emulate the old inline behaviour exactly.

**Tech Stack:** esbuild 0.28.2 bundle, ES modules, jsdom + `node --test` unit tests, Playwright 1.63.0 in the pinned image, espree (already in `node_modules` via ESLint) for the JS codemods, Python 3 stdlib checks, Go 1.26 for the server policy.

**Spec:** `docs/superpowers/specs/2026-10-06-g1e-strict-style-csp-design.md` (approved 2026-10-06, commit `35e96d5c`). Predecessor plan: `docs/superpowers/plans/2026-10-05-g1d-strict-csp.md` — G1e starts only after G1d's final whole-branch review closes.

## Global Constraints

- Contract: G1e may change implementation, but must not intentionally change rendered appearance. No consolidation, normalization, "close enough" values or redesign.
- Final policy: `default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'self'; object-src 'none'; frame-ancestors 'none'; report-uri /api/csp-report` — `dashboardCSP` (orchestrator/cmd/server/static.go) and `orchestrator/web/tests/smoke/csp-policy.txt` byte-identical.
- Static presentation → class; runtime data → validated CSS custom property; behaviour/state → class. No generic set-any-style helper.
- The 400 `el.style.<prop> = …` CSSOM writes stay (except `display`, routed through `setDisplay`, Task 5).
- Visual comparison: viewport 1440×900, deviceScaleFactor 1, `Date` fixed at 2026-01-15T12:00:00Z, seeded `Math.random`, all CSS animations/transitions finished or paused at 0, `document.fonts.ready`, network idle; screenshots byte-identical; computed-style diff empty; allowlist entries need a `reason`.
- Work on `main`; commit and push after every commit; stage files by name; never stage `.claude/settings.local.json`, `go.work.sum`, `Assessment/COMPETITIVE_ANALYSIS.html`, `orchestrator/staging-loadtest-linux`, `docs/superpowers/plans/2026-10-04-g1b-xss-ci-regression-guard.md`, `orchestrator/web/eslint-browser-globals.json`; no directory-level `git checkout --`, `git clean`, `git stash`, resets.
- Commit trailer: `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.
- Node only in the pinned images (`orchestrator/web/tools/node.sh`, `tools/smoke.sh`, `tools/visual.sh`), `npm ci --ignore-scripts`, no new npm dependencies (espree and jsdom are already installed). Python 3 stdlib on the host.
- Bash heredocs on the Windows host mangle backslashes: create/edit files with the Write/Edit tools.
- Proven G1 scripts (`scripts/g1-*.py`, `g1-run-local.sh`) unmodified; the G1 guard (`PYTHONIOENCODING=utf-8 bash scripts/g1-run-local.sh`), `python3 scripts/g1d-check-actions.py`, lint, `npm test`, build, `tools/smoke.sh dist` (2 passed) and — from Task 1 on — `tools/visual.sh` stay green on every commit. Commit regenerated `Assessment/G1_*` if the guard rewrites them.
- Comments and strings in new source must not contain the literal text `style=` (the ratchet counts it); write "style attribute".

## Spec corrections (found while planning — confirm at plan review)

These tighten the spec where its stated mechanism would not reproduce the old rendering. Each is the smallest change that keeps the spec's contract.

- **C1 — display semantics (spec §4.3).** Mapping hide writes to `classList.add('is-hidden')` is not equivalent: after `el.style.display = 'flex'` (inline) a later `classList.add` cannot hide it. And reads (`el.style.display !== 'none'`, 15 sites) would see `''` instead of `'none'` on an initially hidden element. Plan: every `.style.display` write becomes `setDisplay(el, v)` (sets inline, and when `v` is `''`/`null` also removes `is-hidden`/`g1-display-*`), every read becomes `displayOf(el)` (inline value, else the value the display class stands for). Equivalent for every write sequence. Literal `display:<v>` declarations get their own class (`is-hidden` for `none`, `g1-display-<v>` otherwise) so clearing display falls back to app.css exactly as before. Reveal still happens by removing `is-hidden` (inside `setDisplay`); `el.style.display = ''` is banned outside the helper.
- **C2 — other inline-style clears.** `el.className = …` (9 sites) would wipe generated classes, where inline styles survived; `el.style.cssText = …` (5) and `removeAttribute('style')` (1) would leave generated classes in place, where the inline style was wiped. Plan: `replaceClasses`, `setCssText`, `clearInlineStyle` emulate the old behaviour. The 11 non-display partial clears (`el.style.borderColor = ''` etc.) are inventoried and handled per site (Task 5).
- **C3 — data-driven value validation (spec §4.4).** Fixed ranges (0–100 %, 1–24) would drop values the browser rendered (e.g. 105 %), and a valid-at-parse custom property that turns out invalid falls back to `unset`, not to the app.css value an invalid inline declaration fell back to. Plan: one declaration per `g1-v` class; the hydrator renders the declaration value from typed placeholders (types limit the character set: `color`, `number`, `integer`), checks it with `CSS.supports(prop, value)` exactly as the browser parsed the inline declaration, and only then sets the custom property and adds the class. Invalid values are dropped — the same outcome as before.
- **C4 — log level.** Dropped values are logged with `console.warn`, not `console.error`: the browser silently discarded such declarations before (e.g. `color: undefined`), and the smoke harness fails on any new `console.error`.
- **C5 — fixture coverage is enforced by the harness**, not by a one-off fixture pass: the dual build serves the same current fixtures to both trees, so fixtures can grow during Phase 3; every `g1-v` rule must render in some checkpoint or be listed in `UNREACHABLE_RULES` with a reason.

## Review Focus

- Code that measures layout synchronously right after inserting a template (before the hydrator's microtask) — it would read un-hydrated sizes; reviewers check every `offset*`/`getBoundingClientRect` near a converted template.
- Data values the color pattern rejects but CSS accepts (e.g. `hsl(var(--x))`) — dropped where they rendered before; the harness only catches those the fixtures exercise.
- A template whose tag spans several string pieces so the codemod cannot see an existing `class` attribute — a second `class` attribute would be silently ignored; the codemod reports such sites, and Task 6's tests pin that it never emits a second `class`.
- Literal and dynamic declarations on one element that overlap (shorthand/longhand) in an order the class specificity cannot reproduce — the split tool must refuse; Task 6's tests pin the refusal.
- Elements re-rendered by assigning `className` or `cssText` in code paths the fixtures never reach — the mechanical helpers cover them regardless of reachability; Task 5's tests pin each helper's equivalence over full write sequences.

---

## File structure

| File | Responsibility | Task |
|---|---|---|
| `orchestrator/web/tests/smoke/harness.mjs` (new) | Shared page helpers moved out of `smoke.spec.mjs` (`normalize`, `boot`, tab and drawer helpers) plus `makeDeterministic` | 1 |
| `orchestrator/web/tests/visual/{playwright.config.mjs,capture.mjs,compare.mjs,checkpoints.mjs,visual.spec.mjs,selftest.spec.mjs,props.json,BASELINE_REF,g1e-visual-allowlist.json}` (new) | Dual-build comparison | 1 |
| `orchestrator/web/tools/visual.sh` (new) | Extract baseline tree, build both, run the comparison in the pinned image | 1 |
| `orchestrator/web/tools/g1e-props.mjs` (new) | One-time: property list from the pre-migration inline styles | 1 |
| `orchestrator/web/tests/unit/visual-compare.test.mjs` (new) | `compare.mjs` unit tests | 1 |
| `.github/workflows/test.yml` | `web-visual` job (Task 1), removed at exit (Task 11) | 1, 11 |
| `orchestrator/web/src/core/css-vars.js` (new) | `TYPES`, `cssVars()`, `applyCssVars()`, `installCssVars()` | 2 |
| `orchestrator/web/src/core/css-var-rules.js` (new) | Registry of `g1-v` rules (`{prop, value, types}`), maintained by the codemod | 2 |
| `orchestrator/web/styles/index.css` (new), `styles/inline-equivalent.css` (new) | CSS bundle entry (`app.css` in `@layer app`, then the unlayered generated rules) | 3 |
| `orchestrator/web/tools/build.mjs`, `tests/unit/build.test.mjs` | CSS entry switch + layer assertions | 3 |
| `scripts/g1d-check-actions.py`, `scripts/test_g1d_check_actions.py`, `scripts/g1d-inline-baseline.json` | `inline_styles` ratchet + generated-class consistency | 4 |
| `orchestrator/web/src/core/inline-style.js` (new) | `setDisplay`, `displayOf`, `replaceClasses`, `setCssText`, `clearInlineStyle`, `GENERATED` | 5 |
| `orchestrator/web/tools/g1e-js-codemod.mjs` (new, deleted at exit) | Mechanical rewrite of display reads/writes, `className`, `cssText`, `removeAttribute('style')` | 5 |
| `docs/superpowers/specs/g1e-reveal-inventory.md` (new, kept) | Every rewritten site, before → after | 5 |
| `orchestrator/web/tools/g1e-codemod.mjs` (new, deleted at exit) | Style codemod: markup, templates, `--split`, `--class`, `--check-determinism` | 6 |
| `orchestrator/web/index.html`, `src/features/*.js`, `tests/smoke/fixtures.mjs`, `tests/visual/checkpoints.mjs` | Conversion | 7–10 |
| `orchestrator/cmd/server/static.go`, `static_test.go`, `tests/smoke/csp-policy.txt`, `eslint.config.mjs` | Exit | 11 |

---

### Task 1: Dual-build visual equivalence harness

**Files:**
- Create: `orchestrator/web/tests/smoke/harness.mjs`, `orchestrator/web/tests/visual/*` (listed above), `orchestrator/web/tools/visual.sh`, `orchestrator/web/tools/g1e-props.mjs`, `orchestrator/web/tests/unit/visual-compare.test.mjs`
- Modify: `orchestrator/web/tests/smoke/smoke.spec.mjs` (import helpers instead of defining them), `orchestrator/web/.gitignore` (add `.visual/`), `.github/workflows/test.yml` (new `web-visual` job)

**Interfaces:**
- Consumes: G1d end state of `tests/smoke/smoke.spec.mjs` (its `normalize`, `boot`, tab discovery/opening helpers, `DRAWERS` and the drawer-opening code), `tests/smoke/serve.mjs <root> <port>` (no CSP header unless `SMOKE_CSP` is set).
- Produces: `harness.mjs` exports `normalize(msg)`, `boot(page, origin = '')` → `errors[]`, `makeDeterministic(page)`, `tabNames(page)` → `string[]`, `openTab(page, name)`, `DRAWERS` (array, each with a `name`), `openDrawer(page, drawer)`; `capture.mjs` exports `settle(page)`, `snapshotStyles(page, props)` → `{[path]: string}`, `screenshot(page, masks)` → `Buffer`, `runSteps(page, steps)`, `elementPath(page, selector)` → `string`; `compare.mjs` exports `SEP`, `compareStyles(checkpoint, base, head, props)` → `diff[]`, `validateAllowlist(entries)`, `isAllowed(diff, entries)`, `masksFor(checkpoint, entries)`, `formatDiff(diff)`; `checkpoints.mjs` exports `CHECKPOINTS`, `UNREACHABLE_SITES`, `UNREACHABLE_RULES`; `tools/visual.sh` (exit 0 = identical).

- [ ] **Step 1: Record the baseline.** Confirm G1d is closed (its ledger's last line is the final review) and that HEAD's app sources equal the G1d end commit:

```bash
cd /c/Users/Administrator/Downloads/Audspect_Cloud
git rev-parse HEAD > orchestrator/web/tests/visual/BASELINE_REF
cat orchestrator/web/tests/visual/BASELINE_REF
```
Expected: a 40-hex commit hash — the G1d end commit. Every later task compares against this tree.

- [ ] **Step 2: Failing unit test for the comparator** — `orchestrator/web/tests/unit/visual-compare.test.mjs`:

```js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { SEP, compareStyles, validateAllowlist, isAllowed, masksFor, formatDiff } from '../visual/compare.mjs';

const props = ['color', 'margin-top'];
const row = (...v) => v.join(SEP);

test('identical snapshots produce no diffs', () => {
  const s = { body: row('rgb(0, 0, 0)', '0px'), 'body>div:0': row('red', '4px') };
  assert.deepEqual(compareStyles('tab:a', s, { ...s }, props), []);
});

test('a changed property is reported with path, property and both values', () => {
  const base = { 'body>div:0': row('red', '4px') };
  const head = { 'body>div:0': row('red', '5px') };
  assert.deepEqual(compareStyles('tab:a', base, head, props), [
    { checkpoint: 'tab:a', path: 'body>div:0', property: 'margin-top', base: '4px', head: '5px' },
  ]);
});

test('a structural difference is reported as a missing or extra element', () => {
  const d = compareStyles('tab:a', { 'body>p:0': row('a', 'b') }, { 'body>span:0': row('a', 'b') }, props);
  assert.deepEqual(d.map((x) => [x.path, x.base, x.head]), [['body>p:0', 'present', 'missing'], ['body>span:0', 'missing', 'present']]);
});

test('allowlist entries need a reason and known keys', () => {
  assert.throws(() => validateAllowlist([{ checkpoint: 'tab:a', property: 'color' }]), /reason/);
  assert.throws(() => validateAllowlist([{ checkpoint: 'tab:a', reason: 'x', colour: 'y' }]), /unknown key/);
  assert.doesNotThrow(() => validateAllowlist([{ checkpoint: 'tab:a', path: 'body>div:0', property: 'color', reason: 'subpixel AA' }]));
});

test('isAllowed matches checkpoint and the given fields only', () => {
  const d = { checkpoint: 'tab:a', path: 'body>div:0', property: 'color', base: 'a', head: 'b' };
  assert.equal(isAllowed(d, [{ checkpoint: 'tab:a', property: 'color', reason: 'r' }]), true);
  assert.equal(isAllowed(d, [{ checkpoint: 'tab:b', property: 'color', reason: 'r' }]), false);
  assert.equal(isAllowed(d, [{ checkpoint: 'tab:a', path: 'body>div:1', reason: 'r' }]), false);
  assert.equal(isAllowed(d, [{ checkpoint: 'tab:a', mask: '#clock', reason: 'r' }]), false);
});

test('masksFor returns the screenshot masks of one checkpoint', () => {
  const e = [{ checkpoint: 'tab:a', mask: '#clock', reason: 'r' }, { checkpoint: 'tab:b', mask: '#x', reason: 'r' }];
  assert.deepEqual(masksFor('tab:a', e), ['#clock']);
});

test('formatDiff names everything needed to find the element', () => {
  assert.equal(formatDiff({ checkpoint: 'tab:a', path: 'body>div:0', property: 'color', base: 'red', head: 'blue' }),
    'tab:a  body>div:0  color: red -> blue');
});
```

- [ ] **Step 3: Run it** — `cd orchestrator/web && tools/node.sh sh -c 'node --test tests/unit/visual-compare.test.mjs'` → FAIL: `Cannot find module '../visual/compare.mjs'`.

- [ ] **Step 4: Implement `orchestrator/web/tests/visual/compare.mjs`:**

```js
// Pure comparison logic for the G1e dual-build harness (spec section 5).
export const SEP = '\u0001';
const KEYS = new Set(['checkpoint', 'path', 'property', 'mask', 'reason']);

export function compareStyles(checkpoint, base, head, props) {
  const diffs = [];
  for (const path of Object.keys(base)) {
    if (!(path in head)) diffs.push({ checkpoint, path, property: '(element)', base: 'present', head: 'missing' });
  }
  for (const path of Object.keys(head)) {
    if (!(path in base)) diffs.push({ checkpoint, path, property: '(element)', base: 'missing', head: 'present' });
  }
  for (const [path, b] of Object.entries(base)) {
    const h = head[path];
    if (h === undefined || h === b) continue;
    const bv = b.split(SEP);
    const hv = h.split(SEP);
    props.forEach((property, i) => {
      if (bv[i] !== hv[i]) diffs.push({ checkpoint, path, property, base: bv[i], head: hv[i] });
    });
  }
  return diffs;
}

export function validateAllowlist(entries) {
  if (!Array.isArray(entries)) throw new Error('allowlist must be an array');
  for (const e of entries) {
    for (const k of Object.keys(e)) if (!KEYS.has(k)) throw new Error(`allowlist: unknown key ${k}`);
    if (typeof e.reason !== 'string' || !e.reason.trim()) throw new Error(`allowlist: entry without reason: ${JSON.stringify(e)}`);
    if (typeof e.checkpoint !== 'string') throw new Error(`allowlist: entry without checkpoint: ${JSON.stringify(e)}`);
  }
  return entries;
}

export function isAllowed(diff, entries) {
  return entries.some((e) => e.mask === undefined && e.checkpoint === diff.checkpoint
    && (e.path === undefined || e.path === diff.path)
    && (e.property === undefined || e.property === diff.property));
}

export function masksFor(checkpoint, entries) {
  return entries.filter((e) => e.checkpoint === checkpoint && e.mask !== undefined).map((e) => e.mask);
}

export function formatDiff(d) {
  return `${d.checkpoint}  ${d.path}  ${d.property}: ${d.base} -> ${d.head}`;
}
```

- [ ] **Step 5: Run it** — same command → PASS 7/7.

- [ ] **Step 6: Generate the property list** — `orchestrator/web/tools/g1e-props.mjs` (deleted at exit; the output is committed because after migration no inline styles remain to derive it from):

```js
// One-time (G1e): every CSS property named in an inline style attribute, in
// markup or JS templates, at the baseline tree. Output: tests/visual/props.json.
import { readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const web = fileURLToPath(new URL('..', import.meta.url));
const files = [join(web, 'index.html')];
(function walk(d) { for (const e of readdirSync(d)) { const p = join(d, e); if (statSync(p).isDirectory()) walk(p); else if (p.endsWith('.js')) files.push(p); } })(join(web, 'src'));
const props = new Set(['display', 'visibility', 'opacity']);
const ATTR = /(?<![\w.-])style=\\?(["'])([\s\S]*?)\\?\1/g;
for (const f of files) {
  for (const m of readFileSync(f, 'utf8').matchAll(ATTR)) {
    for (const decl of m[2].split(';')) {
      const name = decl.split(':')[0].trim().toLowerCase();
      if (/^-?[a-z][a-z-]*$/.test(name)) props.add(name);
    }
  }
}
writeFileSync(join(web, 'tests/visual/props.json'), JSON.stringify([...props].sort(), null, 1) + '\n');
console.log(`props.json: ${props.size} properties`);
```

Run: `tools/node.sh node tools/g1e-props.mjs` → Expected: `props.json: N properties` with N roughly 70–100. Open `props.json` and confirm it holds only property names (e.g. `color`, `font-size`, `padding`, `border-left`), no fragments of JS.

- [ ] **Step 7: Extract the shared smoke helpers.** Create `orchestrator/web/tests/smoke/harness.mjs` by MOVING (not copying) from `smoke.spec.mjs` the function `normalize`, the function `boot`, the tab discovery helper, the tab-opening helper, the `DRAWERS` list and the drawer-opening code, exactly as they exist at the G1d end commit, under the export names in the Interfaces block (rename only if G1d named them differently; `smoke.spec.mjs` then imports them). Two changes while moving:
  - `boot(page, origin = '')` navigates to `` `${origin}/index.html` `` (smoke passes no origin, so its behaviour is unchanged).
  - the drawer-opening code becomes `export async function openDrawer(page, drawer)` (the body of the smoke drawer loop that opens one drawer and waits for its marker); smoke's loop calls it.
  Add:

```js
// Deterministic page for the G1e visual comparison: fixed clock (timers keep
// running) and a seeded Math.random, identical for both builds.
export async function makeDeterministic(page) {
  await page.clock.setFixedTime(new Date('2026-01-15T12:00:00Z'));
  await page.addInitScript(() => {
    let s = 0x2f6b1d3;
    Math.random = () => { s = (Math.imul(s, 1103515245) + 12345) >>> 0; return s / 4294967296; };
  });
}
```
Run `tools/smoke.sh dist` (after `tools/node.sh sh -c 'npm run build'`) → Expected: `2 passed` (pure move).

- [ ] **Step 8: Page-side capture** — `orchestrator/web/tests/visual/capture.mjs`:

```js
// Page-side capture for the G1e harness. Computed styles are keyed by a
// structural path (tag + child index from body); G1e changes attributes only,
// so paths match one-to-one between the builds.
import { SEP } from './compare.mjs';

export async function settle(page) {
  await page.waitForLoadState('networkidle', { timeout: 10_000 }).catch(() => {});
  await page.evaluate(async () => {
    await document.fonts.ready;
    for (const a of document.getAnimations()) {
      const t = a.effect && a.effect.getComputedTiming();
      if (t && t.iterations === Infinity) { a.pause(); a.currentTime = 0; } else { a.finish(); }
    }
  });
}

export async function snapshotStyles(page, props) {
  return page.evaluate(({ props, sep }) => {
    // Expand shorthands to the longhands the browser actually computes.
    const longhands = new Set();
    for (const p of props) {
      const s = document.createElement('div').style;
      s.setProperty(p, 'initial');
      if (s.length) for (let i = 0; i < s.length; i++) longhands.add(s[i]); else longhands.add(p);
    }
    const list = [...longhands].sort();
    const out = { '#props': list.join(sep) };
    (function walk(el, path) {
      const cs = getComputedStyle(el);
      out[path] = list.map((p) => cs.getPropertyValue(p)).join(sep);
      let i = 0;
      for (const c of el.children) walk(c, `${path}>${c.tagName.toLowerCase()}:${i++}`);
    })(document.body, 'body');
    return out;
  }, { props, sep: SEP });
}

export async function elementPath(page, selector) {
  return page.evaluate((sel) => {
    let el = document.querySelector(sel);
    const parts = [];
    while (el && el !== document.body) {
      parts.unshift(`${el.tagName.toLowerCase()}:${[...el.parentElement.children].indexOf(el)}`);
      el = el.parentElement;
    }
    return ['body', ...parts].join('>');
  }, selector);
}

export async function screenshot(page, masks = []) {
  return page.screenshot({ fullPage: true, animations: 'disabled', caret: 'hide', mask: masks.map((m) => page.locator(m)) });
}

export async function runSteps(page, steps) {
  for (const s of steps) {
    if (s.click) await page.click(s.click);
    else if (s.fill) await page.fill(s.fill[0], s.fill[1]);
    else if (s.select) await page.selectOption(s.select[0], s.select[1]);
    else throw new Error(`unknown checkpoint step ${JSON.stringify(s)}`);
    await settle(page);
  }
}
```

Note: `snapshotStyles` returns `#props` as the first key so `compareStyles` is called with that expanded list: `const props = snap['#props'].split(SEP)`.

- [ ] **Step 9: Checkpoints and allowlist.** `orchestrator/web/tests/visual/checkpoints.mjs`:

```js
// Extra G1e checkpoints beyond every tab and every smoke drawer.
// CHECKPOINTS: reveal and data states reachable under the smoke fixtures:
//   { name, tab, steps: [{ click: sel } | { fill: [sel, text] } | { select: [sel, value] }] }
export const CHECKPOINTS = [];
// Reveal sites (docs/superpowers/specs/g1e-reveal-inventory.md) not reachable
// under fixtures: { 'features/x.js:123': 'reason' }.
export const UNREACHABLE_SITES = {};
// g1-v rules (src/core/css-var-rules.js) not rendered by any checkpoint:
// { 'g1-v-0a1b2c3d': 'reason' }.
export const UNREACHABLE_RULES = {};
```
`orchestrator/web/tests/visual/g1e-visual-allowlist.json`: `[]`.

- [ ] **Step 10: The comparison spec** — `orchestrator/web/tests/visual/visual.spec.mjs`:

```js
import { test, expect } from '@playwright/test';
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { boot, makeDeterministic, tabNames, openTab, DRAWERS, openDrawer } from '../smoke/harness.mjs';
import { settle, snapshotStyles, screenshot, runSteps } from './capture.mjs';
import { SEP, compareStyles, validateAllowlist, isAllowed, masksFor, formatDiff } from './compare.mjs';
import { CHECKPOINTS, UNREACHABLE_RULES } from './checkpoints.mjs';

const here = (p) => fileURLToPath(new URL(p, import.meta.url));
const PROPS = JSON.parse(readFileSync(here('./props.json'), 'utf8'));
const ALLOW = validateAllowlist(JSON.parse(readFileSync(here('./g1e-visual-allowlist.json'), 'utf8')));
const BASE = 'http://127.0.0.1:4174';
const HEAD = 'http://127.0.0.1:4175';

async function rules() {
  try { return Object.keys((await import('../../src/core/css-var-rules.js')).CSS_VAR_RULES); } catch { return []; }
}

test('G1e: HEAD renders identically to the baseline build', async ({ browser }, testInfo) => {
  const open = async (origin) => {
    const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 }, deviceScaleFactor: 1 });
    const page = await ctx.newPage();
    await makeDeterministic(page);
    await boot(page, origin);
    return page;
  };
  const problems = [];
  const allowed = [];
  const seenRules = new Set();
  const compare = async (name, pb, ph) => {
    await Promise.all([settle(pb), settle(ph)]);
    const [sb, sh] = await Promise.all([snapshotStyles(pb, PROPS), snapshotStyles(ph, PROPS)]);
    const props = sb['#props'].split(SEP);
    delete sb['#props']; delete sh['#props'];
    for (const d of compareStyles(name, sb, sh, props)) (isAllowed(d, ALLOW) ? allowed : problems).push(formatDiff(d));
    const masks = masksFor(name, ALLOW);
    const [ib, ih] = await Promise.all([screenshot(pb, masks), screenshot(ph, masks)]);
    if (!ib.equals(ih)) {
      const slug = name.replace(/[^a-z0-9]+/gi, '_');
      writeFileSync(testInfo.outputPath(`${slug}.base.png`), ib);
      writeFileSync(testInfo.outputPath(`${slug}.head.png`), ih);
      problems.push(`${name}  screenshot differs (see ${slug}.base.png / ${slug}.head.png)`);
    }
    for (const c of await ph.evaluate(() => [...document.querySelectorAll('[class*="g1-v-"]')].flatMap((e) => [...e.classList]))) {
      if (c.startsWith('g1-v-')) seenRules.add(c);
    }
  };

  let pb = await open(BASE);
  let ph = await open(HEAD);
  const tabs = await tabNames(pb);
  expect(await tabNames(ph)).toEqual(tabs);
  for (const tab of tabs) {
    await Promise.all([openTab(pb, tab), openTab(ph, tab)]);
    await compare(`tab:${tab}`, pb, ph);
  }
  for (const drawer of DRAWERS) {
    await Promise.all([pb.context().close(), ph.context().close()]);
    [pb, ph] = await Promise.all([open(BASE), open(HEAD)]);
    await Promise.all([openDrawer(pb, drawer), openDrawer(ph, drawer)]);
    await compare(`drawer:${drawer.name}`, pb, ph);
  }
  for (const cp of CHECKPOINTS) {
    await Promise.all([pb.context().close(), ph.context().close()]);
    [pb, ph] = await Promise.all([open(BASE), open(HEAD)]);
    await Promise.all([openTab(pb, cp.tab), openTab(ph, cp.tab)]);
    await runSteps(pb, cp.steps);
    await runSteps(ph, cp.steps);
    await compare(`checkpoint:${cp.name}`, pb, ph);
  }
  for (const r of await rules()) {
    if (!seenRules.has(r) && !(r in UNREACHABLE_RULES)) problems.push(`coverage: ${r} rendered by no checkpoint (add a fixture/checkpoint or UNREACHABLE_RULES entry)`);
  }
  for (const r of Object.keys(UNREACHABLE_RULES)) {
    if (seenRules.has(r)) problems.push(`coverage: ${r} is listed unreachable but rendered`);
  }
  for (const a of allowed) console.log(`allowlisted: ${a}`);
  console.log(`checkpoints: ${tabs.length} tabs, ${DRAWERS.length} drawers, ${CHECKPOINTS.length} extra; g1-v rules seen: ${seenRules.size}`);
  expect(problems, 'rendering differs from the baseline build').toEqual([]);
});
```

- [ ] **Step 11: The self-test** — `orchestrator/web/tests/visual/selftest.spec.mjs` proves the comparison bites (both pages load HEAD; one gets a planted change):

```js
import { test, expect } from '@playwright/test';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { boot, makeDeterministic } from '../smoke/harness.mjs';
import { settle, snapshotStyles, screenshot, elementPath } from './capture.mjs';
import { SEP, compareStyles } from './compare.mjs';

const PROPS = JSON.parse(readFileSync(fileURLToPath(new URL('./props.json', import.meta.url)), 'utf8'));
const HEAD = 'http://127.0.0.1:4175';

async function pair(browser) {
  const pages = [];
  for (let i = 0; i < 2; i++) {
    const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 }, deviceScaleFactor: 1 });
    const p = await ctx.newPage();
    await makeDeterministic(p);
    await boot(p, HEAD);
    await settle(p);
    pages.push(p);
  }
  return pages;
}

test('the same build twice is identical (determinism)', async ({ browser }) => {
  const [a, b] = await pair(browser);
  const [sa, sb] = [await snapshotStyles(a, PROPS), await snapshotStyles(b, PROPS)];
  const props = sa['#props'].split(SEP);
  delete sa['#props']; delete sb['#props'];
  expect(compareStyles('self', sa, sb, props)).toEqual([]);
  expect((await screenshot(a)).equals(await screenshot(b))).toBe(true);
});

test('a planted 1px margin change fails the screenshot comparison', async ({ browser }) => {
  const [a, b] = await pair(browser);
  await b.evaluate(() => { document.getElementById('app').style.marginTop = '1px'; });
  expect((await screenshot(a)).equals(await screenshot(b))).toBe(false);
});

test('a planted font-weight change fails the computed-style comparison, naming element and property', async ({ browser }) => {
  const [a, b] = await pair(browser);
  await b.evaluate(() => { document.getElementById('app').style.fontWeight = '900'; });
  const [sa, sb] = [await snapshotStyles(a, PROPS), await snapshotStyles(b, PROPS)];
  const props = sa['#props'].split(SEP);
  delete sa['#props']; delete sb['#props'];
  const path = await elementPath(a, '#app');
  const diffs = compareStyles('self', sa, sb, props);
  expect(diffs).toContainEqual(expect.objectContaining({ path, property: 'font-weight', head: '900' }));
});
```

- [ ] **Step 12: Config and runner.** `orchestrator/web/tests/visual/playwright.config.mjs`:

```js
import { defineConfig } from '@playwright/test';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const web = resolve(here, '../..');
const serve = resolve(web, 'tests/smoke/serve.mjs');

export default defineConfig({
  testDir: here,
  testMatch: /.*\.spec\.mjs$/,
  timeout: 1_800_000,
  workers: 1,
  reporter: [['list']],
  outputDir: resolve(web, '.visual/results'),
  use: { headless: true },
  webServer: [
    { command: `node ${serve} "${resolve(web, '.visual/base/dist')}" 4174`, url: 'http://127.0.0.1:4174/index.html', reuseExistingServer: false },
    { command: `node ${serve} "${resolve(web, 'dist')}" 4175`, url: 'http://127.0.0.1:4175/index.html', reuseExistingServer: false },
  ],
});
```

`orchestrator/web/tools/visual.sh` (mode 755):

```bash
#!/usr/bin/env bash
# G1e visual equivalence: builds the baseline commit (tests/visual/BASELINE_REF)
# and the working tree, then compares them in the pinned Playwright image.
# Exit 0 = identical. .visual/ is removed on success, kept on failure.
set -euo pipefail
WEB="$(cd "$(dirname "$0")/.." && pwd)"
ORCH="$(cd "$WEB/.." && pwd)"
REPO="$(git -C "$WEB" rev-parse --show-toplevel)"
REF="$(tr -d '[:space:]' < "$WEB/tests/visual/BASELINE_REF")"
rm -rf "$WEB/.visual"
mkdir -p "$WEB/.visual/base"
git -C "$REPO" archive "$REF" orchestrator/web | tar -x -C "$WEB/.visual/base" --strip-components=2
IMAGE="mcr.microsoft.com/playwright:v1.63.0-noble@sha256:eff16c30e6f3f4af0a03fa4b706120d5e9b0891c344a27d64559aff5900a4a27"
HOST="$ORCH"
if command -v cygpath >/dev/null 2>&1; then HOST="$(cygpath -m "$ORCH")"; fi
MSYS_NO_PATHCONV=1 docker run --rm --ipc=host -v "$HOST:/o" -w /o/web -e PLAYWRIGHT_IMAGE_VERSION=1.63.0 "$IMAGE" \
  sh -c 'npm ci --ignore-scripts --no-audit --no-fund >/dev/null \
    && ln -sfn /o/web/node_modules .visual/base/node_modules \
    && (cd .visual/base && node tools/build.mjs) \
    && node tools/build.mjs \
    && npx playwright test -c tests/visual/playwright.config.mjs'
rm -rf "$WEB/.visual"
```

Add `.visual/` to `orchestrator/web/.gitignore`.

- [ ] **Step 13: Run it** — `cd orchestrator/web && bash tools/visual.sh`. Expected: `4 passed` (main comparison + 3 self-tests); the main test logs `checkpoints: 25 tabs, <N> drawers, 0 extra; g1-v rules seen: 0`. If the main test fails here, HEAD equals the baseline, so the harness itself is nondeterministic: fix determinism (never allowlist at this step).

- [ ] **Step 14: CI job** — add to `.github/workflows/test.yml` after the `web` job:

```yaml
  web-visual:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - name: G1e visual equivalence (baseline build vs HEAD)
        run: bash orchestrator/web/tools/visual.sh
      - name: Upload visual artifacts on failure
        if: failure()
        uses: actions/upload-artifact@v4
        with:
          name: visual-artifacts
          path: orchestrator/web/.visual/results
```

- [ ] **Step 15: Gate and commit.** Run lint, `npm test` (adds 7), build, `tools/smoke.sh dist` (2 passed), `python3 scripts/g1d-check-actions.py` (OK), G1 guard (PASS, unchanged), `tools/visual.sh` (4 passed).

```bash
git add orchestrator/web/tests/smoke/harness.mjs orchestrator/web/tests/smoke/smoke.spec.mjs orchestrator/web/tests/visual orchestrator/web/tools/visual.sh orchestrator/web/tools/g1e-props.mjs orchestrator/web/tests/unit/visual-compare.test.mjs orchestrator/web/.gitignore .github/workflows/test.yml
git commit -m "test(web): G1e dual-build visual equivalence harness

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
git push
```

---

### Task 2: Typed CSS custom properties (`core/css-vars.js`)

**Files:**
- Create: `orchestrator/web/src/core/css-vars.js`, `orchestrator/web/src/core/css-var-rules.js`, `orchestrator/web/tests/unit/css-vars.test.mjs`
- Modify: `orchestrator/web/src/main.js` (install the hydrator)

**Interfaces:**
- Consumes: `x(s)` from `src/core/escape.js` (HTML attribute escaper used by `on()`).
- Produces: `TYPES` (`color`, `number`, `integer` → RegExp); `CSS_VAR_RULES` in `css-var-rules.js`: `{ [rule: 'g1-v-<8 hex>']: { prop: string, value: string /* with {0}…{n} */, types: string[] } }`; `cssVars(...entries)` where each entry is `[rule, ...values]` → `' data-css-vars="<escaped JSON>"'`; `renderValue(rule, values)` → `string | null`; `applyCssVars(el, supports = (p, v) => CSS.supports(p, v))`; `installCssVars(root = document)`. For a rule `r`, the custom property is `--r` and the CSS rule (Task 6) is `.r.r { <prop>: var(--r); }`.

- [ ] **Step 1: Failing tests** — `orchestrator/web/tests/unit/css-vars.test.mjs`:

```js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { JSDOM } from 'jsdom';
import { TYPES, cssVars, renderValue, applyCssVars } from '../../src/core/css-vars.js';
import { CSS_VAR_RULES } from '../../src/core/css-var-rules.js';

const RULES = {
  'g1-v-00000001': { prop: 'width', value: '{0}%', types: ['number'] },
  'g1-v-00000002': { prop: 'border', value: '1px solid {0}44', types: ['color'] },
  'g1-v-00000003': { prop: 'grid-template-columns', value: 'repeat({0},1fr)', types: ['integer'] },
};
Object.assign(CSS_VAR_RULES, RULES);
// jsdom has no CSS.supports; this stub accepts what a browser would for these rules.
const supports = (prop, v) => (prop === 'width' ? /^\d+(\.\d+)?%$/.test(v)
  : prop === 'border' ? /^1px solid #([0-9a-f]{3}|[0-9a-f]{6})44$/i.test(v)
  : prop === 'grid-template-columns' ? /^repeat\([1-9]\d*,1fr\)$/.test(v) : false);

function el(html) {
  const dom = new JSDOM(`<body>${html}</body>`);
  return dom.window.document.body.firstElementChild;
}

test('type patterns accept their tokens', () => {
  for (const v of ['#abc', '#aabbcc', '#aabbcc22', 'red', 'transparent', 'var(--danger)', 'rgb(1, 2, 3)', 'rgba(1,2,3,0.5)', 'hsl(120 50% 50% / 50%)']) assert.ok(TYPES.color.test(v), v);
  for (const v of ['0', '12', '-3', '33.5', '.5']) assert.ok(TYPES.number.test(v), v);
  for (const v of ['0', '7', '24', '-1']) assert.ok(TYPES.integer.test(v), v);
});

test('type patterns reject anything outside their character set', () => {
  for (const v of ['red;background:url(x)', 'url(x)', 'expression(alert(1))', 'var(--x) !important', 'var(--x);', '#abc"', 'rgb(1,2,3);x', '"red"', 'red blue', '']) assert.equal(TYPES.color.test(v), false, v);
  for (const v of ['1e3', '12px', 'NaN', '', ' 1']) assert.equal(TYPES.number.test(v), false, v);
  for (const v of ['1.5', '', '1 '] ) assert.equal(TYPES.integer.test(v), false, v);
});

test('renderValue substitutes typed values into the declaration template', () => {
  assert.equal(renderValue('g1-v-00000001', [42]), '42%');
  assert.equal(renderValue('g1-v-00000002', ['#ef4444']), '1px solid #ef444444');
  assert.equal(renderValue('g1-v-00000001', ['42;color:red']), null);
  assert.equal(renderValue('g1-v-00000001', [42, 1]), null);
  assert.equal(renderValue('g1-v-00000001', ['x'.repeat(65)]), null);
  assert.equal(renderValue('g1-v-00000001', [{}]), null);
  assert.equal(renderValue('g1-v-ffffffff', [1]), null);
  assert.equal(renderValue('__proto__', [1]), null);
});

test('cssVars output is one inert attribute that round-trips', () => {
  const attr = cssVars(['g1-v-00000002', '"><img src=x onerror=alert(1)>']);
  const e = el(`<div${attr}></div>`);
  assert.equal(e.attributes.length, 1);
  assert.deepEqual(JSON.parse(e.getAttribute('data-css-vars')), [['g1-v-00000002', '"><img src=x onerror=alert(1)>']]);
});

test('applyCssVars sets the property and adds the class for a valid value', () => {
  const e = el(`<div${cssVars(['g1-v-00000001', 37.5], ['g1-v-00000003', 4])}></div>`);
  applyCssVars(e, supports);
  assert.equal(e.style.getPropertyValue('--g1-v-00000001'), '37.5%');
  assert.equal(e.style.getPropertyValue('--g1-v-00000003'), 'repeat(4,1fr)');
  assert.deepEqual([...e.classList].sort(), ['g1-v-00000001', 'g1-v-00000003']);
});

test('an invalid value is dropped like an invalid inline declaration: no property, no class', () => {
  const e = el(`<div${cssVars(['g1-v-00000003', 0], ['g1-v-00000001', 'undefined'], ['g1-v-00000001', 50])}></div>`);
  const warn = console.warn; const seen = []; console.warn = (m) => seen.push(m);
  try { applyCssVars(e, supports); } finally { console.warn = warn; }
  assert.equal(e.style.getPropertyValue('--g1-v-00000003'), '');
  assert.equal(e.classList.contains('g1-v-00000003'), false);
  assert.equal(e.style.getPropertyValue('--g1-v-00000001'), '50%');
  assert.equal(seen.length, 2);
});

test('unregistered rules, malformed JSON and non-array entries are dropped', () => {
  for (const raw of ['not json', '{"a":1}', '[["g1-v-ffffffff",1]]', '[["constructor",1]]', '[[1,2]]', '[null]']) {
    const e = el('<div></div>');
    e.setAttribute('data-css-vars', raw);
    const warn = console.warn; console.warn = () => {};
    try { applyCssVars(e, supports); } finally { console.warn = warn; }
    assert.equal(e.getAttribute('style'), null, raw);
    assert.equal(e.classList.length, 0, raw);
  }
});
```

Note on the `supports` stub: it accepts only what a real browser would for these three rules (e.g. `'1px solid var(--x)44'` is invalid in a browser, so the stub rejects it).

- [ ] **Step 2: Run** — `tools/node.sh sh -c 'node --test tests/unit/css-vars.test.mjs'` → FAIL: cannot find `../../src/core/css-vars.js`.

- [ ] **Step 3: Implement.** `orchestrator/web/src/core/css-var-rules.js`:

```js
// Registry of data-driven declarations (G1e spec 4.4). Maintained by
// tools/g1e-codemod.mjs --split; keys sorted. Each rule is one declaration:
// prop, value template with {0}..{n} placeholders, and one type per placeholder.
export const CSS_VAR_RULES = {
};
```

`orchestrator/web/src/core/css-vars.js`:

```js
// Data-driven style values under style-src 'self' (G1e spec 4.4).
// Templates emit cssVars([rule, ...values]); installCssVars() renders each
// registered rule's declaration value from typed values, checks it with
// CSS.supports exactly as the browser checked the former inline declaration,
// then sets the custom property (CSSOM, which CSP does not govern) and adds
// the rule's class. Invalid values are dropped, as the browser dropped invalid
// inline declarations. Nothing here applies an arbitrary property or value.
import { x } from './escape.js';
import { CSS_VAR_RULES } from './css-var-rules.js';

// Character-set limits per placeholder type (security); validity is CSS.supports.
export const TYPES = {
  color: /^(?:#[0-9a-f]{3,8}|[a-z]+|var\(--[a-z0-9-]+\)|(?:rgba?|hsla?)\([0-9.,%\s/+-]*\))$/i,
  number: /^-?(?:\d+|\d*\.\d+)$/,
  integer: /^-?\d+$/,
};
const MAX_LEN = 64;

export function cssVars(...entries) {
  return ` data-css-vars="${x(JSON.stringify(entries))}"`;
}

export function renderValue(rule, values) {
  const def = Object.hasOwn(CSS_VAR_RULES, rule) ? CSS_VAR_RULES[rule] : null;
  if (!def || !Array.isArray(values) || values.length !== def.types.length) return null;
  const parts = [];
  for (let i = 0; i < values.length; i++) {
    const v = values[i];
    if (typeof v !== 'string' && typeof v !== 'number') return null;
    const s = String(v);
    if (s.length > MAX_LEN || !TYPES[def.types[i]].test(s)) return null;
    parts.push(s);
  }
  return def.value.replace(/\{(\d+)\}/g, (_, i) => parts[Number(i)]);
}

export function applyCssVars(el, supports = (p, v) => CSS.supports(p, v)) {
  let entries = null;
  try { entries = JSON.parse(el.getAttribute('data-css-vars')); } catch { /* malformed */ }
  if (!Array.isArray(entries)) { console.warn('css-vars: malformed data-css-vars dropped'); return; }
  for (const entry of entries) {
    const rule = Array.isArray(entry) && typeof entry[0] === 'string' ? entry[0] : null;
    const value = rule === null ? null : renderValue(rule, entry.slice(1));
    if (value === null || !supports(CSS_VAR_RULES[rule].prop, value)) {
      console.warn(`css-vars: dropped ${JSON.stringify(entry).slice(0, 120)}`);
      continue;
    }
    el.style.setProperty(`--${rule}`, value);
    el.classList.add(rule);
  }
}

export function installCssVars(root = document) {
  for (const el of root.querySelectorAll('[data-css-vars]')) applyCssVars(el);
  new MutationObserver((records) => {
    for (const r of records) {
      if (r.type === 'attributes') { if (r.target.hasAttribute('data-css-vars')) applyCssVars(r.target); continue; }
      for (const n of r.addedNodes) {
        if (n.nodeType !== 1) continue;
        if (n.hasAttribute('data-css-vars')) applyCssVars(n);
        for (const el of n.querySelectorAll('[data-css-vars]')) applyCssVars(el);
      }
    }
  }).observe(root.documentElement || root, { childList: true, subtree: true, attributes: true, attributeFilter: ['data-css-vars'] });
}
```

Note: `renderValue` for an unknown rule returns null before `CSS_VAR_RULES[rule].prop` is read, so the `supports` call is only reached for registered rules.

- [ ] **Step 4: Run** → PASS 7/7.

- [ ] **Step 5: Install at boot.** In `src/main.js`, directly after `installActions(ACTIONS);`: add `installCssVars();` and import it: `import { installCssVars } from './core/css-vars.js';`. Add a unit assertion to the existing boot/ordering test if one exists; otherwise the smoke run proves it loads without error.

- [ ] **Step 6: G1 spike.** Temporarily convert ONE data-driven width in a template to `cssVars` (pick a progress bar `style="width:' + pct + '%"` in a small module), regenerate nothing else, and run the G1 guard. Outcomes:
  - (a) guard PASS with no new REVIEW sink → revert the spike edit (Phase 3 converts it properly) and record "G1 spike (a)" in the report;
  - (b) guard flags the `cssVars(` concatenation → revert, report NEEDS_CONTEXT with the guard output (G1 scripts may not be modified without a controller ruling).

- [ ] **Step 7: Gate and commit.** Lint, `npm test`, build, smoke (2 passed), g1d check OK, G1 guard PASS, `tools/visual.sh` (4 passed, no change — no template uses `cssVars` yet).

```bash
git add orchestrator/web/src/core/css-vars.js orchestrator/web/src/core/css-var-rules.js orchestrator/web/tests/unit/css-vars.test.mjs orchestrator/web/src/main.js
git commit -m "feat(web): typed, CSS.supports-validated custom properties for data-driven styles (G1e)

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
git push
```

---

### Task 3: Cascade layer and the unlayered generated stylesheet

**Files:**
- Create: `orchestrator/web/styles/index.css`, `orchestrator/web/styles/inline-equivalent.css`
- Modify: `orchestrator/web/tools/build.mjs` (CSS entry), `orchestrator/web/tests/unit/build.test.mjs`

**Interfaces:**
- Produces: built `dist/assets/app.<hash>.css` = all of `app.css` (and anything it imports) inside `@layer app { … }`, followed by the unlayered contents of `inline-equivalent.css`; `inline-equivalent.css` format (Task 6 writes it): header comment, then one rule per line, sorted by class name: `.is-hidden { display: none; }`, `.g1-display-<v> { display: <v>; }`, `.g1-s-<h> { <verbatim text> }`, `.g1-v-<h>.g1-v-<h> { <prop>: var(--g1-v-<h>); }`.

- [ ] **Step 1: Failing build test** — append to `orchestrator/web/tests/unit/build.test.mjs`:

```js
test('app.css is bundled inside @layer app and the generated rules follow it unlayered', () => {
  execFileSync('node', ['tools/build.mjs'], { cwd: web, stdio: 'pipe' });
  const name = readdirSync(join(dist, 'assets')).find((f) => /^app\.[A-Z0-9]+\.css$/i.test(f));
  const css = readFileSync(join(dist, 'assets', name), 'utf8');
  const start = css.search(/@layer app\s*\{/);
  assert.ok(start >= 0, 'no @layer app block');
  let depth = 0, end = -1;
  for (let i = css.indexOf('{', start); i < css.length; i++) {
    if (css[i] === '{') depth++;
    else if (css[i] === '}' && --depth === 0) { end = i; break; }
  }
  assert.ok(end > start, 'unterminated @layer app block');
  const inside = css.slice(start, end);
  assert.ok(inside.includes(':root'), 'app.css rules are not inside the layer');
  const after = css.slice(end + 1).replace(/\/\*[\s\S]*?\*\//g, '').trim();
  assert.ok(after.includes('.is-hidden'), 'generated rules missing after the layer');
  for (const line of after.split('\n').map((l) => l.trim()).filter(Boolean)) {
    assert.match(line, /^(\.is-hidden|\.g1-display-[a-z-]+|\.g1-s-[0-9a-f]{8}|\.g1-v-[0-9a-f]{8}\.g1-v-[0-9a-f]{8}) \{ .* \}$/, `unexpected unlayered css: ${line}`);
  }
  assert.ok(!css.slice(0, start).replace(/\/\*[\s\S]*?\*\//g, '').trim().replace(/^@charset[^;]*;/, '').trim(), 'css before the layer');
});
```
Run `tools/node.sh sh -c 'node --test tests/unit/build.test.mjs'` → FAIL: `no @layer app block`.

- [ ] **Step 2: Implement.** `orchestrator/web/styles/inline-equivalent.css`:

```css
/* G1e: former inline style attributes, one rule per line, sorted, declarations
   verbatim (docs/superpowers/specs/2026-10-06-g1e-strict-style-csp-design.md).
   Unlayered, so these rules outrank @layer app exactly as inline styles did. */
.is-hidden { display: none; }
```

`orchestrator/web/styles/index.css`:

```css
/* CSS bundle entry (G1e spec 4.2): app.css in cascade layer "app"; the
   inline-equivalent rules unlayered after it. */
@import "./app.css" layer(app);
@import "./inline-equivalent.css";
```

In `tools/build.mjs` change the entry `'app-css': 'styles/app.css'` to `'app-css': 'styles/index.css'`.

Run the test → PASS. If it fails because esbuild leaves `@import … layer(app)` unbundled, ledger a Ruling and instead make `build.mjs` write `styles/.layered-app.css` = `'@layer app {\n' + readFileSync('styles/app.css') + '\n}\n'` before the build and point `index.css` at it (git-ignore the file); the test is unchanged.

- [ ] **Step 3: Prove zero visual change, including `!important`.** `grep -n '!important' styles/app.css` → list the 11 rules in the report. Run `bash tools/visual.sh` → 4 passed. Inline styles hold no `!important`, so each of those rules beat the inline value before and beats the generated class now (important layered declarations outrank unlayered normal ones); the computed-style comparison is the proof — if it reports a difference, fix it at that rule and record it in the report.

- [ ] **Step 4: Gate and commit** (lint, `npm test`, build, smoke 2 passed, g1d OK, G1 guard PASS, visual 4 passed):

```bash
git add orchestrator/web/styles/index.css orchestrator/web/styles/inline-equivalent.css orchestrator/web/tools/build.mjs orchestrator/web/tests/unit/build.test.mjs
git commit -m "build(web): app.css in @layer app, unlayered inline-equivalent.css (G1e)

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
git push
```

---

### Task 4: Source-level ratchet and generated-class consistency

**Files:**
- Modify: `scripts/g1d-check-actions.py`, `scripts/test_g1d_check_actions.py`, `scripts/g1d-inline-baseline.json`

**Interfaces:**
- Consumes: `styles/inline-equivalent.css` format (Task 3), `src/core/css-var-rules.js` (Task 2), `src/core/css-vars.js`.
- Produces: `counts()` gains `"inline_styles"`; `check()` gains errors `undefined generated class: <c>`, `orphan generated rule: <c>`, `unregistered css-vars rule: <r>`, `data-css-vars outside core/css-vars.js: <file>`; baseline key `inline_styles` (ratchet, may only go down).

- [ ] **Step 1: Failing tests** — in `scripts/test_g1d_check_actions.py`, extend `make()` with `css=None, rules_js=None` (when given, write `styles/inline-equivalent.css` and `src/core/css-var-rules.js`; `css-vars.js` gets `export function cssVars(...e) { return ' data-css-vars=' }` when `rules_js` is given) and add:

```python
class TestStyles(unittest.TestCase):
    def test_inline_styles_counted_in_markup_and_js(self):
        d, _ = make('<p style="color:red"></p>', js="h += '<b style=\"x\"></b>' + '<i style=\\'y\\'></i>'; el.style.color = 'red';")
        self.assertEqual(g.counts(d)["inline_styles"], 3)

    def test_style_tag_in_js_counted(self):
        d, _ = make("<p></p>", js="h = '<style>p{}</style>';")
        self.assertEqual(g.counts(d)["inline_styles"], 1)

    def test_inline_styles_ratchet(self):
        d, b = make('<p style="a"></p>', baseline={"inline_handlers": 0, "javascript_urls": 0, "inline_styles": 0})
        self.assertIn("inline styles: 1 > baseline 0", g.check(d, b))

    def test_undefined_and_orphan_generated_classes(self):
        css = ".is-hidden { display: none; }\n.g1-s-0000000a { color:red }\n"
        d, b = make('<p class="g1-s-0000000b"></p>', css=css)
        errs = g.check(d, b)
        self.assertIn("undefined generated class: g1-s-0000000b", errs)
        self.assertIn("orphan generated rule: g1-s-0000000a", errs)

    def test_consistent_classes_pass(self):
        css = ".is-hidden { display: none; }\n.g1-display-flex { display: flex; }\n.g1-s-0000000a { color:red }\n.g1-v-0000000c.g1-v-0000000c { width: var(--g1-v-0000000c); }\n"
        rules = "export const CSS_VAR_RULES = {\n  'g1-v-0000000c': { prop: 'width', value: '{0}%', types: ['number'] },\n};\n"
        d, b = make('<p class="g1-s-0000000a g1-display-flex"></p>', js="h = '<i' + cssVars(['g1-v-0000000c', 5]) + '>';", css=css, rules_js=rules)
        self.assertEqual([e for e in g.check(d, b) if "generated" in e or "css-vars" in e], [])

    def test_unregistered_css_vars_rule(self):
        css = ".is-hidden { display: none; }\n"
        rules = "export const CSS_VAR_RULES = {\n};\n"
        d, b = make("<p></p>", js="h = '<i' + cssVars(['g1-v-0000000d', 5]) + '>';", css=css, rules_js=rules)
        self.assertIn("unregistered css-vars rule: g1-v-0000000d", g.check(d, b))

    def test_data_css_vars_only_in_css_vars_module(self):
        d, b = make("<p></p>", js="h = '<i data-css-vars=\"[]\">';", css=".is-hidden { display: none; }\n")
        self.assertTrue(any(e.startswith("data-css-vars outside core/css-vars.js") for e in g.check(d, b)))
```
Run `python3 -m unittest scripts.test_g1d_check_actions -v` (from repo root) → the new tests FAIL (`KeyError: 'inline_styles'` and missing messages).

- [ ] **Step 2: Implement** in `scripts/g1d-check-actions.py`:

```python
INLINE_STYLE = re.compile(r"""(?<![\w.-])style=\\?["']""")
STYLE_TAG = re.compile(r"<style\b", re.I)
GEN_USE = re.compile(r"\b(g1-[sv]-[0-9a-f]{8}|g1-display-[a-z-]+)\b")
GEN_RULE = re.compile(r"(?m)^\.(is-hidden|g1-[sv]-[0-9a-f]{8}|g1-display-[a-z-]+)\b")
RULE_KEY = re.compile(r"""(?m)^\s*['"](g1-v-[0-9a-f]{8})['"]\s*:""")
```
In `counts()` add `"inline_styles": sum(len(INLINE_STYLE.findall(t)) + len(STYLE_TAG.findall(t)) for t in texts)`. In `check()`, after the action checks:

```python
    css_path = web_dir / "styles" / "inline-equivalent.css"
    if css_path.exists():
        defined = set(GEN_RULE.findall(css_path.read_text(encoding="utf-8")))
        rules_path = web_dir / "src" / "core" / "css-var-rules.js"
        registered_rules = set(RULE_KEY.findall(rules_path.read_text(encoding="utf-8"))) if rules_path.exists() else set()
        used_gen = set()
        for p, text in [(web_dir / "index.html", html), *js.items()]:
            found = set(GEN_USE.findall(text))
            if p != rules_path:
                for r in {c for c in found if c.startswith("g1-v-")} - registered_rules:
                    errors.append(f"unregistered css-vars rule: {r}")
            used_gen |= found
            if "data-css-vars" in text and p.name != "css-vars.js":
                errors.append(f"data-css-vars outside core/css-vars.js: {p.relative_to(web_dir).as_posix()}")
        for c in sorted(used_gen - defined):
            errors.append(f"undefined generated class: {c}")
        for c in sorted(defined - used_gen - {"is-hidden"}):
            errors.append(f"orphan generated rule: {c}")
```
Add `("inline_styles", "inline styles")` to the baseline comparison loop, and read the baseline with `base.get(key, 0)`.

- [ ] **Step 3: Run** the unittest module → all PASS.

- [ ] **Step 4: Record the starting baseline** — `python3 scripts/g1d-check-actions.py --update-baseline` → prints counts; `inline_styles` is roughly 2,500 (1,072 markup + ~1,443 templates). Then `python3 scripts/g1d-check-actions.py` → OK.

- [ ] **Step 5: Gate and commit** (python tests, g1d OK, G1 guard PASS; no web change so lint/unit/smoke/visual are unaffected — run `npm test` once anyway):

```bash
git add scripts/g1d-check-actions.py scripts/test_g1d_check_actions.py scripts/g1d-inline-baseline.json
git commit -m "ci(g1e): inline-style ratchet and generated-class consistency checks

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
git push
```

---

### Task 5: Inline-style semantics helpers, JS rewrite and the reveal inventory

**Files:**
- Create: `orchestrator/web/src/core/inline-style.js`, `orchestrator/web/tests/unit/inline-style.test.mjs`, `orchestrator/web/tools/g1e-js-codemod.mjs`, `orchestrator/web/tests/unit/g1e-js-codemod.test.mjs`, `docs/superpowers/specs/g1e-reveal-inventory.md`
- Modify: `orchestrator/web/src/features/*.js` (mechanical rewrite), `orchestrator/web/tests/visual/checkpoints.mjs` (reveal checkpoints)

**Interfaces:**
- Produces: `src/core/inline-style.js` exports `GENERATED` (RegExp `^(?:is-hidden|g1-display-[a-z-]+|g1-[sv]-[0-9a-f]{8})$`), `displayOf(el)` → string, `setDisplay(el, value)` → value, `replaceClasses(el, value)` → value, `setCssText(el, value)` → value, `clearInlineStyle(el)`; `tools/g1e-js-codemod.mjs` exports `rewrite(source, file)` → `{ code, sites: [{file, line, kind, before, after}] }` (kinds: `display-reveal`, `display-hide`, `display-set`, `display-expr`, `display-read`, `class-write`, `csstext-write`, `style-remove`) and errors on `setAttribute('style'|'class', …)`, `style.setProperty('display', …)`, `style['display']`, compound assignment to `.style.display`/`.className`.

- [ ] **Step 1: Failing helper tests** — `orchestrator/web/tests/unit/inline-style.test.mjs`. The core test is equivalence: an element with the old inline style and an element converted the G1e way, driven through the same write sequence, must report the same `style.display` (old) / `displayOf` (new) and the same hidden state at every step.

```js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { JSDOM } from 'jsdom';
import { GENERATED, displayOf, setDisplay, replaceClasses, setCssText, clearInlineStyle } from '../../src/core/inline-style.js';

const doc = new JSDOM('<body></body>').window.document;
const make = (html) => { const d = doc.createElement('div'); d.innerHTML = html; return d.firstElementChild; };
// Effective display as CSS would compute it from inline + generated classes
// (generated rules outrank everything but inline).
const effective = (el) => el.style.display || (el.classList.contains('is-hidden') ? 'none'
  : ([...el.classList].find((c) => c.startsWith('g1-display-')) || '').slice(11)) || 'default';
const oldEffective = (el) => el.style.display || 'default';

const STARTS = [
  ['<p style="display:none"></p>', '<p class="is-hidden"></p>'],
  ['<p style="display:flex"></p>', '<p class="g1-display-flex"></p>'],
  ['<p style="display:inline-block;color:red"></p>', '<p class="g1-display-inline-block g1-s-0000000a"></p>'],
  ['<p></p>', '<p></p>'],
];
const VALUES = ['', 'none', 'flex', 'block', null];

function* sequences(n) {
  if (n === 0) { yield []; return; }
  for (const s of sequences(n - 1)) for (const v of VALUES) yield [...s, v];
}

test('setDisplay/displayOf reproduce inline display for every write sequence up to length 4', () => {
  for (const [oldHtml, newHtml] of STARTS) {
    for (const seq of sequences(4)) {
      const o = make(oldHtml); const n = make(newHtml);
      assert.equal(displayOf(n), o.style.display, `${newHtml} initial`);
      for (const v of seq) {
        o.style.display = v; setDisplay(n, v);
        assert.equal(displayOf(n), o.style.display, `${newHtml} after ${JSON.stringify(seq)}`);
        assert.equal(effective(n), oldEffective(o), `${newHtml} effective after ${JSON.stringify(seq)}`);
      }
    }
  }
});

test('setDisplay returns its value (usable in expressions)', () => {
  assert.equal(setDisplay(make('<p></p>'), 'none'), 'none');
});

test('replaceClasses keeps generated classes, as inline styles survived className writes', () => {
  const n = make('<p class="a is-hidden g1-s-0000000a g1-v-0000000b g1-display-flex"></p>');
  replaceClasses(n, 'b c');
  assert.deepEqual([...n.classList].sort(), ['b', 'c', 'g1-display-flex', 'g1-s-0000000a', 'g1-v-0000000b', 'is-hidden']);
  assert.equal(replaceClasses(n, 'd'), 'd');
});

test('setCssText and clearInlineStyle drop generated classes, as the inline style was replaced', () => {
  const a = make('<p class="keep is-hidden g1-s-0000000a g1-v-0000000b"></p>');
  setCssText(a, 'color: red');
  assert.deepEqual([...a.classList], ['keep']);
  assert.equal(a.style.color, 'red');
  const b = make('<p class="keep g1-display-flex"></p>');
  b.style.setProperty('--g1-v-0000000b', '5%');
  clearInlineStyle(b);
  assert.deepEqual([...b.classList], ['keep']);
  assert.equal(b.getAttribute('style'), null);
});

test('GENERATED matches only generated class names', () => {
  for (const c of ['is-hidden', 'g1-display-inline-flex', 'g1-s-0123abcd', 'g1-v-0123abcd']) assert.ok(GENERATED.test(c), c);
  for (const c of ['hidden', 'g1-s-0123abc', 'g1-x-0123abcd', 'is-hidden2', 'g1-display-']) assert.equal(GENERATED.test(c), false, c);
});
```
Run `tools/node.sh sh -c 'node --test tests/unit/inline-style.test.mjs'` → FAIL: module not found.

- [ ] **Step 2: Implement** `orchestrator/web/src/core/inline-style.js`:

```js
// Inline-style semantics after G1e (spec 4.3, plan C1/C2). Static inline styles
// became generated classes: is-hidden / g1-display-<v> stand for a former
// inline display value, g1-s-* / g1-v-* for a former style attribute. JS that
// read or cleared inline styles goes through these helpers so it sees exactly
// what it saw before.
export const GENERATED = /^(?:is-hidden|g1-display-[a-z-]+|g1-[sv]-[0-9a-f]{8})$/;
const DISPLAY_CLASS = /^(?:is-hidden|g1-display-[a-z-]+)$/;

export function displayOf(el) {
  if (el.style.display) return el.style.display;
  for (const c of el.classList) {
    if (c === 'is-hidden') return 'none';
    if (c.startsWith('g1-display-')) return c.slice(11);
  }
  return '';
}

export function setDisplay(el, value) {
  el.style.display = value;
  // Clearing the inline value used to fall back to the stylesheet; the class
  // standing for the old inline value must go too. Invalid values are ignored
  // by CSSOM, exactly as before, and leave the classes alone.
  if (value === '' || value === null) {
    for (const c of [...el.classList]) if (DISPLAY_CLASS.test(c)) el.classList.remove(c);
  }
  return value;
}

function dropGenerated(el) {
  for (const c of [...el.classList]) if (GENERATED.test(c)) el.classList.remove(c);
}

export function replaceClasses(el, value) {
  const keep = [...el.classList].filter((c) => GENERATED.test(c));
  el.className = value;
  if (keep.length) el.classList.add(...keep);
  return value;
}

export function setCssText(el, value) {
  dropGenerated(el);
  el.style.cssText = value;
  return value;
}

export function clearInlineStyle(el) {
  dropGenerated(el);
  el.removeAttribute('style');
}
```
Run → PASS 5/5.

- [ ] **Step 3: Failing codemod tests** — `orchestrator/web/tests/unit/g1e-js-codemod.test.mjs`:

```js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { rewrite } from '../../tools/g1e-js-codemod.mjs';

const head = "import { x } from '../core/escape.js';\n";

test('display writes and reads become setDisplay/displayOf with the import added', () => {
  const src = head + "function f(el, on) {\n  el.style.display = '';\n  document.getElementById('a').style.display = 'none';\n  el.style.display = on ? 'flex' : 'none';\n  if (el.style.display !== 'none') g();\n}\n";
  const { code, sites } = rewrite(src, 'features/x.js');
  assert.ok(code.includes("import { displayOf, setDisplay } from '../core/inline-style.js';"));
  assert.ok(code.includes("setDisplay(el, '');"));
  assert.ok(code.includes("setDisplay(document.getElementById('a'), 'none');"));
  assert.ok(code.includes("setDisplay(el, on ? 'flex' : 'none');"));
  assert.ok(code.includes("if (displayOf(el) !== 'none') g();"));
  assert.deepEqual(sites.map((s) => s.kind), ['display-reveal', 'display-hide', 'display-expr', 'display-read']);
  assert.equal(sites[0].line, 3);
});

test('className, cssText and removeAttribute(style) are rewritten', () => {
  const src = head + "a.className = 'x';\nb.style.cssText = 'color:red';\nc.removeAttribute('style');\nd.removeAttribute('title');\n";
  const { code, sites } = rewrite(src, 'features/x.js');
  assert.ok(code.includes("replaceClasses(a, 'x');"));
  assert.ok(code.includes("setCssText(b, 'color:red');"));
  assert.ok(code.includes('clearInlineStyle(c);'));
  assert.ok(code.includes("d.removeAttribute('title');"));
  assert.deepEqual(sites.map((s) => s.kind), ['class-write', 'csstext-write', 'style-remove']);
});

test('a module without matches is returned unchanged, without an import', () => {
  const src = head + "el.style.color = '';\n";
  assert.equal(rewrite(src, 'features/x.js').code, src);
});

test('unsupported forms are refused, never guessed', () => {
  for (const bad of ["el.setAttribute('style', 'x');", "el.setAttribute('class', 'x');", "el.style.setProperty('display', 'none');", "el.style['display'] = 'x';", "el.style.display += 'x';", "el.className += ' x';"]) {
    assert.throws(() => rewrite(head + bad + '\n', 'features/x.js'), /refused/, bad);
  }
});

test('a local name that would shadow the helpers is refused', () => {
  assert.throws(() => rewrite(head + "function setDisplay() {}\nel.style.display = '';\n", 'features/x.js'), /shadow/);
});
```
Run → FAIL: module not found.

- [ ] **Step 4: Implement** `orchestrator/web/tools/g1e-js-codemod.mjs` (one-time; deleted in Task 11):

```js
// One-time G1e rewrite (plan Task 5): routes every inline-style read/clear in
// feature modules through src/core/inline-style.js. Refuses forms it does not
// handle. Usage: node tools/g1e-js-codemod.mjs [--write] src/features/*.js
import { readFileSync, writeFileSync } from 'node:fs';
import * as espree from 'espree';

const HELPERS = ['clearInlineStyle', 'displayOf', 'replaceClasses', 'setCssText', 'setDisplay'];
const isStyle = (n) => n && n.type === 'MemberExpression' && !n.computed && n.property.name === 'style';
const isDisplay = (n) => n && n.type === 'MemberExpression' && isStyle(n.object) && !n.computed && n.property.name === 'display';
const lineOf = (src, i) => src.slice(0, i).split('\n').length;

function walk(node, parent, fn) {
  if (!node || typeof node.type !== 'string') return;
  fn(node, parent);
  for (const k of Object.keys(node)) {
    if (k === 'parent') continue;
    const v = node[k];
    if (Array.isArray(v)) v.forEach((c) => walk(c, node, fn));
    else if (v && typeof v.type === 'string') walk(v, node, fn);
  }
}

export function rewrite(src, file) {
  const ast = espree.parse(src, { ecmaVersion: 'latest', sourceType: 'module', range: true, loc: true });
  const edits = [];
  const sites = [];
  const used = new Set();
  const text = (n) => src.slice(n.range[0], n.range[1]);
  const refuse = (n, why) => { throw new Error(`refused ${file}:${lineOf(src, n.range[0])}: ${why}: ${text(n).slice(0, 80)}`); };
  const add = (n, kind, after, helper) => {
    edits.push([n.range[0], n.range[1], after]);
    sites.push({ file, line: lineOf(src, n.range[0]), kind, before: text(n), after });
    used.add(helper);
  };
  const handled = new Set();
  walk(ast, null, (n) => {
    if (n.type === 'CallExpression' && n.callee.type === 'MemberExpression') {
      const name = n.callee.property.name;
      const arg0 = n.arguments[0];
      const lit = arg0 && arg0.type === 'Literal' ? arg0.value : undefined;
      if (name === 'setAttribute' && (lit === 'style' || lit === 'class')) refuse(n, `setAttribute('${lit}')`);
      if (isStyle(n.callee.object) && (name === 'setProperty' || name === 'removeProperty') && lit === 'display') refuse(n, `style.${name}('display')`);
      if (name === 'removeAttribute' && lit === 'style') add(n, 'style-remove', `clearInlineStyle(${text(n.callee.object)})`, 'clearInlineStyle');
    }
    if (n.type === 'MemberExpression' && isStyle(n.object) && n.computed && n.property.type === 'Literal' && n.property.value === 'display') refuse(n, "style['display']");
    if (n.type === 'AssignmentExpression') {
      const l = n.left;
      const isClass = l.type === 'MemberExpression' && !l.computed && l.property.name === 'className';
      const isCss = l.type === 'MemberExpression' && isStyle(l.object) && !l.computed && l.property.name === 'cssText';
      if ((isDisplay(l) || isClass || isCss) && n.operator !== '=') refuse(n, `compound assignment ${n.operator}`);
      if (isDisplay(l)) {
        handled.add(l);
        const r = n.right;
        const kind = r.type === 'Literal' ? (r.value === '' ? 'display-reveal' : r.value === 'none' ? 'display-hide' : 'display-set') : 'display-expr';
        add(n, kind, `setDisplay(${text(l.object.object)}, ${text(r)})`, 'setDisplay');
      } else if (isClass) {
        add(n, 'class-write', `replaceClasses(${text(l.object)}, ${text(n.right)})`, 'replaceClasses');
      } else if (isCss) {
        add(n, 'csstext-write', `setCssText(${text(l.object.object)}, ${text(n.right)})`, 'setCssText');
      }
    }
  });
  walk(ast, null, (n) => {
    if (isDisplay(n) && !handled.has(n)) add(n, 'display-read', `displayOf(${text(n.object.object)})`, 'displayOf');
  });
  if (!edits.length) return { code: src, sites };
  // Nested matches (a display read inside another rewritten expression) would
  // overlap; refuse rather than compose.
  edits.sort((a, b) => a[0] - b[0]);
  for (let i = 1; i < edits.length; i++) if (edits[i][0] < edits[i - 1][1]) throw new Error(`refused ${file}:${lineOf(src, edits[i][0])}: nested inline-style access`);
  const names = [...used].sort();
  for (const h of names) {
    if (new RegExp(`(?:function|const|let|var|import[^;]*\\b)\\s*\\b${h}\\b`).test(src)) throw new Error(`refused ${file}: local name would shadow ${h}`);
  }
  let code = src;
  for (const [s, e, rep] of [...edits].reverse()) code = code.slice(0, s) + rep + code.slice(e);
  const imports = [...code.matchAll(/^import [^;]*;\n/gm)];
  const at = imports.length ? imports[imports.length - 1].index + imports[imports.length - 1][0].length : 0;
  code = code.slice(0, at) + `import { ${names.join(', ')} } from '../core/inline-style.js';\n` + code.slice(at);
  sites.sort((a, b) => a.line - b.line);
  return { code, sites };
}

if (import.meta.url === `file://${process.argv[1]}` || process.argv[1]?.endsWith('g1e-js-codemod.mjs')) {
  const write = process.argv.includes('--write');
  const all = [];
  for (const f of process.argv.slice(2).filter((a) => !a.startsWith('--'))) {
    const src = readFileSync(f, 'utf8');
    const { code, sites } = rewrite(src, f.replace(/^.*src\//, ''));
    all.push(...sites);
    if (write && code !== src) writeFileSync(f, code);
  }
  process.stdout.write(JSON.stringify(all, null, 1) + '\n');
}
```

Note on `lineOf`/`sites[0].line`: line numbers refer to the source before rewriting (the inventory records BASE lines). Run the tests → PASS 5/5. (The shadow check regex is conservative: any declaration or import of the helper name refuses; the test pins it.)

- [ ] **Step 5: Commit the inventory before converting** (spec 4.3: inventory first). Dry-run over all feature modules (`src/features/*.js` and any other `src/**/*.js` except `src/core/inline-style.js`):

```bash
cd orchestrator/web
tools/node.sh sh -c 'node tools/g1e-js-codemod.mjs src/features/*.js src/*.js' > ../../.superpowers/g1e-sites.json
```
Expected: JSON with 82 `display-reveal` sites, the `display-hide`/`display-set` (≈136), `display-expr` (≈89), `display-read` (≈15), 9 `class-write`, 5 `csstext-write`, 1 `style-remove` (counts from the 2026-10-06 inventory; small differences from G1d's edits are fine — record actual counts). A `refused` error means a form the plan did not foresee: stop and report NEEDS_CONTEXT with the message.

Write `docs/superpowers/specs/g1e-reveal-inventory.md` from that JSON: a summary table of counts by kind, then one table per kind with columns `site (file:line at <BASE>) | before | after | status`, status `pending`. Add a section "Partial clears of other properties" listing the 11 `el.style.<prop> = ''` sites for props other than display (`grep -rnE "\.style\.(\w+)\s*=\s*(''|\"\")" src | grep -v style.display`) with, for each: the target element, and whether that element can carry a literal inline value for that property in index.html or a template (read the code). For a site where it can, the rule for Phases 2–3 is recorded in the table: "move `<prop>` of `<element>` into its own `g1-s` class and add `el.classList.remove('<class>')` beside the clear" — Task 7–10 implementers follow it. Commit:

```bash
git add docs/superpowers/specs/g1e-reveal-inventory.md
git commit -m "docs(g1e): inventory of inline-style reads, reveals and clears

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
git push
```

- [ ] **Step 6: Convert.** Run the same command with `--write`. Then `tools/node.sh sh -c 'npx eslint src'` (0 errors), `npm test`, build, smoke (2 passed), g1d OK, G1 guard (PASS; the rewrite touches no sink — if it reports REVIEW/new sinks, stop and report). Mark every inventory row `converted` (same commit). `bash tools/visual.sh` → 4 passed: nothing is converted to classes yet, so the helpers must be exact no-ops.

- [ ] **Step 7: Reveal checkpoints.** For each `display-reveal` site, find the UI action that reaches it under the smoke fixtures (the `data-on-*` element whose action leads to the call). Add a `CHECKPOINTS` entry `{ name: '<file>:<line> <what is revealed>', tab, steps: [{ click: '<selector>' }] }` for each reachable one (one checkpoint may cover several sites — list them in its name), and a `UNREACHABLE_SITES` entry with a concrete reason for each other one (e.g. `'needs a live WebSocket event'`, `'admin-only flow behind a confirm() dialog'`). Every reveal site appears in exactly one of the two. Prefer clicks without `confirm()`/`alert()`, navigation or file pickers. `bash tools/visual.sh` → 4 passed with `<N> extra` checkpoints.

- [ ] **Step 8: Commit:**

```bash
git add orchestrator/web/src/core/inline-style.js orchestrator/web/tests/unit/inline-style.test.mjs orchestrator/web/tools/g1e-js-codemod.mjs orchestrator/web/tests/unit/g1e-js-codemod.test.mjs orchestrator/web/src/features/<each changed module> docs/superpowers/specs/g1e-reveal-inventory.md orchestrator/web/tests/visual/checkpoints.mjs
git commit -m "refactor(web): route inline-style reads and clears through core/inline-style.js (G1e)

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
git push
```

---

### Task 6: The style codemod

**Files:**
- Create: `orchestrator/web/tools/g1e-codemod.mjs`, `orchestrator/web/tests/unit/g1e-codemod.test.mjs`

**Interfaces:**
- Consumes: `inline-equivalent.css` format (Task 3), `CSS_VAR_RULES` format (Task 2).
- Produces (exports): `classFor(text)` → `'g1-s-<sha8>'`; `splitDecls(text)` → `[{prop, raw}]` (raw = verbatim declaration text, trimmed); `planStyle(text)` → `{ classes: string[], rules: Map<class, ruleLine> }` or throws `refused: …`; `parseCss(css)` → `Map<class, ruleLine>` (+ header); `writeCss(header, rules)` → string (sorted, byte-stable); `convertMarkup(html)` → `{ html, rules, reports }`; `convertJs(src, file)` → `{ code, rules, reports }`; `splitDynamic(template, types)` → `{ staticClass?, dynamic: [{rule, prop, value, types}], ruleLines }` or throws; CLI: `--markup <file>`, `--js <file>…`, `--split '<style text with {0}…>' --types t1,t2`, `--class '<style text>'`, `--check-determinism <baseline web dir>`; every write mode merges new rules into `styles/inline-equivalent.css` (and `src/core/css-var-rules.js` for `--split`), refusing a hash collision.

Conversion rules (from spec §4.1 and plan C1, C3):
1. Text = the attribute value as the browser sees it (markup: decode `&quot; &amp; &#39; &lt; &gt;`, refuse any other `&`; JS strings: unescape `\' \" \\`, refuse any other backslash). Refuse text containing `{`, `}`, `<`, `/*`, `!important`.
2. `display` declarations: `display:none` → class `is-hidden`; `display:<v>` with `v` matching `^[a-z-]+$` → `g1-display-<v>` (rule `.g1-display-<v> { display: <v>; }`); more than one `display` declaration, or another value form → refuse.
3. Remaining declarations, in original order, joined with `;` exactly as written (no trailing `;` added or removed), trimmed → one `g1-s-<sha8(text)>` class whose rule is `.g1-s-<h> { <text> }`. Empty remainder → no `g1-s` class.
4. Class placement: if the start tag has a literal `class="…"` (or `class=\"…\"` in a double-quoted JS string) fully inside the same string piece, append ` <classes>` before its closing quote; otherwise replace the style attribute with `class="<classes>"` using the same quote form. Never emit a second `class` attribute: if the tag is not fully contained in one string piece (its `<` or `>` lies in another piece), report the site instead.
5. Templates: a style value that is not complete inside one string piece (concatenation or `${}`) is reported (hand conversion with `--split`), never rewritten.
6. `--split` (hand conversion of data-driven styles): the template text uses `{0}`, `{1}` … for the interpolated parts and `--types` gives one type per placeholder. Literal declarations follow rules 2–3; each declaration containing a placeholder becomes its own rule `g1-v-<sha8("<prop>:<value template>")>` registered as `{prop, value, types}` with CSS `.g1-v-<h>.g1-v-<h> { <prop>: var(--g1-v-<h>); }` (doubled class so it outranks the `g1-s` class, as a later inline declaration would). Refuse when a dynamic declaration's property overlaps (same property, or shorthand/longhand: one name equals the other or is its prefix followed by `-`, plus `inset`↔`top|right|bottom|left`, `gap`↔`row-gap|column-gap`, `place-*`↔`align-*|justify-*`) a literal declaration that comes AFTER it, or another dynamic declaration; refuse a placeholder in `display`.
7. `--class '<text>'` (either/or literal branches): rules 1–3 for one literal text; prints the class list.
8. Every write mode re-reads `inline-equivalent.css`, merges, and rewrites it with `writeCss` (sorted by class name, one rule per line, header kept). An existing class with a different rule line → refuse (hash collision).

- [ ] **Step 1: Failing tests** — `orchestrator/web/tests/unit/g1e-codemod.test.mjs`:

```js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { JSDOM } from 'jsdom';
import { classFor, splitDecls, planStyle, parseCss, writeCss, convertMarkup, convertJs, splitDynamic } from '../../tools/g1e-codemod.mjs';

const h8 = (t) => createHash('sha256').update(t).digest('hex').slice(0, 8);

test('class name is the sha256 prefix of the exact text', () => {
  assert.equal(classFor('color:red;font-size:11px'), `g1-s-${h8('color:red;font-size:11px')}`);
  assert.notEqual(classFor('color:red'), classFor('color: red'));
});

test('declarations are preserved byte for byte', () => {
  const { classes, rules } = planStyle('  margin:0 auto; font-family:"Inter", sans-serif ;color:#fff ');
  const c = classes.find((x) => x.startsWith('g1-s-'));
  assert.equal(rules.get(c), `.${c} { margin:0 auto; font-family:"Inter", sans-serif ;color:#fff }`);
});

test('display:none becomes is-hidden and other display values their own class', () => {
  assert.deepEqual(planStyle('display:none').classes, ['is-hidden']);
  const p = planStyle('color:red;display: inline-flex;gap:4px');
  assert.ok(p.classes.includes('g1-display-inline-flex'));
  const s = p.classes.find((x) => x.startsWith('g1-s-'));
  assert.equal(p.rules.get(s), `.${s} { color:red;gap:4px }`);
  assert.equal(p.rules.get('g1-display-inline-flex'), '.g1-display-inline-flex { display: inline-flex; }');
});

test('unsafe or ambiguous text is refused', () => {
  for (const t of ['display:none;display:block', 'color:red !important', 'a{b}', 'x:/*y*/z', 'display:var(--d)']) assert.throws(() => planStyle(t), /refused/, t);
});

test('css round-trips byte-identically and stays sorted', () => {
  const header = '/* h */\n';
  const rules = new Map([['g1-s-ffffffff', '.g1-s-ffffffff { a:b }'], ['is-hidden', '.is-hidden { display: none; }'], ['g1-display-flex', '.g1-display-flex { display: flex; }']]);
  const css = writeCss(header, rules);
  assert.equal(writeCss(...Object.values(parseCss(css))), css);
  assert.ok(css.indexOf('.g1-display-flex') < css.indexOf('.g1-s-ffffffff') && css.indexOf('.g1-s-ffffffff') < css.indexOf('.is-hidden'));
});

test('markup: class merged into an existing class attribute, attributes otherwise unchanged', () => {
  const html = '<div id="a" class="card x" style="color:red" title="t &amp; u"><p style="display:none">x</p></div>';
  const { html: out } = convertMarkup(html);
  const c = classFor('color:red');
  assert.equal(out, `<div id="a" class="card x ${c}" title="t &amp; u"><p class="is-hidden">x</p></div>`);
  const d = new JSDOM(out).window.document;
  assert.equal(d.querySelectorAll('[class]').length, 2);
});

test('markup: entities in the style value are decoded before hashing', () => {
  const { html: out } = convertMarkup('<b style="font-family:&quot;Inter&quot;">x</b>');
  assert.ok(out.includes(classFor('font-family:"Inter"')));
});

test('templates: literal styles converted, class merged, quote form kept', () => {
  const src = "const a = '<div class=\"row\" style=\"color:red\">' + v + '</div>';\nconst b = \"<span style=\\\"margin:0\\\">\";\nconst c = `<i style=\"padding:2px\">${v}</i>`;\n";
  const { code, reports } = convertJs(src, 'x.js');
  assert.ok(code.includes(`'<div class="row ${classFor('color:red')}">'`));
  assert.ok(code.includes(`"<span class=\\"${classFor('margin:0')}\\">"`));
  assert.ok(code.includes(`\`<i class="${classFor('padding:2px')}">\${v}</i>\``));
  assert.deepEqual(reports, []);
});

test('templates: dynamic styles and split tags are reported, never rewritten', () => {
  const src = "const a = '<b style=\"color:' + c + '\">';\nconst b = '<p class=\"' + k + '\" style=\"color:red\">';\nconst d = '<em ' + attrs + ' style=\"color:red\">';\n";
  const { code, reports } = convertJs(src, 'x.js');
  assert.equal(code, src);
  assert.equal(reports.length, 3);
});

test('templates: never emits a second class attribute', () => {
  const src = "const a = '<p class=\"a\" style=\"color:red\" class=\"b\">';\n";
  const { code, reports } = convertJs(src, 'x.js');
  assert.equal(code, src);
  assert.equal(reports.length, 1);
});

test('split: one doubled-class rule per dynamic declaration, literal part as g1-s', () => {
  const r = splitDynamic('font-size:11px;border:1px solid {0}44;width:{1}%', ['color', 'number']);
  const b = `g1-v-${h8('border:1px solid {0}44')}`;
  const w = `g1-v-${h8('width:{1}%')}`;
  assert.deepEqual(r.dynamic.map((d) => d.rule), [b, w]);
  assert.deepEqual(r.dynamic[0], { rule: b, prop: 'border', value: '1px solid {0}44', types: ['color'] });
  assert.deepEqual(r.dynamic[1], { rule: w, prop: 'width', value: '{0}%', types: ['number'] });
  assert.equal(r.ruleLines.get(b), `.${b}.${b} { border: var(--${b}); }`);
  assert.equal(r.staticClass, classFor('font-size:11px'));
});

test('split: order-dependent overlaps and dynamic display are refused', () => {
  assert.throws(() => splitDynamic('border-color:{0};border:1px solid #333', ['color']), /refused/);
  assert.throws(() => splitDynamic('color:{0};background:{1};background-color:{1}', ['color', 'color']), /refused/);
  assert.throws(() => splitDynamic('display:{0}', ['color']), /refused/);
  assert.doesNotThrow(() => splitDynamic('border:1px solid #333;border-color:{0}', ['color']));
});
```
Note the `width:{1}%` case: a dynamic declaration's own placeholders are renumbered from `{0}` within its rule, and its types are the matching subset — the test pins it.
Run → FAIL: module not found.

- [ ] **Step 2: Implement `tools/g1e-codemod.mjs`** to the interfaces and rules above. Structure:
  - `decode`/`unescapeJs` per rule 1; `splitDecls(text)` splits on `;` outside parentheses and quotes, keeping each declaration's raw text (trimmed) and lower-cased `prop`.
  - `planStyle(text)` applies rules 1–3 and returns `{classes, rules}` (classes ordered: `is-hidden`/`g1-display-*` first, then `g1-s-*`).
  - `convertMarkup(html)`: regex over start tags `/<([a-zA-Z][\w:-]*)((?:\s+[^\s=>\/]+(?:=(?:"[^"]*"|'[^']*'|[^\s>]+))?)*)\s*(\/?)>/g`; for a tag with `style="…"`, rewrite per rule 4. After converting, verify with jsdom: parse input and output; walk both trees in parallel; tag names, child counts and every attribute except `style`/`class` must be equal; output `class` tokens = input tokens + planned classes. Any mismatch → throw (the file is not written).
  - `convertJs(src, file)`: `espree.tokenize(src, { ecmaVersion: 'latest', sourceType: 'module', range: true })`; for each `String` token and each `Template` token piece, find style attributes inside the piece (`(?<![\w.-])style=(\\?["'])`); apply rules 4–5 within the piece; edit back-to-front by range. Report `{file, line, text, why}` for skipped sites.
  - `splitDynamic(template, types)` per rule 6 (renumber placeholders per declaration).
  - CSS read/merge/write per rule 8; `css-var-rules.js` read/merge/write with sorted keys in the Task 2 format.
  - `--check-determinism <dir>`: run `convertMarkup` on `<dir>/index.html` and `convertJs` on every `<dir>/src/**/*.js` in memory; every produced rule line must exist byte-identical in the working tree's `inline-equivalent.css`; print the count of committed `g1-s` rules not produced (hand-converted sites) and exit non-zero on any mismatch.
  Run the tests → PASS 12/12.

- [ ] **Step 3: Dry runs.** `tools/node.sh node tools/g1e-codemod.mjs --markup index.html --dry` and `--js src/features/*.js --dry` → print counts of convertible sites and reports, no file written. Expected: markup ≈1,072 sites, few or no reports; templates ≈1,190 literal convertible, reports ≈ the 253 dynamic + split tags. Record the numbers in the report.

- [ ] **Step 4: Gate and commit** (lint, `npm test`, build, smoke, g1d, G1 guard, visual 4 passed — no source converted yet):

```bash
git add orchestrator/web/tools/g1e-codemod.mjs orchestrator/web/tests/unit/g1e-codemod.test.mjs
git commit -m "test(web): G1e style codemod (generated classes, split tool, determinism check)

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
git push
```

---

### Task 7: Phase 2 — static markup (`index.html`)

**Files:**
- Modify: `orchestrator/web/index.html`, `orchestrator/web/styles/inline-equivalent.css`, `scripts/g1d-inline-baseline.json`, possibly `docs/superpowers/specs/g1e-reveal-inventory.md`, `orchestrator/web/tests/smoke/fixtures.mjs`, `orchestrator/web/tests/visual/checkpoints.mjs`

**Interfaces:**
- Consumes: `tools/g1e-codemod.mjs --markup` (Task 6), helpers (Task 5), inventory partial-clear rules (Task 5).

- [ ] **Step 1: Apply partial-clear rules first.** For every inventory row under "Partial clears of other properties" whose element is in `index.html`, apply its recorded rule by hand (own `g1-s` class via `node tools/g1e-codemod.mjs --class '<that declaration>'`, remove the declaration from the element's style attribute, add `el.classList.remove('<class>')` beside the clear in the JS). Mark the rows done.

- [ ] **Step 2: Convert.** `tools/node.sh node tools/g1e-codemod.mjs --markup index.html` → writes `index.html` and `styles/inline-equivalent.css`, prints reports. Expected: the jsdom verification passes (otherwise nothing is written — fix the input pattern and rerun). Hand-convert each reported site with `--class`, keeping class placement rule 4.

- [ ] **Step 3: Verify.** `grep -c 'style=' index.html` → `0`. `python3 scripts/g1d-check-actions.py --update-baseline` (inline_styles drops by ≈1,072), then `python3 scripts/g1d-check-actions.py` → OK (no undefined/orphan classes). Lint, `npm test`, build, smoke (2 passed), G1 guard (PASS; index.html markup is not a sink). `bash tools/visual.sh` → 4 passed. Any diff is a conversion defect: find it from the path/property, fix the conversion; never allowlist without the user's explicit approval (report the diff and stop).

- [ ] **Step 4: Commit:**

```bash
git add orchestrator/web/index.html orchestrator/web/styles/inline-equivalent.css scripts/g1d-inline-baseline.json
git commit -m "refactor(web): static markup inline styles to generated classes (G1e)

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
git push
```
(add the inventory, fixtures, checkpoints or JS files if Step 1 touched them).

---

### Task 8: Phase 3a — templates in small modules

**Files:** every `src/features/*.js` (and other `src/**/*.js`) with fewer than 50 template style attributes — at the 2026-10-06 count: all except `reports.js`, `variant-report.js`, `agent-drawer.js`, `evidence.js`, `attack-path.js`, `endpoint-mastery.js`, `variants.js`, `openaev.js`, `adversaries.js`, `detection-verification.js`, `campaigns.js` — plus `styles/inline-equivalent.css`, `src/core/css-var-rules.js`, `tests/smoke/fixtures.mjs`, `tests/visual/checkpoints.mjs`, `scripts/g1d-inline-baseline.json`, inventory rows.

**Interfaces:** Consumes `convertJs`/`--js`, `--split`, `--class` (Task 6), `cssVars` (Task 2), helpers (Task 5).

Per-module procedure (one commit per module, smallest module first; `grep -c 'style=' <file>` gives the order):
1. Apply any inventory partial-clear rule whose element is built in this module (as Task 7 Step 1).
2. `tools/node.sh node tools/g1e-codemod.mjs --js src/features/<m>.js` → converts literal styles; note the reports.
3. For each reported site:
   - Either/or literals (`(c ? 'pointer' : 'not-allowed')`, `(x ? '700' : '')`): `--class` for each non-empty branch text; the template selects the class string (`(c ? 'g1-s-…' : 'g1-s-…')`, empty branch → no class); display branches use `is-hidden`/`g1-display-<v>` per rule 2.
   - Data values: `--split '<style text with {0}…>' --types …` (types: `color` for colours including `var(--token)` and hex with alpha suffix, `number` for numbers that get a unit or `%` in the template, `integer` for counts like `repeat({0},1fr)`); edit the template: literal classes into the tag's class attribute (rule 4), and `+ cssVars(['g1-v-…', expr], …)` in place of the style attribute, where `expr` is the original JS expression for that placeholder (unchanged — e.g. `col` for `col + '44'` when the template is `1px solid {0}44`).
   - Split tags (class built elsewhere): restructure only enough to put the generated classes into the existing class attribute expression; never add a second class attribute.
   - If a site needs a placeholder type outside `color`/`number`/`integer`, add it to `TYPES` with unit tests in the same commit and record a Ruling.
4. Fixtures: for every new `g1-v` rule and every either/or branch class, make sure a checkpoint renders it — extend `tests/smoke/fixtures.mjs` data (new fields, extra rows with other statuses/severities) and/or add `CHECKPOINTS`; when truly unreachable under fixtures, add an `UNREACHABLE_RULES` entry with a concrete reason. Fixture changes apply to both builds, so they never mask a difference; smoke must still pass with them.
5. Gate: lint; `npm test`; build; smoke 2 passed; `python3 scripts/g1d-check-actions.py --update-baseline` then plain run OK; G1 guard PASS (commit regenerated `Assessment/G1_*` if rewritten; a new REVIEW/unsafe sink → stop and report); `bash tools/visual.sh` 4 passed with no coverage problems. A diff is a conversion defect: fix it; never allowlist without the user's approval.
6. Commit `refactor(web): <module> inline styles to generated classes and css vars (G1e)` + trailer; push.

- [ ] **Step 1:** List the modules in scope with their counts (`grep -c 'style=' src/features/*.js src/*.js src/core/*.js | sort -t: -k2 -n`) in the report.
- [ ] **Step 2:** Apply the per-module procedure to each, in ascending order, one commit each.
- [ ] **Step 3:** After the last module, record in the report: modules converted, rules added (`g1-s`, `g1-v`), fixtures/checkpoints added, `UNREACHABLE_RULES` entries with reasons, final `inline_styles` baseline.

---

### Task 9: Phase 3b — templates in mid-size modules

**Files:** `src/features/{campaigns,detection-verification,adversaries,openaev,variants,endpoint-mastery,attack-path}.js` plus the shared files listed in Task 8.

**Interfaces:** as Task 8.

Per-module procedure (one commit per module, ascending style count):
1. Apply any inventory partial-clear rule whose element is built in this module.
2. `tools/node.sh node tools/g1e-codemod.mjs --js src/features/<m>.js`; note the reports.
3. Hand-convert each reported site: either/or literals via `--class` per non-empty branch (display branches → `is-hidden`/`g1-display-<v>`); data values via `--split '<text with {0}…>' --types …` and `+ cssVars(['g1-v-…', expr], …)` in place of the style attribute with the original JS expressions unchanged, literal classes into the tag's class attribute; split tags restructured only enough to place the classes in the existing class expression, never a second class attribute; a new placeholder type only with unit tests and a Ruling.
4. Fixtures/`CHECKPOINTS` so every new `g1-v` rule and either/or class renders, else `UNREACHABLE_RULES` with a reason.
5. Gate: lint, `npm test`, build, smoke 2 passed, g1d check (update baseline, then OK), G1 guard PASS (new REVIEW/unsafe sink → stop and report), `bash tools/visual.sh` 4 passed with no coverage problems; a diff is a defect to fix, never allowlisted without the user's approval.
6. Commit `refactor(web): <module> inline styles to generated classes and css vars (G1e)` + trailer; push.

- [ ] **Step 1:** Apply the procedure to each module in scope, ascending, one commit each.
- [ ] **Step 2:** Report as Task 8 Step 3.

---

### Task 10: Phase 3c — the largest modules

**Files:** `src/features/{evidence,agent-drawer,variant-report,reports}.js` plus the shared files listed in Task 8.

**Interfaces:** as Task 8.

Per-module procedure (order: evidence, agent-drawer, variant-report, reports; a module may span several commits — split by function groups, each commit independently green):
1. Apply any inventory partial-clear rule whose element is built in this module.
2. `tools/node.sh node tools/g1e-codemod.mjs --js src/features/<m>.js`; note the reports.
3. Hand-convert each reported site: either/or literals via `--class` per non-empty branch (display branches → `is-hidden`/`g1-display-<v>`); data values via `--split '<text with {0}…>' --types …` and `+ cssVars(['g1-v-…', expr], …)` with the original JS expressions unchanged, literal classes into the tag's class attribute; split tags restructured only enough to place the classes in the existing class expression, never a second class attribute; a new placeholder type only with unit tests and a Ruling. The `ransomware.js` conic-gradient dial pattern (`conic-gradient({0} {1}%, var(--elevated) 0%)`, types `color,number`) and `variant-report.js` `repeat({0},1fr)` (`integer`) are known instances.
4. Fixtures/`CHECKPOINTS` so every new `g1-v` rule and either/or class renders, else `UNREACHABLE_RULES` with a reason.
5. Gate per commit: lint, `npm test`, build, smoke 2 passed, g1d check (update baseline, then OK), G1 guard PASS (new REVIEW/unsafe sink → stop and report), `bash tools/visual.sh` 4 passed with no coverage problems; a diff is a defect to fix, never allowlisted without the user's approval.
6. Commit `refactor(web): <module> inline styles to generated classes and css vars (G1e)` (`… (part n)` when split) + trailer; push.

- [ ] **Step 1:** Apply the procedure to the four modules.
- [ ] **Step 2:** Confirm `python3 scripts/g1d-check-actions.py` reports `inline_styles: 0` and every inventory row is `converted`/`done`.
- [ ] **Step 3:** Determinism (exit criterion 1): `bash` — extract the baseline tree (`git archive $(cat orchestrator/web/tests/visual/BASELINE_REF) orchestrator/web | tar -x -C <scratch> --strip-components=2`) and run `tools/node.sh node tools/g1e-codemod.mjs --check-determinism <scratch path inside /web>` (extract under `orchestrator/web/.visual/det` so the container sees it; delete it afterwards) → Expected: `0 mismatches`, plus the count of hand-converted `g1-s` rules. Record in the report.
- [ ] **Step 4:** Report as Task 8 Step 3, plus the determinism result.

---

### Task 11: Exit — `style-src 'self'`, permanent bans, retire the migration tooling

**Files:**
- Modify: `orchestrator/cmd/server/static.go`, `orchestrator/cmd/server/static_test.go`, `orchestrator/web/tests/smoke/csp-policy.txt`, `orchestrator/web/eslint.config.mjs`, `.github/workflows/test.yml`, `orchestrator/web/tests/smoke/smoke.spec.mjs` only if needed
- Delete: `orchestrator/web/tools/visual.sh`, `orchestrator/web/tests/visual/`, `orchestrator/web/tools/g1e-props.mjs`, `orchestrator/web/tools/g1e-codemod.mjs`, `orchestrator/web/tools/g1e-js-codemod.mjs`, `orchestrator/web/tests/unit/{visual-compare,g1e-codemod,g1e-js-codemod}.test.mjs`
- Keep: `tests/smoke/harness.mjs`, `src/core/{css-vars,css-var-rules,inline-style}.js`, `styles/{index,inline-equivalent}.css`, `docs/superpowers/specs/g1e-reveal-inventory.md`

**Interfaces:**
- Consumes: G1d's `dashboardCSP`, `TestDashboardCSP_ScriptSrcIsStrict`, `TestDashboardCSP_MatchesSmokePolicy`, ESLint `no-restricted-syntax` list from G1d Task 9.

- [ ] **Step 1: Final visual run before retirement.** `bash tools/visual.sh` → 4 passed; record the summary line (tabs, drawers, extra checkpoints, g1-v rules seen) and the allowlist (expected `[]`; list any user-approved entries).

- [ ] **Step 2: Failing Go test** — in `TestDashboardCSP_ScriptSrcIsStrict` (static_test.go) add after the `script-src` check:

```go
	if dirs["style-src"] != "'self'" {
		t.Fatalf("style-src = %q, want exactly 'self'", dirs["style-src"])
	}
```
and extend the weakening loop's condition with `|| strings.Contains(dirs["style-src"], bad)`. Run `cd orchestrator && go test ./cmd/server -run 'DashboardCSP|CSPHeaders' -count=1` → FAIL: `style-src = "'self' 'unsafe-inline'", want exactly 'self'`.

- [ ] **Step 3: Change the policy** — in `dashboardCSP` replace `style-src 'self' 'unsafe-inline'` with `style-src 'self'`, and make the same change in `orchestrator/web/tests/smoke/csp-policy.txt`. Update the constant's comment if it mentions G1e as pending. Run the Go tests → PASS (including `TestDashboardCSP_MatchesSmokePolicy`).

- [ ] **Step 4: Enforced smoke.** Build, then `SMOKE_CSP=enforce tools/smoke.sh dist` and `SMOKE_CSP=enforce SMOKE_STRICT=1 tools/smoke.sh dist` → `2 passed` each, no `csp:` errors. A `csp: style-src` error names the source location: convert it (it escaped the ratchet — also fix the ratchet pattern) and rerun.

- [ ] **Step 5: Permanent ESLint bans.** In `orchestrator/web/eslint.config.mjs`, hoist G1d's `no-restricted-syntax` selector objects into `const G1D_BANS = [ … ];` and add:

```js
const G1E_BANS = [
  { selector: 'Literal[value=/(^|[^\\w.-])style=/]', message: 'Inline style attribute: use a generated class or cssVars() (G1e).' },
  { selector: 'TemplateElement[value.raw=/(^|[^\\w.-])style=/]', message: 'Inline style attribute: use a generated class or cssVars() (G1e).' },
  { selector: 'Literal[value=/<style/i]', message: '<style> element: put CSS in styles/ (G1e).' },
  { selector: 'TemplateElement[value.raw=/<style/i]', message: '<style> element: put CSS in styles/ (G1e).' },
  { selector: 'Literal[value=/data-css-vars/]', message: 'data-css-vars only via cssVars() (G1e).' },
  { selector: "CallExpression[callee.property.name='setAttribute'][arguments.0.value=/^(style|class)$/]", message: 'Use classList, replaceClasses() or cssVars() (G1e).' },
  { selector: "MemberExpression[object.property.name='style'][property.name='display']", message: 'Use setDisplay()/displayOf() from core/inline-style.js (G1e).' },
  { selector: "AssignmentExpression[left.property.name='className']", message: 'Use replaceClasses() from core/inline-style.js (G1e).' },
  { selector: "AssignmentExpression[left.property.name='cssText']", message: 'Use setCssText() from core/inline-style.js (G1e).' },
  { selector: "CallExpression[callee.property.name='removeAttribute'][arguments.0.value='style']", message: 'Use clearInlineStyle() from core/inline-style.js (G1e).' },
];
```
Main config: `'no-restricted-syntax': ['error', ...G1D_BANS, ...G1E_BANS]`; add a config object for `files: ['src/core/inline-style.js', 'src/core/css-vars.js']` with `'no-restricted-syntax': ['error', ...G1D_BANS]`. Verify each ban bites: temporarily add `el.style.display = '';` and `h = '<b style="x">';` to a feature module, run `npx eslint src` → 2 errors with the G1e messages; remove them; `npx eslint src` → 0 errors.

- [ ] **Step 6: Retire the migration tooling.** Delete the files listed above and the `web-visual` job from `.github/workflows/test.yml`. Check nothing imports them: `grep -rn "g1e-codemod\|g1e-js-codemod\|tests/visual\|visual.sh\|g1e-props" orchestrator .github scripts --include=*.mjs --include=*.js --include=*.yml --include=*.sh --include=*.py` → no hits. Remove `.visual/` from `.gitignore` only if nothing else uses it (keep it otherwise — harmless).

- [ ] **Step 7: Full gate.** Lint 0 errors; `npm test` (count drops by the retired tests — record before/after); build; `tools/smoke.sh dist` 2 passed; enforced smoke 2 passed; `python3 scripts/g1d-check-actions.py` OK with `inline_styles: 0`; python unittests OK; G1 guard PASS; `cd orchestrator && go test ./cmd/server -count=1` PASS and `go vet ./cmd/server`.

- [ ] **Step 8: Commit:**

```bash
git add orchestrator/cmd/server/static.go orchestrator/cmd/server/static_test.go orchestrator/web/tests/smoke/csp-policy.txt orchestrator/web/eslint.config.mjs .github/workflows/test.yml
git rm -r orchestrator/web/tests/visual orchestrator/web/tools/visual.sh orchestrator/web/tools/g1e-props.mjs orchestrator/web/tools/g1e-codemod.mjs orchestrator/web/tools/g1e-js-codemod.mjs orchestrator/web/tests/unit/visual-compare.test.mjs orchestrator/web/tests/unit/g1e-codemod.test.mjs orchestrator/web/tests/unit/g1e-js-codemod.test.mjs
git commit -m "feat(security): style-src 'self' -- G1e complete; permanent inline-style bans

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
git push
```

- [ ] **Step 9: Release QA handoff (user-run, not an exit gate).** Record in the report the staging checklist: every tab with DevTools open shows no CSP errors under `BAS_CSP_MODE=enforce`; `BAS_CSP_MODE=report-only` still logs violations to `/api/csp-report`; a quick look at a report, a drawer and a modal against a pre-G1e screenshot.

---

## Self-review

- **Spec coverage:** §4.1 → Tasks 6–10; §4.2 → Task 3 (+ `!important` proof in Task 3 Step 3); §4.3 → Task 5 (C1) and the display rules in Task 6; §4.4 → Task 2 (C3/C4) and `--split` in Task 6; §4.5 → Task 11; §5 → Task 1 (+ coverage C5); §6 → Task 4 and Task 11 Step 5; §7 phases 0–4 → Tasks 1–4, 5, 7, 8–10, 11; §8 tests → Tasks 1, 2, 5, 6; §9 exit criteria 1–7 → Task 10 Step 3, Task 11 Steps 5/7, Task 5 Step 7, Task 2, Task 11 Step 1, Task 11 Steps 2–4; §10 risks → Review Focus; §11 out of scope respected (CSSOM writes kept except display, which C1 requires).
- **Type consistency:** `cssVars(...entries)` with `[rule, ...values]` (Tasks 2, 4, 8–10); rule class `g1-v-<h>`, custom property `--g1-v-<h>`, CSS `.g1-v-<h>.g1-v-<h>` (Tasks 2, 3, 6); `GENERATED`, `setDisplay`, `displayOf`, `replaceClasses`, `setCssText`, `clearInlineStyle` (Tasks 5, 11); `harness.mjs` exports (Tasks 1, 11); `CHECKPOINTS`/`UNREACHABLE_SITES`/`UNREACHABLE_RULES` (Tasks 1, 5, 8–10).
