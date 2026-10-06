# G1d Strict CSP Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Serve the dashboard with an enforcing CSP whose `script-src` is `'self'` only, by replacing all 614 inline event handlers with delegated `data-on-*` actions and adding the header, a Report-Only switch and a violation log to the Go server.

**Architecture:** `src/core/actions.js` provides `on()` (the only way templates attach behaviour) and a document-level dispatcher that looks names up in the `ACTIONS` registry (`src/globals.js`); nothing is looked up on `window`. A codemod converts the mechanical static handlers, the rest are converted by hand module by module, each commit gated by unit tests, the Playwright smoke harness, two registry checks and the G1 guard. The Go side adds `BAS_CSP_MODE`, the header in `cmd/server/static.go`, and `POST /api/csp-report`.

**Tech Stack:** ES modules + esbuild (pinned Node image via `tools/node.sh`), jsdom + `node:test`, Playwright (pinned image via `tools/smoke.sh`), Python 3 stdlib checks, Go 1.26 (chi, `golang.org/x/time/rate` already in `go.mod`).

**Spec:** `docs/superpowers/specs/2026-10-05-g1d-strict-csp-design.md` (approved 2026-10-05, commit `2d7da6b1`).

## Global Constraints

- `script-src 'self'` — never `'unsafe-inline'`, `'unsafe-eval'` or `'unsafe-hashes'`; no nonces (there is no inline script).
- Policy (exact): `default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'self'; object-src 'none'; frame-ancestors 'none'; report-uri /api/csp-report`
- `style-src 'unsafe-inline'` stays (G1e); no `style=` conversion in this plan.
- `BAS_CSP_MODE`: `enforce` (default) or `report-only`; anything else fails startup; no `off`.
- `data-args` is a JSON array of strings/numbers/booleans/null; never evaluated.
- No action lookup on `window`, ever.
- Proven G1 scripts (`g1-innerhtml-sink-classifier.py`, `g1-trace-indirect-sinks.py`, `g1-merge-classification.py`) are not modified.
- Node only in the pinned images (`orchestrator/web/tools/node.sh`, `tools/smoke.sh`); `npm ci --ignore-scripts`; no new npm dependencies.
- Work on `main`; commit and push after every commit; stage files by name; never stage `.claude/settings.local.json`, `go.work.sum`, `Assessment/COMPETITIVE_ANALYSIS.html`, `orchestrator/staging-loadtest-linux`, `docs/superpowers/plans/2026-10-04-g1b-xss-ci-regression-guard.md`.
- Commit trailer: `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.
- Start only after G1c's final whole-branch review is closed.

## Review Focus

1. **Action names that are Object prototype members** (`constructor`, `toString`, `__proto__`) in `data-on-*`: must never call anything — pinned in Task 1 (`prototype names are never dispatched`).
2. **Hostile or unusual arguments through `on()`** (quotes, `</script>`, `&`, unicode, empty string, very long strings): round-trip exactly and stay inert — pinned in Task 1 (`on() round-trips hostile arguments as inert data`).
3. **Clicks on disabled controls** (and their child elements): an inline handler never fired there; the dispatcher must not either — pinned in Task 1 (`disabled form controls are not dispatched`).
4. **Report endpoint abuse** (oversized, wrong content type, malformed JSON, control characters, a flood): 413/415/400, sanitized single-line logs, flood dropped and counted — pinned in Task 11.
5. **`BAS_CSP_MODE` spelling variants** (`Enforce`, ` report-only `, `off`, empty): case/space-insensitive for the two valid values, empty = default, everything else fails startup — pinned in Task 10.

## File map

| File | Responsibility | Task |
|---|---|---|
| `orchestrator/web/src/core/actions.js` (new) | `EVENT_TYPES`, `on()`, `dispatch()`, `installActions()`, `stopEvent` | 1 |
| `orchestrator/web/tests/unit/actions.test.mjs` (new) | dispatcher + `on()` tests | 1 |
| `orchestrator/web/src/globals.js` | `ACTIONS` registry; later loses `HANDLER_FUNCTIONS`, `DYNAMIC_HANDLERS`, `STATE_GLOBALS`, `installGlobals` | 1, 6, 7, 9 |
| `orchestrator/web/src/main.js` | calls `installActions(ACTIONS)` | 1, 9 |
| `scripts/g1d-check-actions.py` + `scripts/test_g1d_check_actions.py` (new) | action registry + inline ratchet | 3, 9 |
| `scripts/g1d-inline-baseline.json` (new) | ratchet counts | 3, 5–9 |
| `scripts/g1c-check-globals.py` + test | counts `data-on-*`/`on()`/string names as "called" (T3); deleted (T9) | 3, 9 |
| `orchestrator/web/tests/smoke/*` | both handler forms, CSP + strict modes, action clicks | 4 |
| `orchestrator/web/tools/g1d-codemod.mjs` + `tests/unit/codemod.test.mjs` (new, deleted in T9) | static markup conversion | 5 |
| `orchestrator/web/index.html`, `src/features/*.js` | conversions | 2, 5–7 |
| `orchestrator/web/fonts/*` (new), `styles/app.css`, `tools/build.mjs` | self-hosted fonts | 8 |
| `orchestrator/config/config.go` + test | `CSPMode` | 10 |
| `orchestrator/cmd/server/static.go`, `main.go` + test | header | 10 |
| `orchestrator/internal/api/csp_report.go` + test, `routes.go`, `rbac_matrix_test.go` | violation endpoint | 11 |
| `.github/workflows/test.yml`, `packaging/compose/docker-compose.yml`, `.env.example` | wiring | 3, 12 |

Decision recorded here (deviates from spec wording, not intent): the `ACTIONS` registry lives in `src/globals.js` (which already imports every feature module), not in `core/actions.js`; `core/actions.js` holds the mechanism only. Putting the registry in `core/actions.js` would make it import every feature module while every feature module imports `on()` from it.

---

### Task 1: `core/actions.js` — dispatcher and `on()`

**Files:**
- Create: `orchestrator/web/src/core/actions.js`, `orchestrator/web/tests/unit/actions.test.mjs`
- Modify: `orchestrator/web/src/globals.js` (add `ACTIONS`), `orchestrator/web/src/main.js`

**Interfaces:**
- Produces: `export const EVENT_TYPES: string[]`; `export function on(eventType: string, name: string, ...args: (string|number|boolean|null)[]): string` (leading space, attribute text); `export function dispatch(registry: object, type: string, event: Event): void`; `export function installActions(registry: object, root = document): void`; `export function stopEvent(el, event)`; `globals.js`: `export const ACTIONS = { ...HANDLER_FUNCTIONS, stopEvent }`. Actions are called as `fn.apply(element, [...args, element, event])`.

- [ ] **Step 1: Write the failing tests `orchestrator/web/tests/unit/actions.test.mjs`**

```js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { JSDOM } from 'jsdom';
import { EVENT_TYPES, on, dispatch, installActions, stopEvent } from '../../src/core/actions.js';

// A fresh document per test so listeners never accumulate.
function fresh(html = '') {
  const dom = new JSDOM(`<!DOCTYPE html><body>${html}</body>`, { url: 'http://127.0.0.1/' });
  return dom.window;
}
function withConsoleErrors(fn) {
  const seen = []; const orig = console.error;
  console.error = (...a) => seen.push(a.join(' '));
  try { fn(); } finally { console.error = orig; }
  return seen;
}

test('on() emits a data-on attribute and JSON args', () => {
  assert.equal(on('click', 'openRun', 'abc', 3), ' data-on-click="openRun" data-args="[&quot;abc&quot;,3]"');
  assert.equal(on('change', 'reload'), ' data-on-change="reload"');
});

test('on() rejects event types the dispatcher does not listen for', () => {
  assert.throws(() => on('dblclick', 'f'), /unsupported event "dblclick"/);
});

test('on() round-trips hostile arguments as inert data', () => {
  const payloads = ['"><img src=x onerror="globalThis.__xss=1">', "'); alert(1); ('", '</script><script>globalThis.__xss=1</script>', '&amp; & é 🔥', '', 'x'.repeat(5000)];
  const w = fresh();
  for (const p of payloads) {
    const div = w.document.createElement('div');
    div.innerHTML = `<b${on('click', 'f', p, 1, true, null)}>t</b>`;
    const b = div.querySelector('b');
    assert.equal(div.querySelectorAll('*').length, 1, 'payload created an element');
    assert.deepEqual([...b.attributes].map((a) => a.name).sort(), ['data-args', 'data-on-click']);
    assert.deepEqual(JSON.parse(b.getAttribute('data-args')), [p, 1, true, null]);
  }
  assert.equal(globalThis.__xss, undefined);
});

test('click on a child dispatches the nearest action with args, this, el and event', () => {
  const w = fresh('<div id="row" data-on-click="openRun" data-args="[&quot;r1&quot;,2]"><span id="s">x</span></div>');
  const calls = [];
  installActions({ openRun(a, b, el, ev) { calls.push([a, b, this.id, el.id, ev.type]); } }, w.document);
  w.document.getElementById('s').click();
  assert.deepEqual(calls, [['r1', 2, 'row', 'row', 'click']]);
});

test('without stopPropagation both nested actions run, inner first', () => {
  const w = fresh('<div data-on-click="outer"><button id="b" data-on-click="inner">x</button></div>');
  const calls = [];
  installActions({ outer() { calls.push('outer'); }, inner() { calls.push('inner'); } }, w.document);
  w.document.getElementById('b').click();
  assert.deepEqual(calls, ['inner', 'outer']);
});

test('stopPropagation in an action ends the ancestor walk', () => {
  const w = fresh('<div data-on-click="outer"><button id="b" data-on-click="stopEvent">x</button></div>');
  const calls = [];
  installActions({ outer() { calls.push('outer'); }, stopEvent }, w.document);
  w.document.getElementById('b').click();
  assert.deepEqual(calls, []);
});

test('unknown and prototype names are never dispatched and never fall back to window', () => {
  for (const name of ['nope', 'constructor', 'toString', '__proto__', 'hasOwnProperty']) {
    const w = fresh(`<button id="b" data-on-click="${name}">x</button>`);
    w.nope = () => { throw new Error('window fallback used'); };
    installActions({}, w.document);
    const errs = withConsoleErrors(() => w.document.getElementById('b').click());
    assert.equal(errs.length, 1, `${name}: expected one console.error`);
    assert.match(errs[0], /not registered/);
  }
});

test('malformed data-args is logged and the action is not called', () => {
  for (const raw of ['{"a":1}', 'not json', '"str"']) {
    const w = fresh(`<button id="b" data-on-click="f" data-args='${raw}'>x</button>`);
    let called = false;
    installActions({ f() { called = true; } }, w.document);
    const errs = withConsoleErrors(() => w.document.getElementById('b').click());
    assert.equal(called, false);
    assert.match(errs[0], /data-args is not a JSON array/);
  }
});

test('an action on <a href="#"> prevents the navigation', () => {
  const w = fresh('<a id="a" href="#" data-on-click="f">x</a>');
  installActions({ f() {} }, w.document);
  const ev = new w.MouseEvent('click', { bubbles: true, cancelable: true });
  w.document.getElementById('a').dispatchEvent(ev);
  assert.equal(ev.defaultPrevented, true);
});

test('disabled form controls are not dispatched', () => {
  const w = fresh('<button id="b" disabled data-on-click="f"><span id="s">x</span></button>');
  let called = false;
  installActions({ f() { called = true; } }, w.document);
  w.document.getElementById('s').dispatchEvent(new w.MouseEvent('click', { bubbles: true }));
  assert.equal(called, false);
});

test('non-bubbling events act on the target only', () => {
  const w = fresh('<div data-on-blur="outer"><input id="i" data-on-blur="inner"></div>');
  const calls = [];
  installActions({ outer() { calls.push('outer'); }, inner() { calls.push('inner'); } }, w.document);
  w.document.getElementById('i').dispatchEvent(new w.FocusEvent('blur', { bubbles: false }));
  assert.deepEqual(calls, ['inner']);
});

test('change and input pass the element so handlers can read value/checked', () => {
  const w = fresh('<input id="i" type="checkbox" data-on-change="toggle" data-args="[7]">');
  const seen = [];
  installActions({ toggle(id) { seen.push([id, this.checked]); } }, w.document);
  const i = w.document.getElementById('i');
  i.checked = true;
  i.dispatchEvent(new w.Event('change', { bubbles: true }));
  assert.deepEqual(seen, [[7, true]]);
});

test('EVENT_TYPES covers every event used by the dashboard today', () => {
  for (const t of ['click', 'change', 'input', 'keydown', 'blur', 'mouseover', 'mouseout', 'mouseenter', 'mouseleave', 'mousedown']) {
    assert.ok(EVENT_TYPES.includes(t), t);
  }
  assert.equal(typeof dispatch, 'function');
});
```

- [ ] **Step 2: Run it to verify it fails**

Run: `cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator/web && tools/node.sh node --test tests/unit/actions.test.mjs`
Expected: FAIL — `Cannot find module '/web/src/core/actions.js'`.

- [ ] **Step 3: Write `orchestrator/web/src/core/actions.js`**

```js
// Delegated event actions (G1d spec section 4). Markup names an action with
// data-on-<event>="name" and optional data-args="<JSON array>"; one listener
// per event type on the document dispatches to the registry passed to
// installActions(). No inline handlers, no window lookups, and arguments are
// data -- they are parsed as JSON, never evaluated.
import { x } from './escape.js';

export const EVENT_TYPES = ['click', 'change', 'input', 'keydown', 'blur', 'mouseover', 'mouseout', 'mouseenter', 'mouseleave', 'mousedown'];

// Events that do not bubble: listened for in the capture phase and acted on
// only at the target, exactly like the inline attribute they replace.
const NON_BUBBLING = new Set(['blur', 'mouseenter', 'mouseleave']);

// The only way templates attach behaviour. Returns attribute text with a
// leading space: '<button' + on('click', 'openRun', id) + '>'.
export function on(eventType, name, ...args) {
  if (!EVENT_TYPES.includes(eventType)) throw new Error(`on(): unsupported event "${eventType}"`);
  let attr = ` data-on-${eventType}="${x(name)}"`;
  if (args.length) attr += ` data-args="${x(JSON.stringify(args))}"`;
  return attr;
}

// Common action: replaces onclick="event.stopPropagation()".
export function stopEvent(el, event) { event.stopPropagation(); }

export function dispatch(registry, type, event) {
  const attr = `data-on-${type}`;
  const walk = !NON_BUBBLING.has(type);
  for (let el = event.target; el && el.nodeType === 1; el = walk ? el.parentElement : null) {
    const name = el.getAttribute(attr);
    if (name === null) continue;
    // An inline handler never fired on a disabled control; neither do we.
    if (el.disabled === true) return;
    const fn = Object.prototype.hasOwnProperty.call(registry, name) ? registry[name] : undefined;
    if (typeof fn !== 'function') { console.error(`action "${name}" is not registered`); return; }
    let args = [];
    const raw = el.getAttribute('data-args');
    if (raw !== null) {
      try { args = JSON.parse(raw); } catch { args = null; }
      if (!Array.isArray(args)) { console.error(`action "${name}": data-args is not a JSON array`); return; }
    }
    if (type === 'click' && el.tagName === 'A' && el.getAttribute('href') === '#') event.preventDefault();
    fn.apply(el, [...args, el, event]);
    if (event.cancelBubble) return;
  }
}

export function installActions(registry, root = document) {
  for (const type of EVENT_TYPES) {
    root.addEventListener(type, (event) => dispatch(registry, type, event), NON_BUBBLING.has(type));
  }
}
```

Note on disabled controls: a click on a child of a disabled `<button>` reaches the document in some browsers; `el.disabled === true` on the action element stops it. Elements without a `disabled` property (`div`, `span`) have `el.disabled === undefined` and dispatch normally.

- [ ] **Step 4: Run it to verify it passes**

Run: `tools/node.sh node --test tests/unit/actions.test.mjs`
Expected: PASS, 13 tests.

- [ ] **Step 5: Wire the registry and dispatcher**

In `src/globals.js`, directly after the closing `};` of `HANDLER_FUNCTIONS`, add:

```js

// The action registry for data-on-* attributes (G1d). During migration it
// holds every inline-handler function plus the explicit actions below; Task 9
// turns it into the explicit list and deletes HANDLER_FUNCTIONS.
export const ACTIONS = {
  ...HANDLER_FUNCTIONS,
  stopEvent,
};
```

and add `import { stopEvent } from './core/actions.js';` after the existing `import { x } from './core/escape.js';` line.

In `src/main.js` replace `import { installGlobals } from './globals.js';` with

```js
import { installGlobals, ACTIONS } from './globals.js';
import { installActions } from './core/actions.js';
```

and replace the line `installGlobals();` with

```js
installGlobals();
installActions(ACTIONS);
```

- [ ] **Step 6: Run the full web gate**

```bash
cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator/web
tools/node.sh sh -c 'npx eslint src --max-warnings=100000 && npm test && npm run build'
tools/smoke.sh dist
cd ../.. && python3 scripts/g1c-check-globals.py && PYTHONIOENCODING=utf-8 bash scripts/g1-run-local.sh
```
Expected: lint 0 errors; all unit tests pass; build OK; smoke `1 passed`; registry OK; G1 guard PASS (adding `actions.js` shifts line numbers only — 0 eliminated, 0 new). If `Assessment/G1_*` changed, they are committed with this task.

- [ ] **Step 7: Commit and push**

```bash
git add orchestrator/web/src/core/actions.js orchestrator/web/tests/unit/actions.test.mjs orchestrator/web/src/globals.js orchestrator/web/src/main.js Assessment/G1_INNERHTML_SINK_INVENTORY.csv Assessment/G1_INNERHTML_SINK_INVENTORY.json Assessment/G1_INDIRECT_SINK_TRACE.csv Assessment/G1_FINAL_CLASSIFICATION.json Assessment/G1_FINAL_CLASSIFICATION.csv
git commit -m "feat(web): delegated data-on-* actions and on() (G1d phase 0)

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
git push
```

---

### Task 2: G1 spike — convert `covSegHtml` and read the guard

**Files:**
- Modify: `orchestrator/web/src/features/attack-path.js` (`covSegHtml`, ~line 1457, and its imports)
- Conditionally modify: `scripts/g1-assemble-classifier-view.py`, `scripts/test_g1_assemble_classifier_view.py`

**Interfaces:**
- Consumes: `on()` from Task 1.
- Produces: the recorded G1 outcome for `on(...)` in templates (ledger line `Task 2: G1 spike outcome: ...`), which Tasks 5–7 rely on.

- [ ] **Step 1: Convert the one template.** In `covSegHtml` replace

```js
    return '<button class="' + (activeVal === o[0] ? 'on' : '') + '" onclick="' + setterFnName + '(\'' + o[0] + '\')">' + label + '</button>';
```
with
```js
    return '<button class="' + (activeVal === o[0] ? 'on' : '') + '"' + on('click', setterFnName, o[0]) + '>' + label + '</button>';
```
and add `on` to the file's imports: `import { on } from '../core/actions.js';` (merge into an existing import from `../core/actions.js` if one exists).

- [ ] **Step 2: Run the gate and the guard**

```bash
cd orchestrator/web && tools/node.sh sh -c 'npx eslint src --max-warnings=100000 && npm test && npm run build' && tools/smoke.sh dist
cd ../.. && PYTHONIOENCODING=utf-8 bash scripts/g1-run-local.sh 2>&1 | grep -E "current sinks|eliminated|new sink|REVIEW|guard:"
```
Expected: smoke `1 passed` (the agents/campaigns/coverage toolbars render through the dispatcher). Then exactly one of:

- **(a) Guard PASS.** Read every REVIEW line: each must be a sink whose RHS now contains `on(` and whose tier is unchanged. Ledger: `Task 2: G1 spike outcome: (a) on() accepted by the classifier unchanged; REVIEW lines: <list>`. Go to Step 4.
- **(b) Guard FAIL, the failing slot's new RHS contains `on(`.** The classifier rates the unknown `on(...)` builder worse. Do Step 3.

- [ ] **Step 3 (only for outcome b): present `on(` as an escaper call in the classifier view.** `on()` returns only escaped attribute text built through `x()`, so the classifier view (a CI analysis artifact, never executed) may show it as `x(`. Add the failing test to `scripts/test_g1_assemble_classifier_view.py` (inside `TestAssemble`):

```python
    def test_on_helper_calls_are_presented_as_escaper_calls(self):
        d = web({**BASE, "src/a.js": "function r(i) { return '<b' + on('click', 'f', i) + '>'; }\nconst moon(1);\n"})
        out = v.assemble(d)
        self.assertIn("'<b' + x('click', 'f', i) + '>'", out)
        self.assertIn("const moon(1);", out)
```

Run `cd scripts && python3 -m unittest test_g1_assemble_classifier_view` → FAIL. Then in `scripts/g1-assemble-classifier-view.py` add below `EXPORT_KW`:

```python
# on() (core/actions.js) returns only x()-escaped attribute text; the proven
# classifier does not know the name, so the view presents it as the escaper.
ON_CALL = re.compile(r"(?<![\w$.])on\(")
```

and change `_as_script` to `return ON_CALL.sub("x(", EXPORT_KW.sub("", IMPORT_LINE.sub("", js)))`. Rerun the unittest → PASS, rerun `scripts/g1-run-local.sh` → guard PASS. Ledger: `Task 2: G1 spike outcome: (b) assembler presents on( as x( — <guard numbers>`.

- [ ] **Step 4: Commit and push** (add the two assembler files only in outcome b)

```bash
git add orchestrator/web/src/features/attack-path.js Assessment/G1_INNERHTML_SINK_INVENTORY.csv Assessment/G1_INNERHTML_SINK_INVENTORY.json Assessment/G1_INDIRECT_SINK_TRACE.csv Assessment/G1_FINAL_CLASSIFICATION.json Assessment/G1_FINAL_CLASSIFICATION.csv
git commit -m "refactor(web): covSegHtml attaches its handler with on() (G1d spike)

<outcome a/b and REVIEW lines>

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
git push
```

---

### Task 3: Registry checks — `g1d-check-actions.py`, ratchet, `g1c` adaptation

**Files:**
- Create: `scripts/g1d-check-actions.py`, `scripts/test_g1d_check_actions.py`, `scripts/g1d-inline-baseline.json`
- Modify: `scripts/g1c-check-globals.py`, `scripts/test_g1c_check_globals.py`, `.github/workflows/test.yml`

**Interfaces:**
- Produces: `check(web_dir, baseline_path) -> list[str]`; `counts(web_dir) -> {"inline_handlers": int, "javascript_urls": int}`; CLI `python3 scripts/g1d-check-actions.py [--update-baseline]`. `g1c-check-globals.py` treats `data-on-*` names, literal `on()` names and identifier-shaped string literals in `src/` as "called" so converted handlers are not reported stale.

Decision (spec §6.1 says "rewritten"): the new rules go in a new script; `g1c-check-globals.py` keeps guarding the not-yet-converted handlers and is deleted in Task 9. Both run in CI until then.

- [ ] **Step 1: Write the failing tests `scripts/test_g1d_check_actions.py`**

```python
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("g1d", REPO_ROOT / "scripts" / "g1d-check-actions.py")
g = importlib.util.module_from_spec(spec)
spec.loader.exec_module(g)

ACTIONS_JS = "export const EVENT_TYPES = ['click', 'change'];\n"
GLOBALS = """export const HANDLER_FUNCTIONS = {
  legacyFn,
};
export const ACTIONS = {
  ...HANDLER_FUNCTIONS,
  openRun,
  stopEvent,
};
"""


def make(html, js="", globals_js=GLOBALS, baseline=None):
    d = Path(tempfile.mkdtemp())
    (d / "src" / "core").mkdir(parents=True)
    (d / "index.html").write_text(html, encoding="utf-8")
    (d / "src" / "core" / "actions.js").write_text(ACTIONS_JS, encoding="utf-8")
    (d / "src" / "globals.js").write_text(globals_js, encoding="utf-8")
    (d / "src" / "a.js").write_text(js, encoding="utf-8")
    b = d / "baseline.json"
    b.write_text(json.dumps(baseline if baseline is not None else g.counts(d)), encoding="utf-8")
    return d, b


CLEAN_HTML = '<a data-on-click="openRun" data-args="[1]"></a><b data-on-change="stopEvent"></b>'


class TestActions(unittest.TestCase):
    def test_clean_tree_passes(self):
        d, b = make(CLEAN_HTML)
        self.assertEqual(g.check(d, b), [])

    def test_unregistered_markup_action_fails(self):
        d, b = make(CLEAN_HTML + '<i data-on-click="ghost"></i>')
        self.assertIn("unregistered action: ghost", g.check(d, b))

    def test_unregistered_on_call_fails(self):
        d, b = make(CLEAN_HTML, "x = '<b' + on('click', 'ghost', 1) + '>';\n")
        self.assertIn("unregistered action: ghost", g.check(d, b))

    def test_unknown_event_type_fails(self):
        d, b = make(CLEAN_HTML + '<i data-on-dblclick="openRun"></i>')
        self.assertIn("unknown event type: dblclick", g.check(d, b))

    def test_unused_explicit_action_fails_but_spread_entries_are_exempt(self):
        d, b = make('<a data-on-click="openRun"></a>')
        errs = g.check(d, b)
        self.assertIn("unused action: stopEvent", errs)
        self.assertNotIn("unused action: legacyFn", errs)

    def test_name_passed_as_a_string_literal_counts_as_used(self):
        d, b = make('<a data-on-click="openRun"></a>', "covSegHtml(items, v, 'stopEvent');\n")
        self.assertEqual(g.check(d, b), [])

    def test_inline_count_may_not_grow(self):
        d, b = make(CLEAN_HTML, baseline={"inline_handlers": 0, "javascript_urls": 0})
        (d / "src" / "a.js").write_text("s = '<b onclick=\"f()\">';\n", encoding="utf-8")
        self.assertIn("inline handlers: 1 > baseline 0", g.check(d, b))

    def test_inline_count_drop_requires_baseline_update(self):
        d, b = make(CLEAN_HTML, baseline={"inline_handlers": 5, "javascript_urls": 1})
        errs = g.check(d, b)
        self.assertIn("inline handlers: 0 < baseline 5 -- run with --update-baseline", errs)
        self.assertIn("javascript: URLs: 0 < baseline 1 -- run with --update-baseline", errs)

    def test_data_on_attribute_is_not_counted_as_inline(self):
        self.assertEqual(g.counts(make(CLEAN_HTML)[0]), {"inline_handlers": 0, "javascript_urls": 0})

    def test_counts_markup_and_template_handlers_and_js_urls(self):
        d, _ = make('<a href="javascript:void(0)" onclick="f()"></a>', "s = '<b onchange=\\\"g()\\\">';\n")
        self.assertEqual(g.counts(d), {"inline_handlers": 2, "javascript_urls": 1})


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run to verify failure**

Run: `cd scripts && python3 -m unittest test_g1d_check_actions -v`
Expected: FAIL — `FileNotFoundError ... g1d-check-actions.py`.

- [ ] **Step 3: Write `scripts/g1d-check-actions.py`**

```python
"""G1d action registry + inline-handler ratchet (G1d spec section 6.1).
Stdlib only. Usage: python3 scripts/g1d-check-actions.py [web_dir] [--update-baseline]"""
import json
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_WEB = REPO_ROOT / "orchestrator" / "web"
DEFAULT_BASELINE = REPO_ROOT / "scripts" / "g1d-inline-baseline.json"

# on<event>= as an attribute (markup or inside a JS string); data-on-click= is
# excluded because "on" there follows "-".
INLINE_HANDLER = re.compile(r"""(?<![\w-])on[a-z]{3,}=\\?["']""")
JS_URL = re.compile(r"javascript:", re.I)
DATA_ON = re.compile(r'data-on-([a-z]+)="([^"]*)"')
ON_CALL = re.compile(r"""(?<![\w$.])on\(\s*['"]([a-z]+)['"]\s*,\s*['"]([A-Za-z_$][\w$]*)['"]""")
STRING_NAME = re.compile(r"""['"]([A-Za-z_$][\w$]*)['"]""")


def _block(js, const):
    m = re.search(r"export const " + const + r" = [\[{](.*?)[\]}];", js, re.S)
    if not m:
        raise ValueError(f"no {const}")
    return [t.strip().strip("',") for t in m.group(1).split("\n") if t.strip().strip("',")]


def _sources(web_dir):
    web_dir = Path(web_dir)
    html = (web_dir / "index.html").read_text(encoding="utf-8")
    js = {p: p.read_text(encoding="utf-8") for p in sorted((web_dir / "src").rglob("*.js"))}
    return web_dir, html, js


def counts(web_dir):
    _, html, js = _sources(web_dir)
    texts = [html, *js.values()]
    return {
        "inline_handlers": sum(len(INLINE_HANDLER.findall(t)) for t in texts),
        "javascript_urls": sum(len(JS_URL.findall(t)) for t in texts),
    }


def check(web_dir, baseline_path=DEFAULT_BASELINE):
    web_dir, html, js = _sources(web_dir)
    globals_js = js[web_dir / "src" / "globals.js"]
    event_types = set(_block(js[web_dir / "src" / "core" / "actions.js"], "EVENT_TYPES"))
    entries = _block(globals_js, "ACTIONS")
    explicit = {e for e in entries if not e.startswith("...")}
    registered = set(explicit)
    for e in entries:
        if e.startswith("..."):
            registered |= set(_block(globals_js, e[3:]))

    errors, used = [], set()
    app_js = [t for p, t in js.items() if p.name != "globals.js"]
    for text in [html, *app_js]:
        for ev, name in DATA_ON.findall(text) + ON_CALL.findall(text):
            used.add(name)
            if ev not in event_types:
                errors.append(f"unknown event type: {ev}")
            if name not in registered:
                errors.append(f"unregistered action: {name}")
    for text in app_js:
        used |= set(STRING_NAME.findall(text))
    for name in sorted(explicit - used):
        errors.append(f"unused action: {name}")

    now = counts(web_dir)
    base = json.loads(Path(baseline_path).read_text(encoding="utf-8"))
    for key, label in (("inline_handlers", "inline handlers"), ("javascript_urls", "javascript: URLs")):
        if now[key] > base[key]:
            errors.append(f"{label}: {now[key]} > baseline {base[key]}")
        elif now[key] < base[key]:
            errors.append(f"{label}: {now[key]} < baseline {base[key]} -- run with --update-baseline")
    return sorted(set(errors))


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    web = Path(args[0]) if args else DEFAULT_WEB
    if "--update-baseline" in sys.argv:
        DEFAULT_BASELINE.write_text(json.dumps(counts(web), indent=2) + "\n", encoding="utf-8")
        print(f"baseline updated: {counts(web)}")
    errors = check(web)
    if errors:
        print("G1d action check: FAIL")
        for e in errors:
            print(f"  {e}")
        return 1
    print(f"G1d action check: OK {counts(web)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

Run: `cd scripts && python3 -m unittest test_g1d_check_actions -v` → Expected: 10 tests OK.

- [ ] **Step 4: Teach `g1c-check-globals.py` about converted handlers — failing test first.** Append to `TestRegistry` in `scripts/test_g1c_check_globals.py`:

```python
    def test_handler_moved_to_data_on_or_on_call_is_not_stale(self):
        d = make('<a data-on-click="openThing"></a>', "x = on('click', 'doOther');\ny = seg('thirdFn');\n",
                 fns=["openThing", "doOther", "thirdFn"])
        self.assertEqual(g.check(d), [])
```

If the test file's `make` helper does not take `fns`, read it (`grep -n "def make" -A25 scripts/test_g1c_check_globals.py`) and build the `HANDLER_FUNCTIONS` block the same way the existing tests do; the assertion is what matters. Run `cd scripts && python3 -m unittest test_g1c_check_globals` → FAIL (`stale: openThing` …).

Then in `scripts/g1c-check-globals.py` add, below `STRING_LIT`:

```python
# Handlers converted to G1d actions are "called" through data-on-* names,
# literal on('evt', 'name') calls, or names passed around as strings.
DATA_ON = re.compile(r'data-on-[a-z]+="([^"]*)"')
ON_CALL_NAME = re.compile(r"""(?<![\w$.])on\(\s*['"][a-z]+['"]\s*,\s*['"]([A-Za-z_$][\w$]*)['"]""")
STRING_NAME = re.compile(r"""['"]([A-Za-z_$][\w$]*)['"]""")
```

and in `check()`, after the `for text in sources:` loop, add:

```python
    for text in sources:
        called |= set(DATA_ON.findall(text)) | set(ON_CALL_NAME.findall(text))
    for text in js_texts:
        called |= set(STRING_NAME.findall(text))
```

Rerun → all tests OK.

- [ ] **Step 5: Record the baseline and run both checks on the real tree**

```bash
cd /c/Users/Administrator/Downloads/Audspect_Cloud
python3 scripts/g1d-check-actions.py --update-baseline
python3 scripts/g1c-check-globals.py
cat scripts/g1d-inline-baseline.json
```
Expected: `G1d action check: OK {...}` with `inline_handlers` ≈ 621 (388 markup + ~233 in `src`, after Task 2 removed one) and `javascript_urls` 13; `G1c globals registry check: OK`.

- [ ] **Step 6: CI** — in `.github/workflows/test.yml`, in the `G1c globals registry check` step's `run:` block, append:

```yaml
          python3 scripts/g1d-check-actions.py
          cd scripts && python3 -m unittest test_g1d_check_actions -v
```

(The step already `cd scripts` for the g1c unittest on its last line — put the g1d script line before that `cd`, and make the g1d unittest part of the same `python3 -m unittest` invocation: `python3 -m unittest test_g1c_check_globals test_g1d_check_actions -v`.)

- [ ] **Step 7: Commit and push**

```bash
git add scripts/g1d-check-actions.py scripts/test_g1d_check_actions.py scripts/g1d-inline-baseline.json scripts/g1c-check-globals.py scripts/test_g1c_check_globals.py .github/workflows/test.yml
git commit -m "ci(g1d): action registry check and inline-handler ratchet

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
git push
```

---

### Task 4: Smoke harness — both handler forms, CSP and strict modes, action clicks

**Files:**
- Create: `orchestrator/web/tests/smoke/csp-policy.txt`
- Modify: `orchestrator/web/tests/smoke/smoke.spec.mjs`, `orchestrator/web/tests/smoke/serve.mjs`, `orchestrator/web/tools/smoke.sh`

**Interfaces:**
- Produces: env `SMOKE_CSP=enforce|report-only` (serve the policy), `SMOKE_STRICT=1` (fail on any `on*` attribute or `javascript:` URL in the live DOM); `csp-policy.txt` is the single policy text that Task 10's Go test compares against.

- [ ] **Step 1: `orchestrator/web/tests/smoke/csp-policy.txt`** (one line, no trailing spaces, newline at end):

```
default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'self'; object-src 'none'; frame-ancestors 'none'; report-uri /api/csp-report
```

- [ ] **Step 2: `serve.mjs`** — add `'.woff2': 'font/woff2'` to `types`, add after the `types` line:

```js
// SMOKE_CSP=enforce|report-only serves the dashboard policy (G1d), read from
// csp-policy.txt -- the same text the Go server's test pins.
const cspMode = process.env.SMOKE_CSP || '';
const csp = readFileSync(new URL('./csp-policy.txt', import.meta.url), 'utf8').trim();
const cspHeader = cspMode === 'enforce' ? 'Content-Security-Policy' : cspMode === 'report-only' ? 'Content-Security-Policy-Report-Only' : '';
```

add `import { readFileSync } from 'node:fs';` to the imports, and change the success `writeHead` to:

```js
    const headers = { 'Content-Type': types[extname(file)] || 'application/octet-stream' };
    if (cspHeader) headers[cspHeader] = csp;
    res.writeHead(200, headers).end(body);
```

- [ ] **Step 3: `smoke.spec.mjs`** — four edits.

(a) In `boot()`'s `addInitScript` callback, after `window.__xss = undefined;` add:

```js
    // Every CSP violation is an error (G1d). Without a policy header this
    // never fires.
    document.addEventListener('securitypolicyviolation', (e) => {
      console.error(`csp: ${e.effectiveDirective} blocked ${e.blockedURI || 'inline'} at ${e.sourceFile || ''}:${e.lineNumber || 0}`);
    });
```

(b) Replace `tabNames` with:

```js
// Tabs are discovered from the markup -- inline onclick="showTab('x')" or the
// G1d form data-on-click="showTab" data-args='["x"]' -- never from app internals.
async function tabNames(page) {
  return page.$$eval('[onclick^="showTab(\'"], [data-on-click="showTab"]', (els) => [...new Set(els.map((e) => {
    const a = e.getAttribute('data-args');
    return a ? JSON.parse(a)[0] : e.getAttribute('onclick').match(/showTab\('([^']+)'\)/)[1];
  }))].sort());
}

async function openTab(page, tab) {
  await page.evaluate((t) => {
    const el = [...document.querySelectorAll('[data-on-click="showTab"]')].find((e) => JSON.parse(e.getAttribute('data-args') || '[]')[0] === t)
      || document.querySelector(`[onclick="showTab('${t}')"]`);
    el.click(); // element.click(): some nav entries live in a collapsed dropdown
  }, tab);
}

// Inline handlers and javascript: URLs left in the live DOM (G1d strict mode).
async function inlineLeft(page) {
  return page.evaluate(() => {
    const out = [];
    for (const el of document.querySelectorAll('*')) {
      for (const a of el.attributes) {
        if (/^on[a-z]+$/.test(a.name)) out.push(`inline handler left: ${a.name} on <${el.tagName.toLowerCase()}${el.id ? '#' + el.id : ''}>`);
        if ((a.name === 'href' || a.name === 'src' || a.name === 'action') && /^\s*javascript:/i.test(a.value)) out.push(`javascript: URL left on <${el.tagName.toLowerCase()}${el.id ? '#' + el.id : ''}>`);
      }
    }
    return [...new Set(out)].sort();
  });
}

// One representative action per tab beyond the tab switch (G1d spec 6.3).
const ACTION_CLICKS = {
  agents: '#agent-toolbar button:nth-child(2)',
  campaigns: '#campaign-toolbar button:nth-child(2)',
};
```

(c) In the test body, replace the two lines

```js
    await page.$eval(`[onclick="showTab('${tab}')"]`, (el) => el.click());
    await page.waitForTimeout(400);
```
with
```js
    await openTab(page, tab);
    await page.waitForTimeout(400);
    const extra = [];
    if (ACTION_CLICKS[tab]) {
      const hit = await page.evaluate((sel) => { const el = document.querySelector(sel); if (!el) return false; el.click(); return true; }, ACTION_CLICKS[tab]);
      if (!hit) extra.push(`action click target missing: ${ACTION_CLICKS[tab]}`);
      await page.waitForTimeout(300);
    }
    if (process.env.SMOKE_STRICT === '1') extra.push(...await inlineLeft(page));
```

(d) Change the `result.tabs[tab] = …` line to include `extra`:

```js
    result.tabs[tab] = [...new Set([...errors, ...missing, ...extra, ...unresolved.map((n) => `unresolved handler: ${n}`)])].sort();
```

- [ ] **Step 4: `tools/smoke.sh`** — add `-e SMOKE_CSP -e SMOKE_STRICT` to the `docker run` arguments (passes the host values through when set), right after `-e "SMOKE_ROOT=$1"`.

- [ ] **Step 5: Verify the three modes on the current tree**

```bash
cd orchestrator/web && tools/node.sh sh -c 'npm run build' >/dev/null
tools/smoke.sh dist                                   # expected: 1 passed
SMOKE_STRICT=1 tools/smoke.sh dist 2>&1 | tail -5     # expected: 1 failed, "inline handler left: onclick ..."
SMOKE_CSP=enforce tools/smoke.sh dist 2>&1 | tail -5  # expected: 1 failed, "csp: script-src-attr blocked inline ..." (tab switches are still inline)
```
The two expected failures prove the strict and CSP modes bite; they become required in Task 12.

- [ ] **Step 6: Commit and push**

```bash
git add orchestrator/web/tests/smoke/csp-policy.txt orchestrator/web/tests/smoke/smoke.spec.mjs orchestrator/web/tests/smoke/serve.mjs orchestrator/web/tools/smoke.sh
git commit -m "test(web): smoke harness understands data-on actions; CSP and strict modes

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
git push
```

---

### Task 5: Codemod — mechanical static handlers in `index.html`

**Files:**
- Create: `orchestrator/web/tools/g1d-codemod.mjs`, `orchestrator/web/tests/unit/codemod.test.mjs` (both deleted in Task 9)
- Modify: `orchestrator/web/index.html`, `scripts/g1d-inline-baseline.json`

**Interfaces:**
- Consumes: `EVENT_TYPES`, `on()` from `src/core/actions.js`.
- Produces: `convertHandler(event: string, body: string) -> string | null` (attribute text from `on()`, or `null` = leave for hand conversion); `convertHtml(html) -> { html, converted: number, skipped: [{line, attr}] }`.

- [ ] **Step 1: Failing tests `orchestrator/web/tests/unit/codemod.test.mjs`**

```js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { convertHandler, convertHtml } from '../../tools/g1d-codemod.mjs';
import { on } from '../../src/core/actions.js';

test('single call with literal args becomes the same text on() produces', () => {
  assert.equal(convertHandler('click', "showTab('agents')"), on('click', 'showTab', 'agents'));
  assert.equal(convertHandler('change', "setThing('a', 3, -1.5, true, null)"), on('change', 'setThing', 'a', 3, -1.5, true, null));
  assert.equal(convertHandler('click', 'closeModal()'), on('click', 'closeModal'));
  assert.equal(convertHandler('click', 'closeModal();'), on('click', 'closeModal'));
});

test('escaped quotes inside a JS string survive', () => {
  assert.equal(convertHandler('click', "say('it\\'s')"), on('click', 'say', "it's"));
});

test('anything that is not a single call with literal args is left alone', () => {
  for (const body of ['setPF(this.value)', 'event.stopPropagation()', "a(); b()", "x = 1", 'f(g())', 'f(someVar)', "f('a' + b)", 'obj.method()']) {
    assert.equal(convertHandler('click', body), null, body);
  }
});

test('unsupported event types are left alone', () => {
  assert.equal(convertHandler('dblclick', 'f()'), null);
});

test('convertHtml decodes attribute entities, rewrites and reports skips with line numbers', () => {
  const src = '<a onclick="showTab(&#39;x&#39;)">a</a>\n<b onclick="setPF(this.value)">b</b>\n<i data-on-click="kept"></i>';
  const out = convertHtml(src);
  assert.equal(out.converted, 1);
  assert.equal(out.html.split('\n')[0], `<a${on('click', 'showTab', 'x')}>a</a>`);
  assert.deepEqual(out.skipped, [{ line: 2, attr: 'onclick="setPF(this.value)"' }]);
  assert.equal(out.html.split('\n').length, 3);
});
```

Run: `cd orchestrator/web && tools/node.sh node --test tests/unit/codemod.test.mjs` → FAIL (`Cannot find module`).

- [ ] **Step 2: Write `orchestrator/web/tools/g1d-codemod.mjs`**

```js
// One-time G1d codemod (deleted in Task 9): converts inline handlers in
// index.html that are a single call with literal arguments into data-on-*
// actions via on(). Everything else is reported for hand conversion.
// Run: node tools/g1d-codemod.mjs [--write]
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { EVENT_TYPES, on } from '../src/core/actions.js';

const ENTITIES = { '&amp;': '&', '&lt;': '<', '&gt;': '>', '&quot;': '"', '&#39;': "'", '&apos;': "'" };
const decode = (s) => s.replace(/&(?:amp|lt|gt|quot|apos|#39);|&#(\d+);|&#x([0-9a-f]+);/gi, (m, d, h) => (d ? String.fromCodePoint(+d) : h ? String.fromCodePoint(parseInt(h, 16)) : ENTITIES[m.toLowerCase()]));

// Parses a comma-separated list of JS literals; returns null on anything else.
function parseArgs(s) {
  const out = []; let i = 0;
  const ws = () => { while (i < s.length && /\s/.test(s[i])) i++; };
  ws();
  if (i === s.length) return out;
  for (;;) {
    ws();
    const q = s[i];
    if (q === "'" || q === '"') {
      let v = ''; i++;
      while (i < s.length && s[i] !== q) {
        if (s[i] === '\\') { i++; const c = s[i]; v += c === 'n' ? '\n' : c === 't' ? '\t' : c; i++; } else { v += s[i++]; }
      }
      if (s[i] !== q) return null;
      i++; out.push(v);
    } else {
      const m = /^(-?\d+(?:\.\d+)?|true|false|null)(?![\w$])/.exec(s.slice(i));
      if (!m) return null;
      out.push(JSON.parse(m[1])); i += m[1].length;
    }
    ws();
    if (i === s.length) return out;
    if (s[i] !== ',') return null;
    i++;
  }
}

export function convertHandler(event, body) {
  if (!EVENT_TYPES.includes(event)) return null;
  const m = /^\s*([A-Za-z_$][\w$]*)\s*\(([\s\S]*)\)\s*;?\s*$/.exec(body);
  if (!m) return null;
  const args = parseArgs(m[2]);
  if (args === null) return null;
  return on(event, m[1], ...args);
}

export function convertHtml(html) {
  let converted = 0; const skipped = [];
  const lines = html.split('\n').map((line, n) => line.replace(/\son([a-z]+)="([^"]*)"/g, (whole, ev, raw) => {
    const attr = convertHandler(ev, decode(raw));
    if (attr === null) { skipped.push({ line: n + 1, attr: whole.trim() }); return whole; }
    converted++; return attr;
  }));
  return { html: lines.join('\n'), converted, skipped };
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const file = fileURLToPath(new URL('../index.html', import.meta.url));
  const { html, converted, skipped } = convertHtml(readFileSync(file, 'utf8'));
  for (const s of skipped) console.log(`skip L${s.line}: ${s.attr}`);
  console.log(`converted ${converted}, skipped ${skipped.length}`);
  if (process.argv.includes('--write')) writeFileSync(file, html);
}
```

Run: `tools/node.sh node --test tests/unit/codemod.test.mjs` → PASS, 5 tests.

- [ ] **Step 3: Dry run, then write**

```bash
tools/node.sh node tools/g1d-codemod.mjs > /tmp/g1d-skips.txt; tail -1 /tmp/g1d-skips.txt
```
Expected: `converted 33x, skipped 4x` (≈338 / ≈50). Keep `/tmp/g1d-skips.txt` — it is Task 6's worklist. Then `tools/node.sh node tools/g1d-codemod.mjs --write`.

- [ ] **Step 4: Gate**

```bash
tools/node.sh sh -c 'npx eslint src --max-warnings=100000 && npm test && npm run build' && tools/smoke.sh dist
cd ../.. && python3 scripts/g1c-check-globals.py && python3 scripts/g1d-check-actions.py --update-baseline && PYTHONIOENCODING=utf-8 bash scripts/g1-run-local.sh 2>&1 | grep -E "eliminated|new sink|guard:"
```
Expected: smoke `1 passed` (tabs are now discovered and opened through `data-on-click="showTab"` and the dispatcher); both registry checks OK; `inline_handlers` baseline drops by the converted count; G1 guard PASS with no change (markup is outside the script and line counts are unchanged).

- [ ] **Step 5: Commit and push**

```bash
git add orchestrator/web/tools/g1d-codemod.mjs orchestrator/web/tests/unit/codemod.test.mjs orchestrator/web/index.html scripts/g1d-inline-baseline.json
git commit -m "refactor(web): convert single-call static handlers to data-on actions (codemod)

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
git push
```

---

### Task 6: Hand conversion — remaining static handlers in `index.html`

**Files:**
- Modify: `orchestrator/web/index.html`, the feature modules that own the called functions, `orchestrator/web/src/globals.js` (explicit `ACTIONS` entries + imports), `scripts/g1d-inline-baseline.json`

**Interfaces:**
- Consumes: Task 5's skip list (`/tmp/g1d-skips.txt`; regenerate with `tools/node.sh node tools/g1d-codemod.mjs` if lost).
- Produces: wrapper actions named by the rules below, each exported from the module that owns the wrapped function and listed explicitly in `ACTIONS`.

**Conversion rules (apply to every skipped handler; same rules in Task 7):**

| Original handler | Becomes | Wrapper (in the owning module) |
|---|---|---|
| `onclick="event.stopPropagation()"` | `data-on-click="stopEvent"` | none (`stopEvent` exists) |
| `onchange="setPF(this.value)"` | `data-on-change="setPFFromValue"` | `export function setPFFromValue() { setPF(this.value); }` |
| `onchange="toggleX('id', this.checked)"` | `data-on-change="toggleXFromChecked" data-args="[&quot;id&quot;]"` | `export function toggleXFromChecked(id) { toggleX(id, this.checked); }` |
| `onclick="event.stopPropagation(); openMenu('id')"` | `data-on-click="openMenuStop" data-args="[&quot;id&quot;]"` | `export function openMenuStop(id, el, event) { event.stopPropagation(); openMenu(id); }` |
| `oninput="scenarioView = 'search'; renderScenarios()"` | `data-on-input="scenarioSearchInput"` | `export function scenarioSearchInput() { state.scenarioView = 'search'; renderScenarios(); }` |
| `onclick="document.getElementById('sched-create-btn').disabled=!this.checked"` | `data-on-change="schedAuthToggle"` | `export function schedAuthToggle() { document.getElementById('sched-create-btn').disabled = !this.checked; }` |
| `<a href="javascript:void(0)" onclick="f()">` | `<a href="#" data-on-click="f">` | none (dispatcher prevents navigation) |

Naming: `<calledFn>From<Property>` for `this.<prop>` wrappers, `<calledFn>Stop` for stop-then-call, otherwise a verb phrase in the module's existing naming style. Wrappers are `function` declarations (not arrows) so `this` is the element. Body text is copied verbatim apart from `this.X` (kept) and bare state names (prefixed with `state.`, which must already be imported in that module).

- [ ] **Step 1: For each skip-list line**, apply the matching rule, add the wrapper next to the function it wraps, export it, and add it to `globals.js`: an import from the owning module and an explicit entry in `ACTIONS` (after `stopEvent`, alphabetical). Work in three commits: (1) `this`-reading handlers, (2) multi-statement and `event` handlers, (3) `javascript:` links in `index.html`.

- [ ] **Step 2: Gate per commit**

```bash
cd orchestrator/web && tools/node.sh sh -c 'npx eslint src --max-warnings=100000 && npm test && npm run build' && tools/smoke.sh dist
cd ../.. && python3 scripts/g1c-check-globals.py && python3 scripts/g1d-check-actions.py --update-baseline && PYTHONIOENCODING=utf-8 bash scripts/g1-run-local.sh 2>&1 | grep -E "eliminated|new sink|REVIEW|guard:"
```
Expected: all green; baseline decreases each commit; G1 guard PASS (wrappers add lines → line shifts only).

- [ ] **Step 3: Commit and push each of the three** (`refactor(web): hand-convert static <kind> handlers to actions`), staging `index.html`, the touched modules, `globals.js`, the baseline and any regenerated `Assessment/G1_*` files by name.

After the third commit: `grep -cE '\son[a-z]+="' orchestrator/web/index.html` → `0` and `grep -c 'javascript:' orchestrator/web/index.html` → `0`.

---

### Task 7: Templates — one module per commit

**Files:** per row: the module, `src/globals.js` (new wrappers), `orchestrator/web/tests/unit/xss.test.mjs` (one payload test per row that had concatenated arguments), `scripts/g1d-inline-baseline.json`, `Assessment/G1_*` (5).

**Interfaces:**
- Consumes: `on()`, `stopEvent`; rules from Task 6; G1 spike outcome (Task 2).

**Template rules** (in addition to Task 6's table):

| Before | After |
|---|---|
| `'<button onclick="openRun(\'' + x(r.id) + '\')">'` | `'<button' + on('click', 'openRun', r.id) + '>'` (raw value — `on()` escapes; never pass `x(...)` into `on()`) |
| `'<tr onclick="openFinding(\'' + x(f.id) + '\', ' + idx + ')">'` | `'<tr' + on('click', 'openFinding', f.id, idx) + '>'` |
| `' onchange="schedToggleGroup(' + node.id + ',this.checked)"'` | `on('change', 'schedToggleGroupFromChecked', node.id)` + wrapper `export function schedToggleGroupFromChecked(id) { schedToggleGroup(id, this.checked); }` |
| `'<td onclick="event.stopPropagation()">'` | `'<td' + on('click', 'stopEvent') + '>'` |
| `onclick="' + fnName + '(…)"` (name in a variable) | `on('click', fnName, …)` — the literal names passed in must be `ACTIONS` entries |
| `onclick="window.open(\'/api/x/' + encodeURIComponent(id) + '/report\',\'_blank\')"` | wrapper `export function openSweepReport(id) { window.open('/api/x/' + encodeURIComponent(id) + '/report', '_blank'); }` + `on('click', 'openSweepReport', id)` |

Numbers stay numbers (`on(..., idx)`), IDs stay strings; if the old handler quoted a number (`'\'' + n + '\''`), pass `String(n)` so the called function receives the same type.

**Per-row procedure** (each row = one commit):

1. Convert every `on<event>=` and `javascript:` in the module per the rules; add wrappers + `ACTIONS` entries; import `on` (and `stopEvent` if used) from `../core/actions.js`.
2. If the row converted concatenated arguments, export the render function whose output carries the most API-controlled data and add a payload test to `tests/unit/xss.test.mjs`, following this pattern (Task 9 of G1c set up `load`/`PAYLOADS`):

```js
test('<module>: <renderFn> keeps payloads inside data-args', async () => {
  const { <renderFn> } = await load(['<renderFn>']);
  for (const p of PAYLOADS) {
    const div = document.createElement('div');
    div.innerHTML = <renderFn>(<a fixture object whose user-facing string fields are p>);
    assertInert(div, '<renderFn>');
    const args = [...div.querySelectorAll('[data-args]')].map((e) => e.getAttribute('data-args')).join(' ');
    assert.ok(args.includes(JSON.stringify(p).slice(1, -1)), 'payload should travel as data-args');
  }
});
```
(`<renderFn>` and its fixture are filled in per row from the function's real parameters; the assertion lines are fixed.)
3. Gate:

```bash
cd orchestrator/web && tools/node.sh sh -c 'npx eslint src --max-warnings=100000 && npm test && npm run build' && tools/smoke.sh dist
cd ../.. && python3 scripts/g1c-check-globals.py && python3 scripts/g1d-check-actions.py --update-baseline && PYTHONIOENCODING=utf-8 bash scripts/g1-run-local.sh 2>&1 | grep -E "current sinks|eliminated|new sink|REVIEW|guard:"
```
Expected: green; `0 slot(s) eliminated`, `0 new`. Every REVIEW line is a template sink whose new RHS uses `on(` and whose tier is unchanged — read each; anything else stops the row (systematic debugging).
4. `git status --porcelain orchestrator/web scripts Assessment` → stage exactly those files by name; commit `refactor(web): <module> handlers to actions (G1d)` with the REVIEW lines in the body; push.
5. `grep -cE "(^|[^\w-])on[a-z]{3,}=" orchestrator/web/src/features/<module>` → `0` before moving on.

**Rows** (handlers / `javascript:` per module, smallest first; counts from the design-time inventory — the per-row grep is authoritative):

- [ ] 7.1 `audit-logs.js` (1) · 7.2 `coverage.js` (1) · 7.3 `ransomware.js` (1) · 7.4 `variant-report.js` (1) · 7.5 `compliance.js` (2) · 7.6 `shell.js` (4) · 7.7 `iocs.js` (5) · 7.8 `scheduled.js` (5)
- [ ] 7.9 `threat-intel.js` (6) · 7.10 `evidence.js` (7) · 7.11 `live-run.js` (7) · 7.12 `agent-drawer.js` (8) · 7.13 `integrations.js` (8) · 7.14 `initiatives.js` (9)
- [ ] 7.15 `adversaries.js` (10) · 7.16 `variants.js` (11) · 7.17 `detection-verification.js` (12) · 7.18 `openaev.js` (12) · 7.19 `findings.js` (15) · 7.20 `endpoint-mastery.js` (17)
- [ ] 7.21 `campaigns.js` (18) · 7.22 `reports.js` (35 + 4 `javascript:`) · 7.23 `attack-path.js` (38 + 3 `javascript:`; covSegHtml already done)

`core/escape.js`'s single match is the word `onclick="..."` in its doc comment — reworded in Task 9.

---

### Task 8: Self-host the fonts

**Files:**
- Create: `orchestrator/web/fonts/inter-latin-wght-normal.woff2`, `space-grotesk-latin-wght-normal.woff2`, `jetbrains-mono-latin-wght-normal.woff2`, `orchestrator/web/fonts/OFL-inter.txt`, `OFL-space-grotesk.txt`, `OFL-jetbrains-mono.txt`
- Modify: `orchestrator/web/index.html` (remove the three Google Fonts `<link>` lines, lines 8–10 at design time), `orchestrator/web/styles/app.css` (add `@font-face` at the top), `orchestrator/web/tools/build.mjs` (copy `fonts/`; external `/fonts/*`), `orchestrator/web/tests/unit/build.test.mjs`

**Interfaces:** Produces `dist/fonts/*.woff2`, listed in `MANIFEST.sha256`.

- [ ] **Step 1: Failing build test** — add to `tests/unit/build.test.mjs` (inside the existing build test or as a new test that runs the build the same way the file's first test does):

```js
test('build ships self-hosted fonts and no external font origins', () => {
  const manifest = readFileSync(join(dist, 'MANIFEST.sha256'), 'utf8');
  for (const f of ['inter-latin-wght-normal.woff2', 'space-grotesk-latin-wght-normal.woff2', 'jetbrains-mono-latin-wght-normal.woff2']) {
    assert.match(manifest, new RegExp(`  fonts/${f}\\n`));
  }
  assert.doesNotMatch(readFileSync(join(dist, 'index.html'), 'utf8'), /fonts\.(googleapis|gstatic)\.com/);
});
```
(Reuse the file's existing `dist`/`readFileSync`/`join` names; if the build runs inside the first test, put this assertion block in a test that runs after it, as the existing tests are ordered.) Run `tools/node.sh node --test tests/unit/build.test.mjs` → FAIL.

- [ ] **Step 2: Vendor the font files (one time, pinned versions, OFL-1.1)**

```bash
cd orchestrator/web && mkdir -p fonts && tools/node.sh sh -c '
  cd /tmp &&
  for p in inter space-grotesk jetbrains-mono; do
    npm pack @fontsource-variable/$p@5.3.0 --silent >/dev/null && tar xzf fontsource-variable-$p-5.3.0.tgz &&
    cp package/files/$p-latin-wght-normal.woff2 /web/fonts/ && cp package/LICENSE /web/fonts/OFL-$p.txt && rm -rf package fontsource-variable-$p-5.3.0.tgz;
  done; ls -l /web/fonts'
```
Expected: three `.woff2` files and three `OFL-*.txt`. If a `files/*-latin-wght-normal.woff2` name differs in that version, `ls package/files` and use the `latin` + `wght` + `normal` file; record the actual names in the ledger and use them in Steps 3–4.

- [ ] **Step 3: `styles/app.css`** — insert at the very top:

```css
/* Self-hosted (G1d: font-src 'self'; air-gapped installs). OFL-1.1, see fonts/OFL-*.txt.
   Variable fonts from @fontsource-variable 5.3.0, latin subset. */
@font-face { font-family: 'Inter'; font-style: normal; font-display: swap; font-weight: 100 900; src: url(/fonts/inter-latin-wght-normal.woff2) format('woff2'); }
@font-face { font-family: 'Space Grotesk'; font-style: normal; font-display: swap; font-weight: 300 700; src: url(/fonts/space-grotesk-latin-wght-normal.woff2) format('woff2'); }
@font-face { font-family: 'JetBrains Mono'; font-style: normal; font-display: swap; font-weight: 100 800; src: url(/fonts/jetbrains-mono-latin-wght-normal.woff2) format('woff2'); }
```
Confirm the family names match the CSS variables: `grep -n "\-\-font-" styles/app.css | head` must reference `'Inter'`, `'Space Grotesk'`, `'JetBrains Mono'` (adjust the `font-family` names above to exactly what those variables use).

- [ ] **Step 4: `tools/build.mjs`** — change `external: ['/images/*', '/assets/*']` to `external: ['/images/*', '/assets/*', '/fonts/*']` and after `cpSync(join(web, 'images'), join(dist, 'images'), { recursive: true });` add `cpSync(join(web, 'fonts'), join(dist, 'fonts'), { recursive: true, filter: (p) => !p.endsWith('.txt') });`. Remove the three Google Fonts `<link>` lines from `index.html`.

- [ ] **Step 5: Gate** — `tools/node.sh sh -c 'npm test && npm run build' && tools/smoke.sh dist` → green. `git check-attr -a orchestrator/web/fonts/inter-latin-wght-normal.woff2` must not show `eol` (binary; the `orchestrator/web/**` eol rules cover text extensions only).

- [ ] **Step 6: Commit and push**

```bash
git add orchestrator/web/fonts orchestrator/web/styles/app.css orchestrator/web/index.html orchestrator/web/tools/build.mjs orchestrator/web/tests/unit/build.test.mjs
git commit -m "build(web): self-host Inter, Space Grotesk, JetBrains Mono (OFL) -- no external font origin

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
git push
```

---

### Task 9: Cleanup — explicit registry, no window surface, retire migration tools

**Files:**
- Modify: `orchestrator/web/src/globals.js`, `src/main.js`, modules reading `window[...]` state or `window.<WINDOW_WRITES>`, `src/core/state.js`, `src/core/escape.js` (comment), `orchestrator/web/eslint.config.mjs`, `scripts/g1d-check-actions.py` (+ test), `orchestrator/web/README.md`, `.github/workflows/test.yml`
- Delete: `scripts/g1c-check-globals.py`, `scripts/test_g1c_check_globals.py`, `orchestrator/web/tools/g1d-codemod.mjs`, `orchestrator/web/tests/unit/codemod.test.mjs`

**Interfaces:**
- Produces: `ACTIONS` as an explicit list (no spread); `WINDOW_WRITES` kept as the documented allowlist checked by `g1d-check-actions.py`; no `installGlobals`.

- [ ] **Step 1: Failing check tests** — append to `scripts/test_g1d_check_actions.py`:

```python
    def test_window_write_outside_allowlist_fails(self):
        g_js = GLOBALS + "export const WINDOW_WRITES = [\n  'onRunEvent',\n];\n"
        d, b = make(CLEAN_HTML, "window.onRunEvent = f;\nwindow.sneaky = 1;\n", globals_js=g_js)
        self.assertIn("window write not in WINDOW_WRITES: sneaky", g.check(d, b))

    def test_window_bracket_lookup_fails(self):
        d, b = make(CLEAN_HTML, "var sel = window[name];\n")
        self.assertIn("window[...] lookup in src/a.js", g.check(d, b))
```
Run → FAIL. Then in `check()` add (before the ratchet block):

```python
    window_writes = set(_block(globals_js, "WINDOW_WRITES")) if "WINDOW_WRITES" in globals_js else set()
    for p, text in js.items():
        if p.name == "globals.js":
            continue
        for name in re.findall(r"(?<![\w$.])window\.([A-Za-z_$][\w$]*)\s*=(?!=)", text):
            if name not in window_writes:
                errors.append(f"window write not in WINDOW_WRITES: {name}")
        if re.search(r"(?<![\w$.])window\[", text):
            errors.append(f"window[...] lookup in {p.relative_to(web_dir).as_posix()}")
```
Rerun → OK.

- [ ] **Step 2: Remove `window[...]` state lookups.** `grep -rn "window\[" orchestrator/web/src` — for `renderGroupCheckboxList` (and any other hit), replace `window[stateVarName]` with `state[stateVarName]` (callers pass the same names: `_tmplGroupSel`, `_groupSel`, `_vexGroupSel`, `_vexRunGroupSel`, all in `state`), importing `state` if needed.

- [ ] **Step 3: Review `WINDOW_WRITES`.** For each of `_campaigns _cmdkBound _covCounts _covSt _covTactics _evidenceResults _findings _rems _slaReport`: replace `window.<name>` with `state.<name>` and add `<name>: undefined,` to `src/core/state.js`. For `openRunPanel`, `onRunEvent`, `toggleLiveStep`: they are assigned inside a closure in `features/live-run.js`; turn each into an exported function at module level (or export a module-level `let` assigned by the closure), import it where it is called, and register `toggleLiveStep`/`openRunPanel` in `ACTIONS` if a `data-on-*`/`on()` names them. Keep in `WINDOW_WRITES` only a name some code outside the bundle still needs (e.g. the WebSocket hub callback if it is wired through `window`), each with a one-line comment saying why. Target: `WINDOW_WRITES` empty or ≤ 3 documented entries.

- [ ] **Step 4: Explicit registry.** In `globals.js`: replace the `...HANDLER_FUNCTIONS,` spread in `ACTIONS` with the explicit names — exactly those `g1d-check-actions.py` reports as used (run it after deleting the spread; every `unregistered action: X` names an entry to add, every `unused action: X` an entry to drop). Delete `HANDLER_FUNCTIONS`, `DYNAMIC_HANDLERS`, `STATE_GLOBALS` and `installGlobals`; drop imports that become unused (ESLint `no-unused-vars` is not enabled — check with `grep`). In `main.js`: `import { ACTIONS } from './globals.js';` and remove the `installGlobals();` line.

- [ ] **Step 5: Retire migration tools and lock the ratchet**

```bash
git rm scripts/g1c-check-globals.py scripts/test_g1c_check_globals.py orchestrator/web/tools/g1d-codemod.mjs orchestrator/web/tests/unit/codemod.test.mjs
```
Reword the `core/escape.js` doc comment's `onclick="..."` to `an inline handler attribute`. In `.github/workflows/test.yml`, rename the `G1c globals registry check` step to `G1d action registry check` and make its `run:` block:

```yaml
          python3 scripts/g1d-check-actions.py
          cd scripts && python3 -m unittest test_g1d_check_actions -v
```
Run `python3 scripts/g1d-check-actions.py --update-baseline` → `{'inline_handlers': 0, 'javascript_urls': 0}`.

- [ ] **Step 6: ESLint ban** — in `eslint.config.mjs` `rules`, add:

```js
      'no-restricted-syntax': ['error',
        { selector: 'Literal[value=/(^|[^\\w-])on[a-z]{3,}=/]', message: 'Inline event handler in markup: use on() from core/actions.js (G1d).' },
        { selector: 'TemplateElement[value.raw=/(^|[^\\w-])on[a-z]{3,}=/]', message: 'Inline event handler in markup: use on() from core/actions.js (G1d).' },
        { selector: 'Literal[value=/javascript:/i]', message: 'javascript: URL (G1d).' },
      ],
```
Prove it bites: temporarily add `const t = '<b onclick="f()">';` to any module → `npx eslint src` reports the error; remove it.

- [ ] **Step 7: README** — in `orchestrator/web/README.md` replace the `src/globals.js` bullet with:

```markdown
- `src/globals.js` — the `ACTIONS` registry. Markup attaches behaviour only with `data-on-<event>="name"` (static HTML) or `on('<event>', 'name', ...args)` (templates); `src/core/actions.js` dispatches through `ACTIONS`, never through `window`. `scripts/g1d-check-actions.py` fails on unregistered/unused actions, any inline `on…=` handler or `javascript:` URL, and window writes outside `WINDOW_WRITES`.
```

- [ ] **Step 8: Gate (strict mode now required)**

```bash
cd orchestrator/web && tools/node.sh sh -c 'npx eslint src && npm test && npm run build' && SMOKE_STRICT=1 tools/smoke.sh dist
cd ../.. && python3 scripts/g1d-check-actions.py && PYTHONIOENCODING=utf-8 bash scripts/g1-run-local.sh 2>&1 | grep -E "eliminated|new sink|REVIEW|guard:"
grep -rn "window\.[A-Za-z_$]* *=[^=]" orchestrator/web/src | grep -v "^orchestrator/web/src/globals.js"
```
Expected: all green; strict smoke `1 passed`; the last grep lists only `WINDOW_WRITES` names.

- [ ] **Step 9: Commit and push** — stage every touched/deleted file by name (`git status --porcelain` first), plus the baseline and `Assessment/G1_*`; message `refactor(web): explicit ACTIONS registry; no app names on window (G1d cleanup)`. In CI, set the smoke step's env to include `SMOKE_STRICT: '1'` in the same commit.

---

### Task 10: Go — `BAS_CSP_MODE` and the header

**Files:**
- Modify: `orchestrator/config/config.go`, `orchestrator/config/config_test.go`, `orchestrator/cmd/server/static.go`, `orchestrator/cmd/server/static_test.go`, `orchestrator/cmd/server/main.go` (the `StaticHandler()` call, line ~842)

**Interfaces:**
- Produces: `Config.CSPMode string` (`"enforce"`|`"report-only"`); `const dashboardCSP string`; `func cspHeaderName(mode string) string`; `func cspHeaders(mode string, h http.Handler) http.Handler`; `func StaticHandler(cspMode string) http.Handler`.

- [ ] **Step 1: Failing config tests** — read how existing tests call `Load` (`grep -n "Load(" orchestrator/config/config_test.go | head -3`) and add, in that style:

```go
func TestLoad_CSPMode(t *testing.T) {
	for _, tc := range []struct{ env, want string; wantErr bool }{
		{"", "enforce", false},
		{"enforce", "enforce", false},
		{"report-only", "report-only", false},
		{" Report-Only ", "report-only", false},
		{"ENFORCE", "enforce", false},
		{"off", "", true},
		{"none", "", true},
		{"reportonly", "", true},
	} {
		t.Run(tc.env, func(t *testing.T) {
			t.Setenv("BAS_CSP_MODE", tc.env)
			cfg, err := Load("")
			if tc.wantErr {
				if err == nil || !strings.Contains(err.Error(), "BAS_CSP_MODE") {
					t.Fatalf("Load() err = %v, want a BAS_CSP_MODE error", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Load() err = %v", err)
			}
			if cfg.CSPMode != tc.want {
				t.Fatalf("CSPMode = %q, want %q", cfg.CSPMode, tc.want)
			}
		})
	}
}
```
(If `Load("")` is not how tests obtain a default config, use the same call the neighbouring tests use; the cases are what matter.) Run `cd orchestrator && go test ./config -run CSPMode -count=1` → FAIL (`cfg.CSPMode undefined`).

- [ ] **Step 2: Implement** — in `Config`, next to `LegacyListenerEnabled`:

```go
	// CSPMode (BAS_CSP_MODE) selects how the dashboard Content-Security-Policy
	// is sent (G1d): "enforce" (default) or "report-only" -- the escape hatch
	// for a client hitting a violation. There is deliberately no "off"; any
	// other value fails Load.
	CSPMode string `json:"csp_mode,omitempty"`
```
In the defaults literal add `CSPMode: "enforce",`. After the `BAS_LEGACY_LISTENER_ENABLED` block add:

```go
	if v := strings.TrimSpace(os.Getenv("BAS_CSP_MODE")); v != "" {
		cfg.CSPMode = strings.ToLower(v)
	}
	if cfg.CSPMode != "enforce" && cfg.CSPMode != "report-only" {
		return nil, fmt.Errorf("BAS_CSP_MODE=%q: must be \"enforce\" or \"report-only\"", cfg.CSPMode)
	}
```
(add `strings` to the imports if absent). Run → PASS.

- [ ] **Step 3: Failing static tests** — append to `orchestrator/cmd/server/static_test.go`:

```go
func TestDashboardCSP_ScriptSrcIsStrict(t *testing.T) {
	dirs := map[string]string{}
	for _, d := range strings.Split(dashboardCSP, ";") {
		f := strings.Fields(d)
		if len(f) > 0 {
			dirs[f[0]] = strings.Join(f[1:], " ")
		}
	}
	if dirs["script-src"] != "'self'" {
		t.Fatalf("script-src = %q, want exactly 'self'", dirs["script-src"])
	}
	if dirs["default-src"] != "'none'" || dirs["object-src"] != "'none'" || dirs["base-uri"] != "'none'" || dirs["frame-ancestors"] != "'none'" {
		t.Fatalf("lockdown directives changed: %v", dirs)
	}
	for _, bad := range []string{"unsafe-eval", "unsafe-hashes", "*", "http:", "https:"} {
		if strings.Contains(dirs["script-src"], bad) || strings.Contains(dirs["default-src"], bad) {
			t.Fatalf("policy weakened with %q: %s", bad, dashboardCSP)
		}
	}
}

func TestDashboardCSP_MatchesSmokePolicy(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "web", "tests", "smoke", "csp-policy.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(string(raw)); got != dashboardCSP {
		t.Fatalf("smoke policy and server policy differ:\nsmoke:  %s\nserver: %s", got, dashboardCSP)
	}
}

func TestCSPHeaders_Modes(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	for mode, want := range map[string]string{"enforce": "Content-Security-Policy", "report-only": "Content-Security-Policy-Report-Only"} {
		rec := httptest.NewRecorder()
		cspHeaders(mode, inner).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
		if rec.Header().Get(want) != dashboardCSP {
			t.Errorf("%s: %s = %q", mode, want, rec.Header().Get(want))
		}
		other := "Content-Security-Policy-Report-Only"
		if want == other {
			other = "Content-Security-Policy"
		}
		if rec.Header().Get(other) != "" {
			t.Errorf("%s: unexpected %s header", mode, other)
		}
	}
}
```
Run `go test ./cmd/server -run 'DashboardCSP|CSPHeaders' -count=1` → FAIL (`undefined: dashboardCSP`).

- [ ] **Step 4: Implement in `static.go`** (after `cacheHeaders`):

```go
// dashboardCSP is the dashboard Content-Security-Policy (G1d spec 4.5).
// script-src is 'self' only -- no inline script, no eval, no hashes; the
// G1c build leaves no inline script, so no nonce is needed.
// TestDashboardCSP_ScriptSrcIsStrict fails if that ever changes.
// style-src 'unsafe-inline' is the staged G1e item (style= attributes).
// Must stay byte-identical to web/tests/smoke/csp-policy.txt.
const dashboardCSP = "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'self'; object-src 'none'; frame-ancestors 'none'; report-uri /api/csp-report"

func cspHeaderName(mode string) string {
	if mode == "report-only" {
		return "Content-Security-Policy-Report-Only"
	}
	return "Content-Security-Policy"
}

// cspHeaders sets the policy on every dashboard response (document and assets).
func cspHeaders(mode string, h http.Handler) http.Handler {
	name := cspHeaderName(mode)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(name, dashboardCSP)
		h.ServeHTTP(w, r)
	})
}
```
Change `func StaticHandler() http.Handler {` to `func StaticHandler(cspMode string) http.Handler {`, and its final `return cacheHeaders(http.FileServer(http.Dir(wwwrootDir)))` to:

```go
	if cspMode == "report-only" {
		log.Println("[~] dashboard CSP: report-only (BAS_CSP_MODE) -- violations are logged, not blocked")
	} else {
		log.Println("[+] dashboard CSP: enforce")
	}
	return cspHeaders(cspMode, cacheHeaders(http.FileServer(http.Dir(wwwrootDir))))
```
In `main.go` change `StaticHandler()` to `StaticHandler(cfg.CSPMode)`; `grep -rn "StaticHandler()" orchestrator` must then return nothing (update any other caller the same way).

- [ ] **Step 5: Verify**

```bash
cd orchestrator && go test ./config ./cmd/server -count=1 && go vet ./config ./cmd/server
for f in config/config.go cmd/server/static.go cmd/server/main.go cmd/server/static_test.go config/config_test.go; do tr -d '\r' < $f | gofmt -l; done
```
Expected: `ok` ×2; vet silent; gofmt prints nothing.

- [ ] **Step 6: Commit and push**

```bash
git add orchestrator/config/config.go orchestrator/config/config_test.go orchestrator/cmd/server/static.go orchestrator/cmd/server/static_test.go orchestrator/cmd/server/main.go
git commit -m "feat(security): dashboard Content-Security-Policy with BAS_CSP_MODE enforce|report-only

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
git push
```

---

### Task 11: Go — `POST /api/csp-report`

**Files:**
- Create: `orchestrator/internal/api/csp_report.go`, `orchestrator/internal/api/csp_report_test.go`
- Modify: `orchestrator/internal/api/routes.go` (public block), `orchestrator/internal/api/rbac_matrix_test.go` (`publicRoutes`)

**Interfaces:**
- Produces: `func (h *Handler) CSPReport(w http.ResponseWriter, r *http.Request)`; package vars `cspReportLimiter *rate.Limiter`, `cspReportsDropped atomic.Int64`; `func cleanCSPField(s string) string`.

Decision (spec §4.6 said "covered by the existing per-IP rate limiter"): the existing limiter is an opt-in global bucket for authenticated groups, not per-IP, so the endpoint gets its own global token bucket (1/s, burst 30); excess reports are dropped and counted, never logged individually. When the licence is locked, `LicenseGate` answers `/api/*` with 402 — reports are not accepted then, which is acceptable (the dashboard is unusable in that state).

- [ ] **Step 1: Failing tests `orchestrator/internal/api/csp_report_test.go`**

```go
package api

import (
	"bytes"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"golang.org/x/time/rate"
)

func postCSP(t *testing.T, ct, body string) (*httptest.ResponseRecorder, string) {
	t.Helper()
	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(prev)
	req := httptest.NewRequest(http.MethodPost, "/api/csp-report", strings.NewReader(body))
	req.Header.Set("Content-Type", ct)
	rec := httptest.NewRecorder()
	(&Handler{}).CSPReport(rec, req)
	return rec, buf.String()
}

func freshCSPLimiter(t *testing.T, burst int) {
	t.Helper()
	prev := cspReportLimiter
	cspReportLimiter = rate.NewLimiter(0, burst)
	cspReportsDropped.Store(0)
	t.Cleanup(func() { cspReportLimiter = prev; cspReportsDropped.Store(0) })
}

const legacyReport = `{"csp-report":{"document-uri":"https://bas.local/","violated-directive":"script-src-attr","effective-directive":"script-src-attr","blocked-uri":"inline","source-file":"https://bas.local/assets/app.X.js","line-number":12}}`

func TestCSPReport_LegacyFormatIsLogged(t *testing.T) {
	freshCSPLimiter(t, 10)
	rec, logs := postCSP(t, "application/csp-report", legacyReport)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", rec.Code)
	}
	for _, want := range []string{"[csp] violation", `directive="script-src-attr"`, `blocked="inline"`, "line=12"} {
		if !strings.Contains(logs, want) {
			t.Errorf("log missing %q: %s", want, logs)
		}
	}
}

func TestCSPReport_ReportingAPIFormatIsLogged(t *testing.T) {
	freshCSPLimiter(t, 10)
	body := `[{"type":"csp-violation","body":{"documentURL":"https://bas.local/","effectiveDirective":"font-src","blockedURL":"https://fonts.gstatic.com/x.woff2","sourceFile":"","lineNumber":0}},{"type":"deprecation","body":{}}]`
	rec, logs := postCSP(t, "application/reports+json", body)
	if rec.Code != http.StatusNoContent || strings.Count(logs, "[csp] violation") != 1 || !strings.Contains(logs, `directive="font-src"`) {
		t.Fatalf("status=%d logs=%s", rec.Code, logs)
	}
}

func TestCSPReport_RejectsOtherContentTypes(t *testing.T) {
	for _, ct := range []string{"application/json", "text/plain", ""} {
		if rec, _ := postCSP(t, ct, legacyReport); rec.Code != http.StatusUnsupportedMediaType {
			t.Errorf("%q: status = %d, want 415", ct, rec.Code)
		}
	}
}

func TestCSPReport_RejectsOversizedBody(t *testing.T) {
	big := `{"csp-report":{"blocked-uri":"` + strings.Repeat("a", 20<<10) + `"}}`
	if rec, _ := postCSP(t, "application/csp-report", big); rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", rec.Code)
	}
}

func TestCSPReport_RejectsMalformedJSON(t *testing.T) {
	if rec, _ := postCSP(t, "application/csp-report", `{"csp-report":`); rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestCSPReport_LogIsSanitized(t *testing.T) {
	freshCSPLimiter(t, 10)
	body := `{"csp-report":{"blocked-uri":"x\nFAKE LOG LINE\r\u0007` + strings.Repeat("b", 400) + `","effective-directive":"img-src"}}`
	_, logs := postCSP(t, "application/csp-report", body)
	if strings.Count(logs, "\n") != 1 {
		t.Fatalf("report produced %d log lines, want 1: %q", strings.Count(logs, "\n"), logs)
	}
	if strings.Contains(logs, "\a") || strings.Contains(logs, strings.Repeat("b", 300)) {
		t.Fatalf("control character or untruncated field in log: %q", logs)
	}
}

func TestCSPReport_FloodIsDroppedAndCounted(t *testing.T) {
	freshCSPLimiter(t, 2)
	var all string
	for i := 0; i < 5; i++ {
		_, logs := postCSP(t, "application/csp-report", legacyReport)
		all += logs
	}
	if n := strings.Count(all, "[csp] violation"); n != 2 {
		t.Fatalf("logged %d reports, want 2 (burst)", n)
	}
	if got := cspReportsDropped.Load(); got != 3 {
		t.Fatalf("dropped = %d, want 3", got)
	}
}
```
Run `cd orchestrator && go test ./internal/api -run CSPReport -count=1` → FAIL (`undefined: ... CSPReport`).

- [ ] **Step 2: Write `orchestrator/internal/api/csp_report.go`**

```go
package api

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"mime"
	"net/http"
	"strings"
	"sync/atomic"
	"unicode"

	"golang.org/x/time/rate"
)

// CSP violation reports (G1d spec 4.6). Browsers send them without the app's
// credentials, so this endpoint is public and trusts nothing: two content
// types, a 16 KB body cap, every logged value stripped of control characters
// and truncated, no database writes, and a global token bucket so a page
// stuck in a violation loop cannot flood the log (excess is counted).

const (
	cspReportMaxBytes = 16 << 10
	cspFieldMax       = 256
	cspMaxEntries     = 20
)

var (
	cspReportLimiter  = rate.NewLimiter(rate.Limit(1), 30)
	cspReportsDropped atomic.Int64
)

type cspViolation struct {
	DocumentURI, Directive, BlockedURI, SourceFile string
	Line                                           int
}

func (h *Handler) CSPReport(w http.ResponseWriter, r *http.Request) {
	ct, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if ct != "application/csp-report" && ct != "application/reports+json" {
		http.Error(w, "unsupported content type", http.StatusUnsupportedMediaType)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, cspReportMaxBytes))
	if err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			http.Error(w, "report too large", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "unreadable report", http.StatusBadRequest)
		return
	}
	vs, err := parseCSPReports(ct, body)
	if err != nil {
		http.Error(w, "malformed report", http.StatusBadRequest)
		return
	}
	for _, v := range vs {
		logCSPViolation(v)
	}
	w.WriteHeader(http.StatusNoContent)
}

func parseCSPReports(ct string, body []byte) ([]cspViolation, error) {
	if ct == "application/csp-report" {
		var doc struct {
			Report struct {
				DocumentURI        string `json:"document-uri"`
				ViolatedDirective  string `json:"violated-directive"`
				EffectiveDirective string `json:"effective-directive"`
				BlockedURI         string `json:"blocked-uri"`
				SourceFile         string `json:"source-file"`
				LineNumber         int    `json:"line-number"`
			} `json:"csp-report"`
		}
		if err := json.Unmarshal(body, &doc); err != nil {
			return nil, err
		}
		d := doc.Report.EffectiveDirective
		if d == "" {
			d = doc.Report.ViolatedDirective
		}
		return []cspViolation{{doc.Report.DocumentURI, d, doc.Report.BlockedURI, doc.Report.SourceFile, doc.Report.LineNumber}}, nil
	}
	var list []struct {
		Type string `json:"type"`
		Body struct {
			DocumentURL        string `json:"documentURL"`
			EffectiveDirective string `json:"effectiveDirective"`
			BlockedURL         string `json:"blockedURL"`
			SourceFile         string `json:"sourceFile"`
			LineNumber         int    `json:"lineNumber"`
		} `json:"body"`
	}
	if err := json.Unmarshal(body, &list); err != nil {
		return nil, err
	}
	var out []cspViolation
	for _, e := range list {
		if e.Type != "csp-violation" || len(out) == cspMaxEntries {
			continue
		}
		out = append(out, cspViolation{e.Body.DocumentURL, e.Body.EffectiveDirective, e.Body.BlockedURL, e.Body.SourceFile, e.Body.LineNumber})
	}
	return out, nil
}

func logCSPViolation(v cspViolation) {
	if !cspReportLimiter.Allow() {
		cspReportsDropped.Add(1)
		return
	}
	log.Printf("[csp] violation directive=%q blocked=%q document=%q source=%q line=%d dropped_since_last=%d",
		cleanCSPField(v.Directive), cleanCSPField(v.BlockedURI), cleanCSPField(v.DocumentURI),
		cleanCSPField(v.SourceFile), v.Line, cspReportsDropped.Swap(0))
}

// cleanCSPField removes control characters and caps the length, so a report
// can neither forge log lines nor bloat the log.
func cleanCSPField(s string) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, s)
	if r := []rune(s); len(r) > cspFieldMax {
		s = string(r[:cspFieldMax]) + "…"
	}
	return s
}
```
Run the tests → PASS (7).

- [ ] **Step 3: Route and RBAC** — in `routes.go`, in the public block after `r.Get("/api/config/ca-root", h.GetCARoot)`, add:

```go
	r.Post("/api/csp-report", h.CSPReport) // CSP violation reports; browsers send them without credentials (G1d)
```
and in `rbac_matrix_test.go` `publicRoutes`, after the `ca-root` entry:

```go
	"POST /api/csp-report":                        true, // CSP violation reports (G1d); browsers send them unauthenticated
```

- [ ] **Step 4: Verify**

```bash
cd orchestrator && go test ./internal/api -run 'CSPReport|RBAC|Rbac|Matrix' -count=1 && go vet ./internal/api
for f in internal/api/csp_report.go internal/api/csp_report_test.go internal/api/routes.go internal/api/rbac_matrix_test.go; do tr -d '\r' < $f | gofmt -l; done
```
Expected: `ok`; vet silent; gofmt silent. (The full `internal/api` package also runs in CI under `-race`.)

- [ ] **Step 5: Commit and push**

```bash
git add orchestrator/internal/api/csp_report.go orchestrator/internal/api/csp_report_test.go orchestrator/internal/api/routes.go orchestrator/internal/api/rbac_matrix_test.go
git commit -m "feat(security): POST /api/csp-report -- capped, sanitized, rate-limited violation log

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
git push
```

---

### Task 12: Switch on enforcement and close G1d (modularization exit)

**Files:**
- Modify: `.github/workflows/test.yml` (smoke env), `packaging/compose/docker-compose.yml`, `packaging/compose/.env.example`

- [ ] **Step 1: Enforced smoke locally**

```bash
cd orchestrator/web && tools/node.sh sh -c 'npm run build' >/dev/null && SMOKE_CSP=enforce SMOKE_STRICT=1 tools/smoke.sh dist
```
Expected: `1 passed` — all 25 tabs, zero CSP violations, zero inline leftovers, both action clicks dispatched. Any `csp:` error is fixed at its source before continuing.

- [ ] **Step 2: CI** — the `Smoke harness (bundled build)` step's `env:` becomes:

```yaml
        env:
          SMOKE_ROOT: dist
          SMOKE_CSP: enforce
          SMOKE_STRICT: '1'
```

- [ ] **Step 3: Compose and env template** — in `docker-compose.yml`, in the orchestrator `environment:` block after `BAS_LEGACY_LISTENER_ENABLED`:

```yaml
      # ── Dashboard Content-Security-Policy (G1d) ─────────────────────────────
      # enforce (default) blocks inline script; report-only only logs
      # violations (POST /api/csp-report -> orchestrator log) -- a temporary
      # escape hatch if a client hits a violation. No "off" value exists.
      BAS_CSP_MODE: ${BAS_CSP_MODE:-enforce}
```
In `.env.example`, after the `BAS_TLS=` block:

```
# Dashboard Content-Security-Policy: enforce (default) or report-only.
# report-only logs violations instead of blocking them; use only while a
# reported dashboard problem is being fixed, then set back to enforce.
BAS_CSP_MODE=enforce
```
Validate: `python3 -c "import yaml;yaml.safe_load(open('packaging/compose/docker-compose.yml'))"`.

- [ ] **Step 4: Exit evidence (spec §8, modularization exit)** — capture each output into the ledger:

```bash
cd /c/Users/Administrator/Downloads/Audspect_Cloud
echo "1: $(grep -rcE '(^|[^\w-])on[a-z]{3,}=' orchestrator/web/index.html orchestrator/web/src | awk -F: '{s+=$2} END {print s}') inline handlers"
echo "2: $(grep -rci 'javascript:' orchestrator/web/index.html orchestrator/web/src | awk -F: '{s+=$2} END {print s}') javascript: URLs"
echo "3: $(grep -cE 'HANDLER_FUNCTIONS|DYNAMIC_HANDLERS|STATE_GLOBALS|installGlobals' orchestrator/web/src/globals.js) legacy registry symbols"; sed -n '/WINDOW_WRITES = \[/,/\];/p' orchestrator/web/src/globals.js
(cd orchestrator && go test ./cmd/server -run 'DashboardCSP|CSPHeaders' -count=1 -v | grep -E '^(--- |ok)')
python3 scripts/g1d-check-actions.py && PYTHONIOENCODING=utf-8 bash scripts/g1-run-local.sh 2>&1 | grep -E "guard:"
grep -rnE "https?://" orchestrator/web/index.html orchestrator/web/styles/app.css | grep -vE 'href="https?://(github|attack\.mitre)' || echo "7: no external loads"
```
Expected: `0`, `0`, `0`; WINDOW_WRITES documented; Go tests PASS; checks OK; guard PASS; criterion 5 is Step 1; criterion 7 prints only plain links (not loads) or the `no external loads` line.

- [ ] **Step 5: Commit, push, confirm CI green**

```bash
git add .github/workflows/test.yml packaging/compose/docker-compose.yml packaging/compose/.env.example
git commit -m "ci,deploy: enforce the dashboard CSP in smoke; BAS_CSP_MODE in compose (G1d exit)

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
git push
```
Expected: both CI jobs green. G1d modularization exit is met on this commit.

---

### Task 13: Release / QA acceptance (staging; user-run commands)

Not a code task; recorded in the ledger. Staging is `192.168.10.78:9443`; the user runs SSH commands in their own terminal (password auth) and pastes output.

- [ ] **Step 1:** Build and deploy the image to staging via `packaging/windows-build.ps1` + `install.sh` (never raw `docker compose`).
- [ ] **Step 2:** `docker logs <orchestrator> 2>&1 | grep "dashboard CSP"` → `[+] dashboard CSP: enforce`. `curl -skI https://192.168.10.78:9443/ | grep -i content-security-policy` → the exact policy.
- [ ] **Step 3:** In a browser with DevTools open, load every tab; Console shows no CSP errors; exercise one action per tab.
- [ ] **Step 4:** Set `BAS_CSP_MODE=report-only` in `.env`, restart via the installer's restart path, confirm the `[~] dashboard CSP: report-only` line and the `Content-Security-Policy-Report-Only` header; trigger a report (`curl -sk -X POST -H 'Content-Type: application/csp-report' --data '{"csp-report":{"effective-directive":"script-src","blocked-uri":"inline"}}' https://192.168.10.78:9443/api/csp-report -o /dev/null -w '%{http_code}'` → `204`) and see the `[csp] violation` log line; set back to `enforce`, restart, confirm.
- [ ] **Step 5:** Upgrade note for clients: `BAS_CSP_MODE` (default `enforce`, `report-only` escape hatch, no `off`), recorded wherever this release's notes live.

---

## Self-review (done while writing)

- **Spec coverage:** §4.1–4.2 → T1; §4.3 → T6/T7 rules; §4.4 → T9 Step 3; §4.5 → T10 (+ T12 compose); §4.6 → T11; §4.7 → T8; §5 phases → T1–T2 (0), T5–T6 (1), T7 (2), T8–T12 (3); §6.1 → T3/T9; §6.2 → T9 Step 6; §6.3 → T4 (+T9/T12 required); §6.4 → every gate; §6.5 → T10/T11; §7 → T1, T7 step 2, T4, T10/T11; §8 → T12 Step 4 + T13; §9 untouched; §10 → Global Constraints.
- **Deviations from spec wording, each justified inline:** registry location (`globals.js`); new `g1d-check-actions.py` instead of rewriting `g1c-check-globals.py`; dedicated limiter instead of "existing per-IP limiter"; payload tests per converted module (T7 step 2) rather than per template function — the generic `on()` hostile-argument test (T1) plus the ESLint/registry ban cover every template, and a per-function test for ~120 functions is not proportionate; flagged for the user at handoff.
- **Type consistency:** `on(eventType, name, ...args)`, `dispatch(registry, type, event)`, `installActions(registry, root)`, `stopEvent(el, event)`, `ACTIONS`, `EVENT_TYPES`, `dashboardCSP`, `cspHeaders(mode, h)`, `StaticHandler(cspMode)`, `Config.CSPMode`, `cspReportLimiter`, `cspReportsDropped`, `cleanCSPField` — used identically across tasks.
