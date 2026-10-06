# G1c — Frontend Modularization & Build Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Split the 22,324-line `orchestrator/wwwroot/index.html` into ES modules built by esbuild in a Docker stage, with a controlled `window` boundary, full integrity coverage, lint, tests and a smoke harness — with zero change to dashboard behavior.

**Architecture:** A frozen snapshot of today's monolith is split **mechanically** by a generator (`web/tools/split.mjs`) that uses ESLint's scope analysis, so every function moves byte-for-byte; only `export`/`import` lines are added and cross-module variables become `state.<name>`. A mapping file (`web/tools/modules.json`) decides which section goes to which module; extraction is done one mapping change per commit, each verified by lint, a registry check, the G1 guard, unit tests and a Playwright smoke harness whose baseline was recorded against the untouched monolith. At the end the generator is retired and `web/src/` becomes hand-maintained source.

**Tech Stack:** Node 24 (Docker/CI only), esbuild 0.28.2, ESLint 10.12.0, jsdom 30.1.2, @playwright/test 1.63.0, Python 3 stdlib (CI checks), Go 1.26 (integrity).

**Spec:** `docs/superpowers/specs/2026-10-05-g1c-frontend-modularization-design.md` (approved 2026-10-05, `444341c6`)

## Global Constraints

- Work directly on `main`; `git push` immediately after every commit. Stage files by name only — never `git add -A`/`.`. Never stage `.claude/settings.local.json`, `go.work.sum`, `Assessment/COMPETITIVE_ANALYSIS.html`, `orchestrator/staging-loadtest-linux`.
- Every commit message ends with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.
- **Never** run `git checkout -- <dir>/` or any directory-wide restore; restore only named files. Run `git status` first.
- The three proven G1 scripts are **not modified**: `scripts/g1-innerhtml-sink-classifier.py`, `scripts/g1-trace-indirect-sinks.py`, `scripts/g1-merge-classification.py`.
- G1b stays independent of the production build: the classifier view is a CI analysis artifact; the production build never reads it, and G1b never reads `web/dist/`.
- Node never runs on the Windows host and never ships in the image. Node runs only in `node:24-alpine@sha256:ebfe2f90462722a7a4de65e91990e97fe0d401c70e0e762c5b53302f905ec1c1` (Docker build, local scripts) and `mcr.microsoft.com/playwright:v1.63.0-noble@sha256:eff16c30e6f3f4af0a03fa4b706120d5e9b0891c344a27d64559aff5900a4a27` (CI `web` job).
- npm: exact versions, `npm ci --ignore-scripts`, lockfile only, exactly four direct devDependencies: `esbuild@0.28.2`, `eslint@10.12.0`, `jsdom@30.1.2`, `@playwright/test@1.63.0`. No `dependencies`. Browser globals for ESLint come from a committed allowlist file, not the `globals` package.
- Playwright browsers come only from the pinned Playwright image; no `npx playwright install`, no lifecycle-script downloads.
- **Frontend freeze:** from Task 1 until Task 11, no unrelated edits to the dashboard. During the freeze `web/src/`, `web/index.html` and `web/styles/app.css` are **generated** — never hand-edit them; change `web/tools/modules.json` (or, for a genuine bug fix, `web/tools/monolith.html`) and regenerate.
- Verbatim moves: no refactoring, renaming or "improvements" of moved code. The only permitted text changes are those the generator makes (§ Task 3).
- esbuild output is unminified, format `iife`, target `es2020`.
- Local Docker invocations from Git Bash use `MSYS_NO_PATHCONV=1` and `$(cygpath -m "$PWD")` for bind mounts.
- Exit criteria are split: **modularization exit** (closes G1c, Task 11) vs **release/QA acceptance** (gates shipping, Task 12).

## Review Focus

1. **Handler writes to app variables** (`onchange="scenarioView='grid'"`, `onchange="INIT_ATTACH_SELECTED=this.value"`, and the runtime-built `onchange="_groupSel[id]=this.checked"`): the module code must see the new value. Pinned by Task 3's `handler-assigned variable is exposed through a state accessor` test and Task 4's assignment-target check.
2. **`window[name]` dynamic lookups** (`renderGroupCheckboxList` reads `window[stateVarName]` and calls `window[summaryFnName]()`): must resolve after the split. Pinned by `modules.json` `windowVars`/`windowFns` + Task 3 test `windowVars entries become state globals` + the registry check (Task 4) keeping those functions on `window`; exercised end to end by Task 12's manual Group(s)-mode check (the stubbed smoke harness loads the group tree but does not drive the modal).
3. **Load-order changes** (a load-time statement reading a `var` declared later in the file, or a `var` initializer using another module's variable): must behave as before or fail generation loudly. Pinned by Task 3 tests `init that reads a later-declared var is reported` and `cross-module initializer is a hard error`.
4. **Strict-mode differences** (implicit globals, `this` in plain functions, legacy octal): modules are always strict. Pinned by Task 3 test `implicit global write becomes state` and the `this`-usage report reviewed in Task 5.
5. **Tampered or extra file in `wwwroot/`** (edited `app.js`, dropped-in `evil.js`, deleted `MANIFEST.sha256`): startup must refuse to serve. Pinned by Task 7 tests `TestVerifyWWWRoot_*`.

---

## File Structure

| Path | Responsibility |
|---|---|
| `orchestrator/web/package.json`, `package-lock.json` | Pinned toolchain, npm scripts |
| `orchestrator/web/tools/monolith.html` | Frozen byte copy of today's `wwwroot/index.html` (generator input; deleted in Task 11) |
| `orchestrator/web/tools/modules.json` | Section → module mapping, pins, dynamic-window lists (deleted in Task 11) |
| `orchestrator/web/tools/split.mjs` | Generator: monolith → `web/index.html`, `styles/app.css`, `src/**` (deleted in Task 11) |
| `orchestrator/web/tools/analyze.mjs` | ESLint-scope analysis used by `split.mjs` (deleted in Task 11) |
| `orchestrator/web/tools/build.mjs` | esbuild bundle → `web/dist/` with hashed names + `MANIFEST.sha256` |
| `orchestrator/web/tools/check-playwright-version.mjs` | Fails if installed `@playwright/test` ≠ image version |
| `orchestrator/web/tools/dev-build.sh` | Local build in Node container → copies `dist/` to `orchestrator/wwwroot/` |
| `orchestrator/web/index.html`, `styles/app.css`, `src/**` | Generated (during freeze) source |
| `orchestrator/web/images/` | Logos (moved from `wwwroot/images/`) |
| `orchestrator/web/eslint.config.mjs`, `eslint-browser-globals.json` | Lint config + reviewed browser-global allowlist |
| `orchestrator/web/tests/unit/*.test.mjs` | `node:test` + jsdom unit/XSS tests |
| `orchestrator/web/tests/smoke/*` | Playwright harness, static server, fixtures, baseline |
| `scripts/g1c-check-globals.py`, `scripts/test_g1c_check_globals.py` | Registry check (missing/stale/assignment/window-writes) |
| `scripts/g1-assemble-classifier-view.py`, `scripts/test_g1_assemble_classifier_view.py` | Deterministic classifier view |
| `scripts/g1-run-local.sh` | Local G1 run that preserves a built `wwwroot/index.html` |
| `scripts/g1-check-no-regression.py` (+ its test) | Adds non-failing REVIEW category |
| `orchestrator/cmd/server/static.go`, `static_test.go` | Manifest integrity, cache headers, watch list |
| `orchestrator/cmd/server/main.go` | Watch every manifest file |
| `orchestrator/Dockerfile`, `packaging/windows-build.ps1` | Node stage, manifest hash via ldflags |
| `.github/workflows/test.yml` | `web` job; G1 step assembles the view; registry check |

---

### Task 1: Freeze the monolith and scaffold the pinned toolchain

**Files:**
- Create: `orchestrator/web/package.json`, `orchestrator/web/package-lock.json`, `orchestrator/web/.gitignore`, `orchestrator/web/tools/monolith.html`, `orchestrator/web/tools/check-playwright-version.mjs`, `orchestrator/web/tools/node.sh`
- Modify: `.github/workflows/test.yml`

**Interfaces:**
- Produces: `web/tools/node.sh <cmd…>` — runs a command in the pinned Node image with `orchestrator/web` mounted at `/web` (used by every later task); npm scripts `test`, `lint`, `build`, `split`, `split:check`, `smoke` (bodies filled in by later tasks; here they exist as listed below).

- [ ] **Step 1: Freeze the snapshot**

```bash
cd /c/Users/Administrator/Downloads/Audspect_Cloud
git status --porcelain
mkdir -p orchestrator/web/tools
cp orchestrator/wwwroot/index.html orchestrator/web/tools/monolith.html
cmp orchestrator/wwwroot/index.html orchestrator/web/tools/monolith.html && echo IDENTICAL
```
Expected: `IDENTICAL`.

- [ ] **Step 2: Write `orchestrator/web/package.json`**

```json
{
  "name": "audspect-web",
  "private": true,
  "type": "module",
  "engines": { "node": ">=24" },
  "scripts": {
    "split": "node tools/split.mjs",
    "split:check": "node tools/split.mjs --check",
    "lint": "eslint src",
    "test": "node --test tests/unit/",
    "build": "node tools/build.mjs",
    "smoke": "playwright test -c tests/smoke/playwright.config.mjs"
  },
  "devDependencies": {
    "@playwright/test": "1.63.0",
    "esbuild": "0.28.2",
    "eslint": "10.12.0",
    "jsdom": "30.1.2"
  }
}
```

- [ ] **Step 3: Write `orchestrator/web/.gitignore`**

```
node_modules/
dist/
test-results/
playwright-report/
```

- [ ] **Step 4: Write `orchestrator/web/tools/node.sh`**

```bash
#!/usr/bin/env bash
# Runs a command inside the pinned Node image with orchestrator/web at /web.
# Node is never installed on the host (G1c Global Constraints).
set -euo pipefail
WEB_DIR="$(cd "$(dirname "$0")/.." && pwd)"
IMAGE="node:24-alpine@sha256:ebfe2f90462722a7a4de65e91990e97fe0d401c70e0e762c5b53302f905ec1c1"
HOST_DIR="$WEB_DIR"
if command -v cygpath >/dev/null 2>&1; then HOST_DIR="$(cygpath -m "$WEB_DIR")"; fi
MSYS_NO_PATHCONV=1 exec docker run --rm -v "$HOST_DIR:/web" -w /web "$IMAGE" "$@"
```

- [ ] **Step 5: Generate the lockfile inside the pinned image**

```bash
cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator/web
chmod +x tools/node.sh
tools/node.sh npm install --ignore-scripts --package-lock-only --no-audit --no-fund
tools/node.sh sh -c 'npm ci --ignore-scripts --no-audit --no-fund && npx esbuild --version && npx eslint --version'
```
Expected: `package-lock.json` created; output ends with `0.28.2` and `v10.12.0`.

- [ ] **Step 6: Write the failing version check `orchestrator/web/tools/check-playwright-version.mjs`**

```js
// Fails unless the installed @playwright/test matches the browser build
// bundled in the pinned Playwright image (PLAYWRIGHT_IMAGE_VERSION).
import { readFileSync } from 'node:fs';
const want = process.env.PLAYWRIGHT_IMAGE_VERSION;
if (!want) { console.error('PLAYWRIGHT_IMAGE_VERSION is not set'); process.exit(1); }
const got = JSON.parse(readFileSync(new URL('../node_modules/@playwright/test/package.json', import.meta.url))).version;
if (got !== want) {
  console.error(`@playwright/test ${got} does not match Playwright image ${want}`);
  process.exit(1);
}
console.log(`@playwright/test ${got} matches Playwright image ${want}`);
```

Run: `tools/node.sh sh -c 'PLAYWRIGHT_IMAGE_VERSION=1.62.0 node tools/check-playwright-version.mjs'`
Expected: exit 1, `@playwright/test 1.63.0 does not match Playwright image 1.62.0`.
Run: `tools/node.sh sh -c 'PLAYWRIGHT_IMAGE_VERSION=1.63.0 node tools/check-playwright-version.mjs'`
Expected: `@playwright/test 1.63.0 matches Playwright image 1.63.0`.

- [ ] **Step 7: Add the CI `web` job** (append to `.github/workflows/test.yml` under `jobs:`)

```yaml
  web:
    runs-on: ubuntu-latest
    container:
      image: mcr.microsoft.com/playwright:v1.63.0-noble@sha256:eff16c30e6f3f4af0a03fa4b706120d5e9b0891c344a27d64559aff5900a4a27
    env:
      PLAYWRIGHT_IMAGE_VERSION: "1.63.0"
    defaults:
      run:
        working-directory: orchestrator/web
    steps:
      - uses: actions/checkout@v4
      - name: npm ci (lockfile only, no lifecycle scripts)
        run: npm ci --ignore-scripts --no-audit --no-fund
      - name: Playwright package matches image browsers
        run: node tools/check-playwright-version.mjs
```

- [ ] **Step 8: Commit and push**

```bash
cd /c/Users/Administrator/Downloads/Audspect_Cloud
git add orchestrator/web/package.json orchestrator/web/package-lock.json orchestrator/web/.gitignore orchestrator/web/tools/monolith.html orchestrator/web/tools/check-playwright-version.mjs orchestrator/web/tools/node.sh .github/workflows/test.yml
git commit -m "build(web): freeze dashboard snapshot and pin G1c frontend toolchain

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
git push
```
Then confirm the `web` job is green on GitHub Actions (`gh run watch`).

---

### Task 2: Smoke harness and baseline against the untouched monolith

**Files:**
- Create: `orchestrator/web/tests/smoke/playwright.config.mjs`, `serve.mjs`, `fixtures.mjs`, `smoke.spec.mjs`, `baseline.json`
- Modify: `.github/workflows/test.yml` (web job)

**Interfaces:**
- Consumes: Task 1 npm script `smoke`, `tools/node.sh`.
- Produces: env `SMOKE_ROOT` (directory to serve; default `../wwwroot` = monolith), env `SMOKE_RECORD=1` (rewrite `baseline.json`), `baseline.json` schema `{ "tabs": { "<tab>": ["<normalized error>", …] }, "drawers": { "<name>": [...] } }`.

- [ ] **Step 1: Write the static server `tests/smoke/serve.mjs`**

```js
// Minimal static server for the smoke harness. API calls never reach it:
// the Playwright test intercepts /api/* and /ready before they leave the page.
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { extname, join, normalize, resolve } from 'node:path';

const root = resolve(process.argv[2]);
const port = Number(process.argv[3] || 4173);
const types = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript', '.css': 'text/css', '.png': 'image/png' };

createServer(async (req, res) => {
  const urlPath = decodeURIComponent(new URL(req.url, 'http://x').pathname);
  const rel = normalize(urlPath === '/' ? '/index.html' : urlPath).replace(/^([/\\])+/, '');
  const file = join(root, rel);
  if (!file.startsWith(root)) { res.writeHead(403).end(); return; }
  try {
    const body = await readFile(file);
    res.writeHead(200, { 'Content-Type': types[extname(file)] || 'application/octet-stream' }).end(body);
  } catch {
    res.writeHead(404).end();
  }
}).listen(port, () => console.log(`smoke server: ${root} on ${port}`));
```

- [ ] **Step 2: Write `tests/smoke/playwright.config.mjs`**

```js
import { defineConfig } from '@playwright/test';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, '../..', process.env.SMOKE_ROOT || '../wwwroot');

export default defineConfig({
  testDir: here,
  timeout: 600_000,
  workers: 1,
  reporter: [['list']],
  use: { baseURL: 'http://127.0.0.1:4173', headless: true },
  webServer: { command: `node ${resolve(here, 'serve.mjs')} "${root}" 4173`, url: 'http://127.0.0.1:4173/index.html', reuseExistingServer: false },
});
```

- [ ] **Step 3: Write `tests/smoke/fixtures.mjs`**

The default for every unmatched `/api/*` is `{}` with HTTP 200. `FIXTURES` maps `METHOD path` (path without query) to a JSON body. Start with exactly these entries; Step 6 adds the rest.

```js
// Fixture responses for the smoke harness. Keys are "METHOD /path" with the
// query string removed. PAYLOAD strings must never execute: smoke.spec.mjs
// fails if window.__xss is ever set.
export const PAYLOAD = '"><img src=x onerror="window.__xss=1"><svg onload="window.__xss=1">';

export const FIXTURES = {
  'GET /ready': { version: '0.0.0-smoke' },
  'GET /api/license/status': { state: 'valid' },
  'GET /api/agents': [],
  'GET /api/auth/me': { username: 'smoke', role: 'admin' },
};

export function fixtureFor(method, pathname) {
  const key = `${method} ${pathname}`;
  return Object.prototype.hasOwnProperty.call(FIXTURES, key) ? FIXTURES[key] : {};
}
```

- [ ] **Step 4: Write `tests/smoke/smoke.spec.mjs`**

```js
import { test, expect } from '@playwright/test';
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { fixtureFor } from './fixtures.mjs';

const BASELINE = fileURLToPath(new URL('./baseline.json', import.meta.url));
const RECORD = process.env.SMOKE_RECORD === '1';

// Errors are compared after removing volatile parts (asset hashes, line/col,
// URLs), so the monolith baseline is comparable with the bundled build.
function normalize(msg) {
  return msg
    .replace(/https?:\/\/[^\s)]+/g, '<url>')
    .replace(/:\d+:\d+/g, '')
    .replace(/app\.[0-9A-Za-z]+\.js/g, 'app.js')
    .trim();
}

async function boot(page) {
  const errors = [];
  page.on('pageerror', (e) => errors.push(normalize(`pageerror: ${e.message}`)));
  page.on('console', (m) => { if (m.type() === 'error') errors.push(normalize(`console: ${m.text()}`)); });
  await page.addInitScript(() => { localStorage.setItem('bas_role', 'admin'); window.__xss = undefined; });
  await page.route('**/*', (route) => {
    const u = new URL(route.request().url());
    if (u.pathname === '/ready' || u.pathname.startsWith('/api/')) {
      return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(fixtureFor(route.request().method(), u.pathname)) });
    }
    if (u.hostname !== '127.0.0.1') return route.fulfill({ status: 204, body: '' }); // fonts etc.: never leave the sandbox
    return route.continue();
  });
  await page.goto('/index.html');
  await page.waitForFunction(() => getComputedStyle(document.getElementById('app')).display !== 'none', null, { timeout: 15_000 });
  return errors;
}

// Tabs are discovered from the markup, not from app internals, so the same
// harness runs unchanged against the monolith and the bundled build.
async function tabNames(page) {
  return page.$$eval('[onclick^="showTab(\'"]', (els) => [...new Set(els.map((e) => e.getAttribute('onclick').match(/showTab\('([^']+)'\)/)[1]))].sort());
}

// Every inline handler in the live DOM whose called function is not on window.
async function unresolvedHandlers(page) {
  return page.evaluate(() => {
    const bad = new Set();
    const skip = new Set(['if', 'function', 'return', 'typeof', 'event', 'this']);
    for (const el of document.querySelectorAll('*')) {
      for (const a of el.attributes) {
        if (!a.name.startsWith('on')) continue;
        for (const m of a.value.matchAll(/(?<![.\w$])([A-Za-z_$][\w$]*)\s*\(/g)) {
          if (!skip.has(m[1]) && typeof window[m[1]] !== 'function') bad.add(m[1]);
        }
      }
    }
    return [...bad].sort();
  });
}

test('every tab renders with no errors beyond the monolith baseline', async ({ page }) => {
  const errors = await boot(page);
  const result = { tabs: {} };
  for (const tab of await tabNames(page)) {
    errors.length = 0;
    // element.click() rather than page.click(): some nav entries (e.g. Profile)
    // live in a collapsed dropdown and are not "visible" to Playwright.
    await page.$eval(`[onclick="showTab('${tab}')"]`, (el) => el.click());
    await page.waitForTimeout(400);
    const unresolved = await unresolvedHandlers(page);
    result.tabs[tab] = [...new Set([...errors, ...unresolved.map((n) => `unresolved handler: ${n}`)])].sort();
  }
  const xss = await page.evaluate(() => window.__xss);
  expect(xss, 'a fixture payload executed').toBeUndefined();

  if (RECORD) { writeFileSync(BASELINE, JSON.stringify(result, null, 2) + '\n'); return; }
  const baseline = JSON.parse(readFileSync(BASELINE, 'utf8'));
  const regressions = [];
  for (const [tab, errs] of Object.entries(result.tabs)) {
    const known = new Set(baseline.tabs[tab] || []);
    for (const e of errs) if (!known.has(e)) regressions.push(`${tab}: ${e}`);
  }
  for (const tab of Object.keys(baseline.tabs)) if (!(tab in result.tabs)) regressions.push(`${tab}: tab disappeared`);
  expect(regressions, 'new errors versus the monolith baseline').toEqual([]);
});
```

- [ ] **Step 5: Run against the monolith in recording mode**

```bash
cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator
MSYS_NO_PATHCONV=1 docker run --rm -v "$(cygpath -m "$PWD"):/o" -w /o/web -e SMOKE_RECORD=1 -e PLAYWRIGHT_IMAGE_VERSION=1.63.0 \
  mcr.microsoft.com/playwright:v1.63.0-noble@sha256:eff16c30e6f3f4af0a03fa4b706120d5e9b0891c344a27d64559aff5900a4a27 \
  sh -c 'npm ci --ignore-scripts --no-audit --no-fund && npm run smoke'
```
Expected: 1 passed; `tests/smoke/baseline.json` written with 26 tab keys (`agents`, `attack-coverage`, `attackpath`, `campaigns`, `compliance`, `coverage`, `dashboard`, `em`, `exercises`, `exposure`, `findings`, `initiatives`, `integrations`, `iocs`, `profile`, `recommendations`, `remediation`, `reports`, `runs`, `scenarios`, `scheduled-assessments`, `settings`, `sla-report`, `threat-priority`, `variants`, `verification`).

- [ ] **Step 6: Populate fixtures for the six busiest views until they are error-free**

For each of `dashboard`, `runs`, `agents`, `findings`, `campaigns`, `coverage`:
1. Read the tab's `baseline.json` errors.
2. Find the endpoint(s) the tab loads: `grep -n "apicall('/api/" orchestrator/web/tools/monolith.html` near that tab's load function (the function `showTab` calls for it).
3. Add a `FIXTURES` entry with the smallest response the render code accepts. Include `PAYLOAD` in at least one string field that the tab renders (a name, title or hostname).
4. Re-run Step 5 (recording) and repeat until that tab's list is `[]`.

Also add the Run modal's group-target data path (Review Focus 2): fixture `GET /api/agent-groups/tree` (or the exact path `loadAgentGroupTree` calls — read it from the monolith) returning one group `{ "id": 1, "name": "smoke", "totalAgentCount": 0, "children": [] }`.

Expected end state: those six tabs have `[]` in `baseline.json`; other tabs may keep recorded errors (pre-existing, out of scope — listed in the commit message); `window.__xss` stays undefined.

- [ ] **Step 7: Verify comparison mode passes and actually catches a regression**

Run Step 5's command **without** `-e SMOKE_RECORD=1`. Expected: 1 passed.
Then temporarily break the monolith served copy (not the snapshot): `sed -i 's/^function showToast(/function showToastX(/' orchestrator/wwwroot/index.html`, re-run. Expected: FAIL listing `unresolved handler`/`showToast is not defined` regressions. Restore exactly that file: `git checkout -- orchestrator/wwwroot/index.html` (single named file).

- [ ] **Step 8: Add the smoke step to the CI `web` job** (after the version check)

```yaml
      - name: Smoke harness (monolith baseline)
        env:
          SMOKE_ROOT: ../wwwroot
        run: npm run smoke
      - name: Upload smoke artifacts on failure
        if: failure()
        uses: actions/upload-artifact@v4
        with:
          name: smoke-artifacts
          path: |
            orchestrator/web/test-results
            orchestrator/web/playwright-report
```

- [ ] **Step 9: Commit and push**

```bash
git add orchestrator/web/tests/smoke/playwright.config.mjs orchestrator/web/tests/smoke/serve.mjs orchestrator/web/tests/smoke/fixtures.mjs orchestrator/web/tests/smoke/smoke.spec.mjs orchestrator/web/tests/smoke/baseline.json .github/workflows/test.yml
git commit -m "test(web): Playwright smoke harness with baseline recorded against the monolith

<list each tab with pre-existing baseline errors here, one line each>

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
git push
```
Confirm the `web` job is green.

---

### Task 3: The generator (analysis + split) with tests

**Files:**
- Create: `orchestrator/web/tools/analyze.mjs`, `orchestrator/web/tools/split.mjs`, `orchestrator/web/tools/modules.json`, `orchestrator/web/tests/unit/split.test.mjs`

**Interfaces:**
- Consumes: `web/tools/monolith.html`.
- Produces:
  - `analyzeScript(jsText) → { chunks: Chunk[], topNames: Map<name, {chunk, kind, declKind}>, refs: Ref[], through: Ref[], windowMembers: {name, start, end, write}[], thisCount: number }` where `Chunk = { start, end, stmtStart, stmtEnd, line, kind: 'function'|'class'|'var'|'other', names: string[], node }` and `Ref = { name, start, end, write, chunkIndex, inShorthand: boolean }`.
  - `splitMonolith(htmlText, modulesConfig) → { files: Map<relativePath, string>, report: object }` — pure (no I/O), used by tests.
  - CLI: `node tools/split.mjs` writes `index.html`, `styles/app.css`, `src/**`, `tools/split-report.json`; `--check` regenerates in memory and exits 1 if any committed file differs.
  - Generated `src/globals.js` exports `HANDLER_FUNCTIONS`, `DYNAMIC_HANDLERS`, `STATE_GLOBALS`, `WINDOW_WRITES`, `installGlobals()`; `src/core/state.js` exports `state`; `src/main.js` calls `installGlobals()` then every `__init_L<line>()` in original order.

**Generator rules (the only permitted text changes):**
1. HTML: `web/index.html` = monolith lines 1–10 + `<link rel="stylesheet" href="/assets/%%APP_CSS%%">` + lines 1322–5160 + `<script src="/assets/%%APP_JS%%"></script>` + lines 22323–end. Lines 11 and 1321 must be exactly `<style>`/`</style>` and 5161/22322 exactly `<script>`/`</script>`, else abort.
2. CSS: lines 12–1320 verbatim → `styles/app.css`.
3. JS (lines 5162–22321) is partitioned losslessly into chunks: one per top-level statement, each chunk spanning from the end of the previous statement to the end of its own (so leading comments travel with the statement). Concatenating all chunks must reproduce the JS byte-for-byte (asserted at runtime).
4. Module of a chunk: the `// ── <Section>` header governing its statement's line → `modules.json.sections`; unmapped → `modules.json.default`; `modules.json.pin[name]` overrides for any declared name.
5. `export ` is inserted before a top-level function/class/variable statement when another module references one of its names (or `globals.js` needs it).
6. **State variables** = top-level `var`/`let`/`const` names that are (a) written from a module other than their own, (b) bare identifiers written or read in inline handler strings, (c) accessed as `window.NAME`, or (d) listed in `modules.json.windowVars`; plus implicit globals (undeclared names written by app code). For each: the declarator is removed from its statement (whole statement removed if no declarators remain), its initializer text goes into `core/state.js`, and every reference becomes `state.NAME` (shorthand `{ NAME }` becomes `{ NAME: state.NAME }`). An initializer that references app names is a hard error unless the name is in `modules.json.lateInit`, in which case `state.NAME = <init>;` is emitted inside that chunk's module as an `__init_L<line>` function.
7. Load-time chunks (`kind: 'other'`) become `export function __init_L<line>() {<chunk text>}` in their module; `main.js` calls them in original line order after `installGlobals()`.
8. Imports: each module imports the names it uses from their owning modules, sorted; plus `state` when used.
9. `globals.js`: `HANDLER_FUNCTIONS` = functions called from inline handlers (scanned from the monolith HTML and JS string literals) ∪ `modules.json.windowFns`; `STATE_GLOBALS` = state variables from rule 6 (b)(c)(d); `WINDOW_WRITES` = names assigned as `window.NAME = …` that are not top-level declarations (left verbatim; registered here).
10. Hard errors (exit 1 with a list): lossless check fails; duplicate top-level names; a state initializer depending on app names not in `lateInit`; a module-level `var` initializer reading a variable from another module. Report-only (in `split-report.json`): load-time chunks that read a `var` declared later in the file (`laterVarReads`), undeclared reads (`undeclaredReads` — candidates for the browser allowlist), `thisCount`.

- [ ] **Step 1: Write the failing tests `tests/unit/split.test.mjs`**

```js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { analyzeScript } from '../../tools/analyze.mjs';
import { splitMonolith } from '../../tools/split.mjs';

// Builds a minimal monolith with the real file's fixed line layout:
// lines 1-10 head, 11 <style>, 12-1320 css, 1321 </style>, 1322-5160 markup,
// 5161 <script>, 5162.. js, then </script></body></html>.
function monolith(js, markup = '<div id="app"></div>') {
  const pad = (n, s = '') => Array.from({ length: n }, () => s);
  const head = ['<!DOCTYPE html>', '<html>', '<head>', ...pad(7, '<!-- h -->')];
  const css = pad(1309, '/* c */');
  const body = [markup, ...pad(3838, '<!-- m -->')];
  return [...head, '<style>', ...css, '</style>', ...body, '<script>', ...js.split('\n'), '</script>', '</body>', '</html>'].join('\n');
}
const cfg = (over = {}) => ({ default: 'legacy.js', sections: [], pin: {}, windowVars: [], windowFns: [], lateInit: [], ...over });
const file = (out, p) => out.files.get(p);

test('chunks partition the script losslessly', () => {
  const js = '// lead\nvar a = 1;\nfunction f() { return a; }\n\n// tail comment\nf();\n';
  const { chunks } = analyzeScript(js);
  assert.equal(chunks.map((c) => js.slice(c.start, c.end)).join(''), js);
});

test('cross-module write turns a variable into state', () => {
  const js = '// ── One ──\nvar count = 0;\nfunction show() { return count; }\n// ── Two ──\nfunction bump() { count = count + 1; }\n';
  const out = splitMonolith(monolith(js), cfg({ sections: [{ header: 'One', module: 'features/one.js' }, { header: 'Two', module: 'features/two.js' }] }));
  assert.match(file(out, 'src/core/state.js'), /count: 0/);
  assert.match(file(out, 'src/features/one.js'), /return state\.count;/);
  assert.match(file(out, 'src/features/two.js'), /state\.count = state\.count \+ 1;/);
  assert.doesNotMatch(file(out, 'src/features/one.js'), /var count/);
});

test('handler-assigned variable is exposed through a state accessor', () => {
  const js = "var scenarioView = 'landing';\nfunction render() { return scenarioView; }\n";
  const out = splitMonolith(monolith(js, '<input oninput="scenarioView = \'search\'; render()">'), cfg());
  const g = file(out, 'src/globals.js');
  assert.match(g, /STATE_GLOBALS = \[\s*'scenarioView'/);
  assert.match(g, /HANDLER_FUNCTIONS = \{[^}]*\brender\b/);
  assert.match(file(out, 'src/legacy.js'), /return state\.scenarioView;/);
});

test('windowVars entries become state globals', () => {
  const js = 'var _groupSel = {};\nfunction read(n) { return window[n]; }\n';
  const out = splitMonolith(monolith(js), cfg({ windowVars: ['_groupSel'] }));
  assert.match(file(out, 'src/globals.js'), /'_groupSel'/);
  assert.match(file(out, 'src/core/state.js'), /_groupSel: \{\}/);
});

test('shorthand property reference is expanded', () => {
  const js = 'var mode = 1;\nfunction pack() { return { mode }; }\n';
  const out = splitMonolith(monolith(js, '<a onclick="mode=2">'), cfg());
  assert.match(file(out, 'src/legacy.js'), /\{ mode: state\.mode \}/);
});

test('load-time statements become ordered init functions', () => {
  const js = 'function a() {}\nwindow.addEventListener("load", a);\nfunction b() {}\nb();\n';
  const out = splitMonolith(monolith(js), cfg());
  const main = file(out, 'src/main.js');
  assert.ok(main.indexOf('__init_L5163()') < main.indexOf('__init_L5165()'));
  assert.ok(main.indexOf('installGlobals()') < main.indexOf('__init_L5163()'));
  assert.match(file(out, 'src/legacy.js'), /export function __init_L5163\(\) \{\nwindow\.addEventListener\("load", a\);\n?\}/);
});

test('cross-module function call gets an import', () => {
  const js = '// ── One ──\nfunction helper() { return 1; }\n// ── Two ──\nfunction user() { return helper(); }\n';
  const out = splitMonolith(monolith(js), cfg({ sections: [{ header: 'One', module: 'features/one.js' }, { header: 'Two', module: 'features/two.js' }] }));
  assert.match(file(out, 'src/features/two.js'), /^import \{ helper \} from '\.\/one\.js';/m);
  assert.match(file(out, 'src/features/one.js'), /^export function helper\(\)/m);
});

test('implicit global write becomes state', () => {
  const js = 'function setIt() { leaked = 5; }\nfunction getIt() { return leaked; }\n';
  const out = splitMonolith(monolith(js), cfg());
  assert.match(file(out, 'src/core/state.js'), /leaked: undefined/);
  assert.match(file(out, 'src/legacy.js'), /state\.leaked = 5;/);
});

test('cross-module initializer is a hard error', () => {
  const js = '// ── One ──\nvar base = 2;\nfunction noop() {}\n// ── Two ──\nvar derived = base * 2;\n';
  assert.throws(() => splitMonolith(monolith(js), cfg({ sections: [{ header: 'One', module: 'features/one.js' }, { header: 'Two', module: 'features/two.js' }] })), /initializer of "derived" reads "base" from another module/);
});

test('init that reads a later-declared var is reported', () => {
  const js = 'console.log(late);\nvar late = 1;\n';
  const out = splitMonolith(monolith(js), cfg());
  assert.deepEqual(out.report.laterVarReads, [{ line: 5162, name: 'late' }]);
});

test('mixed declaration keeps the non-state declarator and rewrites its state reads', () => {
  const js = "var mode = 1, label = 'x', copy = mode;\nfunction f() { return [label, copy]; }\n";
  const out = splitMonolith(monolith(js, '<a onclick="mode=2;f()">'), cfg());
  assert.match(file(out, 'src/legacy.js'), /var label = 'x', copy = state\.mode;/);
  assert.match(file(out, 'src/core/state.js'), /mode: 1/);
});

test('window.NAME writes of undeclared names are registered verbatim', () => {
  const js = '(function(){ window.openRunPanel = function(){}; })();\n';
  const out = splitMonolith(monolith(js), cfg());
  assert.match(file(out, 'src/globals.js'), /WINDOW_WRITES = \[\s*'openRunPanel'/);
  assert.match(file(out, 'src/legacy.js'), /window\.openRunPanel = function\(\)\{\};/);
});
```

- [ ] **Step 2: Run to verify failure**

Run: `cd orchestrator/web && tools/node.sh sh -c 'npm ci --ignore-scripts --no-audit --no-fund && node --test tests/unit/split.test.mjs'`
Expected: FAIL — `Cannot find module '/web/tools/analyze.mjs'`.

- [ ] **Step 3: Write `tools/analyze.mjs`**

```js
// Scope analysis of the monolith's classic script using ESLint's own parser
// and scope manager (no extra dependency). Pure: text in, data out.
import { Linter } from 'eslint';

export function analyzeScript(js) {
  const out = { chunks: [], topNames: new Map(), refs: [], through: [], windowMembers: [], thisCount: 0 };
  let program = null;
  let scopeManager = null;
  const collector = {
    create(context) {
      return {
        Program(node) { program = node; scopeManager = context.sourceCode.scopeManager; },
        ThisExpression() { out.thisCount++; },
        MemberExpression(node) {
          if (node.object.type !== 'Identifier' || node.object.name !== 'window') return;
          let name = null;
          if (!node.computed && node.property.type === 'Identifier') name = node.property.name;
          else if (node.computed && node.property.type === 'Literal' && typeof node.property.value === 'string') name = node.property.value;
          if (!name) return;
          const p = node.parent;
          const write = p && p.type === 'AssignmentExpression' && p.left === node;
          out.windowMembers.push({ name, start: node.range[0], end: node.range[1], write });
        },
      };
    },
  };
  const linter = new Linter({ configType: 'flat' });
  const messages = linter.verify(js, [{
    languageOptions: { ecmaVersion: 'latest', sourceType: 'script' },
    plugins: { g1c: { rules: { collect: collector } } },
    rules: { 'g1c/collect': 'error' },
  }], { filename: 'monolith.js' });
  const fatal = messages.find((m) => m.fatal);
  if (fatal) throw new Error(`parse error at ${fatal.line}:${fatal.column}: ${fatal.message}`);

  // Lossless partition: each chunk runs from the previous statement's end to
  // its own end; trailing text after the last statement joins the last chunk.
  let cursor = 0;
  program.body.forEach((node, i) => {
    const isLast = i === program.body.length - 1;
    const end = isLast ? js.length : node.range[1];
    let kind = 'other';
    if (node.type === 'FunctionDeclaration') kind = 'function';
    else if (node.type === 'ClassDeclaration') kind = 'class';
    else if (node.type === 'VariableDeclaration') kind = 'var';
    out.chunks.push({ start: cursor, end, stmtStart: node.range[0], stmtEnd: node.range[1], line: node.loc.start.line, kind, names: [], node });
    cursor = end;
  });
  if (out.chunks.map((c) => js.slice(c.start, c.end)).join('') !== js) throw new Error('lossless partition failed');

  const chunkAt = (pos) => {
    let lo = 0, hi = out.chunks.length - 1;
    while (lo < hi) { const mid = (lo + hi + 1) >> 1; if (out.chunks[mid].start <= pos) lo = mid; else hi = mid - 1; }
    return lo;
  };
  const isShorthand = (id) => id.parent && id.parent.type === 'Property' && id.parent.shorthand && id.parent.value === id;

  const global = scopeManager.globalScope;
  for (const v of global.variables) {
    if (!v.defs.length) continue;
    const def = v.defs[0];
    const chunkIndex = chunkAt(def.name.range[0]);
    const kind = out.chunks[chunkIndex].kind;
    if (out.topNames.has(v.name)) throw new Error(`duplicate top-level name "${v.name}"`);
    out.topNames.set(v.name, { chunk: chunkIndex, kind, declKind: def.parent && def.parent.kind, def });
    out.chunks[chunkIndex].names.push(v.name);
    for (const r of v.references) {
      const id = r.identifier;
      if (id === def.name && !r.init) continue;
      out.refs.push({ name: v.name, start: id.range[0], end: id.range[1], write: r.isWrite() && !r.init, init: !!r.init, chunkIndex: chunkAt(id.range[0]), inShorthand: isShorthand(id) });
    }
  }
  for (const r of global.through) {
    const id = r.identifier;
    out.through.push({ name: id.name, start: id.range[0], end: id.range[1], write: r.isWrite(), chunkIndex: chunkAt(id.range[0]), inShorthand: isShorthand(id) });
  }
  return out;
}
```

Note: the parent pointers used by `isShorthand` exist because ESLint sets `parent` on every node during traversal; the collector's `Program` visit runs before traversal ends but references are read after `verify` returns, when all parents are set.

- [ ] **Step 4: Write `tools/split.mjs`**

```js
// G1c generator: frozen monolith -> web/index.html, styles/app.css, src/**.
// Verbatim by construction: only the edits listed in the plan's
// "Generator rules" are applied. Run: node tools/split.mjs [--check]
import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { dirname, join, relative, posix } from 'node:path';
import { fileURLToPath } from 'node:url';
import { analyzeScript } from './analyze.mjs';

const HANDLER_ATTR = /\son[a-z]+=\\?"(.*?)\\?"/g;
const NOT_APP = new Set(['if', 'function', 'return', 'typeof', 'var', 'event', 'this', 'new', 'encodeURIComponent', 'decodeURIComponent', 'setTimeout', 'clearTimeout', 'parseInt', 'parseFloat', 'String', 'Number', 'JSON', 'Math', 'Date', 'alert', 'confirm', 'prompt', 'window', 'document', 'rgba', 'rgb', 'true', 'false', 'null', 'undefined']);

function handlerScan(text) {
  const calls = new Set(); const bare = new Set();
  for (const m of text.matchAll(HANDLER_ATTR)) {
    const v = m[1];
    for (const c of v.matchAll(/(?<![.\w$'"])([A-Za-z_$][\w$]*)\s*\(/g)) calls.add(c[1]);
    for (const b of v.matchAll(/(?<![.\w$'"])([A-Za-z_$][\w$]*)\b(?!\s*\()/g)) bare.add(b[1]);
  }
  return { calls, bare };
}

function moduleOf(chunk, headers, cfg) {
  for (const n of chunk.names) if (cfg.pin[n]) return cfg.pin[n];
  let section = null;
  for (const h of headers) if (h.line <= chunk.line) section = h.title; else break;
  const hit = section && cfg.sections.find((s) => section.startsWith(s.header));
  if (!section && cfg.preamble) return cfg.preamble;
  return hit ? hit.module : cfg.default;
}

function relImport(from, to) {
  let r = posix.relative(posix.dirname(from), to);
  if (!r.startsWith('.')) r = './' + r;
  return r;
}

export function splitMonolith(html, cfg) {
  const bom = html.startsWith('﻿') ? '﻿' : '';
  const lines = html.slice(bom.length).split('\n');
  const want = { 11: '<style>', 1321: '</style>', 5161: '<script>' };
  for (const [n, t] of Object.entries(want)) if (lines[n - 1].replace(/\r$/, '') !== t) throw new Error(`line ${n} is not ${t}`);
  const scriptEnd = lines.indexOf('</script>', 5161) + 1; // 1-based line of </script>
  if (scriptEnd <= 0) throw new Error('no closing </script>');

  const indexHtml = bom + [...lines.slice(0, 10), '<link rel="stylesheet" href="/assets/%%APP_CSS%%">', ...lines.slice(1321, 5160), '<script src="/assets/%%APP_JS%%"></script>', ...lines.slice(scriptEnd)].join('\n');
  const css = lines.slice(11, 1320).join('\n') + '\n';
  const js = lines.slice(5161, scriptEnd - 1).join('\n') + '\n';
  const LINE0 = 5161; // js line 1 == file line 5162

  const a = analyzeScript(js);
  const fileLine = (l) => l + LINE0;
  const headers = [];
  js.split('\n').forEach((l, i) => { const m = l.match(/^\/\/ ── (.+?)\s*─*\s*$/); if (m) headers.push({ line: i + 1, title: m[1] }); });

  const handlers = handlerScan(html);
  const modOfChunk = a.chunks.map((c) => moduleOf(c, headers, cfg));
  const ownerMod = (name) => modOfChunk[a.topNames.get(name).chunk];

  // ── State variables (rule 6)
  const isVar = (n) => a.topNames.has(n) && a.topNames.get(n).kind === 'var';
  const windowRead = new Set(a.windowMembers.map((w) => w.name));
  const stateGlobals = new Set();
  for (const n of handlers.bare) if (isVar(n)) stateGlobals.add(n);
  for (const n of windowRead) if (isVar(n)) stateGlobals.add(n);
  for (const n of cfg.windowVars) { if (!isVar(n)) throw new Error(`windowVars entry "${n}" is not a top-level variable`); stateGlobals.add(n); }
  const stateVars = new Set(stateGlobals);
  for (const r of a.refs) if (r.write && isVar(r.name) && modOfChunk[r.chunkIndex] !== ownerMod(r.name)) stateVars.add(r.name);
  const implicit = new Set(a.through.filter((r) => r.write).map((r) => r.name));
  for (const n of implicit) stateVars.add(n);
  for (const n of implicit) if (handlers.bare.has(n) || windowRead.has(n)) stateGlobals.add(n);

  // ── Edits per chunk: [start, end, text] in js coordinates
  const edits = a.chunks.map(() => []);
  const stateInit = new Map(); // name -> init text
  const lateInits = new Map(); // chunkIndex -> [stmt text]
  const report = { laterVarReads: [], undeclaredReads: [], thisCount: a.thisCount, stateVars: [], modules: {} };

  const declNode = (name) => a.topNames.get(name).def.node; // VariableDeclarator
  // Applies js-coordinate edits that fall inside [start, end) to that slice.
  const applyIn = (start, end, es) => {
    let t = js.slice(start, end);
    for (const [s, e, r] of es.filter(([s, e]) => s >= start && e <= end).sort((x, y) => y[0] - x[0])) t = t.slice(0, s - start) + r + t.slice(e - start);
    return t;
  };
  // Every reference to a state variable becomes state.NAME, except the
  // declarator identifiers of state variables (those declarators are removed).
  const refEdits = [];
  for (const r of a.refs.concat(a.through)) {
    if (!stateVars.has(r.name)) continue;
    if (a.topNames.has(r.name) && r.start === declNode(r.name).id.range[0]) continue;
    refEdits.push([r.start, r.end, r.inShorthand ? `${r.name}: state.${r.name}` : `state.${r.name}`, r.chunkIndex]);
  }
  const consumed = new Set();
  const take = (start, end) => refEdits.filter((e, i) => { const hit = e[0] >= start && e[1] <= end; if (hit) consumed.add(i); return hit; });

  for (const name of [...stateVars].sort()) {
    if (implicit.has(name)) { stateInit.set(name, 'undefined'); continue; }
    const d = declNode(name);
    if (!d.init) { stateInit.set(name, 'undefined'); continue; }
    const usesApp = a.refs.concat(a.through).some((r) => r.start >= d.init.range[0] && r.end <= d.init.range[1] && (a.topNames.has(r.name) || implicit.has(r.name)));
    if (usesApp && !cfg.lateInit.includes(name)) throw new Error(`state initializer of "${name}" reads app code; add it to modules.json lateInit`);
    const initText = applyIn(d.init.range[0], d.init.range[1], take(d.init.range[0], d.init.range[1]));
    if (usesApp) { stateInit.set(name, 'undefined'); const ci = a.topNames.get(name).chunk; (lateInits.get(ci) || lateInits.set(ci, []).get(ci)).push(`state.${name} = ${initText};`); }
    else stateInit.set(name, initText);
  }
  // Remove state declarators: the whole statement when none remain, otherwise
  // the declarator list is rebuilt from the kept declarators (their own
  // state rewrites applied), so no two edits ever overlap.
  for (const c of a.chunks) {
    if (c.kind !== 'var') continue;
    const decls = c.node.declarations;
    const keep = decls.filter((d) => !stateVars.has(d.id.name));
    if (keep.length === decls.length) continue;
    const ci = a.chunks.indexOf(c);
    for (const d of decls) if (stateVars.has(d.id.name)) take(d.range[0], d.range[1]); // inits already copied to state.js
    if (!keep.length) { take(c.stmtStart, c.stmtEnd); edits[ci].push([c.stmtStart, c.stmtEnd, '']); continue; }
    const listStart = decls[0].range[0], listEnd = decls[decls.length - 1].range[1];
    const text = keep.map((d) => applyIn(d.range[0], d.range[1], take(d.range[0], d.range[1]))).join(', ');
    take(listStart, listEnd);
    edits[ci].push([listStart, listEnd, text]);
  }
  refEdits.forEach((e, i) => { if (!consumed.has(i)) edits[e[3]].push([e[0], e[1], e[2]]); });

  // Cross-module module-level initializers (rule 10).
  for (const [name, info] of a.topNames) {
    if (info.kind !== 'var' || stateVars.has(name)) continue;
    const d = info.def.node; if (!d.init) continue;
    for (const r of a.refs) {
      if (r.start < d.init.range[0] || r.end > d.init.range[1]) continue;
      if (isVar(r.name) && ownerMod(r.name) !== modOfChunk[info.chunk]) throw new Error(`initializer of "${name}" reads "${r.name}" from another module`);
    }
  }
  // Report-only checks.
  for (const r of a.refs) {
    const owner = a.topNames.get(r.name);
    if (a.chunks[r.chunkIndex].kind === 'other' && owner.kind === 'var' && owner.chunk > r.chunkIndex) report.laterVarReads.push({ line: fileLine(a.chunks[r.chunkIndex].line), name: r.name });
  }
  const undeclared = new Set(a.through.filter((r) => !r.write && !implicit.has(r.name)).map((r) => r.name));
  report.undeclaredReads = [...undeclared].sort();

  // ── Exports, imports, inits
  const usedBy = new Map(); // module -> Set(names from other modules)
  const needsState = new Set();
  for (const r of a.refs) {
    const m = modOfChunk[r.chunkIndex];
    if (stateVars.has(r.name)) { needsState.add(m); continue; }
    const owner = ownerMod(r.name);
    if (owner !== m) (usedBy.get(m) || usedBy.set(m, new Set()).get(m)).add(r.name);
  }
  for (const r of a.through) if (stateVars.has(r.name)) needsState.add(modOfChunk[r.chunkIndex]);
  for (const ci of lateInits.keys()) needsState.add(modOfChunk[ci]);

  const isFn = (n) => a.topNames.has(n) && a.topNames.get(n).kind === 'function';
  const handlerFns = new Set([...handlers.calls].filter(isFn));
  // Functions reached by name rather than by a handler call: modules.json
  // windowFns (window[name] lookups) plus any top-level function accessed as
  // window.NAME. Both are listed in DYNAMIC_HANDLERS so the registry check
  // does not report them as stale.
  const dynamicFns = new Set();
  for (const n of cfg.windowFns) { if (!isFn(n)) throw new Error(`windowFns entry "${n}" is not a top-level function`); dynamicFns.add(n); }
  for (const n of windowRead) if (isFn(n)) dynamicFns.add(n);
  for (const n of dynamicFns) handlerFns.add(n);
  const exported = new Set(handlerFns);
  for (const set of usedBy.values()) for (const n of set) exported.add(n);
  for (const name of exported) {
    const ci = a.topNames.get(name).chunk; const c = a.chunks[ci];
    if (!edits[ci].some((e) => e[0] === c.stmtStart && e[2] === 'export ')) edits[ci].push([c.stmtStart, c.stmtStart, 'export ']);
  }
  const windowWrites = new Set(a.windowMembers.filter((w) => w.write && !a.topNames.has(w.name)).map((w) => w.name));

  // ── Emit modules
  const files = new Map();
  const bodies = new Map(); const inits = [];
  a.chunks.forEach((c, ci) => {
    let text = js.slice(c.start, c.end);
    const es = edits[ci].map(([s, e, t]) => [s - c.start, e - c.start, t]).sort((x, y) => y[0] - x[0] || y[1] - x[1]);
    for (const [s, e, t] of es) text = text.slice(0, s) + t + text.slice(e);
    const m = modOfChunk[ci];
    if (c.kind === 'other') {
      // Leading comments/whitespace stay outside; only the statement is wrapped.
      const cut = c.stmtStart - c.start;
      const prefix = text.slice(0, cut), stmt = text.slice(cut);
      const fn = `__init_L${fileLine(c.line)}`;
      text = `${prefix}export function ${fn}() {\n${stmt}${stmt.endsWith('\n') ? '' : '\n'}}\n`;
      inits.push({ m, fn });
    }
    if (lateInits.has(ci)) {
      const fn = `__init_L${fileLine(c.line)}_state`;
      text += `export function ${fn}() {\n  ${lateInits.get(ci).join('\n  ')}\n}\n`;
      inits.push({ m, fn });
    }
    bodies.set(m, (bodies.get(m) || '') + text);
  });
  const modules = [...new Set(modOfChunk)].sort();
  for (const m of modules) {
    const p = `src/${m}`;
    const imp = [];
    if (needsState.has(m)) imp.push(`import { state } from '${relImport(p, 'src/core/state.js')}';`);
    const byOwner = new Map();
    for (const n of [...(usedBy.get(m) || [])].sort()) { const o = ownerMod(n); (byOwner.get(o) || byOwner.set(o, []).get(o)).push(n); }
    for (const o of [...byOwner.keys()].sort()) imp.push(`import { ${byOwner.get(o).join(', ')} } from '${relImport(p, `src/${o}`)}';`);
    files.set(p, `// GENERATED by web/tools/split.mjs from tools/monolith.html -- do not edit during G1c.\n${imp.join('\n')}${imp.length ? '\n' : ''}${bodies.get(m)}`);
    report.modules[m] = { imports: imp.length, inits: inits.filter((i) => i.m === m).length };
  }
  files.set('src/core/state.js', `// GENERATED by web/tools/split.mjs -- shared mutable state (G1c spec section 5).\nexport const state = {\n${[...stateInit.keys()].sort().map((n) => `  ${n}: ${stateInit.get(n)},`).join('\n')}\n};\n`);

  const g = [];
  const gByOwner = new Map();
  for (const n of [...handlerFns].sort()) { const o = ownerMod(n); (gByOwner.get(o) || gByOwner.set(o, []).get(o)).push(n); }
  g.push('// GENERATED by web/tools/split.mjs -- the only code that defines app names on window (G1c spec section 6).');
  g.push(`import { state } from './core/state.js';`);
  for (const o of [...gByOwner.keys()].sort()) g.push(`import { ${gByOwner.get(o).join(', ')} } from '${relImport('src/globals.js', `src/${o}`)}';`);
  g.push('', '// Called from inline on*= handlers.', `export const HANDLER_FUNCTIONS = {\n${[...handlerFns].sort().map((n) => `  ${n},`).join('\n')}\n};`);
  g.push('', '// Named only via strings (window[name]) -- see web/tools/modules.json windowFns.', `export const DYNAMIC_HANDLERS = [\n${[...dynamicFns].sort().map((n) => `  '${n}',`).join('\n')}\n];`);
  g.push('', '// Variables read or written by handlers or via window.NAME; backed by state.', `export const STATE_GLOBALS = [\n${[...stateGlobals].sort().map((n) => `  '${n}',`).join('\n')}\n];`);
  g.push('', '// Assigned as window.NAME = ... in app code (left verbatim).', `export const WINDOW_WRITES = [\n${[...windowWrites].sort().map((n) => `  '${n}',`).join('\n')}\n];`);
  g.push('', 'export function installGlobals() {', '  Object.assign(window, HANDLER_FUNCTIONS);', '  for (const name of STATE_GLOBALS) {', '    Object.defineProperty(window, name, {', '      get() { return state[name]; },', '      set(v) { state[name] = v; },', '      configurable: true,', '      enumerable: true,', '    });', '  }', '}', '');
  files.set('src/globals.js', g.join('\n'));

  const mainImports = new Map();
  for (const { m, fn } of inits) (mainImports.get(m) || mainImports.set(m, []).get(m)).push(fn);
  const main = ['// GENERATED by web/tools/split.mjs -- entry point: install globals, then run load-time code in original order.', `import { installGlobals } from './globals.js';`];
  for (const m of modules) main.push(mainImports.has(m) ? `import { ${[...mainImports.get(m)].sort().join(', ')} } from './${m}';` : `import './${m}';`);
  main.push('', 'installGlobals();', ...inits.map((i) => `${i.fn}();`), '');
  files.set('src/main.js', main.join('\n'));
  files.set('index.html', indexHtml);
  files.set('styles/app.css', css);
  report.stateVars = [...stateVars].sort();
  return { files, report };
}

// ── CLI
const here = dirname(fileURLToPath(import.meta.url));
if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const web = join(here, '..');
  const cfg = JSON.parse(readFileSync(join(here, 'modules.json'), 'utf8'));
  const { files, report } = splitMonolith(readFileSync(join(here, 'monolith.html'), 'utf8'), cfg);
  if (process.argv.includes('--check')) {
    const drift = [...files].filter(([p, t]) => !existsSync(join(web, p)) || readFileSync(join(web, p), 'utf8') !== t).map(([p]) => p);
    if (drift.length) { console.error('generated files differ from committed:\n  ' + drift.join('\n  ')); process.exit(1); }
    console.log(`split:check OK (${files.size} files)`);
  } else {
    for (const [p, t] of files) { mkdirSync(dirname(join(web, p)), { recursive: true }); writeFileSync(join(web, p), t); }
    writeFileSync(join(here, 'split-report.json'), JSON.stringify(report, null, 2) + '\n');
    console.log(`wrote ${files.size} files; report: tools/split-report.json`);
  }
}
```

- [ ] **Step 5: Write `tools/modules.json` (single-module stage)**

```json
{
  "default": "legacy.js",
  "preamble": null,
  "sections": [],
  "pin": {},
  "windowVars": ["_groupSel", "_tmplGroupSel", "_vexGroupSel", "_vexRunGroupSel"],
  "windowFns": ["renderGroupTargetSummary", "renderRunMode", "renderTmplGroupSummary", "renderTmplOSCompat", "renderVexGroupSummary", "renderVexRunGroupSummary"],
  "lateInit": []
}
```

- [ ] **Step 6: Run the tests until green**

Run: `cd orchestrator/web && tools/node.sh sh -c 'npm ci --ignore-scripts --no-audit --no-fund && node --test tests/unit/split.test.mjs'`
Expected: `# pass 12`, `# fail 0`. Fix the generator (never the tests' intent) until it is green; if a test's expectation is wrong for the spec, ledger a Ruling.

- [ ] **Step 7: Commit and push**

```bash
git add orchestrator/web/tools/analyze.mjs orchestrator/web/tools/split.mjs orchestrator/web/tools/modules.json orchestrator/web/tests/unit/split.test.mjs
git commit -m "build(web): G1c generator -- verbatim monolith split via ESLint scope analysis

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
git push
```

---

### Task 4: Registry check (`scripts/g1c-check-globals.py`)

**Files:**
- Create: `scripts/g1c-check-globals.py`, `scripts/test_g1c_check_globals.py`
- Modify: `.github/workflows/test.yml` (Go job, after the G1 step)

**Interfaces:**
- Consumes: generated `web/src/globals.js` format from Task 3 (the four `export const` lists).
- Produces: `check(web_dir: Path) -> list[str]` (empty = OK); CLI exits 1 and prints each error.

Rules: **missing** — a name called in any inline handler (`web/index.html` markup or a JS string literal in `web/src/**/*.js`) that is not in `HANDLER_FUNCTIONS` ∪ `WINDOW_WRITES` ∪ `BUILTINS`; **stale** — a `HANDLER_FUNCTIONS` key never called by a handler and not in `DYNAMIC_HANDLERS`; **assign** — a bare identifier assigned inside a handler (`name=`, `name[...]=`, `name++`, `name+=`) that is not in `STATE_GLOBALS`; **window-writes** — the set of `window.NAME =` targets in `web/src/**` (excluding `globals.js`) must equal `WINDOW_WRITES` ∪ `STATE_GLOBALS`-backed names written that way.

- [ ] **Step 1: Write the failing tests `scripts/test_g1c_check_globals.py`**

```python
import importlib.util
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("g1c_globals", REPO_ROOT / "scripts" / "g1c-check-globals.py")
g = importlib.util.module_from_spec(spec)
spec.loader.exec_module(g)

GLOBALS = """export const HANDLER_FUNCTIONS = {
  doLogin,
  showTab,
};
export const DYNAMIC_HANDLERS = [
  'renderRunMode',
];
export const STATE_GLOBALS = [
  'scenarioView',
];
export const WINDOW_WRITES = [
  'openRunPanel',
];
"""


def make(index_html, extra_js="", globals_js=GLOBALS):
    d = Path(tempfile.mkdtemp())
    (d / "src").mkdir()
    (d / "index.html").write_text(index_html, encoding="utf-8")
    (d / "src" / "globals.js").write_text(globals_js, encoding="utf-8")
    (d / "src" / "legacy.js").write_text(extra_js, encoding="utf-8")
    return d


class TestRegistry(unittest.TestCase):
    def test_clean_registry_passes(self):
        d = make('<a onclick="showTab(\'x\')"></a><b onclick="doLogin()"></b>',
                 "export function renderRunMode(){}\n(function(){ window.openRunPanel = function(){}; })();\n"
                 "var h = '<i onchange=\"scenarioView=1;openRunPanel()\">';\n")
        self.assertEqual(g.check(d), [])

    def test_missing_handler_function_fails(self):
        d = make('<a onclick="showTab(\'x\');doLogin();vanished()"></a>')
        self.assertIn("missing: vanished", g.check(d))

    def test_stale_registry_entry_fails(self):
        d = make('<a onclick="showTab(\'x\')"></a>', "window.openRunPanel = 1;\n")
        self.assertIn("stale: doLogin", g.check(d))

    def test_dynamic_handler_is_not_stale(self):
        d = make('<a onclick="showTab(\'x\');doLogin()"></a>', "window.openRunPanel = 1;\n")
        self.assertFalse([e for e in g.check(d) if "renderRunMode" in e])

    def test_handler_assignment_to_unregistered_variable_fails(self):
        d = make('<a onclick="showTab(\'x\');doLogin()" onchange="INIT_ATTACH_SELECTED=this.value"></a>', "window.openRunPanel = 1;\n")
        self.assertIn("assign: INIT_ATTACH_SELECTED", g.check(d))

    def test_handler_indexed_assignment_in_js_string_fails_when_unregistered(self):
        js = "window.openRunPanel = 1;\nvar s = ' onchange=\"' + n + '_other[' + id + ']=this.checked;\"';\nvar t = '<i onchange=\"_sel[1]=this.checked\">';\n"
        d = make('<a onclick="showTab(\'x\');doLogin()"></a>', js)
        self.assertIn("assign: _sel", g.check(d))

    def test_unregistered_window_write_fails(self):
        d = make('<a onclick="showTab(\'x\');doLogin()"></a>', "window.openRunPanel = 1;\nwindow.sneaky = 2;\n")
        self.assertIn("window-write not registered: sneaky", g.check(d))

    def test_registered_window_write_never_made_fails(self):
        d = make('<a onclick="showTab(\'x\');doLogin()"></a>')
        self.assertIn("window-write registered but absent: openRunPanel", g.check(d))


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run to verify failure**

Run: `cd scripts && python3 -m unittest test_g1c_check_globals -v`
Expected: FAIL — `FileNotFoundError` for `g1c-check-globals.py`.

- [ ] **Step 3: Write `scripts/g1c-check-globals.py`**

```python
"""G1c registry check: keeps web/src/globals.js the honest, complete list of
app names reachable from inline handlers and window (G1c spec section 6).
Stdlib only. Usage: python3 scripts/g1c-check-globals.py [web_dir]"""
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_WEB = REPO_ROOT / "orchestrator" / "web"

HANDLER_ATTR = re.compile(r"""\son[a-z]+=\\?"(.*?)\\?\"""")
CALL = re.compile(r"(?<![.\w$'\"])([A-Za-z_$][\w$]*)\s*\(")
ASSIGN = re.compile(r"(?<![.\w$'\"])([A-Za-z_$][\w$]*)\s*(?:\[[^\]]*\])?\s*(?:=(?!=)|\+\+|--|\+=|-=)")
WINDOW_WRITE = re.compile(r"(?<![\w$.])window\.([A-Za-z_$][\w$]*)\s*=(?!=)")
BUILTINS = {
    "if", "function", "return", "typeof", "var", "new", "event", "this",
    "encodeURIComponent", "decodeURIComponent", "setTimeout", "clearTimeout",
    "parseInt", "parseFloat", "String", "Number", "JSON", "Math", "Date",
    "alert", "confirm", "prompt", "rgba", "rgb",
}
# Handler fragments built at runtime: '_x[' + id + ']=' leaves "]=" after a
# quote, so the variable name is the identifier right before the opening quote.
DYN_INDEX_ASSIGN = re.compile(r"([A-Za-z_$][\w$]*)\[\s*'\s*\+")


def _list(globals_js, const):
    m = re.search(r"export const " + const + r" = [\[{](.*?)[\]}];", globals_js, re.S)
    if not m:
        raise ValueError(f"globals.js has no {const}")
    return {t.strip().strip("',") for t in m.group(1).split("\n") if t.strip().strip("',")}


def check(web_dir):
    web_dir = Path(web_dir)
    globals_js = (web_dir / "src" / "globals.js").read_text(encoding="utf-8")
    fns = _list(globals_js, "HANDLER_FUNCTIONS")
    dynamic = _list(globals_js, "DYNAMIC_HANDLERS")
    state_globals = _list(globals_js, "STATE_GLOBALS")
    window_writes = _list(globals_js, "WINDOW_WRITES")

    sources = [(web_dir / "index.html").read_text(encoding="utf-8")]
    js_files = sorted(p for p in (web_dir / "src").rglob("*.js") if p.name != "globals.js")
    js_texts = [p.read_text(encoding="utf-8") for p in js_files]
    sources += js_texts

    called, assigned = set(), set()
    for text in sources:
        for m in HANDLER_ATTR.finditer(text):
            called |= set(CALL.findall(m.group(1)))
            assigned |= set(ASSIGN.findall(m.group(1)))
            assigned |= set(DYN_INDEX_ASSIGN.findall(m.group(1)))
    errors = []
    for n in sorted(called - fns - window_writes - BUILTINS):
        errors.append(f"missing: {n}")
    for n in sorted(fns - called - dynamic):
        errors.append(f"stale: {n}")
    for n in sorted(assigned - state_globals - BUILTINS):
        errors.append(f"assign: {n}")
    writes = set()
    for text in js_texts:
        writes |= set(WINDOW_WRITE.findall(text))
    for n in sorted(writes - window_writes - state_globals):
        errors.append(f"window-write not registered: {n}")
    for n in sorted(window_writes - writes):
        errors.append(f"window-write registered but absent: {n}")
    return errors


def main():
    web = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_WEB
    errors = check(web)
    if errors:
        print("G1c globals registry check: FAIL")
        for e in errors:
            print(f"  {e}")
        return 1
    print("G1c globals registry check: OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 4: Run tests until green**

Run: `cd scripts && python3 -m unittest test_g1c_check_globals -v`
Expected: 8 tests OK.

- [ ] **Step 5: Wire into CI** — in the Go job, add after the `G1 XSS sink regression guard` step:

```yaml
      - name: G1c globals registry check
        working-directory: .
        run: |
          python3 scripts/g1c-check-globals.py
          cd scripts && python3 -m unittest test_g1c_check_globals -v
```
(This step fails until Task 5 commits `web/src/`; commit Tasks 4 and 5 back-to-back, pushing after each, and expect this step red only for the Task 4 commit — record that in the commit message.)

- [ ] **Step 6: Commit and push**

```bash
git add scripts/g1c-check-globals.py scripts/test_g1c_check_globals.py .github/workflows/test.yml
git commit -m "ci(g1c): registry check for the window boundary (missing/stale/assign/window-writes)

Expected red in CI until the next commit adds web/src/.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
git push
```

---

### Task 5: Single-module build — generate, lint, bundle, smoke

**Files:**
- Create (generated): `orchestrator/web/index.html`, `styles/app.css`, `src/legacy.js`, `src/core/state.js`, `src/globals.js`, `src/main.js`, `tools/split-report.json`
- Create: `orchestrator/web/tools/build.mjs`, `orchestrator/web/eslint.config.mjs`, `orchestrator/web/eslint-browser-globals.json`, `orchestrator/web/tests/unit/build.test.mjs`
- Move: `orchestrator/wwwroot/images/*` → `orchestrator/web/images/` (`git mv`)
- Modify: `.github/workflows/test.yml` (web job), `orchestrator/web/tools/modules.json` (`lateInit` if the generator demands)

**Interfaces:**
- Consumes: Task 3 generator, Task 2 harness, Task 4 check.
- Produces: `npm run build` → `web/dist/{index.html, assets/app.<hash>.js, assets/app.<hash>.css, images/*, MANIFEST.sha256}`; `MANIFEST.sha256` format: one line per file except itself, `"<sha256-hex>  <posix-relative-path>\n"`, sorted by path.

- [ ] **Step 1: Write the failing build test `tests/unit/build.test.mjs`**

```js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFileSync, readdirSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const web = fileURLToPath(new URL('../..', import.meta.url));
const dist = join(web, 'dist');

test('build emits hashed assets, rewritten index.html and a complete manifest', () => {
  execFileSync('node', ['tools/build.mjs'], { cwd: web, stdio: 'pipe' });
  const assets = readdirSync(join(dist, 'assets')).sort();
  const js = assets.find((f) => /^app\.[A-Z0-9]+\.js$/i.test(f));
  const css = assets.find((f) => /^app\.[A-Z0-9]+\.css$/i.test(f));
  assert.ok(js && css, `assets: ${assets}`);
  const html = readFileSync(join(dist, 'index.html'), 'utf8');
  assert.ok(html.includes(`/assets/${js}`) && html.includes(`/assets/${css}`));
  assert.ok(!html.includes('%%APP_'));
  const lines = readFileSync(join(dist, 'MANIFEST.sha256'), 'utf8').trim().split('\n');
  const paths = lines.map((l) => l.split('  ')[1]);
  assert.deepEqual(paths, [...paths].sort());
  assert.ok(paths.includes('index.html') && paths.includes(`assets/${js}`) && paths.includes('images/logo.png'));
  assert.ok(!paths.includes('MANIFEST.sha256'));
  for (const l of lines) {
    const [hash, p] = l.split('  ');
    assert.equal(createHash('sha256').update(readFileSync(join(dist, p))).digest('hex'), hash, p);
  }
});

test('build is deterministic', () => {
  execFileSync('node', ['tools/build.mjs'], { cwd: web, stdio: 'pipe' });
  const a = readFileSync(join(dist, 'MANIFEST.sha256'), 'utf8');
  execFileSync('node', ['tools/build.mjs'], { cwd: web, stdio: 'pipe' });
  assert.equal(readFileSync(join(dist, 'MANIFEST.sha256'), 'utf8'), a);
});
```

- [ ] **Step 2: Move the images and generate the sources**

```bash
cd /c/Users/Administrator/Downloads/Audspect_Cloud
git mv orchestrator/wwwroot/images orchestrator/web/images
cd orchestrator/web
tools/node.sh sh -c 'npm ci --ignore-scripts --no-audit --no-fund && npm run split'
```
Expected: `wrote 6 files; report: tools/split-report.json`. If it exits with `state initializer of "X" reads app code`, add `"X"` to `modules.json` `lateInit`, ledger a Ruling naming X, and rerun.

- [ ] **Step 3: Review `tools/split-report.json`**

- `laterVarReads`: for each entry, open the monolith line and decide whether the read happens at load (behavior change) or inside a callback (no change). Ledger each as a Ruling.
- `undeclaredReads`: every entry must be a browser API (e.g. `document`, `fetch`, `localStorage`). Write them, sorted, into `orchestrator/web/eslint-browser-globals.json` as `{ "<name>": "readonly", ... }`. Any entry that is not a browser API is a pre-existing bug (it would throw today too): list it in the commit message; do not fix.
- `thisCount`: grep `this` usages inside top-level functions that are called as plain functions (not handlers, not methods); in strict mode `this` is `undefined` instead of `window`. Ledger each finding.

- [ ] **Step 4: Run the build test to verify failure**

Run: `tools/node.sh node --test tests/unit/build.test.mjs`
Expected: FAIL — `Cannot find module '/web/tools/build.mjs'`.

- [ ] **Step 5: Write `tools/build.mjs`**

```js
// Production bundle: src/main.js + styles/app.css -> dist/ with content-hashed
// names, rewritten index.html, copied images and MANIFEST.sha256 (G1c spec 7).
import { build } from 'esbuild';
import { createHash } from 'node:crypto';
import { cpSync, mkdirSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { join, relative, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const web = fileURLToPath(new URL('..', import.meta.url));
const dist = join(web, 'dist');
rmSync(dist, { recursive: true, force: true });
mkdirSync(join(dist, 'assets'), { recursive: true });

const result = await build({
  absWorkingDir: web,
  entryPoints: { app: 'src/main.js', 'app-css': 'styles/app.css' },
  bundle: true,
  format: 'iife',
  target: 'es2020',
  minify: false,
  legalComments: 'inline',
  charset: 'utf8',
  outdir: 'dist/assets',
  entryNames: '[name].[hash]',
  // Absolute same-origin URLs in CSS (e.g. url(/images/logo.png)) are served
  // as-is, never inlined or resolved by the bundler.
  external: ['/images/*', '/assets/*'],
  metafile: true,
  logLevel: 'warning',
});
let jsName, cssName;
for (const out of Object.keys(result.metafile.outputs)) {
  const base = out.split('/').pop();
  if (base.startsWith('app.') && base.endsWith('.js')) jsName = base;
  if (base.startsWith('app-css.') && base.endsWith('.css')) cssName = base.replace(/^app-css\./, 'app.');
  if (base.startsWith('app-css.') && base.endsWith('.css')) cpSync(join(web, out), join(dist, 'assets', cssName)), rmSync(join(web, out));
}
if (!jsName || !cssName) throw new Error('esbuild did not emit app js/css');

const html = readFileSync(join(web, 'index.html'), 'utf8').replace('%%APP_JS%%', jsName).replace('%%APP_CSS%%', cssName);
writeFileSync(join(dist, 'index.html'), html);
cpSync(join(web, 'images'), join(dist, 'images'), { recursive: true });

const files = [];
(function walk(d) { for (const e of readdirSync(d)) { const p = join(d, e); if (statSync(p).isDirectory()) walk(p); else files.push(p); } })(dist);
const manifest = files
  .map((p) => relative(dist, p).split(sep).join('/'))
  .filter((p) => p !== 'MANIFEST.sha256')
  .sort()
  .map((p) => `${createHash('sha256').update(readFileSync(join(dist, p))).digest('hex')}  ${p}\n`)
  .join('');
writeFileSync(join(dist, 'MANIFEST.sha256'), manifest);
console.log(`built dist/: ${jsName}, ${cssName}, ${files.length} files`);
```

Run: `tools/node.sh node --test tests/unit/build.test.mjs`
Expected: 2 pass. A strict-mode syntax error (e.g. legacy octal) fails the esbuild step: fix it **in `tools/monolith.html`** with the minimal strict-equivalent text (`010` → `0o10`), regenerate, ledger a Ruling per fix.

- [ ] **Step 6: Write `eslint.config.mjs`**

```js
import { readFileSync } from 'node:fs';
const browser = JSON.parse(readFileSync(new URL('./eslint-browser-globals.json', import.meta.url), 'utf8'));

export default [
  {
    files: ['src/**/*.js'],
    languageOptions: { ecmaVersion: 2022, sourceType: 'module', globals: browser },
    rules: {
      'no-undef': 'error',
      'no-eval': 'error',
      'no-implied-eval': 'error',
      'no-new-func': 'error',
      'no-import-assign': 'error',
      'no-restricted-properties': ['warn',
        { property: 'innerHTML', message: 'innerHTML sink: gated by the G1 guard.' },
        { property: 'outerHTML', message: 'outerHTML sink.' },
        { property: 'insertAdjacentHTML', message: 'insertAdjacentHTML sink.' },
        { object: 'document', property: 'write', message: 'document.write sink.' },
      ],
    },
  },
];
```

Run: `tools/node.sh npx eslint src --max-warnings=100000`
Expected: 0 errors (warnings allowed — they are the report-only sink list). Any `no-undef` error means a missing browser global in the allowlist or a generator bug; fix the cause, never disable the rule.

- [ ] **Step 7: Registry check and drift check**

```bash
cd /c/Users/Administrator/Downloads/Audspect_Cloud
python3 scripts/g1c-check-globals.py
cd orchestrator/web && tools/node.sh npm run split:check
```
Expected: `G1c globals registry check: OK` and `split:check OK (6 files)`.

- [ ] **Step 8: Smoke the bundled build against the monolith baseline**

```bash
cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator
MSYS_NO_PATHCONV=1 docker run --rm -v "$(cygpath -m "$PWD"):/o" -w /o/web -e SMOKE_ROOT=dist -e PLAYWRIGHT_IMAGE_VERSION=1.63.0 \
  mcr.microsoft.com/playwright:v1.63.0-noble@sha256:eff16c30e6f3f4af0a03fa4b706120d5e9b0891c344a27d64559aff5900a4a27 \
  sh -c 'npm ci --ignore-scripts --no-audit --no-fund && npm run build && npm run smoke'
```
Expected: 1 passed (no new errors, no unresolved handlers, `window.__xss` undefined). On failure, read `test-results/`, fix the generator or `modules.json`, regenerate — never edit generated files.

- [ ] **Step 9: Extend the CI `web` job** (after the version check, before the smoke step; change the smoke step's `SMOKE_ROOT` to `dist` and add a second smoke step that keeps `../wwwroot`, until Task 8 deletes it)

```yaml
      - name: Generated sources match the generator (G1c freeze)
        run: npm run split:check
      - name: Lint
        run: npx eslint src --max-warnings=100000
      - name: Unit tests
        run: npm test
      - name: Build
        run: npm run build
```

- [ ] **Step 10: Commit and push**

```bash
cd /c/Users/Administrator/Downloads/Audspect_Cloud
git add orchestrator/web/index.html orchestrator/web/styles/app.css orchestrator/web/src/legacy.js orchestrator/web/src/core/state.js orchestrator/web/src/globals.js orchestrator/web/src/main.js orchestrator/web/tools/split-report.json orchestrator/web/tools/build.mjs orchestrator/web/tools/modules.json orchestrator/web/eslint.config.mjs orchestrator/web/eslint-browser-globals.json orchestrator/web/tests/unit/build.test.mjs orchestrator/web/images orchestrator/wwwroot/images .github/workflows/test.yml
git commit -m "build(web): single-module ES build of the dashboard, behavior-identical to the monolith

<laterVarReads / undeclaredReads / this rulings summary>

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
git push
```
Confirm both CI jobs green (the registry step from Task 4 turns green here).

---

### Task 6: G1 guard REVIEW category and classifier-view assembler

**Files:**
- Modify: `scripts/g1-check-no-regression.py`, `scripts/test_g1_check_no_regression.py`
- Create: `scripts/g1-assemble-classifier-view.py`, `scripts/test_g1_assemble_classifier_view.py`, `scripts/g1-run-local.sh`

**Interfaces:**
- Produces: `find_rhs_changes(old_sinks, new_sinks) -> [(slot, tier, old_sink_id, new_sink_id), ...]`; `assemble(web_dir: Path) -> str`; CLI `python3 scripts/g1-assemble-classifier-view.py` writes `orchestrator/wwwroot/index.html`.

- [ ] **Step 1: Write failing guard tests** (append to `scripts/test_g1_check_no_regression.py` before `if __name__`)

```python
class TestRhsChanges(unittest.TestCase):
    def test_same_slot_changed_rhs_same_tier_is_reported(self):
        old = [_sink("f", "el", "=", 4, sink_id="f:el:=:aaaaaaaaaaaa")]
        new = [_sink("f", "el", "=", 4, sink_id="f:el:=:bbbbbbbbbbbb")]
        self.assertEqual(guard.find_rhs_changes(old, new),
                         [(("f", "el", "="), 4, "f:el:=:aaaaaaaaaaaa", "f:el:=:bbbbbbbbbbbb")])
        self.assertEqual(guard.compare_slots(old, new)[0], [])  # still not a failure

    def test_identical_sink_is_not_reported(self):
        s = [_sink("f", "el", "=", 4)]
        self.assertEqual(guard.find_rhs_changes(s, list(s)), [])

    def test_tier_change_is_not_a_review_item(self):
        old = [_sink("f", "el", "=", 1, sink_id="f:el:=:aaaaaaaaaaaa")]
        new = [_sink("f", "el", "=", 4, sink_id="f:el:=:bbbbbbbbbbbb")]
        self.assertEqual(guard.find_rhs_changes(old, new), [])
```

Run: `cd scripts && python3 -m unittest test_g1_check_no_regression -v`
Expected: 3 errors — `AttributeError: module ... has no attribute 'find_rhs_changes'`.

- [ ] **Step 2: Implement** (insert after `compare_slots` in `scripts/g1-check-no-regression.py`)

```python
def find_rhs_changes(old_sinks, new_sinks):
    """Same slot, RHS changed, tier unchanged: never a failure, always shown.
    A changed RHS can change data provenance (e.g. an internal value becoming
    user-controlled state) without changing the tier, so a reviewer must see
    it (G1c spec section 8). Pairs the unmatched sinks of each slot exactly
    like compare_slots does and reports the pairs whose tiers are equal."""
    out = []
    old_by_slot = _group_by_slot(old_sinks)
    for slot, news in _group_by_slot(new_sinks).items():
        olds = list(old_by_slot.get(slot, []))
        changed_new = []
        for s in news:
            match = next((o for o in olds if o["sink_id"] == s["sink_id"] and o["severity_tier"] == s["severity_tier"]), None)
            if match is not None:
                olds.remove(match)
            else:
                changed_new.append(s)
        olds.sort(key=lambda o: (-o["severity_tier"], o["sink_id"]))
        changed_new.sort(key=lambda s: (s["severity_tier"], s["sink_id"]))
        for o, n in zip(olds, changed_new):
            if o["severity_tier"] == n["severity_tier"] and o["sink_id"] != n["sink_id"]:
                out.append((slot, n["severity_tier"], o["sink_id"], n["sink_id"]))
    return sorted(out)
```

And in `main()`, after the `added` block:

```python
    rhs_changes = find_rhs_changes(old_sinks, new_sinks)
    if rhs_changes:
        print(f"  {len(rhs_changes)} sink(s) with a changed RHS at the same tier (REVIEW, not failed):")
        for slot, tier, old_id, new_id in rhs_changes:
            print(f"    REVIEW severity={tier}  {format_slot(slot)}  [{old_id} -> {new_id}]")
```

Run: `cd scripts && python3 -m unittest test_g1_check_no_regression -v`
Expected: all tests OK (existing + 3 new).

- [ ] **Step 3: Write failing assembler tests `scripts/test_g1_assemble_classifier_view.py`**

```python
import importlib.util
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("g1_view", REPO_ROOT / "scripts" / "g1-assemble-classifier-view.py")
v = importlib.util.module_from_spec(spec)
spec.loader.exec_module(v)


def web(files):
    d = Path(tempfile.mkdtemp())
    for rel, text in files.items():
        p = d / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(text.encode("utf-8"))
    return d


BASE = {"index.html": "<html>\n<body>\n<script src=\"/assets/%%APP_JS%%\"></script>\n</body>\n</html>\n"}


class TestAssemble(unittest.TestCase):
    def test_inlines_sources_in_sorted_path_order(self):
        d = web({**BASE, "src/b.js": "function b() {}\n", "src/a.js": "function a() {}\n", "src/core/z.js": "function z() {}\n"})
        out = v.assemble(d)
        self.assertIn("<script>\nfunction a() {}\nfunction b() {}\nfunction z() {}\n</script>", out)
        self.assertNotIn("%%APP_JS%%", out)

    def test_is_byte_identical_across_runs_and_uses_lf(self):
        d = web({**BASE, "src/a.js": "function a() {}\r\n"})
        self.assertEqual(v.assemble(d), v.assemble(d))
        self.assertNotIn("\r", v.assemble(d))

    def test_missing_script_tag_fails(self):
        d = web({"index.html": "<html></html>\n", "src/a.js": ""})
        with self.assertRaises(ValueError):
            v.assemble(d)


if __name__ == "__main__":
    unittest.main()
```

Run: `cd scripts && python3 -m unittest test_g1_assemble_classifier_view -v`
Expected: FAIL — file not found.

- [ ] **Step 4: Write `scripts/g1-assemble-classifier-view.py`**

```python
"""Assembles the G1 classifier view: web/index.html with every web/src/**/*.js
inlined (sorted by POSIX path) in place of the bundle <script> tag, LF only.
This is a CI analysis artifact, never application build output: the proven G1
scripts read a hard-coded orchestrator/wwwroot/index.html, so the view is
written there for them (G1c spec sections 2 and 8). Stdlib only."""
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
WEB = REPO_ROOT / "orchestrator" / "web"
OUT = REPO_ROOT / "orchestrator" / "wwwroot" / "index.html"
TAG = '<script src="/assets/%%APP_JS%%"></script>'


def _lf(text):
    return text.replace("\r\n", "\n")


def assemble(web_dir):
    web_dir = Path(web_dir)
    html = _lf((web_dir / "index.html").read_text(encoding="utf-8"))
    if TAG not in html:
        raise ValueError(f"{web_dir / 'index.html'} has no {TAG}")
    files = sorted((web_dir / "src").rglob("*.js"), key=lambda p: p.relative_to(web_dir).as_posix())
    js = "".join(_lf(p.read_text(encoding="utf-8")) for p in files)
    if js and not js.endswith("\n"):
        js += "\n"
    return html.replace(TAG, "<script>\n" + js + "</script>", 1)


def main():
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_bytes(assemble(WEB).encode("utf-8"))
    print(f"G1 classifier view written to {OUT.relative_to(REPO_ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

Run: `cd scripts && python3 -m unittest test_g1_assemble_classifier_view -v`
Expected: 3 tests OK.

- [ ] **Step 5: Write `scripts/g1-run-local.sh`**

```bash
#!/usr/bin/env bash
# Local G1 run on the classifier view. Moves a locally built
# orchestrator/wwwroot/index.html aside and always restores it.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TARGET="$ROOT/orchestrator/wwwroot/index.html"
SAVED=""
if [ -f "$TARGET" ]; then SAVED="$(mktemp)"; mv "$TARGET" "$SAVED"; fi
restore() { rm -f "$TARGET"; if [ -n "$SAVED" ]; then mv "$SAVED" "$TARGET"; fi; }
trap restore EXIT
cd "$ROOT"
python3 scripts/g1-assemble-classifier-view.py
python3 scripts/g1-innerhtml-sink-classifier.py
python3 scripts/g1-trace-indirect-sinks.py
python3 scripts/g1-merge-classification.py
git show HEAD:Assessment/G1_FINAL_CLASSIFICATION.json > "${TMPDIR:-/tmp}/g1_base.json"
python3 scripts/g1-check-no-regression.py --against "${TMPDIR:-/tmp}/g1_base.json"
(cd scripts && python3 -m unittest test_g1_merge_classification test_g1_check_no_regression test_g1_assemble_classifier_view)
```

- [ ] **Step 6: Commit and push** (the assembler is not wired into CI yet — Task 8 does that at cutover)

```bash
chmod +x scripts/g1-run-local.sh
git add scripts/g1-check-no-regression.py scripts/test_g1_check_no_regression.py scripts/g1-assemble-classifier-view.py scripts/test_g1_assemble_classifier_view.py scripts/g1-run-local.sh
git commit -m "ci(g1): REVIEW report for same-tier RHS changes; deterministic classifier view

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
git push
```

---

### Task 7: Go — manifest integrity, cache headers, watch list

**Files:**
- Modify: `orchestrator/cmd/server/static.go`, `orchestrator/cmd/server/static_test.go`, `orchestrator/cmd/server/main.go:878-893`

**Interfaces:**
- Produces: `var expectedWWWManifestHash = ""` (set via `-ldflags -X main.expectedWWWManifestHash=…`); `func verifyWWWRoot(dir, expected string) error`; `func wwwRootWatchList(dir string) []string`; `func cacheHeaders(h http.Handler) http.Handler`. Removes `expectedWWWRootHash`.

- [ ] **Step 1: Write failing tests** (append to `orchestrator/cmd/server/static_test.go`; add `crypto/sha256`, `fmt`, `net/http`, `net/http/httptest`, `sort`, `strings` to its imports)

```go
// writeWWWRoot builds a wwwroot with a valid MANIFEST.sha256 and returns the
// directory plus the manifest's own SHA-256 (what the binary is built with).
func writeWWWRoot(t *testing.T, files map[string]string) (string, string) {
	t.Helper()
	dir := t.TempDir()
	var names []string
	for p, body := range files {
		full := filepath.Join(dir, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		names = append(names, p)
	}
	sort.Strings(names)
	var b strings.Builder
	for _, p := range names {
		fmt.Fprintf(&b, "%x  %s\n", sha256.Sum256([]byte(files[p])), p)
	}
	if err := os.WriteFile(filepath.Join(dir, "MANIFEST.sha256"), []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir, fmt.Sprintf("%x", sha256.Sum256([]byte(b.String())))
}

var sampleWWW = map[string]string{
	"index.html":            "<html></html>",
	"assets/app.ABC123.js":  "console.log(1)",
	"assets/app.DEF456.css": "body{}",
	"images/logo.png":       "png",
}

func TestVerifyWWWRoot_ValidTreePasses(t *testing.T) {
	dir, h := writeWWWRoot(t, sampleWWW)
	if err := verifyWWWRoot(dir, h); err != nil {
		t.Fatalf("verifyWWWRoot = %v, want nil", err)
	}
}

func TestVerifyWWWRoot_TamperedFileFails(t *testing.T) {
	dir, h := writeWWWRoot(t, sampleWWW)
	os.WriteFile(filepath.Join(dir, "assets", "app.ABC123.js"), []byte("alert(1)"), 0o644)
	if err := verifyWWWRoot(dir, h); err == nil || !strings.Contains(err.Error(), "assets/app.ABC123.js") {
		t.Fatalf("verifyWWWRoot = %v, want a hash mismatch naming the file", err)
	}
}

func TestVerifyWWWRoot_UnlistedFileFails(t *testing.T) {
	dir, h := writeWWWRoot(t, sampleWWW)
	os.WriteFile(filepath.Join(dir, "assets", "evil.js"), []byte("x"), 0o644)
	if err := verifyWWWRoot(dir, h); err == nil || !strings.Contains(err.Error(), "evil.js") {
		t.Fatalf("verifyWWWRoot = %v, want an unlisted-file error naming evil.js", err)
	}
}

func TestVerifyWWWRoot_MissingFileFails(t *testing.T) {
	dir, h := writeWWWRoot(t, sampleWWW)
	os.Remove(filepath.Join(dir, "images", "logo.png"))
	if err := verifyWWWRoot(dir, h); err == nil || !strings.Contains(err.Error(), "images/logo.png") {
		t.Fatalf("verifyWWWRoot = %v, want a missing-file error", err)
	}
}

func TestVerifyWWWRoot_EditedManifestFails(t *testing.T) {
	dir, h := writeWWWRoot(t, sampleWWW)
	f, _ := os.OpenFile(filepath.Join(dir, "MANIFEST.sha256"), os.O_APPEND|os.O_WRONLY, 0o644)
	f.WriteString("\n")
	f.Close()
	if err := verifyWWWRoot(dir, h); err == nil || !strings.Contains(err.Error(), "MANIFEST.sha256") {
		t.Fatalf("verifyWWWRoot = %v, want a manifest hash mismatch", err)
	}
}

func TestVerifyWWWRoot_MissingManifestFails(t *testing.T) {
	dir, h := writeWWWRoot(t, sampleWWW)
	os.Remove(filepath.Join(dir, "MANIFEST.sha256"))
	if err := verifyWWWRoot(dir, h); err == nil {
		t.Fatal("verifyWWWRoot = nil, want an error when MANIFEST.sha256 is missing")
	}
}

func TestWWWRootWatchList_CoversEveryManifestFile(t *testing.T) {
	dir, _ := writeWWWRoot(t, sampleWWW)
	got := wwwRootWatchList(dir)
	if len(got) != len(sampleWWW)+1 {
		t.Fatalf("watch list has %d entries, want %d (every file + the manifest): %v", len(got), len(sampleWWW)+1, got)
	}
}

func TestCacheHeaders(t *testing.T) {
	h := cacheHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	for path, want := range map[string]string{
		"/assets/app.ABC123.js": "public, max-age=31536000, immutable",
		"/":                     "no-cache",
		"/index.html":           "no-cache",
	} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if got := rec.Header().Get("Cache-Control"); got != want {
			t.Errorf("%s Cache-Control = %q, want %q", path, got, want)
		}
	}
}
```

Run: `cd orchestrator && go test ./cmd/server -run 'VerifyWWWRoot|WWWRootWatchList|CacheHeaders' -count=1`
Expected: FAIL — `undefined: verifyWWWRoot`.

- [ ] **Step 2: Implement in `static.go`**

Replace the `expectedWWWRootHash` declaration and its comment with:

```go
// expectedWWWManifestHash is the SHA-256 of wwwroot/MANIFEST.sha256, injected
// by the Docker build (-ldflags -X main.expectedWWWManifestHash=...). The
// manifest lists the SHA-256 of every served file, so this one value anchors
// the whole dashboard (G1c spec section 7). Empty in builds made outside
// Docker: the check is then disabled and logged, as before.
var expectedWWWManifestHash = ""
```

Add (with imports `bufio`, `errors`, `strings` alongside the existing ones):

```go
const wwwManifestName = "MANIFEST.sha256"

// verifyWWWRoot checks that the manifest matches expected, that every listed
// file exists with its listed hash, and that no unlisted file exists.
func verifyWWWRoot(dir, expected string) error {
	manifestPath := filepath.Join(dir, wwwManifestName)
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		return fmt.Errorf("read %s: %w", wwwManifestName, err)
	}
	if got := fmt.Sprintf("%x", sha256.Sum256(raw)); got != expected {
		return fmt.Errorf("%s hash mismatch: expected %s got %s", wwwManifestName, expected, got)
	}
	listed := map[string]string{}
	sc := bufio.NewScanner(strings.NewReader(string(raw)))
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			continue
		}
		hash, rel, ok := strings.Cut(line, "  ")
		if !ok || len(hash) != 64 || rel == "" || strings.Contains(rel, "..") {
			return fmt.Errorf("%s: malformed line %q", wwwManifestName, line)
		}
		listed[rel] = hash
	}
	var problems []string
	for rel, want := range listed {
		data, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(rel)))
		if err != nil {
			problems = append(problems, fmt.Sprintf("missing %s", rel))
			continue
		}
		if got := fmt.Sprintf("%x", sha256.Sum256(data)); got != want {
			problems = append(problems, fmt.Sprintf("hash mismatch %s", rel))
		}
	}
	walkErr := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		rel = filepath.ToSlash(rel)
		if rel != wwwManifestName {
			if _, ok := listed[rel]; !ok {
				problems = append(problems, fmt.Sprintf("unlisted file %s", rel))
			}
		}
		return nil
	})
	if walkErr != nil {
		problems = append(problems, walkErr.Error())
	}
	if len(problems) > 0 {
		sort.Strings(problems)
		return errors.New(strings.Join(problems, "; "))
	}
	return nil
}

// wwwRootWatchList returns every manifest-listed file plus the manifest, for
// the runtime integrity watcher. Falls back to index.html when there is no
// manifest (dev builds), matching the previous behavior.
func wwwRootWatchList(dir string) []string {
	raw, err := os.ReadFile(filepath.Join(dir, wwwManifestName))
	if err != nil {
		return []string{filepath.Join(dir, "index.html")}
	}
	out := []string{filepath.Join(dir, wwwManifestName)}
	for _, line := range strings.Split(string(raw), "\n") {
		if _, rel, ok := strings.Cut(line, "  "); ok && rel != "" {
			out = append(out, filepath.Join(dir, filepath.FromSlash(rel)))
		}
	}
	return out
}

// cacheHeaders: hashed assets never change under the same name; index.html
// must be revalidated so an upgrade never pairs an old page with a new bundle.
func cacheHeaders(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/assets/") {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		} else if r.URL.Path == "/" || r.URL.Path == "/index.html" {
			w.Header().Set("Cache-Control", "no-cache")
		}
		h.ServeHTTP(w, r)
	})
}
```

Replace the body of `StaticHandler` after `reporting.SetWWWRoot(wwwrootDir)` with:

```go
	if expectedWWWManifestHash != "" {
		if err := verifyWWWRoot(wwwrootDir, expectedWWWManifestHash); err != nil {
			log.Fatalf("[FATAL] wwwroot integrity: %v -- files may be tampered. Redeploy from a trusted release package.", err)
		}
		log.Printf("[+] wwwroot integrity: manifest and every listed file verified (%s…)", expectedWWWManifestHash[:16])
	} else {
		log.Println("[~] wwwroot integrity: no reference hash compiled in — hash check disabled (dev build)")
	}
	return cacheHeaders(http.FileServer(http.Dir(wwwrootDir)))
```

Add `sort` to the imports. Update the file's top comment block so it describes the manifest (remove the `sha256sum wwwroot/index.html` instructions).

- [ ] **Step 3: Watch every manifest file** — in `main.go`, replace the single `{Path: filepath.Join(resolveWWWRoot(), "index.html"), Severity: "critical"},` entry: remove it from the `WatchPaths` literal and, directly after that `integrity.WatchPaths(...)` call, add:

```go
	// Every served dashboard file, not only index.html (G1c): the watcher
	// closes the running-process window for the whole manifest.
	var wwwWatch []struct {
		Path     string
		Severity string
	}
	for _, p := range wwwRootWatchList(resolveWWWRoot()) {
		wwwWatch = append(wwwWatch, struct {
			Path     string
			Severity string
		}{Path: p, Severity: "critical"})
	}
	integrity.WatchPaths(wwwWatch)
```

- [ ] **Step 4: Run tests, vet, gofmt**

```bash
cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator
go test ./cmd/server -count=1
go vet ./cmd/server
tr -d '\r' < cmd/server/static.go | gofmt -l; tr -d '\r' < cmd/server/main.go | gofmt -l; tr -d '\r' < cmd/server/static_test.go | gofmt -l
grep -rn expectedWWWRootHash --include=*.go . || echo "no references left"
```
Expected: `ok`; vet silent; gofmt prints nothing; `no references left`.

- [ ] **Step 5: Commit and push**

```bash
cd /c/Users/Administrator/Downloads/Audspect_Cloud
git add orchestrator/cmd/server/static.go orchestrator/cmd/server/static_test.go orchestrator/cmd/server/main.go
git commit -m "feat(integrity): verify and watch every dashboard file via MANIFEST.sha256

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
git push
```
(The Dockerfile still passes the old `-X main.expectedWWWRootHash`; garble/ld ignores `-X` for a missing symbol, so the image builds with the check disabled until Task 8. Note this in the ledger.)

---

### Task 8: Cutover — Docker stage, build script, G1 on the classifier view, retire committed wwwroot

**Files:**
- Modify: `orchestrator/Dockerfile`, `packaging/windows-build.ps1`, `.github/workflows/test.yml`, `.gitignore` (repo root)
- Delete from git: `orchestrator/wwwroot/index.html`
- Create: `orchestrator/web/tools/dev-build.sh`
- Regenerate + commit: `Assessment/G1_INNERHTML_SINK_INVENTORY.csv`, `Assessment/G1_INNERHTML_SINK_INVENTORY.json`, `Assessment/G1_INDIRECT_SINK_TRACE.csv`, `Assessment/G1_FINAL_CLASSIFICATION.json`, `Assessment/G1_FINAL_CLASSIFICATION.csv`

**Interfaces:**
- Consumes: Task 5 `npm run build` + `MANIFEST.sha256`; Task 6 assembler; Task 7 `expectedWWWManifestHash`.

- [ ] **Step 1: Dockerfile — add the web stage** (insert before `FROM golang:1.26-alpine AS builder`)

```dockerfile
# ── Dashboard (G1c): Node only here, never in the final image ─────────────────
FROM node:24-alpine@sha256:ebfe2f90462722a7a4de65e91990e97fe0d401c70e0e762c5b53302f905ec1c1 AS web
WORKDIR /web
COPY orchestrator/web/package.json orchestrator/web/package-lock.json ./
RUN npm ci --ignore-scripts --no-audit --no-fund
COPY orchestrator/web/ ./
RUN npm run build && sha256sum dist/MANIFEST.sha256 | cut -d' ' -f1 > /web-manifest.sha256 && echo "wwwroot manifest hash: $(cat /web-manifest.sha256)"
```

In the `builder` stage: delete `ARG BAS_WWWROOT_HASH=""` and its comment; add after `COPY orchestrator/ .`:

```dockerfile
COPY --from=web /web-manifest.sha256 /web-manifest.sha256
```

and change the garble `RUN` to read it:

```dockerfile
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOGARBLE='github.com/audspect/*' \
    garble -literals build \
    -ldflags="-s -w -X main.expectedWWWManifestHash=$(cat /web-manifest.sha256)" \
    -o /bin/orchestrator ./cmd/server
```

In the final stage replace `COPY orchestrator/wwwroot /wwwroot` with:

```dockerfile
COPY --from=web /web/dist /wwwroot
```

- [ ] **Step 2: `packaging/windows-build.ps1`** — delete the `0b-iv` block (the `$WWWRootHash` computation and its warnings, lines starting `# 0b-iv.` through the closing `}` of its `if/else`) and the two lines that add `BAS_WWWROOT_HASH` to `$buildExtraArgs`. Replace them with one log line:

```powershell
Log "  wwwroot integrity: manifest hash is computed inside the Docker build (G1c)."
```

- [ ] **Step 3: `orchestrator/web/tools/dev-build.sh`**

```bash
#!/usr/bin/env bash
# Local dev: build the dashboard in the pinned Node image and copy dist/ to
# orchestrator/wwwroot/ (git-ignored) so the orchestrator can run from disk.
set -euo pipefail
WEB="$(cd "$(dirname "$0")/.." && pwd)"
"$WEB/tools/node.sh" sh -c 'npm ci --ignore-scripts --no-audit --no-fund && npm run build'
rm -rf "$WEB/../wwwroot"
cp -r "$WEB/dist" "$WEB/../wwwroot"
echo "orchestrator/wwwroot refreshed from web/dist"
```

- [ ] **Step 4: Stop tracking the built output**

```bash
cd /c/Users/Administrator/Downloads/Audspect_Cloud
git status --porcelain
git rm orchestrator/wwwroot/index.html
printf '\n# G1c: build output of orchestrator/web (see web/tools/dev-build.sh)\n/orchestrator/wwwroot/\n' >> .gitignore
```

- [ ] **Step 5: CI — run G1 on the classifier view.** In the Go job's `G1 XSS sink regression guard` step, insert as the first line of `run:`:

```yaml
          python3 scripts/g1-assemble-classifier-view.py
```

and change its final unittest line to:

```yaml
          cd scripts && python3 -m unittest test_g1_merge_classification test_g1_check_no_regression test_g1_assemble_classifier_view -v
```

In the `web` job, delete the `Smoke harness (monolith baseline)` step (the monolith is no longer served); keep the `dist` smoke step.

- [ ] **Step 6: Regenerate the G1 baseline on the classifier view**

```bash
scripts/g1-run-local.sh
git diff --stat Assessment/
```
Expected: guard `PASS`; output may contain `REVIEW` lines (state rewrites) — read every one and confirm the new RHS is the same expression with `state.` added; list them in the commit message. Any `FAIL` stops the task: fix the cause.

- [ ] **Step 7: Verify the image end to end**

First add this test to `orchestrator/cmd/server/static_test.go` (skipped unless both env vars are set):

```go
func TestVerifyWWWRoot_ExtractedImage(t *testing.T) {
	dir, hash := os.Getenv("WWW_DIR"), os.Getenv("WWW_HASH")
	if dir == "" || hash == "" {
		t.Skip("set WWW_DIR and WWW_HASH to verify a wwwroot extracted from a built image")
	}
	if err := verifyWWWRoot(dir, hash); err != nil {
		t.Fatalf("extracted image wwwroot fails verification: %v", err)
	}
}
```

Then build the image, extract `/wwwroot`, and verify it against the hash the web stage printed:

```bash
cd /c/Users/Administrator/Downloads/Audspect_Cloud
SCRATCH="${TMPDIR:-/tmp}/g1c-www"
HASH=$(docker build -f orchestrator/Dockerfile --target web --progress=plain -t audspect-web-check . 2>&1 | sed -n 's/.*wwwroot manifest hash: \([0-9a-f]\{64\}\).*/\1/p' | tail -1)
echo "web stage manifest hash: $HASH"
docker build -f orchestrator/Dockerfile -t bas-orchestrator:g1c-check .
CID=$(docker create bas-orchestrator:g1c-check)
rm -rf "$SCRATCH" && docker cp "$CID:/wwwroot" "$SCRATCH" && docker rm "$CID"
sha256sum "$SCRATCH/MANIFEST.sha256"
cd orchestrator && WWW_DIR="$SCRATCH" WWW_HASH="$HASH" go test ./cmd/server -run TestVerifyWWWRoot_ExtractedImage -count=1 -v
```
Expected: a 64-hex hash is printed; the full image builds; `sha256sum` of the extracted manifest equals `$HASH`; the Go test prints `--- PASS: TestVerifyWWWRoot_ExtractedImage` (not SKIP).

- [ ] **Step 8: Commit and push**

```bash
chmod +x orchestrator/web/tools/dev-build.sh
git add orchestrator/Dockerfile packaging/windows-build.ps1 .github/workflows/test.yml .gitignore orchestrator/web/tools/dev-build.sh orchestrator/cmd/server/static_test.go Assessment/G1_INNERHTML_SINK_INVENTORY.csv Assessment/G1_INNERHTML_SINK_INVENTORY.json Assessment/G1_INDIRECT_SINK_TRACE.csv Assessment/G1_FINAL_CLASSIFICATION.json Assessment/G1_FINAL_CLASSIFICATION.csv
git commit -m "build: serve the bundled dashboard; manifest hash from the Docker web stage; G1 on the classifier view

<REVIEW lines from the guard, one per line>

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
git push
```
Note: `git rm` already staged the deletion. Confirm both CI jobs green on GitHub Actions.

---

### Task 9: Unit and XSS tests

**Files:**
- Create: `orchestrator/web/tests/unit/escape.test.mjs`, `orchestrator/web/tests/unit/xss.test.mjs`, `orchestrator/web/tests/unit/dom.mjs`

**Interfaces:**
- Consumes: generated module that exports `escapeHTML`, `x`, `initiativeStateLabel`, `openAdvDrawer` (in `src/legacy.js` now; tests import from `src/globals.js`'s `HANDLER_FUNCTIONS` or the owning module — use `tests/unit/dom.mjs`'s `load()` which resolves names through `HANDLER_FUNCTIONS` and the module namespace so the tests survive later extractions).
- Produces: `load(names: string[]) → Promise<Record<string, Function>>`, `setupDom() → JSDOM` (global `window`/`document` with `web/index.html` markup).

- [ ] **Step 1: Write `tests/unit/dom.mjs`**

```js
// Test helpers: a jsdom window with the real dashboard markup, and a lookup
// that finds an exported function in whichever module currently owns it, so
// tests do not change as Task 10 moves code between modules.
import { JSDOM } from 'jsdom';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const web = fileURLToPath(new URL('../..', import.meta.url));

export function setupDom() {
  const html = readFileSync(join(web, 'index.html'), 'utf8').replace(/<script src="[^"]*"><\/script>/, '');
  const dom = new JSDOM(html, { url: 'http://127.0.0.1/', pretendToBeVisual: true });
  for (const k of ['window', 'document', 'localStorage', 'navigator', 'HTMLElement', 'Node', 'Event', 'CustomEvent']) globalThis[k] = dom.window[k];
  return dom;
}

export async function load(names) {
  const files = [];
  (function walk(d) { for (const e of readdirSync(d)) { const p = join(d, e); if (statSync(p).isDirectory()) walk(p); else if (p.endsWith('.js')) files.push(p); } })(join(web, 'src'));
  const found = {};
  for (const f of files.sort()) {
    if (f.endsWith('main.js')) continue; // main.js runs load-time code
    const mod = await import(pathToFileURL(f).href);
    for (const n of names) if (typeof mod[n] === 'function' && !found[n]) found[n] = mod[n];
  }
  for (const n of names) if (!found[n]) throw new Error(`no module exports ${n}`);
  return found;
}

export const PAYLOADS = [
  '<img src=x onerror="globalThis.__xss=1">',
  '"><svg onload="globalThis.__xss=1">',
  "'><script>globalThis.__xss=1</script>",
  '</textarea><script>globalThis.__xss=1</script>',
];
```

- [ ] **Step 2: Write `tests/unit/escape.test.mjs`**

```js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { setupDom, load } from './dom.mjs';

setupDom();
const { escapeHTML, x } = await load(['escapeHTML', 'x']);

test('escapes & < > " and nothing else (G1a contract)', () => {
  assert.equal(escapeHTML(`&<>"'`), "&amp;&lt;&gt;&quot;'");
});
test('apostrophe is deliberately left raw', () => {
  assert.equal(escapeHTML("it's"), "it's");
});
test('x is an alias of escapeHTML', () => {
  for (const s of ['a&b', '<i>', '"q"', "o'k"]) assert.equal(x(s), escapeHTML(s));
});
test('null, undefined and numbers keep their current behavior', () => {
  for (const v of [null, undefined, 0, 42]) assert.equal(typeof escapeHTML(v), 'string');
  assert.equal(escapeHTML(42), '42');
});
```

Run: `cd orchestrator/web && tools/node.sh node --test tests/unit/escape.test.mjs`
Expected: 4 pass. If `null`/`undefined` assertions fail, read the real `escapeHTML` body and set the expectation to today's actual output (the contract is "unchanged", not a new behavior); ledger it.

- [ ] **Step 3: Write `tests/unit/xss.test.mjs`**

```js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { setupDom, load, PAYLOADS } from './dom.mjs';

setupDom();
const { initiativeStateLabel, openAdvDrawer, openFinding, renderRunReportExtra } =
  await load(['initiativeStateLabel', 'openAdvDrawer', 'openFinding', 'renderRunReportExtra']);
const tick = () => new Promise((r) => setTimeout(r, 0));

function assertInert(container, label) {
  assert.equal(container.querySelector('img,svg,script,iframe'), null, `${label}: payload created an element`);
  for (const el of container.querySelectorAll('*')) {
    for (const a of el.attributes) assert.ok(!/^on/i.test(a.name) || !/__xss/.test(a.value), `${label}: payload created ${a.name} on <${el.tagName}>`);
  }
  assert.equal(globalThis.__xss, undefined, `${label}: payload executed`);
}

test('initiativeStateLabel escapes unknown states', () => {
  for (const p of PAYLOADS) {
    const div = document.createElement('div');
    div.innerHTML = initiativeStateLabel(p);
    assertInert(div, 'initiativeStateLabel');
    assert.equal(div.textContent, p);
  }
});

test('openAdvDrawer: unknown adversary id and ability text stay inert', async () => {
  for (const p of PAYLOADS) {
    globalThis.fetch = async () => ({ status: 200, json: async () => ({ abilities: [{ name: p, description: p, tactic: 'discovery', platforms: [p] }] }) });
    openAdvDrawer(p);
    await tick(); await tick();
    assertInert(document.getElementById('adv-drawer'), 'openAdvDrawer');
  }
});

test('openFinding: finding fields stay inert in the results drawer', async () => {
  for (const p of PAYLOADS) {
    globalThis.fetch = async () => ({ status: 200, json: async () => ({ id: p, techniqueId: p, techniqueName: p, status: 'open', severity: p, enrichment: {} }) });
    openFinding(p);
    await tick(); await tick();
    assertInert(document.getElementById('results-overlay'), 'openFinding');
  }
});

test('renderRunReportExtra: attack-surface and restoration fields stay inert', () => {
  for (const p of PAYLOADS) {
    const div = document.createElement('div');
    div.innerHTML = renderRunReportExtra({
      attackSurfaceAge: 5, oldestFindingID: p, oldestFindingName: p, oldestFindingSeverity: p,
      envRestoration: { impactLevel: 'clean', statusLabel: p, impactLabel: p, cleanupRate: 100, stepsLeaked: 0, stepsCleaned: 1, execSummary: p },
    });
    assertInert(div, 'renderRunReportExtra');
    assert.ok(div.textContent.includes(p), 'payload text should be rendered as text');
  }
});
```

Run: `tools/node.sh node --test tests/unit/xss.test.mjs`
Expected: 4 pass. If `renderRunReportExtra` reads the restoration block from a different key than `envRestoration`, read the line `var envR = ...` in the function and use that key (ledger it). Then prove the tests bite: temporarily change `return x(state);` to `return state;` in `tools/monolith.html`, run `npm run split` and the test — Expected: FAIL `initiativeStateLabel: payload created an element`. Restore with `git checkout -- orchestrator/web/tools/monolith.html orchestrator/web/src/legacy.js orchestrator/web/tools/split-report.json` (named files only; run `git status --porcelain orchestrator/web` first and include any other file the regeneration touched) and rerun: pass.

- [ ] **Step 4: Run the whole unit suite and commit**

```bash
tools/node.sh sh -c 'npm test'
cd /c/Users/Administrator/Downloads/Audspect_Cloud
git add orchestrator/web/tests/unit/dom.mjs orchestrator/web/tests/unit/escape.test.mjs orchestrator/web/tests/unit/xss.test.mjs
git commit -m "test(web): escaper contract and malicious-payload regression tests

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
git push
```
Expected: all unit tests pass; CI green.

---

### Task 10: Extract core and feature modules — one row per commit

**Files:**
- Modify: `orchestrator/web/tools/modules.json` (one change per row)
- Regenerate + commit: `orchestrator/web/src/**`, `orchestrator/web/tools/split-report.json`, `Assessment/G1_*` (5 files)

**Interfaces:**
- Consumes: everything above. Module paths below are final and are what Task 9's `load()` resolves through.

**Per-row procedure (repeat exactly for every row; each row is its own commit):**

1. Edit `modules.json` as the row says (add the `sections` entries — `header` is the start of the `// ── ` title — or `pin` entries).
2. `cd orchestrator/web && tools/node.sh sh -c 'npm ci --ignore-scripts --no-audit --no-fund && npm run split && npx eslint src --max-warnings=100000 && npm test && npm run build'` → Expected: generator OK, 0 lint errors, all unit tests pass, build OK. A generator hard error (`initializer of "A" reads "B" from another module`) means the row must also move B's section (or pin B) — extend the row, ledger a Ruling.
3. Smoke: the Task 5 Step 8 command (`SMOKE_ROOT=dist`) → Expected: 1 passed.
4. `cd /c/Users/Administrator/Downloads/Audspect_Cloud && python3 scripts/g1c-check-globals.py && scripts/g1-run-local.sh` → Expected: registry OK; guard PASS. Read every REVIEW line; each must be the same expression with `state.` added.
5. Commit only `orchestrator/web/tools/modules.json`, `orchestrator/web/tools/split-report.json`, the changed/new files under `orchestrator/web/src/` (list them with `git status --porcelain orchestrator/web/src`), and the 5 `Assessment/G1_*` files; message `refactor(web): extract <module> (verbatim)` + REVIEW lines + Co-Authored-By; push; confirm CI green.
6. If any check fails and the cause is not found within the row, revert that row's `modules.json` change, regenerate, and record the failure in the ledger; continue with the next row.

**Rows (in this order — core first, then smallest features first):**

- [ ] **10.1 core/escape.js** — `pin`: `"escapeHTML": "core/escape.js"`, `"x": "core/escape.js"`
- [ ] **10.2 core/api.js** — `pin`: `"apicall": "core/api.js"`
- [ ] **10.3 core/util.js** — `pin`: `"ago": "core/util.js"`, `"daysAgo": "core/util.js"`, `"fmtDate": "core/util.js"`, `"fmtRunIdCode": "core/util.js"`, `"showToast": "core/util.js"`
- [ ] **10.4 features/shell.js** — `"preamble": "features/shell.js"`; `sections`: `Profile avatar + dropdown`, `Tamper Alert Banner`
- [ ] **10.5 features/agent-actions.js** — `Stop Agent`, `Uninstall Agent`, `Remove Agent (Force Remove)`
- [ ] **10.6 features/variant-executor.js** — `Variant Executor`
- [ ] **10.7 features/compliance.js** — `Compliance score tiles`, `Generic config-save confirmation`
- [ ] **10.8 features/audit-logs.js** — `Audit Logs`
- [ ] **10.9 features/threat-intel.js** — `Threat Intel connector config`, `TAXII Connectors`
- [ ] **10.10 features/iocs.js** — `Indicators (IOCs) tab`, `IOC Registry`
- [ ] **10.11 features/rerun-review.js** — `Re-run Review`
- [ ] **10.12 features/initiatives.js** — `Initiative Layer`
- [ ] **10.13 features/detection-verification.js** — `Detection Verification (SP2)`
- [ ] **10.14 features/coverage.js** — `ATT&CK Coverage`, `Coverage Analytics`, `Unified Technique Library`
- [ ] **10.15 features/adversaries.js** — `Threat Actor Library`, `Adversary Templates`
- [ ] **10.16 features/campaigns.js** — `Campaigns`, `Campaign Source`, `Threat-Informed Campaign Builder`
- [ ] **10.17 features/findings.js** — `Findings`, `Remediation`, `Ticketing`, `Dashboard ITSM widget`, `Findings ticket actions`, `Findings bulk select`, `Remediation bulk tickets`
- [ ] **10.18 features/integrations.js** — `Integrations tab`, `EPP Response Connectors`, `Respond (EPP response actions`
- [ ] **10.19 features/ransomware.js** — `Ransomware Readiness Module`
- [ ] **10.20 features/live-run.js** — `Live Run Panel`
- [ ] **10.21 features/agent-drawer.js** — `Agent Detail Drawer`, `Overview tab`, `Scenarios tab`, `Logs tab`, `Health tab`, `Risk tab`, `Attack Path tab`
- [ ] **10.22 features/scheduled.js** — `Scheduled Assessments`
- [ ] **10.23 features/endpoint-mastery.js** — `Endpoint Mastery`, `Endpoint Mastery Full Sweep`, `Full Sweep Preview & Confirm`
- [ ] **10.24 features/openaev.js** — `OpenAEV Connector`
- [ ] **10.25 features/attack-path.js** — `Attack Path Validation`, `Attack Path Collection`
- [ ] **10.26 features/variant-report.js** — `Variant Coverage Report rendering`
- [ ] **10.27 features/variants.js** — `Run Variants reload-survival`
- [ ] **10.28 features/evidence.js** — `Evidence Panel`
- [ ] **10.29 features/reports.js** — `Reports`

Note on header matching: `moduleOf` matches `section.startsWith(header)`; headers that are prefixes of others (`Endpoint Mastery` vs `Endpoint Mastery Full Sweep`) are resolved by `cfg.sections.find`, which returns the **first** match — so in rows with such pairs, list the **longer** header first in `modules.json`.

After 10.29, `src/legacy.js` must not exist (no chunk maps to `default`). If it still does, the remaining chunks are listed in it; map them in a final row `10.30` to the module whose section they belong to.

---

### Task 11: Modularization exit — retire the generator

**Files:**
- Delete: `orchestrator/web/tools/monolith.html`, `orchestrator/web/tools/split.mjs`, `orchestrator/web/tools/analyze.mjs`, `orchestrator/web/tools/modules.json`, `orchestrator/web/tools/split-report.json`, `orchestrator/web/tests/unit/split.test.mjs`
- Modify: `orchestrator/web/package.json` (drop `split`, `split:check`), `.github/workflows/test.yml` (drop the `split:check` step), generated headers in `src/**` (replace the `GENERATED ... do not edit during G1c` first line with nothing)
- Create: `orchestrator/web/README.md`

- [ ] **Step 1: Verify the seven modularization exit criteria with evidence** (spec §12), capturing each command's output into the ledger:
  1. `ls orchestrator/web/src orchestrator/web/src/core orchestrator/web/src/features` — source present.
  2. `grep -c '<script>' orchestrator/web/index.html` → `0`; `grep -c '<style>' orchestrator/web/index.html` → `0`.
  3. `test ! -f orchestrator/web/src/legacy.js && echo no-legacy` → `no-legacy`.
  4. `npx eslint src` → 0 errors.
  5. `python3 scripts/g1c-check-globals.py` → OK; `grep -rn "window\.[A-Za-z_$]* *=" orchestrator/web/src --include=*.js | grep -v globals.js` lists only `WINDOW_WRITES` names.
  6. `go test ./cmd/server -run 'VerifyWWWRoot|WWWRootWatchList' -count=1` → ok, plus Task 8 Step 7's extracted-image check re-run on the current HEAD.
  7. Latest CI run: G1 step green on the classifier view.

- [ ] **Step 2: Remove the generator and freeze markers**

```bash
cd /c/Users/Administrator/Downloads/Audspect_Cloud
git rm orchestrator/web/tools/monolith.html orchestrator/web/tools/split.mjs orchestrator/web/tools/analyze.mjs orchestrator/web/tools/modules.json orchestrator/web/tools/split-report.json orchestrator/web/tests/unit/split.test.mjs
cd orchestrator/web && for f in $(grep -rl '^// GENERATED by web/tools/split.mjs' src); do sed -i '1{/^\/\/ GENERATED by web\/tools\/split.mjs/d}' "$f"; done
```
Edit `package.json` to remove the two `split` scripts and `.github/workflows/test.yml` to remove the `Generated sources match the generator` step.

- [ ] **Step 3: Write `orchestrator/web/README.md`**

```markdown
# Audspect dashboard (orchestrator/web)

Source for the dashboard served from `/wwwroot` in the orchestrator image.

- `index.html` — markup only; the build injects the hashed CSS/JS names.
- `styles/app.css` — all styles.
- `src/main.js` — entry: `installGlobals()`, then the load-time `__init_L*` functions in their original order.
- `src/globals.js` — the only place app names are defined on `window`. Every function called from an inline `on…=` handler must be listed in `HANDLER_FUNCTIONS`; CI (`scripts/g1c-check-globals.py`) fails on missing or stale entries. This list is the G1d (strict CSP) worklist: it shrinks as handlers move to event listeners.
- `src/core/` — escaper (`escape.js`), API helper (`api.js`), shared formatting (`util.js`), shared mutable state (`state.js`).
- `src/features/` — one module per dashboard area.

Build and test only inside the pinned images (Node is never installed on the host):

    tools/node.sh sh -c 'npm ci --ignore-scripts && npm test && npm run build'
    tools/dev-build.sh            # refreshes orchestrator/wwwroot for local runs
    scripts/g1-run-local.sh       # G1 XSS guard on the classifier view (repo root)

Integrity: the build writes `dist/MANIFEST.sha256`; the Docker build compiles its SHA-256 into the orchestrator, which refuses to start if any served file differs, is missing, or is unlisted.
```

- [ ] **Step 4: Run everything once more, commit and push**

```bash
cd orchestrator/web && tools/node.sh sh -c 'npm ci --ignore-scripts --no-audit --no-fund && npx eslint src && npm test && npm run build'
cd /c/Users/Administrator/Downloads/Audspect_Cloud && python3 scripts/g1c-check-globals.py && scripts/g1-run-local.sh
git add orchestrator/web/package.json orchestrator/web/README.md .github/workflows/test.yml $(git -C . diff --name-only -- orchestrator/web/src)
git commit -m "chore(web): G1c modularization exit -- retire the generator; web/src is hand-maintained source

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
git push
```
Expected: both CI jobs green. G1c is closed on this commit (modularization exit).

---

### Task 12: Release / QA acceptance (gates shipping, not G1c closure)

- [ ] **Step 1:** Latest CI: unit + XSS tests pass; Playwright smoke passes with no errors beyond `baseline.json`.
- [ ] **Step 2:** Build a release with `packaging/windows-build.ps1` and deploy to a real environment with `install.sh` (never raw `docker compose` for client prod). Confirm the orchestrator log shows `wwwroot integrity: manifest and every listed file verified`.
- [ ] **Step 3:** Manual QA checklist, each with a screenshot or note in the ledger: log in; open every sidebar tab; run a scenario on one agent and watch the Live Run panel; view and download a report (PDF logo renders); enroll an agent; edit and save one setting; open a finding drawer; use Run modal Group(s) mode (checkbox selection updates the summary — Review Focus 2).
- [ ] **Step 4:** Tamper test on that deployment: edit one byte of `/wwwroot/assets/app.*.js` inside the container — the integrity watcher raises a tamper event within ~15 s; restart — the orchestrator refuses to start. Redeploy afterwards.
- [ ] **Step 5:** Record the result in `project_group_g_xss_sink_audit` memory and the vault.
