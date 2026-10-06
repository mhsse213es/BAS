# G1c — Frontend Modularization & Build — Design

**Status:** approved in brainstorming 2026-10-05, pending written-spec review
**Group:** G (frontend XSS surface), see `groupG.txt`
**Depends on:** G1a (done), G1b (done, `fe1cc218`; CI green at `41a5f95e`)
**Unblocks:** G1d (strict nonce/hash-based CSP)

## 1. Purpose

`orchestrator/wwwroot/index.html` is a 22,324-line, 1.35 MB single-file SPA:
one `<style>` block (lines 11–1321), markup (1322–5160), one `<script>`
block (5161–22322) holding 748 top-level functions and 194 top-level
`let`/`const`/`var`. It has no build step, no tests, and no lint.

G1c splits it into real ES modules with a build, a controlled global
boundary, full integrity coverage and a test harness, **without changing
dashboard behavior**. Its security purpose is to make the frontend testable
and to make G1d (strict CSP) achievable; it is not itself a CSP change.

Per `groupG.txt`: no rewrite. Code moves verbatim; only references change.

## 2. Key architectural decision: G1b is independent of G1c

**G1b remains valid before, during, and after G1c, because its input is a
deterministic classifier view, not the production `wwwroot/index.html`.**

```
            web/ source tree
           /                \
  G1 classifier view      esbuild (Docker build stage)
  (CI analysis artifact)          |
           |               shipped wwwroot/ assets
  G1 classifier, tracer,
  merge, guard  (= G1b)
```

- The classifier view is a **CI analysis artifact**, not application build
  output. The production build never reads it, and G1b never reads the
  production build.
- G1c is **not** a prerequisite for G1b closure. G1b is closed and stays
  closed; G1c only changes where G1b's input is assembled from.

## 3. Scope

**In G1c:**
- Source tree, ES-module split, esbuild build in Docker.
- `globals.js` controlled global boundary + registry check.
- Integrity manifest covering every served file.
- Classifier-view assembly so G1b keeps working.
- ESLint, unit/XSS tests, Playwright smoke harness, CI `web` job.

**Deferred to G1d (explicitly not touched here):**
- The CSP header itself, and `X-Content-Type-Options: nosniff`.
- The ~600 inline `on…=` handlers and ~2,500 `style=` attributes.
- Self-hosting Google Fonts (`fonts.googleapis.com`), needed for both
  air-gapped installs and CSP.

**Out of scope:** UI or behavior changes of any kind; fixing pre-existing
console errors (they are recorded in the baseline, §8, and listed for later).

## 4. Source layout

```
orchestrator/web/
  index.html            markup + bootstrap only (today's lines 1322–5160),
                        links the built app.<hash>.css / app.<hash>.js
  styles/app.css        today's <style> block, verbatim
  src/main.js           entry: imports all modules, then runs today's 10
                        load-time statements in their original order
  src/globals.js        the ONLY code that writes to window (§6)
  src/core/escape.js    escapeHTML / x — the single canonical escaper
  src/core/api.js       fetch / auth helpers
  src/core/state.js     shared mutable state (exported `state` object)
  src/core/util.js      shared formatting helpers
  src/features/*.js     ~20 modules, one per existing `// ── Section ──` block
  package.json, package-lock.json
  images/               logo.png, logo_name.png (paths unchanged)
```

`orchestrator/wwwroot/` becomes build output only and is git-ignored.

## 5. Module rules

1. **Verbatim moves.** A function moves unchanged; only `import` lines are
   added and shared variables become `state.<name>`. No refactoring or
   "improvements" during a move.
2. **Shared state.** An exported `let` cannot be reassigned by importers, so
   top-level variables used by more than one section move onto the single
   exported `state` object (`currentRun = r` → `state.currentRun = r`).
   Variables used by one section stay module-private.
3. **No work at module load.** Feature modules contain declarations only.
   All load-time statements live in `main.js` and run after every import, in
   today's order. This makes circular imports between features harmless and
   load order irrelevant.
4. **Placement.** Anything used by more than one section goes in `core/`;
   otherwise it lives in its section's feature module.

## 6. Global boundary and registry check

- `src/globals.js` is one explicit, alphabetized
  `Object.assign(window, { … })`. It replaces all implicit globals and the
  existing ad-hoc `window.<name> = …` assignments (e.g. `openRunPanel`).
  Today the inline handlers reference 348 distinct app functions.
- A separate `dynamicHandlers` list holds names a static scan cannot see
  (handler function names taken from variables, e.g. `_sweepRowHtml`'s
  `drilldownFn`), each with a comment naming its caller.
- **Registry check** (`scripts/g1c-check-globals.py`, Python stdlib):
  extracts every called name from every inline handler — in `index.html`
  markup and inside JS string literals — and fails CI if:
  - a handler calls a name not in the registry (**missing**), or
  - a registry name is no longer called by any handler and is not in
    `dynamicHandlers` (**stale**).
  The registry is therefore an honest, shrinking worklist for G1d.

## 7. Build and integrity

**Build (Dockerfile, new first stage):** Node image pinned **by digest**;
`npm ci --ignore-scripts` from the lockfile only; esbuild bundles
`src/main.js` → `assets/app.<contenthash>.js` (IIFE, unminified, ES2020)
and emits `assets/app.<contenthash>.css`; writes `wwwroot/`. The Go stage
copies `wwwroot/` from this stage. Node never reaches the shipped image or
the Windows host. The CI `web` job runs the **same lockfile and the same
build command** as the Docker stage (one shared `npm run build` script).

Unminified on purpose: names inline handlers depend on stay readable,
stack traces stay usable, and 1.3 MB on a LAN is not a concern.

**Integrity manifest.** The build stage writes `wwwroot/MANIFEST.sha256`
(sorted `sha256  path` lines for every emitted file). The Go stage computes
the manifest's SHA-256 and compiles it in via `-ldflags -X` (replacing
today's single-file `BAS_WWWROOT_HASH`; `windows-build.ps1` stops hashing
on the host). At startup `StaticHandler` halts unless:
1. the manifest hash matches the compiled-in value,
2. every listed file exists with a matching hash, and
3. no unlisted file exists under `wwwroot/`.

The runtime integrity watcher covers every manifest file (today it watches
only `index.html`). A Go binary built outside Docker (local dev) has no
compiled-in hash; its check stays disabled and logs that, as today.

**Serving.** `/assets/*`: `Cache-Control: public, max-age=31536000,
immutable` (names change with content). `index.html`: `no-cache`, so an
upgrade never pairs an old page with a new bundle. All same-origin.

**Local dev.** A script runs the same build in a throwaway Node container
and writes `wwwroot/`, so running the orchestrator from disk still works.

## 8. G1b classifier view

- `scripts/g1-assemble-classifier-view.py` (stdlib) concatenates
  `web/index.html` markup, `<script>`, every `src/**/*.js` in sorted path
  order, and `</script>`, deterministically (same input → byte-identical
  output, LF line endings).
- The classifier reads a hard-coded path (`orchestrator/wwwroot/index.html`).
  The assembler only writes the view there. In CI the workspace has no built
  `wwwroot/`, so the G1 step simply assembles and then runs the scripts.
  Locally, `scripts/g1-run-local.sh` moves any built `wwwroot/index.html`
  aside, assembles the view, runs the G1 pipeline, and restores the original
  file (also on failure). The three proven G1 scripts (classifier, tracer,
  merge) are **not modified**.
- The escaper check runs on the same view and still requires exactly one
  escaper-like function (now in `core/escape.js`).
- **Visibility of changed expressions.** `scripts/g1-check-no-regression.py`
  (the G1b guard, not one of the proven scripts) gains one non-failing
  report category: **same slot (function/target/op), RHS changed,
  classification unchanged → REVIEW**. A changed RHS can change data
  provenance (e.g. an internally generated value becoming user-controlled
  state) even when the tier is identical, so it must be shown to the
  reviewer, not silently treated as churn. Tier increases still fail as
  today.
- The G1 baseline is regenerated in the same commit as each extraction, so
  every commit carries its own sink diff for review.

## 9. Tests and harness

**Lint (ESLint):** `no-undef` with browser globals only — proves every
cross-module reference is imported, so the split is complete. Also
`no-eval`, `no-implied-eval`, `no-new-func`; `no-restricted-properties` on
`innerHTML`/`outerHTML`/`insertAdjacentHTML`/`document.write` as
report-only (G1b already gates `innerHTML`).

**Unit and XSS tests** (`node:test` + `jsdom`, importing modules directly):
- `core/escape.js`: `&<>"` escaped, `'` deliberately not (G1a contract);
  `null`/`undefined`/number behavior unchanged.
- Malicious-payload tests on real render functions, starting with those G1a
  fixed (`openFinding`, `renderRunReportExtra`, `openAdvDrawer`, …):
  payloads `<img src=x onerror=…>`, `"><svg onload=…>`,
  `</textarea><script>`, `javascript:` URLs. The rendered DOM must contain
  no element or attribute created by the payload.

**Playwright smoke harness:**
- Serves built `wwwroot/`; intercepts every `/api/*` with fixtures:
  empty-but-valid shapes by default, populated fixtures (including payload
  strings) for Dashboard, Runs, Agents, Findings, Campaigns, Coverage.
- Logs in via stubbed auth, opens every tab and drawer reachable from the
  nav, and records: uncaught/console errors; inline handlers in the rendered
  DOM whose function is not on `window`; whether any payload executed
  (sentinel tripped by `alert`/`onerror`).
- **Baseline first:** the harness runs against today's monolithic
  `index.html` before any code moves; existing errors become the baseline.
  Afterwards, any new error or unresolved handler fails.
- **Browser provisioning is explicit, never via package lifecycle scripts**
  (which `--ignore-scripts` disables). The harness runs in the official
  Playwright image pinned by digest, whose bundled browsers match the pinned
  `@playwright/test` version; a CI step asserts the two versions match and
  fails otherwise. No browser is downloaded implicitly at test time.

**Known limit:** stubbed APIs prove loading, navigation and wiring, not
every real data flow. Covered by verbatim moves, one section per commit,
and the manual QA pass (§11).

## 10. CI

- **New `web` job:** `npm ci --ignore-scripts` → ESLint → registry check →
  unit/XSS tests → `npm run build` → Playwright smoke (in the pinned
  Playwright image). Failure uploads screenshots and console logs.
- **Existing Go job:** unchanged except its G1 step first runs
  `g1-assemble-classifier-view.py`.
- **Supply chain:** exact versions; lockfile only; `--ignore-scripts`; four
  direct dev dependencies (`esbuild`, `eslint`, `jsdom`,
  `@playwright/test`); nothing from npm ships except esbuild's output of our
  own code. Air-gapped installs receive a prebuilt image and are unaffected.

## 11. Migration order

1. Record the Playwright baseline against today's monolith.
2. Scaffold `web/`, build stage, manifest integrity, classifier-view
   assembler, registry check, CI `web` job — with the script still a single
   module (behavior identical).
3. Extract `core/` and `state`.
4. Extract feature modules one per commit, smallest first. Each commit:
   lint, registry check, G1 guard (with regenerated baseline), unit tests
   and smoke harness all green. A failing extraction is reverted alone.

## 12. Exit criteria

**G1c modularization exit (closes G1c):**
1. `web/` contains the source.
2. `index.html` contains markup/bootstrap only.
3. Every feature section is its own module.
4. ESLint `no-undef` is clean.
5. `globals.js` is the controlled global boundary; registry check green
   (missing and stale).
6. Integrity coverage is complete: manifest verified at startup and watched
   at runtime for every served file.
7. The CI G1 classifier/guard passes against the assembled view.

**Release / QA acceptance (separate; gates shipping, not G1c closure):**
1. Unit and XSS tests pass.
2. Playwright smoke passes with no console errors beyond the documented
   baseline.
3. Manual QA succeeds on a real deployment: run a scenario, view and
   download a report, enroll an agent, edit settings.

## 13. Risks

| Risk | Mitigation |
|---|---|
| Missed import breaks a button | `no-undef` lint fails the build |
| Handler name not exported to window | Registry check (static) + harness (dynamic) |
| Shared-state rewrite (`state.x`) changes behavior | Verbatim moves, per-commit harness, G1 REVIEW output for changed RHS |
| Load-order change | No work at module load; `main.js` preserves order |
| Tamper detection weakened by split | Manifest covers every file; unlisted files fail startup |
| npm supply chain | Build-only, pinned, lockfile, `--ignore-scripts`, 4 deps |
| Classifier view drifts from shipped code | Both derive from the same `web/` source in the same commit |
