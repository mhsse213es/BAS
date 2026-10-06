# G1e — Strict style CSP: remove inline styles without changing presentation

**Status:** approved design (2026-10-06), implementation starts after G1d's final whole-branch review closes.
**Group:** G (frontend XSS surface) — G1e is the last open item. G1a/G1b/G1c done, G2 closed, G1d in progress.
**Predecessor:** `docs/superpowers/specs/2026-10-05-g1d-strict-csp-design.md` (ships `style-src 'self' 'unsafe-inline'` as a staged item; this spec removes `'unsafe-inline'`).

## 1. Goal and contract

Serve the dashboard with `style-src 'self'` — no `'unsafe-inline'`, no `'unsafe-hashes'` — by moving every static inline style into stylesheet classes and every data-driven style value into validated CSS custom properties.

**Contract: G1e may change implementation, but must not intentionally change rendered appearance.** It is a mechanical security migration, not a redesign. No spacing normalization, typography or colour cleanup, "close enough" values, or component redesign.

## 2. Decisions

| Decision | Choice |
|---|---|
| Fidelity | Pixel-identical, proven: deterministic dual-build screenshot diff (threshold 0) plus computed-style comparison; explicit allowlist with a reason per entry for unavoidable noise |
| Static styles | Codemod to deterministic generated classes `g1-s-<hash>`, declarations copied verbatim, never normalized or merged |
| Cascade | Existing `app.css` wrapped in `@layer app`; generated rules unlayered so they outrank it the way inline styles did; JS `el.style.*` stays inline and still wins |
| Initially hidden elements | `is-hidden` class; the 82 `el.style.display = ''` reveal sites become `classList.remove('is-hidden')`; explicit committed inventory |
| Data-driven values | Literal either/or choices → two generated classes; real data → allowlisted, typed CSS custom properties applied by a trusted hydrator via `setProperty`; no generic set-any-style helper |
| CSSOM writes (`el.style.x = …`, 400 sites; `.style.cssText`, 5) | Unchanged — CSP does not govern CSSOM; they are behaviour, not static presentation |
| Rejected | Hand-written semantic classes (redesign by another name); `'unsafe-hashes'` + ~1,300 hashes (cannot cover data-driven values, still allows inline styles); copying `style` into a data attribute and re-applying it from JS (restores arbitrary CSS for any injected element — CSP-washing) |

## 3. Inventory (2026-10-06, post-G1c tree)

| What | Count |
|---|---|
| `style="…"` in static markup (`orchestrator/web/index.html`) | 1,072 (515 distinct values) |
| `style=` built in JS templates (`orchestrator/web/src/features/*.js`) | 1,443 — 1,190 literal, 253 data-driven |
| Distinct literal values, markup + templates | 1,225 (892 used once) |
| Template tags that already carry `class=` before `style=` | 316 |
| `<style>` elements, `setAttribute('style', …)` | 0, 0 |
| `el.style.display = ''` (reveal sites) | 82 |
| `el.style.display = '<literal>'` / `= <expression>` | 136 / 89 |
| `removeAttribute('style')` | 1 |
| `!important` in `app.css`; in inline styles | 11; 0 |
| `@layer` in `app.css` | 0 |

Template styles by module (top): reports 226, variant-report 205, agent-drawer 127, evidence 102, attack-path 90, endpoint-mastery 74, variants 70, openaev 60, adversaries 59, detection-verification 59, campaigns 56.

Data-driven declarations by kind: `color` ~144 (mostly computed hex such as `col` or `col + '22'` alpha suffix, some `var(--token)`), `background` ~42 (same shapes, plus one `conic-gradient(<color> <pct>%, …)`), `width` 22 (percentages), `border*` ~34 (`<n>px solid <color>`), one `grid-template-columns: repeat(<n>,1fr)`, and ~10 literal either/or choices (`font-weight`, `cursor`, `opacity`, `display`, `text-decoration`, `padding-bottom`).

## 4. Architecture

### 4.1 Generated classes (static styles)

A one-time codemod, `orchestrator/web/tools/g1e-codemod.mjs` (deleted at exit), converts each literal `style="<text>"`:

- **Class name:** `g1-s-<h>`, `<h>` = first 8 hex chars of SHA-256 of `<text>` exactly as written (trimmed of surrounding whitespace only). Identical text → same class. A collision (same `<h>`, different text) fails the run.
- **Rules:** written to `orchestrator/web/styles/inline-equivalent.css`, one rule per class, declarations copied verbatim, rules ordered by class name — reproducible byte for byte.
- **Placement:** if the tag already has a literal `class="…"`, the generated class is appended to it (never a second `class` attribute — the HTML parser ignores duplicates). If the existing class is built dynamically, or the style mixes literal and dynamic parts the codemod cannot split safely, the site is reported for hand conversion, never guessed.
- **Exclusion:** `display:none` (alone or within a style) is never converted by the codemod; those elements go through §4.3.

After migration `inline-equivalent.css` is ordinary hand-maintained source.

### 4.2 Cascade

- `styles/app.css` is wrapped in `@layer app { … }`. `inline-equivalent.css` is bundled after it, unlayered.
- Normal declarations: unlayered rules beat any layered rule regardless of specificity — the same position inline styles held. JS `el.style.*` writes are inline and beat both, exactly as today.
- `!important`: layer order reverses for important declarations. Inline styles have no `!important` today, so a layered `!important` rule in `app.css` beat the inline value before and still beats the generated class after. Each of the 11 `!important` rules is nevertheless verified by the computed-style comparison (§5), not by this reasoning alone; any difference is fixed at that rule and recorded.
- Requirement: **generated styling must reproduce the computed style of the pre-migration application** — not merely "have higher specificity".

### 4.3 Initially hidden elements and reveal sites

- Elements whose inline style contains `display:none` get class `is-hidden` (`.is-hidden { display: none; }` in `inline-equivalent.css`); any other declarations in the same style go through §4.1.
- Every `el.style.display = ''` that reveals such an element becomes `el.classList.remove('is-hidden')`; the matching hide writes (`= 'none'`) on those elements become `classList.add('is-hidden')`. After migration, `el.style.display = ''` is not used as a reveal mechanism.
- The 89 expression-driven writes (`el.style.display = cond ? … : …`) are classified one by one: those that toggle an `is-hidden` element become `classList.toggle('is-hidden', !cond)`; those on elements never hidden by inline style are left as CSSOM writes.
- **Inventory:** `docs/superpowers/specs/g1e-reveal-inventory.md` lists every reveal, hide and expression site (file:line, element id or selector, before → after), committed before Phase 1 and checked off in the commits that convert each site. It stays auditable after G1e.

### 4.4 Data-driven values

- **Literal either/or choices** (`compatible ? 'pointer' : 'not-allowed'`): both branches become generated classes and the template selects the class (`(compatible ? 'g1-s-…' : 'g1-s-…')`).
- **Real data** (colours, percentages, counts): CSS custom properties.
  - Template helper `cssVars({ '--g1-…': value, … })` in `src/core/css-vars.js` returns ` data-css-vars="<escaped JSON object>"` (same escaping model as G1d's `on()`).
  - The consuming rule lives in `inline-equivalent.css`, e.g. `.g1-v-bar { width: var(--g1-pct); }`, `.g1-v-tone { color: var(--g1-color); }`.
  - **Typed registry** (in `css-vars.js`): each `--g1-*` name declares one type. Types and accepted values:
    - `color`: `#` + 3, 4, 6 or 8 hex digits; `var(--<token>)` where token is `[a-z0-9-]+`; `rgb(`/`rgba(` with numeric arguments only.
    - `percent`: a number 0–100 followed by `%`.
    - `integer`: 1–24.
    Composite values (e.g. `1px solid <color>`, `conic-gradient(<color> <pct>%, var(--elevated) 0%)`) keep their literal parts in the rule and take only the variable parts from typed variables.
  - **Hydrator:** `installCssVars(root = document)` applies `data-css-vars` with `el.style.setProperty(name, value)` for registered names whose value matches the type; anything else is dropped and logged with `console.error` (no exception, no partial CSS). It runs once at boot and through a `MutationObserver` on `document.body` (childList, subtree, and `data-css-vars` attribute changes) that queries only added subtrees. Mutation callbacks run as microtasks, before the next paint.
  - There is no generic `setStyle(el, property, value)` helper; nothing applies arbitrary properties or arbitrary values.
- Static markup has no data-driven styles, so no hydration is needed for first paint.

### 4.5 Policy change (exit)

`dashboardCSP` in `orchestrator/cmd/server/static.go` and `orchestrator/web/tests/smoke/csp-policy.txt` change only `style-src 'self' 'unsafe-inline'` → `style-src 'self'`. `TestDashboardCSP_ScriptSrcIsStrict` (G1d) gains the same exact-value pin for `style-src`. `BAS_CSP_MODE` (enforce / report-only) and `/api/csp-report` are unchanged.

## 5. Verification harness (Phases 0–3)

- **Dual-build comparison.** In the pinned Playwright container, build the baseline tree (a `git worktree` of the G1d end commit, recorded in the plan) and HEAD; serve both with the same current fixtures; compare per checkpoint. No screenshots or baselines are committed.
- **Determinism:** fixed viewport 1440×900; `page.clock` frozen at a fixed instant; screenshots with `animations: 'disabled'` and hidden caret; self-hosted fonts and `document.fonts.ready`; live WebSocket kept silent (as the smoke harness does); network idle before each checkpoint.
- **Checkpoints:** every tab (25), every drawer in the smoke drawer list, and one checkpoint per reveal state reachable under fixtures.
- **Fixtures are extended before the baseline is built** so every data-driven style renders: each verdict and severity colour, non-trivial progress widths, the risk dial, the n-column grid, and paused/active states.
- **Computed-style comparison:** for every element, `getComputedStyle` values for every property that occurs in any inline style in the inventory (~80), keyed by structural path from `body` (tag + child index). G1e changes attributes, not structure, so paths match one-to-one; a structural mismatch is itself a failure. Any difference fails with element path, property, baseline value, HEAD value.
- **Screenshot comparison:** full-page per checkpoint, `maxDiffPixels: 0`.
- **Allowlist:** `orchestrator/web/tests/visual/g1e-visual-allowlist.json` — entries `{checkpoint, path | region, property?, reason}`; an entry without a reason is rejected; CI prints every allowlisted difference. Target: empty; entries only for unavoidable rendering noise, each approved explicitly.
- **Lifetime:** required in CI on every G1e commit; retired at exit (later UI work changes appearance on purpose). Source-level checks (§6) stay.

## 6. Source-level checks (permanent)

- `scripts/g1d-check-actions.py` ratchet gains `inline_styles`: count of `style=` attributes in `index.html` and in JS string/template literals, plus `<style` in strings. It may only go down; it must reach 0 at exit.
- Consistency (same script): every `g1-s-*`/`g1-v-*` class used in markup or templates exists in `inline-equivalent.css`, and every rule there is used (no orphans); every `--g1-*` name passed to `cssVars()` is in the typed registry; `data-css-vars` appears in source only via `cssVars()`.
- ESLint (`no-restricted-syntax`, error): `style=` and `<style` in string and template literals; `setAttribute('style', …)`; literal `data-css-vars`.
- `el.style.x = …` remains allowed.

## 7. Phases

G1e starts after G1d's final review closes; the G1d end commit is the visual baseline.

0. **Foundation (no visual change):** dual-build harness + harness self-test; fixture extension; `core/css-vars.js` (registry, `cssVars()`, hydrator) with tests; `app.css` → `@layer app`; empty `inline-equivalent.css` wired into the build. The harness must show zero difference; the 11 `!important` rules are checked here in isolation.
1. **Reveal sites:** `is-hidden`, the 82 reveal sites and their hide counterparts, the 89 expression sites classified; inventory committed first and checked off per commit.
2. **Static markup:** codemod over `index.html` (1,072); its reported sites converted by hand in the same phase.
3. **Templates:** one module per commit, smallest first; codemod for literal styles and class merging; hand conversion of either/or choices and `cssVars()` for data. `reports.js` and `variant-report.js` may span several commits. Every commit passes both comparisons.
4. **Exit:** `style-src 'self'` (§4.5); smoke (tabs + drawers) under the enforced policy with zero violations; ratchet at 0; harness, codemod and inventory tooling retired (the inventory document stays).

## 8. Testing

- `core/css-vars.js` unit tests: valid and boundary values per type (`#abc`, `#rrggbb22`, `var(--token)`, `0%`, `100%`, 1, 24); hostile values dropped and logged (`red;background:url(x)`, `expression(…)`, `url(…)`, `var(--x) !important`, `101%`, `-1%`, `25`, very long strings); unregistered names dropped; `cssVars()` output inert through `innerHTML` (one element, exact attributes, JSON round-trip).
- Codemod unit tests: declaration text preserved byte for byte; identical text → same class; hash collision fails; merge into an existing literal `class`; dynamic `class` or unsplittable mixed style reported; `display:none` never converted.
- Harness self-test: a planted 1px margin change fails the screenshot diff; a planted `font-weight` change fails the computed-style diff naming the element and property.
- Smoke: both tests under `SMOKE_CSP=enforce` with zero `csp:` errors at exit.

## 9. Exit criteria

1. Generated stylesheet deterministic: rerunning the codemod on the pre-G1e source reproduces `inline-equivalent.css` byte for byte (checked once at the end of Phase 3, before the codemod is deleted).
2. No prohibited static inline styles: `inline_styles` ratchet 0; ESLint bans active.
3. All 82 reveal transitions preserved: inventory fully checked off; every reachable reveal state has a harness checkpoint.
4. Data-driven variables validated (unit tests).
5. Computed-style comparison passes on every checkpoint.
6. Visual comparison passes; allowlist empty or user-approved entries only.
7. Served policy has `style-src 'self'`, pinned by the Go test; enforced smoke shows zero violations.

Release QA (staging, user-run, separate from exit): every tab with DevTools open shows no CSP errors; report-only mode still logs violations.

## 10. Risks

- **Hydrator cost:** observer callbacks query only added subtrees for `[data-css-vars]`.
- **Flash of unstyled content:** none for static markup (no data-driven values); template values are applied in the mutation microtask, before paint.
- **Dynamic `class` attributes hiding a missing class:** the codemod reports them instead of guessing; the harness catches anything missed.
- **`!important` interplay with layers:** verified by computed style in Phase 0 rather than assumed.

## 11. Out of scope

- Style consolidation, spacing/typography/colour normalization, design tokens, component redesign (future UI-quality project).
- The 400 `el.style.x = …` and 5 `.style.cssText` CSSOM writes.
- The Go-rendered PDF/HTML reports (`internal/reporting`) — a separate document with its own policy.
- Splitting `features/reports.js`.

## 12. Carried constraints

Work on `main`; commit and push after every commit; stage files by name, never the user's pre-existing local modifications; Node only in the pinned images (`tools/node.sh`, `tools/smoke.sh`), `npm ci --ignore-scripts`, no new npm dependencies; proven G1 scripts unmodified; the G1 XSS guard and both registry checks stay green on every commit.
