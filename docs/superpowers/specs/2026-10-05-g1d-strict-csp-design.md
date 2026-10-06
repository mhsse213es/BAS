# G1d — Strict Content-Security-Policy for the dashboard

Status: design approved in conversation 2026-10-05; this document awaits review.
Group: G (frontend XSS surface). Depends on: G1c (frontend modularization).
Source requirement: `groupG.txt` — "G1d: deploy strict nonce/hash-based CSP. That prevents a fake remediation where Content-Security-Policy is added but weakened with unsafe-inline/unsafe-eval."

## 1. Goal

Serve the dashboard with an enforcing Content-Security-Policy whose `script-src` allows only the dashboard's own bundled scripts — no `'unsafe-inline'`, no `'unsafe-eval'`, no `'unsafe-hashes'` — so that markup injected through any future escaping bug cannot execute script.

Success means: every inline event handler is converted to delegated actions, nothing app-defined is reachable through `window` except a reviewed list, the Go server sends the policy, and the smoke harness proves all 25 tabs work with zero violations while the policy is enforced.

## 2. Decisions taken (user, 2026-10-05)

| Decision | Choice |
|---|---|
| Style policy | **Scripts strict, styles staged.** `style-src 'self' 'unsafe-inline'` in G1d; converting the ~2,500 `style=` attributes is follow-up **G1e**, which then removes `'unsafe-inline'` from `style-src`. Rationale: style injection cannot execute code; script-src is where the XSS protection lives. |
| Rollout | **Enforce by default, with a Report-Only escape hatch** (`BAS_CSP_MODE`) and an on-box violation log. No external reporting service (air-gapped installs). |
| Handler conversion | **Approach A — delegated actions via `data-` attributes.** Rejected: B (per-render `addEventListener`; touches every render function, re-wiring after `innerHTML` is easy to miss) and C (`'unsafe-hashes'`; concatenated handlers produce per-row bodies that cannot be hashed, and it is itself the weakening groupG rejects). |

"Nonce/hash-based": after G1c, `index.html` contains no inline `<script>`; all script is the external hashed bundle. `script-src 'self'` is therefore sufficient and no per-request nonce (and no server-side HTML templating) is needed. This is stated so the absence of nonces is not read as a gap.

## 3. Inventory at design time (G1c tree, 2026-10-05)

| Blocker under a strict policy | Count | Notes |
|---|---|---|
| Inline handlers in `orchestrator/web/index.html` | 388 | 338 single call with literal args; 30 use `this`; 13 multi-statement; 3 use `event`; 4 other |
| Handlers built inside JS template strings (`src/`, 24 modules) | 226 | 123 args built by string concatenation; 37 multi-statement; 29 use `this`; 9 use `event`; 26 single call; 2 other |
| `javascript:void(0)` links | 13 | |
| `style="…"` attributes | ~1,072 markup + ~1,450 templates | Out of G1d scope (G1e) |
| `eval` / `new Function` / string timers | 0 | |
| External loads | Google Fonts (CSS + font files) | Self-hosted in G1d |
| `window.open` targets | 9, all server URLs (`/api/.../report`, download paths) | Separate documents; not affected |
| `data:` URLs | favicon only | |
| Existing CSP or security-header middleware in Go | none | |

Event types in use: click (≈519), change (≈76), input (≈13), keydown (≈5), mouseover/out/enter/leave/down, blur.

## 4. Architecture

### 4.1 Markup form

`onclick="openRun('abc', 3)"` becomes

```html
data-on-click="openRun" data-args='["abc",3]'
```

`data-on-<event>` names an action; `data-args` (optional) is a JSON array of plain data — strings, numbers, booleans, null. Arguments are never evaluated as code.

### 4.2 `src/core/actions.js`

- `ACTIONS` — the action registry: name → function. Replaces `HANDLER_FUNCTIONS`; it is **not** copied onto `window`.
- `on(eventType, actionName, ...args)` — the only way templates attach behaviour. Returns `' data-on-<event>="<name>" data-args="<json>"'` with the JSON HTML-escaped through the canonical escaper. Retires every concatenated handler string; escaping lives in one place.
- `installActions(root = document)` — one listener per event type on `document`, registered in the capture phase so non-bubbling events (blur, mouseenter, mouseleave) are delivered.

Dispatch rules:

1. From `event.target`, walk ancestors. For each element carrying `data-on-<type>`, call `ACTIONS[name].apply(element, [...args, element, event])` — `this` is the element, so code reading `this.checked`/`this.value` is unchanged; wrappers that need the element or event take them as the trailing parameters.
2. Stop walking when the handler has called `event.stopPropagation()` (`event.cancelBubble`), preserving today's nested behaviour (button inside a clickable row).
3. An `<a href="#">` carrying an action gets `preventDefault()` (replaces the 13 `javascript:void(0)` links).
4. Unknown action name: `console.error` and do nothing. Never fall back to `window[name]`.
5. Malformed `data-args` (not a JSON array): `console.error`, handler not called.

### 4.3 Non-trivial handlers

Handlers that are not a single call (≈120: multi-statement, `event`, inline assignments such as `scenarioView = 'search'; renderScenarios()`) become small named functions in their owning feature module, registered as actions. Inline assignments to state become `state.X = …` inside those functions; the `window` state getters (`STATE_GLOBALS`) are removed once no inline code assigns them.

### 4.4 What remains on `window`

Only the reviewed `WINDOW_WRITES` names (12 today: `_campaigns`, `_cmdkBound`, `_covCounts`, `_covSt`, `_covTactics`, `_evidenceResults`, `_findings`, `_rems`, `_slaReport`, `onRunEvent`, `openRunPanel`, `toggleLiveStep`). G1d reviews each: those used only as module-level caches move to `state`; any still required are documented in `globals.js` with the reason.

### 4.5 The CSP header (Go)

Set in `orchestrator/cmd/server/static.go` (the `cacheHeaders` wrapper) on the dashboard document (`/`, `/index.html`) and its assets. Not set on API JSON or on the server-rendered reports (separate documents; out of scope).

```
default-src 'none';
script-src 'self';
style-src 'self' 'unsafe-inline';
img-src 'self' data:;
font-src 'self';
connect-src 'self';
base-uri 'none';
form-action 'self';
object-src 'none';
frame-ancestors 'none';
report-uri /api/csp-report
```

`style-src 'unsafe-inline'` is the staged G1e item. `connect-src 'self'` covers `fetch` and the same-origin `/ws/browser` socket. `frame-ancestors 'none'` also prevents clickjacking.

Mode — env var `BAS_CSP_MODE`:

- `enforce` (default): `Content-Security-Policy`.
- `report-only`: same policy as `Content-Security-Policy-Report-Only`.
- Any other value: startup fails with a clear message. There is deliberately no `off`.
- Startup logs `[+] dashboard CSP: enforce` or `[~] dashboard CSP: report-only`.
- `install.sh` / the compose `.env` template carry `BAS_CSP_MODE=enforce`.

The header is produced by code, not a file, so the G1c `MANIFEST.sha256` integrity check is unchanged.

### 4.6 Violation endpoint — `POST /api/csp-report`

- Unauthenticated (browsers send reports without the app's auth); added to the RBAC matrix `publicRoutes`.
- Accepts `application/csp-report` and `application/reports+json` only; body capped at 16 KB; covered by the existing per-IP rate limiter.
- Each report → one structured log line: blocked URI, effective directive, document URI, source file, line. Values truncated (256 chars) and control characters stripped (log-injection safe).
- No database writes (a violation loop cannot fill tables or disk beyond normal log rotation).
- Responds `204`.

### 4.7 Fonts

The two Google Fonts links are replaced by self-hosted font files under `orchestrator/web/fonts/`, copied into `dist/` by the build and listed in `MANIFEST.sha256`. Required anyway for air-gapped installs; enables `font-src 'self'`.

## 5. Phases (each commit green on unit, build, smoke, registry, G1)

**Phase 0 — foundation.** `core/actions.js` + unit tests; `installActions()` called from `main.js`; registry check and smoke harness extended (§6) but tolerant of remaining `on*=` (ratchet baseline = current counts). **G1 spike:** convert one template on a trial and run the G1 guard. The proven G1 scripts are not modified; if the classifier rates `on(...)` worse, the adaptation goes into the classifier-view assembler or into how `on()` is written. The finding is recorded before Phase 1.

**Phase 1 — static markup.** A one-time codemod converts the 338 single-call literal-argument handlers in `index.html`; the remaining 50 are converted by hand into named actions. A few commits, split by page area.

**Phase 2 — templates, one module per commit**, smallest first (24 modules, 226 handlers), using `on()`. REVIEW lines from the G1 guard are checked as in G1c.

**Phase 3 — cleanup and switch-on.** Delete `HANDLER_FUNCTIONS`, `DYNAMIC_HANDLERS` (string-named actions such as `covSegHtml(…, 'setAgentFilter')` become `on('click', fnName, v)`), the `window` state getters; review `WINDOW_WRITES`; self-host fonts; add the Go header, mode switch and report endpoint; turn on enforcement in the smoke harness's served header as the gate for that commit.

## 6. Checks (CI ratchets — they only tighten)

1. **Registry check** (`scripts/g1c-check-globals.py`, rewritten):
   - every `data-on-*` name in `index.html` and every literal `on('type', 'name', …)` in `src/` is an `ACTIONS` entry;
   - no `ACTIONS` entry is unused;
   - the number of remaining `on*=` attributes (markup + JS strings) and `javascript:` URLs may only decrease against a committed baseline file (`scripts/g1d-inline-baseline.json`), reaching 0;
   - while any remain, they must still resolve through `HANDLER_FUNCTIONS`.
2. **ESLint** `no-restricted-syntax`: any string or template literal containing `on<event>=` or `javascript:` is an error.
3. **Smoke harness**:
   - the smoke server sends the policy (enforcing from Phase 3; Report-Only before, with violations still failing the run);
   - each tab fails on any `securitypolicyviolation` event;
   - after each tab, the live DOM must contain no `on*` attribute and no `javascript:` URL (catches handlers that are rendered but never clicked);
   - each tab clicks one representative action (tab switch plus a toolbar filter where the tab has one), so dispatch is exercised end to end.
4. **G1 guard** unchanged; must pass on every commit.
5. **Go tests**: exact header string; a test failing if `script-src` ever contains `unsafe-inline`, `unsafe-eval` or `unsafe-hashes`; mode parsing (invalid value fails startup); report endpoint (size cap, content type, sanitization, 204); RBAC public route.

## 7. Testing

- `tests/unit/actions.test.mjs` (jsdom): argument round trip; `this` binding; trailing `(element, event)` parameters; `stopPropagation` ends the ancestor walk; capture of blur/mouseenter; unknown action and malformed `data-args` are logged and not run; `<a href="#">` default prevented; `on()` with hostile arguments (quote, tag and attribute breakouts) yields inert attributes whose decoded `data-args` equals the input.
- Existing XSS tests (Task 9 of G1c) stay; each converted template that previously concatenated handler arguments gets a payload test asserting the payload appears only inside `data-args` as text.
- Smoke harness as in §6.3; Go tests as in §6.5.

## 8. Exit criteria

**G1d modularization exit (done):**

1. Zero `on*=` attributes in `orchestrator/web/index.html` and `orchestrator/web/src`.
2. Zero `javascript:` URLs.
3. `HANDLER_FUNCTIONS`, `DYNAMIC_HANDLERS` and the `window` state getters deleted; `window` carries only the reviewed `WINDOW_WRITES` names, each documented.
4. Enforcing header served by default; `script-src 'self'` with no `unsafe-*`, pinned by test.
5. Smoke harness green under enforcement with zero violations on all 25 tabs.
6. G1 guard passes; all REVIEW items checked.
7. No external origin loaded (fonts self-hosted).

**Release / QA acceptance (separate):** on staging, every tab loaded with the browser console open under `enforce` (no violations); startup log line confirmed; mode flipped to `report-only` and back once; a report observed in the log; client upgrade note documents `BAS_CSP_MODE`.

## 9. Out of scope

- **G1e** — convert `style=` attributes to classes, then remove `'unsafe-inline'` from `style-src`.
- CSP for the server-rendered HTML reports and other non-dashboard documents.
- The intermittent Go data race in `TestFakeBrowser_ConnectReceiveDisconnect` (`internal/api/result_ingestion_helpers_test.go`), a separate fix.

## 10. Constraints carried from G1a–G1c

- The proven G1 scripts (`g1-innerhtml-sink-classifier.py`, `g1-trace-indirect-sinks.py`, `g1-merge-classification.py`) are not modified; G1b stays independent of the production build (the classifier view remains a CI analysis artifact).
- Node only in the digest-pinned Docker images and CI; `npm ci --ignore-scripts`; no new dependencies unless a later plan justifies one.
- Work on `main`, commit and push after every commit, files staged by name.
- G1d implementation starts after G1c's final review, so that review sees G1c alone.
