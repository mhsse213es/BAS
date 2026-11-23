# Audspect Console — Visual & Functional Audit (Phase 1b)

Scope: the real console built from `orchestrator/web` at `main` = `167cc615` (built `dist/`, **not** `docs/ui-demo`).
Status: AUDIT ONLY. No application code, backend calculation or token was changed. Awaiting approval before any design work.
Evidence folder: `docs/ui-redesign/audit-evidence/` (screenshots, per-run `metrics/*.json`, driver scripts in `tools/`).

## 0. Method and its limits (read first)

- Rendered from a clean `git archive` of `167cc615`, built with `tools/build.mjs`, served statically, Chromium via Playwright, **mocked API**.
- Data came from `fixtures-rich.mjs` / empty / 500 sets. These live only in the `ui-redesign-1.9.6` worktree (not tracked on main). **Fixture values are not evidence of real operational values.** Where a number matters (D1–D3) it is flagged for backend verification.
- Classification used per finding:
  - **R** rendered and screenshot inspected by me
  - **M** rendered and measured in the DOM (computed styles / geometry), screenshot not individually inspected
  - **C** code-verified (source read)
  - **I** inferred from prior docs, not re-verified
- "Inspected" for the 30 views at 1440px means one first-viewport contact sheet (3 sheets) plus individual full-size looks at dashboard, findings, agents. Below-the-fold content of most pages was **measured, not looked at**.
- Not done: real browser with real backend, hover/focus-state rendering, chart-graphic contrast, screen-reader testing, tablet/phone interaction (only captured + measured), per-theme review of every page.

## A. Coverage matrix

Views = 30 `showTab` targets + Profile = 29 distinct nav views; `compliance` and `sla-report` are sub-tabs of Reports (same page header), so 28 distinct pages.

| Scope | Captured | Visually inspected | Measured only |
|---|---|---|---|
| 30 views, dark, 1440 (rich fixtures) | 30/30 incl. Profile | first viewport of all 30 (3 sheets); dashboard, findings, agents at full size | full-page DOM metrics for 30 |
| 30 views, dark, 1024 | 30/30 | findings, dashboard (earlier session: dashboard, agents) | overflow, contrast, tap size |
| 30 views, dark, 390 | 30/30 | dashboard, agents, run-scenario modal | overflow (none at page level) |
| Empty state (dark 1440 / 390) | 30/30 each | not individually | empties text, metrics |
| Error state, session valid, data endpoints 500 (1440) | 30/30 | findings, threat-priority | error text per tab |
| Permission-denied (data endpoints 403, 1440) | 30/30 | none | error text per tab |
| Themes: light, cyberpunk, slate (1440) | 30/30 each | light dashboard, cyberpunk findings | contrast only; slate not looked at |
| Modals/drawers (real open via UI, 1440 + 390) | 7 flows | run-scenario(390), generate-report | geometry, role/aria, focus trap, ESC |
| Login / unauth | 4 session states | fresh-visit | computed display/z-index |

Not covered: "Deploy Agent" modal (my selector did not match, flow reported not found), Settings sub-tabs beyond the default, Aleef flows, tablet interaction, loading skeleton states, real viewer-role rendering (the fixture returns admin permissions, so "permission-denied" above only means HTTP 403 from data endpoints).

## Baseline (reproducible, committed files only, `167cc615`)

| Check | Result |
|---|---|
| `npm test` (unit) | 582 / 582 pass |
| smoke (`SMOKE_ROOT=dist`, 2 tests) | **2 / 2 pass** |
| `eslint src` | 1 error, 597 warnings. Error: `attack-path.js:1163 'getComputedStyle' is not defined` (`no-undef`; browser global missing from `eslint-browser-globals.json`, not a runtime bug) |
| `scripts/g1d-check-actions.py` | **FAIL**: inline styles 838 > baseline 836 |
| `tests/redesign/shoot.mjs` | cannot run from main: imports untracked `fixtures-rich.mjs` (+ `demo-*.mjs`) that exist only in the redesign worktree |

**Correction to my earlier report.** I said the smoke test was red on main and that the inline-style gate was 1100 vs 1078. Neither is reproduced: smoke is green; the gate is red at 838 vs 836. Both earlier numbers were unverified and wrong. The real pre-existing reds are the g1d ratchet (+2) and one lint error.

## B. Confirmed visual defects (ranked by impact)

1. **Shell is rendered over the login screen on every unauthenticated load.** R. Sidebar (fixed, z-index 50, 240px) sits on top of the left 240px of the login hero, clipping its headline ("ur defences work / tackers test them"). Evidence: `login-under-sidebar.png`. Viewport 1440, dark. Impact: first screen of the product looks broken; nav labels visible pre-auth. Cause (C): `<div id="app">` (index.html:94) has no hidden initial state and `app.css` sets `#app{display:flex}`; `shell.js` only toggles `#app`/`#login-screen` in `doLogout`/`bootApp`. Trigger (R, repro `tools/login-repro.mjs`): fresh visit with no stored role; stored role + `/api/agents` 401; stored role + 500. Only the "stored role + valid cookie" path hides login. Regression origin not determined (history shows `id="app"` has never carried an inline hide at this path). Fix: initial `#app{display:none}` and show only from `bootApp`. Risk: boot order, license-locked screen, `body` classes, smoke harness expects `#app` visible.
2. **Run Scenario / New simulation modal clipped at 390px.** R (+M `fitsX:false` for both). Content overflows both viewport edges. Evidence: `modal-run-scenario-390.png`. Impact: phone users cannot read or reach edge controls. Risk: shared `.modal` width rules used by 24 overlays.
3. **Findings shows the same severity breakdown twice with different colours.** R (cyberpunk 1440; two donuts "Open by severity" and "Open findings by severity", Medium is blue in one and amber in the other, Low grey vs green). Evidence: `findings-cyberpunk-1440.png`. Impact: contradictory visual encoding of severity. Theme-dependence of the second palette not checked in dark.
4. **Two nav-state defects.** R. "Recent" duplicates items that also appear below, so one page is highlighted twice (Findings, Dashboard); the Recent block also pushes Infrastructure/Administration below the fold at 900px height (`dashboard-light-1440.png`, `findings-1024.png`).
5. **Failed loads are drawn as empty or zero.** R. With a valid session and data endpoints returning 500, Findings shows "No findings yet." (no error), Threat Prioritization shows hero counters "0 / 0 / 0 / 0" plus a raw `Failed to load: l.filter is not a function`. Evidence: `errauth-*.png`. See also C1–C4.
6. **Page title repeated 2–3 times.** M/R. Topbar title, breadcrumb and hero `h1` say the same ("Findings / Visibility › Findings / Findings"). Most views (about 22 of 30 by the measured title lists) have identical topbar and hero titles. Where they differ they are the same page under different names (Compliance → "Reports", Verification → "Detection Verification").
7. **Findings and Agents work surface below summary content.** R (1440). Findings: 5 KPI tiles + filters + 4 charts before the table. Agents: migration banner, status/OS/groups charts and groups panel before the table. Impact: first screen has no rows. (Note: this is a layout judgement, not a defect in correctness.)
8. **Tablet 1024px keeps the full 240px sidebar.** R/M. No horizontal overflow, but the content area is ~784px; sidebar only collapses via `max-width:900px`. 1024 is the common tablet landscape width.
9. **Primary buttons fail AA text contrast.** M. White-on-blue label measured 3.21:1 in dark (cyberpunk/slate identical), 3.68:1 in light (e.g. Deploy Agent, Generate report, New campaign, Launch, Run). Normal text needs 4.5:1. 27 of 30 views have ≥1 failing text node in dark, 29 in light (46 on AD Coverage, 78 on Email, 72 on Dashboard in light). Per-element screenshot review not done; some hits may be decorative.
10. **Native `<select>` controls.** R. 91 `<select>` usages; Findings has 14 on one page, Variants 6. Visually inconsistent with the custom controls (agents/scenarios sheets). Agents also has two search boxes (page-level and in-table).
11. **Scenario cards** carry 3–4 tags plus "Available" on each card with empty space below (R, scenarios sheet at downscale only; low confidence).
12. **Tap targets under 24px.** M. 187 interactive elements <24px at 1440 (Variants 34, Agents 26, Runs 16). Unlabelled interactive elements (no text/aria/title/placeholder): 45 across pages (Agents 8, Exposure 8, Threat Prioritization 8, Scheduled 8).

Not defects despite earlier suspicion: no page-level horizontal overflow at 1024 or 390 on any of the 30 views (M); no JS page errors on any view with rich or empty data (M); no "undefined/NaN/[object" text in any pane (M, regex on rendered text).

## C. Functional and accessibility defects

C1. **Unguarded array assumptions turn a non-array response into a TypeError.** C+R. `(list2 || []).filter` / `l.filter` / `rows2.filter` is not a function on Findings, Exposure Explorer, Threat Prioritization, IOC Registry. Raw JS message is shown to the user (toast and in-card). Reproduced with `{"error":"..."}` bodies, which is what the API returns on error.
C2. **Three views never leave "Loading…" when data fails.** R/M. Campaigns, Initiatives, Scheduled Assessments (errauth 1440).
C3. **403 and 500 render identically on all 30 views, and neither mentions permissions.** M. The 403 run produced byte-identical empty/error text to the 500 run for 30/30 tabs.
C4. **Failure shown as empty-state wording** on ~20 views ("No agents registered yet", "No SLA data yet", "No recommendations yet"). R/M. This conflicts with the project rule that unavailable ≠ zero.
C5. **No focus management in any dialog.** M+C. In 6 of the 6 flows that opened (7 attempted; Deploy Agent not found), focus left the dialog within 30 Tab presses (agent drawer 25, finding drawer 17, run-scenario 30, generate-report 30, new-simulation 16, command palette 29); `focusTrap` does not exist in `src`. Only the Generate-report dialog and command palette declare `role="dialog"`; of the other overlays only a subset has `aria-modal` (18 `aria-modal` in `index.html`).
C6. **Escape closes only some overlays.** C+M. Escape handlers exist in `attack-path.js`, `k8s-scenarios.js`, `scheduled.js`, `evidence.js`, `reports.js` and the user menu. Agent drawer, finding drawer, run-scenario and new-simulation did not close on Escape in my run (`escCloses:false`). The Generate-report flow also reported not closing; the report handler is conditional (`reports.js:1848`), so that result needs a manual recheck.
C7. **Tabs and ARIA.** C. `index.html` has 9 `role="tab"`, 3 `aria-selected`, 1 `aria-live`, 0 `aria-expanded`. No skip link. Only 1 stylesheet honours `prefers-reduced-motion`; `:focus-visible` rules exist in 4 files only.
C8. **Profile reachable only through the user menu**, not via `showTab`; harness had to open the menu. Not a defect, but any redesign test must cover it.
C9. **`attack-path.js:1163`** uses bare `getComputedStyle`; ESLint config gap only.

## D. Data correctness requiring backend verification (do not change presentation yet)

D1. **"Agents online" on the dashboard is probably wrong for real agents.** C (+R with fixtures). `evidence.js:1116` counts `a.status === 'online'`. The real agent (`agent/agent.go`) heartbeats `idle` / `scanning` and the server only ever overrides to `offline` (`models.EffectiveAgentStatus`). No code path found that emits `online`. The Agents page uses `bucketOf()` (offline / degraded by lifecycle state / online otherwise). Rendered with the fixture set: Dashboard "0 / 14 agents online" vs Agents "13 agents, 9 online, 2 degraded, 2 offline, 1 retired". Total also differs (14 includes retired, 13 does not). Update: `Handler.Heartbeat` (`handlers.go:1543`) stores `hb.Status` verbatim in `agents.status`, and the list handler only overrides to `offline`, so the chain agent -> DB -> API is code-verified end to end; no `online` writer found in non-test Go. Remaining uncertainty is limited to agent builds I did not read (staging not available to confirm live). **Needs:** capture real `GET /api/agents` on staging and confirm the `status` vocabulary. If confirmed, the dashboard will show 0 online for a healthy fleet.
D2. **"Prevention score 63%" next to "Techniques prevented 100%"** (R). They are different definitions (mean per-run severity-weighted score vs share of tested techniques prevented in ≥1 run) but neither has an on-screen definition. Code comments document the rules; the UI does not. Verify with the server owner whether both should be shown together.
D3. **Compliance cards**: percentage colour and bar colour disagree (e.g. 75% green with an amber bar; thresholds not stated) (R, light dashboard). Verify intended thresholds.
D4. **Dashboard "Active campaigns" subtitle** concatenates a campaign name and "+1 running" in a tile built for one line (R); cosmetic, listed for completeness.
D5. Fixtures use their own status vocabulary and totals; any number seen in screenshots above is fixture-derived.

## E. Shared component candidates (actual counts, `main`)

| Pattern | Count | Evidence | Verdict |
|---|---|---|---|
| Data table | 44 `<table` in `src` JS + 20 in `index.html` (earlier "41" was a different measure) | Toolbar (filter/columns/page-size/CSV) on ~12 pages, absent elsewhere | Strong candidate; migrate incrementally |
| KPI tile | 108 `kpi(` calls | consistent already | Document, don't rebuild |
| Status pill/chip | 59 | `sbadge`/`pill`/`chip` variants | Candidate (needs one semantic colour set) |
| Modal / drawer shells | 24 overlays + 23 drawer overlays, 18 declare `role=dialog` | divergent aria, focus, Escape | **Strongest candidate**, fixes C5/C6/B2 together |
| Native selects | 91 | | Candidate (filter bar) |
| Empty / error state | 99 "No … yet" strings (12 × "No data yet") | no distinction between empty, failed, forbidden | **Strong candidate**, fixes C1–C4 |
| Search/filter input | 31 | duplicated on Agents | Candidate with table |
| Hard-coded colours | 143 hex occurrences, 50 distinct (top: `#f85149`×14, `#d29922`×12, `#da3633`×10, `#f0883e`×9, `#3b82f6`×5, `#2fd8c3`×5; three reds, three ambers) | | Token candidate, separate step |
| Inline styles | 838 in `src` | gate already red | Do not grow; not part of redesign |

## F. Revised implementation sequence (evidence-based; each step separately reviewed)

0. Baseline repair, no UI change: track the harness (`fixtures-rich` + `demo-*` + `audit.mjs`) on main or in a test-only folder; fix the 838/836 ratchet and the one lint error; record screenshot baselines (dark 1440/1024/390 for the 30 views).
1. **P0 correctness**: login-under-shell fix (B1); then, once D1 is confirmed on staging, fix the agents-online definition; response-shape guards and an explicit empty / failed / forbidden distinction (C1–C4).
2. Shared **overlay shell** (focus trap, Escape, `role=dialog`, mobile fit): B2, C5, C6. Pilot on Run Scenario + Agent drawer.
3. Tokens: spacing, type, semantic status colours **preserving existing values**, then a separate visual-refinement step (so regressions are attributable).
4. Shell: remove nav duplication/double highlight, single page title (B4, B6), tablet sidebar (B8).
5. Shared table + filter bar; migrate Agents, then Findings.
6. Page work: Findings work surface and duplicate donut (B3, B7), Agents, Scenarios.
7. Accessibility pass: contrast of primary buttons (B9), tap targets, labels (B12), reduced motion, focus-visible.
8. Cross-theme and browser verification with before/after screenshots.

Figma file (`42BQzacStXttPfwoHxkuuM`, 3 pages) exists and is intentionally empty; no design work until the direction is approved.

## Open questions

1. What does real `GET /api/agents` return for `status` on staging (D1)?
2. Is the shell-over-login visible in production builds the same way (the dist I used is a local build of `main`)? Not checked against a deployed server.
3. Are the Compliance colour thresholds intended (D3)?
4. Is Escape on the generate-report dialog really broken (C6)? Needs a manual check.
5. Do viewers see the same views, with controls hidden, or are routes blocked? Needs a real viewer account.
6. Remaining unreviewed: below-the-fold content on most pages at 1440, all pages at 1024/390 beyond three samples, slate theme, Settings sub-tabs, Deploy Agent modal, loading states.
