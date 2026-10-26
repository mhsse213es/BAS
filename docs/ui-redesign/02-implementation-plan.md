# Console redesign (1.9.6) — implementation plan and progress ledger

Spec of record: [01-gap-analysis.md](01-gap-analysis.md) (what the demo misses, what it invents, the constraints) and the clickable demo in `docs/ui-demo/`.

**Branch / workspace:** branch `ui-redesign-1.9.6`, own git worktree (so the shared working tree and the other sessions that push to `main` are not disturbed). Merged to `main` only when the whole set below is done and the gates pass, so no half-redesigned console is ever built by accident.

## Approach

The real console is a vanilla-JS app with strict conventions (CSP, `ACTIONS` registry, escaped templates, generated `g1-s-*` style classes, four themes). It is **restyled in place**, not replaced:

1. The visual system (tokens + base components) is changed once in `styles/app.css`, so every page picks up the new look while keeping its behaviour.
2. The shell (sidebar, topbar, breadcrumb, banners, user menu) is rebuilt in `index.html` + a small `src/features/shell-ui.js`.
3. Each page then gets the page header ("hero" with live stat chips), the toolbar/table pattern, and the missing pieces from the gap analysis — all fed by the **real loaders**, never sample numbers.
4. Demo-only elements without a backend follow the decisions in gap analysis section B.

Rules for every phase: TDD where there is logic (pure helpers get unit tests first); markup changes verified by the smoke run (`tests/smoke`) and by screenshots against **rich fixtures** (a populated data set, an empty one, an error one) in all four themes at 1440 / 1024 / 390 px; no inline handlers; every dynamic value escaped; commit per phase; pushed to the branch after each commit.

## Phases and ledger

Status: `todo` / `doing` / `done`. Update this table in the same commit as the work.

| # | Phase | Deliverable | Verification | Status |
|---|---|---|---|---|
| 0 | Workspace and harness | worktree + branch; `node_modules` link; rich-fixture capture harness (populated / empty / error; 4 themes; 3 widths); baseline screenshots of the current console | harness renders all 28 tabs without page errors | todo |
| 1 | Visual foundation | tokens, typography, buttons, inputs/selects, cards, pills, tables (toolbar, sticky head, empty/loading/error), tabs, modal and drawer shells, toasts, focus rings, scrollbars — in `app.css`; all four themes | smoke passes; screenshots of all pages in 4 themes show no regressions | todo |
| 2 | Shell | sidebar (groups, badges, collapse, pinned/recent as client-only), topbar (search, live indicator, role badge, user menu), breadcrumb row, banners (tamper, license) restyled, responsive drawer < 900 px | role-gating and feature-hidden nav unchanged; keyboard and screen-reader pass | todo |
| 3 | Page-header component | shared `pageHero()` helper (icon, title, subtitle, actions, stat chips) + CSS; unit tests | unit tests; used by phase 4+ | todo |
| 4 | Dashboard (operational + executive) | hero stats from real endpoints, KPI cards, compliance strip, charts, all existing panels kept (Ransomware Readiness, Attack flow, …) | populated + empty + error fixtures | todo |
| 5 | Operations pages | Scenarios (+ availability labels, Threat Actor Library), Live Runs, Kubernetes, Scheduled Assessments, Initiatives, Campaigns, Factory Health, Coverage, Variants (+ Executor), AD Coverage, Email | per page: populated/empty/error | todo |
| 6 | Visibility pages | Findings, IOC Registry, Remediation, Reports, Verification, Attack Paths (+ collection/assets/history), Exposure Explorer, Recommendations, Exercises, Technique Coverage, Threat Prioritization (detail sections) | per page | todo |
| 7 | Infrastructure | Agents (all installers, enrollment tokens, health/risk columns, Retired, Task Channel Down, migration states), Integrations (forms, Test Connection) | per page | todo |
| 8 | Administration | Settings (all sub-tabs with real contents), Profile (new look), user dialogs | per page | todo |
| 9 | New pages | Compliance Report, SLA Compliance (from Reports), Profile page | per page | todo |
| 10 | Overlays | every overlay in gap analysis A5/A7 restyled to the shared modal/drawer system | open each one under the harness | todo |
| 11 | Login | restyled login with real behaviour (show/hide password, error line) | login flow in smoke | todo |
| 12 | Gates and docs | update smoke/visual baselines deliberately; unit tests; `eslint`; `g1d-check-actions`; full build + manifest; guide + changelog; screenshots in `docs/` | `npm test`, `npm run build`, smoke, orchestrator Go suite for embedded-asset tests | todo |
| 13 | Merge | merge branch to `main` after a review of the whole branch; push | CI-equivalent run | todo |

## Decisions made (rulings) — change only with a reason

- Restyle in place; no framework, no new dependencies.
- Four themes kept; the demo's light/dark logic is not copied.
- No global time-range picker; no environment badge; the notification bell only if a real feed exists (gap analysis B).
- Pinned / Saved views / Recent are per-browser (`localStorage`) and labelled so.
- The branch is merged only when complete.

## Not in scope

Backend changes, new API endpoints, new scoring, and anything that would make the console show a number the server did not compute.
