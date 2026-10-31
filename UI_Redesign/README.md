# Audspect console — UI/UX redesign proposal (v0.3)

A **static, clickable design proposal** for a redesign of the Audspect orchestrator console.
It is for review and discussion only — it is **not** wired to the backend and is **not** yet
applied to `orchestrator/web`.

## How to review

1. Open **`index.html`** in any modern browser. No build step, no server, no network needed
   (everything is self-contained: self-hosted fonts, inline SVG icons, local sample data).
2. Start with the proposal index, then open the pages in order (the top nav links them all).
3. On any screen:
   - press **N** to toggle the numbered **design notes** (why each element exists, which API
     would feed it, what it replaces today, and what needs building),
   - press **T** to switch between dark and light themes (or add `?theme=light` to the URL),
   - **Ctrl/⌘ K** opens the command palette.

## What's inside

- `index.html` — the proposal: problems with today's console, the benchmark, principles,
  the new information architecture (27 nav items → 15), the page list, backend work, a
  rollout plan, and the open decisions we need the team to weigh in on.
- `01-design-system.html` — tokens, type, components, status language, token migration.
- `02-dashboard.html` — the redesigned **Security posture** dashboard (Executive + Operations).
- `03`–`08` — Assessments, Findings, ATT&CK coverage, Compliance, Endpoints, Reports.
- `09-module.html` — the per-module score template (every dashboard module tile opens it).
- `10`–`17` — Threat library, Purple-team, Detection validation, Attack paths, Threat intel,
  Remediation, Integrations, Settings.
- `00-login.html` — the sign-in screen.
- `assets/` — the shared design system (`ds.css`), shell/behaviour (`shell.js`), sample data
  (`data.js`), per-page scripts, fonts, and the product logo.

## Notes for reviewers

- All data is **fictional** ("Contoso Bank"); technique IDs/names are real MITRE ATT&CK, outcomes
  are invented for the mock-up. No real customer or environment data is present.
- Colours were validated for colour-blind separation and WCAG AA text contrast in both themes.
- The design is built to fit the console's existing constraints (CSP `script-src 'self'`,
  self-hosted fonts, the `data-on-click` actions registry) so it can be adopted incrementally.

Please add review comments / requested changes and we'll iterate before anything is applied to
the live console.
