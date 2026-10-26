# Console redesign (1.9.6) — gap analysis: `docs/ui-demo` vs the real console

Written 2026-10-26, before any code is changed in `orchestrator/web`.

**What was compared**

| | Real console | Demo |
|---|---|---|
| Source | `orchestrator/web` (`index.html`, `styles/app.css`, `src/features/*.js`) | `docs/ui-demo` (`index.html`, `demo*.js`, `demo.css`) |
| Pages | 28 tabs (+ Profile, which is not in the nav) | 26 routes |
| Overlays | 72 modal/drawer/panel containers in `index.html` | about 50 modals and drawers |
| Method | built `dist/`, rendered every tab with the smoke-test fixtures (screenshots), static inventory of every page's headings, buttons, columns, labels and selects, read the shell markup and the theme code | rendered every route (screenshots + structure dump), listed every `mhd()/dhd()` title |

Screenshots and the structure dumps are regenerable with the scripts under the session scratchpad; they are not committed.

The two UIs share one design lineage: the same colour tokens (`--bg`, `--surface`, `--accent`, …), the same three fonts (Inter, Space Grotesk, JetBrains Mono — the real build already self-hosts them, which the strict CSP and air-gapped installs require). So this is an evolution of the existing look, not a second design system.

---

## A. What the demo is missing (must be designed and added in the same style)

### A1. Pages that exist in the real console and have no demo page
| Real page | What it does | Plan |
|---|---|---|
| **Profile** (`tab-profile`, reached from the user menu) | the signed-in user's profile, change password | add: profile card, role, last login, change-password form |
| **Compliance Report** (`tab-compliance`, from Reports) | pick an agent + framework → generate a framework report | add: stepper-style form, framework picker, result view with control table and export |
| **SLA Compliance** (`tab-sla-report`, from Reports) | fleet SLA: on-time resolution rate by severity, trend, history | add: KPI strip, by-severity bars, trend chart, history table |

### A2. Global shell features the demo does not have
| Real feature | Why it matters |
|---|---|
| **Tamper / integrity alert banner** (`#tamper-banner`, "Acknowledge & Clear") | security-critical; must stay above everything |
| **License grace banner** (fixed, reserves space via `--license-banner-h`) | licensing state |
| **Live-connection indicator** with real states (connected / reconnecting / disconnected) | the demo shows a static green "System Healthy" |
| **Role badge + role-gated navigation** (Settings, Integrations, Kubernetes, Scheduled Assessments are hidden until the role/feature allows) | demo shows every item to everyone |
| **Four themes: Dark, Light, Cyberpunk, Slate** (`body.theme-*`, picker in Settings → Theme & display) | demo has only light/dark; all four must keep working |
| **Dashboard preference** (`bas_dash_pref`) and **last tab / last dashboard view** restore | existing user preference storage |
| **Command palette** (`⌘K`) wired to real search | demo palette searches sample data |
| Login: show/hide password, real error line, "SEBI CSCRF / RBI CSF / IRDAI aligned" copy | demo login is a visual only |

### A3. Agents
- **Deploy agent panel with every real installer**: Windows MSI; Linux one-download `.run` (x86_64 and ARM64) and uninstaller; `.deb` / `.rpm` (x86_64, ARM64); macOS setup apps (Apple Silicon / Intel) and the both-Macs uninstaller; CLI binaries; legacy installers; **enrollment tokens** (Generate, Copy, Show, Clear, Download CSV). The demo's Deploy modal shows an MSI only.
- Table columns the real console has: **IP address, Sims, Actions** (row menu), and on the Risk tab **Health Score, Criticality, Trend, Top Issue, Open Findings**.
- States: **Retired** filter and bucket, **"Task Channel Down"** badge, **Legacy Transport Migration** with its *not yet eligible* state (demo shows only *eligible*), "Load more" pagination.
- Overlays: Revoke, Reinstate, Force Remove (demo has), Stop, Uninstall, Approve for local execution, group picker, agent detail drawer with real tabs.

### A4. Settings
The demo lists the sub-tabs but not their real contents:
- **Users & roles**: create, **edit**, **change password**, **reset password**, enable/disable, last login; the three role-permission rows.
- **Caldera engine**: server URL, enabled, last poll, last result, **Check Now / Sync Now**.
- **Threat intel**: MISP, OpenCTI, OTX, TAXII, OpenAEV config panels, **+ Add Connector**, enabled/last poll.
- **ART content**: library status, **Reseed from Pack**.
- **Audit logs**: Time, Action, Resource/Detail, IP address, Outcome, filters, **Export CSV**, ‹ Prev / Next ›.
- **Theme & display**, **Dashboard** preferences, **License**.
- **Backup & Recovery**: **Backup Now**, history (Date, Trigger, Local, Remote), **Restore**, refresh.
- The "Base simulations / Available variants" header with its click-for-breakdown.

### A5. Scenario launch flow and policy
The real launcher is a family of overlays the demo collapses into one "Run Scenario": individual / additional / group / all / customize selection, mode + mode warning, reason, variant + variant note, privilege. Plus the **execution policy panel** and the **legacy-migration panel**.

### A6. Page-level gaps (from the static diff)
| Page | Missing in the demo |
|---|---|
| Scenarios | availability labels (Available / Catalogued only / Unavailable: connector not configured / Experimental) and the **Threat Actor Library** section |
| Live Runs | real column set (Scenario Runs table) and per-run status model |
| Kubernetes | form labels: Action, Object name, ConfigMap value, "Show built-in system: roles" |
| Campaigns | columns Scenario, Targets, Status, **Result mix** |
| Initiatives | columns Name, State |
| Coverage | columns Runs, Tested at |
| Attack Paths | Discover Subnet, Start/Cancel Collection, **View Results / Retry**, assets table (Host, Crown-Jewel Tag, Segment, Tier-0, Criticality, Flags), collection history (Collected, Agent, Nodes, Edges, Duration, SharpHound, Status), edge legend (Edge / Meaning), schedule form (interval, segment tag, SharpHound each cycle) |
| Findings | columns Agent, **Ticket** |
| IOC Registry | columns Value, Origin, Status, First Seen; **Show suppressed** |
| Reports | columns Scope, Generated by, Generated, Status; links to Compliance and SLA |
| Integrations | form: Enabled, Auto-update on change, Auto-close on heal; **Test Connection**; **View Findings →** |
| Exercises | columns Steps, Created |
| Technique Coverage | columns Simulation, Detection Profile, Purple Exercise, Compliance Mapping, Response Playbook; Actor filter |
| Threat Prioritization (detail) | sections Why this score, Uncovered Techniques, Technique Coverage Breakdown, Sources, Technique Evidence, History, Recommendations for this actor |
| Variants | **Variant Executor** (agent, techniques, base source, mode, Include Advanced Pack/AMSI bypass), Coverage Aggregate with "why this number?" |
| Email | columns Created, Completed |
| Dashboard | "Executive Dashboard" Refresh action |

### A7. Overlays with no demo equivalent
Edit user, Change password, Revoke agent, Reinstate agent, privileged-coverage panel, variant-result panel, evidence viewer, scenario builder, sweep drill-down, exposure detail, OpenAEV detail, exercise detail, initiative drawer / create / attach, TAXII connector, respond overlay, rerun-review, run-live (demo has a drawer), confirm-diff.

---

## B. What the demo has that the real backend cannot support today

The demo uses invented sample data for these. Putting them in the real console as-is would show numbers that do not exist. Each needs a decision (this follows the standing rule: never show an inflated or invented figure).

| Demo element | Backend today | Decision |
|---|---|---|
| Global **time-range picker** (24h/7d/30d/90d) | only `/api/dashboard/trends?days=` takes a range | show only on the panels whose endpoint accepts it; no global picker |
| **Environment badge** ("Production") | none | drop, or a label read from `setup.conf` if added later |
| **Notification bell** | no notification feed | feed it from real sources only (tamper events, license state); otherwise omit |
| **Pinned / Saved views / Recent** | none | client-only per browser (`localStorage`), labelled as such |
| "Updated 15:39" refresh stamp | page load time is real | keep (real time of last successful load) |
| Dashboard hero stats: *Validations (30d), Detection rate, Mean time to detect* | not all computed server-side | show only values the API returns; otherwise the real KPI already on the page |
| 428 agents / 1,284 validations etc. | sample | all numbers come from the real loaders; empty states stay honest ("no runs yet") |
| Light theme as the only alternative | real has four | keep four |
| Breadcrumbs, density toggle, accent picker, keyboard-shortcut dialog | none | client-only; safe to add |

---

## C. Look-and-feel upgrades to apply

From the side-by-side captures, the redesign changes:

1. **Shell**: grouped sidebar with count/alert badges and a collapse handle; topbar with search, breadcrumb row, page actions; footer health.
2. **Page header ("hero")**: gradient banner with icon, title, subtitle, primary actions and a row of live stat chips — replaces the bare `h1 + subtitle`.
3. **KPI cards**: label + icon + value + sub-text + sparkline, coloured top rule by severity.
4. **Tables**: toolbar (filter, Columns, page size, Export CSV), sticky header, row hover, bulk selection, empty/loading/error states.
5. **Charts**: one consistent kit (donut, bars, area, sparkline) with tooltips.
6. **Cards, buttons, pills, inputs, tabs, drawers, modals, toasts**: one radius/spacing/focus system; visible focus rings.
7. **Typography**: Space Grotesk for numbers and headings, Inter for UI, JetBrains Mono for ids/code.
8. **Responsive**: sidebar becomes a drawer under 900 px.
9. **Empty and error states**: icon + explanation + the next action (the real console currently shows bare "No scenarios loaded.").
10. **Logo**: sits on a white tile in both UIs; the transparent mark on the dark sidebar would look cleaner (proposed, not yet decided).

## D. Constraints the port has to respect (the demo ignores them)

- **CSP**: `script-src 'self'`, no inline handlers, no inline script; fonts and images self-hosted; `style-src 'unsafe-inline'` is allowed today but the project goal is `'self'` — new code must not add inline `style=` that blocks that.
- **Action registry**: behaviour only via `data-on-<event>` and `ACTIONS` (`src/globals.js`); `scripts/g1d-check-actions.py` fails the build otherwise. The demo's `data-act` handlers cannot be copied.
- **Escaping**: every dynamic value through `escape.js`; the smoke fixtures inject XSS payloads and fail if `window.__xss` is set.
- **Four themes** and the existing `localStorage` keys must keep working.
- **Integrity manifest**: the build writes `dist/MANIFEST.sha256`; the orchestrator refuses to start if a served file differs.
- **Tests that will need deliberate updates**: smoke baseline, visual baseline (`tests/visual`), unit tests that assert markup.
- **Real data states** the demo never shows: loading, error, empty, partial, role-restricted, and very long names / large counts. Every redesigned page is verified against richer fixtures than the smoke set (which is nearly empty).
