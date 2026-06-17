# Dashboard → North-Star Parity Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task (inline; no subagents per user preference). Steps use checkbox (`- [ ]`) syntax.

**Goal:** Reshape the real dashboard (`orchestrator/wwwroot/index.html`, `#tab-dashboard`) to match the `audspect.html` mockup's Dashboard — same layout, components, and visual language — building everything we have data for and greying the rest as "coming soon" placeholders for later.

**Architecture:** Pure front-end. The mockup renders its dashboard in JS (`PAGES.dashboard`, `audspect.html:942`); we port its *structure and helpers* (sparkline, ring gauge, trend chip, dual-rail kill-chain preview) into our existing `loadDashboard()` flow, wired to the data we already fetch (`/api/agents`, `/api/scenarios/runs`, `/api/campaigns`) + the per-run kill-chain/detection data. No backend changes.

**Tech Stack:** vanilla JS + inline SVG in `index.html`. Validate each change by parsing the `<script>` block with Node.

**Design reference:** `audspect.html` (dummy-data north-star). Real dashboard: `orchestrator/wwwroot/index.html`.

---

## Decisions (locked with user)

- **Findings area** (mockup's "Open findings" KPI + "Top exposure gaps" card): **grey-out placeholder** — there is no persistent findings/triage backend. Keep our real **Top Failing Techniques** panel alongside.
- **Posture 90-day trend bars**: build a **simplified** version from the last N completed runs' real scores. **Grey only** the true week-over-week % (no time-window aggregation backend yet).
- No subagents — execute inline.

## Data classification

| Component | Source | Status |
|---|---|---|
| Hero title/subtitle (agents N, techniques M, last-run time) | `/api/agents`, `/api/scenarios/runs` | build |
| KPI: Prevention score + trend + sparkline | runs[].score.preventionScore / .trend | build (spark from recent runs) |
| KPI: ATT&CK coverage % + sparkline | tactic coverage from runs | build |
| KPI: Active campaigns + live dot | `/api/campaigns` summary.status | build |
| KPI: Open findings | — | **grey** |
| Posture ring gauge + trend | latest score + run history | build |
| Posture "vs target" / WoW % | — | **grey** |
| Control-effectiveness donut (Prevented/Detected-only/Missed/Not-tested) | run results + detection data (Detections loop) | build (split Failed → Detected-only/Missed) |
| Live campaigns w/ progress | `/api/campaigns` | build |
| Top exposure gaps (findings list) | — | **grey** (keep Top Failing Techniques) |
| Attack-flow dual-rail kill-chain preview | latest completed run report.json (`killChain`) | build (renderer exists in run drawer) |
| ATT&CK tactic coverage | runs | keep |

## Target layout (top → bottom)

1. Hero header — title "Security Posture" + context subtitle + actions (New simulation → run wizard; Generate report → Compliance tab).
2. KPI row (4 tiles, sparkline+trend): **Open findings [GREY]** · Prevention score · ATT&CK coverage % · Active campaigns. (Agents Online folds into the subtitle; Total Runs shown as a tile foot or dropped.)
3. Row `1.3fr / 1fr`: Posture ring-gauge card (simplified trend bars; greyed "vs target") | Control-effectiveness donut (4-way split).
4. Row `1fr / 1fr`: Live campaigns (progress bars) | **Top exposure gaps [GREY placeholder]**.
5. Row `1fr / 1fr`: Recent Runs (keep) | Top Failing Techniques (keep).
6. Full-width: **Attack-flow** dual-rail kill-chain preview (latest completed run).
7. ATT&CK Tactic Coverage (keep).

---

## File Structure

| File | Responsibility | Change |
|---|---|---|
| `orchestrator/wwwroot/index.html` (CSS block) | stat-tile + sparkline + ring-gauge + trend-chip + grey-placeholder styles | Modify |
| `orchestrator/wwwroot/index.html` (`#tab-dashboard` markup) | new layout scaffold | Modify |
| `orchestrator/wwwroot/index.html` (`loadDashboard` + helpers) | render the new components from existing data | Modify |

Validation command used after every task:
```
node -e "const fs=require('fs');const h=fs.readFileSync('orchestrator/wwwroot/index.html','utf8');const m=h.match(/<script>([\s\S]*)<\/script>/);new Function(m[1]);console.log('OK');"
```

---

## Task 1: Visual primitives (CSS + SVG helpers)

**Files:** Modify `orchestrator/wwwroot/index.html` (CSS near `.kpi-*`; JS helpers near `donutSVG`).

- [ ] **Step 1: Add CSS** for `.stat-tile` (tile with sparkline footer), `.trend.up/.down/.flat`, `.ring`/`.ring-c` (gauge center overlay), `.dash-soon` (greyed placeholder: reduced opacity, dashed border, "Coming soon" ribbon), and `.lrow`/`.prog` (live-row + progress bar) — adapt names/values from `audspect.html` CSS but use our `--accent/--success/--warning/--danger/--muted/--elevated/--border` tokens (NOT the mockup's `--atk/--def`).
- [ ] **Step 2: Port SVG helpers** into the script, adapting `audspect.html:606-640`:
  - `sparkSVG(data, w, h, color)` — sparkline polyline + soft fill.
  - `gaugeSVG(value, size, stroke)` — 270° arc gauge (value 0–100).
  - `miniBars(data, w, h)` — small monthly/run bars.
  - (Reuse existing `donutSVG` for the donut; reuse the run-drawer kill-chain renderer for Task 8.)
- [ ] **Step 3: Validate** (node parse) → `OK`. **Commit:** `feat(dashboard): visual primitives — sparkline, ring gauge, mini-bars, placeholder CSS`.

## Task 2: Hero header

- [ ] **Step 1:** Replace the top of `#tab-dashboard` with a hero block: `<h1>Security Posture</h1>` + `#dash-subtitle` (filled in JS: "Continuous validation across N agents and M techniques. Last assessment <ago>.") + actions `New simulation` (calls the run-wizard opener) and `Generate report` (→ `showTab('compliance')`).
- [ ] **Step 2:** In `loadDashboard`, set `#dash-subtitle` from agents length, total technique count (distinct technique ids across runs), and the latest run's `startedAt`/`completedAt` via `ago()`.
- [ ] **Step 3:** Validate + **Commit:** `feat(dashboard): Security Posture hero header + context subtitle`.

## Task 3: KPI tiles (sparkline + trend) + greyed Open-findings

- [ ] **Step 1:** Rebuild `.kpi-row` as 4 `.stat-tile`s: **Open findings** (greyed `.dash-soon`, value "—", "coming soon"), **Prevention score** (real % + `.trend` arrow from `score.trend` + `sparkSVG` of recent runs' prevention scores), **ATT&CK coverage %** (real + spark), **Active campaigns** (count of running, live dot).
- [ ] **Step 2:** In `loadDashboard`, compute the prevention-score series from the last ~8 completed runs (oldest→newest) for the sparkline; coverage % from tactic coverage; active-campaign count from `/api/campaigns` summaries (`status==='running'`).
- [ ] **Step 3:** Validate + **Commit:** `feat(dashboard): KPI stat-tiles with sparklines + trend; grey Open-findings`.

## Task 4: Posture ring-gauge card

- [ ] **Step 1:** Add the `1.3fr/1fr` row. Left card "Posture score": `gaugeSVG(preventionScore)` with center value `/100`, trend label ("Improving"/"Degrading"/"Stable" from `score.trend`), greyed "vs target" stat (`.dash-soon`), and `miniBars` of the last N runs' scores (real). Caption: "Based on the latest N validated runs."
- [ ] **Step 2:** Validate + **Commit:** `feat(dashboard): posture ring gauge + run-history trend bars`.

## Task 5: Control-effectiveness donut — 4-way split

- [ ] **Step 1:** Right card of the row. Reuse `donutSVG` but split the current Prevented/Failed/Not-scored into **Prevented** (pass|blocked), **Detected-only** (fail AND detected — use the per-run detection data the same way the kill-chain does), **Missed** (fail AND not detected), **Not-tested** (error|skipped). Legend with counts; "Open matrix" link → ATT&CK coverage section (or grey if no matrix view).
- [ ] **Step 2:** In `loadDashboard`, classify each result row across runs; detected-vs-missed from each run's `detection_summary`/events (mirror `detectedTechs`/kill-chain logic, client-side from report data already loaded, or from run `results[].events`).
- [ ] **Step 3:** Validate + **Commit:** `feat(dashboard): control-effectiveness donut split — prevented/detected/missed/not-tested`.

## Task 6: Live campaigns (progress bars)

- [ ] **Step 1:** Add the `1fr/1fr` row. Left card "Live campaigns": running campaigns as `.lrow` with icon, name + status badge, scenario·target, **progress bar** (`summary.progress`), `%`. Empty state "No campaigns running". Row click → `openCampaignDetail`. "View all" → `showTab('campaigns')`.
- [ ] **Step 2:** Validate + **Commit:** `feat(dashboard): live campaigns panel with progress bars`.

## Task 7: Top exposure gaps — greyed placeholder

- [ ] **Step 1:** Right card of the row: `.dash-soon` placeholder titled "Top exposure gaps" with a short "Findings triage — coming soon" note and a muted illustration/rows. No data wiring.
- [ ] **Step 2:** Validate + **Commit:** `feat(dashboard): grey 'Top exposure gaps' placeholder (findings backend pending)`.

## Task 8: Attack-flow kill-chain preview

- [ ] **Step 1:** Full-width card "Attack flow · <latest run name>". On dashboard load, fetch the latest completed run's report JSON (`/api/scenarios/runs/{id}/report.json`) and render its `killChain` with the existing dual-rail renderer (Adversary/Defense legend). Link "Open run →" → `viewRunResults`. Empty state if no completed runs.
- [ ] **Step 2:** Validate + **Commit:** `feat(dashboard): attack-flow dual-rail kill-chain preview (latest run)`.

## Task 9: Keep + reposition real panels

- [ ] **Step 1:** Ensure Recent Runs + Top Failing Techniques sit in a `1fr/1fr` row below the live-campaigns row, and ATT&CK Tactic Coverage stays full-width at the bottom. Remove the now-duplicated standalone "Recent Campaigns" panel (superseded by Task 6's Live campaigns).
- [ ] **Step 2:** Validate + **Commit:** `refactor(dashboard): arrange retained panels; drop duplicate recent-campaigns`.

---

## Self-Review

**Coverage:** Hero ✓(T2) · KPI tiles+spark ✓(T3) · posture gauge ✓(T4) · donut split ✓(T5) · live campaigns ✓(T6) · attack-flow ✓(T8) · ATT&CK coverage kept ✓(T9). Grey: Open-findings ✓(T3), Top exposure gaps ✓(T7), vs-target/WoW ✓(T4). Simplified-real trend bars ✓(T4).

**Placeholder scan:** the only intentional "coming soon" stubs are the three greyed items above — explicitly requested. All other tiles wire to existing data/APIs.

**Type/consistency:** new helpers `sparkSVG/gaugeSVG/miniBars` reused across T3/T4; `.stat-tile/.dash-soon/.lrow/.prog` defined once in T1 and consumed T3/T4/T6/T7; donut reuses `donutSVG`; kill-chain reuses the run-drawer renderer (no second copy). Uses our color tokens, not the mockup's `--atk/--def`.

**Risk notes:** T5/T8 depend on per-run detection/kill-chain data being present; both must degrade gracefully (donut falls back to Missed when no detection data; attack-flow shows empty state with no completed runs). No backend changes, so nothing to break server-side.
