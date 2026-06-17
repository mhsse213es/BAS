# Campaigns North-Star Parity Plan

> Inline execution (no subagents). Frontend-only — the Campaigns backend + summary (status/progress/targets/dispatched/skipped/prevented/detected/missed/errored) already exist.

**Goal:** Bring the Campaigns tab up to the `audspect.html` mockup where it adds value, honouring our multi-agent fan-out model (per-agent breakdown stays; we do NOT flatten to the mockup's single-run shape).

**Decisions (locked):** enrich the existing detail **drawer** (not a full page); **grey** the extras we have no backend for (Schedule, Re-run, Export report, Recommended next steps).

**File:** `orchestrator/wwwroot/index.html`. Validate each task: `node -e "...new Function(script)..."`.

---

## Task 1: List hero + status-filter tabs + running progress bar

**What:** Replace the plain `sec-hdr` header on `#tab-campaigns` with a hero (title + subtitle + **Schedule [greyed]** + Refresh + New campaign). Add a segmented status filter (All / Running / Completed / Partial / Failed / Stopped / Empty) with live counts that filters the table client-side. In the Status cell, render an inline progress bar for running campaigns (not just the % text). Add an `id` sub-line under the campaign name.

- [ ] **Step 1:** Edit the `#tab-campaigns` markup: hero block + a `#campaign-toolbar` slot above the table; keep the existing `<table>`/`#campaigns-body`.
- [ ] **Step 2:** `loadCampaigns()` keeps the full list in `window._campaigns`, computes status counts, renders the filter segments (reuse `.cov-seg` styles), then calls `renderCampaignRows()`.
- [ ] **Step 3:** `renderCampaignRows()` filters by `CAMPAIGN_TAB`, renders rows (name + `id` sub; scenario; targets; status badge + inline `.prog` bar when running; `campaignMixBar`; started). `setCampaignTab(v)` re-renders.
- [ ] **Step 4:** Validate + commit: `feat(campaigns): list hero + status-filter tabs + inline progress`.

## Task 2: Detail drawer — result-mix stat tiles + greyed extras

**What:** In `openCampaignDetail`, add a second tile row — **Effectiveness / Prevented / Detected only / Missed** — computed from the summary (`effectiveness = round((prevented*100 + detected*50) / (prevented+detected+missed))`). Keep the existing Status/Progress/Dispatched/Skipped row (agent reconciliation) and the per-agent runs (our fan-out strength). For completed campaigns, show greyed `Export report · soon` / `Re-run · soon` buttons in the action area; add a greyed "Recommended next steps — coming soon" mini-block. Stop stays for running.

- [ ] **Step 1:** Add the result-mix tile row + effectiveness calc.
- [ ] **Step 2:** Action area: Stop (running) or greyed Export/Re-run (terminal); append greyed recommendations block.
- [ ] **Step 3:** Validate + commit: `feat(campaigns): detail result-mix tiles + greyed export/re-run/recommendations`.

---

## Self-review
- Honesty: all tile values come from the real campaign summary; effectiveness mirrors the mockup's weighting. Per-agent kill-chains stay reachable via each run's drawer (no fabricated campaign-level aggregate flow). Greyed items are clearly "coming soon".
- Consistency: reuse `.cov-seg` (filter), `.prog`/`.sbadge`/`campaignMixBar`, `dash-soon`/disabled styling for greys. Status taxonomy = our six campaign statuses.
- No backend change.
