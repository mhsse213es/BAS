# Implementation Plan — Dashboard North-Star Parity

Address the visual, component-level, and feature gaps in the main dashboard (`index.html`) to align it with the design vision in `audspect.html`.

## User Review Required

We are moving the dashboard structure to match the layout of `audspect.html`. This includes:
- **Hero Header:** Standardizing page titles, subtitle telemetry, and global actions.
- **SVG Visualizations:** Custom CSS styles and inline SVG generators for sparklines, 270-degree radial posture gauges, control-effectiveness donuts, and historical trend bars.
- **Placeholder Management:** Intentionally graying out pending features (Open Findings, Top Exposure Gaps) that require future backend work (triage database, persistent findings store), while keeping real dashboard panels (Top Failing Techniques, Recent Runs, ATT&CK Coverage) operational.

> [!IMPORTANT]
> The implementation will be purely frontend-focused in `index.html`, utilizing the backend APIs already available (such as the newly enabled `killChain` field in `/api/scenarios/runs/{id}/report.json` and the runs/agents list APIs).

---

## Proposed Changes

### Dashboard Component

#### [MODIFY] [index.html](file:///c:/Users/Administrator/Downloads/Audspect_Cloud/orchestrator/wwwroot/index.html)

- **Task 1: Visual Primitives (CSS & SVG helpers)**
  - Define utility classes for `.stat-tile`, `.trend.up/.down/.flat`, `.ring-c`, `.prog`, and `.dash-soon` (grayed placeholder ribbon/borders).
  - Implement JS helper functions in the `<script>` block:
    - `sparkSVG(data, w, h, color)`: Custom polyline + area-fill sparkline.
    - `gaugeSVG(value, size, stroke)`: 270-degree arc gauge rendering.
    - `miniBars(data, w, h)`: Historical run-by-run score columns.

- **Task 2: Hero Header & Title**
  - Replace the `#tab-dashboard` top header with:
    - Heading: `<h1>Security Posture</h1>`
    - Subtitle: `#dash-subtitle` ("Continuous validation across N agents and M techniques. Last assessment X ago.")
    - Actions: `New simulation` (opens the run wizard) and `Generate report` (switches to compliance tab).

- **Task 3: KPI Tiles & Sparklines**
  - Re-engineer the top stat row to contain 4 `.stat-tile` blocks:
    1.  **Open Findings** (grayed out placeholder).
    2.  **Prevention Score** (wires latest prevention score + trend + SVG sparkline of the last 8 runs).
    3.  **ATT&CK Coverage** (wires tactic coverage % + sparkline).
    4.  **Active Campaigns** (wires active/running campaigns count + live blinking dot).

- **Task 4: Posture Score & Trend Bars**
  - Create a two-column card row (`1.3fr / 1fr`):
    - Left card: **Posture Score** containing the radial `gaugeSVG` displaying the latest score, overall trend, and historical `miniBars` representing scores of the last N runs.

- **Task 5: Control Effectiveness Donut Chart**
  - Right card of the row: **Control Effectiveness** donut chart displaying a 4-way split:
    - **Prevented** (pass/blocked actions).
    - **Detected Only** (failed runs with matching security alerts/telemetry).
    - **Missed** (failed runs with no alerts).
    - **Not-Tested** (errors/warnings/skipped steps).

- **Task 6: Live Campaigns & Progress**
  - Create a two-column card row below the posture row:
    - Left card: **Live Campaigns** displaying active campaigns from `/api/campaigns` as list rows with progress bars, scenario metadata, and click navigation to campaign details.
    - Right card: **Top Exposure Gaps** (grayed-out placeholder for findings triage).

- **Task 7: Retain and Re-arrange Existing Panels**
  - Place **Recent Runs** and **Top Failing Techniques** side-by-side.
  - Full-width card: **Attack Flow** displaying the dual-rail kill-chain graph of the latest completed simulation run.
  - Keep the full-width **ATT&CK Tactic Coverage** matrix at the bottom.

---

## Verification Plan

### Automated Tests
- Validate that the modified `index.html` remains syntactically valid and parses correctly:
  ```powershell
  node -e "const fs=require('fs');const h=fs.readFileSync('orchestrator/wwwroot/index.html','utf8');const m=h.match(/<script>([\s\S]*)<\/script>/);new Function(m[1]);console.log('JavaScript Syntax Check: OK');"
  ```

### Manual Verification
- Open the dashboard page in the browser.
- Verify that the layout adjusts to the new layout grid.
- Verify that the radial gauge, sparklines, and donuts render correctly.
- Verify that the "Attack Flow" preview matches the latest completed run.
- Click the navigation actions and verify they transition to the correct tabs.
