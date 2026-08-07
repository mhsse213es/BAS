# Native Status Console Visual Redesign — Design

## Context

`agent/statuswindow_windows.go` (built earlier this session, commits `326cc63`..`992399a`) opens a real native Win32 window via `windigo` instead of the browser, replacing the abandoned WebView2 approach. It works and was live-verified against a real production-connected agent, but it uses stock `windigo` controls (`ui.Static`, `ui.Button`, `ui.ListView`, `ui.ProgressBar`), which render with the default flat-grey Windows theme — confirmed "retro"-looking against the existing browser dashboard (`agent/ui_dashboard.html`, served at `/`), which uses a dark navy, card-based design with colored status pills and icons (screenshotted live at `http://127.0.0.1:9001` during this session).

This spec covers rewriting the native window's *rendering* to visually match the browser dashboard via owner-drawn GDI, while leaving the underlying architecture (statusclient → StatusSnapshot/StatusWindow → StatusController) untouched.

## Goal

Make the native status console look like a deliberately designed enterprise security-agent console (in the spirit of how CrowdStrike/Trellix/Trend Micro present local agent status) instead of a stock Win32 dialog, by fully owner-drawing the window instead of relying on stock controls.

## Non-Goals

- No change to `statusclient`, `StatusSnapshot`, `StatusWindow` interface, or `StatusController` (Tasks 1-3 of the original plan stand as-is).
- No change to `browserWindow` or the native-creation-failure fallback path (Task 4's fallback logic stands as-is).
- No change to Task 8's comment cleanup.
- No window resizing, no scrolling (approved: tall fixed window instead).
- No embedded custom font (Inter) — uses Segoe UI, the OS-native equivalent.
- No GDI+ / alpha-blended bitmap icons — icons are hand-drawn GDI vector glyphs (approved trade-off: less pixel-perfect than the browser's icon set, but zero asset pipeline, fully self-contained in the Go binary).
- No animation/transition effects.

## Architecture

Unchanged 4-layer flow:

```
statusclient (HTTP/JSON) → StatusSnapshot/StatusWindow interface → StatusController (adaptive polling) → windigoWindow (presentation)
```

Only `windigoWindow`'s internals change. `StatusController.Run()` still calls `window.Refresh(snap)` from its own goroutine; `Refresh` still marshals onto the UI thread via `sw.wnd.UiThread(...)`. The difference is what happens once on the UI thread: instead of calling `SetTextAndResize` on a tree of pre-created stock controls, `Refresh` stores the snapshot and triggers a repaint; a `WM_PAINT` handler does all the drawing.

### File split

- **`agent/statuswindow_windows.go`** (rewritten) — window lifecycle (`newWindigoWindow`, `Show`/`Close`/`Refresh`), holds `latest StatusSnapshot`, wires `WM_PAINT` to the canvas renderer, wires `WM_LBUTTONUP` to hit-test the two action buttons and forward clicks to `controller.ExportDiagnostics()` / `controller.OpenDashboard(...)`, exactly as today's `btnExport.On().BnClicked` does.
- **`agent/statuscanvas_windows.go`** (new) — pure GDI drawing primitives and the full-frame paint routine. No knowledge of `StatusController` or networking; takes a `StatusSnapshot` and a device context, draws the frame, and returns the button hit-rects for the window-lifecycle file to store.

This mirrors the isolation the original plan already established between networking/business-logic and presentation — this spec just draws that same line one layer deeper, between "what to draw" and "how to draw."

## Visual Design

### Palette (reuses the existing dashboard design-system tokens, not new values)

| Token | Hex | Use |
|---|---|---|
| `bg` | `#0b1420` | Window background |
| `card` | `#152338` | Card fill |
| `elevated` | `#1b2a41` | Stat tiles / nested surfaces inside cards |
| `border` | `#22324a` | Card borders (1px) |
| `accent` | `#2f81f7` | Primary buttons, header icon badge, links |
| `muted` | `#9aa9bc` | Secondary/label text |
| `success` | `#238636` | "ACTIVE"/"HEALTHY"/"Connected" badges |
| `warning` | `#d29922` | "CHECK"/"DEGRADED" badges |
| `danger` | `#da3633` | "ABSENT"/offline/disconnected states |
| text primary | `#e6edf3` | Headline/value text (new token, matches typical text-on-navy contrast; not previously defined since the native window had no dark background before) |

### Typography

Segoe UI (always present on Windows, closest native equivalent to the dashboard's Inter). Three weights via `CreateFont`: Semibold ~15pt for card headers and the hero state word, Regular ~10pt for body/labels, Semibold ~20pt for the hero's big state word (e.g. "Idle"/"Active").

### Window chrome

Dark title bar via `DwmSetWindowAttribute(hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE, ...)` so the OS-drawn title bar doesn't clash with the owner-drawn body. Fixed size, not resizable (matches current behavior).

### Layout (top to bottom, single column of full-width and half-width cards, mirroring the browser dashboard's section order)

1. **Page header** (not a card — sits directly on `bg`): small accent-colored rounded-square badge with a hand-drawn shield glyph, "Audspect BAS Agent" title + "Breach & Attack Simulation · Endpoint Defense Validation" subtitle on the left; agent version chip + a colored state pill (dot + word, e.g. "Idle"/"Active"/"Disconnected") on the right.
2. **Hero card**: left edge 4px accent-colored bar (color reflects state: success=healthy/idle, warning=paused, danger=disconnected/quarantined/restricted — same states `render()` already switches on today). Icon + eyebrow label "ENDPOINT PROTECTION STATUS" + big state word + one-line description, hostname right-aligned muted.
3. **Two-column row**: **Connection** card (icon+header, then Server/Link/Lifecycle State/Uptime/Last Heartbeat rows — same 5 fields as today's `lblConn*`) and **Current Operation** card (icon+header, scenario title, meta line, progress bar, result line — same fields as today's `renderOperation`).
4. **Endpoint Security Controls** card (full width): 2-column × 3-row grid of the same 6 controls (Defender RTP, Sysmon, Firewall, AppLocker, WDAC, AMSI), each a colored dot + name + right-aligned pill badge (ACTIVE=success, DEGRADED=warning, ABSENT=danger) instead of today's `[STATUS]` bracket text.
5. **Two-column row**: **Evidence · Last Run** card (2×2 grid of stat tiles — Events Collected, Defender Alerts, Sysmon Detections, Upload Queue, same 4 fields as today's `lblEv*`) and **Self-Protection** card (5 rows — Service Running, Policy Sync, Evidence Queue, Last Upload OK, Server Contact — same fields as today's `lblSp*`, each with a HEALTHY=success/CHECK=warning pill).
6. **Resources** card (full width): 3 stat tiles — Memory, Agent Version, Agent ID (same fields as today's `lblRes*`).
7. **Recent Activity** card (full width, fixed row count since there's no scrolling — show the most recent 8 entries, same data source and same diff-aware fingerprint skip-repaint logic as today's `renderActivity`/`activityFingerprint`, just painted rows instead of a `ListView`).
8. **Action row**: two owner-drawn buttons ("Export Diagnostic Bundle", "Open BAS Console" — same two actions as today) left-aligned, "Updated HH:MM:SS" muted timestamp right-aligned.

Exact pixel coordinates, card heights, and the resulting total window size are a plan-writing concern (the plan will compute concrete values from this section's content and spacing rules: 24px page margin, 16px inter-card gap, cards use 16px internal padding). The window grows tall enough to fit all 8 sections without scrolling.

### Offline state

When `StatusSnapshot.Online == false`, the header state pill and hero card render in the `danger` color with "Agent Unreachable" / "The local agent service is not responding" text, hostname omitted (unknown), and all data cards render their prior/blank state rather than freezing on stale numbers — mirrors what `render()` already special-cases today, just restyled.

### Icons (hand-drawn GDI glyphs, ~16-20px)

- **Shield** (header badge, Endpoint Security Controls header): simple 5-point shield outline via `Polygon`/`Polyline`, optionally with a checkmark inside for "controls" context.
- **Signal bars** (Connection header): 3 vertical bars of increasing height via `FillRect`.
- **Clock** (Current Operation header): circle (`Ellipse`) + two lines from center to edge (`MoveToEx`/`LineTo`).
- **Check-badge** (Evidence header): circle with a checkmark inside.
- **Pin/location** (Self-Protection header): teardrop via `Polygon` (or a simplified circle-with-point).
- **Monitor** (Resources header): rounded rect + small stand, via `RoundRect` + `FillRect`.
- **Activity/pulse** (Recent Activity header): simple zigzag line via `Polyline`.
- **Status dots** (used throughout — control rows, self-protection rows, header pill): filled `Ellipse`, colored per state.

Each is a small (~10-20 line) drawing function taking a top-left point and a color, callable from the card-header-drawing primitive.

### Buttons

Owner-drawn: rounded rect (`RoundRect`) filled `elevated` (secondary) or `accent` (primary — "Open BAS Console" is primary, matching the browser dashboard's blue-filled button; "Export Diagnostic Bundle" is secondary/outlined), centered label text. Hit-testing: the paint routine records each button's rect; `WM_LBUTTONUP` checks the click point against stored rects and invokes the matching controller call — same two calls as today's `BnClicked` handlers, just dispatched manually instead of via a stock `ui.Button`.

## Testing

- No behavior change to `statusclient`/`statuscontroller` — their existing unit tests (`statusclient_test.go`, `statuscontroller_test.go`) are untouched and must keep passing.
- Pure helper functions that survive the rewrite unchanged in purpose (`formatUptime`, `orDash`, `activityFingerprint`, and the state→badge-color mapping used across Controls/Self-Protection/Evidence) keep or gain unit tests — these are the only genuinely unit-testable pieces of this rewrite.
- GDI painting itself is verified manually: same `PrintWindow`-based screenshot technique already used this session (`GetWindowRect` + `PrintWindow` + save PNG), run against a live agent (real or test) after each major section is wired up, plus a final full-window pass.
- Manual click-testing of both owner-drawn buttons (hit-test correctness) is a new manual-verification item, added to whatever Task 9-equivalent closes this out.
- Build/vet/`go test ./...` plus `GOOS=linux`/`GOOS=darwin` cross-compile checks after every task, matching this session's established discipline (`agent/statuscanvas_windows.go` and the rewritten `agent/statuswindow_windows.go` both carry `//go:build windows`, same as today).

## Migration Note

This supersedes the *rendering* portions of Tasks 4-7 in `docs/superpowers/plans/2026-08-07-native-status-console.md` (the stock-control creation and `render*` methods). Tasks 1-3 (statusclient, StatusWindow interface, StatusController) and Task 8 (comment cleanup) are unaffected and remain the foundation this rewrite builds on.
