# Audspect BAS — Release Notes

---

## v1.9.6 — console redesign (unreleased)

The web console has a new look. Every screen keeps its existing behaviour, data and permissions.

- New header banner on every page: title, one-line description, the page's actions, and live counts taken from the same data the page already loads
- Breadcrumb row with the time the page was last refreshed
- Sidebar: rounded items, the Audspect mark on a transparent background (readable on dark and light themes; the shield alone when collapsed), and an off-canvas drawer on narrow screens
- All four themes (Dark, Light, Cyberpunk, Slate) share one set of colour tokens, so the Light theme now has a light sidebar and header, and status text stays readable on light backgrounds
- Sign-in page: form card, larger logo, stacked layout on narrow screens
- Settings: side navigation becomes a card, and tabs on narrow screens
- Every page now has the demo's richer layout: KPI tiles, donut/bar/line charts, cards, filters and polished tables. Every number comes from data the page already loads; widgets that would need data the server does not provide were left out
- Sidebar: count badges (agents offline or degraded, open findings, running campaigns), a pin star on each item, and Pinned and Recent groups (saved in the browser only)
- Windows agent: the service now checks every 30 seconds that the tray icon process is running and restarts it; a top-level Start Menu entry "Audspect Agent" brings the tray back by hand (MSI and CLI install); starting the tray from a shortcut no longer shows a console window
- Fixes found on the way: the Factory health and Email pages no longer throw when the server returns an empty or unexpected response

---

## v1.7.3 (Current) — 2026-07-03

### New Features

**Reporting Suite (Cymulate-style)**
- Full HTML/PDF/CSV reporting for per-run, full-agent, campaign, audit-pack, compliance, and exercise types
- PDF generation via headless Chromium sidecar; the built-in Go (fpdf) renderer is the fallback when the sidecar is unavailable
- Audit pack ZIP per agent: executive HTML and PDF, summary and per-run JSON, per-framework compliance CSVs, agent inventory, SHA-256 manifest (`MANIFEST.sha256`) and signed attestation
- MITRE ATT&CK Navigator export (JSON attack flow) per run

**Attack Path Validation — Job Lifecycle**
- AP collection now uses a tracked job system: queued → dispatched → running → completed/failed/timed_out/delivery_failed/cancelled
- Full job lifecycle visible in dashboard: Attack Path section + new Attack Path tab in agent detail drawer
- Real-time progress streaming via WebSocket: stages, percentage, targets-completed/total
- Auto-retry on agent reconnect for queued jobs
- AP job scheduling: recurring collections on a fixed interval in minutes (`intervalMinutes`), with targets and optional SharpHound run

**Findings and Remediation**
- Finding statuses: `open`, `triaged`, `remediated`, `risk_accepted`
- Re-validate: targeted single-technique dispatch with before/after evidence comparison
- Bulk operations: multi-select status change, bulk ticket creation, bulk CSV export

**Purple Team Exercise Engine**
- Exercise plans with step-by-step blue team approval
- Evidence chain: notes, artifacts, screenshots per step
- SMTP phishing injection for realistic exercise scenarios
- HTML/PDF/CSV/JSON exercise reports with full evidence chain

**Threat Intelligence Integration**
- MISP connector: pull events and indicators, auto-generate scenarios
- OpenCTI connector: pull STIX bundles, auto-generate scenarios
- Configurable polling interval, sector filter, region filter

**Security Enhancements**
- PBKDF2-HMAC-SHA256 replaces bcrypt for all new password storage
  - 310,000 iterations (NIST SP 800-132 minimum)
  - Transparent migration: bcrypt hashes re-hash on next login
- Scenario RSA-4096 signing enforced on all load and dispatch
- 15-second filesystem watcher for scenario tamper detection
- Agent binary trust verification on every heartbeat

**Variant Engine**
- Technique families: group related techniques for coverage analytics
- Payload families: track payload variants across runs

### Bug Fixes

- `450fca3` — Reporting: audit-pack HTML generation crash on `priorityScore` comparison with nil pointer
- `4f9e39d` — UI: re-validate step shows exact technique ID (was showing scenario ID in some flows)
- `22314a0` — Remediation: re-validate now correctly targets the specific failing technique for `artAllWindows` scenarios
- `dbc85e6` — Installer: `BAS_ADMIN_EMAIL` env var now correctly passed to orchestrator container
- `c1dc508` — Audit pack: new PDF design applied; removed redundant legacy PDF button

### Breaking Changes

- Passwords stored with bcrypt are transparently upgraded to PBKDF2 on next login. There is no fallback to bcrypt for writing new hashes.
- `POST /api/attackpath/collect/{agentId}` (fire-and-forget dispatch) is superseded by `POST /api/attackpath/jobs`. The old endpoint is retained for backward compatibility.
- Report MIME type for audit pack changed from `application/zip` with filename suffix to explicit `Content-Disposition: attachment; filename="bas-audit-pack-*.zip"`.

---

## v1.7.2 — 2026-06-15

### New Features
- Campaign reporting: multi-agent, multi-scenario unified report
- Compliance dashboard: per-framework control gap view
- Posture catalog: per-OS check catalog harvested at enrollment

### Bug Fixes
- Fixed: campaign score incorrectly excluded zero-FAIL agents from denominator
- Fixed: posture catalog showing empty after agent upgrade (re-enroll required)
- Fixed: ART prerequisite check failing on Windows Server 2016 (WinAPI compat)

---

## v1.7.1 — 2026-05-20

### New Features
- Pre-seed config file support (`setup.conf`) for automated deployments
- Scenario YAML upload via dashboard

### Bug Fixes
- Fixed: scenario delete leaving orphaned `.sig` files
- Fixed: live run WebSocket dropped after 60 seconds behind nginx (missing `proxy_read_timeout`)
- Fixed: ART all-windows runs not cleanly marking Partial on agent reconnect

---

## v1.7.0 — 2026-04-10

### New Features
- Multi-context execution: Posture / Telemetry / Lab execution modes
- Hybrid scenario framework: mix ART + Custom steps in one scenario
- Attack Path Validation: initial release (fire-and-forget dispatch, no job lifecycle)
- SharpHound integration for Active Directory relationship collection
- Ticket integration: ServiceNow and Jira webhook-based finding tickets

### Bug Fixes
- Fixed: scoring engine division-by-zero when all steps are SKIPPED
- Fixed: agent state not updating to Active after reconnect under load
- Fixed: report download filename collision when multiple agents share a hostname

---

## v1.6.0 — 2026-01-15

### First General Availability Release

- Core BAS simulation engine: ART + Caldera + Custom frameworks
- Prevention Score, Exposure Score, Coverage Score, Kill Chain Amplifier
- Four-verdict taxonomy: PASS / FAIL / ERROR / SKIPPED
- Per-run findings creation and deduplication
- Basic HTML reports
- MITRE ATT&CK v14 mapping
- RSA-4096 scenario signing
- Agent binary trust verification
- Three-role RBAC (Viewer / Analyst / Admin)
- PBKDF2-HMAC-SHA256 password hashing
- Caldera CTID adversary emulation library integration

---

*© Audspect — Confidential — Customer Distribution*
