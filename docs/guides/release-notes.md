# Audspect BAS — Release Notes

---

## v1.7.3 (Current) — 2026-07-03

### New Features

**Reporting Suite (Cymulate-style)**
- Full HTML/PDF/CSV reporting for per-run, full-agent, campaign, audit-pack, compliance, and exercise types
- PDF generation via headless Chromium sidecar (replaces Go-native PDF)
- Audit pack ZIP: HTML + PDF + CSV + raw JSON + SHA-256 manifest per agent
- MITRE ATT&CK Navigator export (JSON attack flow) per run

**Attack Path Validation — Job Lifecycle**
- AP collection now uses a tracked job system: queued → dispatched → running → completed/failed
- Full job lifecycle visible in dashboard: Attack Path section + new Attack Path tab in agent detail drawer
- Real-time progress streaming via WebSocket: stages, percentage, targets-completed/total
- Auto-retry on agent reconnect for queued jobs
- AP job scheduling: recurring collections per agent with cron expressions

**Findings and Remediation**
- Structured finding lifecycle: Created → Open → In Progress → Validated → Resolved / False Positive / Suppressed / Archived
- Automatic closure: 3 consecutive passes auto-resolves Created/Open findings
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
- `GET /api/attackpath/collect` (fire-and-forget) is deprecated in favor of `POST /api/attackpath/jobs`. The old endpoint is retained for backward compatibility.
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
- Web wizard installer (browser-based setup flow replacing whiptail)
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
