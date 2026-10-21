# Audspect BAS — Reporting Guide

**Platform Version:** v1.7.3

---

## Overview

Audspect BAS v1.7.3 ships a comprehensive Cymulate-style reporting suite. Reports are rendered from HTML templates and converted to PDF via a headless Chromium sidecar; if the sidecar is unavailable, the built-in renderer is used instead. Reports can be generated on demand or scheduled.

Audit packs carry a SHA-256 manifest and a signed attestation, so their contents can be verified after generation. See Report Integrity Verification below.

---

## Available Report Types

### Per-Run Report

A detailed report for a single scenario execution on a single agent.

**Contents:**
- Run metadata (scenario, agent, start/end time, operator)
- Executive summary: Prevention Score, Exposure Score, Risk Classification, Trend
- Kill chain heatmap: pass/fail breakdown by MITRE ATT&CK tactic
- Step-by-step table: technique ID, tactic, severity, verdict, raw output, remediation
- Score breakdown with calculation methodology
- Appendix: scoring weights and formulas

**Formats:** HTML, PDF, CSV (step-level data), JSON (full structured output)

**Access:**
- Dashboard: Live Runs → [run] → Reports tab → PDF Report
- API: `GET /api/scenarios/runs/{runId}/report` (HTML)
- API: `GET /api/scenarios/runs/{runId}/pdf` (PDF)
- API: `GET /api/scenarios/runs/{runId}/forensic.csv` (CSV)
- API: `GET /api/scenarios/runs/{runId}/export` (JSON)

---

### Full Agent Report

An aggregated report covering all runs for a single agent, across all scenarios.

**Contents:**
- Agent profile: hostname, OS, enrollment date, last seen
- Posture trend: Prevention Score over time (last 90 days)
- Tactic coverage matrix: pass rates per MITRE ATT&CK tactic
- Top failing techniques (most frequent failures across all runs)
- Scenario breakdown: latest run per scenario with score
- Comparison vs. baseline (first run per scenario)
- Finding summary: open/in-progress counts by severity

**Formats:** HTML, PDF, CSV (per-run scores)

**Access:**
- Dashboard: Reports → [agent] → PDF Report
- API: `GET /api/report/full/{html|pdf|csv|json}?agentId={agentId}`

---

### Audit Pack

A ZIP archive containing a complete assessment record for one agent. Intended for compliance, audit, and management review.

**Contents:**
- `executive-report.html` — Executive HTML report
- `executive-report.pdf` — Executive PDF report
- `summary.json` — Full machine-readable report
- `runs/*.json` — Raw structured JSON for each run (machine-readable, suitable for SIEM/SOAR)
- `compliance/*.csv` — One CSV per compliance framework
- `agent-inventory.json` — Agent metadata, security tools, and detection categories
- `MANIFEST.sha256` — SHA-256 checksum of every file in the ZIP
- `SIGNATURE.txt` and `attestation.json` — Signed digest of the manifest (tamper evidence)
- `README.txt` — What the pack contains and how to verify integrity

**Access:**
- Dashboard: Reports → [agent] → Audit pack
- API: `GET /api/report/audit-pack?agentId={agentId}` (the agent needs at least one completed or partial run)

---

### Campaign Report

A unified report across all agents and scenarios in a Campaign.

**Contents:**
- Campaign metadata and configuration
- Cross-agent score comparison table
- Attack surface heatmap: which tactics are failing across the fleet
- Per-agent summaries with quick-link to individual run reports
- Campaign-level Prevention Score (fleet-wide average, weighted by step count)
- Top N failing techniques across the fleet

**Formats:** HTML, PDF, CSV

**Access:**
- Dashboard: Campaigns → [campaign] → HTML Report / PDF Report
- API: `GET /api/campaigns/{id}/report` (HTML), `GET /api/campaigns/{id}/pdf` (PDF), `GET /api/campaigns/{id}/forensic.csv` (CSV)

---

### Compliance Report

A framework-mapped control gap report. Shows which ATT&CK techniques are tested, which are failing, and which controls map to specific framework requirements.

**Supported frameworks:**
- NIST Cybersecurity Framework 2.0 (`NIST_CSF_2`)
- ISO/IEC 27001:2022 (`ISO_27001_2022`)
- PCI DSS v4.0 (`PCI_DSS_V4`)
- RBI Cybersecurity, Technology Risk, Resilience and Assurance Framework (`RBI_CSF`)
- SEBI Cyber Security and Cyber Resilience Framework (`SEBI_CSCRF`)
- CERT-In Directions on Information Security Practices (`CERT_IN`)
- IRDAI Cyber Security Guidelines (`IRDAI_CSF`)

**Contents:**
- Framework summary: tested controls, failing controls, compliance score
- Technique-to-control mapping table
- Gap analysis: which framework controls have no test coverage
- Remediation priority list: ordered by compliance impact

**Formats:** JSON, CSV

**Access:**
- API: `GET /api/compliance/report?framework={frameworkId}&agentId={agentId}` (add `format=csv` for CSV)

---

### Exercise Report (Purple Team)

A structured report for a Purple Team exercise execution.

**Contents:**
- Exercise plan and execution metadata
- Step-by-step execution record with blue team detection evidence
- Detection rate: which steps were detected vs. missed
- MITRE ATT&CK mapping for each step
- Evidence chain: analyst notes, screenshots, artifacts per step
- Executive summary: overall detection rate, gaps, recommendations

**Formats:** HTML, PDF, CSV, JSON (structured evidence export)

**Access:**
- API: `GET /api/exercises/executions/{id}/report.{json|html|pdf|csv}`

---

### Attack Flow Report

A single-run visual attack flow diagram showing the kill chain progression of a completed run, rendered as a MITRE ATT&CK Navigator layer JSON.

**Format:** JSON (ATT&CK Navigator compatible)

**Access:**
- API: `GET /api/scenarios/runs/{runId}/attackflow`
- Import directly into MITRE ATT&CK Navigator for visualization

---

## PDF Generation

PDFs are generated by a headless Chromium sidecar container included in the deployment. The flow:

1. Orchestrator renders the report as HTML using Go templates
2. Orchestrator calls the Chromium sidecar via local HTTP
3. Chromium renders the HTML and generates PDF (A4, print media, background graphics enabled)
4. PDF returned to the requesting client

**Troubleshooting PDF generation:**
- Chromium sidecar not running → PDFs fall back to the built-in renderer; check the container with `docker ps | grep chrome`
- Slow PDF generation (>30 seconds) → Chromium resource limits
- Missing fonts → Fonts are embedded in the HTML; no external requests are made

---

## Report Scheduling

Scheduled reports are managed by an administrator at `/api/report/schedules` (list, create, update, delete, and run now at `POST /api/report/schedules/{id}/run`). Each schedule sets:

- `reportType`: `board`, `compliance`, or `audit_pack`
- `scopeKind` and `scopeId`: an agent or a campaign
- `framework`: for compliance schedules
- `format`: `pdf` or `html` (audit packs are always ZIP)
- `frequency`: `daily`, `weekly`, or `monthly`, with `hourUtc`, and `dayOfWeek` (0 = Sunday) for weekly or `dayOfMonth` (1–28) for monthly
- `recipients`, `name`, and `enabled`

```
POST /api/report/schedules
Body:
{
  "name": "Weekly board report",
  "reportType": "board",
  "scopeKind": "campaign",
  "scopeId": "<campaignId>",
  "format": "pdf",
  "recipients": "ciso@company.com,secops@company.com",
  "frequency": "weekly",
  "hourUtc": 6,
  "dayOfWeek": 1,
  "enabled": true
}
```

---

## Export Formats

| Format | MIME Type | Description |
|---|---|---|
| HTML | `text/html` | Interactive, with charts, collapsible sections |
| PDF | `application/pdf` | Print-ready, paginated, embedded fonts |
| CSV | `text/csv` | Flat table: one row per step or per run |
| JSON | `application/json` | Structured data: complete run object with nested steps |
| ZIP | `application/zip` | Audit pack containing multiple formats |
| ATT&CK Navigator JSON | `application/json` | ATT&CK layer for visualization in Navigator |

---

## Storage and Naming Conventions

Reports are generated on demand or on schedule. Each generation is logged to the `report_log` table, which holds metadata only (report type, format, scope, generated by, time), not the report content.

**Report filename conventions (when downloaded):**

Downloaded report files are named `Audspect_<ReportType>_<scope>_<YYYY-MM-DD_HH-MM-SS>.<ext>` (UTC timestamp), for example `Audspect_Audit_Pack_<scope>_<timestamp>.zip` for an audit pack. The scope is truncated to 80 characters, and any character other than a letter, digit, `-` or `_` is replaced with `_`.

---

## Report Integrity Verification

**Audit pack:** `MANIFEST.sha256` in the ZIP lists the SHA-256 digest and path of every file, one per line. Verify it from inside the extracted folder with `sha256sum -c MANIFEST.sha256`. `SIGNATURE.txt` and `attestation.json` bind a digest of the manifest to the generator identity and time. The attestation is an HMAC-SHA256 signature when the deployment has a signing secret configured; otherwise it carries a SHA-256 digest only (`Algorithm: SHA-256 (unsigned)`).

**Compliance and board reports:** each carries an attestation footer with its SHA-256 digest and algorithm.

---

## Executive Summaries

The HTML version of Full Agent Reports and Campaign Reports includes a dedicated **Executive Summary** section designed for non-technical readers:

- Plain-language risk classification (Protected / Low / Medium / High / Critical)
- Comparison to previous period
- Trend direction badge

This section is rendered at the top of the HTML report and on page 1 of the PDF, separate from the technical detail.

---

## Technical Summaries

The HTML and PDF reports include a **Technical Summary** section for security operations:

- Severity-bucketed step counts (Critical FAIL, High FAIL, etc.)
- Tactic coverage matrix
- Steps requiring immediate remediation (Critical severity, Fail verdict)
- Detection coverage (for Purple Team integration)
- Detailed step output for failed steps

---

## Watermarking

Reports carry a **CONFIDENTIAL** classification label in the page header of each section. It is printed as text in the report, not as a background watermark.

---

*© Audspect — Confidential — Customer Distribution*
