# Audspect BAS — Reporting Guide

**Platform Version:** v1.7.3

---

## Overview

Audspect BAS v1.7.3 ships a comprehensive Cymulate-style reporting suite. Every report is rendered from a live HTML template and converted to PDF via a headless Chromium sidecar. Reports can be generated on demand or scheduled.

All generated reports embed a SHA-256 integrity hash in the file header, allowing verification that report content has not been altered after generation.

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
- Dashboard: Scenarios → Runs → [run] → Download Report
- API: `GET /api/scenarios/runs/{runId}/report?format=html`
- API: `GET /api/scenarios/runs/{runId}/report?format=pdf`
- API: `GET /api/scenarios/runs/{runId}/report?format=csv`

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
- Dashboard: Agents → [agent] → Reports → Full Agent Report
- API: `GET /api/report/agent/{agentId}?format=pdf`

---

### Audit Pack

A ZIP archive containing a complete assessment record for one agent. Intended for compliance, audit, and management review.

**Contents:**
- `report.html` — Full agent HTML report
- `report.pdf` — Full agent PDF report
- `data.csv` — Run-level CSV export
- `runs/*.json` — Raw structured JSON for each run (machine-readable, suitable for SIEM/SOAR)
- `manifest.json` — SHA-256 hashes of all files in the ZIP
- `README.txt` — What the pack contains and how to verify integrity

**Access:**
- Dashboard: Agents → [agent] → Reports → Download Audit Pack
- API: `GET /api/report/agent/{agentId}/auditpack`

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
- Dashboard: Campaigns → [campaign] → Report
- API: `GET /api/campaigns/{id}/report?format=pdf`

---

### Compliance Report

A framework-mapped control gap report. Shows which ATT&CK techniques are tested, which are failing, and which controls map to specific framework requirements.

**Supported frameworks:**
- MITRE ATT&CK v14
- RBI Cyber Security Framework
- SEBI Cybersecurity Circular (MII)
- CIS Benchmarks (L1)
- NIST SP 800-53 (mapped via technique coverage)
- ISO 27001 (mapped via control families)

**Contents:**
- Framework summary: tested controls, failing controls, compliance score
- Technique-to-control mapping table
- Gap analysis: which framework controls have no test coverage
- Remediation priority list: ordered by compliance impact

**Formats:** HTML, PDF

**Access:**
- Dashboard: Compliance → [framework] → Download Report
- API: `GET /api/compliance/report/{framework}?format=pdf`

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
- Dashboard: Exercises → [execution] → Report
- API: `GET /api/exercises/executions/{id}/report?format=pdf`

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
- Blank PDF → Chromium container not running: `docker ps | grep chromium`
- Slow PDF generation (>30 seconds) → Chromium resource limits; increase container memory to 1 GB
- Missing fonts → Fonts are embedded in the HTML; no external requests are made

---

## Report Scheduling

Reports can be scheduled using the Campaign scheduling system:

1. Create a Campaign with the desired scenarios and agents
2. Set a schedule: daily, weekly, monthly, or custom cron expression
3. When the campaign runs automatically, a Campaign Report is generated and stored
4. Optional: configure SMTP to email the PDF report to specified addresses on completion

```
POST /api/campaigns/{id}/schedule
Body:
{
  "cronExpression": "0 6 * * 1",    // Every Monday at 06:00
  "reportFormats": ["pdf", "csv"],
  "emailRecipients": ["ciso@company.com", "secops@company.com"]
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

Generated report files are stored in PostgreSQL as binary blobs (BYTEA columns). They are generated on demand or on schedule and do not consume disk space outside the database.

**Report filename conventions (when downloaded):**

| Report Type | Filename Pattern |
|---|---|
| Per-run | `bas-report-{scenario-slug}-{agentId}-{YYYYMMDD}.{ext}` |
| Full agent | `bas-agent-{hostname}-{YYYYMMDD}.{ext}` |
| Audit pack | `bas-audit-pack-{hostname}-{YYYYMMDD}.zip` |
| Campaign | `bas-campaign-{name}-{YYYYMMDD}.{ext}` |
| Compliance | `bas-compliance-{framework}-{YYYYMMDD}.{ext}` |
| Exercise | `bas-exercise-{name}-{YYYYMMDD}.{ext}` |

---

## Report Integrity Verification

Every generated report includes an integrity header:

**HTML reports:** An HTML comment near the top:
```html
<!-- Audspect Report
     Generated: 2026-07-01T09:00:00Z
     Run ID: run-abc123
     SHA-256: a4b5c6d7e8...
-->
```

**PDF reports:** Document metadata field `Subject` contains the SHA-256 hash.

**Audit pack:** `manifest.json` in the ZIP root contains SHA-256 hashes for every file:
```json
{
  "generatedAt": "2026-07-01T09:00:00Z",
  "agentId": "agt-xyz",
  "files": {
    "report.html": "sha256:a4b5c6...",
    "report.pdf": "sha256:b5c6d7...",
    "data.csv": "sha256:c6d7e8..."
  }
}
```

---

## Executive Summaries

The HTML version of Full Agent Reports and Campaign Reports includes a dedicated **Executive Summary** section designed for non-technical readers:

- Plain-language risk classification (Protected / Low / Medium / High / Critical)
- One-sentence description of the risk level
- Top 3 most critical gaps with business impact framing
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

PDF reports include a **CONFIDENTIAL** watermark on every page. This is applied as a CSS background layer during HTML-to-PDF rendering and cannot be removed without re-generating the report.

Reports generated for specific named users include the requesting user's email in the footer of every page.

---

*© Audspect — Confidential — Customer Distribution*
