# Audspect BAS Platform
## Product Guide — v1.7.5

---

**Classification:** Confidential — Customer Distribution  
**Document Version:** 2.1  
**Platform Version:** 1.7.5  
**Prepared by:** Audspect  
**Contact:** support@audspect.com  
**Last Updated:** 2026-08-10

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Why Audspect](#2-why-audspect)
3. [Platform Overview](#3-platform-overview)
4. [Architecture](#4-architecture)
5. [Core Capabilities](#5-core-capabilities)
   - 5.1 Breach and Attack Simulation
   - 5.2 Posture Validation
   - 5.3 Reporting Suite
   - 5.4 Findings and Remediation
   - 5.5 Threat Intelligence
   - 5.6 Attack Path Validation
   - 5.7 Integrity System
   - 5.8 Fleet Operations at Scale
   - 5.9 Executive Dashboard and Threat Prioritization
   - 5.10 Detection Validation and Automated Response
   - 5.11 Global Search
6. [Deployment Models](#6-deployment-models)
7. [Security Model](#7-security-model)
8. [Operations Overview](#8-operations-overview)
9. [Roles and Permissions](#9-roles-and-permissions)
10. [Installation Overview](#10-installation-overview)
11. [Licensing](#11-licensing)
12. [Day-to-Day Operations](#12-day-to-day-operations)
13. [REST API Overview](#13-rest-api-overview)
14. [Configuration Overview](#14-configuration-overview)
15. [Security and Cryptography](#15-security-and-cryptography)
16. [Compliance Mapping](#16-compliance-mapping)
17. [Troubleshooting](#17-troubleshooting)
18. [Glossary](#18-glossary)
19. [References](#19-references)

---

## 1. Executive Summary

**Audspect BAS** (Breach and Attack Simulation) is an enterprise-grade, on-premises security validation platform built for BFSI (Banking, Financial Services, and Insurance) organizations and other regulated industries. The platform continuously validates the effectiveness of deployed security controls by simulating real-world adversary techniques across production and staging environments — without disrupting operations.

Audspect BAS tests whether your security controls (EDR, AV, SIEM, DLP, firewall policies, hardening baselines) actually stop known attack patterns. Every simulation step is mapped to the MITRE ATT&CK framework and scored across four risk dimensions. Results surface in a real-time dashboard designed for security operations teams and feed directly into a structured Findings and Remediation workflow.

**Platform version 1.7.5 introduces (on top of the 1.7.3 feature set below):**

- Executive Dashboard: fleet-wide Risk Score, Exposure Score, Detection Coverage, and Asset Count trended over time, with an honest "No data yet" state instead of a misleading perfect score before any Attack Path collection has run
- Threat Prioritization: standing per-actor risk scoring across 9 factors, ranking which threat actors matter most to your environment right now
- Agent Groups: hierarchical, admin-managed organizational structure for endpoints, replacing flat environment labels
- Scheduled Assessments: recurring scenario runs (daily/weekly/monthly) with an immutable execution-authorization audit trail for Telemetry-mode runs
- Campaigns can now target an Agent Group or all enrolled agents directly, not just an explicit agent list
- Threat Intelligence connectors (MISP, OpenCTI, OTX/AlienVault) are now configured entirely from the console — enter the API key and URL, Test Connection, Save — with changes taking effect immediately and no `.env` editing or container restart required
- Detection Validation: expected-vs-actual gap analysis against live SIEM/EDR connectors (Microsoft Sentinel, Defender XDR, IBM QRadar, Splunk, CrowdStrike)
- EPP Response Actions: isolate, kill process, or quarantine a file directly from a finding, via CrowdStrike or Microsoft Defender
- Global Search across agents, scenarios, findings, and more, with a `type:` filter operator
- Multi-Tenancy foundation, SSO/SCIM identity integration, and API rate limiting

**Platform version 1.7.3 introduced:**

- Cymulate-style reporting suite: per-run, per-agent, campaign, audit-pack, and compliance reports in HTML, PDF, and CSV
- Structured Findings and Remediation workflow with severity triage and re-validate
- Attack Path Validation with a full job lifecycle, SharpHound integration, and asset tagging
- Purple Team Exercise Engine with evidence chain, step-by-step approval, and phishing simulation
- Threat Intelligence connectors (MISP, OpenCTI) with automatic scenario generation
- Ticket integration for finding-to-ticket workflows
- SIEM integration for alert correlation
- Platform-level cryptographic integrity: RSA-4096 scenario signing, binary trust verification, and filesystem watch

---

## 2. Why Audspect

### The Problem

Security teams spend budget on controls they cannot continuously validate. A firewall rule that blocks lateral movement today may be overridden by a change tomorrow. An EDR exclusion added during an incident response engagement may never be removed. Patch cycles leave known-exploited techniques unblocked for weeks.

Vulnerability scanners find weaknesses in software versions but cannot answer: **does my control stack stop this specific attack?** SIEMs ingest logs but cannot tell you: **is this alert reliably generated when an attacker does this?** Penetration tests answer the question once a year.

### The Audspect Approach

Audspect BAS answers the question continuously. Every day, or on demand, real adversary techniques execute on your endpoints under controlled conditions. The platform measures whether each technique was blocked, detected, or passed through — weighted by severity, mapped to kill-chain phase, and trended over time.

**Key differentiators vs. market alternatives:**

| Capability | Audspect | Cloud-based BAS | Red Team |
|---|---|---|---|
| Air-gapped, fully on-prem | Yes | No | Optional |
| No data leaves environment | Yes | No | Yes |
| BFSI-specific scenarios | Yes | Limited | Depends |
| Continuous, automated | Yes | Yes | No |
| Structured remediation workflow | Yes | Partial | No |
| Attack path graph analysis | Yes | Partial | No |
| MITRE ATT&CK mapped | Yes | Yes | Partial |
| RBI/SEBI compliance scenarios | Yes | No | Optional |
| Evidence chain for audit | Yes | No | Partial |

---

## 3. Platform Overview

### 3.1 What Audspect BAS Does

Audspect BAS deploys a lightweight agent on endpoint machines and a central orchestrator within the customer's network. Security analysts select pre-built or custom attack scenarios from the web dashboard and dispatch them to one or more agents. Each agent executes the scenario using native OS tooling, reports raw output to the orchestrator, and the orchestrator interprets results against MITRE ATT&CK, computes a multi-dimensional risk score, and streams results live to the dashboard.

Failed controls surface as structured Findings with severity, technique, tactic, and recommended remediation. Analysts can validate remediation by re-running the specific technique against the specific agent. Attack Path Validation maps lateral movement opportunities between systems using observed network reachability and privilege relationships.

### 3.2 What It Is Not

- **Not a vulnerability scanner.** Audspect BAS does not scan for CVEs. It tests whether your controls stop known attack behaviors.
- **Not a SIEM.** It does not ingest logs; it generates ground-truth events that your SIEM should detect.
- **Not an EDR replacement.** The agent is exclusively an execution and reporting vehicle with no ongoing monitoring.
- **Not a penetration test.** Audspect BAS is continuous, automated, and controlled. It does not pivot between systems, escalate privileges against live accounts, or extract real data.

### 3.3 Platform Components

| Component | Technology | Role |
|---|---|---|
| Orchestrator | Go | Scenario engine, scoring, API, WebSocket hub, dashboard |
| Scoring API | Python | Supplemental risk scoring and analytics |
| PostgreSQL 16 | Docker | Persistent store for all data |
| Web Dashboard | SPA (browser) | Analyst and admin interface |
| BAS Agent | Go binary | Scenario execution on target endpoints |
| PDF Renderer | Headless Chromium | HTML-to-PDF report generation |
| Caldera | Docker (optional) | Adversary emulation ability source |

---

## 4. Architecture

### 4.1 System Diagram

```
┌──────────────────────────────────────────────────────────────────────────┐
│                         CUSTOMER ON-PREM NETWORK                         │
│                                                                          │
│  ┌─────────────────────────────────────────────────────────────────────┐ │
│  │                      ORCHESTRATOR SERVER                            │ │
│  │                   (Ubuntu + Docker Compose)                         │ │
│  │                                                                     │ │
│  │  ┌───────────────┐  ┌────────────┐  ┌──────────┐  ┌─────────────┐ │ │
│  │  │  Orchestrator  │  │ PostgreSQL  │  │ Chromium │  │ Caldera     │ │ │
│  │  │  :9443         │  │ :5432       │  │ (PDF)    │  │ :8888 (opt) │ │ │
│  │  └───────┬────────┘  └────────────┘  └──────────┘  └─────────────┘ │ │
│  └──────────┼──────────────────────────────────────────────────────────┘ │
│             │  HTTP / WebSocket (port 9443)                              │
│             │                                                            │
│   ┌─────────┴──────────┐        ┌──────────────────────────────────┐    │
│   │  BROWSER            │        │  TARGET ENDPOINTS                │    │
│   │  Security Analyst   │        │                                  │    │
│   │  WebSocket client   │        │  [Windows Agent] [Linux Agent]   │    │
│   └─────────────────────┘        │  [macOS Agent]                   │    │
│                                  └──────────────────────────────────┘    │
│                                                                          │
│  ┌─────────────────────────────────────────────────────────────────────┐ │
│  │  OPTIONAL INTEGRATIONS (all on-prem or vendor-hosted)                │ │
│  │  MISP  │  OpenCTI  │  OTX  │  Ticketing System  │  SIEM  │  EPP     │ │
│  └─────────────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────────────┘
```

### 4.2 Communication Model

| Flow | Transport | Authentication |
|---|---|---|
| Agent → Orchestrator heartbeat | HTTP POST | `X-Agent-Token` header |
| Agent → Orchestrator WebSocket | `ws://` or `wss://` | Agent secret in URL param |
| Orchestrator → Agent command | WebSocket (server push) | Established WS session |
| Agent → Orchestrator result | HTTP POST | HMAC-SHA256 MAC over body |
| Browser → Orchestrator API | HTTP(S) REST | JWT (HttpOnly cookie or Bearer) |
| Browser ↔ Orchestrator live events | WebSocket | JWT |

The default listening port is **9443**. TLS is opt-in (`BAS_TLS=true` in `setup.conf`) — plain HTTP is the out-of-the-box default; a reverse proxy or `BAS_TLS` is expected for anything internet-adjacent. No agent port is opened inbound. Agents initiate all connections outbound to the orchestrator's listening port.

### 4.3 Data Residency

All data — agents, results, reports, user accounts, findings, attack path graphs — is stored exclusively in the on-premises PostgreSQL instance. No telemetry, results, or agent data is transmitted to Audspect or any external service.

For a detailed architecture deep-dive including database schema, internal service boundaries, and the scoring pipeline, see → **[Architecture Deep Dive](guides/architecture-deep-dive.md)**.

---

## 5. Core Capabilities

### 5.1 Breach and Attack Simulation

The scenario engine is the core of the platform. It resolves scenario YAML definitions into executable steps server-side and dispatches fully-formed commands to agents. Agents are intentionally kept "dumb" — they receive ready-to-execute commands, not framework SDKs.

**Supported execution frameworks:**

| Framework | Description |
|---|---|
| Custom | PowerShell/Bash posture checks with PASS/FAIL/SKIP/ERROR output |
| Atomic Red Team (ART) | MITRE ATT&CK-mapped atomic tests; YAML bundled server-side |
| Caldera | Adversary emulation abilities fetched via Caldera REST API |
| Hybrid | Combined posture + live execution modes (Posture / Telemetry / Lab) |

**Platform ships with 50+ built-in scenarios** covering the full MITRE ATT&CK kill chain plus BFSI-specific coverage including APT36 spear-phishing, UPI fraud kill chain, RBI/CSCRF compliance drills, DLP validation, ransomware readiness (including current families such as BlackCat, Akira, Play, RansomHub, and Cl0p), and insider threat behaviors.

Analysts can author custom scenarios visually from the dashboard or by uploading YAML, without SSH access or service restarts.

→ See **[Scenarios Guide](guides/scenarios.md)** for the complete scenario library, YAML format, hybrid execution modes, and the scenario builder.

### 5.2 Posture Validation

Every scenario run produces a **four-verdict result** per step:

| Verdict | Meaning |
|---|---|
| **PASS** | Control blocked or detected the technique |
| **FAIL** | Control allowed the technique through (attacker succeeds) |
| **ERROR** | Execution failed on the BAS side (infrastructure issue, not a control result) |
| **SKIPPED** | Step not applicable to this OS or configuration |

Runs produce a **multi-dimensional score**: Prevention Score, Exposure Score, Coverage Score, Kill Chain Amplifier, and Trend. ERROR and SKIPPED steps are excluded from scoring.

→ See **[Scoring Methodology](guides/scoring-methodology.md)** for full weighting tables, formulas, normalization, and baseline comparison.

### 5.3 Reporting Suite

Audspect BAS v1.7.3 ships a complete Cymulate-style reporting suite. Every report renders from a live HTML template and converts to PDF via headless Chromium — no static PDF generation.

| Report Type | Formats | What It Contains |
|---|---|---|
| Per-Run Report | HTML, PDF, CSV | Single scenario execution: steps, verdicts, scores, remediation |
| Full Agent Report | HTML, PDF, CSV | Aggregated view across all runs for one agent |
| Campaign Report | HTML, PDF, CSV | Multi-scenario, multi-agent campaign summary |
| Audit Pack | ZIP | Per-agent: HTML report + PDF + CSV + raw JSON + metadata |
| Compliance Report | HTML, PDF | Framework-mapped control gaps (RBI, SEBI, CIS, MITRE) |
| Exercise Report | HTML, PDF, CSV, JSON | Purple Team exercise with evidence chain |
| Forensic CSV | CSV | Step-level raw output for SIEM/SOAR ingestion |

All reports carry a SHA-256 integrity hash in the file header, enabling verification that the report content has not been altered after generation.

→ See **[Reporting Guide](guides/reporting.md)** for scheduling, naming conventions, storage layout, digital signatures, evidence embedding, and watermarking.

### 5.4 Findings and Remediation

Failed simulations automatically create or update structured **Findings** in the platform's finding database. Findings are deduped by `(agent, technique, control_class)` and carry a full lifecycle:

```
Created → Open → In Progress → Validated → Resolved
                                         → Suppressed / False Positive / Archived
```

Analysts can:
- Set status, add notes, and link findings to external tickets
- Use **Re-validate** to dispatch a targeted single-technique run for a specific agent
- Compare before/after evidence between the original failure and the re-validation run
- Filter by severity, tactic, status, or agent in the Remediation view

→ See **[Findings and Remediation Guide](guides/findings-remediation.md)** for the full lifecycle, automatic closure rules, ticket integration, and evidence comparison.

### 5.5 Threat Intelligence

The Threat Intelligence module connects to MISP, OpenCTI, and OTX (AlienVault) to pull structured intelligence and automatically generate test scenarios from it.

- **Sources:** MISP events and indicators; OpenCTI bundles (STIX 2.1); OTX (AlienVault) pulses
- **Configuration:** Entirely from the console (Settings → Threat Intel Connector) — enter the base URL and API key for MISP/OpenCTI, or just the API key for OTX, click **Test Connection** to validate before saving, then **Save**. Changes take effect immediately; there is no `.env` file to edit and no container restart required.
- **Polling:** Configurable interval (default: 24 hours), plus a manual **Sync Now**
- **Filters:** Sector (e.g., financial-services, banking) and region (e.g., Asia, India)
- **Output:** Auto-generated custom scenarios mapped to techniques in the intelligence
- **ATT&CK enrichment:** Bundled ATT&CK STIX authoritative data + curated overlay
- **Threat Prioritization:** every actor pulled in from a connector is scored and ranked — see 5.9 below

CVE/KEV/OWASP enrichment uses the CISA Known Exploited Vulnerabilities catalog (bundled in image) and FIRST EPSS scores (optional). These are **curated mappings only** — the platform never auto-maps or fabricates CVE-to-technique relationships.

→ See **[Integrations Guide](guides/integrations.md)** for connector setup, polling configuration, and auto-scenario management.

### 5.6 Attack Path Validation

Attack Path Validation identifies potential lateral movement paths between systems using **observed reachability and privilege relationships** — not exploitation or vulnerability scanning.

The agent probes only the hosts you explicitly supply, collects local administrator group membership and active session data, and uploads the result as a graph (nodes = hosts/users, edges = relationships). The server builds a fleet-wide graph, computes blast radius, choke points, and crown jewel exposure, and assigns an Attack Path Score (0–100, higher = safer).

**Job lifecycle:**

```
Queued → Dispatched → Running → Completed
                     → delivery_failed / timed_out / failed / cancelled
```

All jobs are tracked in the `attackpath_jobs` table with full lifecycle timestamps, progress stages, and execution metrics. Jobs auto-retry on agent reconnect. SharpHound (optional, domain-joined hosts) deepens the graph with Active Directory relationship data.

→ See **[Attack Path Guide](guides/attack-path.md)** for collection dispatch, job monitoring, SharpHound setup, asset tagging, risk calculation, and remediation mapping.

### 5.7 Integrity System

The platform enforces multi-layer integrity validation across scenario content, agent binaries, and report output.

**Scenario signing:** Every scenario YAML ships with an RSA-4096 signature (`.yaml.sig`). The orchestrator verifies signatures on load and rejects unsigned or tampered scenarios. A 15-second filesystem watcher detects in-place tampering of loaded scenarios and alerts in the dashboard.

**Agent binary trust:** On every heartbeat, the orchestrator compares the agent's self-reported binary hash against the `BINARIES.sha256` manifest shipped with the platform. Mismatches are flagged in the dashboard and audit log.

**Result integrity:** All agent-submitted results carry an HMAC-SHA256 MAC computed over the payload using the shared `AGENT_SECRET`. The orchestrator rejects results where the MAC does not match.

**Report integrity:** Generated reports embed a SHA-256 content hash in the file header for post-generation verification.

→ See **[Security Hardening Guide](guides/security-hardening.md)** for the full integrity pipeline, certificate rotation, and FIPS considerations.

### 5.8 Fleet Operations at Scale

Three capabilities that reduce day-to-day operational overhead for larger fleets:

**Agent Groups** — a real, admin-managed hierarchical group tree for organizing endpoints (e.g., by business unit, region, or environment), replacing the earlier flat environment-label column. Groups appear as a tree panel on the Agents page; any view or run target that accepts an agent list can also accept a group.

**Scheduled Assessments** — recurring scenario runs (once, daily, weekly, or monthly) that reuse the same execution engine as an on-demand run — not a second, separate scheduler. A Telemetry-mode schedule requires Admin approval and a recorded reason at creation time, captured as an immutable audit record (who approved it, when, under which policy version) — schedules cannot be silently edited afterward; changing one means cancelling and recreating it.

**Campaigns** can target an explicit agent list (as before), a single Agent Group, or all enrolled agents — selectable directly in the New Campaign wizard, with a live preview of which agents are actually in scope before you launch.

### 5.9 Executive Dashboard and Threat Prioritization

The **Executive Dashboard** gives a fleet-wide, at-a-glance view: Risk Score, Exposure Score, Detection Coverage, and Asset Count, each with a trend sparkline over the selected time window. Exposure Score and Detection Coverage are computed from the Attack Path graph (5.6) — before any Attack Path collection has run, the dashboard shows an explicit **"No data yet"** state on those two tiles instead of a misleadingly perfect score, so an unscanned fleet is never mistaken for a well-defended one.

**Threat Prioritization** maintains a standing, per-actor risk score across every threat actor your MISP/OpenCTI/OTX connectors have surfaced, blending 9 factors (technique coverage gaps, sector/region relevance, recency, and others) into a ranked list — answering "which threat actor matters most to us right now," not just "which actors exist in our intel feed." Scores recompute automatically whenever new intelligence arrives.

### 5.10 Detection Validation and Automated Response

**Detection Validation** runs an expected-vs-actual gap analysis: for a technique the platform executed, did your SIEM/EDR actually generate the alert you'd expect? Live connectors are available for Microsoft Sentinel, Microsoft Defender XDR, IBM QRadar, Splunk, and CrowdStrike.

**EPP Response Actions** let an analyst isolate a host, kill a process, or quarantine a file directly from a finding — via CrowdStrike or Microsoft Defender — closing the loop from "we found a gap" to "we contained it" without leaving the platform.

### 5.11 Global Search

A single search bar (accessible fleet-wide, not per-tab) across agents, scenarios, findings, and other long-tail entities, with a `type:` operator to scope results (e.g. `type:agent hostname`) and results filtered to what the current user's role can actually see.

---

## 6. Deployment Models

### 6.1 Standard On-Premises (Recommended)

Single server deployment using Docker Compose. All components run as Docker containers on a dedicated Ubuntu server inside the customer's network. No internet access required after initial setup.

**Components on one server:**
- Orchestrator container (port 9443)
- PostgreSQL container (internal port 5432)
- Headless Chromium PDF sidecar
- Caldera container (optional, port 8888)

→ See **[Installation Guide](guides/installation.md)** for step-by-step deployment.

### 6.2 Air-Gapped Deployment

Delivery ZIP contains all Docker image tarballs. No `docker pull` or internet access required on the server. Images are loaded from local files: `docker load < image.tar`.

The ART atomics YAML library, CISA KEV catalog, and ATT&CK STIX data are all bundled inside the orchestrator image at build time.

### 6.3 High-Availability (Advanced)

Two-server active-passive setup with a shared PostgreSQL instance and a load balancer. Requires coordinating the WebSocket session affinity (sticky sessions) at the load balancer. Contact Audspect support for HA configuration guidance.

---

## 7. Security Model

### 7.1 Authentication and Session

- JWT HS256 tokens, 24-hour TTL
- HttpOnly, SameSite=Strict cookies — CSRF-resistant by default
- All API routes require a valid JWT except `/health`, `/api/auth/login`, and the agent WebSocket endpoint
- Mandatory password change on first login (`must_change_pw` flag)

### 7.2 Password Security

- **Algorithm:** PBKDF2-HMAC-SHA256, 310,000 iterations (NIST SP 800-132 minimum), 256-bit derived key, 256-bit random salt
- **Self-describing hash format:** `$pbkdf2-sha256$<iterations>$<salt>$<dk>`
- **Iteration count:** Configurable via `BAS_PBKDF2_ITERATIONS` (minimum enforced: 310,000)
- **Legacy migration:** Existing bcrypt hashes from versions prior to 1.7.x are verified read-only and transparently re-hashed on next login

### 7.3 Agent Security

- Agent binary trust verification on every heartbeat against `BINARIES.sha256` manifest
- Result submission authenticated with HMAC-SHA256 over the full payload body
- Agent secret stored as environment variable, never embedded in binary

### 7.4 Least Privilege

- Orchestrator runs as `nonroot` user inside a distroless container
- No shell or package manager in the container image
- Three-role RBAC model; each role grants minimum necessary permissions

### 7.5 Platform Hardening Recommendations

1. Enable TLS — either directly via `BAS_TLS=true` in `setup.conf` (installer-managed) or via an nginx/Caddy reverse proxy in front of port 9443
2. Restrict port 9443 to analyst workstations and endpoint subnets only
3. Isolate the orchestrator on a dedicated management VLAN
4. Rotate `AGENT_SECRET` and `JWT_SECRET` on a defined schedule
5. Enable scenario signature verification (enabled by default)

→ See **[Security Hardening Guide](guides/security-hardening.md)** for cipher suites, Docker hardening, audit logging, FIPS considerations, and immutable log configuration.

---

## 8. Operations Overview

A typical security operations workflow on Audspect BAS follows this sequence:

**1. Enroll agents** — Deploy the agent binary to each target endpoint. Agents self-register on first heartbeat.

**2. Run baseline** — Execute the Full Posture Scan (`full-scan`) on each agent to establish a baseline security posture score.

**3. Review findings** — Open findings are automatically created for every failed technique. Prioritize by severity and kill-chain phase.

**4. Remediate** — Security team applies fixes based on the finding's built-in remediation guidance.

**5. Re-validate** — Use the Remediation view's **Re-validate** action to dispatch a targeted single-technique run. The finding updates automatically when the re-run passes.

**6. Schedule campaigns** — Group multiple scenarios across multiple agents (or a whole Agent Group, or all enrolled agents) into a Campaign for simultaneous execution and a unified campaign report.

**7. Track trends** — Prevention Score trend (Improving / Degrading / Stable) appears on each run and agent summary. Historical comparison is available in the full agent report and the Executive Dashboard.

**8. Validate attack paths** — Run Attack Path collection from the Attack Path section to map lateral movement opportunities between enrolled agents and nearby hosts.

**9. Automate recurring assessments** — Create a Scheduled Assessment for a scenario that should run on a standing cadence (daily/weekly/monthly) rather than being triggered manually each time.

---

## 9. Roles and Permissions

The platform enforces role-based access control (RBAC) with three roles.

| Capability | Viewer | Analyst | Admin |
|---|---|---|---|
| View agents, scenarios, runs, reports | ✓ | ✓ | ✓ |
| Download agent binaries | ✓ | ✓ | ✓ |
| View findings and remediations | ✓ | ✓ | ✓ |
| View compliance scores | ✓ | ✓ | ✓ |
| Run scenarios | | ✓ | ✓ |
| Create/edit/clone custom scenarios | | ✓ | ✓ |
| Dispatch attack path collection | | ✓ | ✓ |
| Set finding status | | ✓ | ✓ |
| Create and run campaigns | | ✓ | ✓ |
| Target a Campaign at an Agent Group | | ✓ | ✓ |
| Create and run exercises | | ✓ | ✓ |
| Create scheduled assessments | | ✓ | ✓ |
| View and target agent groups | ✓ | ✓ | ✓ |
| Trigger threat intel sync | | ✓ | ✓ |
| View connection config (agent secret) | | | ✓ |
| Manage users | | | ✓ |
| Reset passwords | | | ✓ |
| Platform configuration | | | ✓ |
| Set agent lifecycle state (quarantine/restrict/retire) | | | ✓ |
| Configure AP schedule | | | ✓ |
| Create/rename/move/delete agent groups | | | ✓ |
| Target a Campaign at all enrolled agents | | | ✓ |
| Update Threat Intel connector config (URL/API key) | | | ✓ |

→ See **[User Management Guide](guides/user-management.md)** for user creation, password policy details, and the must-change-pw flow.

---

## 10. Installation Overview

Installation is performed via the web-based setup wizard or manually through the `setup.sh` script. Both paths produce an identical final configuration.

**High-level steps:**

1. Transfer the delivery ZIP to the Ubuntu server
2. Extract and load Docker images (offline)
3. Run the web wizard (`./setup.sh --web`) or the CLI installer (`./setup.sh`)
4. Configure environment: server URL, admin credentials, agent secret, JWT secret
5. Start Docker Compose
6. Open the dashboard and complete first-login password change

**Minimum system requirements:**

| Component | Minimum | Recommended |
|---|---|---|
| OS | Ubuntu 20.04 LTS | Ubuntu 22.04/24.04 LTS |
| CPU | 2 vCPU | 4 vCPU |
| RAM | 4 GB | 8 GB |
| Disk | 40 GB | 100 GB |
| Docker | 24.0+ | 25.0+ |
| Docker Compose | v2.20+ | v2.24+ |

→ See **[Installation Guide](guides/installation.md)** for complete step-by-step instructions, TLS setup, systemd service, proxy environments, and certificate management.

→ See **[Upgrade Guide](guides/upgrade-guide.md)** for upgrading from v1.6.x or v1.7.x.

---

## 11. Licensing

### 11.1 License Model

Audspect BAS uses node-locked, time-limited licenses. Each license is generated for a specific Customer ID and includes an expiry date.

### 11.2 License Validation

The platform validates the license file on startup. Location is set via `BAS_LICENSE_PATH` environment variable. The license status is visible at `GET /api/license`.

### 11.3 License Expiry

When a license expires, the platform continues serving existing data but blocks new scenario executions and new agent enrollments. Active WebSocket sessions are not terminated. Contact support@audspect.com for renewal.

---

## 12. Day-to-Day Operations

### 12.1 Running Scenarios

1. Navigate to **Scenarios** in the left sidebar
2. Browse or filter by tactic tag, framework, or search
3. Click a scenario card → **Run** → select agent → confirm
4. Switch to **Live Runs** to watch real-time step output
5. Completed runs appear in the run history with scores

### 12.2 Interpreting Results

Each step displays: status badge (PASS/FAIL/ERROR/SKIPPED), technique ID, tactic, severity, raw output, and remediation guidance for failures.

Run-level summary shows: Prevention Score, Exposure Score, Coverage Score, Risk Classification, Trend, and Kill Chain Amplifier.

### 12.3 Managing Findings

Open findings are visible in **Findings** (per-technique) and **Remediation** (grouped by technique across all agents). The **Re-validate** action on a remediation card dispatches a targeted run directly to step 4 of the run wizard, pre-locked to the specific technique and a suitable scenario.

### 12.4 Attack Path Collection

Navigate to the **Attack Path** section → **Run Collection**. Select an agent and supply a list of target IP addresses or hostnames. The job progress is visible in the Attack Path section and in the agent's **Attack Path** detail tab.

### 12.5 Generating Reports

From the **Agents** view, click an agent → **Reports** → select format. For campaign reports, navigate to the **Campaigns** section. Audit packs (ZIP containing HTML + PDF + CSV + JSON) are downloaded from the agent detail or from the dashboard.

---

## 13. REST API Overview

All API endpoints are served at `http://<server>:9443` (or `https://` if TLS is enabled). Authentication uses JWT tokens issued by `POST /api/auth/login`, sent as an HttpOnly cookie or `Authorization: Bearer <token>` header.

**Endpoint families** (71 route groups exist today — this is a representative subset; see the API Reference for the complete list):

| Family | Base Path | Description |
|---|---|---|
| Authentication | `/api/auth/*` | Login, logout, password change, first-run setup |
| Agents | `/api/agents/*` | List, download, state management, enrollment |
| Agent Groups | `/api/agent-groups/*` | Hierarchical group tree: create, rename, move, delete, assign |
| Scenarios | `/api/scenarios/*` | CRUD, run dispatch, upload/download YAML |
| Runs | `/api/scenarios/runs/*` | Run history, cancel, per-run reports |
| Scheduled Assessments | `/api/scheduled-assessments/*` | Recurring scenario run schedules |
| Findings | `/api/findings/*` | List, get, set status |
| Remediation | `/api/remediations/*` | Grouped findings by technique |
| Reports | `/api/report/*` | Full-agent HTML/PDF/CSV, audit pack, compliance |
| Campaigns | `/api/campaigns/*` | Create, list, summary, campaign reports (agent / group / all-agents targeting) |
| Exercises | `/api/exercises/*` | Purple Team exercise plans and executions |
| Attack Path | `/api/attackpath/*` | Jobs, collect, schedule, assets, summary, history |
| Threat Intel Connector Status | `/api/connector/*` | Fleet-wide MISP/OpenCTI/OTX/bundle sync status and manual trigger |
| Threat Intel Connector Config | `/api/threat-intel/{connector}/config[/test]` | Per-connector URL/API-key config: get, save, test connection |
| Threat Prioritization | `/api/threat-priority/*` | Per-actor ranked scores and detail |
| Dashboard | `/api/dashboard/*` | Executive dashboard current snapshot and trends |
| Users | `/api/users/*` | CRUD, password reset |
| Config | `/api/config/*` | Connection config, crypto info, license |
| Health | `/health` | Liveness check |

**Representative example — login:**
```
POST /api/auth/login

Request:  { "username": "analyst", "password": "..." }
Response: { "token": "<jwt>", "role": "analyst", "username": "analyst" }
          Cookie: bas_token=<jwt>; HttpOnly; SameSite=Strict

Status codes: 200 OK · 400 Bad Request · 401 Unauthorized · 429 Too Many Requests
```

→ See **[API Reference](guides/api-reference.md)** for complete endpoint documentation with request schemas, response schemas, and status codes.

---

## 14. Configuration Overview

Configuration is loaded from `/etc/bas/config.json` (optional) and overridden by environment variables. Environment variables take precedence.

**Required variables:**

| Variable | Description |
|---|---|
| `DATABASE_URL` | PostgreSQL connection string |
| `JWT_SECRET` | JWT signing key (minimum 32 characters) |

**Commonly configured variables:**

| Variable | Default | Description |
|---|---|---|
| `AGENT_SECRET` | — | Shared secret for agent MAC verification |
| `HTTP_PORT` | `9000` (binary default; the shipped Docker Compose/installer sets `9443`) | Listening port |
| `BAS_ADMIN_EMAIL` | `admin` | Admin username on first-run seed |
| `BAS_ADMIN_PASSWORD` | — | Admin initial password |
| `BAS_PBKDF2_ITERATIONS` | `310000` | Password hash iteration count |
| `CALDERA_URL` | — | Caldera REST API URL (optional integration) |
| `CALDERA_API_KEY` | — | Caldera authentication key |
| `BAS_LICENSE_PATH` | — | Path to customer license file |
| `BAS_SHARPHOUND_PATH` | — | Path to SharpHound.exe for AP collection |

→ See **[Configuration Guide](guides/configuration.md)** for the complete variable reference, Docker Compose tuning, agent environment variables, and scenario YAML schema.

---

## 15. Security and Cryptography

| Control | Implementation |
|---|---|
| **Password hashing** | PBKDF2-HMAC-SHA256, 310,000 iterations, 256-bit key, 256-bit random salt |
| **Session tokens** | JWT HS256, 24-hour TTL, HttpOnly SameSite=Strict cookie |
| **Result integrity** | HMAC-SHA256 over full agent-submitted payload |
| **Scenario signing** | RSA-4096 signatures on all scenario YAML files |
| **Binary trust** | SHA-256 manifest verification on every agent heartbeat |
| **Report integrity** | SHA-256 content hash embedded in generated reports |
| **Filesystem watch** | 15-second interval tamper detection on loaded scenario files |
| **Container hardening** | Distroless base image, `nonroot` user, no shell or package manager |
| **Code obfuscation** | Garble (`-literals -tiny`) applied to orchestrator binary |
| **CSRF protection** | SameSite=Strict cookie policy |
| **Input validation** | Scenario IDs, ability IDs, and technique IDs validated with regex |

→ See **[Security Hardening Guide](guides/security-hardening.md)** for TLS cipher suite configuration, secrets rotation schedule, Docker network isolation, and audit log configuration.

---

## 16. Compliance Mapping

The platform includes built-in scenarios and compliance report generation for:

| Framework | Coverage |
|---|---|
| MITRE ATT&CK v14 | All scenarios mapped to technique and tactic |
| RBI Cyber Security Framework | CSCRF/MII drill scenario |
| SEBI Cybersecurity Circular | Compliance drill checks |
| CIS Benchmarks L1 | Ubuntu L1 benchmark scenario |
| NIST SP 800-53 | Mapped via technique coverage |
| ISO 27001 | Mapped via control families |

The compliance dashboard at `GET /api/compliance/scores` shows a per-framework control gap summary, updated automatically after each simulation run.

→ See **[Compliance Mapping Guide](guides/compliance-mapping.md)** for framework-to-technique mapping tables and audit report generation.

---

## 17. Troubleshooting

| Symptom | Likely Cause | Fix |
|---|---|---|
| Agent not appearing in dashboard | Wrong `BAS_SERVER_URL` or port blocked | Verify URL in config; test with `telnet <server> 9443` |
| Agent shows Offline immediately | Wrong `AGENT_SECRET` | Copy secret from Admin → Connection Config |
| 401 on agent heartbeat | Secret mismatch | Verify `AGENT_SECRET` matches between server and agent |
| Scenario run stuck at "Running" | Agent went offline mid-run | Staleness monitor marks it Partial after 90 seconds |
| WebSocket never connects in browser | Proxy stripping Upgrade headers | Forward `Upgrade` and `Connection` headers in reverse proxy |
| PDF report uses old design | Go template type error in `html.go` | Upgrade to v1.7.3 — fixed in commit `450fca3` |
| Executive report PDF is blank | Chromium sidecar not running | Verify Chromium container is up: `docker ps` |
| AP job stays Queued | Agent offline when job was created | Job re-dispatches automatically on agent reconnect |
| AP job shows delivery_failed | Agent did not ACK within 30 seconds | Check agent connectivity; retry the job |
| Re-validate shows wrong T-ID | Stale `_runSelection` state (pre-v1.7.3) | Upgrade to v1.7.3 — fixed in commits `22314a0` + `4f9e39d` |
| Scores show 0 for Exposure/Coverage | Empty tactic assignments in old agent | Upgrade agent binary; re-run scenario |
| Admin password rejected | `BAS_ADMIN_EMAIL` not reaching container | Verify env var is in Docker Compose `environment:` block |
| Scenario rejected as unsigned | Scenario file modified without re-signing | Re-sign with `windows-build.ps1` signing step or disable signature check |
| `.deb` installed but agent not starting | Config not written post-install | Edit `/etc/bas-agent/config`, set URL and secret, restart service |

→ See **[Troubleshooting Guide](guides/troubleshooting.md)** for the complete 60+ entry symptom/cause/fix reference and diagnostic command reference.

---

## 18. Glossary

| Term | Definition |
|---|---|
| **Agent** | Lightweight binary deployed on a target endpoint; executes scenarios and reports results |
| **ART** | Atomic Red Team — open-source library of adversary simulation test cases (Red Canary) |
| **Attack Path** | Observed sequence of reachability and privilege relationships an attacker could traverse |
| **Audit Pack** | ZIP archive containing HTML, PDF, CSV, and JSON for one agent's complete assessment |
| **Baseline** | First run for an agent with no prior comparison; establishes the starting posture score |
| **BAS** | Breach and Attack Simulation — methodology for continuously testing security controls |
| **BFSI** | Banking, Financial Services, and Insurance |
| **Blast Radius** | Set of hosts an attacker can reach from a given starting point in the attack path graph |
| **Caldera** | Open-source adversary emulation platform (MITRE); used as ability source |
| **Campaign** | Grouped execution of multiple scenarios across multiple agents with a unified report |
| **Choke Point** | Host appearing in many attack paths; hardening it reduces attacker reach significantly |
| **Coverage Score** | Percentage of tested MITRE ATT&CK tactics where every check passed (higher = better) |
| **Crown Jewel** | Asset tagged as highest-value; attack paths terminating here are flagged critical |
| **Detection** | EDR/SIEM alert generated by a simulation step; evidence that the control detected the technique |
| **Edge** | Relationship between two nodes in the attack path graph (SMB, WinRM, admin-to, has-session) |
| **Evidence** | Raw output, screenshots, or telemetry captured during a simulation step |
| **Exercise** | Structured purple team engagement with step-by-step approval, evidence chain, and report |
| **Exposure Score** | Tactic-weighted failure measure amplified by consecutive kill-chain failures (higher = worse) |
| **Finding** | Structured record of a failed simulation: technique, severity, agent, control class, lifecycle |
| **Framework** | Execution method for a scenario step: `art`, `caldera`, or `custom` |
| **Heartbeat** | Periodic status message from agent to orchestrator every 30 seconds |
| **HMAC** | Hash-based Message Authentication Code — used to sign agent result submissions |
| **Integrity** | Platform-level assurance that scenario YAML, agent binaries, and reports have not been tampered |
| **JWT** | JSON Web Token — used for browser session authentication |
| **Kill Chain** | Ordered sequence of MITRE ATT&CK tactics representing an attacker's progression |
| **Kill Chain Amplifier** | Score multiplier applied when multiple consecutive kill-chain phases fail |
| **LOLBIN** | Living-Off-the-Land Binary — legitimate OS binary abused by attackers |
| **MITRE ATT&CK** | Knowledge base of adversary tactics, techniques, and procedures |
| **Node** | Host or user identity in the attack path graph |
| **Orchestrator** | Central BAS server: scenario engine, scoring, API, WebSocket hub, dashboard |
| **PBKDF2** | Password-Based Key Derivation Function 2 — the platform's password hashing algorithm |
| **Posture** | The security configuration state of an endpoint as measured by BAS simulation results |
| **Prevention Score** | Severity-weighted pass rate (0–100, higher = better controls) |
| **RBAC** | Role-Based Access Control — the platform's three-role permission model |
| **Remediation** | Recommended fix for a failed technique; grouped view across agents in the platform |
| **Re-validate** | Targeted single-technique dispatch to verify a remediation is effective |
| **Run** | Single execution of a scenario on a specific agent at a specific time |
| **Scenario** | Named collection of attack simulation steps defined in a YAML file |
| **SharpHound** | BloodHound data collector for Active Directory relationships |
| **Tactic** | MITRE ATT&CK kill-chain phase (e.g., credential-access, lateral-movement) |
| **Technique** | Specific MITRE ATT&CK method (e.g., T1003.001 — LSASS Memory) |
| **Telemetry** | Real EDR/SIEM events generated by live simulation steps |
| **Trend** | Direction of Prevention Score change vs. prior run (Improving / Degrading / Stable / Baseline) |
| **TTP** | Tactics, Techniques, and Procedures — vocabulary of adversary behavior |
| **Verdict** | Step-level outcome: PASS, FAIL, ERROR, or SKIPPED |

→ See **[Glossary](guides/glossary.md)** for the expanded 50+ term reference.

---

## 19. References

### Sub-Guides (Customer)

| Guide | Description |
|---|---|
| [Quick Start](guides/quick-start.md) | Deploy and run first simulation in under 30 minutes |
| [Installation Guide](guides/installation.md) | Full deployment: web wizard, TLS, systemd, sizing |
| [Upgrade Guide](guides/upgrade-guide.md) | Upgrading from v1.6.x or v1.7.x |
| [Backup and Restore](guides/backup-restore.md) | Database backup, restore, and disaster recovery |
| [Agent Management](guides/agent-management.md) | Agent deployment, lifecycle states, detail drawer |
| [Scenarios Guide](guides/scenarios.md) | Library, YAML format, builder, hybrid modes |
| [Scoring Methodology](guides/scoring-methodology.md) | Formulas, weights, normalization, baseline comparison |
| [Reporting Guide](guides/reporting.md) | All report types, scheduling, formats, integrity |
| [Findings and Remediation](guides/findings-remediation.md) | Finding lifecycle, re-validate, ticket integration |
| [Attack Path Guide](guides/attack-path.md) | Collection, job lifecycle, SharpHound, graph analysis |
| [Posture Checks](guides/posture-checks.md) | Posture catalog, per-OS checks, re-enroll |
| [User Management](guides/user-management.md) | RBAC, user creation, password policy |
| [API Reference](guides/api-reference.md) | Complete endpoint reference |
| [Configuration Guide](guides/configuration.md) | All environment variables and config options |
| [Security Hardening](guides/security-hardening.md) | TLS, secrets, Docker hardening, audit logging |
| [Compliance Mapping](guides/compliance-mapping.md) | Framework-to-technique mapping tables |
| [Architecture Deep Dive](guides/architecture-deep-dive.md) | Database schema, service boundaries, pipelines |
| [Troubleshooting](guides/troubleshooting.md) | 60+ symptom/cause/fix entries |
| [FAQ](guides/faq.md) | Frequently asked questions |
| [Glossary](guides/glossary.md) | 50+ term definitions |
| [Release Notes](guides/release-notes.md) | v1.7.x changelog |

### Standards Referenced

- MITRE ATT&CK v14 — https://attack.mitre.org
- NIST SP 800-132 — PBKDF2 guidance
- CISA KEV Catalog — Known Exploited Vulnerabilities
- FIRST EPSS — Exploit Prediction Scoring System
- RBI Cyber Security Framework for Banks
- SEBI Cybersecurity Circular (MII)
- CIS Benchmarks v8

---

*© Audspect — All rights reserved.*  
*Classification: Confidential — Customer Distribution.*  
*This document is intended solely for the named customer. Unauthorized distribution is prohibited.*

---

**Document History**

| Version | Date | Platform | Description |
|---|---|---|---|
| 1.0 | 2026-06-01 | v1.6.0 | Initial release |
| 2.0 | 2026-07-03 | v1.7.3 | Complete rewrite: v1.7.3 feature set, corrected crypto, new modules |
| 2.1 | 2026-08-10 | v1.7.5 | Refresh: Fleet Operations at Scale (Agent Groups, Scheduled Assessments, Campaign group/all-agents targeting), Executive Dashboard + Threat Prioritization, DB-backed Threat Intel connector config (OTX added, no-restart config), Detection Validation + EPP Response Actions, Global Search; corrected default port (9443, not 9000) and scenario count (50+) |
