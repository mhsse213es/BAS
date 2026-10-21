# Audspect BAS — Findings and Remediation Guide

**Platform Version:** v1.7.3

---

## Overview

Every technique that produces a **FAIL** verdict in a simulation run automatically creates or updates a structured **Finding** in the platform. Findings give the security team a single place to track which controls are failing, prioritize remediation work, verify fixes, and report closure to management.

---

## Finding Lifecycle

A FAIL verdict creates a finding with status `open`. Findings move between four statuses:

### Status definitions

| Status | Who Sets It | Meaning |
|---|---|---|
| **open** | Automatic (new finding, or reopened) | Control gap is live and not yet triaged or remediated |
| **triaged** | Analyst | Analyst has reviewed the finding |
| **remediated** | Automatic or Analyst | A newer run shows the technique blocked, or an analyst marked it fixed. Sets the resolved time |
| **risk_accepted** | Analyst | Risk accepted. Sticky: later recurrences are counted, but the status is never changed automatically |

Automatic transitions:
- An **open** or **triaged** finding becomes **remediated** when a newer run shows the technique prevented.
- A **remediated** finding is reopened to **open** when the technique fails again, and its reopened count increases.

---

## Finding Fields

Each finding carries:

| Field | Description |
|---|---|
| **Technique ID** | MITRE ATT&CK technique (e.g., T1003.001) |
| **Tactic** | MITRE ATT&CK tactic (e.g., Credential Access) |
| **Severity** | Critical / High / Medium / Low |
| **Agent** | The endpoint where the technique succeeded |
| **Scenario** | The scenario that produced this finding |
| **Run ID** | Link to the specific run instance |
| **Control Class** | Category of control that should block this (e.g., EDR, AV, SIEM, Firewall) |
| **First Seen** | Timestamp of first FAIL for this technique × agent combination |
| **Last Seen** | Timestamp of most recent FAIL |
| **Recurrence Count** | Number of times this technique has produced FAIL |
| **Status** | Current lifecycle state |
| **Assigned To** | Analyst responsible for remediation |
| **Notes** | Free-text notes added by analysts |
| **Linked Ticket** | External ticket ID (if ticket integration is configured) |
| **Evidence** | Raw step output from the failing run |
| **Remediation Guidance** | Built-in fix recommendations for this technique |

---

## Deduplication

Findings are deduplicated by the combination of `(agent_id, technique_id, control_class)`. If the same technique fails on the same agent in a subsequent run, the existing finding is updated (Last Seen, Recurrence Count) rather than creating a duplicate.

This means one finding per technique, agent and control class. If a technique fails across 10 agents, there are 10 findings — one per agent.

---

## Severity Assignment

Severity flows from the step definition in the scenario YAML. The severity hierarchy:

| Severity | CVSS Equivalent | Typical technique examples |
|---|---|---|
| **Critical** | 9.0–10.0 | LSASS dump, credential harvesting, ransomware deployment |
| **High** | 7.0–8.9 | Lateral movement, privilege escalation, C2 communication |
| **Medium** | 4.0–6.9 | Defense evasion, persistence, discovery |
| **Low** | 0.1–3.9 | Reconnaissance, benign enumeration |

---

## Remediation View

**Findings** shows individual findings (one row = one technique × agent).

**Remediation** groups findings by technique across all agents — showing how many agents are affected, the combined severity, and a single remediation recommendation.

**Example Remediation card:**
```
T1003.001 — OS Credential Dumping: LSASS Memory
Severity: Critical     Affected agents: 4 of 12
─────────────────────────────────────────────────
Recommendation:
  Enable Credential Guard on domain-joined endpoints.
  Configure EDR to block lsass.exe memory access.
  Audit exclusions: ensure no EDR exclusion covers C:\Windows\System32\lsass.exe

  [Re-validate on all 4 agents]   [Suppress]   [Create Ticket]
```

---

## Re-validate

**Re-validate** dispatches a targeted single-technique run to the specified agent(s). It sends only the failing step from the original scenario — not the full scenario — to minimize operational impact.

### How it works

1. Analyst clicks **Re-validate** on a finding or remediation card
2. The platform selects an appropriate scenario that tests the target technique
3. A run is created with `revalidation=true` and dispatched only to the affected agent(s)
4. The run targets the specific technique ID rather than a named scenario
5. When the run completes:
   - **PASS** (technique prevented) → Finding status automatically moves to **remediated**
   - **FAIL** → Last Seen and Recurrence Count are updated; a remediated finding is reopened to **open**; a risk_accepted finding stays as it is

The Re-validate action is visible on every finding and on each remediation card.

### Re-validate history

The finding detail view shows the full re-validate history: when each re-validate ran, what the result was, and the raw step output for comparison against the original failure evidence.

---

## Automatic Closure

If a previously failing technique is prevented in a newer run without manual intervention (for example, after an AV signature update or a patch), the platform moves an **open** or **triaged** finding to **remediated**. A **risk_accepted** finding is never changed automatically. Analysts can review the status change and reopen the finding if the control regresses.

This prevents stale findings from accumulating when controls are updated via other channels.

---

## Evidence Comparison

When a finding is re-validated, the platform stores both the original failure evidence and the new re-validate evidence. The **Evidence** tab on a finding shows a side-by-side diff:

| | Original Run | Re-validate Run |
|---|---|---|
| Timestamp | 2026-06-28 10:15:32 | 2026-07-01 14:22:10 |
| Verdict | FAIL | PASS |
| Raw output | `Invoke-Mimikatz success...` | `Access denied: EDR blocked` |
| Control response | None observed | EDR alert generated |

Evidence is stored as structured JSON and rendered in the dashboard. It is also included in audit pack exports.

---

## Ticket Integration

If a ticketing integration is configured (ServiceNow, Jira, or generic webhook), the **Create Ticket** button on a finding sends a structured payload to the configured endpoint.

The ticket payload includes:
- Finding ID, technique ID, tactic, severity
- Affected agent hostname and IP
- Control class and remediation recommendation
- Link to the finding in the Audspect dashboard
- Evidence (first 2,000 characters)

On ticket creation, the ticket ID is stored against the finding in the finding-tickets record. The finding status does not change automatically based on ticket status — status must be updated in Audspect directly.

---

## Bulk Operations

From the **Findings** list view, analysts can select multiple findings and:
- Set status (open, triaged, remediated, risk_accepted)
- Assign to a user
- Create tickets (one per finding)
- Export selected findings to CSV

---

## Findings API

```
GET /api/findings                     — List findings (query filters: status, severity, agentId)
GET /api/findings/{id}               — Get single finding detail
POST /api/findings/{id}/status       — Body {"status": "open|triaged|remediated|risk_accepted", "reason": "..."}
GET /api/remediations                — List grouped remediations by technique
```

Re-validate is started from the **Re-validate** button on a finding or remediation card in the dashboard; it has no separate public API route in this release.

**Example: list critical open findings**
```
GET /api/findings?severity=critical&status=open

Response:
[
  {
    "id": "find-abc123",
    "techniqueId": "T1003.001",
    "tactic": "credential-access",
    "severity": "critical",
    "agentId": "agt-xyz",
    "agentHostname": "WIN-FINANCE-01",
    "status": "open",
    "firstSeen": "2026-06-28T10:15:32Z",
    "lastSeen": "2026-07-01T09:12:00Z",
    "recurrenceCount": 3
  }
]
```

---

*© Audspect — Confidential — Customer Distribution*
