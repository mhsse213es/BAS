# Audspect BAS — API Reference

**Platform Version:** v1.7.3  
**Base URL:** `http://<server>:9000`

---

## Authentication

All API endpoints (except `/health`, `POST /api/auth/login`, and the agent WebSocket endpoint) require a valid JWT.

**Obtaining a token:**
```
POST /api/auth/login
Content-Type: application/json

{"username": "analyst@company.com", "password": "..."}
```

The token is returned in the response body AND set as an HttpOnly cookie (`bas_token`). Browser clients use the cookie automatically. API clients should use the `Authorization: Bearer <token>` header.

**Token TTL:** 24 hours.

---

## Authentication Endpoints

### POST /api/auth/login

```
Request:  { "username": "string", "password": "string" }
Response: { "token": "string", "role": "string", "username": "string", "mustChangePw": bool }
Status:   200 OK | 400 Bad Request | 401 Unauthorized | 429 Too Many Requests
```

### POST /api/auth/logout

Clears the session cookie.
```
Request:  (no body)
Response: { "ok": true }
Status:   200 OK | 401 Unauthorized
```

### POST /api/auth/change-password

```
Request:  { "currentPassword": "string", "newPassword": "string" }
Response: { "ok": true }
Status:   200 OK | 400 Bad Request | 401 Unauthorized
```

### GET /api/auth/me

Returns the current user's profile.
```
Response: { "id": "string", "username": "string", "role": "string", "mustChangePw": bool }
Status:   200 OK | 401 Unauthorized
```

---

## Agent Endpoints

### GET /api/agents

List all agents.

**Query params:** `state` (filter: active/offline/restricted/quarantined/retired), `limit`, `offset`

```
Response:
[
  {
    "id": "agt-abc123",
    "hostname": "WIN-FINANCE-01",
    "label": "Finance Workstation",
    "ip": "192.168.1.100",
    "os": "windows",
    "osVersion": "Windows 11 23H2",
    "arch": "amd64",
    "state": "active",
    "agentVersion": "1.7.3",
    "binaryTrustStatus": "trusted",
    "lastHeartbeat": "2026-07-01T09:30:00Z",
    "enrolledAt": "2026-06-01T08:00:00Z"
  }
]
Status: 200 OK | 401 Unauthorized
```

### GET /api/agents/{id}

Get single agent detail.

### POST /api/agents/{id}/state

Set agent lifecycle state. Admin only.

```
Request:  { "state": "quarantined", "reason": "Suspicious activity" }
Response: { "id": "agt-abc123", "state": "quarantined" }
Status:   200 OK | 400 Bad Request | 403 Forbidden | 404 Not Found
```

### DELETE /api/agents/{id}

Permanently delete agent and all associated data.
```
Status: 204 No Content | 403 Forbidden | 404 Not Found
```

### GET /api/agents/download

Download agent binary.

**Query params:** `os` (windows/linux/darwin), `arch` (amd64/arm64)

```
Response: binary stream
Content-Disposition: attachment; filename="bas-agent.exe"
Status:   200 OK | 400 Bad Request
```

---

## Scenario Endpoints

### GET /api/scenarios

List all scenarios.

**Query params:** `framework` (art/caldera/custom), `tag`, `search`, `limit`, `offset`

```
Response:
[
  {
    "id": "safe-simulation",
    "name": "Safe Simulation",
    "version": "1.0.0",
    "description": "Read-only OS queries",
    "framework": "custom",
    "tags": ["safe", "windows", "linux"],
    "stepCount": 5,
    "signatureValid": true,
    "builtin": true
  }
]
Status: 200 OK
```

### GET /api/scenarios/{id}

Get scenario detail including step definitions.

### POST /api/scenarios

Create a custom scenario.

```
Request:
{
  "id": "my-custom-check",
  "name": "My Custom Check",
  "description": "...",
  "tags": ["custom", "windows"],
  "steps": [...]
}
Response: { "id": "my-custom-check", "signatureValid": true }
Status:   201 Created | 400 Bad Request | 409 Conflict (ID already exists)
```

### POST /api/scenarios/{id}/run

Dispatch a scenario run to an agent.

```
Request:  { "agentId": "agt-abc123", "label": "Optional run label" }
Response: { "runId": "run-xyz", "status": "dispatched" }
Status:   200 OK | 400 Bad Request | 404 Not Found (scenario or agent)
```

### GET /api/scenarios/{id}/yaml

Download scenario YAML.
```
Response: text/yaml
Status:   200 OK | 404 Not Found
```

### POST /api/scenarios/upload

Upload a scenario YAML file (multipart/form-data, field: `file`).
```
Response: { "id": "string", "signatureValid": true }
Status:   201 Created | 400 Bad Request (invalid YAML or signature)
```

---

## Run Endpoints

### GET /api/scenarios/runs

List runs.

**Query params:** `agentId`, `scenarioId`, `status`, `from`, `to`, `limit`, `offset`

```
Response:
[
  {
    "id": "run-xyz",
    "scenarioId": "safe-simulation",
    "agentId": "agt-abc123",
    "status": "completed",
    "startedAt": "2026-07-01T09:00:00Z",
    "completedAt": "2026-07-01T09:02:30Z",
    "preventionScore": 82,
    "exposureScore": 18,
    "coverageScore": 75,
    "riskBand": "low",
    "trend": "improving",
    "stepCount": 5,
    "passCount": 4,
    "failCount": 1
  }
]
Status: 200 OK
```

### GET /api/scenarios/runs/{id}

Get run detail including step results.

```
Response:
{
  "id": "run-xyz",
  ...run fields...,
  "steps": [
    {
      "stepId": "step-001",
      "technique": "T1082",
      "tactic": "discovery",
      "severity": "low",
      "verdict": "pass",
      "output": "System info: ...",
      "durationMs": 1250
    }
  ]
}
```

### DELETE /api/scenarios/runs/{id}

Cancel a running run.
```
Status: 204 No Content | 400 Bad Request (run already completed)
```

### GET /api/scenarios/runs/{id}/report

Download run report.

**Query params:** `format` (html/pdf/csv/json)

```
Response: binary or text stream
Status:   200 OK | 404 Not Found
```

### GET /api/scenarios/runs/{id}/attackflow

Download ATT&CK Navigator JSON for this run.

---

## Findings Endpoints

### GET /api/findings

List findings.

**Query params:** `status`, `severity`, `agentId`, `tactic`, `techniqueId`, `limit`, `offset`

```
Response:
[
  {
    "id": "find-abc",
    "techniqueId": "T1003.001",
    "tactic": "credential-access",
    "severity": "critical",
    "agentId": "agt-xyz",
    "agentHostname": "WIN-DC-01",
    "status": "open",
    "controlClass": "edr",
    "firstSeen": "2026-06-28T10:00:00Z",
    "lastSeen": "2026-07-01T09:00:00Z",
    "recurrenceCount": 2,
    "remediationGuidance": "Enable Credential Guard..."
  }
]
Status: 200 OK
```

### GET /api/findings/{id}

Get single finding detail including evidence.

### POST /api/findings/{id}/status

Update finding status.

```
Request:  { "status": "in_progress", "note": "Assigned to EDR team" }
Response: { "id": "find-abc", "status": "in_progress" }
Status:   200 OK | 400 Bad Request | 404 Not Found
```

### GET /api/remediations

List grouped remediations (by technique across all agents).

### POST /api/remediations/{techniqueId}/revalidate

Dispatch re-validate run for a technique on all affected agents (or a specific agent).

```
Request:  { "agentId": "agt-xyz" }  // optional — omit to re-validate on all affected agents
Response: [{ "runId": "run-abc", "agentId": "agt-xyz", "status": "dispatched" }]
Status:   200 OK | 404 Not Found
```

---

## Report Endpoints

### GET /api/report/agent/{agentId}

Full agent report.

**Query params:** `format` (html/pdf/csv)

### GET /api/report/agent/{agentId}/auditpack

Download audit pack ZIP.

### GET /api/compliance/scores

Compliance scores for all configured frameworks.

### GET /api/compliance/report/{framework}

Compliance report for a specific framework.

**Supported framework values:** `mitre-attack`, `rbi-csf`, `sebi`, `cis-l1`, `nist-800-53`, `iso-27001`

**Query params:** `format` (html/pdf)

---

## Campaign Endpoints

### POST /api/campaigns

Create a campaign.

```
Request:
{
  "name": "July 2026 Full Assessment",
  "description": "...",
  "scenarioIds": ["safe-simulation", "art-selective"],
  "agentIds": ["agt-abc", "agt-xyz"],
  "schedule": { "cronExpression": "0 6 * * 1" }
}
Response: { "id": "camp-abc", "status": "created" }
Status:   201 Created
```

### GET /api/campaigns

List campaigns.

### GET /api/campaigns/{id}

Get campaign detail.

### GET /api/campaigns/{id}/summary

Campaign summary with aggregate scores.

### GET /api/campaigns/{id}/report

Campaign report.

**Query params:** `format` (html/pdf/csv)

### POST /api/campaigns/{id}/run

Trigger campaign execution immediately.

### DELETE /api/campaigns/{id}/run

Stop an in-progress campaign.

---

## Attack Path Endpoints

### POST /api/attackpath/jobs

Create and dispatch an AP collection job.

```
Request:
{
  "agentId": "agt-abc123",
  "targets": ["192.168.1.0/24", "10.0.0.50"],
  "enableSharpHound": false,
  "label": "Weekly scan"
}
Response: { "jobId": "ap-job-xyz", "status": "queued" }
Status:   201 Created | 400 Bad Request | 404 Not Found (agent)
```

### GET /api/attackpath/jobs

List AP jobs.

**Query params:** `agentId`, `status`, `limit`, `offset`

### GET /api/attackpath/jobs/{jobId}

Get job detail including progress and metrics.

```
Response:
{
  "jobId": "ap-job-xyz",
  "agentId": "agt-abc123",
  "status": "completed",
  "createdAt": "2026-07-01T02:00:00Z",
  "completedAt": "2026-07-01T02:18:30Z",
  "progress": { "stage": "uploading", "progressPercent": 95, "targetsCompleted": 48, "targetsTotal": 50 },
  "metrics": { "nodeCount": 52, "edgeCount": 120, "pathCount": 340 }
}
```

### GET /api/attackpath/summary/{agentId}

Latest attack path summary for an agent: score, blast radius, choke points, crown jewel exposure.

### GET /api/attackpath/history/{agentId}

Collection history for an agent.

### POST /api/attackpath/schedule

Create a recurring AP collection schedule.

### GET /api/attackpath/assets

List tagged assets.

### POST /api/attackpath/assets/{hostId}/tag

Set asset criticality tier.

---

## User Endpoints (Admin Only)

### GET /api/users

List users.

### POST /api/users

Create user.

```
Request:  { "email": "string", "password": "string", "role": "viewer|analyst|admin" }
Response: { "id": "string", "email": "string", "role": "string" }
Status:   201 Created | 400 Bad Request | 409 Conflict
```

### PUT /api/users/{id}

Update user role.

### POST /api/users/{id}/reset-password

Reset user password (admin sets new password directly).

### DELETE /api/users/{id}

Delete user.

---

## Configuration Endpoints

### GET /api/config

Runtime configuration summary (non-sensitive fields only).

### GET /api/config/connection

Returns the agent connection config (server URL, agent secret). Admin only.

### GET /api/license

License status: validity, expiry date, licensed feature set.

---

## Health Endpoint

### GET /health

Platform health check. No authentication required.

```
Response: { "status": "ok", "db": "ok", "version": "1.7.3" }
Status:   200 OK (healthy) | 503 Service Unavailable (degraded)
```

---

## Common Status Codes

| Code | Meaning |
|---|---|
| 200 | OK |
| 201 | Created |
| 204 | No Content (successful delete) |
| 400 | Bad Request — invalid input, see `error` field |
| 401 | Unauthorized — missing or expired JWT |
| 403 | Forbidden — insufficient role |
| 404 | Not Found |
| 409 | Conflict — duplicate ID or resource state conflict |
| 429 | Too Many Requests — rate limited |
| 500 | Internal Server Error |
| 503 | Service Unavailable — database or dependency unavailable |

---

## Error Response Format

All error responses follow:
```json
{
  "error": "human-readable error message",
  "code": "machine-readable-error-code"
}
```

---

*© Audspect — Confidential — Customer Distribution*
