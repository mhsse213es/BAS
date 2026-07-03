# Audspect BAS — Architecture Deep Dive

**Platform Version:** v1.7.3

---

## Service Boundaries

```
┌──────────────────────────────────────────────────────────────┐
│  ORCHESTRATOR (Go, port 9000)                                │
│                                                              │
│  ┌─────────────┐  ┌──────────────┐  ┌────────────────────┐  │
│  │  HTTP Router │  │ WebSocket Hub│  │  Background Workers│  │
│  │  (chi/mux)   │  │  (gorilla/ws)│  │  AP monitor        │  │
│  └──────┬──────┘  └──────┬───────┘  │  Heartbeat cleanup │  │
│         │                │           │  TI poller         │  │
│  ┌──────▼──────────────▼───────────┐ │  Staleness monitor │  │
│  │       API Handlers               │ │  Filesystem watcher│  │
│  │  (agents, scenarios, runs,       │ └────────────────────┘  │
│  │   findings, reports, AP, users,  │                          │
│  │   campaigns, exercises, TI,      │  ┌──────────────────┐   │
│  │   compliance, config)            │  │  Scoring Engine  │   │
│  └──────────────────────────────────┘  └──────────────────┘   │
│                                                              │
│  ┌────────────────────────────────────────────────────────┐  │
│  │  Reporting Engine (HTML template → Chromium → PDF)     │  │
│  └────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────┘
          │                        │
          │ pgx pool (max 25)       │ HTTP /print
          ▼                        ▼
    ┌──────────┐            ┌───────────────┐
    │PostgreSQL│            │Chromium sidecar│
    │:5432     │            │(PDF generation)│
    └──────────┘            └───────────────┘

    ┌───────────────────────────────────┐
    │  Caldera (optional, :8888)        │
    │  bas-caldera image               │
    │  CTID library ~2213 abilities    │
    └───────────────────────────────────┘
```

---

## Request Lifecycle: Scenario Run Dispatch

```
Browser → POST /api/scenarios/{id}/run
              │
              ▼
         CreateRun() in api/handlers.go
              │ validates scenario (signature check)
              │ validates agent (state = active)
              │ resolves scenario steps server-side:
              │   ART: reads art_atomics + art_atomic_tests from Postgres
              │   Caldera: fetches ability from Caldera REST API
              │   Custom: step command verbatim
              │
              ▼
         Inserts `scenario_runs` row (status=dispatched)
         Inserts `run_steps` rows
              │
              ▼
         BroadcastJSON(MsgRunDispatched) → all WS sessions
              │
              ▼
         HubSend(agentId, RunCommand{...}) → agent WS session
              │
              ▼
         Agent receives RunCommand
         Agent executes steps in sequence
         Agent POSTs each step result to:
           POST /api/agents/result
              │
              ▼
         HandleAgentResult() in api/handlers.go
              │ verifies HMAC-SHA256 MAC on request body
              │ upserts run_step row with verdict + output
              │ calls scoring engine on final step
              │ creates/updates findings for FAIL verdicts
              │
              ▼
         BroadcastJSON(MsgRunStepResult) → WS sessions
              │
              ▼
         Browser receives WS event → updates live run view
```

---

## WebSocket Hub

The WebSocket hub is a single goroutine managing all connected browser sessions. All broadcasts go through a channel to avoid lock contention:

```go
// Simplified hub structure
type Hub struct {
    sessions  map[string]*Session   // sessionId → session
    broadcast chan WSMessage
    register  chan *Session
    unregister chan *Session
}
```

Message types (all defined in `internal/models/schema.go`):

| Constant | Value | Purpose |
|---|---|---|
| `MsgRunDispatched` | `"run_dispatched"` | Run created and sent to agent |
| `MsgRunStepResult` | `"run_step_result"` | Step verdict received |
| `MsgRunCompleted` | `"run_completed"` | Run fully complete with scores |
| `MsgAgentStateChange` | `"agent_state_change"` | Agent lifecycle state changed |
| `MsgHeartbeat` | `"heartbeat"` | Agent heartbeat received (updates Last Seen) |
| `MsgAPJobUpdate` | `"ap_job_update"` | AP job status change |
| `MsgAPJobProgress` | `"ap_job_progress"` | AP job stage/percentage update |
| `MsgAttackPathCollected` | `"attackpath_collected"` | AP collection complete |

---

## ART Payload Resolution

```
Scenario YAML declares: art_technique="T1003.001" art_test_index=0
           │
           ▼
       api/handlers.go → resolveARTStep()
           │
           ▼
       Queries Postgres:
         SELECT executor, command, cleanup_command, prereq_command, prereq_description
         FROM art_atomic_tests
         WHERE technique_id = 'T1003.001'
         AND test_index = 0
         AND executor_os LIKE '%windows%'   -- matches agent OS
           │
           ▼
       Substitutes InputArguments from art_atomics YAML defaults
           │
           ▼
       Returns complete RunStepCommand{executor, command, cleanup}
           │ (ready-to-execute — no ART parsing on agent)
           ▼
       Dispatched to agent
```

The ART library (YAML) is seeded into PostgreSQL on first startup. Tables:
- `art_atomics` — raw YAML metadata per technique
- `art_atomic_tests` — parsed individual test definitions
- `art_atomic_raw` — original YAML text per technique (for reseed)
- `art_payloads` — metadata for external payload files

---

## Scoring Engine

`internal/scoring/scoring.go` is called after the final step result arrives for a run.

```go
type RunScore struct {
    PreventionScore float64
    ExposureScore   float64
    CoverageScore   float64
    KillChainAmp    float64
    RiskBand        string
    Trend           string
}
```

Input: `[]RunStep` with verdicts and severity tags.

Algorithm:
1. Filter to scorable steps: verdict IN (PASS, FAIL)
2. Compute `PreventionScore`: Σ(weight × isPass) / Σ(weight) × 100
3. Compute per-tactic fail rates → `base_exposure`
4. Compute `KillChainAmp` from consecutive failing phases
5. `ExposureScore` = min(base_exposure × amp, 100)
6. `CoverageScore` = (tactics where all steps passed / tactics tested) × 100
7. `RiskBand` = risk band from Prevention Score threshold table
8. `Trend` = compare PreventionScore to most recent previous run for same agent+scenario

---

## Database Tables (Key)

| Table | Purpose |
|---|---|
| `users` | User accounts (email, password hash, role, must_change_pw) |
| `agents` | Agent records (id, hostname, ip, os, state, last_heartbeat) |
| `scenario_runs` | Run instances (id, scenario_id, agent_id, status, scores) |
| `run_steps` | Individual step results (run_id, step_id, verdict, output) |
| `run_reports` | Generated reports (run_id, format, data BYTEA) |
| `findings` | Control gap findings (technique_id, agent_id, severity, status) |
| `remediations` | Grouped by technique across agents |
| `campaigns` | Campaign definitions and schedules |
| `campaign_runs` | Individual campaign execution instances |
| `exercises` | Purple team exercise plans |
| `exercise_executions` | Exercise execution records with evidence chain |
| `attackpath_jobs` | AP collection job lifecycle tracking |
| `attackpath_results` | Processed graph data per job |
| `attackpath_assets` | Asset criticality tags |
| `art_atomics` | ART technique metadata |
| `art_atomic_tests` | ART individual test definitions |
| `art_atomic_raw` | Raw YAML (for reseed) |
| `art_payloads` | ART payload metadata |
| `events` | Audit log entries |
| `schema_migrations` | Applied migration tracking |

---

## Scenario Signing Verification Path

```
Orchestrator startup
       │
       ▼
LoadScenarios(dir)
       │
       ├── for each *.yaml:
       │       │
       │       ├── check for *.yaml.sig
       │       │     │
       │       │     ├── not found → mark unsigned (cannot dispatch)
       │       │     │
       │       │     └── found → gpg --verify <sig> <yaml>
       │       │             │
       │       │             ├── invalid → mark "signature_invalid" (cannot dispatch)
       │       │             │
       │       │             └── valid → mark "loaded" (can dispatch)
       │       │
       │       └── parse YAML into scenario struct
       │
       └── start 15s filesystem watcher
                    │
                    └── on change: re-verify + update status
```

---

## Result Delivery: At-Least-Once + Idempotent

Agent result submission is designed for reliability over exactly-once:

1. Agent POSTs step result → server processes → 200 OK
2. If network failure before 200 → agent retries (same step result)
3. Server receives duplicate → `INSERT ... ON CONFLICT DO UPDATE` (upsert by step_id)
4. Duplicate is safe: same verdict written twice = same outcome

Late submission healing:
- Run status = `partial` if no result received for 90 seconds
- Agent reconnects, submits buffered results
- Server processes results → if all steps now have results → run moves to `completed`
- Finding creation re-runs on final completion

---

## Attack Path Job State Machine (Server Side)

```go
// attackpath_jobs.go
// State transitions enforced in the database via status column checks

Queued → Dispatched  (on agent ACK)
Queued → DeliveryFailed  (30s timeout: no ACK)
Dispatched → Running  (on agent progress update)
Running → Completed  (on result submission via SubmitAttackPathCollection)
Running → Failed  (on agent error report)
Running → TimedOut  (30 min timeout via StartAPJobMonitor ticker)
Any → Cancelled  (admin action)
```

---

*© Audspect — Confidential — Customer Distribution*
