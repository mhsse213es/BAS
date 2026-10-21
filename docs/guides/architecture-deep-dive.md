# Audspect BAS — Architecture Deep Dive

**Platform Version:** v1.7.3

---

## Service Boundaries

```
┌──────────────────────────────────────────────────────────────┐
│  ORCHESTRATOR (Go, port 9443)                                │
│                                                              │
│  ┌─────────────┐  ┌──────────────┐  ┌────────────────────┐  │
│  │  HTTP Router │  │ WebSocket Hub│  │  Background Workers│  │
│  │  (chi/mux)   │  │  (gorilla/ws)│  │  AP monitor        │  │
│  └──────┬──────┘  └──────┬───────┘  │                    │  │
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
          │ pgx pool                │ CDP (CHROME_WS_URL)
          ▼                        ▼
    ┌──────────┐            ┌───────────────┐
    │PostgreSQL│            │Chromium sidecar│
    │:5432     │            │(PDF generation)│
    └──────────┘            └───────────────┘

    ┌───────────────────────────────────┐
    │  Caldera (optional, :8888)        │
    │  bas-caldera image               │
    │  CTID library abilities          │
    └───────────────────────────────────┘
```

---

## Request Lifecycle: Scenario Run Dispatch

```
Browser → POST /api/scenarios/{id}/run
              │
              ▼
         RunScenario() in api/handlers.go
              │ validates scenario (signature check)
              │ validates agent (state = active)
              │ resolves scenario steps server-side:
              │   ART: reads art_atomic_tests from Postgres
              │   Caldera: fetches ability from Caldera REST API
              │   Custom: step command verbatim
              │
              ▼
         Inserts `scenario_runs` row (status=dispatched)
              │
              ▼
         HubSend(agentId, RunCommand{...}) → agent WS session
              │
              ▼
         Agent receives RunCommand
         Agent executes steps in sequence
         Agent POSTs each step result to:
           POST /api/scenarios/result
              │
              ▼
         SubmitScenarioResult() in api/handlers.go
              │ verifies X-Result-MAC (HMAC-SHA256) on request body
              │ records the step verdict and output
              │ calls scoring engine on final step
              │ creates/updates findings for FAIL verdicts
              │
              ▼
```

---

## WebSocket Hub

The WebSocket hub (`internal/ws/hub.go`) tracks agent and browser connections. Its session maps are guarded by a read/write mutex, and it holds separate records for agent and browser connections:

```go
// Structure (abridged)
type Hub struct {
    mu            sync.RWMutex
    agents        map[string]*conn  // agentID → connection
    browsers      []*conn
    signer        *rsa.PrivateKey   // deployment command-signing key
    allowedOrigin string            // host a browser WS Origin must match
}
```

Message types (all defined in `internal/models/schema.go`):

| Constant | Value | Purpose |
|---|---|---|
| `MsgHeartbeat` | `"heartbeat"` | Agent heartbeat received (updates Last Seen) |
| `MsgScenarioResult` | `"scenario_result"` | Scenario result received from an agent |
| `MsgRunEvent` | `"run_event"` | Run progress event |
| `MsgAPJobUpdate` | `"ap_job_update"` | AP job status change |
| `MsgAPJobProgress` | `"ap_job_progress"` | AP job progress update |
| `MsgAttackPathCollected` | `"attackpath_collected"` | AP collection complete |
| `MsgAgentReconnected` | `"agent_reconnected"` | Agent came back online |
| `MsgAgentDisconnected` | `"agent_disconnected"` | Agent WebSocket dropped |
| `MsgTamperAlert` | `"tamper_alert"` | Filesystem tamper detected |

---

## ART Payload Resolution

```
Scenario YAML declares: art_technique="T1003.001" art_test_index=0
           │
           ▼
       scenario/art.go → ARTStore.GetStepsByPlatform()
           │
           ▼
       In-memory ARTStore, loaded at startup by:
         SELECT technique_id, name, executor, command, cleanup, timeout_sec, required_payloads, platform, requires_priv
         FROM art_atomic_tests
         ORDER BY technique_id, test_index
           │
           ▼
       Platform filter (agent OS)
           │
           ▼
       Substitutes InputArguments
           │
           ▼
       Returns complete RunStepCommand{executor, command, cleanup}
           │ (ready-to-execute — no ART parsing on agent)
           ▼
       Dispatched to agent
```

The ART library (YAML) is seeded into PostgreSQL on first startup. Tables:
- `art_atomic_tests` — parsed individual test definitions
- `art_atomic_raw` — original YAML text per technique (for reseed)
- `art_payloads` — metadata for external payload files

---

## Scoring Engine

`ComputeScore` in `internal/models/score.go` builds the run score from the run's technique results.

```go
type Score struct {
    PreventionScore         float64  // 0–100, weighted pass rate
    ExposureScore           float64  // 0–100, tactic-weighted fail rate
    CoverageScore           float64  // 0–100, % of tested tactics with zero failures
    KillChainCoverage       float64  // 0–100, % of ATT&CK enterprise tactics exercised
    KillChainAmplifier      float64  // 1.0–2.5, consecutive kill-chain failures
    Trend                   string   // Improving | Degrading | Stable | Baseline
    PreviousPreventionScore float64
    CriticalFailures        []CriticalFailure
}
```

Input: the run's technique results, each with a result type and a severity.

Algorithm:
1. Results with type Skipped, Error or Vetoed are excluded from scoring and counted separately.
2. `PreventionScore`: severity-weighted share of Pass and Blocked results × 100.
3. `ExposureScore`: tactic-weighted fail rate, amplified by kill-chain depth.
4. `KillChainAmplifier`: multiplier from consecutive kill-chain phase failures.
5. `CoverageScore`: % of tested tactics where no step failed.
6. `Trend`: compare PreventionScore to the previous run for the same agent and scenario.

---

## Database Tables (Key)

| Table | Purpose |
|---|---|
| `users` | User accounts (email, password hash, role, must_change_pw) |
| `agents` | Agent records (id, hostname, ip, os, state, last_heartbeat) |
| `scenario_runs` | Run instances (id, scenario_id, agent_id, status, scores) |
| `findings` | Control gap findings (technique_id, agent_id, severity, status) |
| `remediations` | Grouped by technique across agents |
| `campaigns` | Campaign definitions and schedules |
| `exercise_executions` | Exercise execution records with evidence chain |
| `attackpath_jobs` | AP collection job lifecycle tracking |
| `art_atomic_tests` | ART individual test definitions |
| `art_atomic_raw` | Raw YAML (for reseed) |
| `art_payloads` | ART payload metadata |
| `audit_logs` | Audit log entries |

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
       │       │     └── found → RSA-SHA256 check (integrity.VerifyScenarioFile)
       │       │             │
       │       │             ├── invalid → refused, not added to the scenario map
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
- A run whose agent has been silent for more than 90 seconds (the agent offline threshold) is marked `partial` when a new run is dispatched to that agent
- Agent reconnects, submits buffered results
- Server processes results and sets the run to `completed` (or `partial` if the submission is itself partial), even if the run was already `partial` or `failed`
- Finding creation runs on every submission, partial ones included, and is idempotent

---

## Attack Path Job State Machine (Server Side)

```go
// attackpath_jobs.go
// State transitions enforced in the database via status column checks

queued → dispatched        (job sent to agent over WebSocket)
dispatched → running      (agent ACK via AckAttackPathJob)
dispatched → delivery_failed  (no ACK within 30 seconds)
running → completed       (results submitted via SubmitAttackPathCollection)
running → failed          (agent reported an error)
running → timed_out       (per-job timeout: 30 s + 3 s per target, clamped to 2–15 minutes;
                           enforced by the StartAPJobMonitor loop, which runs every 15 seconds)
any active state → cancelled  (operator action)
```

---

*© Audspect — Confidential — Customer Distribution*
