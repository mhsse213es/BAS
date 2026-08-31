# Load / Performance / Scale Testing — Design

**Status:** Platform Roadmap 2026H2, Phase 8 (Production Readiness) —
[[project_platform_roadmap_2026h2]]. Backup/restore+DR and monitoring/
observability are already done ([[project_backup_recovery]],
[[project_observability_foundation]]); this is the load/perf/scale piece of
Phase 8's remaining scope, split off from penetration testing (its own
future sub-project — different discipline, needs its own design pass) and
from release documentation (also its own future sub-project). Target
environment is a dedicated test/staging server — not client PROD — so
aggressive load generation carries no risk to real customer data or uptime.

## Goal

Answer, with real numbers: *how big an agent fleet can one Audspect
orchestrator instance support, while users are simultaneously working the
dashboard/API, before latency or errors degrade past acceptable bounds* —
and characterize what happens beyond that point. Not "can the WebSocket
server handle N sockets" in isolation — the combined agent-plane +
API-plane picture, since that's the real production question.

## Scope

**In scope:**
- Extracting a clean, execution-free `agent/protocol` package from the
  current `agent/agent.go` monolith, with regression + wire-contract tests
  proving the real agent's behavior is unchanged.
- A `go.work` workspace so a new `orchestrator/cmd/loadgen` binary can
  import `agent/protocol` directly — no duplicated protocol implementation.
- `loadgen`: a Go binary that simulates N agents' full lifecycle (enroll →
  WS connect → heartbeat → dispatch → fake execution → result submission)
  against a real server, with configurable scale/ramp/timing and detailed
  client-side metrics.
- k6 scripts exercising the HTTP/API plane with a realistic endpoint mix.
- A combined-test runbook: loadgen + k6 run simultaneously against the
  staging server, at a staged fleet-size ramp (100 → 500 → 1,000 → 2,500 →
  5,000 → 10,000), scraping the orchestrator's own `/metrics` throughout
  for server-side impact (process CPU/RSS, `jobs_active`,
  `http_request_duration_seconds`).
- A written capacity report with real numbers: p95/p99 latencies, error
  rates, connection stability, and resource consumption at each fleet size.

**Explicitly out of scope**, decided during brainstorming:
- **Penetration testing.** Different discipline, own future sub-project.
- **Release documentation.** Own future sub-project.
- **Postgres-side instrumentation** (connection pool stats, query
  latency). Not currently exposed via `/metrics`; adding new DB
  instrumentation is beyond this sub-project. The orchestrator process's
  own resource footprint (via `/metrics`'s existing Go/process collectors)
  is in scope; the database's isn't.
- **A `protocol`/`transport` sub-split inside `agent/protocol`.** The
  immediate objective is a clean execution-free boundary, not a full
  agent-architecture rewrite. Don't over-engineer Task 0.
- **Client PROD testing of any kind.** This entire sub-project targets the
  dedicated staging server only.
- **10,000-agent SLO parity with the 5,000-agent milestone.** 10k is
  stretch/characterization, not a second production-capacity claim.
- **Real-traffic-derived k6 workload mix on day one.** Staging has no
  traffic history yet; the mix starts as an informed estimate and gets
  refined once `http_requests_total{route}` accumulates real data.

## Task 0 — Protocol extraction

`agent/agent.go` (1,170 lines, `package main`) currently entangles wire
protocol (enroll, heartbeat, WS connect, result submission) with real
execution (`runScenario`, `runLocalScan` — actual OS-touching technique
logic, job/watchdog state). `loadgen` needs the former without the latter,
and must never duplicate it by hand (a hand-duplicated protocol is a
second implementation that silently drifts from the real agent, producing
a "green" load test that no longer represents production).

New package `agent/protocol/`:
```
agent/
├── agent.go            # orchestration/execution (unchanged in spirit)
└── protocol/
    ├── messages.go     # wire structures (enroll req/resp, heartbeat,
    │                   #   WS message envelopes, dispatch, result payload)
    ├── enroll.go        # enrollment request/response handling
    ├── heartbeat.go      # heartbeat payload construction/send
    ├── websocket.go       # WS connect/message encode-decode
    └── result.go          # result submission serialization
```

**Hard rule:** `agent/protocol` contains zero OS/technique-execution
logic. It knows about wire formats, serialization, and network calls; it
does not know how a scenario is actually run. If moving a piece into
`protocol` would require changing execution behavior, that piece stays in
`agent.go` — stop and reconsider the boundary rather than forcing it.

The real `Agent` (in `agent.go`) becomes a consumer of `agent/protocol`
for its wire-level calls, with its execution logic (`runScenario`,
`runLocalScan`, job state, watchdogs) untouched in place.

## Task 1 — Preserve the real agent

Before `loadgen` exists at all: the full existing `agent` test suite
(`go test ./...` in the `agent` module) must pass unchanged after the
extraction. This is the primary regression gate — if this doesn't pass,
Task 0 isn't done, regardless of how clean the new package looks.

## Task 2 — Protocol wire-contract tests

New tests in `agent/protocol/*_test.go`, testing the wire contract
specifically, not just "the function returned without erroring":
- Enrollment request serialization and response parsing.
- Heartbeat payload serialization.
- WS message encoding/decoding (both directions).
- Dispatch message parsing.
- Result payload serialization.
- Malformed-message handling (server sends garbage — must not panic,
  must surface a clear error).
- Server-error handling (non-2xx responses, connection drops).

Where practical, capture a real payload from the pre-refactor code path
(e.g. via a one-off script run against the current `agent.go` before
touching it) and assert the post-refactor `agent/protocol` code produces
byte-identical (or semantically identical, for non-deterministic fields
like timestamps) output. This is a stronger regression boundary than
"it compiles and the existing tests still pass."

## Task 3 — `go.work`

Repo-root `go.work`:
```
go 1.26.0

use (
	./agent
	./orchestrator
)
```

Both modules already pin `go 1.26.0` — no version-mismatch risk.

**CI verification, explicit task, not an assumption:** `.github/workflows/
test.yml` currently runs everything with `working-directory: orchestrator`
and never touches the `agent` module at all. `./...`-style commands stay
directory-scoped regardless of workspace mode, so existing CI steps
(`gofmt -l .`, `go vet ./...`, `staticcheck ./...`, `go build ./...`,
`go test ./... -race -coverprofile=coverage.out`) should keep building only
`orchestrator`'s own packages — but the new `orchestrator/cmd/loadgen`
becomes a real dependency of that build the moment it imports
`agent/protocol`, so CI is now implicitly building a slice of the `agent`
module too. This task actually runs CI (or an equivalent clean-checkout
build) after `go.work` lands and after `loadgen` exists, and confirms:
gofmt/vet/staticcheck/build/test all still pass, and nothing about the
existing `orchestrator`-only build's package set changed. `go.work` is a
development/build convenience — it must not become an implicit production
dependency (it's never referenced by any Dockerfile or release build step).

## Task 4 — `loadgen`: state machine and configuration

New `orchestrator/cmd/loadgen/main.go` (+ supporting files as needed).
Each simulated agent runs this state machine, built on `agent/protocol`:

```
START
  ↓
ENROLL
  ↓
AUTHENTICATE
  ↓
WS CONNECT
  ↓
HEARTBEAT LOOP ──────────────┐
  ↓                          │
WAIT FOR DISPATCH             │
  ↓                          │
RECEIVE SCENARIO               │
  ↓                          │
SIMULATE EXECUTION              │
  (configurable sleep, then     │
   a realistic fake result       │
   payload — never real          │
   technique execution)           │
  ↓                          │
SUBMIT RESULT                 │
  ↓                          │
WAIT ──────────────────────────┘
```

CLI flags:
```
--agents <int>              total simulated fleet size
--ramp-rate <N>/s           agents enrolled per second during ramp-up
--duration <duration>       how long to hold steady-state after ramp
--heartbeat <duration>      per-agent heartbeat interval
--scenario-rate <rate>      how often a simulated agent receives a dispatch
--execution-latency <dur>   fake-execution sleep duration (fixed or range)
--result-size <bytes>       approximate size of the fake result payload
--disconnect-rate <rate>    fraction of agents that randomly disconnect/
                            reconnect during the run, to exercise the
                            reconnect path
--server <url>              target orchestrator base URL
```

Metrics collected and reported (stdout + CSV, one row per interval):
- Enrollment latency
- WS connection latency
- Heartbeat success/failure counts
- Dispatch latency (server push → agent receipt)
- Result submission latency
- Reconnect time (post-disconnect)
- Connection drop count
- Protocol errors (malformed/unexpected messages)
- HTTP errors (non-2xx)
- Active agent count (live gauge)
- Messages/sec, results/sec

`loadgen`'s own state-machine logic gets unit tests against a mock HTTP/WS
test server (`httptest.Server` + a WS test harness) — verifying the state
transitions and metric recording without needing a live orchestrator.
Integration validation (Tasks 5-6 below) is separate and runs against the
real staging server.

## Task 5-6 — Validate against the real server

Staged ramp, run in order, each a real invocation against the staging
server:

| Stage | Fleet size | Purpose |
|---|---|---|
| 1 | 100 | Protocol correctness — does the full lifecycle work at all |
| 2 | 500 | Basic stability |
| 3 | 1,000 | Baseline capacity |
| 4 | 2,500 | Scale validation |
| 5 | 5,000 | **Primary capacity milestone** — must meet the SLOs defined below |
| 6 | 10,000 | **Stretch/characterization only** — no SLO requirement; the goal is finding where the curve bends (latency degradation, resource exhaustion, connection instability), not claiming 10k production capacity |

SLOs for the 5,000-agent milestone (initial working numbers, adjust once
stage-3/4 data exists to sanity-check them): heartbeat success rate
≥99.5%, dispatch p95 latency under 5s, result-submission p95 latency under
5s, zero unexpected connection drops under normal (non-`--disconnect-rate`)
operation.

## Task 7 — Ramp/duration/metrics

Covered by Task 4's CLI surface and metrics list above; kept as its own
numbered section (matching the approved 0-9 sequence) because the
implementation plan should give it its own verification checkpoint —
confirming ramp-rate pacing and metric recording actually work under a
real run — rather than folding it silently into the initial `loadgen`
scaffold's own task.

## Task 8 — k6 (independent of loadgen)

New `orchestrator/loadtest/k6/` (or similar) directory with `.js` scripts
exercising a realistic mixture of the dashboard/API surface, not hammering
one endpoint. Working mix to implement (informed estimate, grounded in
what the dashboard UI actually calls most — a concrete starting point, not
a placeholder; refine once `http_requests_total{route}` has real staging
traffic to compare against):

| Category | Share | Example endpoints |
|---|---|---|
| Dashboard/read queries | 60% | `GET /api/dashboard/*`, `GET /api/agents`, `GET /api/campaigns` |
| Run/result queries | 20% | `GET /api/runs/*`, `GET /api/scenarios/runs/*` |
| Finding/posture queries | 10% | `GET /api/findings`, posture-finding endpoints |
| Report generation | 10% | `POST /api/reports/*` |

k6's built-in ramping-VUs executor, latency percentiles, and thresholds
cover this without any custom tooling.

## Task 9 — Combined fleet + API stress test

```
                 ┌──────────────┐
                 │    k6        │
                 │ API traffic  │
                 └──────┬───────┘
                        │
                        ▼
                 ┌──────────────┐
                 │    BAS       │
                 │   Server     │
                 └──────┬───────┘
                        ▲
                        │
                 ┌──────┴───────┐
                 │  loadgen     │
                 │ 1k/5k/10k... │
                 └──────────────┘
```

`k6` and `loadgen` run simultaneously against the staging server at each
stage of the ramp table above (Tasks 5-6 already validated the agent
plane alone; this repeats the ramp with API traffic running concurrently,
since that's the combination that actually matters). A lightweight
runbook script scrapes the orchestrator's `/metrics` endpoint at a fixed
interval throughout each run (curl in a loop is sufficient — no
Prometheus server needed for this), capturing `process_cpu_seconds_total`,
`process_resident_memory_bytes`, `jobs_active`, and
`http_request_duration_seconds` alongside loadgen's and k6's own output.

**Deliverable:** a written capacity report (plain markdown, committed to
`docs/`) with per-fleet-size tables: loadgen's client-side metrics, k6's
latency/error percentiles, and the `/metrics` snapshots — closing with a
plain-language answer to "how big a fleet can Audspect support, and what
happens past that point."

## Testing summary

- `agent/protocol`: wire-contract tests (Task 2), run as part of the
  `agent` module's normal test suite.
- `agent` (existing): full regression suite must pass unchanged (Task 1).
- `loadgen`: unit tests against a mock HTTP/WS server for state-machine
  correctness (Task 4); real-server validation is integration-level, run
  manually against staging (Tasks 5-6, 9), not part of any CI job.
- `k6` scripts: no unit tests (k6 scripts are themselves the test) —
  correctness is "the script hits the intended endpoint mix in the
  intended proportions," checked by reading k6's own summary output.
- CI: explicit verification task (Task 3) that adding `go.work` doesn't
  change what the existing `orchestrator`-scoped CI job builds/tests.

## Migration

No DB schema change. No production code path changes beyond the
`agent/agent.go` → `agent/protocol` extraction (behavior-preserving by
construction, gated on Task 1's regression suite). `go.work` is
development/build-only, never referenced by any release/Docker build step.
