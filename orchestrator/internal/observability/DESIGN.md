# Observability Instrumentation Boundaries

## Correlation ID Flow

Correlation IDs propagate through the execution pipeline:

```
Run (API) → Task (Scenario Definition) → Attempt (Job Dispatch) → Agent (Dispatch) → Process (Executor)
```

### ID Origins

- **run_id**: Created at API entry point when a run is initiated (`POST /api/runs`)
- **task_id**: Defined in scenario manifest; generated at scenario load time
- **attempt_id**: Created in job dispatch when a task retry occurs; starts at 1 for first attempt
- **agent_id**: Assigned when executor dispatches task to an agent pool; stable per agent lifecycle

## Execution Boundaries

### Scheduler Layer (`orchestrator/internal/exercise/scheduler.go`)

- **Entry point**: `Scheduler.Start(tick func(ctx context.Context))`
- **Responsibility**: Periodic polling (1s default), context propagation to executor
- **Instrumentation**:
  - Wrap `tick()` to measure polling frequency
  - Record `scheduler_tick_duration_seconds` histogram
  - No correlation IDs available at this layer (context.Background() only)

### Executor Layer (`orchestrator/internal/exercise/executor.go`)

- **Entry point**: `Executor.tick(ctx context.Context)` (called by scheduler)
- **Responsibility**: Advance DAG step state machines, invoke step handlers
- **Key functions**:
  - `tick()`: Main polling loop, reads DB, updates state
  - `handleAgentTask()`: Dispatches task to agent via `e.dispatch()`
  - `handleWaitForAgent()`: Waits for agent response
- **Instrumentation**:
  - `Executor.tick()` starts a span, records `executor_tick_duration_seconds`
  - `handleAgentTask()` receives run_id, task_id from DB; adds to context before dispatch
  - Measure `agent_dispatch_latency_seconds` (time to dispatch vs. actual execution start)

### Job Dispatch Layer (Job Engine)

- **Entry point**: Job state machine transitions (Pending → Queued → Running → Done)
- **Responsibility**: Manage retry logic, backoff, timeout handling
- **Instrumentation**:
  - Record `task_queue_wait_duration_seconds` when transitioning Pending → Queued
  - Track attempt_id in context before job execution
  - Measure `task_execution_duration_seconds` from Running → terminal state

### Agent Task Handler (`handleAgentTask()`)

- **Context available**: run_id, task_id
- **Responsibility**: Serialize task payload, invoke dispatch function
- **Instrumentation**:
  - Add run_id, task_id to context before dispatch
  - Record `agent_dispatch_latency_seconds` from now to actual agent execution start
  - Log task dispatch event with correlation IDs

### Agent Execution (Remote Process)

- **Entry point**: Agent receives task via HTTP/gRPC from dispatch channel
- **Responsibility**: Execute task locally (run ART atomics, collect evidence)
- **Instrumentation**:
  - Agent reads correlation IDs from task payload (run_id, task_id, attempt_id)
  - Agent logs with correlation IDs (structured JSON output)
  - Agent emits execution telemetry: technique, status, duration, error
  - Sends result back with correlation IDs for reconciliation

## Current Metrics (Baseline)

**Existing in `orchestrator/internal/api/observability.go`:**
- `http_requests_total` (counter, by method/route/status)
- `http_request_duration_seconds` (histogram, by method/route)
- `jobs_active` (gauge, by job type)
- `job_execution_duration_seconds` (histogram, by job type)
- `sla_breach_evaluations_total` (counter)
- `sla_breaches_total` (counter, by severity)
- `db_ready` (gauge)

**Not yet instrumented:**
- Queue wait times (Pending → Queued)
- Scheduler tick frequency and latency
- Agent dispatch latency (local system to remote agent)
- Execution duration by technique (not just job type)
- Agent resource usage (CPU, memory during execution)

## Overhead Budget: 0.5ms per task

### Allocation
- Correlation ID context management: ~0.05ms (4 WithX calls + 1 GetX call)
- Metric recording (histograms): ~0.15ms (3-4 histogram observations)
- Structured logging (slog with JSON): ~0.2ms (per log line, amortized across execution)
- Span emission (OpenTelemetry, if enabled): ~0.1ms (configurable, off by default)

### Overhead when idle
- No profiling: <0.01ms (lazy initialization, no collection)
- No tracing: <0.01ms (context propagation only)
- No alerting: <0.01ms (rule engine disabled)

## Spans to Emit (P1)

For OpenTelemetry distributed tracing (optional, configurable export):

- **task_dispatch**: Start when `handleAgentTask()` begins, end when agent receives task
  - Attributes: run_id, task_id, agent_id, payload_size
- **task_execution**: Start when agent begins executing, end when result is sent back
  - Attributes: run_id, task_id, attempt_id, agent_id, technique, status
- **job_step**: Start when step enters executor, end when step reaches terminal state
  - Attributes: run_id, step_type, step_name, result

## Metrics to Add (P0)

**Task Queue Layer:**
- `task_queue_wait_duration_seconds` (histogram) — Time from Pending to Queued
  - Labels: task_type (bounded: "agent_task", "wait", "approval", etc.)

**Scheduler Layer:**
- `scheduler_tick_duration_seconds` (histogram) — Time per scheduler tick
  - Labels: none (single series)
- `scheduler_active_tasks` (gauge) — Number of tasks in DAG at tick time
  - Labels: none (single series)

**Agent Dispatch Layer:**
- `agent_dispatch_latency_seconds` (histogram) — Time from dispatch call to agent start
  - Labels: agent_pool (bounded: pool name from config)
- `agent_available` (gauge) — Number of available agents ready to receive tasks
  - Labels: agent_pool

**Execution Layer:**
- `execution_duration_seconds` (histogram) — Time from step start to step end
  - Labels: step_type (bounded: "agent_task", "wait", "webhook", etc.)
- `execution_errors_total` (counter) — Total execution errors
  - Labels: step_type, error_code (bounded)

**Resource Layer (P1+):**
- `agent_cpu_seconds` (histogram) — CPU time consumed by agent during execution
  - Labels: agent_pool (gauge, sampled)
- `agent_memory_bytes` (histogram) — Peak memory during execution
  - Labels: agent_pool (gauge, sampled)

## Instrumentation Points (Summary)

| Layer | Function | Metric(s) | Span(s) |
|-------|----------|-----------|--------|
| Scheduler | `Scheduler.Start/Stop` | `scheduler_tick_duration_seconds` | — |
| Executor | `Executor.tick()` | `execution_duration_seconds` (step type) | `job_step` |
| Executor | `handleAgentTask()` | `agent_dispatch_latency_seconds` | `task_dispatch` |
| Job Dispatch | Job state transitions | `task_queue_wait_duration_seconds` | — |
| Agent Dispatch | Task received | Read run_id, task_id, attempt_id from payload | `task_execution` |
| Logging | All layers | Structured slog output with correlation IDs | — |

## Implementation Order

1. **Task 2**: Correlation ID context propagation (WithRunID, WithTaskID, etc.)
2. **Task 3**: Metrics expansion (add histogram collectors)
3. **Task 4**: Built-in dashboard (/api/observability/summary endpoint)
4. **Task 5**: OpenTelemetry SDK and span emission
5. **Task 6-10**: Exporters, alerting, profiling, tests, docs
