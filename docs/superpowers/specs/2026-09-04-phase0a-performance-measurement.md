# Phase 0A: Windows Execution Performance Measurement & Fix

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:writing-plans to create the implementation plan for this spec.

**Goal:** Measure where time is actually spent in Windows execution (orchestrator → agent → orchestrator cycle) so we can identify and fix the largest bottleneck before building adaptive planning (Phase 0B/2/3).

**Architecture:** Lightweight instrumentation via execution_id correlation + timestamping at orchestrator checkpoints + minimal agent-side logging. Post-run log parsing produces latency table (median/P95 per stage). Hypothesis testing targets PowerShell overhead and scheduler serialization.

**Tech Stack:** Go (orchestrator + agent), structured logging (slog), post-run log parsing utility

**Spec:** This document. Based on architectural discussion: Phase 0A is foundation before Phase 0B (ExecutionAttempt) and Phase 2-3 (DAG/parallel). Windows agent is performance-sensitive; this measurement prevents premature optimization while enabling data-driven fixes.

## Global Constraints

- Instrumentation overhead must be negligible when not actively measured (no performance impact on production)
- Execution_id propagation must not break existing code paths (additive only)
- Log parsing must be deterministic and reproducible
- No new external dependencies (use stdlib + existing slog infrastructure)
- Measurement runs on both local Docker Compose and staging (zain@audspectserver)

---

## Problem Statement

Current state: Unknown where time is spent in execution cycle. Suspected bottlenecks are:

1. **PowerShell process overhead** (🔴 highest suspicion): Process startup + PowerShell initialization adds ~300ms per technique; 100 small techniques becomes expensive
2. **Scheduler/resource serialization** (🟠 secondary suspicion): Techniques may be accidentally serialized when they should parallelize; would explode scenario duration
3. **Network/serialization** (lower suspicion): Agent communication latency
4. **Evidence correlation** (lower suspicion): Post-execution log processing
5. **Scoring** (lowest suspicion): Verdict calculation

Without measurement, we're guessing. Phase 0A produces concrete data to drive Phase 0B and beyond.

---

## Design

### 1. Execution ID Propagation

**Definition:**
Unique identifier per execution attempt: `{run_id}/{task_id}/{attempt_id}` (e.g., `run-abc123/task-1/attempt-1`)

**Flow:**
```
Orchestrator (scheduler.go)
    ↓
    generates execution_id
    ↓
Orchestrator (executor.go)
    ↓
    includes execution_id in agent dispatch payload
    ↓
Agent (executor.go)
    ↓
    receives execution_id, includes in logs
    ↓
Agent sends result + execution_id back to orchestrator
    ↓
Orchestrator logs execution_id in result processing
```

**Implementation:**
- Scheduler creates execution_id when task is created (within `Task` struct or context)
- Executor receives execution_id from scheduler, carries through dispatch
- Agent payload includes execution_id; agent logs it with each checkpoint
- All logs include `[execution_id]` prefix for easy grepping

**Backward compatibility:** Execution_id is optional metadata; absence doesn't break anything. Old log entries without it are simply ignored by parser.

### 2. Orchestrator Instrumentation Points

**File: orchestrator/internal/exercise/scheduler.go**

Timestamps at:
- `queue_wait_started`: When task is queued in scheduler
- `queue_wait_finished`: When task is dequeued and ready for dispatch
- Duration: `queue_wait = queue_wait_finished - queue_wait_started`

Log format:
```
[execution_id=run-abc/task-1/attempt-1] queue_wait_started: 2026-09-04T12:01:00.001Z
[execution_id=run-abc/task-1/attempt-1] queue_wait_finished: 2026-09-04T12:01:00.003Z
```

**File: orchestrator/internal/exercise/executor.go**

Timestamps at:
- `dispatch_started`: When executor begins dispatch to agent
- `dispatch_sent`: When dispatch message is sent to agent (network layer)
- Duration: `dispatch_latency = dispatch_sent - dispatch_started`

Timestamps at:
- `result_received`: When orchestrator receives result from agent
- `evidence_processing_done`: After evidence correlation completes
- `scoring_completed`: After verdicts are assigned
- Durations: `result_transport`, `evidence_processing`, `scoring`

Log format:
```
[execution_id=run-abc/task-1/attempt-1] dispatch_started: 2026-09-04T12:01:00.003Z
[execution_id=run-abc/task-1/attempt-1] dispatch_sent: 2026-09-04T12:01:00.004Z
[execution_id=run-abc/task-1/attempt-1] result_received: 2026-09-04T12:01:00.325Z
[execution_id=run-abc/task-1/attempt-1] evidence_processing_done: 2026-09-04T12:01:00.326Z
[execution_id=run-abc/task-1/attempt-1] scoring_completed: 2026-09-04T12:01:00.327Z
```

**No changes to control flow.** Timestamps are logged after existing logic, not before. Exception: If dispatch fails, log `dispatch_failed` with reason.

### 3. Agent Instrumentation Points

**File: agent/executor.go** (Windows agent)

Minimal logging (two lines per execution):
- `execution_started`: When PowerShell/cmd command is about to launch
- `execution_finished`: When command exits (regardless of success/failure)

These timestamps allow orchestrator to calculate: `agent_execution = execution_finished - execution_started`

Log format (via agent's existing logging):
```
[execution_id=run-abc/task-1/attempt-1] execution_started: 2026-09-04T12:01:00.312Z
[execution_id=run-abc/task-1/attempt-1] execution_finished: 2026-09-04T12:01:00.321Z
```

**No overhead:** Just two log lines per technique. No structured instrumentation, no metrics collection, no external calls.

### 4. Log Parsing & Analysis

**New utility: scripts/parse-performance-logs.go**

Purpose: Extract execution_id lines from orchestrator + agent logs, calculate per-stage durations, produce latency table.

**Input:**
- Orchestrator log file (stdout/stderr captured during run)
- Agent log file (stdout/stderr captured during run, from agent host)
- Run ID (to filter for specific run)

**Output:**
Latency table (CSV + pretty-printed):
```
Stage                  Median (ms)    P95 (ms)    Max (ms)    Count
Queue wait             2              5           10          42
Dispatch latency       1              2           5           42
Agent execution        320            350         400         42
Result transport       5              10          20          42
Evidence processing    50             100         200         42
Scoring                20             50          100         42
Total                  398            517         735         42
```

**Algorithm:**
1. Parse all log lines, filter for `[execution_id=...]` prefix
2. For each unique execution_id, extract timestamps for each stage
3. Calculate stage durations
4. Compute median/P95/max across all executions
5. Output table

**Implementation notes:**
- Robust to log interleaving (different order of orchestrator/agent lines)
- Ignores partial executions (missing start or end timestamp)
- Reports which execution_ids were incomplete (for debugging)

### 5. Measurement Methodology

#### Environment 1: Local (Docker Compose)

**Setup:**
- `docker-compose up` on Windows host (existing compose file)
- One Windows container agent, fresh PowerShell per step
- Orchestrator and agent logs captured to files

**Scenario:** `windows-discovery.yaml`
- ~30-40 steps (discovery techniques: T1082, T1087, T1018, T1057, etc.)
- Expected duration: 5-10 minutes per run
- Run 3 times (measure median across runs)

**Data collection:**
- Enable DEBUG-level logging during runs
- Capture orchestrator stdout/stderr → `orchestrator.log`
- Capture agent stdout/stderr → `agent.log` (from container)
- Run parse-performance-logs: `parse-performance-logs orchestrator.log agent.log run-{id}`

**Goal:** Establish baseline in controlled environment.

#### Environment 2: Staging (zain@audspectserver)

**Setup:**
- Existing Windows agent already enrolled at 192.168.10.78:9443
- Orchestrator accessible via SSH/RDP

**Scenario A (Quick):** `windows-discovery.yaml`
- Same as local; validate findings in production-like network

**Scenario B (Full):** `art-full-windows.yaml`
- 100+ techniques (all atomics across all techniques)
- Expected duration: 30+ minutes
- Run once (staging is production-adjacent; don't hammer it)
- Measures sustained scheduler load + evidence correlation overhead

**Data collection:** Same as local (logs + parse-performance-logs)

**Goal:** Validate local findings at scale and in realistic network.

### 6. Hypothesis Testing

#### Hypothesis #1: PowerShell Process Overhead

**Suspicion level:** 🔴 Highest

**Test approach:**
1. Extract `agent_execution` durations from latency table (local run)
2. For first technique in run, examine raw agent log:
   - `execution_started` → `execution_finished` = first PowerShell startup
   - Expected: ~300ms for fresh PowerShell (even if command is trivial)
3. Compare against host-pool execution:
   - If pool is being used, pool dispatch should be <100ms
   - If execution still takes 300+ms, PowerShell overhead is dominant
4. Run comparison test (if host pool exists):
   - Measure time from `dispatch_sent` to `execution_started` (pool dispatch time)
   - Measure time from `execution_started` to `execution_finished` (PowerShell + command time)
   - If pool dispatch is fast but execution is slow, PowerShell is the bottleneck

**Expected finding:**
- If `agent_execution` is consistently 300-500ms even for trivial commands (e.g., `whoami`), PowerShell startup is the bottleneck
- Fix direction: Pooling strategy improvements, warm-up techniques, or consider alternative executor

**Not the bottleneck if:**
- `agent_execution` scales with command complexity (e.g., recursive file scan is 5s, whoami is 20ms)
- Pool dispatch time dominates overall execution

#### Hypothesis #2: Scheduler Serialization

**Suspicion level:** 🟠 Secondary

**Test approach:**
1. Extract `dispatch_sent` timestamps from latency table (staging, full sweep)
2. Analyze dispatch pattern:
   - Parallel: Multiple techniques have `dispatch_sent` within same 100ms window
   - Serialized: Gap between `dispatch_sent` entries is consistently >1s
3. If serialized, examine scheduler code:
   - Look for mutex locks held during dispatch loop
   - Check if resource contention logic is blocking (should be conflict-based, not blanket)
   - Inspect task batch size (should batch multiple tasks if not resource-constrained)
4. Run test with resource footprint inspection:
   - Modify scheduler to log when it skips dispatch due to resource conflict
   - If logging shows many skips, resource locking is too aggressive

**Expected finding:**
- If dispatch is serialized and gap is >1s, scheduler is bottleneck
- Fix direction: Unlock batch dispatch, refine resource conflict detection, or add concurrent dispatch queue

**Not the bottleneck if:**
- Multiple techniques are dispatched within 100ms window (parallel)
- Or dispatcher is waiting for agent to consume task (network/agent limitation)

### 7. Success Criteria

**Phase 0A Complete when:**

1. ✅ **Execution_id propagation implemented and tested**
   - Execution_id created at task queue time, passed through scheduler → executor → agent
   - Unit tests verify propagation through each component
   - No existing code paths broken

2. ✅ **All timestamps logged at specified checkpoints**
   - Orchestrator logs 7 timestamps (queue_wait_started/finished, dispatch_started/sent, result_received, evidence_processing_done, scoring_completed)
   - Agent logs 2 timestamps (execution_started, execution_finished)
   - Integration test runs quick scenario, verifies all timestamps present in logs

3. ✅ **Log parser produces latency table**
   - `parse-performance-logs` utility reads orchestrator + agent logs
   - Outputs latency table with median/P95 for each stage
   - Manual verification: Table values are sensible (positive durations, total ≈ sum of stages)

4. ✅ **Local baseline captured**
   - Run `windows-discovery.yaml` 3 times on Docker Compose
   - Parse logs from all 3 runs
   - Produce aggregate latency table (median/P95/max across 3 runs)
   - Save to `reports/phase0a-local-baseline.txt`

5. ✅ **Staging validation captured**
   - Run `windows-discovery.yaml` on staging (quick scenario)
   - Run `art-full-windows.yaml` on staging (full sweep)
   - Parse logs from both runs
   - Produce separate latency tables
   - Save to `reports/phase0a-staging-quick.txt` and `reports/phase0a-staging-full.txt`

6. ✅ **Hypothesis #1 & #2 investigated**
   - For Hypothesis #1: Extract first technique's `agent_execution` from local baseline; compare against known PowerShell startup time; document finding
   - For Hypothesis #2: Analyze `dispatch_sent` timestamps from staging full sweep; characterize as parallel or serialized; document finding
   - Produce summary: `reports/phase0a-hypothesis-findings.txt` with recommendation for Phase 0B (which bottleneck to fix first)

---

## Testing

### Unit Tests

- **orchestrator/internal/exercise/scheduler_test.go**: Verify execution_id is created and carried through scheduler
- **orchestrator/internal/exercise/executor_test.go**: Verify execution_id is passed to agent dispatch and logged at each checkpoint
- **agent/executor_test.go** (Windows): Verify agent logs execution_started/finished with execution_id

### Integration Test

**Test: TestPhase0APerformanceMeasurement**
- Setup: Start orchestrator + one agent in Docker Compose
- Scenario: Run `windows-discovery.yaml` (1 run, quick)
- Verification:
  - Both orchestrator and agent logs contain `execution_id` entries
  - All 7 orchestrator timestamps present
  - Both agent timestamps present
  - parse-performance-logs runs without error
  - Produced latency table has valid durations (all positive, total ≈ sum)

### Manual QA

- **Local (Docker Compose):**
  - Run 3x `windows-discovery.yaml`
  - Inspect raw logs for execution_id consistency
  - Verify parse-performance-logs output is sensible
  - Save baseline report

- **Staging:**
  - Run `windows-discovery.yaml` 1x (quick scenario)
  - Run `art-full-windows.yaml` 1x (full sweep)
  - Inspect logs for correlation (agent timestamp should align with orchestrator result_received)
  - Verify parsing handles multi-host logs correctly
  - Test hypothesis findings with raw log inspection

---

## Implementation Notes

### No Breaking Changes

- Execution_id is optional; absence doesn't break code
- Timestamps are logged after logic completes; don't affect control flow
- Agent logging is additive (two new log lines per execution)
- Existing test suite should pass without modification

### Performance Impact

- Timestamp operations: negligible (nanosecond precision, no I/O)
- Logging: already using slog; adding two strings per checkpoint has minimal overhead
- Log volume: ~20-30KB per run (small discovery), ~500KB per full sweep (negligible)

### Error Handling

- Missing execution_id: Log parser warns and skips that execution
- Partial execution (missing start/end): Parser reports count of incomplete executions
- Clock skew (backward timestamps): Parser detects and reports; likely indicates system clock issue

---

## Deliverables

**Code:**
- Modified scheduler.go, executor.go (orchestrator)
- Modified agent/executor.go (agent)
- New parse-performance-logs.go (utility)
- Tests for each component

**Reports:**
- `reports/phase0a-local-baseline.txt` — Local latency table (3 runs, median/P95/max)
- `reports/phase0a-staging-quick.txt` — Staging quick scenario
- `reports/phase0a-staging-full.txt` — Staging full sweep
- `reports/phase0a-hypothesis-findings.txt` — Analysis of Hypothesis #1 & #2, recommendation

**Documentation:**
- This spec (committed to git)
- Inline code comments explaining execution_id + timestamps

---

## Timeline

- **Implementation:** 2-3 days (execution_id + logging + parser)
- **Local measurement:** 1-2 hours
- **Staging validation:** 3-4 hours
- **Analysis:** 1 hour
- **Total:** ~3-4 days wall-clock

---

## Next Steps (Phase 0B and Beyond)

Once Phase 0A is complete:

1. **Identify largest bottleneck** from latency table (which stage consumes >50% of total time)
2. **Phase 0B (ExecutionAttempt)** — Build attempt-level state contract for dependency tracking and prerequisite evaluation
3. **Phase 0C (Prerequisites/Effects)** — Add deterministic gating based on system state (domain_joined?, ldap_reachable?)
4. **Phase 1 (Detection Parity)** — Close platform gap (Linux detection, macOS inventory)
5. **Phase 2-3 (DAG/Parallel)** — Implement DAG scenarios and resource-aware parallel execution (H2 2026)

The data from Phase 0A drives all downstream decisions.
