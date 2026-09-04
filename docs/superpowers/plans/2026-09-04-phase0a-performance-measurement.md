# Phase 0A: Windows Execution Performance Measurement Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Instrument orchestrator and Windows agent to measure where time is spent in the execution cycle, identify the largest bottleneck, and produce data-driven recommendations for Phase 0B.

**Architecture:** Lightweight instrumentation via execution_id correlation (run_id/task_id/attempt_id) + timestamps at orchestrator checkpoints + minimal agent logging. Post-run utility parses logs to produce latency table (median/P95 per stage). No performance overhead when not actively measured.

**Tech Stack:** Go (orchestrator + agent), slog (structured logging), post-run log parsing utility

**Spec:** [docs/superpowers/specs/2026-09-04-phase0a-performance-measurement.md](../specs/2026-09-04-phase0a-performance-measurement.md)

## Global Constraints

- Instrumentation overhead must be negligible when not actively measured (no production performance impact)
- Execution_id propagation must be additive (no breaking changes to existing code paths)
- Log parsing must be deterministic and reproducible across multiple runs
- No new external dependencies (use stdlib + existing slog)
- Measurement runs on both local Docker Compose and staging (zain@audspectserver)

---

## File Structure

**Files to modify:**
- `orchestrator/internal/exercise/scheduler.go` — Add execution_id generation + queue_wait timestamps
- `orchestrator/internal/exercise/executor.go` — Add dispatch/result processing timestamps + pass execution_id to agent
- `agent/executor.go` — Add execution_started/finished timestamps

**Files to create:**
- `scripts/parse-performance-logs.go` — Log parser utility to produce latency table
- `orchestrator/internal/exercise/scheduler_test.go` — Unit tests for execution_id in scheduler (if not exists)
- `orchestrator/internal/exercise/executor_test.go` — Unit tests for executor instrumentation (if not exists)
- `agent/executor_test.go` — Unit tests for agent instrumentation (if not exists)

**Test file:**
- `orchestrator/internal/exercise/integration_test.go` — Integration test for full measurement flow

---

## Task Breakdown

### Task 1: Add execution_id Field to Task Struct

**Files:**
- Modify: `orchestrator/internal/exercise/scheduler.go`
- Modify: `orchestrator/internal/exercise/executor.go`

**Interfaces:**
- Consumes: Existing `Task` struct definition
- Produces: `Task.ExecutionID` field (string, format: `{run_id}/{task_id}/{attempt_id}`)

**Steps:**

- [ ] **Step 1: Inspect Task struct in scheduler.go**

Read current Task struct definition to understand its fields and where to add ExecutionID.

```bash
grep -A 20 "type Task struct" orchestrator/internal/exercise/scheduler.go
```

Expected: See existing fields like RunID, ScenarioID, StepIndex, etc.

- [ ] **Step 2: Add ExecutionID field to Task struct**

```go
type Task struct {
    // ... existing fields ...
    RunID string
    TaskID string
    AttemptID string
    ExecutionID string  // NEW: correlation ID for performance measurement (run_id/task_id/attempt_id)
}
```

- [ ] **Step 3: Update Task creation in scheduler to generate ExecutionID**

Find where `Task` is created/pushed onto queue in scheduler. Add execution_id generation:

```go
// In the scheduler's task creation logic (e.g., in Run() or a task enqueue function):
task := &Task{
    RunID: run.ID,
    TaskID: step.ID, // or whatever identifies the individual step
    AttemptID: "1",  // Start at 1 for first attempt; increment on retry
    ExecutionID: fmt.Sprintf("%s/%s/%s", run.ID, step.ID, "1"),
    // ... rest of fields ...
}
```

- [ ] **Step 4: Commit**

```bash
git add orchestrator/internal/exercise/scheduler.go
git commit -m "feat(perf): add ExecutionID field to Task struct for correlation"
```

---

### Task 2: Add queue_wait Timestamps to Scheduler

**Files:**
- Modify: `orchestrator/internal/exercise/scheduler.go`
- Modify: `orchestrator/internal/exercise/scheduler_test.go`

**Interfaces:**
- Consumes: `Task.ExecutionID` from Task 1
- Produces: Logs with format `[execution_id=...] queue_wait_started: 2026-09-04T12:01:00.001Z` and `queue_wait_finished`

**Steps:**

- [ ] **Step 1: Find scheduler's task enqueue and dequeue points**

```bash
grep -n "append.*Task\|queue.*Task\|tasks = \|for.*tasks\|range.*tasks" orchestrator/internal/exercise/scheduler.go | head -20
```

Expected: Identify where tasks are added to queue and where they're removed for dispatch.

- [ ] **Step 2: Add queue_wait_started log when task is queued**

In the scheduler's task enqueue function (find exact function name in Step 1), add:

```go
slog.Info(
    "queue_wait_started",
    "execution_id", task.ExecutionID,
    "timestamp", time.Now().UTC().Format(time.RFC3339Nano),
)
```

(The spec shows RFC3339Nano as the format; adjust if the codebase uses a different timestamp format. Check existing logs for consistency.)

- [ ] **Step 3: Add queue_wait_finished log when task is dequeued**

In the scheduler's dequeue logic (e.g., when a task is popped from the queue for dispatch), add:

```go
slog.Info(
    "queue_wait_finished",
    "execution_id", task.ExecutionID,
    "timestamp", time.Now().UTC().Format(time.RFC3339Nano),
)
```

- [ ] **Step 4: Write unit test**

In `orchestrator/internal/exercise/scheduler_test.go`, add:

```go
func TestSchedulerQueueWaitLogging(t *testing.T) {
    // Setup: Create a scheduler with one task
    sched := NewScheduler()
    run := &Run{ID: "test-run-1"}
    task := &Task{
        RunID: run.ID,
        TaskID: "task-1",
        AttemptID: "1",
        ExecutionID: "test-run-1/task-1/1",
        // ... other fields ...
    }
    
    // Enqueue task
    sched.QueueTask(task) // adjust method name if different
    
    // Dequeue task
    dequeuedTask := sched.DequeueTask() // adjust method name if different
    
    // Assert: task has ExecutionID
    if dequeuedTask.ExecutionID != "test-run-1/task-1/1" {
        t.Fatalf("ExecutionID mismatch: expected test-run-1/task-1/1, got %s", dequeuedTask.ExecutionID)
    }
}
```

(This test verifies the ExecutionID is preserved; log capture is tested in integration test.)

- [ ] **Step 5: Run test**

```bash
cd orchestrator && go test ./internal/exercise -run TestSchedulerQueueWaitLogging -v
```

Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/exercise/scheduler.go orchestrator/internal/exercise/scheduler_test.go
git commit -m "feat(perf): add queue_wait timestamps to scheduler"
```

---

### Task 3: Add ExecutionID to Agent Dispatch Payload

**Files:**
- Modify: `orchestrator/internal/exercise/executor.go`
- Modify: `orchestrator/internal/api/handlers.go` (if agent dispatch goes through API handlers)

**Interfaces:**
- Consumes: `Task.ExecutionID` from Task 1
- Produces: Agent dispatch payload includes `execution_id` field (string)

**Steps:**

- [ ] **Step 1: Find agent dispatch payload structure**

Search for the struct sent to the agent:

```bash
grep -r "type.*Request\|type.*Command\|type.*Dispatch" orchestrator/internal/ | grep -i agent
```

Expected: Find struct like `AgentTaskRequest` or similar.

- [ ] **Step 2: Inspect the dispatch payload struct**

Read the struct definition to understand its current fields:

```bash
grep -A 30 "type AgentTaskRequest struct" orchestrator/internal/ -r
```

- [ ] **Step 3: Add ExecutionID field to dispatch payload**

```go
type AgentTaskRequest struct {
    // ... existing fields like RunID, StepID, Command, etc. ...
    ExecutionID string `json:"execution_id"`  // NEW: correlation ID (run_id/task_id/attempt_id)
}
```

- [ ] **Step 4: Populate ExecutionID when creating dispatch payload**

Find where `AgentTaskRequest` is constructed in executor.go. Populate the field:

```go
req := &AgentTaskRequest{
    RunID: task.RunID,
    StepID: task.StepID,
    ExecutionID: task.ExecutionID,  // NEW
    // ... other fields ...
}
```

- [ ] **Step 5: Write unit test**

In `orchestrator/internal/exercise/executor_test.go`, add:

```go
func TestExecutorIncludesExecutionIDInDispatch(t *testing.T) {
    // Setup: Create executor with a task
    executor := NewExecutor()
    task := &Task{
        ExecutionID: "run-1/task-1/1",
        // ... other fields ...
    }
    
    // Build dispatch payload
    payload := executor.buildDispatchPayload(task)
    
    // Assert: payload contains ExecutionID
    if payload.ExecutionID != "run-1/task-1/1" {
        t.Fatalf("ExecutionID not in dispatch payload: got %s", payload.ExecutionID)
    }
}
```

- [ ] **Step 6: Run test**

```bash
cd orchestrator && go test ./internal/exercise -run TestExecutorIncludesExecutionIDInDispatch -v
```

Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add orchestrator/internal/exercise/executor.go orchestrator/internal/exercise/executor_test.go
git commit -m "feat(perf): add ExecutionID to agent dispatch payload"
```

---

### Task 4: Add Dispatch Timestamps to Executor

**Files:**
- Modify: `orchestrator/internal/exercise/executor.go`
- Modify: `orchestrator/internal/exercise/executor_test.go`

**Interfaces:**
- Consumes: `Task.ExecutionID`, agent dispatch payload from Task 3
- Produces: Logs with format `[execution_id=...] dispatch_started` and `dispatch_sent`

**Steps:**

- [ ] **Step 1: Find dispatch sending logic in executor**

```bash
grep -n "Send\|dispatch\|Agent\|WebSocket\|HTTP" orchestrator/internal/exercise/executor.go | grep -i "send\|write\|submit" | head -10
```

Expected: Identify the function that actually sends the task to the agent.

- [ ] **Step 2: Add dispatch_started log**

Before the dispatch is sent, log:

```go
slog.Info(
    "dispatch_started",
    "execution_id", task.ExecutionID,
    "timestamp", time.Now().UTC().Format(time.RFC3339Nano),
)
```

- [ ] **Step 3: Add dispatch_sent log**

After the dispatch is successfully sent, log:

```go
slog.Info(
    "dispatch_sent",
    "execution_id", task.ExecutionID,
    "timestamp", time.Now().UTC().Format(time.RFC3339Nano),
)
```

If dispatch fails, log `dispatch_failed` instead:

```go
slog.Error(
    "dispatch_failed",
    "execution_id", task.ExecutionID,
    "error", err.Error(),
)
```

- [ ] **Step 4: Write unit test**

```go
func TestExecutorDispatchTimestamps(t *testing.T) {
    executor := NewExecutor()
    task := &Task{
        ExecutionID: "run-1/task-1/1",
        // ... other fields ...
    }
    
    // Send dispatch (this should log dispatch_started and dispatch_sent)
    err := executor.DispatchTask(task)
    
    if err != nil {
        t.Fatalf("DispatchTask failed: %v", err)
    }
    // Logging is verified in integration test (Task 8)
}
```

- [ ] **Step 5: Run test**

```bash
cd orchestrator && go test ./internal/exercise -run TestExecutorDispatchTimestamps -v
```

Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/exercise/executor.go orchestrator/internal/exercise/executor_test.go
git commit -m "feat(perf): add dispatch_started/sent timestamps to executor"
```

---

### Task 5: Add Result Processing Timestamps to Executor

**Files:**
- Modify: `orchestrator/internal/exercise/executor.go`
- Modify: `orchestrator/internal/exercise/executor_test.go`

**Interfaces:**
- Consumes: `Task.ExecutionID` from Task 1
- Produces: Logs for `result_received`, `evidence_processing_done`, `scoring_completed`

**Steps:**

- [ ] **Step 1: Find result receiving logic in executor**

```bash
grep -n "result\|Result\|SubmitRunEvents\|Receive" orchestrator/internal/exercise/executor.go | head -15
```

Expected: Identify where agent results are received and processed.

- [ ] **Step 2: Add result_received log**

When a result from the agent is received, log:

```go
slog.Info(
    "result_received",
    "execution_id", result.ExecutionID,  // Assume result has ExecutionID from Task 3
    "timestamp", time.Now().UTC().Format(time.RFC3339Nano),
)
```

- [ ] **Step 3: Find evidence processing logic**

```bash
grep -n "evidence\|Evidence\|correlation\|Correlation" orchestrator/internal/exercise/executor.go | head -10
```

Expected: Identify where evidence correlation happens after result is received.

- [ ] **Step 4: Add evidence_processing_done log**

After evidence processing completes, log:

```go
slog.Info(
    "evidence_processing_done",
    "execution_id", result.ExecutionID,
    "timestamp", time.Now().UTC().Format(time.RFC3339Nano),
)
```

- [ ] **Step 5: Find scoring logic**

```bash
grep -n "score\|Score\|verdict\|Verdict" orchestrator/internal/exercise/executor.go | head -10
```

Expected: Identify where verdicts are assigned.

- [ ] **Step 6: Add scoring_completed log**

After scoring finishes, log:

```go
slog.Info(
    "scoring_completed",
    "execution_id", result.ExecutionID,
    "timestamp", time.Now().UTC().Format(time.RFC3339Nano),
)
```

- [ ] **Step 7: Write unit test**

```go
func TestExecutorResultProcessingTimestamps(t *testing.T) {
    executor := NewExecutor()
    result := &StepResult{
        ExecutionID: "run-1/task-1/1",
        // ... other fields ...
    }
    
    // Process result (should trigger evidence + scoring)
    err := executor.ProcessResult(result)
    
    if err != nil {
        t.Fatalf("ProcessResult failed: %v", err)
    }
}
```

- [ ] **Step 8: Run test**

```bash
cd orchestrator && go test ./internal/exercise -run TestExecutorResultProcessingTimestamps -v
```

Expected: PASS

- [ ] **Step 9: Commit**

```bash
git add orchestrator/internal/exercise/executor.go orchestrator/internal/exercise/executor_test.go
git commit -m "feat(perf): add result processing timestamps to executor"
```

---

### Task 6: Add Execution Timestamps to Windows Agent

**Files:**
- Modify: `agent/executor.go`
- Modify: `agent/executor_test.go`

**Interfaces:**
- Consumes: `ExecutionID` from agent dispatch payload (Task 3)
- Produces: Logs with format `[execution_id=...] execution_started` and `execution_finished`

**Steps:**

- [ ] **Step 1: Find where agent receives task from orchestrator**

```bash
grep -n "Receive\|Handler\|POST\|execute" agent/executor.go | head -15
```

Expected: Identify the function that receives and handles incoming tasks.

- [ ] **Step 2: Extract ExecutionID from incoming payload**

When a task is received, extract the ExecutionID:

```go
func (e *Executor) HandleTask(req *AgentTaskRequest) error {
    executionID := req.ExecutionID  // From orchestrator dispatch payload
    // ... rest of logic ...
}
```

- [ ] **Step 3: Add execution_started log before command launch**

Before PowerShell/cmd is launched, log:

```go
slog.Info(
    "execution_started",
    "execution_id", executionID,
    "timestamp", time.Now().UTC().Format(time.RFC3339Nano),
    "command", req.Command,  // Optional: helps debugging
)
```

- [ ] **Step 4: Add execution_finished log after command exits**

After the command completes (regardless of exit code), log:

```go
slog.Info(
    "execution_finished",
    "execution_id", executionID,
    "timestamp", time.Now().UTC().Format(time.RFC3339Nano),
    "exit_code", cmd.ProcessState.ExitCode(),  // Optional
)
```

- [ ] **Step 5: Write unit test**

```go
func TestAgentExecutionTimestamps(t *testing.T) {
    executor := NewExecutor()
    req := &AgentTaskRequest{
        ExecutionID: "run-1/task-1/1",
        Command: "echo test",
        // ... other fields ...
    }
    
    // Execute task (should log execution_started and execution_finished)
    result := executor.HandleTask(req)
    
    if result.ExitCode != 0 && result.ExitCode != 1 { // echo returns 0, command "test" might return 1
        t.Fatalf("Unexpected exit code: %d", result.ExitCode)
    }
}
```

- [ ] **Step 6: Run test**

```bash
cd agent && go test ./... -run TestAgentExecutionTimestamps -v
```

Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add agent/executor.go agent/executor_test.go
git commit -m "feat(perf): add execution_started/finished timestamps to agent"
```

---

### Task 7: Write parse-performance-logs.go Utility

**Files:**
- Create: `scripts/parse-performance-logs.go`
- Create: `scripts/parse-performance-logs_test.go`

**Interfaces:**
- Consumes: Raw orchestrator + agent log files, run ID
- Produces: Latency table (CSV/pretty-printed) with median/P95/max for each stage

**Steps:**

- [ ] **Step 1: Create parse-performance-logs.go skeleton**

```go
package main

import (
    "flag"
    "fmt"
    "log"
    "os"
)

func main() {
    orchestratorLogFile := flag.String("orchestrator", "", "Path to orchestrator log file")
    agentLogFile := flag.String("agent", "", "Path to agent log file")
    runID := flag.String("run-id", "", "Run ID to filter for")
    flag.Parse()

    if *orchestratorLogFile == "" || *agentLogFile == "" || *runID == "" {
        log.Fatal("Usage: parse-performance-logs -orchestrator=<file> -agent=<file> -run-id=<id>")
    }

    // TODO: Parse logs, calculate latencies, output table
}
```

- [ ] **Step 2: Implement log parsing function**

```go
type ExecutionTimestamps struct {
    ExecutionID          string
    QueueWaitStarted     time.Time
    QueueWaitFinished    time.Time
    DispatchStarted      time.Time
    DispatchSent         time.Time
    ExecutionStarted     time.Time
    ExecutionFinished    time.Time
    ResultReceived       time.Time
    EvidenceProcessing   time.Time
    ScoringCompleted     time.Time
}

type LatencyStage struct {
    Name      string
    Values    []time.Duration
}

func parseLogFile(filename string, runID string) (map[string]*ExecutionTimestamps, error) {
    // Read file line-by-line
    // Pattern: [execution_id=run-{runID}/task-*/attempt-*] <stage_name>: <timestamp>
    // Extract execution_id and stage timestamp
    // Return map[execution_id]*ExecutionTimestamps
    
    result := make(map[string]*ExecutionTimestamps)
    
    file, err := os.Open(filename)
    if err != nil {
        return nil, err
    }
    defer file.Close()
    
    scanner := bufio.NewScanner(file)
    for scanner.Scan() {
        line := scanner.Text()
        // Parse: [execution_id=run-abc/task-1/attempt-1] queue_wait_started: 2026-09-04T12:01:00.001Z
        // Use regex or string parsing to extract fields
        
        // Example regex: `\[execution_id=([^\]]+)\].*?([a-z_]+):\s*(\S+)`
        // Extract: execution_id, stage_name, timestamp
        
        // Initialize ExecutionTimestamps if not exists
        // Populate appropriate field based on stage_name
    }
    
    return result, scanner.Err()
}
```

- [ ] **Step 3: Implement latency calculation**

```go
func calculateLatencies(timestamps map[string]*ExecutionTimestamps) map[string][]time.Duration {
    latencies := map[string][]time.Duration{
        "queue_wait": {},
        "dispatch_latency": {},
        "agent_execution": {},
        "result_transport": {},
        "evidence_processing": {},
        "scoring": {},
        "total": {},
    }
    
    for _, ts := range timestamps {
        if !ts.QueueWaitFinished.IsZero() && !ts.QueueWaitStarted.IsZero() {
            latencies["queue_wait"] = append(latencies["queue_wait"], ts.QueueWaitFinished.Sub(ts.QueueWaitStarted))
        }
        if !ts.DispatchSent.IsZero() && !ts.DispatchStarted.IsZero() {
            latencies["dispatch_latency"] = append(latencies["dispatch_latency"], ts.DispatchSent.Sub(ts.DispatchStarted))
        }
        if !ts.ExecutionFinished.IsZero() && !ts.ExecutionStarted.IsZero() {
            latencies["agent_execution"] = append(latencies["agent_execution"], ts.ExecutionFinished.Sub(ts.ExecutionStarted))
        }
        if !ts.ResultReceived.IsZero() && !ts.DispatchSent.IsZero() {
            latencies["result_transport"] = append(latencies["result_transport"], ts.ResultReceived.Sub(ts.DispatchSent))
        }
        if !ts.EvidenceProcessing.IsZero() && !ts.ResultReceived.IsZero() {
            latencies["evidence_processing"] = append(latencies["evidence_processing"], ts.EvidenceProcessing.Sub(ts.ResultReceived))
        }
        if !ts.ScoringCompleted.IsZero() && !ts.EvidenceProcessing.IsZero() {
            latencies["scoring"] = append(latencies["scoring"], ts.ScoringCompleted.Sub(ts.EvidenceProcessing))
        }
        if !ts.ScoringCompleted.IsZero() && !ts.QueueWaitStarted.IsZero() {
            latencies["total"] = append(latencies["total"], ts.ScoringCompleted.Sub(ts.QueueWaitStarted))
        }
    }
    
    return latencies
}
```

- [ ] **Step 4: Implement percentile calculation**

```go
func percentile(values []time.Duration, p float64) time.Duration {
    if len(values) == 0 {
        return 0
    }
    sort.Slice(values, func(i, j int) bool { return values[i] < values[j] })
    index := int(float64(len(values)) * p / 100)
    if index >= len(values) {
        index = len(values) - 1
    }
    return values[index]
}

func median(values []time.Duration) time.Duration {
    return percentile(values, 50)
}

func p95(values []time.Duration) time.Duration {
    return percentile(values, 95)
}
```

- [ ] **Step 5: Implement output formatting**

```go
func printLatencyTable(latencies map[string][]time.Duration) {
    fmt.Printf("%-25s %12s %12s %12s %8s\n", "Stage", "Median (ms)", "P95 (ms)", "Max (ms)", "Count")
    fmt.Println(strings.Repeat("-", 75))
    
    stages := []string{"queue_wait", "dispatch_latency", "agent_execution", "result_transport", "evidence_processing", "scoring", "total"}
    
    for _, stage := range stages {
        values := latencies[stage]
        if len(values) == 0 {
            continue
        }
        
        med := median(values)
        p95Val := p95(values)
        maxVal := values[len(values)-1]
        
        fmt.Printf("%-25s %12.1f %12.1f %12.1f %8d\n",
            stage,
            float64(med.Milliseconds()),
            float64(p95Val.Milliseconds()),
            float64(maxVal.Milliseconds()),
            len(values),
        )
    }
}
```

- [ ] **Step 6: Update main() to call functions**

```go
func main() {
    // ... flag parsing ...
    
    orchTimestamps, err := parseLogFile(*orchestratorLogFile, *runID)
    if err != nil {
        log.Fatalf("Failed to parse orchestrator log: %v", err)
    }
    
    agentTimestamps, err := parseLogFile(*agentLogFile, *runID)
    if err != nil {
        log.Fatalf("Failed to parse agent log: %v", err)
    }
    
    // Merge timestamps from both sources
    for id, ts := range agentTimestamps {
        if orchTs, exists := orchTimestamps[id]; exists {
            orchTs.ExecutionStarted = ts.ExecutionStarted
            orchTs.ExecutionFinished = ts.ExecutionFinished
        }
    }
    
    latencies := calculateLatencies(orchTimestamps)
    printLatencyTable(latencies)
}
```

- [ ] **Step 7: Write unit test**

```go
func TestParseLogFile(t *testing.T) {
    logContent := `[execution_id=run-1/task-1/1] queue_wait_started: 2026-09-04T12:01:00.001Z
[execution_id=run-1/task-1/1] queue_wait_finished: 2026-09-04T12:01:00.003Z
[execution_id=run-1/task-1/1] dispatch_started: 2026-09-04T12:01:00.003Z
[execution_id=run-1/task-1/1] dispatch_sent: 2026-09-04T12:01:00.004Z`
    
    // Write to temp file
    tmpFile, _ := os.CreateTemp("", "test-log")
    defer os.Remove(tmpFile.Name())
    tmpFile.WriteString(logContent)
    tmpFile.Close()
    
    timestamps, err := parseLogFile(tmpFile.Name(), "run-1")
    
    if err != nil {
        t.Fatalf("parseLogFile failed: %v", err)
    }
    
    ts := timestamps["run-1/task-1/1"]
    if ts == nil {
        t.Fatalf("Execution ID not found in parsed logs")
    }
    
    if ts.QueueWaitFinished.Sub(ts.QueueWaitStarted) != 2*time.Millisecond {
        t.Fatalf("Queue wait latency incorrect")
    }
}
```

- [ ] **Step 8: Run test**

```bash
cd scripts && go test -run TestParseLogFile -v
```

Expected: PASS

- [ ] **Step 9: Build and verify**

```bash
cd scripts && go build parse-performance-logs.go
```

- [ ] **Step 10: Commit**

```bash
git add scripts/parse-performance-logs.go scripts/parse-performance-logs_test.go
git commit -m "feat(perf): add log parser utility for latency table generation"
```

---

### Task 8: Create Integration Test for Full Measurement Flow

**Files:**
- Create: `orchestrator/internal/exercise/integration_test.go` (or append to existing)

**Interfaces:**
- Consumes: All instrumentation from Tasks 1-6
- Produces: Integration test that runs a quick scenario and verifies all timestamps are logged

**Steps:**

- [ ] **Step 1: Create integration test function**

```go
func TestPhase0APerformanceMeasurement(t *testing.T) {
    if testing.Short() {
        t.Skip("Skipping integration test in short mode")
    }
    
    // Setup: Start orchestrator + agent in Docker Compose
    // Run windows-discovery.yaml scenario
    // Capture logs
    // Verify execution_id and timestamps
}
```

- [ ] **Step 2: Implement test setup**

```go
func TestPhase0APerformanceMeasurement(t *testing.T) {
    // Start Docker Compose
    cmd := exec.Command("docker-compose", "up", "-d")
    if err := cmd.Run(); err != nil {
        t.Fatalf("docker-compose up failed: %v", err)
    }
    defer exec.Command("docker-compose", "down").Run()
    
    // Wait for services to be ready
    time.Sleep(5 * time.Second)
}
```

- [ ] **Step 3: Start orchestrator and capture logs**

```go
    // Start orchestrator in foreground, redirect stdout/stderr
    orchestratorLog, err := os.Create("test-orchestrator.log")
    if err != nil {
        t.Fatalf("Failed to create log file: %v", err)
    }
    defer orchestratorLog.Close()
    
    orchestratorCmd := exec.Command("go", "run", "./cmd/server/main.go")
    orchestratorCmd.Stdout = orchestratorLog
    orchestratorCmd.Stderr = orchestratorLog
    
    if err := orchestratorCmd.Start(); err != nil {
        t.Fatalf("Failed to start orchestrator: %v", err)
    }
    defer orchestratorCmd.Process.Kill()
```

- [ ] **Step 4: Trigger a scenario run**

```go
    // Use API to trigger windows-discovery.yaml scenario
    client := &http.Client{}
    runPayload := map[string]interface{}{
        "scenario_id": "windows-discovery",
        "target_agents": []string{"test-agent"},
    }
    
    payload, _ := json.Marshal(runPayload)
    req, _ := http.NewRequest("POST", "http://localhost:9443/api/runs", bytes.NewReader(payload))
    resp, err := client.Do(req)
    if err != nil {
        t.Fatalf("Failed to start run: %v", err)
    }
    
    var runResp map[string]interface{}
    json.NewDecoder(resp.Body).Decode(&runResp)
    runID := runResp["run_id"].(string)
```

- [ ] **Step 5: Wait for run completion**

```go
    // Poll run status until completion
    maxRetries := 120 // 10 minutes with 5s intervals
    for i := 0; i < maxRetries; i++ {
        req, _ := http.NewRequest("GET", fmt.Sprintf("http://localhost:9443/api/runs/%s", runID), nil)
        resp, _ := client.Do(req)
        var runStatus map[string]interface{}
        json.NewDecoder(resp.Body).Decode(&runStatus)
        
        status := runStatus["status"].(string)
        if status == "completed" || status == "partial" || status == "failed" {
            break
        }
        
        time.Sleep(5 * time.Second)
    }
```

- [ ] **Step 6: Verify execution_id and timestamps in logs**

```go
    // Parse logs
    orchestratorLogs, _ := os.ReadFile("test-orchestrator.log")
    agentLogs, _ := os.ReadFile("test-agent.log")
    
    // Verify execution_id is present
    if !strings.Contains(string(orchestratorLogs), "execution_id=") {
        t.Fatalf("Execution IDs not found in orchestrator logs")
    }
    
    // Verify all timestamps are present
    requiredTimestamps := []string{
        "queue_wait_started",
        "queue_wait_finished",
        "dispatch_started",
        "dispatch_sent",
        "execution_started",
        "execution_finished",
        "result_received",
        "evidence_processing_done",
        "scoring_completed",
    }
    
    for _, timestamp := range requiredTimestamps {
        if !strings.Contains(string(orchestratorLogs), timestamp) && !strings.Contains(string(agentLogs), timestamp) {
            t.Errorf("Timestamp %s not found in logs", timestamp)
        }
    }
```

- [ ] **Step 7: Verify log parser works**

```go
    // Run parse-performance-logs
    parseCmd := exec.Command("go", "run", "./scripts/parse-performance-logs.go",
        "-orchestrator=test-orchestrator.log",
        "-agent=test-agent.log",
        "-run-id=" + runID,
    )
    
    output, err := parseCmd.Output()
    if err != nil {
        t.Fatalf("Log parser failed: %v", err)
    }
    
    // Verify table output is reasonable
    outputStr := string(output)
    if !strings.Contains(outputStr, "queue_wait") {
        t.Fatalf("Parsed output missing stage names")
    }
    
    // Verify latencies are positive
    // (Simple regex check for numeric values)
```

- [ ] **Step 8: Cleanup**

```go
    os.Remove("test-orchestrator.log")
    os.Remove("test-agent.log")
}
```

- [ ] **Step 9: Run integration test**

```bash
cd orchestrator && go test ./internal/exercise -run TestPhase0APerformanceMeasurement -v -timeout 15m
```

Expected: PASS (test should complete in ~10 minutes)

- [ ] **Step 10: Commit**

```bash
git add orchestrator/internal/exercise/integration_test.go
git commit -m "test(perf): add integration test for Phase 0A measurement flow"
```

---

### Task 9: Run Local Measurement (Quick Scenario)

**Files:**
- (No code changes; data collection task)

**Output:**
- `reports/phase0a-local-baseline.txt` — Latency table from 3 runs of windows-discovery.yaml

**Steps:**

- [ ] **Step 1: Start Docker Compose**

```bash
cd orchestrator && docker-compose up -d
sleep 10
```

- [ ] **Step 2: Run windows-discovery.yaml 3 times**

For each run (1, 2, 3):

```bash
# Start orchestrator with log capture
go run ./cmd/server/main.go > test-run-${RUN_NUM}-orchestrator.log 2>&1 &
ORCH_PID=$!

# Trigger scenario via API
RUN_ID=$(curl -s -X POST http://localhost:9443/api/runs \
  -H "Content-Type: application/json" \
  -d '{"scenario_id":"windows-discovery","target_agents":["default"]}' \
  | jq -r '.run_id')

# Wait for completion
while true; do
  status=$(curl -s http://localhost:9443/api/runs/$RUN_ID | jq -r '.status')
  if [[ $status == "completed" || $status == "partial" || $status == "failed" ]]; then
    break
  fi
  sleep 5
done

# Stop orchestrator
kill $ORCH_PID
wait $ORCH_PID 2>/dev/null
```

- [ ] **Step 3: Collect agent logs**

```bash
# For each run, copy agent logs from container
docker-compose logs agent > test-run-${RUN_NUM}-agent.log
```

- [ ] **Step 4: Parse each run's logs**

```bash
for run in 1 2 3; do
  go run ./scripts/parse-performance-logs.go \
    -orchestrator="test-run-${run}-orchestrator.log" \
    -agent="test-run-${run}-agent.log" \
    -run-id="run-${run}" > "test-run-${run}-latencies.txt"
done
```

- [ ] **Step 5: Aggregate results**

Create a script to combine the three runs' data and calculate median/P95/max across all runs:

```bash
# Create summary report
cat > reports/phase0a-local-baseline.txt << EOF
=== Phase 0A Local Baseline Measurement ===
Scenario: windows-discovery.yaml
Environment: Docker Compose (local)
Runs: 3
Date: $(date)

EOF

# Append parsed latencies from each run
for run in 1 2 3; do
  cat "test-run-${run}-latencies.txt" >> reports/phase0a-local-baseline.txt
  echo "" >> reports/phase0a-local-baseline.txt
done

cat reports/phase0a-local-baseline.txt
```

- [ ] **Step 6: Save report**

```bash
mkdir -p reports
# Report created in Step 5
git add reports/phase0a-local-baseline.txt
```

---

### Task 10: Run Staging Measurement (Quick + Full Sweep)

**Files:**
- (No code changes; data collection task)

**Output:**
- `reports/phase0a-staging-quick.txt` — Latency table from windows-discovery.yaml on staging
- `reports/phase0a-staging-full.txt` — Latency table from art-full-windows.yaml on staging

**Steps:**

- [ ] **Step 1: SSH into staging server**

```bash
ssh zain@audspectserver 192.168.10.78
```

- [ ] **Step 2: Start orchestrator with log capture**

```bash
cd /path/to/Audspect_Cloud
go run ./cmd/server/main.go > orchestrator.log 2>&1 &
ORCH_PID=$!
sleep 5
```

- [ ] **Step 3: Run quick scenario (windows-discovery.yaml)**

```bash
RUN_ID_QUICK=$(curl -s -X POST http://localhost:9443/api/runs \
  -H "Content-Type: application/json" \
  -d '{"scenario_id":"windows-discovery","target_agents":["all"]}' \
  | jq -r '.run_id')

echo "Quick run ID: $RUN_ID_QUICK"

# Wait for completion (up to 20 minutes)
for i in {1..240}; do
  status=$(curl -s http://localhost:9443/api/runs/$RUN_ID_QUICK | jq -r '.status')
  echo "Status (attempt $i/240): $status"
  if [[ $status == "completed" || $status == "partial" || $status == "failed" ]]; then
    echo "Quick scenario completed"
    break
  fi
  sleep 5
done
```

- [ ] **Step 4: Parse quick scenario logs**

```bash
go run ./scripts/parse-performance-logs.go \
  -orchestrator="orchestrator.log" \
  -agent="agent.log" \
  -run-id="$RUN_ID_QUICK" > reports/phase0a-staging-quick.txt

cat reports/phase0a-staging-quick.txt
```

- [ ] **Step 5: Run full sweep scenario (art-full-windows.yaml)**

```bash
RUN_ID_FULL=$(curl -s -X POST http://localhost:9443/api/runs \
  -H "Content-Type: application/json" \
  -d '{"scenario_id":"art-full-windows","target_agents":["all"]}' \
  | jq -r '.run_id')

echo "Full sweep run ID: $RUN_ID_FULL"

# Wait for completion (up to 60 minutes)
for i in {1..720}; do
  status=$(curl -s http://localhost:9443/api/runs/$RUN_ID_FULL | jq -r '.status')
  echo "Status (attempt $i/720): $status"
  if [[ $status == "completed" || $status == "partial" || $status == "failed" ]]; then
    echo "Full sweep completed"
    break
  fi
  sleep 5
done
```

- [ ] **Step 6: Parse full sweep logs**

```bash
go run ./scripts/parse-performance-logs.go \
  -orchestrator="orchestrator.log" \
  -agent="agent.log" \
  -run-id="$RUN_ID_FULL" > reports/phase0a-staging-full.txt

cat reports/phase0a-staging-full.txt
```

- [ ] **Step 7: Stop orchestrator and download reports**

```bash
kill $ORCH_PID
wait $ORCH_PID 2>/dev/null

# Download reports locally
exit  # Exit SSH session
scp zain@audspectserver:reports/phase0a-staging-*.txt reports/
```

---

### Task 11: Analyze Hypothesis #1 (PowerShell Overhead)

**Files:**
- (No code changes; analysis task)

**Output:**
- Analysis findings added to `reports/phase0a-hypothesis-findings.txt`

**Steps:**

- [ ] **Step 1: Extract agent_execution times**

From `reports/phase0a-local-baseline.txt`, note the `agent_execution` median/P95 values.

- [ ] **Step 2: Inspect raw logs for first technique**

```bash
grep "execution_started\|execution_finished" test-run-1-orchestrator.log | head -4
```

Expected output:
```
[execution_id=run-1/task-1/1] execution_started: 2026-09-04T12:01:00.312Z
[execution_id=run-1/task-1/1] execution_finished: 2026-09-04T12:01:00.621Z
```

Duration: 309ms (309 - 0 = 309ms... this is approximately 300ms PowerShell overhead + trivial command)

- [ ] **Step 3: Compare against command complexity**

In the first technique's logs, find the actual command executed:

```bash
grep "command\|Command" test-run-1-orchestrator.log | grep "task-1" | head -1
```

If the command is trivial (e.g., `whoami`, `echo`, `systeminfo`), and execution took 300+ms, then PowerShell overhead is likely dominant.

- [ ] **Step 4: Document finding**

Create `reports/phase0a-hypothesis-findings.txt`:

```
=== Phase 0A Hypothesis Analysis ===

Hypothesis #1: PowerShell Process Overhead
Status: [CONFIRMED / NOT CONFIRMED / INCONCLUSIVE]

Evidence:
- Local baseline agent_execution median: XXX ms (from reports/phase0a-local-baseline.txt)
- First technique command: whoami (trivial, <1ms expected)
- First technique actual duration: 300+ ms
- PowerShell overhead estimate: ~300ms per fresh PowerShell invocation

Interpretation:
[If confirmed] PowerShell startup is consuming ~300ms per technique. With 100 techniques,
this alone contributes 30 seconds of overhead. This is likely the dominant bottleneck.

[If not confirmed] PowerShell overhead is not the primary issue. Investigate scheduler
serialization (Hypothesis #2) or network/evidence processing.

Recommendation for Phase 0B:
[If confirmed] Investigate pooling strategies, warm-up techniques, or alternative executors.
[If not confirmed] Proceed to Hypothesis #2.
```

- [ ] **Step 5: Commit finding**

```bash
git add reports/phase0a-hypothesis-findings.txt
git commit -m "analysis(perf): Hypothesis #1 PowerShell overhead analysis"
```

---

### Task 12: Analyze Hypothesis #2 (Scheduler Serialization)

**Files:**
- (No code changes; analysis task)

**Output:**
- Analysis findings appended to `reports/phase0a-hypothesis-findings.txt`

**Steps:**

- [ ] **Step 1: Extract dispatch_sent timestamps from full sweep**

From `test-run-full-orchestrator.log` (staging full sweep), grep for dispatch_sent:

```bash
grep "dispatch_sent" test-run-full-orchestrator.log | head -20
```

Expected output:
```
[execution_id=run-full/task-1/1] dispatch_sent: 2026-09-04T12:01:00.004Z
[execution_id=run-full/task-2/1] dispatch_sent: 2026-09-04T12:01:00.005Z
[execution_id=run-full/task-3/1] dispatch_sent: 2026-09-04T12:01:00.006Z
...
[execution_id=run-full/task-50/1] dispatch_sent: 2026-09-04T12:01:05.000Z  ← 5 second gap!
```

- [ ] **Step 2: Analyze gap pattern**

Write a small script to extract and analyze gaps:

```bash
grep "dispatch_sent" test-run-full-orchestrator.log | sed 's/.*dispatch_sent: //' | awk '{
    if (prev != "") {
        cmd = "date -d " $1 " +%s.%N"
        cmd | getline curr
        cmd = "date -d " prev " +%s.%N"
        cmd | getline prevTime
        gap = curr - prevTime
        if (gap > 1.0) {
            print "Large gap: " gap "s between dispatches"
        }
    }
    prev = $1
}' > gaps.txt
```

- [ ] **Step 3: Categorize dispatch pattern**

If gaps are consistently small (<100ms):
```
Pattern: PARALLEL — Techniques are dispatched concurrently
Gap distribution: 1-50ms between dispatches
Interpretation: Not a serialization bottleneck
```

If gaps are large (>1s):
```
Pattern: SERIALIZED — Techniques are dispatched sequentially
Gap distribution: 1-10s between dispatches
Interpretation: Likely scheduler/resource contention
```

- [ ] **Step 4: If serialized, investigate scheduler code**

```bash
grep -n "mutex\|Lock\|Unlock\|wait\|Wait" orchestrator/internal/exercise/scheduler.go | head -15
```

Look for:
- Unintended mutex locks in dispatch loop
- Sequential task processing instead of batch
- Resource contention causing dispatch delays

- [ ] **Step 5: Document finding**

Append to `reports/phase0a-hypothesis-findings.txt`:

```
Hypothesis #2: Scheduler/Resource Serialization
Status: [CONFIRMED / NOT CONFIRMED / INCONCLUSIVE]

Evidence:
- Full sweep dispatch pattern: [PARALLEL / SERIALIZED]
- Gap distribution: [1-50ms / 1-10s]
- Number of concurrent dispatches observed: X

Interpretation:
[If serialized] Scheduler is dispatching techniques one-at-a-time, with significant gaps
between dispatches. This is likely due to:
- Unintended mutex locks in dispatch loop
- Resource contention logic too aggressive
- Sequential task dequeue instead of batch

[If parallel] Scheduler is dispatching correctly. Latency is in agent execution or
post-execution processing.

Recommendation for Phase 0B:
[If confirmed] Unlock batch dispatch, refine resource conflict detection, or add
concurrent dispatch queue.
[If not confirmed] Bottleneck is in agent execution (Hypothesis #1) or post-execution
(evidence/scoring).
```

- [ ] **Step 6: Commit finding**

```bash
git add reports/phase0a-hypothesis-findings.txt
git commit -m "analysis(perf): Hypothesis #2 scheduler serialization analysis"
```

---

### Task 13: Generate Final Summary Report

**Files:**
- (No code changes; reporting task)

**Output:**
- `reports/phase0a-final-report.txt` — Executive summary + recommendations

**Steps:**

- [ ] **Step 1: Consolidate findings**

Combine findings from all three measurement/analysis tasks into a single report:

```bash
cat > reports/phase0a-final-report.txt << 'EOF'
=== Phase 0A Performance Measurement — Final Report ===

Date: $(date)
Executor: $(git log -1 --format=%aN)

## Executive Summary

This report presents findings from Phase 0A: Windows Execution Performance Measurement.
The goal was to identify where time is spent in the execution cycle (orchestrator →
agent → orchestrator) and recommend the highest-impact fix for Phase 0B.

## Measurement Overview

### Local Baseline (Docker Compose)
- Scenario: windows-discovery.yaml (discovery techniques)
- Runs: 3 (median results below)
- Results: [INSERT FROM reports/phase0a-local-baseline.txt]

### Staging Validation
- Quick Scenario: windows-discovery.yaml
  Results: [INSERT FROM reports/phase0a-staging-quick.txt]

- Full Sweep: art-full-windows.yaml (100+ techniques)
  Results: [INSERT FROM reports/phase0a-staging-full.txt]

## Hypothesis Testing Results

### Hypothesis #1: PowerShell Process Overhead
[INSERT FROM reports/phase0a-hypothesis-findings.txt — Hypothesis #1 section]

### Hypothesis #2: Scheduler/Resource Serialization
[INSERT FROM reports/phase0a-hypothesis-findings.txt — Hypothesis #2 section]

## Conclusions

The largest bottleneck is: [PowerShell overhead / Scheduler serialization / Other]

Impact:
- Accounts for approximately XX% of total execution time
- On a 100-technique full sweep, this translates to ~XXX seconds of overhead

## Recommendations for Phase 0B

1. [Fix recommendation based on identified bottleneck]
2. [Secondary optimization opportunity, if any]

## Next Steps

Phase 0B (ExecutionAttempt) will implement the foundational state contract and
prerequisite evaluation system. These performance insights will guide optimization
decisions within Phase 0B and beyond.

EOF
```

- [ ] **Step 2: Add actual data to report**

Manually insert data from the generated reports into the template:

```bash
# Copy relevant sections
head -10 reports/phase0a-local-baseline.txt >> reports/phase0a-final-report.txt
head -10 reports/phase0a-staging-quick.txt >> reports/phase0a-final-report.txt
head -10 reports/phase0a-staging-full.txt >> reports/phase0a-final-report.txt
tail -20 reports/phase0a-hypothesis-findings.txt >> reports/phase0a-final-report.txt
```

- [ ] **Step 3: Review report**

```bash
cat reports/phase0a-final-report.txt
```

Ensure it tells a coherent story:
- What we measured ✓
- What we found ✓
- Which hypothesis was confirmed ✓
- What to fix next ✓

- [ ] **Step 4: Commit all reports**

```bash
git add reports/phase0a-*.txt
git commit -m "docs(perf): Phase 0A final measurement reports and hypothesis analysis"
```

- [ ] **Step 5: Push to remote**

```bash
git push origin main
```

---

## Summary

**Phase 0A Implementation Complete**

After Task 13, you will have:

✅ Execution_id propagation through scheduler → executor → agent  
✅ Orchestrator instrumentation at 7 checkpoints (queue, dispatch, result, evidence, scoring)  
✅ Agent instrumentation (2 checkpoints: execution start/end)  
✅ Log parser utility to produce latency tables  
✅ Local baseline measurement (3 runs)  
✅ Staging validation (quick + full sweep)  
✅ Hypothesis testing analysis (PowerShell overhead + scheduler serialization)  
✅ Final summary report with recommendations  

**Deliverables:**
- Instrumented code (scheduler, executor, agent)
- Log parser utility (scripts/parse-performance-logs.go)
- Measurement reports (4 files in reports/)
- Clear recommendation for Phase 0B fix

**Testing:**
- All unit tests pass (scheduler, executor, agent)
- Integration test passes (full flow verification)
- Manual QA on local + staging (logs inspected, data validated)

**Total effort: ~3-4 days wall-clock**
- Implementation: 2-3 days
- Measurement: 1-2 hours
- Staging validation: 3-4 hours
- Analysis: 1 hour
