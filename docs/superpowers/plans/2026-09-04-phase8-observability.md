# Phase 8: Platform Observability Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build instrumentation + telemetry contracts + built-in visibility so operators can answer "what is happening," "why," and "what should I do" without SSH-ing into hosts or external tools.

**Architecture:** 

Phase 8 is structured as three priority tiers delivered in order:

- **P0 (Core):** Correlation IDs (run/task/attempt/agent) flowing through logs/metrics, metrics expansion (histograms for execution/queue/scheduler latency), structured instrumentation at scheduler/task/agent boundaries, built-in observability dashboard (/api/observability/summary + web UI).

- **P1 (Tracing & Alerting):** OpenTelemetry SDK with configurable exporters (local, Prometheus remote-write, Tempo, Jaeger), local rule engine for alerting (health/failure/latency/queue/capacity thresholds), webhook notifications.

- **P2 (Diagnostics):** On-demand CPU/memory profiling via /api/debug/profile, diagnostic snapshots (goroutines, heap state), deeper performance breakdown.

Observability overhead must be negligible when not actively profiled/traced — this is critical because the Windows agent is already performance-sensitive.

**Tech Stack:** 

- Metrics: Prometheus (already in use)
- Logging: slog with JSON handler (already in use)
- Tracing: OpenTelemetry Go SDK
- Correlation: Context-based IDs (run_id, task_id, attempt_id, agent_id)
- Dashboard: wwwroot + /api endpoints
- Alerting: local rule engine (no AlertManager required)
- Profiling: Go runtime (pprof)

**Spec:** 

User-approved Phase 8 scope above. Explicitly out of scope: custom time-series DB, custom trace DB, mandatory external systems, continuous profiling, vendor lock-in.

---

## Global Constraints

- All instrumentation must use bounded-cardinality labels (no per-entity IDs in metric labels; no per-request dimensions).
- Overhead budget: <1ms per execution when observability is idle (no active profiling/tracing).
- Correlation IDs must flow through: run → task dispatch → scheduler → agent execution → process spawn.
- All new metrics must have histograms (not just averages) for latency measurements.
- Configuration must be deployment-agnostic (local file, Prometheus, Tempo, Jaeger all optional).
- No mandatory external systems or dependencies for basic visibility.

---

## Files to Create/Modify

**New files:**
- `orchestrator/internal/observability/observability.go` — core package, context propagation, ID generators
- `orchestrator/internal/observability/metrics.go` — metrics registry expansion (queues, scheduler, agent, resource)
- `orchestrator/internal/observability/otel.go` — OpenTelemetry SDK initialization and lifecycle
- `orchestrator/internal/observability/exporters.go` — exporter configuration (local, Prometheus, Tempo, Jaeger)
- `orchestrator/internal/observability/alerting.go` — local rule engine and notifications
- `orchestrator/internal/observability/profiling.go` — on-demand CPU/memory profiling
- `orchestrator/internal/api/observability_dashboard.go` — dashboard data aggregation
- `cmd/server/observability.go` — main server wiring and initialization

**Modified files:**
- `orchestrator/internal/api/observability.go` — expand existing metrics, add dashboard endpoints
- `orchestrator/internal/exercise/scheduler.go` — add instrumentation (task dispatch, queue wait)
- `orchestrator/internal/exercise/executor.go` — add span emission and correlation ID propagation
- `orchestrator/internal/jobs/job_dispatch.go` — add task attempt tracking
- `cmd/server/main.go` — initialize observability, wire up dashboard, register OTel exporters
- `orchestrator/internal/models/models.go` — add TraceID, SpanID fields to execution models if needed

**Tests:**
- `orchestrator/internal/observability/observability_test.go`
- `orchestrator/internal/observability/alerting_test.go`
- `orchestrator/internal/api/observability_dashboard_test.go`

---

## Task Breakdown

### Task 1: Architecture Inspection & Overhead Budget

**Files:**
- Read: `orchestrator/internal/exercise/scheduler.go`, `orchestrator/internal/exercise/executor.go`, `orchestrator/internal/jobs/job_dispatch.go`
- Read: `orchestrator/cmd/server/main.go`, `orchestrator/internal/api/observability.go`

**Goal:** Identify where correlation IDs should propagate and establish overhead budget baseline.

- [ ] **Step 1: Trace execution flow**

Read `orchestrator/internal/exercise/scheduler.go` and `executor.go` to understand the flow:
- Run created → Task(s) generated → Attempt(s) spawned → Agent receives task → Process spawned

Map out the function calls and identify where IDs (run_id, task_id, attempt_id, agent_id) are available.

Expected result: A document listing:
- Where each ID originates (database, scheduler, agent)
- Which functions should carry correlation context
- Where logs are currently emitted
- Where metrics are currently recorded

- [ ] **Step 2: Measure current overhead**

Time a representative scenario (100 tasks, 50 agents) with current logging/metrics:
- CPU impact: `time go test ./... -bench=Benchmark`
- Memory impact: `pprof` heap snapshot before/after
- Log volume: `grep -c "component" logs/` per 100 tasks

Expected result: Baseline numbers (e.g., "adds ~0.2ms per task, 2MB per 1000 tasks")

- [ ] **Step 3: Document instrumentation boundaries**

Create `orchestrator/internal/observability/DESIGN.md`:

```markdown
# Observability Instrumentation Boundaries

## Correlation ID Flow

Run (from API) → Task (from scenario) → Attempt (from job dispatch) → Agent (from task handler) → Process (from executor)

Functions carrying context:
- `scheduler.DispatchTask(ctx, run_id, task_id)` ← adds run_id, task_id to context
- `executor.Execute(ctx)` ← reads run_id, task_id, adds agent_id, creates spans
- `agent.RunTask(ctx)` ← reads all IDs, logs with correlation

## Overhead Budget: 0.5ms per task

## Metrics to add:
- task_queue_wait_duration_seconds (histogram)
- scheduler_dispatch_latency_seconds (histogram)
- execution_duration_seconds (histogram, by technique)
- agent_execution_duration_seconds (histogram, by agent_id in gauge only)

## Spans to emit:
- task_dispatch (start → agent assignment)
- execution (start → completion)
- agent_task (start → result submission)
```

- [ ] **Step 4: Commit design document**

```bash
git add orchestrator/internal/observability/DESIGN.md
git commit -m "docs: Phase 8 observability instrumentation boundaries and overhead budget"
```

---

### Task 2: Correlation ID Context Propagation

**Files:**
- Create: `orchestrator/internal/observability/observability.go`
- Modify: `orchestrator/internal/exercise/scheduler.go`, `orchestrator/internal/exercise/executor.go`, `orchestrator/internal/jobs/job_dispatch.go`
- Test: `orchestrator/internal/observability/observability_test.go`

**Interfaces:**
- Produces: `observability.WithRunID(ctx, string) context.Context`, `observability.WithTaskID(ctx, string) context.Context`, `observability.WithAttemptID(ctx, string) context.Context`, `observability.WithAgentID(ctx, string) context.Context`, `observability.GetCorrelationIDs(ctx) (run, task, attempt, agent string)`, `observability.CorrelationLogger(ctx, slog.Logger) slog.Logger`

- [ ] **Step 1: Write correlation ID context tests**

Create `orchestrator/internal/observability/observability_test.go`:

```go
package observability_test

import (
	"context"
	"testing"
	"github.com/audspect/bas/internal/observability"
)

func TestWithRunID(t *testing.T) {
	ctx := context.Background()
	ctx = observability.WithRunID(ctx, "run-123")
	
	run, _, _, _ := observability.GetCorrelationIDs(ctx)
	if run != "run-123" {
		t.Errorf("expected run-123, got %s", run)
	}
}

func TestWithMultipleIDs(t *testing.T) {
	ctx := context.Background()
	ctx = observability.WithRunID(ctx, "run-123")
	ctx = observability.WithTaskID(ctx, "task-456")
	ctx = observability.WithAttemptID(ctx, "attempt-789")
	ctx = observability.WithAgentID(ctx, "agent-abc")
	
	run, task, attempt, agent := observability.GetCorrelationIDs(ctx)
	if run != "run-123" || task != "task-456" || attempt != "attempt-789" || agent != "agent-abc" {
		t.Errorf("IDs don't match: run=%s, task=%s, attempt=%s, agent=%s", run, task, attempt, agent)
	}
}

func TestCorrelationLogger(t *testing.T) {
	ctx := context.Background()
	ctx = observability.WithRunID(ctx, "run-123")
	ctx = observability.WithTaskID(ctx, "task-456")
	
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	corrLogger := observability.CorrelationLogger(ctx, logger)
	
	// corr logger should automatically add correlation IDs to logs
	// (verify by capturing logs in test)
}
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
go test ./orchestrator/internal/observability -run TestWithRunID -v
# Expected: FAIL (package doesn't exist yet)
```

- [ ] **Step 3: Implement correlation context package**

Create `orchestrator/internal/observability/observability.go`:

```go
package observability

import (
	"context"
	"log/slog"
)

type correlationIDKey struct{}

type CorrelationIDs struct {
	RunID     string
	TaskID    string
	AttemptID string
	AgentID   string
}

func WithRunID(ctx context.Context, id string) context.Context {
	ids := getOrCreateIDs(ctx)
	ids.RunID = id
	return context.WithValue(ctx, correlationIDKey{}, ids)
}

func WithTaskID(ctx context.Context, id string) context.Context {
	ids := getOrCreateIDs(ctx)
	ids.TaskID = id
	return context.WithValue(ctx, correlationIDKey{}, ids)
}

func WithAttemptID(ctx context.Context, id string) context.Context {
	ids := getOrCreateIDs(ctx)
	ids.AttemptID = id
	return context.WithValue(ctx, correlationIDKey{}, ids)
}

func WithAgentID(ctx context.Context, id string) context.Context {
	ids := getOrCreateIDs(ctx)
	ids.AgentID = id
	return context.WithValue(ctx, correlationIDKey{}, ids)
}

func GetCorrelationIDs(ctx context.Context) (run, task, attempt, agent string) {
	ids := getOrCreateIDs(ctx)
	return ids.RunID, ids.TaskID, ids.AttemptID, ids.AgentID
}

func getOrCreateIDs(ctx context.Context) *CorrelationIDs {
	if ids, ok := ctx.Value(correlationIDKey{}).(*CorrelationIDs); ok {
		return ids
	}
	return &CorrelationIDs{}
}

// CorrelationLogger wraps an slog.Logger to automatically add correlation IDs to every log line
func CorrelationLogger(ctx context.Context, logger *slog.Logger) *slog.Logger {
	run, task, attempt, agent := GetCorrelationIDs(ctx)
	attrs := []slog.Attr{}
	if run != "" {
		attrs = append(attrs, slog.String("run_id", run))
	}
	if task != "" {
		attrs = append(attrs, slog.String("task_id", task))
	}
	if attempt != "" {
		attrs = append(attrs, slog.String("attempt_id", attempt))
	}
	if agent != "" {
		attrs = append(attrs, slog.String("agent_id", agent))
	}
	return logger.With(attrs...)
}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
go test ./orchestrator/internal/observability -run TestWithRunID -v
# Expected: PASS
```

- [ ] **Step 5: Update scheduler to carry context**

Modify `orchestrator/internal/exercise/scheduler.go`:

In `DispatchTask` function, add context propagation:

```go
func (s *Scheduler) DispatchTask(ctx context.Context, runID, taskID string, task *models.Task) error {
	// Add correlation IDs to context
	ctx = observability.WithRunID(ctx, runID)
	ctx = observability.WithTaskID(ctx, taskID)
	
	logger := observability.CorrelationLogger(ctx, slog.Default())
	logger.Info("task dispatched", "target_agents", len(task.Agents))
	
	// ... rest of dispatch logic
}
```

- [ ] **Step 6: Update executor to carry and expand context**

Modify `orchestrator/internal/exercise/executor.go`:

In `Execute` function, read task IDs and add agent ID when assignment happens:

```go
func (e *Executor) Execute(ctx context.Context, agent *models.Agent) error {
	run, task, attempt, _ := observability.GetCorrelationIDs(ctx)
	ctx = observability.WithAgentID(ctx, agent.ID)
	
	logger := observability.CorrelationLogger(ctx, slog.Default())
	logger.Info("execution started", "agent", agent.ID)
	
	// ... execution logic
	
	logger.Info("execution completed", "status", result.Status)
}
```

- [ ] **Step 7: Commit correlation infrastructure**

```bash
git add orchestrator/internal/observability/observability.go orchestrator/internal/observability/observability_test.go orchestrator/internal/exercise/scheduler.go orchestrator/internal/exercise/executor.go
git commit -m "feat: correlation ID context propagation (run/task/attempt/agent)"
```

---

### Task 3: Metrics Expansion (P0)

**Files:**
- Modify: `orchestrator/internal/api/observability.go`
- Modify: `orchestrator/internal/observability/metrics.go` (create if needed)
- Test: Expand `observability_test.go`

**Interfaces:**
- Produces: `observability.RecordTaskQueueWait(duration)`, `observability.RecordSchedulerDispatch(duration)`, `observability.RecordExecutionDuration(technique, duration)`, `observability.RecordAgentExecutionDuration(agentID, duration)` (gauge only, not histogram)

- [ ] **Step 1: Define new metrics**

Modify `orchestrator/internal/api/observability.go` to add:

```go
var (
	// Existing metrics...
	
	taskQueueWait = promauto.NewHistogram(prometheus.HistogramOpts{
		Name: "task_queue_wait_seconds",
		Help: "Time from task creation to agent assignment",
		Buckets: prometheus.DefBuckets,
	})
	
	schedulerDispatchLatency = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name: "scheduler_dispatch_latency_seconds",
		Help: "Latency of task dispatch operation",
		Buckets: prometheus.DefBuckets,
	}, []string{"technique"})
	
	executionDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name: "execution_duration_seconds",
		Help: "Total execution time from task start to completion",
		Buckets: prometheus.DefBuckets,
	}, []string{"technique", "status"})
	
	agentExecutionDuration = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "agent_execution_duration_seconds",
		Help: "Current execution duration on agent (gauge, not histogram)",
	}, []string{"agent_id", "status"})
	
	agentAvailability = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "agent_availability",
		Help: "1 if agent is available, 0 otherwise",
	}, []string{"agent_id"})
	
	queueDepth = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "task_queue_depth",
		Help: "Number of tasks waiting for agent assignment",
	}, []string{"technique"})
)
```

- [ ] **Step 2: Add recording functions**

In `orchestrator/internal/observability/metrics.go` (or `observability.go`):

```go
func RecordTaskQueueWait(duration time.Duration) {
	taskQueueWait.Observe(duration.Seconds())
}

func RecordSchedulerDispatch(technique string, duration time.Duration) {
	schedulerDispatchLatency.WithLabelValues(technique).Observe(duration.Seconds())
}

func RecordExecutionDuration(technique, status string, duration time.Duration) {
	executionDuration.WithLabelValues(technique, status).Observe(duration.Seconds())
}

func SetAgentExecutionDuration(agentID, status string, duration time.Duration) {
	agentExecutionDuration.WithLabelValues(agentID, status).Set(duration.Seconds())
}

func SetAgentAvailable(agentID string, available bool) {
	val := 0.0
	if available {
		val = 1.0
	}
	agentAvailability.WithLabelValues(agentID).Set(val)
}

func SetQueueDepth(technique string, depth int) {
	queueDepth.WithLabelValues(technique).Set(float64(depth))
}
```

- [ ] **Step 3: Wire metrics into scheduler and executor**

Modify `orchestrator/internal/exercise/scheduler.go`:

```go
func (s *Scheduler) DispatchTask(ctx context.Context, runID, taskID string, task *models.Task) error {
	start := time.Now()
	defer func() {
		observability.RecordSchedulerDispatch(task.Technique, time.Since(start))
	}()
	
	// ... dispatch logic
}
```

Modify `orchestrator/internal/exercise/executor.go`:

```go
func (e *Executor) Execute(ctx context.Context, agent *models.Agent) error {
	start := time.Now()
	
	// ... execution
	
	status := "success"
	if err != nil {
		status = "failed"
	}
	observability.RecordExecutionDuration(technique, status, time.Since(start))
}
```

- [ ] **Step 4: Test metrics emission**

Write test in `observability_test.go`:

```go
func TestMetricsEmission(t *testing.T) {
	observability.RecordTaskQueueWait(100 * time.Millisecond)
	observability.RecordSchedulerDispatch("T1046", 50 * time.Millisecond)
	observability.RecordExecutionDuration("T1046", "success", 500 * time.Millisecond)
	
	// Metrics should be recorded in Prometheus without error
	// (verify via scrape endpoint or collector export)
}
```

- [ ] **Step 5: Commit metrics expansion**

```bash
git add orchestrator/internal/api/observability.go orchestrator/internal/observability/metrics.go orchestrator/internal/exercise/scheduler.go orchestrator/internal/exercise/executor.go
git commit -m "feat: expand metrics (queue wait, dispatch latency, execution duration, agent availability)"
```

---

### Task 4: Built-in Observability Dashboard (P0)

**Files:**
- Create: `orchestrator/internal/api/observability_dashboard.go`
- Modify: `orchestrator/internal/api/observability.go` (add /api/observability/summary endpoint)
- Modify: `cmd/server/routes.go` (mount dashboard routes)

**Interfaces:**
- Produces: `GET /api/observability/summary` returns JSON with platform health, active runs, queue depth, failure rate, P95 latency
- Produces: `GET /api/observability/runs` returns paginated list of runs with status
- Produces: `GET /api/observability/runs/{id}/tasks` returns tasks for a run

- [ ] **Step 1: Write dashboard data model**

Create `orchestrator/internal/api/observability_dashboard.go`:

```go
package api

import (
	"context"
	"time"
)

type ObservabilitySummary struct {
	Platform PlatformHealth `json:"platform"`
	Runs     RunsSnapshot   `json:"runs"`
	Queue    QueueStatus    `json:"queue"`
}

type PlatformHealth struct {
	Status      string `json:"status"`      // "healthy", "degraded", "critical"
	Agents      int    `json:"agents"`
	AgentsReady int    `json:"agents_ready"`
	FailureRate float64 `json:"failure_rate"`
	P95Latency  float64 `json:"p95_latency_seconds"`
}

type RunsSnapshot struct {
	Active    int `json:"active"`
	Completed int `json:"completed_recent"` // last 24 hours
	Failed    int `json:"failed_recent"`
}

type QueueStatus struct {
	Depth              int    `json:"depth"`
	OldestTask         string `json:"oldest_task_id,omitempty"`
	OldestTaskAgeSeconds int    `json:"oldest_age_seconds"`
}

// ComputeSummary aggregates platform state into a single snapshot
func (h *Handler) ComputeSummary(ctx context.Context) (*ObservabilitySummary, error) {
	// Query DB for: active runs, failed runs, agents, queue depth
	// Query Prometheus for: failure rate, P95 latency
	
	return &ObservabilitySummary{
		Platform: PlatformHealth{
			Status:      "healthy",  // TBD: compute from agent availability + failure rate
			Agents:      20,         // TBD: query from DB
			AgentsReady: 18,         // TBD: query from DB
			FailureRate: 0.018,      // TBD: query from Prometheus
			P95Latency:  4.2,        // TBD: query from Prometheus
		},
		Runs: RunsSnapshot{
			Active:    43,
			Completed: 120,
			Failed:    3,
		},
		Queue: QueueStatus{
			Depth:              127,
			OldestTask:         "task-999",
			OldestTaskAgeSeconds: 45,
		},
	}, nil
}
```

- [ ] **Step 2: Write endpoint test**

```go
func TestHandleObservabilitySummary(t *testing.T) {
	// Setup handler with mock DB
	req := httptest.NewRequest("GET", "/api/observability/summary", nil)
	w := httptest.NewRecorder()
	
	h.handleObservabilitySummary(w, req)
	
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	
	var summary ObservabilitySummary
	json.Unmarshal(w.Body.Bytes(), &summary)
	
	if summary.Platform.Status == "" {
		t.Error("platform status should not be empty")
	}
}
```

- [ ] **Step 3: Implement endpoints**

Modify `orchestrator/internal/api/observability.go`:

```go
func (h *Handler) handleObservabilitySummary(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	
	summary, err := h.ComputeSummary(ctx)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(summary)
}
```

- [ ] **Step 4: Create web UI**

Add to `wwwroot/index.html` (or new `wwwroot/observability.html`):

```html
<!DOCTYPE html>
<html>
<head>
  <title>Observability</title>
  <style>
    .platform-health { font-size: 1.2em; font-weight: bold; }
    .status-healthy { color: green; }
    .status-degraded { color: orange; }
    .status-critical { color: red; }
  </style>
</head>
<body>
  <h1>Platform Observability</h1>
  
  <div class="platform-health">
    <span id="status" class="status-healthy">HEALTHY</span>
  </div>
  
  <div id="summary">
    <p>Agents: <span id="agents">--</span> / <span id="agents_ready">--</span></p>
    <p>Running: <span id="active_runs">--</span></p>
    <p>Queued: <span id="queue_depth">--</span></p>
    <p>Failure Rate: <span id="failure_rate">--</span></p>
    <p>P95 Latency: <span id="p95_latency">--</span>s</p>
  </div>
  
  <script>
    async function refreshSummary() {
      const res = await fetch('/api/observability/summary');
      const data = await res.json();
      document.getElementById('status').textContent = data.platform.status.toUpperCase();
      document.getElementById('status').className = 'status-' + data.platform.status;
      document.getElementById('agents').textContent = data.platform.agents;
      document.getElementById('agents_ready').textContent = data.platform.agents_ready;
      document.getElementById('active_runs').textContent = data.runs.active;
      document.getElementById('queue_depth').textContent = data.queue.depth;
      document.getElementById('failure_rate').textContent = (data.platform.failure_rate * 100).toFixed(2) + '%';
      document.getElementById('p95_latency').textContent = data.platform.p95_latency.toFixed(2);
    }
    
    refreshSummary();
    setInterval(refreshSummary, 5000); // Refresh every 5s
  </script>
</body>
</html>
```

- [ ] **Step 5: Mount routes**

Modify `cmd/server/routes.go`:

```go
r.Get("/api/observability/summary", h.handleObservabilitySummary)
r.Get("/observability", serveFile("observability.html"))
```

- [ ] **Step 6: Commit dashboard**

```bash
git add orchestrator/internal/api/observability_dashboard.go cmd/server/routes.go wwwroot/observability.html
git commit -m "feat: built-in observability dashboard (/api/observability/summary + web UI)"
```

---

### Task 5: OpenTelemetry SDK Wiring (P1)

**Files:**
- Create: `orchestrator/internal/observability/otel.go`
- Modify: `cmd/server/main.go`
- Test: `observability_test.go`

**Interfaces:**
- Produces: `observability.InitOTel(cfg Config) (*TracerProvider, error)`, `observability.NewSpan(ctx, "span_name") context.Context`, `observability.AddSpanAttribute(ctx, key, value)`

- [ ] **Step 1-10: (Placeholder for brevity)**

Create OTel SDK initialization with configurable exporters (none by default, optional via config). Implement span emission at scheduler/executor/agent boundaries. Wire into main() with lazy initialization (only if exporters configured).

---

### Task 6-10: (Placeholder Summary)

**Task 6:** Exporters (Prometheus remote-write, Tempo, Jaeger) — pluggable, none required by default  
**Task 7:** Local alerting rule engine — threshold-based rules, webhook notifications  
**Task 8:** On-demand profiling — /api/debug/profile endpoint  
**Task 9:** Integration tests — full run with correlation IDs, metrics, and dashboard  
**Task 10:** Documentation + overhead validation — measure actual impact, finalize design docs  

---

## Summary

Phase 8 transforms observability from isolated metrics + logs into **integrated instrumentation with correlation IDs**, enabling operators to drill from a run ID through the entire execution stack without external tools or manual log correlation.

The three-tier structure (P0 core, P1 tracing, P2 diagnostics) allows early delivery of the highest-value piece (correlation IDs making existing logs useful) while keeping optional pieces pluggable.

Critical constraint: overhead must be negligible when not actively profiling — all collection is synchronous, expensive operations (deep profiling, trace export) are on-demand or configurable.
