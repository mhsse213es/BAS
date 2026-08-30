# Observability Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give the orchestrator real observability infrastructure — `log/slog` structured logging for new code, a genuine liveness/readiness split, and a Prometheus `/metrics` endpoint — without needing a live dev server to build or test any of it.

**Architecture:** A new `internal/jobs.MetricsFn` hook (mirroring the existing `NotifyFn` pattern exactly) lets `internal/jobs.Dispatcher` report job start/completion without importing a metrics library. A new `internal/api/observability.go` owns every Prometheus collector, the `RequestLoggingMiddleware` that feeds both HTTP metrics and structured request logs from one instrumentation point, and the `/ready` + `/metrics` handlers. `TickSLABreaches` (already in `internal/api/sla_handlers.go`) gets two direct metric increments. `Config.MetricsToken` is a new optional field, unset-by-default-open, gating `/metrics` the same way other optional secrets in this codebase gate their features.

**Tech Stack:** Go 1.26, `log/slog` (stdlib), `github.com/prometheus/client_golang` (new dependency), `github.com/go-chi/chi/v5` (already in use), testcontainers-backed Postgres via the existing `sharedDB.RunWithPool` test harness.

**Spec:** `orchestrator/docs/superpowers/specs/2026-08-29-observability-foundation-design.md`

## Global Constraints

- `log/slog` is the structured-logging convention for **new code only** — the existing 373 `log.Printf`/`log.Println`/`log.Fatal` call sites are not touched.
- No wrapper around `slog.Logger` — call sites use `slog.Logger`/`slog.Default()` directly.
- No request-ID/correlation-ID system, no automated secret/PII redaction — code-review discipline only.
- `/health` (`routes.go:122`) stays byte-for-byte unchanged.
- `/metrics` uses `promhttp.Handler()` directly — never a hand-rolled exposition format.
- Every metric label is bounded-cardinality: `method`, `route` (chi's matched pattern, never the raw URL), `status`, `type`, `severity`. Never `user_id`/`agent_id`/`run_id`/`finding_id`/`request_id`.
- `middleware.Logger` (chi's built-in, `routes.go:24`) is **replaced** by the new `RequestLoggingMiddleware`, not run alongside it — avoids duplicate per-request log lines.
- No Grafana/Prometheus-server/Kubernetes/alerting work. No perf/load testing, no upgrade validation — separate Phase 8 items.

---

## File Structure

- **Create** `orchestrator/internal/jobs/metrics.go` — `MetricsEvent`/`MetricsFn`/`SetMetrics`, mirroring `notify.go`.
- **Modify** `orchestrator/internal/jobs/dispatch.go` — fire the metrics hook from `Tick()`'s state-transition block.
- **Modify** `orchestrator/internal/jobs/dispatch_test.go` — extend two existing tests to assert the new hook fires correctly.
- **Modify** `orchestrator/go.mod` / `go.sum` — add `github.com/prometheus/client_golang`.
- **Create** `orchestrator/internal/api/observability.go` — every Prometheus collector, `RequestLoggingMiddleware`, `dispatchJobMetrics` adapter, `handleReady`, `metricsHandler`.
- **Create** `orchestrator/internal/api/observability_test.go` — tests for the middleware, `/ready`, `/metrics`.
- **Modify** `orchestrator/internal/api/handlers.go` — add `metricsToken` field to `Handler`, add `WithMetricsToken`.
- **Modify** `orchestrator/internal/api/job_dispatch.go` — wire `dispatcher.SetMetrics(h.dispatchJobMetrics)` into `WithJobsDispatcher`.
- **Modify** `orchestrator/internal/api/routes.go` — replace `middleware.Logger`, add `/ready` and `/metrics` routes.
- **Modify** `orchestrator/internal/api/sla_handlers.go` — two metric increments inside `TickSLABreaches`.
- **Modify** `orchestrator/internal/api/sla_handlers_test.go` — extend one existing test to assert the new counters.
- **Modify** `orchestrator/config/config.go` — add `MetricsToken` field + `METRICS_TOKEN` env override.
- **Modify** `orchestrator/cmd/server/main.go` — `slog.SetDefault(...)` at startup, `.WithMetricsToken(cfg.MetricsToken)` in the handler chain.

---

### Task 1: `internal/jobs` metrics hook

**Files:**
- Create: `orchestrator/internal/jobs/metrics.go`
- Modify: `orchestrator/internal/jobs/dispatch.go`
- Test: `orchestrator/internal/jobs/dispatch_test.go`

**Interfaces:**
- Produces: `type MetricsEvent struct { Type, JobType string; DurationSecs float64; HasDuration bool }`, `type MetricsFn func(evt MetricsEvent)`, `func (d *Dispatcher) SetMetrics(fn MetricsFn)`, consts `MetricsEventJobStarted = "job_started"`, `MetricsEventJobCompleted = "job_completed"`. Task 2's `dispatchJobMetrics` adapter consumes these exact names.

- [ ] **Step 1: Write the failing tests**

Extend `TestTick_NotifiesTargetDeferred` (the existing requested→running scenario, `orchestrator/internal/jobs/dispatch_test.go` lines 214-263) to also assert the metrics hook fires:

```go
		var events []NotifyEvent
		var metricsEvents []MetricsEvent
		d := NewDispatcher(store)
		d.SetDispatch(func(ctx context.Context, j Job, target JobTarget) (string, error) {
			t.Fatal("dispatch should not be called -- the agent is frozen")
			return "", nil
		})
		d.SetStatus(func(ctx context.Context, jobType, refID string) (string, string, bool) { return "", "", false })
		d.SetNotify(func(ctx context.Context, evt NotifyEvent) {
			events = append(events, evt)
		})
		d.SetMetrics(func(evt MetricsEvent) {
			metricsEvents = append(metricsEvents, evt)
		})

		if err := d.Tick(ctx); err != nil {
			t.Fatalf("Tick: %v", err)
		}
		// ... existing events assertions unchanged ...
		if len(metricsEvents) != 1 {
			t.Fatalf("got %d metrics events, want 1 (job_started): %+v", len(metricsEvents), metricsEvents)
		}
		if metricsEvents[0].Type != MetricsEventJobStarted || metricsEvents[0].JobType != "batch_remediation" {
			t.Errorf("metricsEvents[0] = %+v, want job_started for type batch_remediation", metricsEvents[0])
		}
```

Extend `TestTick_ResolvesTerminalTargetsAndAggregatesJobState` (the existing dispatched→completed scenario, lines 56-96) to also assert the completed hook fires with a known duration:

```go
		var metricsEvents []MetricsEvent
		d := NewDispatcher(store)
		d.SetDispatch(func(ctx context.Context, j Job, target JobTarget) (string, error) {
			t.Fatal("dispatch should not be called -- the only target is already dispatched")
			return "", nil
		})
		d.SetStatus(func(ctx context.Context, jobType, refID string) (string, string, bool) {
			if refID == "ref-done" {
				return TargetStateCompleted, "", true
			}
			return TargetStateDispatched, "", false
		})
		d.SetMetrics(func(evt MetricsEvent) {
			metricsEvents = append(metricsEvents, evt)
		})

		if err := d.Tick(ctx); err != nil {
			t.Fatalf("Tick: %v", err)
		}
		// ... existing gotJob assertions unchanged ...
		if len(metricsEvents) != 1 {
			t.Fatalf("got %d metrics events, want 1 (job_completed): %+v", len(metricsEvents), metricsEvents)
		}
		if metricsEvents[0].Type != MetricsEventJobCompleted || metricsEvents[0].JobType != "batch_remediation" {
			t.Errorf("metricsEvents[0] = %+v, want job_completed for type batch_remediation", metricsEvents[0])
		}
		if !metricsEvents[0].HasDuration || metricsEvents[0].DurationSecs < 0 {
			t.Errorf("metricsEvents[0] = %+v, want HasDuration=true and DurationSecs >= 0", metricsEvents[0])
		}
```

(This job goes straight from `requested` to `completed` in one tick — SetJobState's `COALESCE(started_at, NOW())` and `completed_at=NOW()` are stamped together, so `DurationSecs` will typically read as `0`, which is why the assertion checks `HasDuration` rather than `DurationSecs > 0`.)

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/jobs/... -run 'TestTick_NotifiesTargetDeferred|TestTick_ResolvesTerminalTargetsAndAggregatesJobState' -v`
Expected: FAIL — `d.SetMetrics undefined`, `MetricsEvent undefined`

- [ ] **Step 3: Create `metrics.go`**

```go
package jobs

// MetricsEvent is internal/jobs's own copy of the metrics-event shape --
// the same reasoning as NotifyEvent (notify.go): internal/jobs must not
// import a metrics library or internal/api directly, so SetMetrics is an
// injected hook, keeping this package a leaf dependency.
type MetricsEvent struct {
	Type    string
	JobType string
	// DurationSecs and HasDuration are only meaningful when
	// Type == MetricsEventJobCompleted. HasDuration is false only when the
	// post-transition Store.Get() lookup needed to read back the
	// DB-stamped started_at/completed_at failed -- distinct from
	// DurationSecs == 0, which is the real (if common) case of a job
	// resolving straight to a terminal state in the same tick it left
	// "requested" (SetJobState's COALESCE stamps both timestamps together
	// in one UPDATE, so they read as equal).
	DurationSecs float64
	HasDuration  bool
}

// MetricsFn is called for every job state transition Tick() records.
// Like NotifyFn, it is optional: every call site in dispatch.go MUST
// guard with `if d.metrics != nil` (recordStateMetrics does this once,
// centrally).
type MetricsFn func(evt MetricsEvent)

func (d *Dispatcher) SetMetrics(fn MetricsFn) { d.metrics = fn }

const (
	MetricsEventJobStarted   = "job_started"
	MetricsEventJobCompleted = "job_completed"
)
```

- [ ] **Step 4: Add the `metrics` field to `Dispatcher` and fire the hook from `Tick()`**

In `orchestrator/internal/jobs/dispatch.go`, add the field:

```go
type Dispatcher struct {
	store    *Store
	dispatch DispatchFn
	status   StatusFn
	notify   NotifyFn
	metrics  MetricsFn
}
```

Replace the aggregate-state block (currently lines 145-167) with:

```go
	for jobID := range touchedJobs {
		targets, err := d.store.ListTargets(ctx, jobID)
		if err != nil {
			continue
		}
		job, err := jobOf(jobID)
		if err != nil {
			continue
		}
		newState := AggregateState(job.State, targets)
		if newState != job.State {
			if err := d.store.SetJobState(ctx, jobID, newState); err == nil {
				updated := job
				updated.State = newState
				jobCache[jobID] = updated
				if d.notify != nil {
					if evtType, sev, ok := classifyJobTransition(newState); ok {
						d.notify(ctx, NotifyEvent{Type: evtType, JobID: jobID, Severity: sev})
					}
				}
				d.recordStateMetrics(ctx, jobID, job.Type, newState)
			}
		}
	}
	return nil
}

// recordStateMetrics fires the optional metrics hook for a job's state
// transition. Called after SetJobState persists newState. For a terminal
// transition it re-fetches the job: SetJobState's COALESCE-stamped
// started_at/completed_at aren't reflected in the in-memory job value
// Tick() already holds (only .State is hand-updated on the jobCache copy
// above).
func (d *Dispatcher) recordStateMetrics(ctx context.Context, jobID, jobType, newState string) {
	if d.metrics == nil {
		return
	}
	if newState == JobStateRunning {
		d.metrics(MetricsEvent{Type: MetricsEventJobStarted, JobType: jobType})
		return
	}
	if !IsTerminalJobState(newState) {
		return
	}
	evt := MetricsEvent{Type: MetricsEventJobCompleted, JobType: jobType}
	if fresh, err := d.store.Get(ctx, jobID); err == nil && fresh.StartedAt != nil && fresh.CompletedAt != nil {
		dur := fresh.CompletedAt.Sub(*fresh.StartedAt)
		if dur < 0 {
			dur = 0
		}
		evt.DurationSecs = dur.Seconds()
		evt.HasDuration = true
	}
	d.metrics(evt)
}
```

(Note: the final `return nil` and closing `}` of `Tick()` move up to right after the loop, as shown -- `recordStateMetrics` is a new top-level function after it, not nested inside `Tick()`.)

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/jobs/... -run 'TestTick_NotifiesTargetDeferred|TestTick_ResolvesTerminalTargetsAndAggregatesJobState' -v`
Expected: PASS

- [ ] **Step 6: Run the full `internal/jobs` suite**

Run: `cd orchestrator && go test ./internal/jobs/... -p 1`
Expected: PASS (no regressions in unrelated jobs tests)

- [ ] **Step 7: Commit**

```bash
git add orchestrator/internal/jobs/metrics.go orchestrator/internal/jobs/dispatch.go orchestrator/internal/jobs/dispatch_test.go
git commit -m "feat: add optional metrics hook to internal/jobs.Dispatcher"
git push
```

---

### Task 2: Prometheus collectors, request-logging middleware, job-metrics adapter

**Files:**
- Modify: `orchestrator/go.mod`, `orchestrator/go.sum`
- Create: `orchestrator/internal/api/observability.go`
- Create: `orchestrator/internal/api/observability_test.go`

**Interfaces:**
- Consumes: `jobs.MetricsEvent`, `jobs.MetricsEventJobStarted`, `jobs.MetricsEventJobCompleted` (Task 1).
- Produces: package-level collectors `httpRequestsTotal`, `httpRequestDuration`, `jobsActive`, `jobExecutionDuration`, `slaBreachEvaluationsTotal`, `slaBreachesTotal`, `dbReady` (all `*prometheus.CounterVec`/`*prometheus.HistogramVec`/`*prometheus.GaugeVec`/`prometheus.Counter`/`prometheus.Gauge`); `func RequestLoggingMiddleware(next http.Handler) http.Handler`; `func (h *Handler) dispatchJobMetrics(evt jobs.MetricsEvent)`; `func (h *Handler) handleReady(w http.ResponseWriter, r *http.Request)`; `func (h *Handler) metricsHandler() http.Handler`. Task 3 wires `handleReady`/`metricsHandler` into routes; Task 4 wires `dispatchJobMetrics`; Task 5 uses `slaBreachEvaluationsTotal`/`slaBreachesTotal` directly (same package, no import needed).

- [ ] **Step 1: Add the dependency**

Run: `cd orchestrator && go get github.com/prometheus/client_golang@latest && go mod tidy`
Expected: `go.mod`/`go.sum` gain `github.com/prometheus/client_golang` and its transitive deps (`github.com/beorn7/perks`, `github.com/cespare/xxhash/v2`, `github.com/prometheus/client_model`, `github.com/prometheus/common`, `github.com/prometheus/procfs`, `google.golang.org/protobuf` if not already present).

- [ ] **Step 2: Write the failing test for the middleware**

```go
package api

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
)

func TestRequestLoggingMiddleware_LogsAndRecordsMetrics(t *testing.T) {
	var logBuf strings.Builder
	prevLogger := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logBuf, nil)))
	defer slog.SetDefault(prevLogger)

	r := chi.NewRouter()
	r.Use(RequestLoggingMiddleware)
	r.Get("/api/widgets/{id}", func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusCreated)
	})

	before := testutil.ToFloat64(httpRequestsTotal.WithLabelValues("GET", "/api/widgets/{id}", "201"))

	req := httptest.NewRequest(http.MethodGet, "/api/widgets/42", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201", rec.Code)
	}

	after := testutil.ToFloat64(httpRequestsTotal.WithLabelValues("GET", "/api/widgets/{id}", "201"))
	if after != before+1 {
		t.Errorf("httpRequestsTotal delta = %v, want 1", after-before)
	}

	logOut := logBuf.String()
	for _, want := range []string{`"component":"http"`, `"method":"GET"`, `"route":"/api/widgets/{id}"`, `"status":201`} {
		if !strings.Contains(logOut, want) {
			t.Errorf("log output missing %q; got %s", want, logOut)
		}
	}
}
```

Add `"github.com/prometheus/client_golang/prometheus/testutil"` to the test file's imports.

- [ ] **Step 3: Run the test to verify it fails**

Run: `cd orchestrator && go test ./internal/api/... -run TestRequestLoggingMiddleware -v`
Expected: FAIL — `RequestLoggingMiddleware undefined`, `httpRequestsTotal undefined`

- [ ] **Step 4: Create `observability.go`**

```go
package api

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/audspect/bas/internal/jobs"
)

// Every label below is bounded-cardinality by construction: method is one
// of a handful of HTTP verbs, route is chi's matched pattern (e.g.
// "/api/sla/policies/{severity}"), status is an HTTP status code, type is
// a job type string, severity is one of Critical/High/Medium/Low. Never
// add a label carrying a per-entity ID (user_id, agent_id, run_id,
// finding_id, request_id) -- see the observability-foundation design spec.
var (
	httpRequestsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "http_requests_total",
		Help: "Total HTTP requests processed, labeled by method, route, and status.",
	}, []string{"method", "route", "status"})

	httpRequestDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name: "http_request_duration_seconds",
		Help: "HTTP request latency in seconds, labeled by method and route.",
	}, []string{"method", "route"})

	jobsActive = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "jobs_active",
		Help: "Number of Fleet Job Engine jobs currently in a non-terminal state, labeled by job type.",
	}, []string{"type"})

	jobExecutionDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name: "job_execution_duration_seconds",
		Help: "Elapsed time from a job's first state transition to its terminal state, labeled by job type.",
	}, []string{"type"})

	slaBreachEvaluationsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sla_breach_evaluations_total",
		Help: "Total number of TickSLABreaches evaluation runs.",
	})

	slaBreachesTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sla_breaches_total",
		Help: "Total number of posture findings marked breached, labeled by severity.",
	}, []string{"severity"})

	dbReady = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "db_ready",
		Help: "1 if the most recent /ready check reached Postgres successfully, 0 otherwise.",
	})
)

// RequestLoggingMiddleware replaces chi's default middleware.Logger
// (routes.go). One instrumentation point per completed request feeds both
// a structured slog line and the two HTTP metrics above.
func RequestLoggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
		next.ServeHTTP(ww, r)
		duration := time.Since(start)

		route := chi.RouteContext(r.Context()).RoutePattern()
		if route == "" {
			route = "unmatched" // avoids one label value per raw 404 path
		}
		status := ww.Status()
		if status == 0 {
			status = http.StatusOK
		}

		httpRequestsTotal.WithLabelValues(r.Method, route, strconv.Itoa(status)).Inc()
		httpRequestDuration.WithLabelValues(r.Method, route).Observe(duration.Seconds())

		slog.Info("http request",
			"component", "http",
			"method", r.Method,
			"route", route,
			"status", status,
			"duration_ms", duration.Milliseconds(),
		)
	})
}

// dispatchJobMetrics adapts a jobs.MetricsEvent (plain strings, defined in
// internal/jobs -- that package must not import prometheus) into the
// jobsActive/jobExecutionDuration collectors above. Passed to
// jobsDispatcher.SetMetrics in WithJobsDispatcher (job_dispatch.go),
// mirroring dispatchJobNotify's exact shape.
func (h *Handler) dispatchJobMetrics(evt jobs.MetricsEvent) {
	switch evt.Type {
	case jobs.MetricsEventJobStarted:
		jobsActive.WithLabelValues(evt.JobType).Inc()
	case jobs.MetricsEventJobCompleted:
		jobsActive.WithLabelValues(evt.JobType).Dec()
		if evt.HasDuration {
			jobExecutionDuration.WithLabelValues(evt.JobType).Observe(evt.DurationSecs)
		}
	}
}

// handleReady answers "can this instance actually serve traffic right
// now" (readiness), distinct from /health's "is the process alive"
// (liveness). Top-level route -- bypasses LicenseGate's prefix-based
// gating the same way /health already does.
func (h *Handler) handleReady(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	w.Header().Set("Content-Type", "application/json")
	if err := h.db.Ping(ctx); err != nil {
		dbReady.Set(0)
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(map[string]any{
			"status": "not_ready",
			"checks": map[string]string{"database": err.Error()},
		})
		return
	}
	dbReady.Set(1)
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]any{
		"status": "ready",
		"checks": map[string]string{"database": "ok"},
	})
}

// metricsHandler serves Prometheus text-exposition format via
// promhttp.Handler() directly. When h.metricsToken is set, every request
// needs a matching "Authorization: Bearer <token>" header -- a simple
// equality check, not the SCIM token_hash/tenant-lookup machinery (no
// per-tenant dimension for a single instance-wide optional secret).
func (h *Handler) metricsHandler() http.Handler {
	base := promhttp.Handler()
	if h.metricsToken == "" {
		return base
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+h.metricsToken {
			jsonError(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		base.ServeHTTP(w, r)
	})
}
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `cd orchestrator && go test ./internal/api/... -run TestRequestLoggingMiddleware -v`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add orchestrator/go.mod orchestrator/go.sum orchestrator/internal/api/observability.go orchestrator/internal/api/observability_test.go
git commit -m "feat: add Prometheus collectors and request-logging middleware"
git push
```

---

### Task 3: `/ready` endpoint

**Files:**
- Test: `orchestrator/internal/api/observability_test.go`
- Modify: `orchestrator/internal/api/routes.go`

**Interfaces:**
- Consumes: `h.handleReady` (Task 2).
- Produces: `GET /ready` wired into `Mount()`.

- [ ] **Step 1: Write the failing tests**

Append to `orchestrator/internal/api/observability_test.go`:

```go
func TestHandleReady_DatabaseReachable_Returns200(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		req := httptest.NewRequest(http.MethodGet, "/ready", nil)
		rec := httptest.NewRecorder()
		h.handleReady(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
		var body map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if body["status"] != "ready" {
			t.Errorf("status field = %v, want ready", body["status"])
		}
	})
}

func TestHandleReady_DatabaseUnreachable_Returns503(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		pool.Close() // simulates an unreachable database
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		req := httptest.NewRequest(http.MethodGet, "/ready", nil)
		rec := httptest.NewRecorder()
		h.handleReady(rec, req)

		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("status = %d, want 503", rec.Code)
		}
		var body map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if body["status"] != "not_ready" {
			t.Errorf("status field = %v, want not_ready", body["status"])
		}
	})
}
```

Also append this regression test guarding `/health`'s unconditional behavior, per the spec's testing section ("`/health`: unchanged regression test"). It exercises the real route through `Mount()`, not just `handleReady` directly:

```go
func TestHealthEndpoint_UnconditionalOK(t *testing.T) {
	h := New(nil, ws.NewHub(), scenario.NewEngine(t.TempDir()), "test-secret")
	router := Mount(h, ws.NewHub(), "test-secret", "", http.NotFoundHandler(), 0, 0)

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if rec.Body.String() != `{"status":"ok"}` {
		t.Errorf("body = %q, want exactly {\"status\":\"ok\"} (unconditional -- no DB dependency)", rec.Body.String())
	}
}
```

(`h.db` is `nil` here deliberately -- `/health` must return 200 even with no database at all, unlike the new `/ready`. This is the guard against `/health` accidentally growing a DB check.)

Add `"encoding/json"`, `"github.com/audspect/bas/internal/scenario"`, `"github.com/audspect/bas/internal/ws"`, `"github.com/jackc/pgx/v5/pgxpool"` to the test file's imports if not already present (mirror `sla_handlers_test.go`'s import block).

- [ ] **Step 2: Run the new tests**

Run: `cd orchestrator && go test ./internal/api/... -run 'TestHandleReady|TestHealthEndpoint_UnconditionalOK' -v`
Expected: all three PASS immediately. `TestHealthEndpoint_UnconditionalOK` is a pure regression guard on code that already exists and is untouched. `TestHandleReady_*` also pass immediately because `handleReady` itself was already written in Task 2, Step 4 -- this task only adds its dedicated tests and the `/ready` route registration (Step 4 below). If any of the three fail, stop and investigate before continuing -- Task 2 should already satisfy them.

- [ ] **Step 3: Wire `/ready` into `Mount()`**

In `orchestrator/internal/api/routes.go`, immediately after the existing `/health` block (lines 121-125):

```go
	// Health check
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	})

	// Readiness check -- distinct from /health above: this one actually
	// reaches Postgres. Top-level, so it bypasses LicenseGate's
	// prefix-based gating the same way /health does.
	r.Get("/ready", h.handleReady)
```

- [ ] **Step 4: Run the full `internal/api` suite**

Run: `cd orchestrator && go test ./internal/api/... -p 1`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/api/observability_test.go orchestrator/internal/api/routes.go
git commit -m "feat: add /ready readiness endpoint"
git push
```

---

### Task 4: `/metrics` endpoint, request-logging middleware wiring, job-metrics hook wiring

**Files:**
- Modify: `orchestrator/internal/api/handlers.go`
- Modify: `orchestrator/internal/api/job_dispatch.go`
- Modify: `orchestrator/internal/api/routes.go`
- Test: `orchestrator/internal/api/observability_test.go`
- Test: `orchestrator/internal/api/license_gate_test.go` (regression check only, no edit expected)

**Interfaces:**
- Consumes: `h.metricsHandler`, `h.dispatchJobMetrics` (Task 2).
- Produces: `Handler.metricsToken string` field, `func (h *Handler) WithMetricsToken(token string) *Handler`. Task 6 (main.go) calls `WithMetricsToken(cfg.MetricsToken)`.

- [ ] **Step 1: Write the failing tests**

Append to `orchestrator/internal/api/observability_test.go`:

```go
func TestMetricsHandler_NoTokenConfigured_Open(t *testing.T) {
	h := New(nil, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	h.metricsHandler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "go_goroutines") {
		t.Errorf("response missing expected Go runtime collector output")
	}
}

func TestMetricsHandler_TokenConfigured_RequiresBearer(t *testing.T) {
	h := New(nil, ws.NewHub(), scenario.NewEngine(t.TempDir()), "").WithMetricsToken("s3cr3t")

	noAuth := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	recNoAuth := httptest.NewRecorder()
	h.metricsHandler().ServeHTTP(recNoAuth, noAuth)
	if recNoAuth.Code != http.StatusUnauthorized {
		t.Errorf("no-auth status = %d, want 401", recNoAuth.Code)
	}

	wrongAuth := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	wrongAuth.Header.Set("Authorization", "Bearer wrong")
	recWrong := httptest.NewRecorder()
	h.metricsHandler().ServeHTTP(recWrong, wrongAuth)
	if recWrong.Code != http.StatusUnauthorized {
		t.Errorf("wrong-token status = %d, want 401", recWrong.Code)
	}

	rightAuth := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rightAuth.Header.Set("Authorization", "Bearer s3cr3t")
	recRight := httptest.NewRecorder()
	h.metricsHandler().ServeHTTP(recRight, rightAuth)
	if recRight.Code != http.StatusOK {
		t.Errorf("correct-token status = %d, want 200", recRight.Code)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/api/... -run TestMetricsHandler -v`
Expected: FAIL — `h.WithMetricsToken undefined`

- [ ] **Step 3: Add the `metricsToken` field and `WithMetricsToken` wither**

In `orchestrator/internal/api/handlers.go`, add the field to the `Handler` struct (immediately after `cancelGracePeriod`):

```go
	cancelGracePeriod time.Duration
	// metricsToken, when non-empty, requires "Authorization: Bearer
	// <token>" on GET /metrics. Empty (the default) leaves it open --
	// same opt-in-by-default-off posture as BAS_DB_BREAKGLASS_PASSWORD
	// and API rate limiting.
	metricsToken string
}
```

Add the wither after `WithAgentSecret`:

```go
// WithMetricsToken configures the optional bearer token gating GET /metrics.
func (h *Handler) WithMetricsToken(token string) *Handler {
	h.metricsToken = token
	return h
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/api/... -run TestMetricsHandler -v`
Expected: PASS

- [ ] **Step 5: Wire `SetMetrics` into `WithJobsDispatcher`**

In `orchestrator/internal/api/job_dispatch.go`, update `WithJobsDispatcher`:

```go
func (h *Handler) WithJobsDispatcher(store *jobs.Store, dispatcher *jobs.Dispatcher) *Handler {
	h.jobsStore = store
	dispatcher.SetDispatch(h.dispatchJobTarget)
	dispatcher.SetStatus(h.statusForJobTarget)
	dispatcher.SetNotify(h.dispatchJobNotify)
	dispatcher.SetMetrics(h.dispatchJobMetrics)
	return h
}
```

- [ ] **Step 6: Replace `middleware.Logger` and add `/metrics` in `Mount()`**

In `orchestrator/internal/api/routes.go`, replace line 24:

```go
	r.Use(middleware.RealIP)
	r.Use(RequestLoggingMiddleware)
	r.Use(middleware.Recoverer)
	r.Use(middleware.StripSlashes)
	r.Use(LicenseGate)
```

And immediately after the `/ready` line added in Task 3:

```go
	r.Get("/ready", h.handleReady)

	// Metrics -- Prometheus text-exposition format. Top-level, so it
	// bypasses LicenseGate the same way /health and /ready do. Gated by
	// h.metricsToken when configured (see WithMetricsToken).
	r.Handle("/metrics", h.metricsHandler())
```

- [ ] **Step 7: Run the full `internal/api` suite**

Run: `cd orchestrator && go test ./internal/api/... -p 1`
Expected: PASS, including `license_gate_test.go`'s existing `Mount(...)` call site (unchanged signature) and no duplicate-logging regressions.

- [ ] **Step 8: Commit**

```bash
git add orchestrator/internal/api/handlers.go orchestrator/internal/api/job_dispatch.go orchestrator/internal/api/routes.go orchestrator/internal/api/observability_test.go
git commit -m "feat: add /metrics endpoint with optional bearer-token gating"
git push
```

---

### Task 5: SLA breach metrics

**Files:**
- Modify: `orchestrator/internal/api/sla_handlers.go`
- Modify: `orchestrator/internal/api/sla_handlers_test.go`

**Interfaces:**
- Consumes: `slaBreachEvaluationsTotal`, `slaBreachesTotal` (Task 2, same package).

- [ ] **Step 1: Write the failing test**

Extend `TestTickSLABreaches_MultipleFindingsBreachInSameTick` in `orchestrator/internal/api/sla_handlers_test.go` (add `testutil` import: `"github.com/prometheus/client_golang/prometheus/testutil"`):

```go
		evaluationsBefore := testutil.ToFloat64(slaBreachEvaluationsTotal)
		highBreachesBefore := testutil.ToFloat64(slaBreachesTotal.WithLabelValues("High"))

		if err := h.TickSLABreaches(context.Background()); err != nil {
			t.Fatalf("TickSLABreaches: %v", err)
		}

		if got := testutil.ToFloat64(slaBreachEvaluationsTotal); got != evaluationsBefore+1 {
			t.Errorf("slaBreachEvaluationsTotal delta = %v, want 1", got-evaluationsBefore)
		}
		// existing test seeds 2 High-severity overdue findings in this scenario --
		// see the existing seedFindingSLA calls above in this test.
		if got := testutil.ToFloat64(slaBreachesTotal.WithLabelValues("High")); got != highBreachesBefore+2 {
			t.Errorf("slaBreachesTotal{High} delta = %v, want 2", got-highBreachesBefore)
		}
```

(Confirmed by reading the existing test body: it seeds exactly two `"High"`-severity overdue `finding_slas` rows, `fs-multi1` and `fs-multi2`, both of which breach in this one tick -- hence the `+1` evaluations delta and `+2` `"High"` breaches delta above are exact, not estimates.)

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd orchestrator && go test ./internal/api/... -run TestTickSLABreaches_MultipleFindingsBreachInSameTick -v`
Expected: FAIL — counters never incremented (delta 0)

- [ ] **Step 3: Add the increments to `TickSLABreaches`**

In `orchestrator/internal/api/sla_handlers.go`:

```go
func (h *Handler) TickSLABreaches(ctx context.Context) error {
	slaBreachEvaluationsTotal.Inc()

	rows, err := h.db.Query(ctx,
		`SELECT fs.id, fs.deadline_at, pf.agent_id, pf.check_id, pf.title, pf.severity
		   FROM finding_slas fs
		   JOIN posture_findings pf ON pf.id = fs.posture_finding_id
		  WHERE fs.status = 'active' AND fs.deadline_at <= NOW()`)
	// ... unchanged ...
```

And inside the loop, immediately after the successful `UPDATE`'s `RowsAffected()` check:

```go
		tag, err := h.db.Exec(ctx,
			`UPDATE finding_slas SET status='breached', breached_at=NOW() WHERE id=$1 AND status='active'`, c.id)
		if err != nil || tag.RowsAffected() == 0 {
			continue // already handled (concurrent tick) or write failed -- next tick re-evaluates from the query above
		}
		slaBreachesTotal.WithLabelValues(c.severity).Inc()
		if h.notifications == nil {
			continue
		}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd orchestrator && go test ./internal/api/... -run TestTickSLABreaches_MultipleFindingsBreachInSameTick -v`
Expected: PASS

- [ ] **Step 5: Run the full SLA test set**

Run: `cd orchestrator && go test ./internal/api/... -run TestTickSLABreaches -v`
Expected: PASS (all existing SLA tick tests still pass)

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/api/sla_handlers.go orchestrator/internal/api/sla_handlers_test.go
git commit -m "feat: record sla_breach_evaluations_total and sla_breaches_total metrics"
git push
```

---

### Task 6: Config field, structured-logging bootstrap, main.go wiring

**Files:**
- Modify: `orchestrator/config/config.go`
- Modify: `orchestrator/cmd/server/main.go`

**Interfaces:**
- Consumes: `Handler.WithMetricsToken` (Task 4).

- [ ] **Step 1: Add `MetricsToken` to `Config`**

In `orchestrator/config/config.go`, add the field immediately before the struct's closing `}` (after `DNSSinkEnabled`):

```go
	// DNSSinkEnabled controls the DNS-tunneling exfiltration listener
	// (internal/dnssink). ...
	DNSSinkEnabled bool `json:"dns_sink_enabled,omitempty"`

	// MetricsToken, when set, requires "Authorization: Bearer <token>" on
	// GET /metrics. Empty (the default) leaves it open -- same opt-in
	// posture as DBBreakGlassPassword and RateLimitEnabled.
	MetricsToken string `json:"metrics_token,omitempty"`
}
```

Add the environment-variable override, mirroring `AGENT_SECRET`'s exact shape, immediately after the existing `DNS_SINK_ENABLED` block:

```go
	if v := os.Getenv("DNS_SINK_ENABLED"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			cfg.DNSSinkEnabled = b
		}
	}
	if v := os.Getenv("METRICS_TOKEN"); v != "" {
		cfg.MetricsToken = v
	}
```

- [ ] **Step 2: Verify the config package still builds and its existing tests pass**

Run: `cd orchestrator && go build ./config/... && go test ./config/... -v`
Expected: PASS (no existing config test references an exhaustive field list that this addition would break; if one does, extend it the same way the other optional fields are already covered)

- [ ] **Step 3: Bootstrap `slog` and wire `WithMetricsToken` in `main.go`**

In `orchestrator/cmd/server/main.go`, add `"log/slog"` to the import block (alphabetical, after `"log"`):

```go
	"log"
	"log/slog"
	"net/http"
```

Add the `slog` default handler immediately after the existing `log.SetFlags` line:

```go
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))
```

Add `.WithMetricsToken(cfg.MetricsToken)` to the handler chain (after `.WithAgentSecret(cfg.AgentSecret)`):

```go
		WithAgentSecret(cfg.AgentSecret).
		WithMetricsToken(cfg.MetricsToken).
		WithManifest(manifest).
```

- [ ] **Step 4: Verify the server builds**

Run: `cd orchestrator && go build ./...`
Expected: success, no errors

- [ ] **Step 5: Commit**

```bash
git add orchestrator/config/config.go orchestrator/cmd/server/main.go
git commit -m "feat: wire metrics_token config and slog bootstrap into main"
git push
```

---

### Task 7: Full-suite verification (no commit)

**Files:** none — verification only.

- [ ] **Step 1: Run the full backend test suite**

Run: `cd orchestrator && go build ./... && go vet ./... && go test ./... -p 2`
Expected: PASS across every package, no build or vet errors. `-p 2` matches this session's established concurrency cap for this host's ~7.8GB RAM.

- [ ] **Step 2: Confirm `/health` behavior is unchanged**

`TestHealthEndpoint_UnconditionalOK` (added in Task 3) already covers this and ran as part of Step 1's full suite. As a final confirmation, run it in isolation and re-read `routes.go`'s `/health` block to confirm it is byte-for-byte what it was before this plan (Task 3/4 only ever added lines after it, never edited it):

Run: `cd orchestrator && go test ./internal/api/... -run TestHealthEndpoint_UnconditionalOK -v`
Expected: PASS

- [ ] **Step 3: Report the exact metric/endpoint surface added**

Summarize for the user: the 7 custom metric names now exposed at `/metrics` (plus the auto-registered Go/process collectors), the `/ready` response shape, and confirmation that `/health` and `middleware.Logger`'s removal were verified, not assumed. State plainly that no live server was started this task — every verification above is `go build`/`go vet`/`go test` only, consistent with the "no server access" constraint given at the start of this sub-project. If the user later has server access, real `curl http://localhost:<port>/ready` and `/metrics` checks would be the natural follow-up, but that is explicitly out of scope for this task.

---

## Post-Plan: Update Memory

After Task 7 verification passes, update the two-file memory system:
- Add a new topic file `project_observability_foundation.md` under `C:\Users\Administrator\.claude\projects\C--Users-Administrator-Downloads-Audspect-Cloud\memory\` documenting: what was built (structured logging convention, `/ready`, `/metrics`, the `jobs.MetricsFn` hook pattern), the commits, and that it closes the "monitoring/observability" item of Platform Roadmap 2026H2 Phase 8 (leaving perf/load/pen testing, upgrade validation, and release documentation as the phase's remaining unscoped items).
- Update `project_platform_roadmap_2026h2.md` to reflect Phase 8's new status.
- Add one line to `MEMORY.md`'s index for the new topic file.
