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

// Version is set once at startup (cmd/server/main.go) from the build-time
// Version var, so /ready can report the running build's actual version to
// the frontend instead of a hardcoded string. "dev" for unpackaged builds.
var Version = "dev"

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
			"status":  "not_ready",
			"version": Version,
			"checks":  map[string]string{"database": err.Error()},
		})
		return
	}
	dbReady.Set(1)
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]any{
		"status":  "ready",
		"version": Version,
		"checks":  map[string]string{"database": "ok"},
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
