package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
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

	// legacyListenerRequestsTotal counts requests that arrived on the
	// temporary plaintext legacy listener (:9000). Spec Section 4 step 4:
	// the B2 decision to retire that port is made on observed usage, so
	// this is kept separate from http_requests_total (whose label set is
	// unchanged) and can be read directly without filtering.
	legacyListenerRequestsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "legacy_listener_requests_total",
		Help: "Total HTTP requests received on the legacy plaintext listener, labeled by method, route, and status.",
	}, []string{"method", "route", "status"})
)

// WithLegacyListenerTag marks every request passing through it as having
// arrived on the legacy plaintext listener. It wraps the legacy server's
// handler only (cmd/server/main.go); RequestLoggingMiddleware, which runs
// inside the router and so already knows the matched route and final
// status, reads the mark and emits the distinct legacy log line and metric.
func WithLegacyListenerTag(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKeyLegacyListener, true)))
	})
}

func isLegacyListener(r *http.Request) bool {
	v, _ := r.Context().Value(ctxKeyLegacyListener).(bool)
	return v
}

// legacyProtocolRoutes is the exact, verified allowlist from
// docs/superpowers/specs/2026-09-30-b2-legacy-transport-retirement-design.md
// -- routes.go:79-97's agent-protocol block plus /ws/agent. Deliberately
// NOT "any 2xx on :9000": that listener's handler is the same full router
// every other listener uses (main.go), so it also serves /health,
// dashboard statics, and admin endpoints that say nothing about legacy
// agent dependency.
var legacyProtocolRoutes = map[string]bool{
	"/api/agents/enroll":                     true,
	"/api/agents/enroll-csr":                 true,
	"/api/agents/unenroll":                   true,
	"/api/agents/{agentId}/uninstall-result": true,
	"/api/agents/events":                     true,
	"/api/heartbeat":                         true,
	"/api/scenarios/result":                  true,
	"/api/scenarios/events":                  true,
	"/api/scenarios/runs/{runId}/detections": true,
	"/api/attackpath/collect":                true,
	"/api/attackpath/sharphound":             true,
	"/api/attackpath/jobs/{id}/ack":          true,
	"/ws/agent":                              true,
	"/api/agents/ping":                       true,
}

// legacyBodyAgentID is the minimal shape needed to opportunistically read
// an agent identity out of a legacy-protocol POST body without depending
// on any specific handler's own request struct -- this codebase's
// AgentID-carrying JSON structs overwhelmingly use one of these two key
// spellings.
type legacyBodyAgentID struct {
	AgentIDCamel string `json:"agentId"`
	AgentIDSnake string `json:"agent_id"`
}

// legacyBodyCaptureCap bounds how much of a legacy POST body this
// middleware ever holds in memory for attribution parsing. The :9000
// listener is unauthenticated by default (empty AGENT_SECRET), so an
// unbounded pre-read here would be a trivial OOM vector; 64 KiB is far
// more than any real agentId-carrying JSON payload needs.
const legacyBodyCaptureCap = 64 * 1024

// cappedCaptureWriter accumulates up to limit bytes and silently discards
// the rest, always reporting the full write as consumed -- used as the
// second destination of an io.TeeReader so it never errors or short-reads
// the real reader it's paired with.
type cappedCaptureWriter struct {
	buf   *bytes.Buffer
	limit int
}

func (w *cappedCaptureWriter) Write(p []byte) (int, error) {
	if w.buf.Len() < w.limit {
		remaining := w.limit - w.buf.Len()
		if remaining > len(p) {
			remaining = len(p)
		}
		w.buf.Write(p[:remaining])
	}
	return len(p), nil
}

// teeReadCloser pairs a TeeReader with the original body's Close, since
// io.TeeReader itself returns a plain io.Reader.
type teeReadCloser struct {
	io.Reader
	io.Closer
}

// RequestLoggingMiddleware replaces chi's default middleware.Logger
// (routes.go). One instrumentation point per completed request feeds both
// a structured slog line and the two HTTP metrics above -- and, as of B2,
// the legacy-transport-retirement evidence log for requests on the :9000
// listener. A *Handler method (not a bare function) specifically so it can
// reach h.recordLegacyUsage; routes.go's two r.Use call sites updated
// accordingly.
func (h *Handler) RequestLoggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)

		// Legacy POST bodies are captured here via a capped TeeReader, not a
		// full io.ReadAll -- the real handler downstream still reads the
		// complete, uncapped body exactly as it always did (this middleware
		// never buffers the whole thing itself), but at most
		// legacyBodyCaptureCap bytes of whatever the handler actually reads
		// are mirrored into legacyBodyBuf for attribution parsing below. A
		// body larger than the cap simply fails attribution (falls through
		// to the unattributed table) rather than being fully buffered in
		// memory -- the :9000 listener is unauthenticated by default, so an
		// unbounded pre-read here would be a trivial OOM vector.
		var legacyBodyBuf *bytes.Buffer
		if isLegacyListener(r) && r.Method == http.MethodPost && r.Body != nil {
			legacyBodyBuf = &bytes.Buffer{}
			r.Body = teeReadCloser{
				Reader: io.TeeReader(r.Body, &cappedCaptureWriter{buf: legacyBodyBuf, limit: legacyBodyCaptureCap}),
				Closer: r.Body,
			}
		}

		next.ServeHTTP(ww, r)

		var legacyBody []byte
		if legacyBodyBuf != nil {
			legacyBody = legacyBodyBuf.Bytes()
		}
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

		if isLegacyListener(r) {
			legacyListenerRequestsTotal.WithLabelValues(r.Method, route, strconv.Itoa(status)).Inc()
			slog.Info("legacy listener request",
				"component", "http",
				"listener", "legacy",
				"method", r.Method,
				"route", route,
				"status", status,
				"remote_addr", r.RemoteAddr,
				"agent_id", r.URL.Query().Get("agentId"),
			)

			if status >= 200 && status < 300 && legacyProtocolRoutes[route] {
				agentID := chi.URLParam(r, "agentId")
				if agentID == "" {
					agentID = r.URL.Query().Get("agentId")
				}
				if agentID == "" && len(legacyBody) > 0 {
					var parsed legacyBodyAgentID
					if json.Unmarshal(legacyBody, &parsed) == nil {
						if parsed.AgentIDCamel != "" {
							agentID = parsed.AgentIDCamel
						} else {
							agentID = parsed.AgentIDSnake
						}
					}
					// A json.Unmarshal error here is not itself logged/handled --
					// it just leaves agentID empty, which correctly routes this
					// request to the unattributed table below rather than being
					// dropped.
				}
				h.recordLegacyUsage(r.Context(), agentID, route, time.Now())
			}
		}
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
