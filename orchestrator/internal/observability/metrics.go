package observability

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// MetricsRegistry holds all P0 observability metrics.
// All metrics use bounded-cardinality labels: step_type, agent_pool, error_code, etc.
// Never use per-entity IDs (run_id, task_id, agent_id) as labels.
type MetricsRegistry struct {
	// TaskQueueWaitDuration measures time from Pending → Queued state transition.
	// Labels: task_type (bounded: "agent_task", "wait", "approval", "webhook", etc.)
	TaskQueueWaitDuration *prometheus.HistogramVec

	// SchedulerTickDuration measures time per scheduler poll iteration.
	SchedulerTickDuration prometheus.Histogram

	// ExecutionDuration measures time from step start → terminal state.
	// Labels: step_type (bounded: "agent_task", "wait", "approval", "webhook", etc.)
	ExecutionDuration *prometheus.HistogramVec

	// AgentDispatchLatency measures time from dispatch call → agent execution start.
	// Labels: agent_pool (bounded: pool name from config, e.g. "default", "high-privilege")
	AgentDispatchLatency *prometheus.HistogramVec

	// ExecutionErrors counts execution errors by step type and error code.
	// Labels: step_type, error_code (both bounded)
	ExecutionErrors *prometheus.CounterVec

	// AgentAvailable tracks count of ready agents per pool (gauge, sampled per scheduler tick).
	// Labels: agent_pool (bounded)
	AgentAvailable *prometheus.GaugeVec

	// CollectorRegistry is the underlying Prometheus registry these metrics use.
	// Exposed for testing and to support Gather().
	CollectorRegistry prometheus.Registerer
}

// NewMetricsRegistry creates and registers all P0 metrics with the default Prometheus registerer.
// Returns a ready-to-use registry; metrics are immediately observable.
func NewMetricsRegistry() *MetricsRegistry {
	return NewMetricsRegistryWithRegisterer(prometheus.DefaultRegisterer)
}

// NewMetricsRegistryWithRegisterer creates metrics with a custom Prometheus registerer
// (useful for testing to avoid global state pollution).
func NewMetricsRegistryWithRegisterer(reg prometheus.Registerer) *MetricsRegistry {
	return &MetricsRegistry{
		TaskQueueWaitDuration: promauto.With(reg).NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "task_queue_wait_duration_seconds",
				Help:    "Time from task Pending to Queued state, labeled by task type.",
				Buckets: prometheus.DefBuckets,
			},
			[]string{"task_type"},
		),
		SchedulerTickDuration: promauto.With(reg).NewHistogram(
			prometheus.HistogramOpts{
				Name:    "scheduler_tick_duration_seconds",
				Help:    "Time per scheduler polling iteration.",
				Buckets: prometheus.DefBuckets,
			},
		),
		ExecutionDuration: promauto.With(reg).NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "execution_duration_seconds",
				Help:    "Time from step start to step terminal state, labeled by step type.",
				Buckets: prometheus.DefBuckets,
			},
			[]string{"step_type"},
		),
		AgentDispatchLatency: promauto.With(reg).NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "agent_dispatch_latency_seconds",
				Help:    "Time from dispatch call to agent execution start, labeled by agent pool.",
				Buckets: prometheus.DefBuckets,
			},
			[]string{"agent_pool"},
		),
		ExecutionErrors: promauto.With(reg).NewCounterVec(
			prometheus.CounterOpts{
				Name: "execution_errors_total",
				Help: "Total execution errors, labeled by step type and error code.",
			},
			[]string{"step_type", "error_code"},
		),
		AgentAvailable: promauto.With(reg).NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "agent_available",
				Help: "Number of available agents ready to receive tasks, labeled by agent pool.",
			},
			[]string{"agent_pool"},
		),
		CollectorRegistry: reg,
	}
}

// Gather collects all metrics in the registry (Prometheus compatibility method).
// Useful for testing and metrics export.
func (m *MetricsRegistry) Gather() (interface{}, error) {
	if gatherer, ok := m.CollectorRegistry.(prometheus.Gatherer); ok {
		return gatherer.Gather()
	}
	// If registerer is not also a gatherer, return empty (this shouldn't happen in practice)
	return nil, nil
}
