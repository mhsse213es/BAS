package observability

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// CloudMetrics measures cloud discovery, preflight, probes and refusals.
//
// Label values are bounded so the series count cannot grow with the estate:
//   - provider: "aws", "azure", "gcp".
//   - outcome: "ok", "failed".
//   - object_kind: "identity", "permission", or a resource kind from the code's
//     fixed vocabulary (for example "s3-bucket"). Never a resource name.
//   - category: a fixed set; see the cloud failure classifier in the API layer.
//   - check: a preflight check name with any ":<canonical>" suffix removed.
//   - operation and outcome for probes: the fixed probe registry and outcomes.
//   - reason: "allow-list", "busy", "saturated".
//
// Account IDs, identity IDs and resource names are never labels. They belong
// in audit records and structured logs.
type CloudMetrics struct {
	DiscoveryPassDuration *prometheus.HistogramVec // provider, outcome
	DiscoveryObjects      *prometheus.CounterVec   // provider, object_kind
	DiscoveryFailures     *prometheus.CounterVec   // provider, category
	PreflightFailures     *prometheus.CounterVec   // provider, check
	ProbeOutcomes         *prometheus.CounterVec   // provider, operation, outcome
	RateLimitWait         *prometheus.HistogramVec // provider
	Refusals              *prometheus.CounterVec   // reason
}

// NewDefaultCloudMetrics registers the cloud metrics with the default Prometheus
// registerer, the one the server's /metrics endpoint serves. Call it once.
func NewDefaultCloudMetrics() *CloudMetrics {
	return NewCloudMetrics(prometheus.DefaultRegisterer)
}

// NewCloudMetrics registers the cloud metrics with reg. Register once per registerer.
func NewCloudMetrics(reg prometheus.Registerer) *CloudMetrics {
	return &CloudMetrics{
		DiscoveryPassDuration: promauto.With(reg).NewHistogramVec(prometheus.HistogramOpts{
			Name:    "cloud_discovery_pass_duration_seconds",
			Help:    "Duration of one cloud discovery pass, by provider and outcome.",
			Buckets: prometheus.ExponentialBuckets(1, 2, 12),
		}, []string{"provider", "outcome"}),
		DiscoveryObjects: promauto.With(reg).NewCounterVec(prometheus.CounterOpts{
			Name: "cloud_discovery_objects_total",
			Help: "Objects found by cloud discovery, by provider and object kind.",
		}, []string{"provider", "object_kind"}),
		DiscoveryFailures: promauto.With(reg).NewCounterVec(prometheus.CounterOpts{
			Name: "cloud_discovery_failures_total",
			Help: "Failed cloud discovery passes, by provider and failure category.",
		}, []string{"provider", "category"}),
		PreflightFailures: promauto.With(reg).NewCounterVec(prometheus.CounterOpts{
			Name: "cloud_preflight_failures_total",
			Help: "Failed preflight checks, by provider and check name.",
		}, []string{"provider", "check"}),
		ProbeOutcomes: promauto.With(reg).NewCounterVec(prometheus.CounterOpts{
			Name: "cloud_probe_outcomes_total",
			Help: "Read-only probe outcomes, by provider, operation and outcome.",
		}, []string{"provider", "operation", "outcome"}),
		RateLimitWait: promauto.With(reg).NewHistogramVec(prometheus.HistogramOpts{
			Name:    "cloud_rate_limit_wait_seconds",
			Help:    "Rate-limiter delays imposed on cloud API calls. The count is the number of waits.",
			Buckets: prometheus.ExponentialBuckets(0.005, 2, 12),
		}, []string{"provider"}),
		Refusals: promauto.With(reg).NewCounterVec(prometheus.CounterOpts{
			Name: "cloud_request_refusals_total",
			Help: "Cloud requests refused before any provider call, by reason.",
		}, []string{"reason"}),
	}
}
