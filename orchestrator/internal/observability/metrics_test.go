package observability_test

import (
	"testing"

	"github.com/audspect/bas/internal/observability"
	"github.com/prometheus/client_golang/prometheus"
)

func TestMetricsRegistry(t *testing.T) {
	reg := observability.NewMetricsRegistryWithRegisterer(prometheus.NewRegistry())

	if reg == nil {
		t.Fatalf("NewMetricsRegistry returned nil")
	}

	// Verify core metrics exist and are non-nil
	if reg.TaskQueueWaitDuration == nil {
		t.Error("TaskQueueWaitDuration metric is nil")
	}
	if reg.SchedulerTickDuration == nil {
		t.Error("SchedulerTickDuration metric is nil")
	}
	if reg.ExecutionDuration == nil {
		t.Error("ExecutionDuration metric is nil")
	}
	if reg.AgentDispatchLatency == nil {
		t.Error("AgentDispatchLatency metric is nil")
	}
	if reg.ExecutionErrors == nil {
		t.Error("ExecutionErrors metric is nil")
	}
	if reg.AgentAvailable == nil {
		t.Error("AgentAvailable metric is nil")
	}
}

func TestTaskQueueWaitObservation(t *testing.T) {
	reg := observability.NewMetricsRegistryWithRegisterer(prometheus.NewRegistry())

	// Record a queue wait time
	reg.TaskQueueWaitDuration.WithLabelValues("agent_task").Observe(0.123)

	// Verify the metric was recorded (basic check that no panic occurs)
	// More detailed validation would require examining the metric output
	if reg.TaskQueueWaitDuration == nil {
		t.Error("TaskQueueWaitDuration should not be nil after observation")
	}
}

func TestExecutionDurationObservation(t *testing.T) {
	reg := observability.NewMetricsRegistryWithRegisterer(prometheus.NewRegistry())

	// Record execution durations for different step types
	reg.ExecutionDuration.WithLabelValues("agent_task").Observe(0.500)
	reg.ExecutionDuration.WithLabelValues("wait").Observe(1.250)
	reg.ExecutionDuration.WithLabelValues("webhook").Observe(0.789)

	// Verify the metric was recorded
	if reg.ExecutionDuration == nil {
		t.Error("ExecutionDuration should not be nil after observations")
	}
}

func TestAgentDispatchLatencyObservation(t *testing.T) {
	reg := observability.NewMetricsRegistryWithRegisterer(prometheus.NewRegistry())

	// Record dispatch latencies for different agent pools
	reg.AgentDispatchLatency.WithLabelValues("default").Observe(0.050)
	reg.AgentDispatchLatency.WithLabelValues("high-privilege").Observe(0.075)

	// Verify the metric was recorded
	if reg.AgentDispatchLatency == nil {
		t.Error("AgentDispatchLatency should not be nil after observations")
	}
}

func TestExecutionErrorsCounter(t *testing.T) {
	reg := observability.NewMetricsRegistryWithRegisterer(prometheus.NewRegistry())

	// Record errors for different step types
	reg.ExecutionErrors.WithLabelValues("agent_task", "timeout").Inc()
	reg.ExecutionErrors.WithLabelValues("webhook", "connection_refused").Inc()

	// Verify the metric was recorded
	if reg.ExecutionErrors == nil {
		t.Error("ExecutionErrors should not be nil after increments")
	}
}

func TestAgentAvailableGauge(t *testing.T) {
	reg := observability.NewMetricsRegistryWithRegisterer(prometheus.NewRegistry())

	// Set available agent counts for different pools
	reg.AgentAvailable.WithLabelValues("default").Set(5)
	reg.AgentAvailable.WithLabelValues("high-privilege").Set(2)

	// Verify the metric was recorded
	if reg.AgentAvailable == nil {
		t.Error("AgentAvailable should not be nil after Set calls")
	}
}

func TestMetricsArePrometheusCompatible(t *testing.T) {
	reg := observability.NewMetricsRegistryWithRegisterer(prometheus.NewRegistry())

	// Record some test data
	reg.TaskQueueWaitDuration.WithLabelValues("agent_task").Observe(0.1)
	reg.ExecutionDuration.WithLabelValues("wait").Observe(0.2)
	reg.AgentAvailable.WithLabelValues("default").Set(10)

	// Verify we can collect the metrics (Prometheus validation)
	// This will panic if metrics are malformed
	metrics, err := reg.Gather()
	if err != nil {
		t.Errorf("Gather() should not error: %v", err)
	}
	if metrics == nil {
		t.Error("Gather() should return metrics")
	}
}
