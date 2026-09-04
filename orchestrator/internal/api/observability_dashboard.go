package api

import (
	"encoding/json"
	"net/http"
	"time"
)

// ObservabilitySummary is the response payload for /api/observability/summary.
// It provides a snapshot of platform health, execution metrics, and recent run details.
type ObservabilitySummary struct {
	// Timestamp is the server time when this snapshot was taken (RFC3339 format).
	Timestamp string `json:"timestamp"`

	// SchedulerHealth contains scheduler polling and task queue metrics.
	SchedulerHealth *SchedulerHealthMetrics `json:"scheduler_health"`

	// ExecutionMetrics contains aggregate run counts and status breakdown.
	ExecutionMetrics *ExecutionMetrics `json:"execution_metrics"`

	// RecentRuns is a list of the N most recent runs (sorted by start time, newest first).
	RecentRuns []RunSummary `json:"recent_runs"`

	// PlatformStatus is an overall health indicator: "healthy", "degraded", "unhealthy".
	PlatformStatus string `json:"platform_status"`
}

// SchedulerHealthMetrics describes scheduler loop and queue health.
type SchedulerHealthMetrics struct {
	// TicksPerSecond is the observed scheduler polling frequency (should be ~1 tick/sec by default).
	TicksPerSecond float64 `json:"ticks_per_second"`

	// ActiveTasks is the count of non-terminal tasks in the DAG right now.
	ActiveTasks int64 `json:"active_tasks"`

	// QueueDepth is the count of tasks waiting in the job queue.
	QueueDepth int64 `json:"queue_depth"`

	// AverageDispatchLatency is the mean time from dispatch to agent execution start (in seconds).
	AverageDispatchLatency float64 `json:"average_dispatch_latency_seconds"`
}

// ExecutionMetrics tracks run counts and outcomes.
type ExecutionMetrics struct {
	// TotalRuns is the total count of all runs ever started.
	TotalRuns int64 `json:"total_runs"`

	// RunningRuns is the count of currently executing runs.
	RunningRuns int64 `json:"running_runs"`

	// CompletedRuns is the count of runs that reached terminal state (passed all checks).
	CompletedRuns int64 `json:"completed_runs"`

	// FailedRuns is the count of runs that failed or were cancelled.
	FailedRuns int64 `json:"failed_runs"`

	// PartialRuns is the count of runs stopped early (but with some results).
	PartialRuns int64 `json:"partial_runs"`

	// AverageDuration is the mean execution time for completed/partial runs (in seconds).
	AverageDuration float64 `json:"average_duration_seconds"`
}

// RunSummary is a brief summary of a single run for drill-down.
type RunSummary struct {
	// ID is the run UUID.
	ID string `json:"id"`

	// Name is the scenario name or user-provided run name.
	Name string `json:"name"`

	// Status is one of: running, completed, partial, failed.
	Status string `json:"status"`

	// StartedAt is the run start time (RFC3339 format).
	StartedAt string `json:"started_at"`

	// CompletedAt is the run end time (RFC3339 format, empty if still running).
	CompletedAt string `json:"completed_at,omitempty"`

	// DurationSeconds is the execution time in seconds.
	DurationSeconds float64 `json:"duration_seconds"`

	// AgentID is the agent that executed this run.
	AgentID string `json:"agent_id,omitempty"`

	// StepsPassed is the count of passed steps.
	StepsPassed int `json:"steps_passed,omitempty"`

	// StepsFailed is the count of failed steps.
	StepsFailed int `json:"steps_failed,omitempty"`

	// ErrorMessage is set if the run failed (dispatch error, agent crash, etc.).
	ErrorMessage string `json:"error_message,omitempty"`
}

// HandleObservabilitySummary serves the /api/observability/summary endpoint.
// Returns a JSON snapshot of platform health and recent run activity.
func HandleObservabilitySummary(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Build the summary (placeholder data for now; in real implementation,
	// this would query the database and metrics registry)
	summary := &ObservabilitySummary{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		SchedulerHealth: &SchedulerHealthMetrics{
			TicksPerSecond:         1.0,
			ActiveTasks:            0,
			QueueDepth:             0,
			AverageDispatchLatency: 0.050,
		},
		ExecutionMetrics: &ExecutionMetrics{
			TotalRuns:       0,
			RunningRuns:     0,
			CompletedRuns:   0,
			FailedRuns:      0,
			PartialRuns:     0,
			AverageDuration: 0.0,
		},
		RecentRuns:    []RunSummary{},
		PlatformStatus: "healthy",
	}

	// Encode response as JSON
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(summary)
}
