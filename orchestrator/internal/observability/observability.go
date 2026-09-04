package observability

import (
	"context"
	"log/slog"
)

// correlationIDKey is the context key for correlation IDs.
type correlationIDKey struct{}

// CorrelationIDs holds the four-level ID hierarchy flowing through execution.
type CorrelationIDs struct {
	RunID     string
	TaskID    string
	AttemptID string
	AgentID   string
}

// WithRunID returns a new context with the run ID set.
func WithRunID(ctx context.Context, id string) context.Context {
	ids := getOrCreateIDs(ctx)
	ids.RunID = id
	return context.WithValue(ctx, correlationIDKey{}, ids)
}

// WithTaskID returns a new context with the task ID set.
func WithTaskID(ctx context.Context, id string) context.Context {
	ids := getOrCreateIDs(ctx)
	ids.TaskID = id
	return context.WithValue(ctx, correlationIDKey{}, ids)
}

// WithAttemptID returns a new context with the attempt ID set.
func WithAttemptID(ctx context.Context, id string) context.Context {
	ids := getOrCreateIDs(ctx)
	ids.AttemptID = id
	return context.WithValue(ctx, correlationIDKey{}, ids)
}

// WithAgentID returns a new context with the agent ID set.
func WithAgentID(ctx context.Context, id string) context.Context {
	ids := getOrCreateIDs(ctx)
	ids.AgentID = id
	return context.WithValue(ctx, correlationIDKey{}, ids)
}

// GetCorrelationIDs retrieves all four correlation IDs from the context.
// Returns empty strings for any IDs not yet set.
func GetCorrelationIDs(ctx context.Context) (run, task, attempt, agent string) {
	ids := getOrCreateIDs(ctx)
	return ids.RunID, ids.TaskID, ids.AttemptID, ids.AgentID
}

// getOrCreateIDs retrieves the CorrelationIDs from context or creates a new one.
func getOrCreateIDs(ctx context.Context) *CorrelationIDs {
	if ids, ok := ctx.Value(correlationIDKey{}).(*CorrelationIDs); ok {
		return ids
	}
	return &CorrelationIDs{}
}

// CorrelationLogger wraps an slog.Logger to automatically add correlation IDs to every log line.
// If any correlation IDs are set in the context, they are added as attributes.
func CorrelationLogger(ctx context.Context, logger *slog.Logger) *slog.Logger {
	run, task, attempt, agent := GetCorrelationIDs(ctx)
	attrs := []any{}
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
