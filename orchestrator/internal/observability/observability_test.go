package observability_test

import (
	"context"
	"io"
	"log/slog"
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

func TestWithTaskID(t *testing.T) {
	ctx := context.Background()
	ctx = observability.WithTaskID(ctx, "task-456")

	_, task, _, _ := observability.GetCorrelationIDs(ctx)
	if task != "task-456" {
		t.Errorf("expected task-456, got %s", task)
	}
}

func TestWithAttemptID(t *testing.T) {
	ctx := context.Background()
	ctx = observability.WithAttemptID(ctx, "attempt-789")

	_, _, attempt, _ := observability.GetCorrelationIDs(ctx)
	if attempt != "attempt-789" {
		t.Errorf("expected attempt-789, got %s", attempt)
	}
}

func TestWithAgentID(t *testing.T) {
	ctx := context.Background()
	ctx = observability.WithAgentID(ctx, "agent-abc")

	_, _, _, agent := observability.GetCorrelationIDs(ctx)
	if agent != "agent-abc" {
		t.Errorf("expected agent-abc, got %s", agent)
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

func TestIDsAreIndependent(t *testing.T) {
	ctx := context.Background()
	ctx = observability.WithRunID(ctx, "run-1")
	ctx = observability.WithTaskID(ctx, "task-1")

	run, task, _, _ := observability.GetCorrelationIDs(ctx)
	if run != "run-1" || task != "task-1" {
		t.Errorf("expected run-1 and task-1, got run=%s task=%s", run, task)
	}

	// Getting IDs on empty context should return empty strings
	emptyCtx := context.Background()
	run2, task2, attempt2, agent2 := observability.GetCorrelationIDs(emptyCtx)
	if run2 != "" || task2 != "" || attempt2 != "" || agent2 != "" {
		t.Errorf("expected all empty strings on empty context, got run=%s task=%s attempt=%s agent=%s", run2, task2, attempt2, agent2)
	}
}

func TestCorrelationLogger(t *testing.T) {
	ctx := context.Background()
	ctx = observability.WithRunID(ctx, "run-123")
	ctx = observability.WithTaskID(ctx, "task-456")
	ctx = observability.WithAttemptID(ctx, "attempt-789")

	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	corrLogger := observability.CorrelationLogger(ctx, logger)

	if corrLogger == nil {
		t.Errorf("CorrelationLogger should not return nil")
	}
}

func TestCorrelationLoggerWithoutIDs(t *testing.T) {
	ctx := context.Background()
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	corrLogger := observability.CorrelationLogger(ctx, logger)

	if corrLogger == nil {
		t.Errorf("CorrelationLogger should not return nil even with empty context")
	}
}
