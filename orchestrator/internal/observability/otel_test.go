package observability_test

import (
	"context"
	"testing"

	"github.com/audspect/bas/internal/observability"
	"go.opentelemetry.io/otel/attribute"
)

func TestNewTracerProvider(t *testing.T) {
	tp := observability.NewTracerProvider()
	if tp == nil {
		t.Fatalf("NewTracerProvider returned nil")
	}
}

func TestNewTracerProviderWithConfig(t *testing.T) {
	config := &observability.OTelConfig{
		Enabled: true,
		Exporters: observability.ExporterConfig{
			Console: true,
		},
	}
	tp := observability.NewTracerProviderWithConfig(config)
	if tp == nil {
		t.Fatalf("NewTracerProviderWithConfig returned nil")
	}
}

func TestTracerProviderShutdown(t *testing.T) {
	tp := observability.NewTracerProvider()
	err := tp.Shutdown(context.Background())
	if err != nil {
		t.Errorf("Shutdown failed: %v", err)
	}
}

func TestGetTracer(t *testing.T) {
	tp := observability.NewTracerProvider()
	defer tp.Shutdown(context.Background())

	tracer := tp.Tracer("test-tracer")
	if tracer == nil {
		t.Error("tracer should not be nil")
	}
}

func TestSpanCreation(t *testing.T) {
	tp := observability.NewTracerProvider()
	defer tp.Shutdown(context.Background())

	tracer := tp.Tracer("test")
	ctx, span := tracer.Start(context.Background(), "test-span")
	if span == nil {
		t.Error("span should not be nil")
	}
	span.End()

	if ctx == nil {
		t.Error("context should not be nil")
	}
}

func TestSpanWithAttributes(t *testing.T) {
	tp := observability.NewTracerProvider()
	defer tp.Shutdown(context.Background())

	tracer := tp.Tracer("test")
	ctx, span := tracer.Start(context.Background(), "test-span")
	defer span.End()

	// Add attributes (this should not panic)
	span.SetAttributes(
		attribute.String("run_id", "run-123"),
		attribute.String("task_id", "task-456"),
	)

	if ctx == nil {
		t.Error("context should not be nil")
	}
}

func TestOTelConfigDefaults(t *testing.T) {
	config := &observability.OTelConfig{}

	// Disabled by default
	if config.Enabled {
		t.Error("OTel should be disabled by default")
	}
}

func TestDisabledOTelNoExporter(t *testing.T) {
	config := &observability.OTelConfig{
		Enabled: false,
	}
	tp := observability.NewTracerProviderWithConfig(config)
	if tp == nil {
		t.Fatalf("NewTracerProviderWithConfig should not return nil even when disabled")
	}
	defer tp.Shutdown(context.Background())

	tracer := tp.Tracer("test")
	ctx, span := tracer.Start(context.Background(), "test-span")
	span.End()

	if ctx == nil {
		t.Error("context should not be nil")
	}
}

func TestConsoleExporterConfig(t *testing.T) {
	config := &observability.OTelConfig{
		Enabled: true,
		Exporters: observability.ExporterConfig{
			Console: true,
		},
	}
	tp := observability.NewTracerProviderWithConfig(config)
	if tp == nil {
		t.Fatalf("NewTracerProviderWithConfig returned nil")
	}
	defer tp.Shutdown(context.Background())
}

func TestProviderIsTracerProviderType(t *testing.T) {
	tp := observability.NewTracerProvider()
	defer tp.Shutdown(context.Background())

	// Verify it's a valid trace provider (can call methods)
	tracer := tp.Tracer("test")
	if tracer == nil {
		t.Error("Tracer() should return a valid tracer")
	}
}

func TestMultipleTracers(t *testing.T) {
	tp := observability.NewTracerProvider()
	defer tp.Shutdown(context.Background())

	tracer1 := tp.Tracer("tracer1")
	tracer2 := tp.Tracer("tracer2")

	if tracer1 == nil || tracer2 == nil {
		t.Error("both tracers should not be nil")
	}
}

func TestSpanStatusRecording(t *testing.T) {
	tp := observability.NewTracerProvider()
	defer tp.Shutdown(context.Background())

	tracer := tp.Tracer("test")
	ctx, span := tracer.Start(context.Background(), "test-span")
	defer span.End()

	// Record error (should not panic)
	span.RecordError(context.DeadlineExceeded)

	if ctx == nil {
		t.Error("context should not be nil")
	}
}
