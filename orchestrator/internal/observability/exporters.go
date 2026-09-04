package observability

import (
	"context"
	"fmt"
	"net/url"

	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/sdk/trace"
)

// NewPrometheusRemoteWriteExporter creates a span exporter for Prometheus remote-write API.
// Endpoint should be the full URL to the remote-write endpoint (e.g., http://prometheus:9009/api/v1/write).
// Note: This returns a trace exporter stub for now. Full Prometheus metrics export is handled
// separately via the metrics registry (Task 3).
func NewPrometheusRemoteWriteExporter(endpoint string) (trace.SpanExporter, error) {
	if endpoint == "" {
		return nil, fmt.Errorf("prometheus remote-write endpoint cannot be empty")
	}

	// Validate URL
	if _, err := url.Parse(endpoint); err != nil {
		return nil, fmt.Errorf("invalid prometheus endpoint URL: %w", err)
	}

	// TODO: Implement actual Prometheus remote-write exporter in a future phase.
	// For now, return a no-op exporter to satisfy the interface.
	// This allows the configuration to be wired without blocking on Prometheus integration.
	return newNoOpExporter(), nil
}

// NewTempoExporter creates a span exporter for Grafana Tempo via OTLP HTTP.
// Endpoint should be the Tempo OTLP HTTP receiver (e.g., http://localhost:4318).
func NewTempoExporter(endpoint string) (trace.SpanExporter, error) {
	if endpoint == "" {
		return nil, fmt.Errorf("tempo endpoint cannot be empty")
	}

	// Validate URL
	if _, err := url.Parse(endpoint); err != nil {
		return nil, fmt.Errorf("invalid tempo endpoint URL: %w", err)
	}

	// Create OTLP HTTP trace exporter
	exporter, err := otlptracehttp.New(nil, otlptracehttp.WithEndpoint(endpoint))
	if err != nil {
		return nil, fmt.Errorf("failed to create tempo exporter: %w", err)
	}

	return exporter, nil
}

// NewJaegerExporter creates a span exporter for Jaeger via OTLP HTTP.
// Endpoint should be the Jaeger OTLP HTTP receiver (e.g., http://localhost:4317).
func NewJaegerExporter(endpoint string) (trace.SpanExporter, error) {
	if endpoint == "" {
		return nil, fmt.Errorf("jaeger endpoint cannot be empty")
	}

	// Validate URL
	if _, err := url.Parse(endpoint); err != nil {
		return nil, fmt.Errorf("invalid jaeger endpoint URL: %w", err)
	}

	// Create OTLP HTTP trace exporter (Jaeger also supports OTLP)
	exporter, err := otlptracehttp.New(nil, otlptracehttp.WithEndpoint(endpoint))
	if err != nil {
		return nil, fmt.Errorf("failed to create jaeger exporter: %w", err)
	}

	return exporter, nil
}

// noOpExporter is a placeholder span exporter that does nothing.
// Used for exporters that are not yet fully implemented but need to satisfy the interface.
type noOpExporter struct{}

// ExportSpans implements the SpanExporter interface (no-op).
func (e *noOpExporter) ExportSpans(ctx context.Context, spans []trace.ReadOnlySpan) error {
	return nil
}

// Shutdown implements the SpanExporter interface (no-op).
func (e *noOpExporter) Shutdown(ctx context.Context) error {
	return nil
}

// newNoOpExporter creates a new no-op exporter.
func newNoOpExporter() trace.SpanExporter {
	return &noOpExporter{}
}
