package observability

import (
	"context"
	"fmt"
	"net/url"

	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/sdk/trace"
)

// NewPrometheusRemoteWriteExporter always returns a no-op exporter, by
// design, not as an unfinished stub: Prometheus remote-write is a
// metrics-ingestion protocol (a stream of timeseries samples), and
// trace.SpanExporter -- this function's return type -- exports trace
// spans. There is no shape of "Prometheus remote-write trace exporter" to
// implement; the two don't carry the same data.
//
// Real Prometheus metrics export already works today via the separate,
// MetricsToken-gated /metrics scrape endpoint (see metrics.go) -- which is
// also the more standard deployment shape for a self-hosted Prometheus
// against a single on-prem instance (it scrapes you; you don't push to it).
// If a push-based OTLP *metrics* exporter is ever wanted in addition to
// that, it needs the otlpmetrichttp exporter type and its own SDK metrics
// pipeline, not this function. Endpoint/URL validation is still performed
// so a misconfigured endpoint fails loudly instead of being silently
// accepted.
func NewPrometheusRemoteWriteExporter(endpoint string) (trace.SpanExporter, error) {
	if endpoint == "" {
		return nil, fmt.Errorf("prometheus remote-write endpoint cannot be empty")
	}

	// Validate URL
	if _, err := url.Parse(endpoint); err != nil {
		return nil, fmt.Errorf("invalid prometheus endpoint URL: %w", err)
	}

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
	exporter, err := otlptracehttp.New(context.Background(), otlptracehttp.WithEndpoint(endpoint))
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
	exporter, err := otlptracehttp.New(context.Background(), otlptracehttp.WithEndpoint(endpoint))
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
