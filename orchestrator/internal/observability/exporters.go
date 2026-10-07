package observability

import (
	"context"
	"fmt"
	"net/url"

	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/sdk/trace"
)

// otlpTracesURL turns an OTLP/HTTP base URL into the traces endpoint. A bare
// base (http://tempo:4318) gets the OTLP path /v1/traces; an explicit path is
// kept as given.
func otlpTracesURL(endpoint string) (string, error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return "", err
	}
	if u.Path == "" || u.Path == "/" {
		u.Path = "/v1/traces"
	}
	return u.String(), nil
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
	tracesURL, err := otlpTracesURL(endpoint)
	if err != nil {
		return nil, fmt.Errorf("invalid tempo endpoint URL: %w", err)
	}
	exporter, err := otlptracehttp.New(context.Background(), otlptracehttp.WithEndpointURL(tracesURL))
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
	tracesURL, err := otlpTracesURL(endpoint)
	if err != nil {
		return nil, fmt.Errorf("invalid tempo endpoint URL: %w", err)
	}
	exporter, err := otlptracehttp.New(context.Background(), otlptracehttp.WithEndpointURL(tracesURL))
	if err != nil {
		return nil, fmt.Errorf("failed to create jaeger exporter: %w", err)
	}

	return exporter, nil
}
