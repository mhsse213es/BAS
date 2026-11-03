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

// otlpHTTPEndpoint checks an endpoint for the OTLP HTTP exporter. It must be a full http or https URL with a
// host. Port 4317 is the OTLP gRPC port, and this exporter speaks OTLP over HTTP, so 4317 is refused here rather
// than failing later at export time.
func otlpHTTPEndpoint(kind, endpoint string) (string, error) {
	if endpoint == "" {
		return "", fmt.Errorf("%s endpoint cannot be empty", kind)
	}
	u, err := url.Parse(endpoint)
	if err != nil {
		return "", fmt.Errorf("invalid %s endpoint URL: %w", kind, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("%s endpoint must start with http:// or https:// (OTLP over HTTP), got %q", kind, endpoint)
	}
	if u.Host == "" {
		return "", fmt.Errorf("%s endpoint has no host", kind)
	}
	if u.Port() == "4317" {
		return "", fmt.Errorf("%s endpoint uses port 4317, the OTLP gRPC port; use the OTLP HTTP port 4318", kind)
	}
	return endpoint, nil
}

// newOTLPHTTPExporter builds an OTLP HTTP span exporter. WithEndpointURL reads the scheme, so an http:// endpoint
// is sent without TLS and an https:// endpoint with it.
func newOTLPHTTPExporter(kind, endpoint string) (trace.SpanExporter, error) {
	ep, err := otlpHTTPEndpoint(kind, endpoint)
	if err != nil {
		return nil, err
	}
	exporter, err := otlptracehttp.New(context.Background(), otlptracehttp.WithEndpointURL(ep))
	if err != nil {
		return nil, fmt.Errorf("failed to create %s exporter: %w", kind, err)
	}
	return exporter, nil
}

// NewTempoExporter creates a span exporter for a self-hosted Grafana Tempo over OTLP HTTP.
// Endpoint is the Tempo OTLP HTTP receiver, for example http://tempo.internal:4318.
func NewTempoExporter(endpoint string) (trace.SpanExporter, error) {
	return newOTLPHTTPExporter("tempo", endpoint)
}

// NewJaegerExporter creates a span exporter for Jaeger over OTLP HTTP. Jaeger receives OTLP HTTP on port 4318.
// Endpoint is for example http://jaeger.internal:4318. Port 4317 is refused, because it is the gRPC port.
func NewJaegerExporter(endpoint string) (trace.SpanExporter, error) {
	return newOTLPHTTPExporter("jaeger", endpoint)
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
