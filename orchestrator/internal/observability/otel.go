package observability

import (
	"io"
	"log"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
	"go.opentelemetry.io/otel/sdk/resource"
	"go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.28.0"
)

// OTelConfig holds OpenTelemetry SDK configuration.
type OTelConfig struct {
	// Enabled controls whether tracing is active. If false, a no-op tracer is used.
	Enabled bool

	// Exporters specifies which exporters to wire up.
	Exporters ExporterConfig

	// ServiceName is the name of this service (used in resource attributes).
	ServiceName string

	// ServiceVersion is the semantic version of this service.
	ServiceVersion string
}

// ExporterConfig specifies which OpenTelemetry exporters to enable.
type ExporterConfig struct {
	// Console exports spans to stdout for development/testing.
	Console bool

	// TempoEndpoint exports traces to a Tempo OTLP HTTP receiver (e.g., http://localhost:4318).
	TempoEndpoint string

	// JaegerEndpoint exports traces to a Jaeger OTLP HTTP receiver (e.g., http://localhost:4318).
	JaegerEndpoint string
}

// NewTracerProvider creates a tracer provider with default (no-op) configuration.
// Use NewTracerProviderWithConfig for custom exporters.
func NewTracerProvider() *trace.TracerProvider {
	return NewTracerProviderWithConfig(&OTelConfig{Enabled: false})
}

// NewTracerProviderWithConfig creates a tracer provider with the given configuration.
// If config.Enabled is false, returns a no-op tracer provider.
// Otherwise wires up the configured exporters.
func NewTracerProviderWithConfig(config *OTelConfig) *trace.TracerProvider {
	if config == nil {
		config = &OTelConfig{Enabled: false}
	}

	// Create resource with service metadata
	r, err := resource.Merge(
		resource.Default(),
		resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceName(getServiceName(config)),
			semconv.ServiceVersion(getServiceVersion(config)),
		),
	)
	if err != nil {
		// Fallback to default resource on error
		r = resource.Default()
	}

	// If disabled, return a no-op tracer provider
	if !config.Enabled {
		return trace.NewTracerProvider(
			trace.WithResource(r),
		)
	}

	// Build the list of span exporters based on config
	var exporters []trace.SpanExporter

	// Console exporter for development
	if config.Exporters.Console {
		exporter, err := stdouttrace.New(stdouttrace.WithWriter(io.Discard))
		if err == nil {
			exporters = append(exporters, exporter)
		}
	}

	// An exporter that cannot be built is logged and skipped rather than
	// stopping the server: tracing is optional.
	if config.Exporters.TempoEndpoint != "" {
		if exp, err := NewTempoExporter(config.Exporters.TempoEndpoint); err != nil {
			log.Printf("[observability] tempo exporter disabled: %v", err)
		} else {
			exporters = append(exporters, exp)
		}
	}
	if config.Exporters.JaegerEndpoint != "" {
		if exp, err := NewJaegerExporter(config.Exporters.JaegerEndpoint); err != nil {
			log.Printf("[observability] jaeger exporter disabled: %v", err)
		} else {
			exporters = append(exporters, exp)
		}
	}

	// Create tracer provider with exporters
	var opts []trace.TracerProviderOption
	opts = append(opts, trace.WithResource(r))

	// Add span processors for each exporter
	for _, exporter := range exporters {
		opts = append(opts, trace.WithBatcher(exporter))
	}

	// Create and return the tracer provider
	tp := trace.NewTracerProvider(opts...)

	// Set as global tracer provider
	otel.SetTracerProvider(tp)

	return tp
}

// getServiceName returns the configured service name or a default.
func getServiceName(config *OTelConfig) string {
	if config != nil && config.ServiceName != "" {
		return config.ServiceName
	}
	return "audspect-orchestrator"
}

// getServiceVersion returns the configured service version or a default.
func getServiceVersion(config *OTelConfig) string {
	if config != nil && config.ServiceVersion != "" {
		return config.ServiceVersion
	}
	return "unknown"
}
