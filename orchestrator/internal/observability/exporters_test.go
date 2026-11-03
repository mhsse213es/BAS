package observability

import (
	"strings"
	"testing"

	"go.opentelemetry.io/otel/sdk/trace"
)

func TestNewTempoExporter_EmptyEndpoint_ReturnsError(t *testing.T) {
	if _, err := NewTempoExporter(""); err == nil {
		t.Fatal("expected an error for an empty endpoint")
	}
}

func TestNewTempoExporter_InvalidURL_ReturnsError(t *testing.T) {
	if _, err := NewTempoExporter("://not a url"); err == nil {
		t.Fatal("expected an error for an invalid URL")
	}
}

func TestNewTempoExporter_ValidEndpoint_ReturnsRealExporter(t *testing.T) {
	// otlptracehttp.New is lazy -- it doesn't dial until the first export, so
	// construction succeeds even against an endpoint nothing is listening
	// on. This locks in that NewTempoExporter returns the real OTLP
	// exporter (not the no-op stub Prometheus's path returns).
	exp, err := NewTempoExporter("http://localhost:4318")
	if err != nil {
		t.Fatalf("NewTempoExporter: %v", err)
	}
	if exp == nil {
		t.Fatal("expected a non-nil exporter")
	}
	if _, ok := exp.(*noOpExporter); ok {
		t.Fatal("NewTempoExporter must return a real OTLP exporter, not the no-op stub")
	}
}

func TestNewJaegerExporter_EmptyEndpoint_ReturnsError(t *testing.T) {
	if _, err := NewJaegerExporter(""); err == nil {
		t.Fatal("expected an error for an empty endpoint")
	}
}

func TestNewJaegerExporter_InvalidURL_ReturnsError(t *testing.T) {
	if _, err := NewJaegerExporter("://not a url"); err == nil {
		t.Fatal("expected an error for an invalid URL")
	}
}

func TestNewJaegerExporter_ValidEndpoint_ReturnsRealExporter(t *testing.T) {
	exp, err := NewJaegerExporter("http://localhost:4318")
	if err != nil {
		t.Fatalf("NewJaegerExporter: %v", err)
	}
	if exp == nil {
		t.Fatal("expected a non-nil exporter")
	}
	if _, ok := exp.(*noOpExporter); ok {
		t.Fatal("NewJaegerExporter must return a real OTLP exporter, not the no-op stub")
	}
}

func TestNewPrometheusRemoteWriteExporter_EmptyEndpoint_ReturnsError(t *testing.T) {
	if _, err := NewPrometheusRemoteWriteExporter(""); err == nil {
		t.Fatal("expected an error for an empty endpoint")
	}
}

func TestNewPrometheusRemoteWriteExporter_InvalidURL_ReturnsError(t *testing.T) {
	if _, err := NewPrometheusRemoteWriteExporter("://not a url"); err == nil {
		t.Fatal("expected an error for an invalid URL")
	}
}

// TestNewPrometheusRemoteWriteExporter_IsDeliberatelyANoOp locks in, rather
// than hides, the reason this one stays a stub: Prometheus remote-write is
// a metrics-ingestion protocol (a stream of timeseries samples) and cannot
// carry trace spans at all -- trace.SpanExporter is the wrong interface for
// it, which is why this was never implementable as written. Real Prometheus
// metrics export already happens via the working, MetricsToken-gated
// /metrics scrape endpoint (see metrics.go); a push-based OTLP *metrics*
// exporter, if ever wanted in addition to that, needs the otlpmetrichttp
// exporter type, not this function.
func TestNewPrometheusRemoteWriteExporter_IsDeliberatelyANoOp(t *testing.T) {
	exp, err := NewPrometheusRemoteWriteExporter("http://prometheus:9009/api/v1/write")
	if err != nil {
		t.Fatalf("NewPrometheusRemoteWriteExporter: %v", err)
	}
	if _, ok := exp.(*noOpExporter); !ok {
		t.Fatal("expected the no-op stub -- see the doc comment on NewPrometheusRemoteWriteExporter for why")
	}
}

// An endpoint without a scheme is refused: the exporter needs to know whether to use TLS.
func TestOTLPExporters_SchemeRequired(t *testing.T) {
	for name, ctor := range map[string]func(string) (trace.SpanExporter, error){
		"tempo":  NewTempoExporter,
		"jaeger": NewJaegerExporter,
	} {
		if _, err := ctor("localhost:4318"); err == nil {
			t.Errorf("%s accepted an endpoint without http:// or https://", name)
		}
	}
}

// Port 4317 is the OTLP gRPC port. The exporter speaks HTTP, so it is refused with a message that names 4318.
func TestOTLPExporters_RefuseGRPCPort(t *testing.T) {
	for name, ctor := range map[string]func(string) (trace.SpanExporter, error){
		"tempo":  NewTempoExporter,
		"jaeger": NewJaegerExporter,
	} {
		_, err := ctor("http://localhost:4317")
		if err == nil {
			t.Errorf("%s accepted port 4317", name)
			continue
		}
		if !strings.Contains(err.Error(), "4318") {
			t.Errorf("%s error should name the HTTP port 4318: %v", name, err)
		}
	}
}

// https is accepted, so a TLS-fronted receiver can be used.
func TestOTLPExporters_HTTPSAccepted(t *testing.T) {
	if _, err := NewTempoExporter("https://tempo.internal:4318"); err != nil {
		t.Errorf("https endpoint refused: %v", err)
	}
}
