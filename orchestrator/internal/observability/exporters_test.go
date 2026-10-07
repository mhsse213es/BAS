package observability

import "testing"

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
	exp, err := NewTempoExporter("localhost:4318")
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
	exp, err := NewJaegerExporter("localhost:4317")
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
