package observability

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

// otlpReceiver counts OTLP/HTTP trace exports it receives.
func otlpReceiver(t *testing.T) (*httptest.Server, *atomic.Int32, *atomic.Value) {
	t.Helper()
	var n atomic.Int32
	var path atomic.Value
	path.Store("")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		path.Store(r.URL.Path)
		w.Header().Set("Content-Type", "application/x-protobuf")
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	return srv, &n, &path
}

func TestTempoExporter_SendsSpansToOTLPTracesPath(t *testing.T) {
	srv, n, path := otlpReceiver(t)
	exp, err := NewTempoExporter(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exp))
	_, span := tp.Tracer("test").Start(context.Background(), "op")
	span.End()
	if err := tp.ForceFlush(context.Background()); err != nil {
		t.Fatalf("flush: %v", err)
	}
	if n.Load() == 0 {
		t.Fatal("no OTLP export reached the receiver")
	}
	if got := path.Load().(string); got != "/v1/traces" {
		t.Fatalf("export path = %q, want /v1/traces", got)
	}
}

func TestNewTracerProviderWithConfig_ExportsWhenEnabled(t *testing.T) {
	srv, n, _ := otlpReceiver(t)
	tp := NewTracerProviderWithConfig(&OTelConfig{
		Enabled:   true,
		Exporters: ExporterConfig{TempoEndpoint: srv.URL},
	})
	defer tp.Shutdown(context.Background())
	_, span := tp.Tracer("test").Start(context.Background(), "op")
	span.End()
	if err := tp.ForceFlush(context.Background()); err != nil {
		t.Fatalf("flush: %v", err)
	}
	if n.Load() == 0 {
		t.Fatal("configured Tempo endpoint received no spans")
	}
}

func TestNewTracerProviderWithConfig_DisabledExportsNothing(t *testing.T) {
	srv, n, _ := otlpReceiver(t)
	tp := NewTracerProviderWithConfig(&OTelConfig{
		Enabled:   false,
		Exporters: ExporterConfig{TempoEndpoint: srv.URL},
	})
	defer tp.Shutdown(context.Background())
	_, span := tp.Tracer("test").Start(context.Background(), "op")
	span.End()
	_ = tp.ForceFlush(context.Background())
	if n.Load() != 0 {
		t.Fatalf("disabled tracing exported %d requests", n.Load())
	}
}

// The whole path an operator relies on: a request through the span middleware,
// with the provider built from config, reaches the OTLP receiver.
func TestRequestTraffic_ReachesConfiguredReceiver(t *testing.T) {
	srv, n, _ := otlpReceiver(t)
	tp := NewTracerProviderWithConfig(&OTelConfig{
		Enabled:   true,
		Exporters: ExporterConfig{TempoEndpoint: srv.URL},
	})
	defer tp.Shutdown(context.Background())
	h := RequestSpanMiddleware(tp.Tracer("audspect-orchestrator"), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/api/health", nil))
	if err := tp.ForceFlush(context.Background()); err != nil {
		t.Fatalf("flush: %v", err)
	}
	if n.Load() == 0 {
		t.Fatal("a request span did not reach the configured OTLP receiver")
	}
}
