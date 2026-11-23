package observability

import (
	"net/http"
	"net/http/httptest"
	"testing"

	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

func TestRequestSpan_RecordsMethodPathAndStatus(t *testing.T) {
	rec := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(rec))
	h := RequestSpanMiddleware(tp.Tracer("http"), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	}))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/api/runs", nil))

	spans := rec.Ended()
	if len(spans) != 1 {
		t.Fatalf("got %d spans, want 1", len(spans))
	}
	s := spans[0]
	if s.Name() != "POST /api/runs" {
		t.Errorf("span name = %q, want %q", s.Name(), "POST /api/runs")
	}
	got := map[string]any{}
	for _, kv := range s.Attributes() {
		got[string(kv.Key)] = kv.Value.AsInterface()
	}
	if got["http.request.method"] != "POST" || got["url.path"] != "/api/runs" {
		t.Errorf("attributes = %v", got)
	}
	if got["http.response.status_code"] != int64(http.StatusTeapot) {
		t.Errorf("status attribute = %v, want %d", got["http.response.status_code"], http.StatusTeapot)
	}
}
