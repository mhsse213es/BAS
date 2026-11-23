package observability

import (
	"net/http"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// statusRecorder keeps the status code the handler wrote so the span can
// carry it. Handlers that never call WriteHeader get 200, as net/http sends.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

// RequestSpanMiddleware opens one span per HTTP request. The span carries the
// method, path and final status code. With no exporter configured the global
// provider is a no-op and this costs almost nothing.
func RequestSpanMiddleware(tracer trace.Tracer, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, span := tracer.Start(r.Context(), r.Method+" "+r.URL.Path)
		defer span.End()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		span.SetAttributes(
			attribute.String("http.request.method", r.Method),
			attribute.String("url.path", r.URL.Path),
		)
		next.ServeHTTP(rec, r.WithContext(ctx))
		span.SetAttributes(attribute.Int("http.response.status_code", rec.status))
	})
}
