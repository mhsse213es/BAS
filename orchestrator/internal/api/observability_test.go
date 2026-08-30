package api

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestRequestLoggingMiddleware_LogsAndRecordsMetrics(t *testing.T) {
	var logBuf strings.Builder
	prevLogger := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logBuf, nil)))
	defer slog.SetDefault(prevLogger)

	r := chi.NewRouter()
	r.Use(RequestLoggingMiddleware)
	r.Get("/api/widgets/{id}", func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusCreated)
	})

	before := testutil.ToFloat64(httpRequestsTotal.WithLabelValues("GET", "/api/widgets/{id}", "201"))

	req := httptest.NewRequest(http.MethodGet, "/api/widgets/42", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201", rec.Code)
	}

	after := testutil.ToFloat64(httpRequestsTotal.WithLabelValues("GET", "/api/widgets/{id}", "201"))
	if after != before+1 {
		t.Errorf("httpRequestsTotal delta = %v, want 1", after-before)
	}

	logOut := logBuf.String()
	for _, want := range []string{`"component":"http"`, `"method":"GET"`, `"route":"/api/widgets/{id}"`, `"status":201`} {
		if !strings.Contains(logOut, want) {
			t.Errorf("log output missing %q; got %s", want, logOut)
		}
	}
}
