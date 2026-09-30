// orchestrator/internal/api/listener_routing_test.go
package api

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

// The :9444 enrollment router must expose enroll-csr and /health only.
func TestMountEnrollment_ServesOnlyEnrollmentAndHealth(t *testing.T) {
	h := New(nil, ws.NewHub(), scenario.NewEngine(t.TempDir()), "test-secret") // no PKI: enroll-csr answers 503, proving it was routed
	router := MountEnrollment(h)

	cases := []struct {
		method, path string
		want         int
	}{
		{http.MethodGet, "/health", http.StatusOK},
		{http.MethodPost, "/api/agents/enroll-csr", http.StatusServiceUnavailable},
		{http.MethodGet, "/ws/agent", http.StatusNotFound},
		{http.MethodPost, "/api/agents/enroll", http.StatusNotFound},
		{http.MethodPost, "/api/heartbeat", http.StatusNotFound},
		{http.MethodPost, "/api/auth/login", http.StatusNotFound},
		{http.MethodGet, "/api/agents/ping", http.StatusNotFound},
		{http.MethodGet, "/", http.StatusNotFound},
		{http.MethodGet, "/metrics", http.StatusNotFound},
	}
	for _, c := range cases {
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, httptest.NewRequest(c.method, c.path, strings.NewReader("{}")))
		// chi answers 405 for a known path with the wrong method; anything
		// not registered is 404. Both mean "not served here".
		if rec.Code != c.want {
			t.Errorf("%s %s: status = %d, want %d", c.method, c.path, rec.Code, c.want)
		}
	}
}

// Requests arriving through WithLegacyListenerTag are counted and logged
// distinctly; the same request without the tag is not.
func TestLegacyListenerTag_LogsAndCountsDistinctly(t *testing.T) {
	var logBuf strings.Builder
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logBuf, nil)))
	defer slog.SetDefault(prev)

	h := &Handler{}
	r := chi.NewRouter()
	r.Use(h.RequestLoggingMiddleware)
	r.Post("/api/legacytest/{id}", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusAccepted) })

	counter := legacyListenerRequestsTotal.WithLabelValues("POST", "/api/legacytest/{id}", "202")
	before := testutil.ToFloat64(counter)

	// Untagged (mTLS/enrollment listener): no legacy count, no legacy line.
	r.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/api/legacytest/1", nil))
	if got := testutil.ToFloat64(counter); got != before {
		t.Errorf("untagged request incremented legacy counter by %v", got-before)
	}
	if strings.Contains(logBuf.String(), "legacy listener request") {
		t.Errorf("untagged request produced a legacy log line: %s", logBuf.String())
	}

	// Tagged (legacy listener).
	WithLegacyListenerTag(r).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/api/legacytest/2?agentId=0123456789abcdef", nil))
	if got := testutil.ToFloat64(counter); got != before+1 {
		t.Errorf("legacy counter delta = %v, want 1", got-before)
	}
	out := logBuf.String()
	for _, want := range []string{`"msg":"legacy listener request"`, `"listener":"legacy"`, `"route":"/api/legacytest/{id}"`, `"status":202`, `"agent_id":"0123456789abcdef"`} {
		if !strings.Contains(out, want) {
			t.Errorf("legacy log output missing %q; got %s", want, out)
		}
	}
}
