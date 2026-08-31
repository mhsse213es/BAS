package api

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
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

func TestHealthEndpoint_UnconditionalOK(t *testing.T) {
	h := New(nil, ws.NewHub(), scenario.NewEngine(t.TempDir()), "test-secret")
	router := Mount(h, ws.NewHub(), "test-secret", "", http.NotFoundHandler(), 0, 0)

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if rec.Body.String() != `{"status":"ok"}` {
		t.Errorf("body = %q, want exactly {\"status\":\"ok\"} (unconditional -- no DB dependency)", rec.Body.String())
	}
}

func TestHandleReady_DatabaseReachable_Returns200(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		req := httptest.NewRequest(http.MethodGet, "/ready", nil)
		rec := httptest.NewRecorder()
		h.handleReady(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
		var body map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if body["status"] != "ready" {
			t.Errorf("status field = %v, want ready", body["status"])
		}
	})
}

func TestHandleReady_DatabaseUnreachable_Returns503(t *testing.T) {
	// A throwaway pool pointed at a host that doesn't exist -- distinct
	// from sharedDB's pool (never touch that one: it's reused across this
	// whole test binary, and closing it would break every test that runs
	// after this one).
	badPool, err := pgxpool.New(context.Background(), "postgres://user:pass@127.0.0.1:1/nonexistent?connect_timeout=1")
	if err != nil {
		t.Fatalf("pgxpool.New: %v", err)
	}
	defer badPool.Close()

	h := New(badPool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
	req := httptest.NewRequest(http.MethodGet, "/ready", nil)
	rec := httptest.NewRecorder()
	h.handleReady(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if body["status"] != "not_ready" {
		t.Errorf("status field = %v, want not_ready", body["status"])
	}
}

func TestMetricsHandler_NoTokenConfigured_Open(t *testing.T) {
	h := New(nil, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	h.metricsHandler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "go_goroutines") {
		t.Errorf("response missing expected Go runtime collector output")
	}
}

func TestMetricsHandler_TokenConfigured_RequiresBearer(t *testing.T) {
	h := New(nil, ws.NewHub(), scenario.NewEngine(t.TempDir()), "").WithMetricsToken("s3cr3t")

	noAuth := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	recNoAuth := httptest.NewRecorder()
	h.metricsHandler().ServeHTTP(recNoAuth, noAuth)
	if recNoAuth.Code != http.StatusUnauthorized {
		t.Errorf("no-auth status = %d, want 401", recNoAuth.Code)
	}

	wrongAuth := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	wrongAuth.Header.Set("Authorization", "Bearer wrong")
	recWrong := httptest.NewRecorder()
	h.metricsHandler().ServeHTTP(recWrong, wrongAuth)
	if recWrong.Code != http.StatusUnauthorized {
		t.Errorf("wrong-token status = %d, want 401", recWrong.Code)
	}

	rightAuth := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rightAuth.Header.Set("Authorization", "Bearer s3cr3t")
	recRight := httptest.NewRecorder()
	h.metricsHandler().ServeHTTP(recRight, rightAuth)
	if recRight.Code != http.StatusOK {
		t.Errorf("correct-token status = %d, want 200", recRight.Code)
	}
}
