package api

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func newTestRouterWithHandler(h *Handler) chi.Router {
	r := chi.NewRouter()
	r.Use(h.RequestLoggingMiddleware)
	r.Post("/api/heartbeat", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	r.Get("/ws/agent", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	return r
}

func legacyRequest(method, path string, body []byte) *http.Request {
	var req *http.Request
	if body != nil {
		req = httptest.NewRequest(method, path, bytes.NewReader(body))
	} else {
		req = httptest.NewRequest(method, path, nil)
	}
	return req.WithContext(context.WithValue(req.Context(), ctxKeyLegacyListener, true))
}

func TestMiddleware_AllowlistedRouteWithJSONBody_RecordsAttributed(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := &Handler{db: pool}
		router := newTestRouterWithHandler(h)

		req := legacyRequest(http.MethodPost, "/api/heartbeat", []byte(`{"agentId":"agent-mw-1"}`))
		router.ServeHTTP(httptest.NewRecorder(), req)
		waitForAsyncWrite(t, pool, "legacy_transport_log", "agent_id = 'agent-mw-1'")
	})
}

func TestMiddleware_NonAllowlistedRoute_NeverRecorded(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := &Handler{db: pool}
		router := newTestRouterWithHandler(h)

		req := legacyRequest(http.MethodGet, "/health", nil)
		router.ServeHTTP(httptest.NewRecorder(), req)

		time.Sleep(200 * time.Millisecond) // give any (incorrect) async write a chance to land
		var count int
		if err := pool.QueryRow(context.Background(),
			`SELECT COUNT(*) FROM legacy_transport_log`).Scan(&count); err != nil {
			t.Fatalf("query: %v", err)
		}
		if count != 0 {
			t.Errorf("a request to /health (not in the legacy-protocol allowlist) was recorded as agent usage -- expected 0 rows, got %d", count)
		}
		if err := pool.QueryRow(context.Background(),
			`SELECT COUNT(*) FROM legacy_transport_unattributed`).Scan(&count); err != nil {
			t.Fatalf("query: %v", err)
		}
		if count != 0 {
			t.Errorf("a request to /health was recorded as unattributed legacy traffic -- expected 0 rows, got %d", count)
		}
	})
}

func TestMiddleware_MalformedBody_RecordsUnattributedNotDropped(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := &Handler{db: pool}
		router := newTestRouterWithHandler(h)

		req := legacyRequest(http.MethodPost, "/api/heartbeat", []byte(`not valid json at all`))
		router.ServeHTTP(httptest.NewRecorder(), req)
		waitForAsyncWrite(t, pool, "legacy_transport_unattributed", "request_count >= 1")
	})
}

func TestMiddleware_QueryParamAgentID_RecordsAttributed(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := &Handler{db: pool}
		router := newTestRouterWithHandler(h)

		req := legacyRequest(http.MethodGet, "/ws/agent?agentId=agent-mw-ws", nil)
		router.ServeHTTP(httptest.NewRecorder(), req)
		waitForAsyncWrite(t, pool, "legacy_transport_log", "agent_id = 'agent-mw-ws'")
	})
}

func TestMiddleware_NonLegacyListener_NeverRecorded(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := &Handler{db: pool}
		router := newTestRouterWithHandler(h)

		// No ctxKeyLegacyListener set -- an ordinary request on the mTLS/dashboard listener.
		req := httptest.NewRequest(http.MethodPost, "/api/heartbeat", bytes.NewReader([]byte(`{"agentId":"agent-not-legacy"}`)))
		router.ServeHTTP(httptest.NewRecorder(), req)

		time.Sleep(200 * time.Millisecond)
		var count int
		if err := pool.QueryRow(context.Background(),
			`SELECT COUNT(*) FROM legacy_transport_log WHERE agent_id = 'agent-not-legacy'`).Scan(&count); err != nil {
			t.Fatalf("query: %v", err)
		}
		if count != 0 {
			t.Errorf("a non-legacy-listener request was recorded as legacy usage -- expected 0 rows, got %d", count)
		}
	})
}
