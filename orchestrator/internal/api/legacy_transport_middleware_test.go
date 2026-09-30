package api

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func newTestRouterWithHandler(h *Handler) chi.Router {
	r := chi.NewRouter()
	r.Use(h.RequestLoggingMiddleware)
	r.Post("/api/heartbeat", func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body) // real handlers decode the body; draining it here is what makes the TeeReader capture fill
		w.WriteHeader(http.StatusOK)
	})
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	r.Get("/ws/agent", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	r.Post("/api/scenarios/events", func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("X-Body-Len", strconv.Itoa(len(body)))
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

func TestMiddleware_LargeBody_DownstreamHandlerSeesFullBodyUncapped(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := &Handler{db: pool}
		router := newTestRouterWithHandler(h)

		// Larger than the middleware's capture cap (64 KiB) -- proves the
		// TeeReader passes every byte through to the real handler
		// uncapped; only the middleware's own attribution capture is
		// bounded, never the request the downstream handler actually
		// receives.
		bigBody := strings.Repeat("A", 200*1024)
		req := legacyRequest(http.MethodPost, "/api/scenarios/events", []byte(bigBody))
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", rec.Code)
		}
		if got := rec.Header().Get("X-Body-Len"); got != strconv.Itoa(len(bigBody)) {
			t.Errorf("downstream handler read %s bytes, want %d -- the capture cap must never truncate what the real handler receives", got, len(bigBody))
		}
	})
}

func TestMiddleware_LargeBody_AttributionCaptureIsCapped(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := &Handler{db: pool}
		router := newTestRouterWithHandler(h)

		// agentId sits at the very front, but the JSON object never closes
		// within the capped prefix the middleware captures -- attribution
		// must fail safe (fall through to unattributed) rather than buffer
		// the whole 200KiB body into memory to find a closing brace.
		bigBody := `{"agentId":"agent-huge",` + `"padding":"` + strings.Repeat("A", 200*1024) + `"}`
		req := legacyRequest(http.MethodPost, "/api/heartbeat", []byte(bigBody))
		router.ServeHTTP(httptest.NewRecorder(), req)

		waitForAsyncWrite(t, pool, "legacy_transport_unattributed", "request_count >= 1")

		var count int
		if err := pool.QueryRow(context.Background(),
			`SELECT COUNT(*) FROM legacy_transport_log WHERE agent_id = 'agent-huge'`).Scan(&count); err != nil {
			t.Fatalf("query: %v", err)
		}
		if count != 0 {
			t.Errorf("expected the oversized body to NOT be attributed (capped capture can't see the full JSON), got %d attributed rows for agent-huge", count)
		}
	})
}
