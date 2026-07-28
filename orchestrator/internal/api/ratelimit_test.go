package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRateLimitMiddleware_AllowsWithinBurst(t *testing.T) {
	mw := RateLimitMiddleware(60, 3) // 1/sec sustained, burst 3
	calls := 0
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusOK)
	}))

	for i := 0; i < 3; i++ {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
		if w.Code != http.StatusOK {
			t.Fatalf("request %d: status = %d, want 200 (within burst)", i, w.Code)
		}
	}
	if calls != 3 {
		t.Fatalf("calls = %d, want 3", calls)
	}
}

func TestRateLimitMiddleware_429sOverBurst(t *testing.T) {
	mw := RateLimitMiddleware(60, 2) // burst 2
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Exhaust the burst.
	for i := 0; i < 2; i++ {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
		if w.Code != http.StatusOK {
			t.Fatalf("request %d: status = %d, want 200", i, w.Code)
		}
	}

	// Next immediate request must be rejected.
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429 once burst is exhausted", w.Code)
	}
}

func TestRateLimitMiddleware_SharedAcrossRequests(t *testing.T) {
	// A single middleware instance shares ONE limiter across every request it
	// wraps -- confirms the "single global limit" semantic, not per-request
	// or per-connection isolation.
	mw := RateLimitMiddleware(60, 1)
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	w1 := httptest.NewRecorder()
	h.ServeHTTP(w1, httptest.NewRequest("GET", "/a", nil))
	if w1.Code != http.StatusOK {
		t.Fatalf("first request: status = %d, want 200", w1.Code)
	}

	w2 := httptest.NewRecorder()
	h.ServeHTTP(w2, httptest.NewRequest("GET", "/b", nil))
	if w2.Code != http.StatusTooManyRequests {
		t.Fatalf("second request (different path): status = %d, want 429 -- limiter must be shared, not per-route", w2.Code)
	}
}
