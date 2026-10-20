package cloudgraph

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

var fastRetry = RetryPolicy{MaxAttempts: 4, BaseDelay: time.Millisecond, MaxDelay: 5 * time.Millisecond}

func getBuilder(url string) func(context.Context) (*http.Request, error) {
	return func(ctx context.Context) (*http.Request, error) {
		return http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	}
}

func TestDoWithRetry_RetriesThrottleThenSucceeds(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) < 3 {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		io.WriteString(w, "ok")
	}))
	defer srv.Close()

	resp, err := doWithRetry(context.Background(), srv.Client(), nil, fastRetry, getBuilder(srv.URL))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if got := calls.Load(); got != 3 {
		t.Errorf("attempts = %d, want 3", got)
	}
}

func TestDoWithRetry_ForbiddenIsNeverRetried(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	resp, err := doWithRetry(context.Background(), srv.Client(), nil, fastRetry, getBuilder(srv.URL))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403 passed through", resp.StatusCode)
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("attempts = %d, want 1 (4xx is a caller error)", got)
	}
}

func TestDoWithRetry_ExhaustedReturnsLastRetryableResponse(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	resp, err := doWithRetry(context.Background(), srv.Client(), nil, fastRetry, getBuilder(srv.URL))
	if err != nil {
		t.Fatalf("a final retryable status must be returned to the caller, got error %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", resp.StatusCode)
	}
	if got := calls.Load(); got != int32(fastRetry.MaxAttempts) {
		t.Errorf("attempts = %d, want %d", got, fastRetry.MaxAttempts)
	}
}

func TestDoWithRetry_TransportErrorExhaustedReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := srv.URL
	srv.Close() // every attempt now fails at the transport layer

	_, err := doWithRetry(context.Background(), http.DefaultClient, nil, fastRetry, getBuilder(url))
	if err == nil {
		t.Fatal("expected error after transport failures")
	}
	if !strings.Contains(err.Error(), "gave up after 4 attempts") {
		t.Errorf("error should say how many attempts were made, got %v", err)
	}
}

func TestDoWithRetry_ContextCancelStopsWithoutRetry(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		cancel()
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	slow := RetryPolicy{MaxAttempts: 4, BaseDelay: time.Hour, MaxDelay: time.Hour}
	_, err := doWithRetry(ctx, srv.Client(), nil, slow, getBuilder(srv.URL))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("attempts = %d, want 1 after cancellation", got)
	}
}

func TestParseRetryAfter(t *testing.T) {
	cases := map[string]time.Duration{
		"7":                7 * time.Second,
		" 2 ":              2 * time.Second,
		"":                 0,
		"Wed, 21 Oct 2015": 0,
		"-3":               0,
	}
	for in, want := range cases {
		if got := parseRetryAfter(in); got != want {
			t.Errorf("parseRetryAfter(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestBackoff_BoundedByMaxDelay(t *testing.T) {
	p := RetryPolicy{BaseDelay: time.Second, MaxDelay: 4 * time.Second}
	for n := 1; n <= 10; n++ {
		if d := p.backoff(n, 0); d > p.MaxDelay {
			t.Errorf("backoff(%d) = %v exceeds MaxDelay %v", n, d, p.MaxDelay)
		}
	}
	// Retry-After larger than the cap must still be bounded by it.
	if d := p.backoff(1, time.Hour); d > p.MaxDelay {
		t.Errorf("Retry-After not capped: %v", d)
	}
}

func TestRedact(t *testing.T) {
	got := Redact("token=abc123 and secret=s3cr3t", "abc123", "", "s3cr3t")
	want := "token=[REDACTED] and secret=[REDACTED]"
	if got != want {
		t.Errorf("Redact = %q, want %q", got, want)
	}
}
