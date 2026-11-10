package modsecwaf

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/audspect/bas/internal/wafcatalog"
)

// Review Focus: SendBurst exists to drive a real, bounded burst of concurrent
// requests at one target so a rate limiter's own enforcement behavior can be
// observed -- a single Client.Send call cannot represent "N requests in a
// short window" at all. This test proves it collects every response (not
// just the first or last) and that the responses genuinely reflect what the
// server returned per-request, not a single shared result.
func TestSendBurst_CollectsEveryResponse(t *testing.T) {
	var count atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := count.Add(1)
		if n <= 3 {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
	}))
	defer srv.Close()

	c := NewClient(Config{BaseURL: srv.URL})
	responses, err := c.SendBurst(context.Background(), wafcatalog.RequestTemplate{
		Method: "GET", Path: "/api/quote",
	}, 10)
	if err != nil {
		t.Fatalf("SendBurst: %v", err)
	}
	if len(responses) != 10 {
		t.Fatalf("len(responses) = %d, want 10", len(responses))
	}

	var ok, blocked int
	for _, r := range responses {
		switch r.StatusCode {
		case http.StatusOK:
			ok++
		case http.StatusServiceUnavailable:
			blocked++
		default:
			t.Errorf("unexpected status %d", r.StatusCode)
		}
	}
	if ok != 3 {
		t.Errorf("ok count = %d, want 3", ok)
	}
	if blocked != 7 {
		t.Errorf("blocked count = %d, want 7", blocked)
	}
}
