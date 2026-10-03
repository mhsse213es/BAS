package ws

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gorilla/websocket"
)

// F3: the browser WebSocket upgrader must validate Origin against the
// configured public base URL (or the request's own same-origin host as
// a fallback), rather than CheckOrigin always returning true -- a real
// WebSocket handshake, not just a unit-tested predicate, since a
// misconfigured upgrader is exactly the kind of thing a pure-function
// test can miss.

func TestServeBrowserWS_ConfiguredOrigin_Accepted(t *testing.T) {
	h := NewHub()
	h.SetAllowedOrigin("https://bas.internal")

	srv := httptest.NewServer(http.HandlerFunc(h.ServeBrowserWS))
	defer srv.Close()
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")

	header := http.Header{"Origin": {"https://bas.internal"}}
	conn, resp, err := websocket.DefaultDialer.Dial(wsURL, header)
	if err != nil {
		t.Fatalf("expected the configured origin to be accepted, got: %v (status %v)", err, statusOf(resp))
	}
	conn.Close()
}

func TestServeBrowserWS_MaliciousOrigin_Rejected(t *testing.T) {
	h := NewHub()
	h.SetAllowedOrigin("https://bas.internal")

	srv := httptest.NewServer(http.HandlerFunc(h.ServeBrowserWS))
	defer srv.Close()
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")

	header := http.Header{"Origin": {"https://evil.example.com"}}
	conn, resp, err := websocket.DefaultDialer.Dial(wsURL, header)
	if err == nil {
		conn.Close()
		t.Fatal("expected a cross-origin WebSocket upgrade to be rejected, got a successful connection")
	}
	if resp == nil || resp.StatusCode != http.StatusForbidden {
		t.Errorf("expected HTTP 403 for a rejected origin, got %v", statusOf(resp))
	}
}

func TestServeBrowserWS_NoOrigin_Rejected(t *testing.T) {
	// A real browser's WebSocket handshake always sends Origin. Its
	// absence is not a legitimate same-origin browser connection to this
	// endpoint -- explicitly defined and tested, per F3's own test plan,
	// rather than left as whatever gorilla/websocket's library default
	// happens to do.
	h := NewHub()
	h.SetAllowedOrigin("https://bas.internal")

	srv := httptest.NewServer(http.HandlerFunc(h.ServeBrowserWS))
	defer srv.Close()
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")

	conn, resp, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err == nil {
		conn.Close()
		t.Fatal("expected a WebSocket upgrade with no Origin header to be rejected, got a successful connection")
	}
	if resp == nil || resp.StatusCode != http.StatusForbidden {
		t.Errorf("expected HTTP 403 for a missing origin, got %v", statusOf(resp))
	}
}

func TestServeBrowserWS_SameOriginFallback_AcceptedWithoutExplicitConfig(t *testing.T) {
	// No SetAllowedOrigin call at all -- the SPA is served by this same
	// orchestrator, so a browser's Origin naturally matches the actual
	// request's own Host even with nothing explicitly configured.
	h := NewHub()

	srv := httptest.NewServer(http.HandlerFunc(h.ServeBrowserWS))
	defer srv.Close()
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")

	u, _ := url.Parse(srv.URL)
	header := http.Header{"Origin": {"http://" + u.Host}}
	conn, resp, err := websocket.DefaultDialer.Dial(wsURL, header)
	if err != nil {
		t.Fatalf("expected the same-origin fallback to accept a same-host origin, got: %v (status %v)", err, statusOf(resp))
	}
	conn.Close()
}

func TestServeAgentWS_AnyOrigin_RemainsUnaffected(t *testing.T) {
	// F3 explicitly must not touch the agent WS path -- agents are
	// credential-gated separately (X-Agent-Token), not by browser
	// same-origin semantics, and don't necessarily send an Origin header
	// at all.
	h := NewHub()
	h.SetAllowedOrigin("https://bas.internal")

	srv := httptest.NewServer(http.HandlerFunc(h.ServeAgentWS))
	defer srv.Close()
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "?agentId=test-agent-1"

	header := http.Header{"Origin": {"https://evil.example.com"}}
	conn, resp, err := websocket.DefaultDialer.Dial(wsURL, header)
	if err != nil {
		t.Fatalf("expected the agent WS path to remain unaffected by browser origin validation, got: %v (status %v)", err, statusOf(resp))
	}
	conn.Close()
}

func statusOf(resp *http.Response) string {
	if resp == nil {
		return "<nil response>"
	}
	return resp.Status
}
