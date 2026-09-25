package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestTrustedRealIP_DirectConnection_IgnoresForgedHeader(t *testing.T) {
	// The default, most common deployment: no reverse proxy in front,
	// orchestrator's port exposed directly to the network. The peer here is
	// a real external IP -- not loopback, not private -- so any
	// X-Forwarded-For it sends must be ignored: honoring it is exactly the
	// spoofing vulnerability (GHSA-3fxj-6jh8-hvhx) this replaces.
	var gotRemoteAddr string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotRemoteAddr = r.RemoteAddr
	})
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "203.0.113.7:54321" // TEST-NET-3, a real-looking public IP
	req.Header.Set("X-Forwarded-For", "10.10.10.10")
	rec := httptest.NewRecorder()

	trustedRealIP(next).ServeHTTP(rec, req)

	if gotRemoteAddr != "203.0.113.7:54321" {
		t.Errorf("RemoteAddr = %q, want unchanged %q -- a direct (untrusted) peer's forged header must be ignored", gotRemoteAddr, "203.0.113.7:54321")
	}
}

func TestTrustedRealIP_TrustedProxyPeer_HonorsForwardedHeader(t *testing.T) {
	// A reverse proxy (nginx/Caddy per the installation guide's documented
	// optional setup) running on the same host or private docker network --
	// the direct TCP peer is loopback/private, so its X-Forwarded-For is
	// trusted and used for the real client IP.
	var gotRemoteAddr string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotRemoteAddr = r.RemoteAddr
	})
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "172.20.0.5:54321" // docker bridge network range
	req.Header.Set("X-Forwarded-For", "198.51.100.42, 172.20.0.1")
	rec := httptest.NewRecorder()

	trustedRealIP(next).ServeHTTP(rec, req)

	if gotRemoteAddr != "198.51.100.42" {
		t.Errorf("RemoteAddr = %q, want %q -- a trusted proxy peer's X-Forwarded-For (first hop = real client) must be honored", gotRemoteAddr, "198.51.100.42")
	}
}

func TestTrustedRealIP_TrustedProxyPeer_LoopbackAlsoTrusted(t *testing.T) {
	var gotRemoteAddr string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotRemoteAddr = r.RemoteAddr
	})
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "127.0.0.1:54321"
	req.Header.Set("X-Real-IP", "198.51.100.42")
	rec := httptest.NewRecorder()

	trustedRealIP(next).ServeHTTP(rec, req)

	if gotRemoteAddr != "198.51.100.42" {
		t.Errorf("RemoteAddr = %q, want %q -- loopback peer is trusted, X-Real-IP honored", gotRemoteAddr, "198.51.100.42")
	}
}

func TestTrustedRealIP_TrustedPeer_NoForwardedHeader_KeepsRemoteAddr(t *testing.T) {
	// A trusted proxy that, for whatever reason, didn't set either header --
	// must fall back to the real (trusted) peer address, not blank/panic.
	var gotRemoteAddr string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotRemoteAddr = r.RemoteAddr
	})
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.5:54321"
	rec := httptest.NewRecorder()

	trustedRealIP(next).ServeHTTP(rec, req)

	if gotRemoteAddr != "10.0.0.5:54321" {
		t.Errorf("RemoteAddr = %q, want unchanged %q", gotRemoteAddr, "10.0.0.5:54321")
	}
}

func TestTrustedRealIP_TrustedPeer_MalformedForwardedHeader_FallsBackSafely(t *testing.T) {
	var gotRemoteAddr string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotRemoteAddr = r.RemoteAddr
	})
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.5:54321"
	req.Header.Set("X-Forwarded-For", "   ") // present but empty/whitespace-only
	rec := httptest.NewRecorder()

	trustedRealIP(next).ServeHTTP(rec, req)

	if gotRemoteAddr != "10.0.0.5:54321" {
		t.Errorf("RemoteAddr = %q, want unchanged %q -- an empty forwarded value must not blank out the real peer address", gotRemoteAddr, "10.0.0.5:54321")
	}
}

func TestTrustedRealIP_RemoteAddrWithoutPort_HandledGracefully(t *testing.T) {
	// net/http's own RemoteAddr always includes a port in production, but a
	// hand-built request (as tests, or some non-standard client, might
	// produce) should not panic or misclassify -- SplitHostPort's error
	// path must degrade safely to "not trusted" rather than crash.
	var gotRemoteAddr string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotRemoteAddr = r.RemoteAddr
	})
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "203.0.113.7" // no port
	req.Header.Set("X-Forwarded-For", "10.10.10.10")
	rec := httptest.NewRecorder()

	trustedRealIP(next).ServeHTTP(rec, req)

	if gotRemoteAddr != "203.0.113.7" {
		t.Errorf("RemoteAddr = %q, want unchanged %q -- malformed RemoteAddr must not be treated as a trusted peer", gotRemoteAddr, "203.0.113.7")
	}
}
