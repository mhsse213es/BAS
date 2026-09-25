package main

import (
	"net/http"
	"testing"
)

// These tests verify WIRING only -- that each construction site below
// attaches a Transport with a real, non-default DialContext (i.e.
// proxyAwareNetDialContext(cfg), not the zero-value Transport that falls
// back to net.Dial with no proxy-negotiation capability at all) and
// disables the stdlib's own (limited) built-in proxy handling via
// Proxy: nil, so the two don't stack.
//
// This deliberately does NOT attempt to prove "a real proxy gets
// contacted" end-to-end via HTTP_PROXY/HTTPS_PROXY env vars: Go's
// http.ProxyFromEnvironment caches its env-var resolution exactly once
// per process (sync.Once, see net/http/transport.go's envProxyOnce) --
// this package's own TestProxyAwareNetDialContext_NoProxyConfigured_DialsDirect
// (proxyauth_test.go) is the first caller of http.ProxyFromEnvironment in
// this test binary and permanently caches "no proxy" for every test that
// runs afterward in the same binary, regardless of what any later test
// sets via t.Setenv. dialThroughProxy's own real proxy-contact behavior is
// already covered end-to-end by proxyauth_test.go's fake-CONNECT-proxy
// tests, which call it directly with an explicit proxy address rather than
// through env-var resolution -- that coverage is not being duplicated
// here, only extended to confirm each NEW call site actually reaches it.
func TestNewAgent_ClientHasProxyAwareTransport(t *testing.T) {
	cfg := Config{ServerURL: "https://orchestrator.example:9443"}
	a := newAgent(cfg, Identity{AgentID: "a1"})

	tr, ok := a.client.Transport.(*http.Transport)
	if !ok || tr == nil {
		t.Fatalf("a.client.Transport = %T, want a non-nil *http.Transport", a.client.Transport)
	}
	if tr.DialContext == nil {
		t.Error("a.client.Transport.DialContext is nil -- proxyAwareNetDialContext(cfg) was not wired in")
	}
	if tr.Proxy != nil {
		t.Error("a.client.Transport.Proxy is set -- must be nil so stdlib's own (limited) proxy handling doesn't stack with proxyAwareNetDialContext's")
	}
}

func TestNewLogger_ClientHasProxyAwareTransport(t *testing.T) {
	cfg := Config{ServerURL: "https://orchestrator.example:9443"}
	l := NewLogger(cfg, "a1")

	tr, ok := l.client.Transport.(*http.Transport)
	if !ok || tr == nil {
		t.Fatalf("Logger.client.Transport = %T, want a non-nil *http.Transport", l.client.Transport)
	}
	if tr.DialContext == nil {
		t.Error("Logger.client.Transport.DialContext is nil -- proxyAwareNetDialContext(cfg) was not wired in")
	}
	if tr.Proxy != nil {
		t.Error("Logger.client.Transport.Proxy is set -- must be nil so stdlib's own (limited) proxy handling doesn't stack with proxyAwareNetDialContext's")
	}
}
