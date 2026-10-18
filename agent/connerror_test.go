package main

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

func TestClassifyConnError_ProxyAuthString_IsProxyAuth(t *testing.T) {
	got := ClassifyConnError(errors.New("proxy rejected the configured credentials"))
	if got.Category != ConnErrorProxyAuth {
		t.Fatalf("category = %q, want %q", got.Category, ConnErrorProxyAuth)
	}
}

func TestClassifyConnError_Nil_IsNone(t *testing.T) {
	got := ClassifyConnError(nil)
	if got.Category != ConnErrorNone {
		t.Fatalf("category = %q, want %q", got.Category, ConnErrorNone)
	}
}

func TestClassifyConnError_SetsTimestamp(t *testing.T) {
	before := time.Now()
	got := ClassifyConnError(errors.New("connection refused"))
	if got.At.Before(before) {
		t.Fatal("At was not set to the time of classification")
	}
}

// TestClassifyConnError_ProxyAuthStringWinsOverGenericOpError pins the
// ordering Task 2's brief calls for: a proxy rejection often also wraps a
// *net.OpError, and the more specific proxy-auth classification must win
// over the generic TCP fallback.
func TestClassifyConnError_ProxyAuthStringWinsOverGenericOpError(t *testing.T) {
	wrapped := &net.OpError{Op: "dial", Err: errors.New("no supported mechanism")}
	got := ClassifyConnError(wrapped)
	if got.Category != ConnErrorProxyAuth {
		t.Fatalf("category = %q, want %q (proxy-auth string must win over generic OpError match)", got.Category, ConnErrorProxyAuth)
	}
}

// TestAgent_RecordsLastConnErrorOnFailedAttempt drives a real failed
// connection attempt through the agent's existing bootstrap retry path
// (no CA root installed, so ensureCertificate fails immediately) and
// asserts a.lastConnErrPtr.Load() is set with a plausible category.
// retryBootstrapUntilEnrolled loops forever retrying until it succeeds, so
// this runs it in a goroutine and polls for the first write rather than
// waiting for it to return.
func TestAgent_RecordsLastConnErrorOnFailedAttempt(t *testing.T) {
	t.Setenv("BAS_CERT_DIR", t.TempDir()) // no CA root installed -> bootstrap cannot run

	legacyCfg := Config{ServerURL: "http://orchestrator.local:9000", AgentSecret: "secret"}
	a := newAgent(legacyCfg, Identity{AgentID: "abc123deadbeef01"})

	go a.retryBootstrapUntilEnrolled(context.Background())

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if lce := a.lastConnErrPtr.Load(); lce != nil {
			if lce.Category == ConnErrorNone || lce.Category == "" {
				t.Fatalf("recorded category = %q, want a real failure category", lce.Category)
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("lastConnErrPtr was never set within the deadline")
}

// TestAgent_RecordAndClearConnError pins the two helpers connectWS now
// calls directly (unlike retryBootstrapUntilEnrolled's rare legacy-retry
// path, connectWS is the path an already-enrolled agent that merely lost
// connectivity actually exercises -- the common real-world case the
// review found never updated lastConnErrPtr at all).
func TestAgent_RecordAndClearConnError(t *testing.T) {
	a := newAgent(Config{ServerURL: "https://orchestrator.local:9443", AgentSecret: "secret"}, Identity{AgentID: "abc123deadbeef01"})

	a.recordConnError(errors.New("connection refused"))
	lce := a.lastConnErrPtr.Load()
	if lce == nil || lce.Category == ConnErrorNone || lce.Category == "" {
		t.Fatalf("after recordConnError: lastConnErrPtr = %+v, want a real failure category", lce)
	}

	a.clearConnError()
	lce = a.lastConnErrPtr.Load()
	if lce == nil || lce.Category != ConnErrorNone {
		t.Fatalf("after clearConnError: lastConnErrPtr = %+v, want Category == ConnErrorNone", lce)
	}
}
