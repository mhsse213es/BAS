//go:build windows

package main

import (
	"errors"
	"net"
	"sync"
	"testing"
	"time"
)

func newTestAgentForMutate(t *testing.T) *Agent {
	t.Helper()
	return newAgent(Config{ServerURL: "https://orchestrator.local:9443", AgentSecret: "secret"}, Identity{AgentID: "abc123deadbeef01"})
}

func TestHandleTestServer_InvalidHost_NoNetworkCallMade(t *testing.T) {
	origDial := dialTLSCheck
	called := false
	dialTLSCheck = func(addr string, cfg Config) error {
		called = true
		return nil
	}
	defer func() { dialTLSCheck = origDial }()

	a := newTestAgentForMutate(t)
	outcome, _ := a.handleTestServer("https://host:9443/foo?x=1")
	if outcome != TestOutcomeInvalidHost {
		t.Fatalf("outcome = %q, want %q", outcome, TestOutcomeInvalidHost)
	}
	if called {
		t.Fatal("dialTLSCheck must never be called for an invalid host")
	}
}

func TestHandleTestServer_DialFails_HostUnreachable(t *testing.T) {
	origDial := dialTLSCheck
	dialTLSCheck = func(addr string, cfg Config) error {
		return &net.OpError{Op: "dial", Err: errors.New("connection refused")}
	}
	defer func() { dialTLSCheck = origDial }()

	a := newTestAgentForMutate(t)
	outcome, _ := a.handleTestServer("https://10.0.0.5:9443")
	if outcome != TestOutcomeHostUnreachable {
		t.Fatalf("outcome = %q, want %q", outcome, TestOutcomeHostUnreachable)
	}
}

func TestHandleTestServer_TLSOK_AuthRejected_ServerRejected(t *testing.T) {
	origDial, origAuth := dialTLSCheck, authCheck
	dialTLSCheck = func(addr string, cfg Config) error { return nil }
	authCheck = func(a *Agent, cfg Config) (error, time.Time) {
		return errors.New("server 401 on /api/heartbeat"), time.Time{}
	}
	defer func() { dialTLSCheck, authCheck = origDial, origAuth }()

	a := newTestAgentForMutate(t)
	outcome, _ := a.handleTestServer("https://10.0.0.5:9443")
	if outcome != TestOutcomeServerRejected {
		t.Fatalf("outcome = %q, want %q", outcome, TestOutcomeServerRejected)
	}
}

func TestHandleTestServer_Connected_ReturnsServerTime(t *testing.T) {
	origDial, origAuth := dialTLSCheck, authCheck
	wantTime := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	dialTLSCheck = func(addr string, cfg Config) error { return nil }
	authCheck = func(a *Agent, cfg Config) (error, time.Time) { return nil, wantTime }
	defer func() { dialTLSCheck, authCheck = origDial, origAuth }()

	a := newTestAgentForMutate(t)
	outcome, _, serverTime := a.testServerWithServerTime("https://10.0.0.5:9443")
	if outcome != TestOutcomeConnected {
		t.Fatalf("outcome = %q, want %q", outcome, TestOutcomeConnected)
	}
	if !serverTime.Equal(wantTime) {
		t.Fatalf("serverTime = %v, want %v", serverTime, wantTime)
	}
}

// callLog records persist/apply calls in order, under its own mutex, so
// TestHandleSetServer_ConcurrentCalls_Serialized can assert on ordering
// without racing the fakes themselves.
type callLog struct {
	mu    sync.Mutex
	calls []string
}

func (c *callLog) add(s string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls = append(c.calls, s)
}

func (c *callLog) snapshot() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.calls...)
}

// fakeSetServerSeams swaps setServerPersist/setServerApply/
// setServerVerifyReconnect/setServerReadPrevious and returns a restore
// func -- every handleSetServer test needs all four now that "previous"
// is read via its own seam instead of a.cfg().ServerURL (which no longer
// matches what setServerPersist actually persists; see the ledger).
func fakeSetServerSeams(t *testing.T, prevURL string, persist func(string) error, apply func(*Agent, Config) error, verify func(*Agent, string) bool) {
	t.Helper()
	origPersist, origApply, origVerify, origPrev := setServerPersist, setServerApply, setServerVerifyReconnect, setServerReadPrevious
	setServerPersist = persist
	setServerApply = apply
	setServerVerifyReconnect = verify
	setServerReadPrevious = func() string { return prevURL }
	t.Cleanup(func() {
		setServerPersist, setServerApply, setServerVerifyReconnect, setServerReadPrevious = origPersist, origApply, origVerify, origPrev
	})
}

func TestHandleSetServer_ReconnectSucceeds_ReturnsOK(t *testing.T) {
	fakeSetServerSeams(t, "https://old:9443",
		func(serverURL string) error { return nil },
		func(a *Agent, cfg Config) error { return nil },
		func(a *Agent, host string) bool { return true },
	)

	a := newTestAgentForMutate(t)
	ok, _ := a.handleSetServerWithTimeout("https://10.0.0.5:9443", 200*time.Millisecond, 5*time.Millisecond)
	if !ok {
		t.Fatal("expected ok == true when reconnect succeeds")
	}
}

func TestHandleSetServer_ReconnectTimesOut_RollsBackAndReportsFailure(t *testing.T) {
	log := &callLog{}
	prevURL := "https://old:9443"
	fakeSetServerSeams(t, prevURL,
		func(serverURL string) error {
			log.add("persist:" + serverURL)
			return nil
		},
		func(a *Agent, cfg Config) error { return nil },
		func(a *Agent, host string) bool { return false },
	)

	a := newTestAgentForMutate(t)
	ok, detail := a.handleSetServerWithTimeout("https://10.0.0.5:9443", 50*time.Millisecond, 5*time.Millisecond)
	if ok {
		t.Fatal("expected ok == false when reconnect never succeeds")
	}
	calls := log.snapshot()
	if len(calls) < 2 || calls[len(calls)-1] != "persist:"+prevURL {
		t.Fatalf("persist calls = %v, want the last call to revert to the original host %q", calls, prevURL)
	}
	if detail == "" {
		t.Fatal("expected a non-empty detail mentioning the revert")
	}
}

func TestHandleSetServer_PersistFails_NeverAttemptsApply(t *testing.T) {
	applyCalled := false
	fakeSetServerSeams(t, "https://old:9443",
		func(serverURL string) error { return errors.New("registry write denied") },
		func(a *Agent, cfg Config) error {
			applyCalled = true
			return nil
		},
		func(a *Agent, host string) bool { return true },
	)

	a := newTestAgentForMutate(t)
	ok, _ := a.handleSetServerWithTimeout("https://10.0.0.5:9443", 200*time.Millisecond, 5*time.Millisecond)
	if ok {
		t.Fatal("expected ok == false when persist fails")
	}
	if applyCalled {
		t.Fatal("apply must never be attempted when persist fails")
	}
}

func TestHandleSetServer_ApplyFails_RollsBack(t *testing.T) {
	log := &callLog{}
	prevURL := "https://old:9443"
	fakeSetServerSeams(t, prevURL,
		func(serverURL string) error {
			log.add("persist:" + serverURL)
			return nil
		},
		func(a *Agent, cfg Config) error { return errors.New("apply failed") },
		func(a *Agent, host string) bool { return true },
	)

	a := newTestAgentForMutate(t)
	ok, _ := a.handleSetServerWithTimeout("https://10.0.0.5:9443", 200*time.Millisecond, 5*time.Millisecond)
	if ok {
		t.Fatal("expected ok == false when apply itself fails")
	}
	calls := log.snapshot()
	if len(calls) < 2 || calls[len(calls)-1] != "persist:"+prevURL {
		t.Fatalf("persist calls = %v, want the last call to revert to the original host %q", calls, prevURL)
	}
}

func TestHandleSetServer_RollbackPersistFails_ReportsRevertFailureHonestly(t *testing.T) {
	// Review Focus-adjacent: a rollback that itself fails must never be
	// reported as "reverted" -- the reviewer's finding #6.
	rollbackAttempts := 0
	fakeSetServerSeams(t, "https://old:9443",
		func(serverURL string) error {
			rollbackAttempts++
			if rollbackAttempts == 1 {
				return nil // the forward persist succeeds
			}
			return errors.New("registry busy") // the rollback persist fails
		},
		func(a *Agent, cfg Config) error { return errors.New("apply failed") },
		func(a *Agent, host string) bool { return true },
	)

	a := newTestAgentForMutate(t)
	ok, detail := a.handleSetServerWithTimeout("https://10.0.0.5:9443", 200*time.Millisecond, 5*time.Millisecond)
	if ok {
		t.Fatal("expected ok == false")
	}
	if detail == "" {
		t.Fatal("expected a detail message")
	}
	wantSubstr := "also failed"
	if !containsSubstr(detail, wantSubstr) {
		t.Fatalf("detail = %q, want it to mention the rollback itself failing (%q)", detail, wantSubstr)
	}
}

func containsSubstr(s, substr string) bool {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestHandleSetServer_ConcurrentCalls_Serialized(t *testing.T) {
	log := &callLog{}
	fakeSetServerSeams(t, "https://old:9443",
		func(serverURL string) error {
			log.add("persist-start:" + serverURL)
			time.Sleep(20 * time.Millisecond) // widen the window a race would need to land in
			log.add("persist-end:" + serverURL)
			return nil
		},
		func(a *Agent, cfg Config) error { return nil },
		func(a *Agent, host string) bool { return true },
	)

	a := newTestAgentForMutate(t)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		a.handleSetServerWithTimeout("https://host-a:9443", 200*time.Millisecond, 5*time.Millisecond)
	}()
	go func() {
		defer wg.Done()
		a.handleSetServerWithTimeout("https://host-b:9443", 200*time.Millisecond, 5*time.Millisecond)
	}()
	wg.Wait()

	calls := log.snapshot()
	if len(calls) != 4 {
		t.Fatalf("expected 4 recorded calls (start+end per call), got %v", calls)
	}
	// Serialized means each call's "-end" immediately follows its own
	// "-start", never another call's "-start" sneaking in between.
	for i := 0; i < len(calls); i += 2 {
		hostOfStart := calls[i][len("persist-start:"):]
		hostOfEnd := calls[i+1][len("persist-end:"):]
		if hostOfStart != hostOfEnd {
			t.Fatalf("calls interleaved: %v", calls)
		}
	}
}
