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
	authCheck = func(cfg Config) error { return errors.New("server 401 on /api/heartbeat") }
	defer func() { dialTLSCheck, authCheck = origDial, origAuth }()

	a := newTestAgentForMutate(t)
	outcome, _ := a.handleTestServer("https://10.0.0.5:9443")
	if outcome != TestOutcomeServerRejected {
		t.Fatalf("outcome = %q, want %q", outcome, TestOutcomeServerRejected)
	}
}

// callLog records persist/restart calls in order, under its own mutex, so
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

func TestHandleSetServer_ReconnectSucceeds_ReturnsOK(t *testing.T) {
	origPersist, origRestart, origVerify := setServerPersist, setServerRestart, setServerVerifyReconnect
	setServerPersist = func(serverURL string) error { return nil }
	setServerRestart = func() error { return nil }
	setServerVerifyReconnect = func(a *Agent, host string) bool { return true }
	defer func() { setServerPersist, setServerRestart, setServerVerifyReconnect = origPersist, origRestart, origVerify }()

	a := newTestAgentForMutate(t)
	ok, _ := a.handleSetServerWithTimeout("https://10.0.0.5:9443", 200*time.Millisecond, 5*time.Millisecond)
	if !ok {
		t.Fatal("expected ok == true when reconnect succeeds")
	}
}

func TestHandleSetServer_ReconnectTimesOut_RollsBackAndReportsFailure(t *testing.T) {
	origPersist, origRestart, origVerify := setServerPersist, setServerRestart, setServerVerifyReconnect
	log := &callLog{}
	setServerPersist = func(serverURL string) error {
		log.add("persist:" + serverURL)
		return nil
	}
	setServerRestart = func() error { return nil }
	setServerVerifyReconnect = func(a *Agent, host string) bool { return false }
	defer func() { setServerPersist, setServerRestart, setServerVerifyReconnect = origPersist, origRestart, origVerify }()

	a := newTestAgentForMutate(t)
	prevURL := a.cfg().ServerURL
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

func TestHandleSetServer_PersistFails_NeverAttemptsRestart(t *testing.T) {
	origPersist, origRestart, origVerify := setServerPersist, setServerRestart, setServerVerifyReconnect
	restartCalled := false
	setServerPersist = func(serverURL string) error { return errors.New("registry write denied") }
	setServerRestart = func() error {
		restartCalled = true
		return nil
	}
	setServerVerifyReconnect = func(a *Agent, host string) bool { return true }
	defer func() { setServerPersist, setServerRestart, setServerVerifyReconnect = origPersist, origRestart, origVerify }()

	a := newTestAgentForMutate(t)
	ok, _ := a.handleSetServerWithTimeout("https://10.0.0.5:9443", 200*time.Millisecond, 5*time.Millisecond)
	if ok {
		t.Fatal("expected ok == false when persist fails")
	}
	if restartCalled {
		t.Fatal("restart must never be attempted when persist fails")
	}
}

func TestHandleSetServer_RestartLaunchFails_RollsBack(t *testing.T) {
	origPersist, origRestart, origVerify := setServerPersist, setServerRestart, setServerVerifyReconnect
	log := &callLog{}
	setServerPersist = func(serverURL string) error {
		log.add("persist:" + serverURL)
		return nil
	}
	setServerRestart = func() error { return errors.New("SCM StartService failed") }
	setServerVerifyReconnect = func(a *Agent, host string) bool { return true }
	defer func() { setServerPersist, setServerRestart, setServerVerifyReconnect = origPersist, origRestart, origVerify }()

	a := newTestAgentForMutate(t)
	prevURL := a.cfg().ServerURL
	ok, _ := a.handleSetServerWithTimeout("https://10.0.0.5:9443", 200*time.Millisecond, 5*time.Millisecond)
	if ok {
		t.Fatal("expected ok == false when the restart trigger itself fails to launch")
	}
	calls := log.snapshot()
	if len(calls) < 2 || calls[len(calls)-1] != "persist:"+prevURL {
		t.Fatalf("persist calls = %v, want the last call to revert to the original host %q", calls, prevURL)
	}
}

func TestHandleSetServer_ConcurrentCalls_Serialized(t *testing.T) {
	origPersist, origRestart, origVerify := setServerPersist, setServerRestart, setServerVerifyReconnect
	log := &callLog{}
	setServerPersist = func(serverURL string) error {
		log.add("persist-start:" + serverURL)
		time.Sleep(20 * time.Millisecond) // widen the window a race would need to land in
		log.add("persist-end:" + serverURL)
		return nil
	}
	setServerRestart = func() error { return nil }
	setServerVerifyReconnect = func(a *Agent, host string) bool { return true }
	defer func() { setServerPersist, setServerRestart, setServerVerifyReconnect = origPersist, origRestart, origVerify }()

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
