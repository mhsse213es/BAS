//go:build windows

package main

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
)

const otherUserSID = "S-1-5-21-1111111111-2222222222-3333333333-1001"

func processSID(t *testing.T) string {
	t.Helper()
	tu, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	return tu.User.Sid.String()
}

// In production the pipe is created by SYSTEM (the service) while its ACL names the logged-in user. go-winio opens the
// existing pipe with read/write access to create every instance after the first, so the creator must be in the ACL too
// or the listener dies on its first Accept and every client waits for a pipe that never opens (the Settings window's
// Test then timed out although the server was connected).
func TestPipeSDDL_GrantsTheCreatorAndTheLoggedInUserAndNobodyElse(t *testing.T) {
	got := pipeSDDL(otherUserSID, "S-1-5-18")
	want := "D:(A;;GA;;;S-1-5-18)(A;;GA;;;" + otherUserSID + ")"
	if got != want {
		t.Errorf("pipeSDDL = %q, want %q", got, want)
	}
	if same := pipeSDDL("S-1-5-18", "S-1-5-18"); same != "D:(A;;GA;;;S-1-5-18)" {
		t.Errorf("one identity must be granted once, got %q", same)
	}
}

func TestMutatePipe_IsReachableWhenTheLoggedInUserIsNotTheCreator(t *testing.T) {
	old := resolvePipeSDDL
	resolvePipeSDDL = func() (string, error) { return pipeSDDL(otherUserSID, processSID(t)), nil }
	defer func() { resolvePipeSDDL = old }()

	path := testMutatePipePath(t)
	if err := startMutatePipeListener(path, func() int32 { return 0 }, nil); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := winio.DialPipeContext(ctx, path)
	if err != nil {
		t.Fatalf("the pipe must be open for a client (creator and user both in the ACL): %v", err)
	}
	conn.Close()
}

// ---- the accept loop ----

type scriptedListener struct {
	steps []error // one entry per Accept: nil means "a connection arrives"
	i     int
}

type nopConn struct{ net.Conn }

func (nopConn) Close() error { return nil }

func (l *scriptedListener) Accept() (net.Conn, error) {
	if l.i >= len(l.steps) {
		return nil, net.ErrClosed
	}
	e := l.steps[l.i]
	l.i++
	if e != nil {
		return nil, e
	}
	return nopConn{}, nil
}
func (l *scriptedListener) Close() error   { return nil }
func (l *scriptedListener) Addr() net.Addr { return nil }

// A failed Accept used to end the loop for good, leaving the pipe visible but never answering.
func TestServeListener_KeepsAcceptingAfterAFailedAccept(t *testing.T) {
	l := &scriptedListener{steps: []error{errors.New("transient"), errors.New("transient"), nil, nil}}
	var served atomic.Int32
	serveListener(l, func(net.Conn) { served.Add(1) }, time.Millisecond, func(string, ...any) {})
	deadline := time.Now().Add(2 * time.Second)
	for served.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if served.Load() != 2 {
		t.Errorf("connections served = %d, want 2 (the loop must survive the two failed accepts)", served.Load())
	}
}

func TestServeListener_StopsWhenTheListenerIsClosed(t *testing.T) {
	l := &scriptedListener{steps: nil} // first Accept returns net.ErrClosed
	done := make(chan struct{})
	go func() { serveListener(l, func(net.Conn) {}, time.Millisecond, func(string, ...any) {}); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("the loop must end when the listener is closed")
	}
}
