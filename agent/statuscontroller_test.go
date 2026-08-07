//go:build windows

package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"audspect/agent/statusclient"
)

// fakeWindow records every Refresh call so tests can assert on cadence and content.
type fakeWindow struct {
	mu        sync.Mutex
	refreshes []StatusSnapshot
}

func (f *fakeWindow) Show() error { return nil }
func (f *fakeWindow) Close()      {}
func (f *fakeWindow) Refresh(s StatusSnapshot) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.refreshes = append(f.refreshes, s)
}
func (f *fakeWindow) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.refreshes)
}
func (f *fakeWindow) last() StatusSnapshot {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.refreshes[len(f.refreshes)-1]
}

func newTestServer(t *testing.T, running bool) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/status":
			json.NewEncoder(w).Encode(statusclient.StatusResponse{Hostname: "H", ServerConnected: true})
		case "/activity":
			var cur *statusclient.Operation
			if running {
				cur = &statusclient.Operation{Running: true, ScenarioName: "test-scenario"}
			}
			json.NewEncoder(w).Encode(statusclient.ActivityResponse{CurrentOperation: cur})
		case "/evidence":
			json.NewEncoder(w).Encode(statusclient.EvidenceResponse{})
		case "/controls":
			json.NewEncoder(w).Encode(statusclient.ControlsResponse{})
		}
	}))
}

func TestStatusController_Run_RefreshesUntilStopped(t *testing.T) {
	srv := newTestServer(t, false)
	defer srv.Close()

	win := &fakeWindow{}
	c := NewStatusController(statusclient.New(srv.Listener.Addr().String(), ""), win)
	go c.Run()
	defer c.Stop()

	deadline := time.Now().Add(2 * time.Second)
	for win.count() < 1 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if win.count() < 1 {
		t.Fatal("expected at least one Refresh call")
	}
	if !win.last().Online {
		t.Fatalf("last snapshot Online = false, want true")
	}
}

func TestPollInterval_FastWhileRunning_SlowWhenIdle(t *testing.T) {
	running := StatusSnapshot{Activity: statusclient.ActivityResponse{
		CurrentOperation: &statusclient.Operation{Running: true},
	}}
	idle := StatusSnapshot{Activity: statusclient.ActivityResponse{}}

	if got := pollInterval(running); got != 1*time.Second {
		t.Errorf("pollInterval(running) = %v, want 1s", got)
	}
	if got := pollInterval(idle); got != 5*time.Second {
		t.Errorf("pollInterval(idle) = %v, want 5s", got)
	}
}

func TestStatusController_Poll_OfflineWhenUnreachable(t *testing.T) {
	c := NewStatusController(statusclient.New("127.0.0.1:1", ""), &fakeWindow{})
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	snap := c.pollWithContext(ctx)
	if snap.Online {
		t.Fatal("expected Online = false when the local API is unreachable")
	}
}
