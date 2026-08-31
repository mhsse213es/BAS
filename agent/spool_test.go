package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"audspect/agent/protocol"
)

// newSpoolTestAgent wires an Agent at a temp spool dir pointed at the given server.
func newSpoolTestAgent(t *testing.T, serverURL string) *Agent {
	t.Helper()
	dir := t.TempDir()
	spoolDirOverride = dir
	t.Cleanup(func() { spoolDirOverride = "" })
	return &Agent{
		cfg:       Config{ServerURL: serverURL},
		client:    http.DefaultClient,
		spoolKick: make(chan struct{}, 1),
	}
}

func TestSpoolWriteRoundTrip(t *testing.T) {
	a := newSpoolTestAgent(t, "http://127.0.0.1:0")
	payload := protocol.RawRunResult{RunID: "run-123", ScenarioID: "scn-1", AgentID: "agt-1", Partial: true}

	path, err := a.spoolWrite(payload, "partial")
	if err != nil {
		t.Fatalf("spoolWrite: %v", err)
	}
	if filepath.Base(path) != "run-123.json" {
		t.Errorf("spool filename = %q, want run-123.json", filepath.Base(path))
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read spooled file: %v", err)
	}
	var env spooledResult
	if err := json.Unmarshal(data, &env); err != nil {
		t.Fatalf("unmarshal envelope: %v", err)
	}
	if env.Label != "partial" || env.Payload.RunID != "run-123" || !env.Payload.Partial {
		t.Errorf("round-trip mismatch: %+v", env)
	}
}

func TestSpoolWriteOverwritesSameRun(t *testing.T) {
	a := newSpoolTestAgent(t, "http://127.0.0.1:0")
	if _, err := a.spoolWrite(protocol.RawRunResult{RunID: "run-x", Partial: true}, "partial"); err != nil {
		t.Fatal(err)
	}
	if _, err := a.spoolWrite(protocol.RawRunResult{RunID: "run-x", Partial: false}, "completed"); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(resolveSpoolDir())
	if len(entries) != 1 {
		t.Fatalf("re-spooling same run left %d files, want 1 (overwrite)", len(entries))
	}
}

func TestDrainSpoolDeliversAndDeletes(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/scenarios/result" {
			atomic.AddInt32(&hits, 1)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	a := newSpoolTestAgent(t, srv.URL)
	if _, err := a.spoolWrite(protocol.RawRunResult{RunID: "run-a"}, "completed"); err != nil {
		t.Fatal(err)
	}
	if _, err := a.spoolWrite(protocol.RawRunResult{RunID: "run-b"}, "completed"); err != nil {
		t.Fatal(err)
	}

	a.drainSpool()

	if got := atomic.LoadInt32(&hits); got != 2 {
		t.Errorf("server received %d submissions, want 2", got)
	}
	entries, _ := os.ReadDir(resolveSpoolDir())
	if len(entries) != 0 {
		t.Errorf("spool still holds %d files after successful drain, want 0", len(entries))
	}
}

func TestDrainSpoolKeepsFileWhenServerDown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	a := newSpoolTestAgent(t, srv.URL)
	if _, err := a.spoolWrite(protocol.RawRunResult{RunID: "run-stuck"}, "partial"); err != nil {
		t.Fatal(err)
	}

	a.drainSpool()

	entries, _ := os.ReadDir(resolveSpoolDir())
	if len(entries) != 1 {
		t.Errorf("failed delivery left %d files, want 1 (retained for retry)", len(entries))
	}
}

func TestDrainSpoolDropsCorruptEnvelope(t *testing.T) {
	a := newSpoolTestAgent(t, "http://127.0.0.1:0")
	bad := filepath.Join(resolveSpoolDir(), "garbage.json")
	if err := os.WriteFile(bad, []byte("{not valid json"), 0o600); err != nil {
		t.Fatal(err)
	}

	a.drainSpool()

	if _, err := os.Stat(bad); !os.IsNotExist(err) {
		t.Errorf("corrupt envelope was not dropped (it would wedge the queue forever)")
	}
}
