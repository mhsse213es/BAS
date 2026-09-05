package main

import (
	"encoding/json"
	"sync"
	"testing"
	"time"

	"audspect/agent/protocol"
)

func TestEventForResult(t *testing.T) {
	cases := []struct {
		name    string
		res     protocol.ExecResult
		typ     string
		verdict string
	}{
		{"pass", protocol.ExecResult{ExitCode: 0}, "completed", "pass"},
		{"fail", protocol.ExecResult{ExitCode: 1}, "completed", "fail"},
		{"blocked", protocol.ExecResult{ExitCode: -1, Blocked: true}, "completed", "blocked"},
		{"timeout", protocol.ExecResult{ExitCode: -1, TimedOut: true}, "timeout", ""},
		// ExitCode -1 with neither TimedOut nor Blocked set is this codebase's
		// own agent-side sentinel for "we didn't get a real result" (see
		// executor.go's cmd.Start() failure, WaitDelay-abandoned, and
		// scenario-cancellation paths, which all set exactly this shape) --
		// never a genuine command exit code. Must report as "error", not
		// "fail": a step whose process never even launched (e.g. "fork/exec
		// ...: Access is denied") is not evidence a control failed to block
		// anything, and the frontend's VERDICT_LABEL already renders "error"
		// as a neutral "Error" badge distinct from "Not Prevented".
		{"execution-error (process never launched)", protocol.ExecResult{ExitCode: -1}, "completed", "error"},
	}
	for _, c := range cases {
		typ, verdict := eventForResult(c.res)
		if typ != c.typ || verdict != c.verdict {
			t.Errorf("%s: got (%q,%q) want (%q,%q)", c.name, typ, verdict, c.typ, c.verdict)
		}
	}
}

type fakeSender struct {
	mu      sync.Mutex
	batches [][]RunEvent
	fail    bool
}

func (f *fakeSender) send(b []RunEvent) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail {
		return errFakeSend
	}
	cp := make([]RunEvent, len(b))
	copy(cp, b)
	f.batches = append(f.batches, cp)
	return nil
}
func (f *fakeSender) total() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, b := range f.batches {
		n += len(b)
	}
	return n
}

var errFakeSend = errFake("send failed")

type errFake string

func (e errFake) Error() string { return string(e) }

func TestEmitterFlushesAndDelivers(t *testing.T) {
	fs := &fakeSender{}
	em := newEventEmitter(fs.send, 100, 10*time.Millisecond)
	for i := 0; i < 5; i++ {
		em.emit(RunEvent{Type: "started", Seq: int64(i)})
	}
	em.close()
	if fs.total() != 5 {
		t.Fatalf("delivered %d events, want 5", fs.total())
	}
}

func TestEmitterBoundedDropsAndNeverBlocks(t *testing.T) {
	fs := &fakeSender{fail: true}
	em := newEventEmitter(fs.send, 50, time.Hour)
	done := make(chan struct{})
	go func() {
		for i := 0; i < 100000; i++ {
			em.emit(RunEvent{Type: "started", Seq: int64(i)})
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("emit blocked — bounded queue must drop, never block the run")
	}
	em.close()
}

// TestEmitCritical_SurvivesQueueEviction reproduces the "264/0" production
// bug: run_started is always the first event emitted, so on a large sweep
// (e.g. 314 ART techniques) the burst of "queued" events that immediately
// follows can fill the bounded queue while the consumer goroutine is
// blocked inside a single slow send() call -- at which point emit()'s
// drop-oldest eviction discards run_started first, since it's the oldest
// item in the queue. scenario_runs.steps_total is set exclusively from
// run_started's payload (event_handlers.go), so losing it leaves the run's
// progress total stuck at 0 forever even though hundreds of subsequent
// step-completion events arrive fine. emitCritical must bypass the queue
// entirely so run_started can never be evicted this way.
func TestEmitCritical_SurvivesQueueEviction(t *testing.T) {
	var mu sync.Mutex
	var batches [][]RunEvent
	firstCall := make(chan struct{})
	release := make(chan struct{})
	callCount := 0
	send := func(b []RunEvent) error {
		mu.Lock()
		callCount++
		isFirst := callCount == 1
		cp := make([]RunEvent, len(b))
		copy(cp, b)
		batches = append(batches, cp)
		mu.Unlock()
		if isFirst {
			close(firstCall)
			<-release // hold the consumer inside send() so the queue can fill behind it
		}
		return nil
	}

	em := newEventEmitter(send, 5, 5*time.Millisecond) // tiny queue -- easy to overflow
	em.emitCritical(RunEvent{Type: "run_started", Seq: 0})

	<-firstCall // consumer is now blocked inside the first send() call

	// Flood well past the queue's capacity while the consumer can't drain --
	// this is what a 314-technique sweep's burst of "queued" events does.
	for i := 1; i <= 50; i++ {
		em.emit(RunEvent{Type: "queued", Seq: int64(i)})
	}

	close(release)
	em.close()

	mu.Lock()
	defer mu.Unlock()
	for _, b := range batches {
		for _, ev := range b {
			if ev.Type == "run_started" {
				return // survived -- test passes
			}
		}
	}
	t.Fatal("run_started was dropped by queue eviction under load -- emitCritical must bypass the bounded queue")
}

func TestHeartbeatAdvertisesCapability(t *testing.T) {
	hb := protocol.Heartbeat{AgentID: "a", ProtocolVersion: protocol.ProtocolVersion, EmitsEvents: true}
	raw, _ := json.Marshal(hb)
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	if m["protocolVersion"] != float64(2) {
		t.Errorf("protocolVersion = %v, want 2", m["protocolVersion"])
	}
	if m["emitsEvents"] != true {
		t.Errorf("emitsEvents = %v, want true", m["emitsEvents"])
	}
}
