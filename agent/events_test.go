package main

import (
	"encoding/json"
	"sync"
	"testing"
	"time"
)

func TestEventForResult(t *testing.T) {
	cases := []struct {
		name    string
		res     ExecResult
		typ     string
		verdict string
	}{
		{"pass", ExecResult{ExitCode: 0}, "completed", "pass"},
		{"fail", ExecResult{ExitCode: 1}, "completed", "fail"},
		{"blocked", ExecResult{ExitCode: -1, Blocked: true}, "completed", "blocked"},
		{"timeout", ExecResult{ExitCode: -1, TimedOut: true}, "timeout", ""},
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

func TestHeartbeatAdvertisesCapability(t *testing.T) {
	hb := Heartbeat{AgentID: "a", ProtocolVersion: protocolVersion, EmitsEvents: true}
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
