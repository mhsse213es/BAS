package main

import (
	"testing"
	"time"

	"audspect/agent/protocol"
)

// A step still writing when its deadline fires must be distinguishable from one
// that was silent. The execute deadline is pure wall-clock and kills both
// identically; the only thing that separates them afterwards is this record.
func TestStepTermination_BusyStepRecordsRecentOutput(t *testing.T) {
	before := time.Now().Add(-120 * time.Second)
	endedAt := before.Add(120 * time.Second)

	stdout := newCappedBuffer(8192)
	stderr := newCappedBuffer(8192)
	stdout.Write([]byte("still going"))
	// Force the stamp to 300ms before the kill.
	stdout.mu.Lock()
	stdout.last = endedAt.Add(-300 * time.Millisecond)
	stdout.mu.Unlock()

	got := stepTermination(protocol.TermExecutionTimeout, before, endedAt, stdout, stderr)
	if got == nil {
		t.Fatal("no termination record for a timed-out step")
	}
	if got.Reason != protocol.TermExecutionTimeout {
		t.Errorf("Reason = %q, want %q", got.Reason, protocol.TermExecutionTimeout)
	}
	if got.ElapsedMs != 120000 {
		t.Errorf("ElapsedMs = %d, want 120000", got.ElapsedMs)
	}
	if got.OutputBytes != int64(len("still going")) {
		t.Errorf("OutputBytes = %d, want %d", got.OutputBytes, len("still going"))
	}
	if got.SilenceMs != 300 {
		t.Errorf("SilenceMs = %d, want 300", got.SilenceMs)
	}
}

// A step that never wrote has been silent for its whole run — not for zero
// milliseconds, which is what a naive "now minus last write" would report
// against a zero timestamp.
func TestStepTermination_SilentStepIsSilentForWholeWindow(t *testing.T) {
	before := time.Now().Add(-120 * time.Second)
	endedAt := before.Add(120 * time.Second)

	got := stepTermination(protocol.TermExecutionTimeout, before, endedAt,
		newCappedBuffer(8192), newCappedBuffer(8192))
	if got == nil {
		t.Fatal("no termination record")
	}
	if got.OutputBytes != 0 {
		t.Errorf("OutputBytes = %d, want 0", got.OutputBytes)
	}
	if got.SilenceMs != got.ElapsedMs {
		t.Errorf("SilenceMs = %d, want it to equal ElapsedMs %d", got.SilenceMs, got.ElapsedMs)
	}
}

// Silence is measured against the LATER of the two streams. A step writing only
// to stderr is still a step producing output; reading stdout alone would report
// it as silent.
func TestStepTermination_StderrOnlyStepIsNotSilent(t *testing.T) {
	before := time.Now().Add(-60 * time.Second)
	endedAt := before.Add(60 * time.Second)

	stdout := newCappedBuffer(8192)
	stderr := newCappedBuffer(8192)
	stderr.Write([]byte("Permission denied"))
	stderr.mu.Lock()
	stderr.last = endedAt.Add(-500 * time.Millisecond)
	stderr.mu.Unlock()

	got := stepTermination(protocol.TermExecutionTimeout, before, endedAt, stdout, stderr)
	if got.SilenceMs != 500 {
		t.Errorf("SilenceMs = %d, want 500 — a stderr-only step is not silent", got.SilenceMs)
	}
	if got.OutputBytes != int64(len("Permission denied")) {
		t.Errorf("OutputBytes = %d, want %d", got.OutputBytes, len("Permission denied"))
	}
}

// The count must include bytes discarded past the retention cap. A step that
// emitted 400 MB is exactly the case worth knowing about, and the retained
// slice is capped at 8 KB.
func TestStepTermination_CountsDiscardedBytes(t *testing.T) {
	before := time.Now().Add(-10 * time.Second)
	endedAt := before.Add(10 * time.Second)

	stdout := newCappedBuffer(16)
	stdout.Write(make([]byte, 100000))

	got := stepTermination(protocol.TermExecutionTimeout, before, endedAt, stdout, newCappedBuffer(16))
	if got.OutputBytes != 100000 {
		t.Errorf("OutputBytes = %d, want 100000 (retained slice is only 16 bytes)", got.OutputBytes)
	}
}

// A step that exited on its own gets no record. This is evidence about OUR
// kills, and a nil record is what tells a reader nothing was measured.
func TestStepTermination_NoRecordForNormalExit(t *testing.T) {
	if got := stepTermination("", time.Now(), time.Now(), newCappedBuffer(8), newCappedBuffer(8)); got != nil {
		t.Errorf("got %+v, want nil for a step that was not terminated", got)
	}
}

// A write can land between endedAt and the read, which would otherwise produce
// a negative duration in a client-facing report.
func TestStepTermination_NegativeSilenceIsClamped(t *testing.T) {
	before := time.Now().Add(-10 * time.Second)
	endedAt := before.Add(10 * time.Second)

	stdout := newCappedBuffer(8192)
	stdout.Write([]byte("late"))
	stdout.mu.Lock()
	stdout.last = endedAt.Add(2 * time.Second) // after the kill
	stdout.mu.Unlock()

	got := stepTermination(protocol.TermExecutionTimeout, before, endedAt, stdout, newCappedBuffer(8192))
	if got.SilenceMs != 0 {
		t.Errorf("SilenceMs = %d, want 0 — a negative silence must never be reported", got.SilenceMs)
	}
}

// The operator-facing note must carry the evidence, and must keep the phrase
// the server's fallback timeout detection keys on.
func TestTerminationEvidence_Rendering(t *testing.T) {
	cases := []struct {
		name string
		in   *protocol.StepTermination
		want string
	}{
		{"not reported", nil, ""},
		{"silent", &protocol.StepTermination{OutputBytes: 0, SilenceMs: 120000},
			"; output=0 bytes; no output at any point"},
		{"busy", &protocol.StepTermination{OutputBytes: 4404019, SilenceMs: 300},
			"; output=4.2 MB; last output=300ms ago"},
	}
	for _, tc := range cases {
		if got := terminationEvidence(tc.in); got != tc.want {
			t.Errorf("%s: got %q, want %q", tc.name, got, tc.want)
		}
	}
}
