package reporting

import (
	"testing"
	"time"
)

func TestParseDLPEventStart_ExactlyOneMatchingMarker(t *testing.T) {
	raw := "EXEC T1052.001: copied\nDLP_EVENT_START: task-a 2026-10-20T04:39:43.4623678Z\nDLP_OBSERVATION: OperationSucceeded\n"
	at, reason := ParseDLPEventStart(raw, "task-a")
	if reason != "" {
		t.Fatalf("reason = %q, want empty", reason)
	}
	want := time.Date(2026, 10, 20, 4, 39, 43, 462367800, time.UTC)
	if !at.Equal(want) {
		t.Fatalf("at = %v, want %v", at, want)
	}
}

func TestParseDLPEventStart_IgnoresOtherTasksMarkers(t *testing.T) {
	raw := "DLP_EVENT_START: task-b 2026-10-20T04:39:43Z\n"
	at, reason := ParseDLPEventStart(raw, "task-a")
	if reason != "no_marker" || !at.IsZero() {
		t.Fatalf("got (%v, %q), want zero time and no_marker", at, reason)
	}
}

func TestParseDLPEventStart_NoMarker(t *testing.T) {
	at, reason := ParseDLPEventStart("DLP_OBSERVATION: OperationBlocked", "task-a")
	if reason != "no_marker" || !at.IsZero() {
		t.Fatalf("got (%v, %q), want zero time and no_marker", at, reason)
	}
}

func TestParseDLPEventStart_TwoMatchingMarkersAreAmbiguous(t *testing.T) {
	raw := "DLP_EVENT_START: task-a 2026-10-20T04:39:43Z\nDLP_EVENT_START: task-a 2026-10-20T04:39:44Z\n"
	at, reason := ParseDLPEventStart(raw, "task-a")
	if reason != "ambiguous" || !at.IsZero() {
		t.Fatalf("got (%v, %q), want zero time and ambiguous", at, reason)
	}
}

func TestParseDLPEventStart_UnparseableTimestamp(t *testing.T) {
	at, reason := ParseDLPEventStart("DLP_EVENT_START: task-a not-a-time", "task-a")
	if reason != "unparseable" || !at.IsZero() {
		t.Fatalf("got (%v, %q), want zero time and unparseable", at, reason)
	}
}

func TestParseDLPEventStart_EmptyTaskIDNeverMatches(t *testing.T) {
	at, reason := ParseDLPEventStart("DLP_EVENT_START: task-a 2026-10-20T04:39:43Z", "")
	if reason != "no_marker" || !at.IsZero() {
		t.Fatalf("got (%v, %q), want no_marker: an empty task id must never correlate", at, reason)
	}
}
