package connector

import (
	"testing"
	"time"
)

// observedAtOrNow must never return the Go zero time: a MISP event with a
// missing or unparseable timestamp would otherwise stamp 0001-01-01 into the
// threat clock and the threat_observed SLA event.
func TestObservedAtOrNow(t *testing.T) {
	before := time.Now().Add(-time.Second)

	// Missing / unparseable -> a sane recent time, never zero.
	for _, ts := range []string{"", "not-a-timestamp"} {
		got := observedAtOrNow(ts)
		if got.IsZero() {
			t.Fatalf("observedAtOrNow(%q) returned the zero time", ts)
		}
		if got.Before(before) {
			t.Fatalf("observedAtOrNow(%q) = %v, expected ~now", ts, got)
		}
	}

	// A valid MISP epoch string is preserved exactly.
	if got := observedAtOrNow("1700000000"); !got.Equal(time.Unix(1700000000, 0)) {
		t.Fatalf("observedAtOrNow(epoch) = %v, want %v", got, time.Unix(1700000000, 0))
	}

	// A valid RFC3339 string is preserved exactly.
	want, _ := time.Parse(time.RFC3339, "2026-10-01T12:00:00Z")
	if got := observedAtOrNow("2026-10-01T12:00:00Z"); !got.Equal(want) {
		t.Fatalf("observedAtOrNow(rfc3339) = %v, want %v", got, want)
	}
}
