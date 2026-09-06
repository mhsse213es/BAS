package main

import (
	"testing"
	"time"
)

func TestWsBackoffDelay_DoublesUpToCap(t *testing.T) {
	cases := []struct {
		attempt int
		want    time.Duration
	}{
		{0, 1 * time.Second},
		{1, 2 * time.Second},
		{2, 4 * time.Second},
		{3, 8 * time.Second},
		{4, 16 * time.Second},
		{5, 32 * time.Second},
		{6, 64 * time.Second},
		{7, wsBackoffMax}, // 128s would exceed the 120s cap
		{8, wsBackoffMax},
		{100, wsBackoffMax}, // must never overflow or wrap for large attempt counts
	}
	for _, c := range cases {
		got := wsBackoffDelay(c.attempt)
		if got != c.want {
			t.Errorf("wsBackoffDelay(%d) = %s, want %s", c.attempt, got, c.want)
		}
	}
}

func TestWsBackoffDelay_NegativeAttemptTreatedAsZero(t *testing.T) {
	if got := wsBackoffDelay(-5); got != wsBackoffBase {
		t.Errorf("wsBackoffDelay(-5) = %s, want %s", got, wsBackoffBase)
	}
}

func TestWsJitter_StaysWithinBounds(t *testing.T) {
	d := 10 * time.Second
	for i := 0; i < 200; i++ {
		got := wsJitter(d)
		if got < 0 || got > d {
			t.Fatalf("wsJitter(%s) = %s, out of [0, %s]", d, got, d)
		}
	}
}

func TestWsJitter_ZeroStaysZero(t *testing.T) {
	if got := wsJitter(0); got != 0 {
		t.Errorf("wsJitter(0) = %s, want 0", got)
	}
}

// TestWsJitter_ActuallyVaries proves full jitter -- not a fixed fraction of
// d -- by sampling many draws and checking they're not all identical. A flaky
// failure here (extraordinarily unlikely: identical int64 draws 50 times in a
// row) would indicate rand is seeded to a constant, not that jitter is absent.
func TestWsJitter_ActuallyVaries(t *testing.T) {
	d := 10 * time.Second
	first := wsJitter(d)
	varied := false
	for i := 0; i < 50; i++ {
		if wsJitter(d) != first {
			varied = true
			break
		}
	}
	if !varied {
		t.Error("wsJitter produced the same value 50 times in a row -- jitter is not varying")
	}
}

func TestWsShouldResetBackoff_ResetsOnRealMessage(t *testing.T) {
	// Even a connection that lasted a few milliseconds resets the backoff if a
	// real application message was exchanged -- that's stronger evidence than
	// mere elapsed time.
	if !wsShouldResetBackoff(50*time.Millisecond, true) {
		t.Error("expected reset when a message was received, regardless of how briefly the connection lasted")
	}
}

func TestWsShouldResetBackoff_ResetsAfterSurvivingHealthyWindow(t *testing.T) {
	if !wsShouldResetBackoff(wsHealthyConnection, false) {
		t.Error("expected reset once the connection survived the healthy-connection window, even with no message")
	}
	if !wsShouldResetBackoff(wsHealthyConnection+time.Second, false) {
		t.Error("expected reset comfortably past the healthy-connection window")
	}
}

func TestWsShouldResetBackoff_NoResetForQuickBounce(t *testing.T) {
	// The exact scenario the reset logic must guard against: the HTTP upgrade
	// succeeds (Dial returns no error) but the server immediately closes the
	// connection -- e.g. capacity shedding or a duplicate agentId kick -- before
	// any real message and well short of the healthy-connection window.
	if wsShouldResetBackoff(200*time.Millisecond, false) {
		t.Error("must not reset backoff for a connection that bounced immediately with no message exchanged")
	}
}

func TestWsReconnectBackoff_NeverExceedsCap(t *testing.T) {
	for attempt := 0; attempt <= 20; attempt++ {
		for i := 0; i < 20; i++ {
			got := wsReconnectBackoff(attempt)
			if got > wsBackoffMax {
				t.Fatalf("wsReconnectBackoff(%d) = %s, exceeds cap %s", attempt, got, wsBackoffMax)
			}
			if got < 0 {
				t.Fatalf("wsReconnectBackoff(%d) = %s, negative", attempt, got)
			}
		}
	}
}
