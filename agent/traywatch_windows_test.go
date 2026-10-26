//go:build windows

package main

import (
	"testing"
	"time"
)

func TestShouldRelaunchTray(t *testing.T) {
	now := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	past := now.Add(-time.Minute)
	future := now.Add(time.Minute)

	cases := []struct {
		name       string
		retryAfter time.Time
		alive      bool
		want       bool
	}{
		{"tray is running: leave it alone", past, true, false},
		{"tray is gone and no back-off: start it", past, false, true},
		{"tray is gone but a duplicate was seen recently: wait", future, false, false},
		{"back-off expires exactly now: start it", now, false, true},
		{"running and backed off: leave it alone", future, true, false},
	}
	for _, c := range cases {
		if got := shouldRelaunchTray(now, c.retryAfter, c.alive); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

func TestNoteTrayDuplicateSuppressesTheWatchdogForTheBackoffWindow(t *testing.T) {
	defer trayRetryAfter.Store(trayRetryAfter.Load())
	now := time.Now()
	noteTrayDuplicate(now)
	retry := time.Unix(0, trayRetryAfter.Load())
	if shouldRelaunchTray(now.Add(time.Minute), retry, false) {
		t.Fatal("watchdog restarted a tray inside the back-off window")
	}
	if !shouldRelaunchTray(now.Add(trayDuplicateBackoff+time.Second), retry, false) {
		t.Fatal("watchdog never resumed after the back-off window")
	}
}
