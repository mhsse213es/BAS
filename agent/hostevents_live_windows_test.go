//go:build windows

package main

import (
	"os"
	"testing"
	"time"
)

// Runs the real collector against this host. It is skipped unless
// AUDSPECT_LIVE_HOSTEVENTS=1, because it reads the Security log.
func TestLiveHostEvents_CollectsAndProbesThisHost(t *testing.T) {
	if os.Getenv("AUDSPECT_LIVE_HOSTEVENTS") != "1" {
		t.Skip("set AUDSPECT_LIVE_HOSTEVENTS=1 to read this host's Security log")
	}
	to := time.Now()
	from := to.Add(-30 * time.Minute)
	recs, truncated, err := collectHostEvents(from, to, 500)
	if err != nil {
		t.Fatal(err)
	}
	counts := map[int]int{}
	for _, r := range recs {
		counts[r.EventID]++
		if r.EventID != 4688 && r.EventID != 4624 && r.EventID != 4648 {
			t.Fatalf("collected an event outside the required set: %d", r.EventID)
		}
		if r.EventID == 4624 && r.LogonType != 3 && r.LogonType != 10 {
			t.Fatalf("kept a logon type outside 3 and 10: %d", r.LogonType)
		}
	}
	audit := probeAudit()
	t.Logf("window %s to %s: events=%v truncated=%v audit=%+v", from.Format(time.RFC3339), to.Format(time.RFC3339), counts, truncated, audit)
}
