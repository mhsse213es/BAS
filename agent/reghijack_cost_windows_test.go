//go:build windows

package main

import (
	"testing"
	"time"
)

// A snapshot is taken at the start of every run, so recording the guarded roots must stay quick, and a root too large
// to record exactly must be reported as such rather than silently half-guarded.
func TestRegGuard_RecordingEveryDefaultRootIsFastOnARealMachine(t *testing.T) {
	start := time.Now()
	g := captureRegGuard("cost-check")
	took := time.Since(start)
	if g == nil {
		t.Fatal("no guard taken")
	}
	truncated := 0
	for _, st := range g.Roots {
		if st.Truncated {
			truncated++
			t.Logf("too large to record exactly, left alone: %s", st.Root)
		}
	}
	t.Logf("recorded %d roots in %v (%d too large)", len(g.Roots), took, truncated)
	if took > 10*time.Second {
		t.Errorf("recording the roots took %v: the run would start noticeably late", took)
	}
	g.restore() // nothing changed: touches nothing
}
