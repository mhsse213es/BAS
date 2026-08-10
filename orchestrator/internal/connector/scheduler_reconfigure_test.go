package connector

import (
	"testing"
	"time"
)

func TestReconfigure_UpdatesSourcesAndStatusFlags(t *testing.T) {
	s := NewScheduler(nil, nil, nil, 24, nil, nil)
	s.Reconfigure([]Source{fakeSource{name: "misp"}, fakeSource{name: "opencti"}})

	st := s.Status()
	if !st.MISPEnabled || !st.OpenCTIEnabled {
		t.Errorf("status = %+v, want MISPEnabled and OpenCTIEnabled both true", st)
	}

	s.Reconfigure([]Source{fakeSource{name: "opencti"}})
	st = s.Status()
	if st.MISPEnabled {
		t.Error("MISPEnabled still true after reconfiguring MISP out of the source list")
	}
	if !st.OpenCTIEnabled {
		t.Error("OpenCTIEnabled should still be true")
	}
}

func TestReconfigure_StartsBackgroundLoopOnFirstNonEmptySources(t *testing.T) {
	// NewScheduler with zero sources: Start() would see len(sources)==0 and
	// never launch the background goroutine -- exactly the "fresh install,
	// nothing configured yet" case. Reconfigure must detect that the
	// scheduler never actually started and launch it now, retroactively.
	s := NewScheduler(nil, nil, nil, 24, nil, nil)
	s.Start() // sources is empty -- run() must NOT be launched here

	s.Reconfigure([]Source{fakeSource{name: "misp"}})

	// s.started is set (under s.mu) the moment Reconfigure launches run();
	// give the goroutine a moment to actually set it before asserting.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		s.mu.RLock()
		started := s.started
		s.mu.RUnlock()
		if started {
			return // pass
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Error("started never became true after Reconfigure added the first source to a scheduler whose Start() saw zero sources")
}

func TestReconfigure_DoesNotDoubleStartAnAlreadyRunningScheduler(t *testing.T) {
	s := NewScheduler([]Source{fakeSource{name: "misp"}}, nil, nil, 24, nil, nil)
	s.Start() // sources non-empty -- run() launches here, s.started becomes true

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		s.mu.RLock()
		started := s.started
		s.mu.RUnlock()
		if started {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Reconfigure again -- must not attempt to launch a second run() goroutine.
	s.Reconfigure([]Source{fakeSource{name: "misp"}, fakeSource{name: "opencti"}})
	s.mu.RLock()
	sourceCount := len(s.sources)
	s.mu.RUnlock()
	if sourceCount != 2 {
		t.Errorf("source count = %d, want 2 (Reconfigure must still update sources even when already started)", sourceCount)
	}
}
