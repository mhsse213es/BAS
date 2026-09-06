//go:build windows

package pressure

import "testing"

// TestSampleHost_FirstCallReturnsNoBaseline proves the documented cold-start
// contract: the very first call in a fresh process has nothing to diff CPU
// time against, and must say so via an error rather than a real-looking
// (0, 0, nil). Keep this test first in the file -- it depends on being the
// very first call to sampleHost in the test binary's process.
func TestSampleHost_FirstCallReturnsNoBaseline(t *testing.T) {
	_, _, err := sampleHost()
	if err != ErrNoBaseline {
		t.Fatalf("sampleHost() first call: err = %v, want %v", err, ErrNoBaseline)
	}
}

// TestSampleHost_SecondCallReturnsPlausibleReading proves the mechanism
// itself works on a real Windows host: after establishing a baseline, a
// second call (with real elapsed time between the two syscalls) must return
// a real, in-range reading.
func TestSampleHost_SecondCallReturnsPlausibleReading(t *testing.T) {
	cpu, mem, err := sampleHost()
	if err != nil {
		t.Fatalf("sampleHost() second call: unexpected error %v", err)
	}
	if cpu < 0 || cpu > 100 {
		t.Errorf("sampleHost() cpuPercent = %v, want [0,100]", cpu)
	}
	if mem < 0 || mem > 100 {
		t.Errorf("sampleHost() memPercent = %v, want [0,100]", mem)
	}
	t.Logf("host: cpu=%.1f%% mem=%.1f%%", cpu, mem)
}

func TestSampleSelf_FirstCallReturnsNoBaseline(t *testing.T) {
	_, _, err := sampleSelf()
	if err != ErrNoBaseline {
		t.Fatalf("sampleSelf() first call: err = %v, want %v", err, ErrNoBaseline)
	}
}

func TestSampleSelf_SecondCallReturnsPlausibleReading(t *testing.T) {
	cpu, mem, err := sampleSelf()
	if err != nil {
		t.Fatalf("sampleSelf() second call: unexpected error %v", err)
	}
	if cpu < 0 || cpu > 100 {
		t.Errorf("sampleSelf() cpuPercent = %v, want [0,100]", cpu)
	}
	if mem < 0 || mem > 100 {
		t.Errorf("sampleSelf() memPercent = %v, want [0,100]", mem)
	}
	t.Logf("self: cpu=%.1f%% mem=%.1f%%", cpu, mem)
}
