//go:build darwin

package pressure

import "testing"

// Unlike Windows/Linux, this platform's sampleHost/sampleSelf are backed by
// `top -l 1 -n 0` and `ps -o rss=,%cpu=`, both of which are single-shot,
// OS-delta-computed readings -- there is no raw cumulative counter here that
// needs a second call to diff against, so there is no ErrNoBaseline cold
// start to test on this platform (see sample_darwin.go's doc comment).

func TestSampleHost_ReturnsPlausibleReading(t *testing.T) {
	cpu, mem, err := sampleHost()
	if err != nil {
		t.Fatalf("sampleHost(): unexpected error %v", err)
	}
	if cpu < 0 || cpu > 100 {
		t.Errorf("sampleHost() cpuPercent = %v, want [0,100]", cpu)
	}
	if mem < 0 || mem > 100 {
		t.Errorf("sampleHost() memPercent = %v, want [0,100]", mem)
	}
	t.Logf("host: cpu=%.1f%% mem=%.1f%%", cpu, mem)
}

func TestSampleSelf_ReturnsPlausibleReading(t *testing.T) {
	cpu, mem, err := sampleSelf()
	if err != nil {
		t.Fatalf("sampleSelf(): unexpected error %v", err)
	}
	if cpu < 0 || cpu > 100 {
		t.Errorf("sampleSelf() cpuPercent = %v, want [0,100]", cpu)
	}
	if mem < 0 || mem > 100 {
		t.Errorf("sampleSelf() memPercent = %v, want [0,100]", mem)
	}
	t.Logf("self: cpu=%.1f%% mem=%.1f%%", cpu, mem)
}
