//go:build darwin

package pressure

import "testing"

// Unlike Windows/Linux, this platform's SampleHost/SampleSelf are backed by
// `top -l 1 -n 0` and `ps -o rss=,%cpu=`, both of which are single-shot,
// OS-delta-computed readings -- there is no raw cumulative counter here that
// needs a second call to diff against, so there is no ErrNoBaseline cold
// start to test on this platform (see sample_darwin.go's doc comment).

func TestSampleHost_ReturnsPlausibleReading(t *testing.T) {
	cpu, mem, err := SampleHost()
	if err != nil {
		t.Fatalf("SampleHost(): unexpected error %v", err)
	}
	if cpu < 0 || cpu > 100 {
		t.Errorf("SampleHost() cpuPercent = %v, want [0,100]", cpu)
	}
	if mem < 0 || mem > 100 {
		t.Errorf("SampleHost() memPercent = %v, want [0,100]", mem)
	}
	t.Logf("host: cpu=%.1f%% mem=%.1f%%", cpu, mem)
}

func TestSampleSelf_ReturnsPlausibleReading(t *testing.T) {
	cpu, mem, err := SampleSelf()
	if err != nil {
		t.Fatalf("SampleSelf(): unexpected error %v", err)
	}
	if cpu < 0 || cpu > 100 {
		t.Errorf("SampleSelf() cpuPercent = %v, want [0,100]", cpu)
	}
	if mem < 0 || mem > 100 {
		t.Errorf("SampleSelf() memPercent = %v, want [0,100]", mem)
	}
	t.Logf("self: cpu=%.1f%% mem=%.1f%%", cpu, mem)
}
