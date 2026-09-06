//go:build linux

package pressure

import "testing"

func TestSampleHost_FirstCallReturnsNoBaseline(t *testing.T) {
	_, _, err := SampleHost()
	if err != ErrNoBaseline {
		t.Fatalf("SampleHost() first call: err = %v, want %v", err, ErrNoBaseline)
	}
}

func TestSampleHost_SecondCallReturnsPlausibleReading(t *testing.T) {
	cpu, mem, err := SampleHost()
	if err != nil {
		t.Fatalf("SampleHost() second call: unexpected error %v", err)
	}
	if cpu < 0 || cpu > 100 {
		t.Errorf("SampleHost() cpuPercent = %v, want [0,100]", cpu)
	}
	if mem < 0 || mem > 100 {
		t.Errorf("SampleHost() memPercent = %v, want [0,100]", mem)
	}
	t.Logf("host: cpu=%.1f%% mem=%.1f%%", cpu, mem)
}

func TestSampleSelf_FirstCallReturnsNoBaseline(t *testing.T) {
	_, _, err := SampleSelf()
	if err != ErrNoBaseline {
		t.Fatalf("SampleSelf() first call: err = %v, want %v", err, ErrNoBaseline)
	}
}

func TestSampleSelf_SecondCallReturnsPlausibleReading(t *testing.T) {
	cpu, mem, err := SampleSelf()
	if err != nil {
		t.Fatalf("SampleSelf() second call: unexpected error %v", err)
	}
	if cpu < 0 || cpu > 100 {
		t.Errorf("SampleSelf() cpuPercent = %v, want [0,100]", cpu)
	}
	if mem < 0 || mem > 100 {
		t.Errorf("SampleSelf() memPercent = %v, want [0,100]", mem)
	}
	t.Logf("self: cpu=%.1f%% mem=%.1f%%", cpu, mem)
}
