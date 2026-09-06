//go:build linux

package pressure

import "testing"

func TestSampleHost_FirstCallReturnsNoBaseline(t *testing.T) {
	_, _, err := sampleHost()
	if err != ErrNoBaseline {
		t.Fatalf("sampleHost() first call: err = %v, want %v", err, ErrNoBaseline)
	}
}

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
