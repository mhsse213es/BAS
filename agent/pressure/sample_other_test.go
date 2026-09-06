//go:build !windows && !linux && !darwin

package pressure

import "testing"

func TestSampleHost_ReturnsUnsupportedPlatform(t *testing.T) {
	cpu, mem, err := SampleHost()
	if err == nil {
		t.Fatal("SampleHost() on an unsupported platform: err = nil, want a non-nil error")
	}
	if cpu != 0 || mem != 0 {
		t.Errorf("SampleHost() = (%v, %v, %v), want (0, 0, err)", cpu, mem, err)
	}
}

func TestSampleSelf_ReturnsUnsupportedPlatform(t *testing.T) {
	cpu, mem, err := SampleSelf()
	if err == nil {
		t.Fatal("SampleSelf() on an unsupported platform: err = nil, want a non-nil error")
	}
	if cpu != 0 || mem != 0 {
		t.Errorf("SampleSelf() = (%v, %v, %v), want (0, 0, err)", cpu, mem, err)
	}
}
