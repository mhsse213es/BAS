//go:build !windows && !linux && !darwin

package pressure

import "testing"

func TestSampleHost_ReturnsUnsupportedPlatform(t *testing.T) {
	cpu, mem, err := sampleHost()
	if err == nil {
		t.Fatal("sampleHost() on an unsupported platform: err = nil, want a non-nil error")
	}
	if cpu != 0 || mem != 0 {
		t.Errorf("sampleHost() = (%v, %v, %v), want (0, 0, err)", cpu, mem, err)
	}
}

func TestSampleSelf_ReturnsUnsupportedPlatform(t *testing.T) {
	cpu, mem, err := sampleSelf()
	if err == nil {
		t.Fatal("sampleSelf() on an unsupported platform: err = nil, want a non-nil error")
	}
	if cpu != 0 || mem != 0 {
		t.Errorf("sampleSelf() = (%v, %v, %v), want (0, 0, err)", cpu, mem, err)
	}
}
