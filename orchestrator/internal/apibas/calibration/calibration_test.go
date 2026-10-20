package calibration

import (
	"os"
	"path/filepath"
	"testing"
)

func record(version, supersedes int) Record {
	return Record{
		ScenarioID: "API-BAS-ABUSE-002",
		Version:    version,
		Supersedes: supersedes,
		Profile:    Profile{Machine: "lab-i5-8250u", GOOS: "windows", GOARCH: "amd64", NumCPU: 8, GoVersion: "go1.26.8"},
		Thresholds: Thresholds{DeclaredBaselineMs: 0.15, Tolerance: 4, CeilingMs: 250, MinRatio: 5, MaxCV: 0.5, AttackMaxMs: 5000, Warmup: 3, Trials: 10, Rounds: 3},
	}
}

func TestFirstVersionIsOne(t *testing.T) {
	dir := t.TempDir()
	if _, err := Write(dir, record(1, 0)); err != nil {
		t.Fatal(err)
	}
	if v, _ := NextVersion(dir, "API-BAS-ABUSE-002"); v != 2 {
		t.Fatalf("next version = %d, want 2", v)
	}
}

// A recalibration must name the version it supersedes and must leave the first in place.
func TestRecalibrationPreservesPreviousVersion(t *testing.T) {
	dir := t.TempDir()
	first, err := Write(dir, record(1, 0))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Write(dir, record(2, 1)); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(first); err != nil {
		t.Fatalf("version 1 was removed: %v", err)
	}
}

func TestWriteRefusesWrongVersionOrSupersession(t *testing.T) {
	dir := t.TempDir()
	if _, err := Write(dir, record(2, 1)); err == nil {
		t.Fatal("version 2 accepted with no version 1")
	}
	if _, err := Write(dir, record(1, 0)); err != nil {
		t.Fatal(err)
	}
	if _, err := Write(dir, record(2, 0)); err == nil {
		t.Fatal("version 2 accepted without superseding version 1")
	}
}

func TestWriteRequiresMachineLabel(t *testing.T) {
	r := record(1, 0)
	r.Profile.Machine = ""
	if _, err := Write(t.TempDir(), r); err == nil {
		t.Fatal("record with no machine label accepted")
	}
}

// Write never overwrites: an existing file blocks a second write of the same version.
func TestWriteIsExclusive(t *testing.T) {
	dir := t.TempDir()
	if _, err := Write(dir, record(1, 0)); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "API-BAS-ABUSE-002.v1.json"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Write(dir, record(1, 0)); err == nil {
		t.Fatal("existing version overwritten")
	}
}

func TestGetMissingRecordFails(t *testing.T) {
	if _, err := Get("API-BAS-ABUSE-002", 99); err == nil {
		t.Fatal("missing embedded record returned without error")
	}
}
