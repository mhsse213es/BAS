package avscenario

import (
	"errors"
	"testing"

	"github.com/audspect/bas/internal/avcatalog"
	"github.com/audspect/bas/internal/avval"
)

func dispatchableVector(t *testing.T, id string, counterpart *avcatalog.ExecutionTemplate) avcatalog.Vector {
	t.Helper()
	noReason := ""
	if counterpart == nil {
		noReason = "no counterpart needed"
	}
	v, err := avcatalog.NewVector(
		id, 1, avcatalog.FamilyScriptFileless, "test vector", avcatalog.SeverityHigh,
		[]avcatalog.Platform{avcatalog.PlatformWindowsWorkstation}, []avcatalog.RequiredCapability{avcatalog.CapabilityBehavioralNGAV},
		"preconditions", avval.ClaimPrevention,
		avcatalog.ExecutionTemplate{
			Executor: "powershell", Command: `Set-Content -Path "$env:TEMP\x.txt" -Value 'x'`,
			Description: "d", CleanupCommand: `Remove-Item -Path "$env:TEMP\x.txt" -Force -ErrorAction SilentlyContinue`,
		},
		counterpart, noReason,
		"delete marker", "", avcatalog.StandardsMapping{ATTACKTechniques: []string{"T1059.001"}}, "test-authored",
	)
	if err != nil {
		t.Fatalf("NewVector: %v", err)
	}
	return v
}

func harnessRequiredVector(t *testing.T) avcatalog.Vector {
	t.Helper()
	v, err := avcatalog.NewVector(
		"AV-HARNESS-TEST", 1, avcatalog.FamilyBehavioralExploit, "needs harness", avcatalog.SeverityHigh,
		[]avcatalog.Platform{avcatalog.PlatformWindowsWorkstation}, []avcatalog.RequiredCapability{avcatalog.CapabilityBehavioralNGAV},
		"preconditions", avval.ClaimPrevention,
		avcatalog.ExecutionTemplate{Executor: "binary", Command: "avtest-fictional.exe", Description: "d"},
		nil, "no counterpart",
		"n/a", "requires a dedicated test harness", avcatalog.StandardsMapping{ATTACKTechniques: []string{"T1055"}}, "test-authored",
	)
	if err != nil {
		t.Fatalf("NewVector: %v", err)
	}
	return v
}

func TestPlatformToOS(t *testing.T) {
	cases := map[avcatalog.Platform]string{
		avcatalog.PlatformWindowsWorkstation: "windows",
		avcatalog.PlatformWindowsServer:      "windows",
		avcatalog.PlatformLinuxServer:        "linux",
		avcatalog.PlatformMacOS:              "darwin",
	}
	for platform, want := range cases {
		got, err := PlatformToOS(platform)
		if err != nil {
			t.Errorf("PlatformToOS(%q): %v", platform, err)
		}
		if got != want {
			t.Errorf("PlatformToOS(%q) = %q, want %q", platform, got, want)
		}
	}
}

func TestSupportedOS_Deduplicates(t *testing.T) {
	v := dispatchableVector(t, "AV-ADAPT-001", nil)
	v.Platforms = []avcatalog.Platform{avcatalog.PlatformWindowsWorkstation, avcatalog.PlatformWindowsServer}
	os, err := SupportedOS(v)
	if err != nil {
		t.Fatalf("SupportedOS: %v", err)
	}
	if len(os) != 1 || os[0] != "windows" {
		t.Errorf("SupportedOS = %v, want [windows] (deduplicated)", os)
	}
}

func TestBuildPrimaryStep_RealCommand_Succeeds(t *testing.T) {
	v := dispatchableVector(t, "AV-ADAPT-002", nil)
	step, err := BuildPrimaryStep(v)
	if err != nil {
		t.Fatalf("BuildPrimaryStep: %v", err)
	}
	if step.Executor != "powershell" {
		t.Errorf("Executor = %q, want powershell", step.Executor)
	}
	if step.TechniqueID != "T1059.001" {
		t.Errorf("TechniqueID = %q, want T1059.001", step.TechniqueID)
	}
	if step.Cleanup == "" {
		t.Error("Cleanup should carry the vector's CleanupCommand")
	}
	if step.TimeoutSec != defaultTimeoutSec {
		t.Errorf("TimeoutSec = %d, want %d", step.TimeoutSec, defaultTimeoutSec)
	}
	if len(step.ThreatIntelSources) != 1 || step.ThreatIntelSources[0].Reference != "test-authored" {
		t.Errorf("ThreatIntelSources = %+v, want provenance carried through", step.ThreatIntelSources)
	}
}

// Review Focus: a vector naming a non-standard executor (no dedicated test
// harness built yet) must be explicitly rejected, never silently turned
// into an undispatchable step.
func TestBuildPrimaryStep_NonStandardExecutor_ErrHarnessRequired(t *testing.T) {
	v := harnessRequiredVector(t)
	_, err := BuildPrimaryStep(v)
	if !errors.Is(err, ErrHarnessRequired) {
		t.Fatalf("err = %v, want wrapping ErrHarnessRequired", err)
	}
}

func TestBuildCounterpartStep_NoCounterpart_NotOK_NoError(t *testing.T) {
	v := dispatchableVector(t, "AV-ADAPT-003", nil)
	_, ok, err := BuildCounterpartStep(v)
	if err != nil {
		t.Fatalf("BuildCounterpartStep: %v", err)
	}
	if ok {
		t.Error("ok should be false when vector has no counterpart")
	}
}

func TestBuildCounterpartStep_WithCounterpart_BuildsRealStep(t *testing.T) {
	cp := avcatalog.ExecutionTemplate{Executor: "powershell", Command: `Set-Content -Path "$env:TEMP\y.txt" -Value 'y'`, Description: "cp"}
	v := dispatchableVector(t, "AV-ADAPT-004", &cp)
	step, ok, err := BuildCounterpartStep(v)
	if err != nil {
		t.Fatalf("BuildCounterpartStep: %v", err)
	}
	if !ok {
		t.Fatal("ok should be true when vector has a counterpart")
	}
	if step.Executor != "powershell" {
		t.Errorf("Executor = %q, want powershell", step.Executor)
	}
}

func TestBuildScenario_RealVectors_ProducesValidatedScenario(t *testing.T) {
	cp := avcatalog.ExecutionTemplate{Executor: "powershell", Command: `Set-Content -Path "$env:TEMP\y.txt" -Value 'y'`, Description: "cp"}
	v1 := dispatchableVector(t, "AV-ADAPT-005", &cp)
	v2 := dispatchableVector(t, "AV-ADAPT-006", nil)
	s, err := BuildScenario("av-adapt-test-scenario", "AV Adapter Test Scenario", "integration test", []avcatalog.Vector{v1, v2})
	if err != nil {
		t.Fatalf("BuildScenario: %v", err)
	}
	// v1 contributes 2 steps (primary+counterpart), v2 contributes 1.
	if len(s.Steps) != 3 {
		t.Fatalf("len(Steps) = %d, want 3", len(s.Steps))
	}
	if !s.Executable {
		t.Error("Executable should be true")
	}
	if len(s.SupportedOS) != 1 || s.SupportedOS[0] != "windows" {
		t.Errorf("SupportedOS = %v, want [windows]", s.SupportedOS)
	}
	// Validate() must have already passed inside BuildScenario; confirm it
	// is independently re-affirmable (the real validator, not reimplemented).
	if err := s.Validate(); err != nil {
		t.Errorf("built scenario does not pass the real scenario.Scenario.Validate(): %v", err)
	}
}

func TestBuildScenario_HarnessRequiredVector_PropagatesError(t *testing.T) {
	v := harnessRequiredVector(t)
	_, err := BuildScenario("av-adapt-harness-scenario", "name", "desc", []avcatalog.Vector{v})
	if !errors.Is(err, ErrHarnessRequired) {
		t.Fatalf("err = %v, want wrapping ErrHarnessRequired", err)
	}
}

func TestBuildScenario_NoVectors_Error(t *testing.T) {
	if _, err := BuildScenario("av-adapt-empty", "name", "desc", nil); err == nil {
		t.Fatal("want error for zero vectors, got nil")
	}
}

// Review Focus: a scenario ID using the catalog's own uppercase vector-ID
// convention must be rejected by the real scenario.Scenario.Validate(),
// proving BuildScenario genuinely delegates rather than skipping validation.
func TestBuildScenario_UppercaseID_RejectedByRealValidate(t *testing.T) {
	v := dispatchableVector(t, "AV-ADAPT-007", nil)
	_, err := BuildScenario("AV-UPPERCASE-ID", "name", "desc", []avcatalog.Vector{v})
	if err == nil {
		t.Fatal("want error for an uppercase scenario ID, got nil")
	}
}

// Review Focus: the real seed catalog's one documented harness-required
// vector (AV-BEHAV-001) must be rejected the same way a hand-built test
// vector is -- proving the rejection isn't specific to synthetic fixtures.
func TestBuildPrimaryStep_RealCatalogHarnessRequiredVector(t *testing.T) {
	catalog, err := avcatalog.AudspectAVAttackCatalog()
	if err != nil {
		t.Fatalf("AudspectAVAttackCatalog: %v", err)
	}
	var vector avcatalog.Vector
	for _, v := range catalog {
		if v.ID == "AV-BEHAV-001" {
			vector = v
		}
	}
	if vector.ID == "" {
		t.Fatal("AV-BEHAV-001 not found in catalog")
	}
	_, err = BuildPrimaryStep(vector)
	if !errors.Is(err, ErrHarnessRequired) {
		t.Fatalf("err = %v, want wrapping ErrHarnessRequired", err)
	}
}

// Review Focus: the real seed catalog's dispatchable vectors must actually
// build real, validated scenarios end to end.
func TestBuildScenario_RealCatalogDispatchableSubset(t *testing.T) {
	catalog, err := avcatalog.AudspectAVAttackCatalog()
	if err != nil {
		t.Fatalf("AudspectAVAttackCatalog: %v", err)
	}
	dispatchableIDs := map[string]bool{
		"AV-FILE-001": true, "AV-FILE-002": true, "AV-SCRIPT-001": true, "AV-SCRIPT-002": true,
		"AV-BEHAV-002": true, "AV-NET-001": true, "AV-PERSIST-001": true, "AV-PERSIST-002": true,
		"AV-FP-001": true, "AV-FP-002": true,
	}
	var vectors []avcatalog.Vector
	for _, v := range catalog {
		if dispatchableIDs[v.ID] {
			vectors = append(vectors, v)
		}
	}
	if len(vectors) != len(dispatchableIDs) {
		t.Fatalf("found %d dispatchable vectors in the catalog, want %d", len(vectors), len(dispatchableIDs))
	}
	s, err := BuildScenario("av-real-catalog-dispatchable", "Real Catalog Dispatchable Subset", "integration test", vectors)
	if err != nil {
		t.Fatalf("BuildScenario: %v", err)
	}
	if len(s.Steps) == 0 {
		t.Error("expected at least one step")
	}
}
