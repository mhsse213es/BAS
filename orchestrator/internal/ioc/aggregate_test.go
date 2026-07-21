package ioc

import (
	"testing"

	"github.com/audspect/bas/internal/scenario"
)

func TestBuildRunIndicators_SameIndicatorTwoStepsSameTechnique(t *testing.T) {
	execResults := []scenario.ExecResult{
		{TaskID: "T1059::PowerShell", Stdout: "beacon to 45.33.32.156"},
		{TaskID: "T1059::EncodedCommand", Stdout: "beacon to 45.33.32.156"},
	}
	stepMap := map[string]scenario.Step{
		"T1059::PowerShell":     {TechniqueID: "T1059"},
		"T1059::EncodedCommand": {TechniqueID: "T1059"},
	}
	got := BuildRunIndicators(execResults, nil, stepMap)
	if len(got) != 1 {
		t.Fatalf("got %d indicators, want 1: %+v", len(got), got)
	}
	ind := got[0]
	if len(ind.SimulationIDs) != 2 {
		t.Errorf("SimulationIDs = %v, want 2 entries", ind.SimulationIDs)
	}
	if len(ind.TechniqueIDs) != 1 || ind.TechniqueIDs[0] != "T1059" {
		t.Errorf("TechniqueIDs = %v, want [T1059]", ind.TechniqueIDs)
	}
}

func TestBuildRunIndicators_SameIndicatorTwoTechniques(t *testing.T) {
	execResults := []scenario.ExecResult{
		{TaskID: "T1059::A", Stdout: "beacon to 45.33.32.156"},
		{TaskID: "T1071::B", Stdout: "beacon to 45.33.32.156"},
	}
	stepMap := map[string]scenario.Step{
		"T1059::A": {TechniqueID: "T1059"},
		"T1071::B": {TechniqueID: "T1071"},
	}
	got := BuildRunIndicators(execResults, nil, stepMap)
	if len(got) != 1 || len(got[0].TechniqueIDs) != 2 {
		t.Fatalf("got %+v", got)
	}
}

func TestBuildRunIndicators_StdoutBeforeStderr(t *testing.T) {
	execResults := []scenario.ExecResult{
		{TaskID: "T1059::A", Stdout: "45.33.32.156 in stdout", Stderr: "45.33.32.156 in stderr"},
	}
	stepMap := map[string]scenario.Step{"T1059::A": {TechniqueID: "T1059"}}
	got := BuildRunIndicators(execResults, nil, stepMap)
	if len(got) != 1 || got[0].Source != "stdout" {
		t.Fatalf("got %+v, want Source=stdout (first in scan order)", got)
	}
}

func TestBuildRunIndicators_LocalCheckUsesDetailsSource(t *testing.T) {
	checks := []scenario.SimCheckResult{
		{ID: "os-patch-posture::last-patch-age", TechniqueID: "T1082", Details: "CVE-2024-3094 unpatched"},
	}
	got := BuildRunIndicators(nil, checks, nil)
	if len(got) != 1 || got[0].Source != "details" || got[0].Type != "cve" {
		t.Fatalf("got %+v", got)
	}
	if len(got[0].SimulationIDs) != 1 || got[0].SimulationIDs[0] != "os-patch-posture::last-patch-age" {
		t.Errorf("SimulationIDs = %v, want [os-patch-posture::last-patch-age]", got[0].SimulationIDs)
	}
}

func TestBuildRunIndicators_UnknownTaskIDNoTechnique(t *testing.T) {
	execResults := []scenario.ExecResult{
		{TaskID: "custom::adhoc", Stdout: "beacon to 45.33.32.156"},
	}
	got := BuildRunIndicators(execResults, nil, map[string]scenario.Step{})
	if len(got) != 1 || len(got[0].TechniqueIDs) != 0 {
		t.Fatalf("got %+v, want empty TechniqueIDs for an unmapped step", got)
	}
	if len(got[0].SimulationIDs) != 1 || got[0].SimulationIDs[0] != "custom::adhoc" {
		t.Errorf("SimulationIDs = %v", got[0].SimulationIDs)
	}
}

func TestBuildRunIndicators_EmptyInputsReturnsEmptySlice(t *testing.T) {
	got := BuildRunIndicators(nil, nil, nil)
	if len(got) != 0 {
		t.Errorf("got %+v, want empty", got)
	}
}
