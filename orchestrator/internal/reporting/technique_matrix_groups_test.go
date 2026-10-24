package reporting

import "testing"

func TestGroupTechniqueMatrix_AdjacentStepsOfOneTechniqueMerge(t *testing.T) {
	rows := []TechniqueRow{
		{TechniqueID: "T1059.001", TechniqueName: "PowerShell", Tactic: "execution", Severity: "high", StepName: "primary", ExecVerdict: "fail"},
		{TechniqueID: "T1059.001", TechniqueName: "PowerShell", Tactic: "execution", Severity: "high", StepName: "counterpart", ExecVerdict: "pass"},
		{TechniqueID: "T1105", TechniqueName: "Ingress Tool Transfer", Tactic: "command-and-control", Severity: "high"},
	}
	got := groupTechniqueMatrix(rows)
	if len(got) != 2 {
		t.Fatalf("groups = %d, want 2", len(got))
	}
	if len(got[0].Steps) != 2 {
		t.Fatalf("first group steps = %d, want 2", len(got[0].Steps))
	}
	if got[0].Steps[0].StepName != "primary" || got[0].Steps[1].StepName != "counterpart" {
		t.Error("steps lost their order or names")
	}
}

func TestGroupTechniqueMatrix_NonAdjacentRepeatsStayApart(t *testing.T) {
	rows := []TechniqueRow{
		{TechniqueID: "T1059.001", Tactic: "execution"},
		{TechniqueID: "T1105", Tactic: "command-and-control"},
		{TechniqueID: "T1059.001", Tactic: "execution"},
	}
	if got := groupTechniqueMatrix(rows); len(got) != 3 {
		t.Fatalf("groups = %d, want 3", len(got))
	}
}
