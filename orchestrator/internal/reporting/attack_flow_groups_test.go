package reporting

import "testing"

func TestGroupAttackFlow_AdjacentStepsOfOneTechniqueMerge(t *testing.T) {
	nodes := []AttackFlowNode{
		{Step: 1, TechniqueID: "T1059.001", TechniqueName: "PowerShell", Tactic: "execution", StepName: "primary", Verdict: "bypassed", DurationMs: 2},
		{Step: 2, TechniqueID: "T1059.001", TechniqueName: "PowerShell", Tactic: "execution", StepName: "counterpart", Verdict: "bypassed", DurationMs: 3},
		{Step: 3, TechniqueID: "T1105", TechniqueName: "Ingress Tool Transfer", Tactic: "command-and-control", Verdict: "detected", DurationMs: 4},
	}
	got := groupAttackFlow(nodes)
	if len(got) != 2 {
		t.Fatalf("groups = %d, want 2", len(got))
	}
	if len(got[0].Steps) != 2 {
		t.Fatalf("first group steps = %d, want 2", len(got[0].Steps))
	}
	if got[0].DurationMs != 5 {
		t.Errorf("first group duration = %d, want 5", got[0].DurationMs)
	}
	if got[0].Steps[0].StepName != "primary" || got[0].Steps[1].StepName != "counterpart" {
		t.Error("steps lost their order or names")
	}
}

func TestGroupAttackFlow_NonAdjacentRepeatsStayInKillChainOrder(t *testing.T) {
	nodes := []AttackFlowNode{
		{TechniqueID: "T1059.001", Tactic: "execution"},
		{TechniqueID: "T1105", Tactic: "command-and-control"},
		{TechniqueID: "T1059.001", Tactic: "execution"},
	}
	if got := groupAttackFlow(nodes); len(got) != 3 {
		t.Fatalf("groups = %d, want 3 (a repeat after another technique is a new step in the chain)", len(got))
	}
}
