package openaev

import (
	"testing"

	"github.com/audspect/bas/internal/exercise"
)

func TestBuildPlan_TechniqueInjectBecomesAgentTask(t *testing.T) {
	plan := BuildPlan(
		Scenario{Name: "Test Scenario"},
		Detail{Description: "desc", Injects: []DetailInject{{Title: "Recon", TechniqueIDs: []string{"T1046"}}}},
	)
	if plan.Name != "Test Scenario" || plan.Description != "desc" {
		t.Fatalf("name/desc not copied: %+v", plan)
	}
	if len(plan.Steps) != 1 {
		t.Fatalf("want 1 step, got %d", len(plan.Steps))
	}
	st := plan.Steps[0]
	if st.Type != exercise.StepTypeAgentTask {
		t.Fatalf("want agent_task, got %s", st.Type)
	}
	if st.Config.AgentTask == nil || st.Config.AgentTask.TechniqueID != "T1046" {
		t.Fatalf("technique not mapped: %+v", st.Config.AgentTask)
	}
	if st.Config.AgentTask.AgentID != "${agent_id}" {
		t.Fatalf("want ${agent_id}, got %q", st.Config.AgentTask.AgentID)
	}
}

func TestBuildPlan_MultiTechniqueMakesLinearChain(t *testing.T) {
	plan := BuildPlan(Scenario{Name: "x"}, Detail{
		Injects: []DetailInject{{Title: "Multi", TechniqueIDs: []string{"T1046", "T1057"}}},
	})
	if len(plan.Steps) != 2 {
		t.Fatalf("want 2 steps, got %d", len(plan.Steps))
	}
	if len(plan.Steps[1].DependsOn) != 1 || plan.Steps[1].DependsOn[0] != plan.Steps[0].ID {
		t.Fatalf("step 2 must depend on step 1: %+v", plan.Steps[1].DependsOn)
	}
	if len(plan.Steps[0].DependsOn) != 0 {
		t.Fatalf("first step must have no deps")
	}
}

func TestBuildPlan_NonTechniqueInjectBecomesApproval(t *testing.T) {
	plan := BuildPlan(Scenario{Name: "x"}, Detail{
		Injects: []DetailInject{{Title: "Send phishing email"}},
	})
	if len(plan.Steps) != 1 || plan.Steps[0].Type != exercise.StepTypeApproval {
		t.Fatalf("want 1 approval step: %+v", plan.Steps)
	}
	if plan.Steps[0].Config.ApprovalPrompt != "Send phishing email" {
		t.Fatalf("prompt not set: %q", plan.Steps[0].Config.ApprovalPrompt)
	}
	if plan.Steps[0].Label != "Send phishing email" {
		t.Fatalf("label not set: %q", plan.Steps[0].Label)
	}
}

func TestBuildPlan_VariablesPassthroughPlusAgentID(t *testing.T) {
	plan := BuildPlan(Scenario{Name: "x"}, Detail{
		Variables: []DetailVariable{{Key: "target_url", Description: "the URL"}},
	})
	byName := map[string]exercise.VarDef{}
	for _, v := range plan.Variables {
		byName[v.Name] = v
	}
	if a, ok := byName["agent_id"]; !ok || !a.Required || a.Type != exercise.VarTypeString {
		t.Fatalf("agent_id var wrong: %+v", a)
	}
	if u, ok := byName["target_url"]; !ok || u.Description != "the URL" {
		t.Fatalf("target_url var missing/wrong: %+v", u)
	}
}

func TestBuildPlan_EmptyScenario(t *testing.T) {
	plan := BuildPlan(Scenario{Name: "empty"}, Detail{})
	if len(plan.Steps) != 0 {
		t.Fatalf("want 0 steps, got %d", len(plan.Steps))
	}
	if len(plan.Variables) != 1 { // just agent_id
		t.Fatalf("want 1 var (agent_id), got %d", len(plan.Variables))
	}
}
