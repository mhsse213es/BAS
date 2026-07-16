package openaev

import (
	"fmt"

	"github.com/audspect/bas/internal/exercise"
)

// BuildPlan converts a synced OpenAEV scenario into an editable exercise.Plan.
//
// It is a pure, lossy, one-directional transform (see the 2026-07-16 design spec):
//   - technique-bearing injects  → one agent_task step per TechniqueID, with the
//     target left as the ${agent_id} plan variable (resolved at launch);
//   - non-technique injects       → an approval placeholder step preserving the
//     inject's Title and its ordinal position (nothing is silently dropped);
//   - steps form a linear DAG in inject order (step N depends on step N-1).
func BuildPlan(s Scenario, d Detail) exercise.Plan {
	plan := exercise.Plan{
		Name:        s.Name,
		Description: d.Description,
	}

	// agent_id is bound at launch and referenced by every agent_task step.
	plan.Variables = append(plan.Variables, exercise.VarDef{
		Name:        "agent_id",
		Type:        exercise.VarTypeString,
		Description: "Target agent for attack (agent_task) steps",
		Required:    true,
	})
	for _, v := range d.Variables {
		plan.Variables = append(plan.Variables, exercise.VarDef{
			Name:        v.Key,
			Type:        exercise.VarTypeString,
			Description: v.Description,
		})
	}

	var prevID string
	stepNum := 0
	addStep := func(st exercise.PlanStep) {
		stepNum++
		st.ID = fmt.Sprintf("step-%d", stepNum)
		if prevID != "" {
			st.DependsOn = []string{prevID}
		}
		prevID = st.ID
		plan.Steps = append(plan.Steps, st)
	}

	for _, inj := range d.Injects {
		if len(inj.TechniqueIDs) == 0 {
			addStep(exercise.PlanStep{
				Type:   exercise.StepTypeApproval,
				Label:  inj.Title,
				Config: exercise.StepConfig{ApprovalPrompt: inj.Title},
			})
			continue
		}
		for _, tid := range inj.TechniqueIDs {
			addStep(exercise.PlanStep{
				Type:  exercise.StepTypeAgentTask,
				Label: inj.Title + " — " + tid,
				Config: exercise.StepConfig{
					AgentTask: &exercise.AgentTaskConfig{
						AgentID:     "${agent_id}",
						TechniqueID: tid,
					},
				},
			})
		}
	}

	return plan
}
