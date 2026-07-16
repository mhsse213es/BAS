package exercise

import "testing"

func TestRegisterBuiltins_RegistersAllChannels(t *testing.T) {
	e := &Executor{registry: NewRegistry()}
	e.RegisterBuiltins(nil, nil, nil, nil)
	for _, st := range []StepType{
		StepTypeSendEmail, StepTypeSendSMS, StepTypeSlack, StepTypeTeams,
		StepTypeAgentTask, StepTypeApproval,
	} {
		if !e.registry.Has(st) {
			t.Fatalf("no handler registered for %s", st)
		}
	}
}
