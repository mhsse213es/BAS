package exercise

import "context"

// TriggerFn checks whether a wait condition has been met for a waiting step.
// Returns triggered=true when the step should advance to Completed.
// payload is merged into the step result.
// Returning (false, nil, nil) means "not yet" — check again next tick.
type TriggerFn func(ctx context.Context, exec *Execution, ps *PlanStep, se *StepExecution) (triggered bool, payload map[string]any, err error)

// TriggerRegistry maps StepType → TriggerFn for event-driven wait steps.
// The executor checks all registered triggers on every tick for steps in
// StepWaiting state. Adding a new event source = Register(type, fn).
type TriggerRegistry struct {
	fns map[StepType]TriggerFn
}

func NewTriggerRegistry() *TriggerRegistry {
	return &TriggerRegistry{fns: make(map[StepType]TriggerFn)}
}

func (r *TriggerRegistry) Register(t StepType, fn TriggerFn) { r.fns[t] = fn }

func (r *TriggerRegistry) Has(t StepType) bool {
	_, ok := r.fns[t]
	return ok
}

// Check calls the registered trigger for ps.Type.
// Returns (false, nil, nil) if no trigger is registered for this type.
func (r *TriggerRegistry) Check(ctx context.Context, exec *Execution, ps *PlanStep, se *StepExecution) (bool, map[string]any, error) {
	fn, ok := r.fns[ps.Type]
	if !ok {
		return false, nil, nil
	}
	return fn(ctx, exec, ps, se)
}
