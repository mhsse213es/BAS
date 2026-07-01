package exercise

import (
	"context"
	"fmt"
)

// StepHandler is the interface every step type must implement.
// Registering a new step type = implement this interface + call Registry.Register().
type StepHandler interface {
	Execute(ctx context.Context, exec *Execution, step *PlanStep, se *StepExecution) error
}

// StepHandlerFunc adapts a plain function to StepHandler.
type StepHandlerFunc func(ctx context.Context, exec *Execution, step *PlanStep, se *StepExecution) error

func (f StepHandlerFunc) Execute(ctx context.Context, exec *Execution, step *PlanStep, se *StepExecution) error {
	return f(ctx, exec, step, se)
}

// Registry maps StepType → StepHandler.
type Registry struct {
	handlers map[StepType]StepHandler
}

func NewRegistry() *Registry {
	return &Registry{handlers: make(map[StepType]StepHandler)}
}

// Register adds a handler for the given step type. Overwrites silently.
func (r *Registry) Register(t StepType, h StepHandler) {
	r.handlers[t] = h
}

// Dispatch calls the registered handler for step.Type.
func (r *Registry) Dispatch(ctx context.Context, exec *Execution, step *PlanStep, se *StepExecution) error {
	h, ok := r.handlers[step.Type]
	if !ok {
		return fmt.Errorf("no handler registered for step type %q", step.Type)
	}
	return h.Execute(ctx, exec, step, se)
}

// Has reports whether a handler is registered for t.
func (r *Registry) Has(t StepType) bool {
	_, ok := r.handlers[t]
	return ok
}
