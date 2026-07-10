package exercise

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestRegistry_DispatchAndHas(t *testing.T) {
	r := NewRegistry()
	if r.Has(StepTypeNotify) {
		t.Fatal("empty registry should not Has notify")
	}
	var called bool
	r.Register(StepTypeNotify, StepHandlerFunc(func(_ context.Context, _ *Execution, _ *PlanStep, _ *StepExecution) error {
		called = true
		return nil
	}))
	if !r.Has(StepTypeNotify) {
		t.Fatal("Has should be true after Register")
	}
	if err := r.Dispatch(context.Background(), &Execution{}, &PlanStep{Type: StepTypeNotify}, &StepExecution{}); err != nil {
		t.Fatalf("Dispatch: %v", err)
	}
	if !called {
		t.Fatal("handler was not invoked")
	}
}

func TestRegistry_UnknownTypeError(t *testing.T) {
	r := NewRegistry()
	err := r.Dispatch(context.Background(), &Execution{}, &PlanStep{Type: StepType("mystery")}, &StepExecution{})
	if err == nil {
		t.Fatal("expected error for unknown step type")
	}
}

func TestRegistry_RegisterOverwrites(t *testing.T) {
	r := NewRegistry()
	r.Register(StepTypeNotify, StepHandlerFunc(func(context.Context, *Execution, *PlanStep, *StepExecution) error {
		return errors.New("first")
	}))
	r.Register(StepTypeNotify, StepHandlerFunc(func(context.Context, *Execution, *PlanStep, *StepExecution) error {
		return nil
	}))
	if err := r.Dispatch(context.Background(), &Execution{}, &PlanStep{Type: StepTypeNotify}, &StepExecution{}); err != nil {
		t.Fatalf("second registration should win: %v", err)
	}
}

func TestTriggerRegistry_CheckWithAndWithout(t *testing.T) {
	tr := NewTriggerRegistry()
	// No trigger registered → (false, nil, nil).
	ok, payload, err := tr.Check(context.Background(), &Execution{}, &PlanStep{Type: StepTypeWaitForWebhook}, &StepExecution{})
	if ok || payload != nil || err != nil {
		t.Fatalf("unregistered Check = (%v,%v,%v), want (false,nil,nil)", ok, payload, err)
	}
	tr.Register(StepTypeWaitForWebhook, func(context.Context, *Execution, *PlanStep, *StepExecution) (bool, map[string]any, error) {
		return true, map[string]any{"hit": 1}, nil
	})
	if !tr.Has(StepTypeWaitForWebhook) {
		t.Fatal("Has should be true after Register")
	}
	ok, payload, err = tr.Check(context.Background(), &Execution{}, &PlanStep{Type: StepTypeWaitForWebhook}, &StepExecution{})
	if !ok || payload["hit"] != 1 || err != nil {
		t.Fatalf("registered Check = (%v,%v,%v), want (true,{hit:1},nil)", ok, payload, err)
	}
}

func TestPollScheduler_TicksAndStopIdempotent(t *testing.T) {
	s := NewPollScheduler(5 * time.Millisecond)
	fired := make(chan struct{}, 1)
	var once sync.Once
	s.Start(func(context.Context) {
		once.Do(func() { close(fired) })
	})
	select {
	case <-fired:
	case <-time.After(2 * time.Second):
		t.Fatal("scheduler tick did not fire within 2s")
	}
	s.Stop()
	s.Stop() // must not panic (exercises the select-default branch)
}

func TestMergeMaps(t *testing.T) {
	a := map[string]any{"x": 1, "y": 2}
	b := map[string]any{"y": 99, "z": 3}
	out := mergeMaps(a, b)
	if out["x"] != 1 || out["y"] != 99 || out["z"] != 3 {
		t.Fatalf("mergeMaps = %v, want {x:1,y:99,z:3}", out)
	}
	if a["y"] != 2 {
		t.Fatal("mergeMaps must not mutate input a")
	}
}

func TestMintHookToken(t *testing.T) {
	tok, err := mintHookToken()
	if err != nil {
		t.Fatalf("mintHookToken: %v", err)
	}
	if len(tok) != 32 {
		t.Fatalf("token length = %d, want 32 hex chars", len(tok))
	}
	// Error path: stub cryptoRandRead to fail.
	orig := cryptoRandRead
	t.Cleanup(func() { cryptoRandRead = orig })
	cryptoRandRead = func([]byte) (int, error) { return 0, errors.New("boom") }
	if _, err := mintHookToken(); err == nil {
		t.Fatal("expected error when cryptoRandRead fails")
	}
}
