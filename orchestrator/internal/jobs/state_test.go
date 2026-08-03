package jobs

import "testing"

func TestAggregateState_AllPendingStaysRequested(t *testing.T) {
	targets := []JobTarget{{State: TargetStatePending}, {State: TargetStatePending}}
	got := AggregateState(JobStateRequested, targets)
	if got != JobStateRequested {
		t.Errorf("AggregateState() = %q, want %q", got, JobStateRequested)
	}
}

func TestAggregateState_SomeDispatchedBecomesRunning(t *testing.T) {
	targets := []JobTarget{{State: TargetStateDispatched}, {State: TargetStatePending}}
	got := AggregateState(JobStateRequested, targets)
	if got != JobStateRunning {
		t.Errorf("AggregateState() = %q, want %q", got, JobStateRunning)
	}
}

func TestAggregateState_AllCompletedBecomesCompleted(t *testing.T) {
	targets := []JobTarget{{State: TargetStateCompleted}, {State: TargetStateCompleted}}
	got := AggregateState(JobStateRunning, targets)
	if got != JobStateCompleted {
		t.Errorf("AggregateState() = %q, want %q", got, JobStateCompleted)
	}
}

func TestAggregateState_AllFailedBecomesFailed(t *testing.T) {
	targets := []JobTarget{{State: TargetStateFailed}, {State: TargetStateFailed}}
	got := AggregateState(JobStateRunning, targets)
	if got != JobStateFailed {
		t.Errorf("AggregateState() = %q, want %q", got, JobStateFailed)
	}
}

func TestAggregateState_MixOfCompletedAndFailedBecomesPartial(t *testing.T) {
	targets := []JobTarget{{State: TargetStateCompleted}, {State: TargetStateFailed}, {State: TargetStateCompleted}}
	got := AggregateState(JobStateRunning, targets)
	if got != JobStatePartial {
		t.Errorf("AggregateState() = %q, want %q", got, JobStatePartial)
	}
}

func TestAggregateState_CancelledJobIsNeverRecomputed(t *testing.T) {
	// A job the operator already cancelled must stay cancelled even if a
	// late-arriving tick sees targets that would otherwise aggregate to
	// something else (e.g. an in-flight target finishing after cancel).
	targets := []JobTarget{{State: TargetStateCompleted}, {State: TargetStateCancelled}}
	got := AggregateState(JobStateCancelled, targets)
	if got != JobStateCancelled {
		t.Errorf("AggregateState() = %q, want %q (cancelled is sticky)", got, JobStateCancelled)
	}
}

func TestAggregateState_StillInFlightNotYetTerminal(t *testing.T) {
	targets := []JobTarget{{State: TargetStateCompleted}, {State: TargetStateDispatched}}
	got := AggregateState(JobStateRunning, targets)
	if got != JobStateRunning {
		t.Errorf("AggregateState() = %q, want %q (one target still dispatched)", got, JobStateRunning)
	}
}
