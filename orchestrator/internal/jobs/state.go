package jobs

// AggregateState computes a Job's rolled-up state from its targets'
// current states. A job the operator already cancelled (current ==
// JobStateCancelled) is never recomputed -- that's a sticky, operator-driven
// terminal state, not something a later tick should overwrite even if an
// in-flight target happens to resolve afterward.
func AggregateState(current string, targets []JobTarget) string {
	if current == JobStateCancelled {
		return JobStateCancelled
	}

	var completed, terminal, dispatchedOrTerminal int
	for _, t := range targets {
		switch t.State {
		case TargetStateCompleted:
			completed++
			terminal++
			dispatchedOrTerminal++
		case TargetStateFailed, TargetStateCancelled:
			terminal++
			dispatchedOrTerminal++
		case TargetStateDispatched:
			dispatchedOrTerminal++
		}
	}

	total := len(targets)
	if terminal == total && total > 0 {
		if completed == total {
			return JobStateCompleted
		}
		if completed == 0 {
			return JobStateFailed
		}
		return JobStatePartial
	}
	if dispatchedOrTerminal > 0 {
		return JobStateRunning
	}
	return JobStateRequested
}
