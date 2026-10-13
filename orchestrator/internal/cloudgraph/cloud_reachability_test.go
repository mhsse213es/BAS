package cloudgraph

import "testing"

func TestWorstState_AllPolicySupported(t *testing.T) {
	got := worstState([]PathState{PolicySupported, PolicySupported})
	if got != PolicySupported {
		t.Errorf("Expected PolicySupported, got %s", got)
	}
}

func TestWorstState_AnyBlockedWins(t *testing.T) {
	got := worstState([]PathState{PolicySupported, Blocked, Observed})
	if got != Blocked {
		t.Errorf("Expected Blocked, got %s", got)
	}
}

func TestWorstState_UnknownWithoutBlocked(t *testing.T) {
	got := worstState([]PathState{PolicySupported, Unknown})
	if got != Unknown {
		t.Errorf("Expected Unknown, got %s", got)
	}
}

func TestWorstState_BlockedBeatsUnknownWhenBothPresent(t *testing.T) {
	got := worstState([]PathState{Unknown, Blocked})
	if got != Blocked {
		t.Errorf("Expected Blocked to beat Unknown, got %s", got)
	}
}

func TestWorstState_AllObserved(t *testing.T) {
	got := worstState([]PathState{Observed, Observed})
	if got != Observed {
		t.Errorf("Expected Observed, got %s", got)
	}
}

func TestWorstState_EmptySliceDefaultsToPolicySupported(t *testing.T) {
	got := worstState(nil)
	if got != PolicySupported {
		t.Errorf("Expected PolicySupported for empty input, got %s", got)
	}
}
