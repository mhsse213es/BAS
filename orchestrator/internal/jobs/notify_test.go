package jobs

import "testing"

func TestClassifyJobTransition(t *testing.T) {
	cases := []struct {
		newState string
		wantType string
		wantSev  string
		wantOk   bool
	}{
		{JobStateRunning, notifyTypeJobStarted, notifySeverityInfo, true},
		{JobStateCompleted, notifyTypeJobCompleted, notifySeverityInfo, true},
		{JobStatePartial, notifyTypeJobPartial, notifySeverityWarning, true},
		{JobStateFailed, notifyTypeJobFailed, notifySeverityCritical, true},
		{JobStateRequested, "", "", false},
		{JobStateCancelled, "", "", false},
	}
	for _, c := range cases {
		gotType, gotSev, gotOk := classifyJobTransition(c.newState)
		if gotType != c.wantType || gotSev != c.wantSev || gotOk != c.wantOk {
			t.Errorf("classifyJobTransition(%q) = (%q, %q, %v), want (%q, %q, %v)",
				c.newState, gotType, gotSev, gotOk, c.wantType, c.wantSev, c.wantOk)
		}
	}
}
