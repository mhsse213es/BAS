package variant

import (
	"strings"
	"testing"
)

func TestSummarizeCleanup(t *testing.T) {
	ok := CleanupStep{NeedsCleanup: true, Verdict: "reverted"}
	cases := []struct {
		name        string
		steps       []CleanupStep
		wantState   CleanupState
		wantRemedy  bool
		errContains string
	}{
		{"nothing needed cleanup", []CleanupStep{{}}, CleanupNotRequired, false, ""},
		{"all reverted", []CleanupStep{ok, ok}, CleanupSucceeded, false, ""},
		{"cleanup not yet reported", []CleanupStep{{NeedsCleanup: true}}, CleanupPending, false, ""},
		{"partial revert is a failure", []CleanupStep{ok, {NeedsCleanup: true, Verdict: "partial", Error: "key left behind"}}, CleanupFailed, true, "key left behind"},
		{"leaked is a failure", []CleanupStep{{NeedsCleanup: true, Verdict: "leaked"}}, CleanupFailed, true, "leaked"},
		{"failure wins over pending", []CleanupStep{{NeedsCleanup: true}, {NeedsCleanup: true, Verdict: "leaked"}}, CleanupFailed, true, ""},
		{"ran without a verified cleanup fails closed", []CleanupStep{{Unverified: true}}, CleanupFailed, true, "without a verified cleanup"},
		{"rescued counts as reverted", []CleanupStep{{NeedsCleanup: true, Verdict: "rescued"}}, CleanupSucceeded, false, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			state, errText, remedy := SummarizeCleanup(c.steps)
			if state != c.wantState || remedy != c.wantRemedy {
				t.Errorf("state=%s remedy=%v, want %s %v", state, remedy, c.wantState, c.wantRemedy)
			}
			if c.errContains != "" && !strings.Contains(errText, c.errContains) {
				t.Errorf("error %q does not mention %q", errText, c.errContains)
			}
		})
	}
}
