package remediation

import "testing"

func TestIsTerminal(t *testing.T) {
	terminal := []string{StatusCompleted, StatusFailed, StatusVerificationFailed, StatusTimedOut, StatusCancelled}
	for _, s := range terminal {
		if !IsTerminal(s) {
			t.Errorf("IsTerminal(%q) = false, want true", s)
		}
	}
	nonTerminal := []string{StatusRequested, StatusDispatched, StatusRunning, StatusVerifying}
	for _, s := range nonTerminal {
		if IsTerminal(s) {
			t.Errorf("IsTerminal(%q) = true, want false", s)
		}
	}
}
