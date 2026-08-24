package main

import (
	"io"
	"strings"
	"testing"

	"audspect/agent/sched"
)

// declinePromptInput must supply a bounded stream of "No" answers so an
// interactive console prompt never blocks a step on stdin. It must be small
// enough to fit an OS pipe buffer (no deadlock when a step ignores stdin) and
// must terminate (end at EOF) so a re-prompt loop cannot run forever.
func TestDeclinePromptInput(t *testing.T) {
	data, err := io.ReadAll(declinePromptInput())
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !strings.HasPrefix(string(data), "n\r\n") {
		t.Errorf("decline input must start with an n + newline, got %q", string(data))
	}
	if len(data) == 0 || len(data) > 4096 {
		t.Errorf("decline input length = %d, want bounded within the OS pipe buffer (1..4096)", len(data))
	}
	if strings.Trim(string(data), "n\r\n") != "" {
		t.Errorf("decline input must contain only n/newline answers, got %q", string(data))
	}
}

func TestReconcileCleanupVerdict(t *testing.T) {
	clean := &SystemSnapshot{Lists: map[string][]string{"tmp_files": {"/tmp/a"}}}
	dirty := &SystemSnapshot{Lists: map[string][]string{"tmp_files": {"/tmp/a", "/tmp/evil"}}}

	cases := []struct {
		name         string
		pre, post    *SystemSnapshot
		verdict      string
		wantVerdict  string
		wantResidual int // len(residual) — 0 or 1 for these fixtures
	}{
		{"reverted downgrades when residue found", clean, dirty, "reverted", "partial", 1},
		{"leaked upgrades when no residue found", clean, clean, "leaked", "reverted", 0},
		{"partial stays partial regardless of residue", clean, dirty, "partial", "partial", 1},
		{"reverted stays reverted when no residue", clean, clean, "reverted", "reverted", 0},
		{"nil pre skips reconciliation", nil, clean, "leaked", "leaked", 0},
		{"nil post skips reconciliation", clean, nil, "leaked", "leaked", 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			residual, verdict := reconcileCleanupVerdict(c.pre, c.post, c.verdict)
			if verdict != c.wantVerdict {
				t.Errorf("verdict = %q, want %q", verdict, c.wantVerdict)
			}
			if len(residual) != c.wantResidual {
				t.Errorf("len(residual) = %d, want %d (residual=%v)", len(residual), c.wantResidual, residual)
			}
		})
	}
}

func TestExecuteSecondsPrecedence(t *testing.T) {
	cases := []struct {
		name string
		step ScenarioStep
		want int
	}{
		{"profile wins", ScenarioStep{TimeoutSec: 120, Timeout: &sched.TimeoutProfile{ExecuteSec: 15}}, 15},
		{"falls back to legacy TimeoutSec", ScenarioStep{TimeoutSec: 90}, 90},
		{"blanket default when unset", ScenarioStep{}, 120},
		{"profile zero falls through", ScenarioStep{TimeoutSec: 45, Timeout: &sched.TimeoutProfile{}}, 45},
	}
	for _, c := range cases {
		if got := executeSeconds(c.step); got != c.want {
			t.Errorf("%s: executeSeconds=%d want %d", c.name, got, c.want)
		}
	}
}

func TestGraceSecondsPrecedence(t *testing.T) {
	if got := graceSeconds(ScenarioStep{Timeout: &sched.TimeoutProfile{GraceSec: 9}}); got != 9 {
		t.Errorf("profile grace = %d want 9", got)
	}
	if got := graceSeconds(ScenarioStep{}); got != defaultGraceSec {
		t.Errorf("default grace = %d want %d", got, defaultGraceSec)
	}
}
