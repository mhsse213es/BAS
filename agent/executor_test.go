package main

import (
	"io"
	"strings"
	"testing"

	"github.com/audspect/bas-agent/sched"
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
