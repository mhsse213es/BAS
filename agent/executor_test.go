package main

import (
	"testing"

	"github.com/audspect/bas-agent/sched"
)

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
