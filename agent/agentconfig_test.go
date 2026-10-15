package main

import (
	"strings"
	"testing"
)

func TestRenderPosixAgentConfig_IncludesEnrollPortWhenSet(t *testing.T) {
	got := renderPosixAgentConfig("https://h:9443", "Staging", "sek", "", "", "9445")
	if !strings.Contains(got, "BAS_SERVER_URL=https://h:9443\n") {
		t.Errorf("missing server URL line:\n%s", got)
	}
	if !strings.Contains(got, "BAS_ENROLL_PORT=9445\n") {
		t.Errorf("remapped enrollment port must be persisted so bootstrap reaches it:\n%s", got)
	}
}

func TestRenderPosixAgentConfig_OmitsEnrollPortWhenEmpty(t *testing.T) {
	got := renderPosixAgentConfig("https://h:9443", "Staging", "sek", "", "", "")
	if strings.Contains(got, "BAS_ENROLL_PORT") {
		t.Errorf("no enrollment port should be written when unset (agent uses its 9444 default):\n%s", got)
	}
	// The base keys are still present and unchanged.
	for _, want := range []string{"BAS_SERVER_URL=https://h:9443\n", "BAS_ENV_LABEL=Staging\n", "BAS_AGENT_SECRET=sek\n"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
}
