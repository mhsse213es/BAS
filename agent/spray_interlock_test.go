package main

import (
	"strings"
	"testing"

	"audspect/agent/protocol"
)

func TestSprayPolicyRefusal(t *testing.T) {
	cases := []struct {
		name    string
		policy  *protocol.LivePolicy
		refuse  bool
		because string
	}{
		{"nil policy passes", nil, false, ""},
		{"no cap passes", &protocol.LivePolicy{}, false, ""},
		{"cap with three named accounts passes", &protocol.LivePolicy{MaxSprayAttempts: 3, SprayAccountAllowlist: []string{"bassim1", "bassim2", "bassim3"}}, false, ""},
		{"cap with empty allowlist refused", &protocol.LivePolicy{MaxSprayAttempts: 3}, true, "names no accounts"},
		{"cap below account count refused", &protocol.LivePolicy{MaxSprayAttempts: 2, SprayAccountAllowlist: []string{"a", "b", "c"}}, true, "below the 3 allowlisted"},
		{"duplicate account refused", &protocol.LivePolicy{MaxSprayAttempts: 2, SprayAccountAllowlist: []string{"a", "a"}}, true, "more than once"},
		{"empty name refused", &protocol.LivePolicy{MaxSprayAttempts: 2, SprayAccountAllowlist: []string{"a", ""}}, true, "empty account name"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := sprayPolicyRefusal(c.policy)
			if c.refuse && got == "" {
				t.Fatalf("expected refusal, got none")
			}
			if !c.refuse && got != "" {
				t.Fatalf("expected no refusal, got %q", got)
			}
			if c.refuse && !strings.Contains(got, c.because) {
				t.Fatalf("refusal %q does not mention %q", got, c.because)
			}
		})
	}
}
