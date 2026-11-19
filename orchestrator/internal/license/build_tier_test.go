package license

import (
	"strings"
	"testing"
)

func TestBuildMismatch(t *testing.T) {
	cases := []struct {
		build   string
		licence Tier
		warn    bool
	}{
		{"Core", TierEnterprise, true},
		{"Core", TierAdvanced, true},
		{"Advanced", TierEnterprise, true},
		{"Core", TierCore, false},
		{"Enterprise", TierCore, false}, // a lower licence on a fuller build is held to the licence
		{"Enterprise", TierEnterprise, false},
		{"", TierEnterprise, false},      // an unstamped build (older package) is not judged
		{"Bogus", TierEnterprise, false}, // neither is a stamp that is not a tier
	}
	for _, c := range cases {
		msg := BuildMismatch(c.build, c.licence)
		if (msg != "") != c.warn {
			t.Errorf("BuildMismatch(%q, %q) = %q, warning expected: %v", c.build, c.licence, msg, c.warn)
		}
	}
	msg := BuildMismatch("Core", TierEnterprise)
	for _, want := range []string{"Core", "Enterprise"} {
		if !strings.Contains(msg, want) {
			t.Errorf("the message %q must name %s", msg, want)
		}
	}
}
