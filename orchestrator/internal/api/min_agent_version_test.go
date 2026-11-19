package api

import "testing"

func TestBelowMinimumAgentVersion(t *testing.T) {
	cases := []struct {
		name, agent, min string
		want             bool
	}{
		{"no minimum set never flags", "1.0.0", "", false},
		{"lower patch is below", "1.9.6", "1.9.7", true},
		{"equal is not below", "1.9.7", "1.9.7", false},
		{"higher is not below", "1.9.8", "1.9.7", false},
		{"numeric not lexical: 1.10 is above 1.9", "1.10.0", "1.9.9", false},
		{"numeric not lexical: 1.9 is below 1.10", "1.9.0", "1.10.0", true},
		{"missing parts count as zero", "1.9", "1.9.0", false},
		{"shorter minimum", "1.9.0", "2", true},
		{"v prefix accepted", "v1.9.6", "1.9.7", true},
		{"pre-release suffix ignored", "1.9.7-rc1", "1.9.7", false},
		{"unknown agent version is not flagged", "", "1.9.7", false},
		{"unparseable agent version is not flagged", "dev-build", "1.9.7", false},
		{"unparseable minimum disables the check", "1.0.0", "latest", false},
	}
	for _, c := range cases {
		if got := belowMinimumAgentVersion(c.agent, c.min); got != c.want {
			t.Errorf("%s: belowMinimumAgentVersion(%q, %q) = %v, want %v", c.name, c.agent, c.min, got, c.want)
		}
	}
}
