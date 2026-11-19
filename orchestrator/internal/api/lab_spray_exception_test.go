package api

import "testing"

func TestLabExceptionFor(t *testing.T) {
	cases := []struct {
		name     string
		scenario string
		lab      bool
		want     bool
	}{
		{"lab agent, spray scenario", "ad-password-spray-lab", true, true},
		{"lab agent, guessing scenario", "ad-password-guessing-lab", true, true},
		{"ordinary agent, spray scenario", "ad-password-spray-lab", false, false},
		{"ordinary agent, guessing scenario", "ad-password-guessing-lab", false, false},
		{"lab agent, unrelated scenario", "ad-ntds-access-attempt", true, false},
		{"ordinary agent, unrelated scenario", "ad-ntds-access-attempt", false, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := labExceptionFor(c.scenario, c.lab); got != c.want {
				t.Fatalf("labExceptionFor(%q, %v) = %v, want %v", c.scenario, c.lab, got, c.want)
			}
		})
	}
}
