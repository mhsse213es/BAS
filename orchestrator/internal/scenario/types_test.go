package scenario

import "testing"

func TestPrivilegeExceeds(t *testing.T) {
	cases := []struct {
		name     string
		stepTier string
		maxTier  string
		want     bool
	}{
		{"empty maxTier means unconstrained", "admin", "", false},
		{"empty stepTier (legacy/unannotated) never exceeds", "", "user", false},
		{"user step under user ceiling", "user", "user", false},
		{"admin step under admin ceiling", "admin", "admin", false},
		{"admin step exceeds user ceiling", "admin", "user", true},
		{"system step exceeds admin ceiling", "system", "admin", true},
		{"system step under system ceiling", "system", "system", false},
		{"user step never exceeds admin ceiling", "user", "admin", false},
		{"unrecognized stepTier treated as user (lowest)", "bogus", "user", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := PrivilegeExceeds(c.stepTier, c.maxTier); got != c.want {
				t.Errorf("PrivilegeExceeds(%q, %q) = %v, want %v", c.stepTier, c.maxTier, got, c.want)
			}
		})
	}
}
