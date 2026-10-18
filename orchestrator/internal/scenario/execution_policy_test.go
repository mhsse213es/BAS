package scenario

import "testing"

// Only the documented values are accepted. Anything else is rejected, not
// mapped to a default, because a guessed policy would decide the verdict.
func TestValidInProcessPolicy(t *testing.T) {
	cases := map[string]bool{
		"":             true, // not stated: the step reports UNVERIFIED
		"restricted":   true,
		"unrestricted": true,
		"Restricted":   false,
		" restricted":  false,
		"strict":       false,
		"allowed":      false,
	}
	for in, want := range cases {
		if got := ValidInProcessPolicy(in); got != want {
			t.Errorf("ValidInProcessPolicy(%q) = %v, want %v", in, got, want)
		}
	}
}
