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

// The effective policy follows explicit > installation default > not stated.
// Neither source is ever assumed, so no input yields restricted or unrestricted
// on its own.
func TestEffectiveInProcessPolicy(t *testing.T) {
	cases := []struct {
		name            string
		explicit, dflt  string
		want            string
		wantErr         bool
	}{
		{"explicit wins over default", "unrestricted", "restricted", "unrestricted", false},
		{"default used when no explicit value", "", "restricted", "restricted", false},
		{"neither set means not stated", "", "", "", false},
		{"explicit alone", "restricted", "", "restricted", false},
		{"invalid explicit rejected", "strict", "restricted", "", true},
		{"invalid default rejected", "", "allowed", "", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := EffectiveInProcessPolicy(c.explicit, c.dflt)
			if (err != nil) != c.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, c.wantErr)
			}
			if got != c.want {
				t.Errorf("got %q, want %q", got, c.want)
			}
		})
	}
}
