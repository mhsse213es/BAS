package api

import "testing"

// Setting an agent active is refused only when its binary is unknown to the manifest. A trusted binary, a previous
// signed release, and an agent that has not reported a hash are all allowed.
func TestRestoreRefused(t *testing.T) {
	cases := []struct {
		name     string
		hash     string
		trusted  bool
		previous bool
		want     bool
	}{
		{"unknown binary is refused", "38dfaadfe89595f9", false, false, true},
		{"trusted binary is allowed", "c02d106c", true, false, false},
		{"previous release is allowed", "36821e74", false, true, false},
		{"no hash reported is allowed", "", false, false, false},
	}
	for _, c := range cases {
		if got := restoreRefused(c.hash, c.trusted, c.previous); got != c.want {
			t.Errorf("%s: restoreRefused = %v, want %v", c.name, got, c.want)
		}
	}
}
