package validationlab

import (
	"testing"
	"time"
)

// The configured VALIDATION_LAB_TIMEOUT_MINUTES is clamped: unset/invalid
// falls back to the default, and a conservative hard maximum caps it so
// configuration can never turn an unbounded run into an accepted validation.
func TestClampValidationTimeout(t *testing.T) {
	cases := []struct {
		in   int
		want time.Duration
	}{
		{0, 10 * time.Minute},   // unset -> default
		{-5, 10 * time.Minute},  // invalid -> default
		{5, 5 * time.Minute},    // in range
		{30, 30 * time.Minute},  // at the hard max
		{999, 30 * time.Minute}, // above the hard max -> capped
	}
	for _, c := range cases {
		if got := ClampValidationTimeout(c.in); got != c.want {
			t.Errorf("ClampValidationTimeout(%d) = %v, want %v", c.in, got, c.want)
		}
	}
}
