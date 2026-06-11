package main

import "testing"

// deriveLocalResultLabel must mirror the server's 4-verdict taxonomy: ERROR steps
// (timed out, or non-zero exit without a security block) are excluded from the
// Detected/Evaded decision, never counted as "Evaded". A run with no conclusively
// scored steps is "Error", not "Evaded".
func TestDeriveLocalResultLabel(t *testing.T) {
	blocked := ExecResult{Blocked: true}
	evaded := ExecResult{ExitCode: 0}                 // ran clean, unblocked → FAIL
	timedOut := ExecResult{ExitCode: -1, TimedOut: true} // ERROR
	errExit := ExecResult{ExitCode: 1}                // non-zero, not blocked → ERROR

	cases := []struct {
		name    string
		results []ExecResult
		partial bool
		want    string
	}{
		{"cancelled run is partial", []ExecResult{blocked, evaded}, true, "Partial"},
		{"all blocked", []ExecResult{blocked, blocked}, false, "Detected"},
		{"all evaded", []ExecResult{evaded, evaded}, false, "Evaded"},
		{"mixed blocked and evaded", []ExecResult{blocked, evaded}, false, "Partial"},
		{"all timed out is error", []ExecResult{timedOut, timedOut}, false, "Error"},
		{"all non-zero exit is error", []ExecResult{errExit, errExit}, false, "Error"},
		{"empty run is error", []ExecResult{}, false, "Error"},
		// The regression this fix targets: a crashed step must NOT drag the run to
		// "Evaded". One technique blocked, the rest errored → every *scored* step
		// was blocked → Detected.
		{"one blocked rest errored is detected", []ExecResult{blocked, errExit, timedOut}, false, "Detected"},
		// One technique genuinely evaded, the rest errored → the only scored step
		// evaded → Evaded (errors excluded, not masking the real finding).
		{"one evaded rest errored is evaded", []ExecResult{evaded, errExit, timedOut}, false, "Evaded"},
		{"blocked evaded and errored mix", []ExecResult{blocked, evaded, errExit}, false, "Partial"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := deriveLocalResultLabel(c.results, c.partial); got != c.want {
				t.Errorf("deriveLocalResultLabel(%v, partial=%v) = %q, want %q",
					c.results, c.partial, got, c.want)
			}
		})
	}
}
