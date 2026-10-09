package main

import (
	"testing"

	"audspect/agent/protocol"
)

// deriveLocalResultLabel must mirror the server's 4-verdict taxonomy: ERROR steps
// (timed out, or non-zero exit without a security block) are excluded from the
// Detected/Evaded decision, never counted as "Evaded". A run with no conclusively
// scored steps is "Error", not "Evaded".
func TestDeriveLocalResultLabel(t *testing.T) {
	blocked := protocol.ExecResult{Blocked: true}
	evaded := protocol.ExecResult{ExitCode: 0}                    // ran clean, unblocked → FAIL
	timedOut := protocol.ExecResult{ExitCode: -1, TimedOut: true} // ERROR
	errExit := protocol.ExecResult{ExitCode: 1}                   // non-zero, not blocked → ERROR
	// Shape the domain-controller safety interlock (agent.go runScenario)
	// actually submits (increment 2.1, 2026-10-09): Vetoed, never Blocked --
	// nothing was attempted, so this must never resolve to "Detected" (that
	// would falsely claim a customer control stopped a real attempt).
	dcVetoed := protocol.ExecResult{ExitCode: -1, Vetoed: true, VetoedBlockSource: "domain_controller_interlock"}

	cases := []struct {
		name    string
		results []protocol.ExecResult
		partial bool
		want    string
	}{
		{"cancelled run is partial", []protocol.ExecResult{blocked, evaded}, true, "Partial"},
		{"all blocked", []protocol.ExecResult{blocked, blocked}, false, "Detected"},
		{"all evaded", []protocol.ExecResult{evaded, evaded}, false, "Evaded"},
		{"mixed blocked and evaded", []protocol.ExecResult{blocked, evaded}, false, "Partial"},
		{"all timed out is error", []protocol.ExecResult{timedOut, timedOut}, false, "Error"},
		{"all non-zero exit is error", []protocol.ExecResult{errExit, errExit}, false, "Error"},
		{"empty run is error", []protocol.ExecResult{}, false, "Error"},
		// The regression this fix targets: a crashed step must NOT drag the run to
		// "Evaded". One technique blocked, the rest errored → every *scored* step
		// was blocked → Detected.
		{"one blocked rest errored is detected", []protocol.ExecResult{blocked, errExit, timedOut}, false, "Detected"},
		// One technique genuinely evaded, the rest errored → the only scored step
		// evaded → Evaded (errors excluded, not masking the real finding).
		{"one evaded rest errored is evaded", []protocol.ExecResult{evaded, errExit, timedOut}, false, "Evaded"},
		{"blocked evaded and errored mix", []protocol.ExecResult{blocked, evaded, errExit}, false, "Partial"},
		// The DC-interlock abort must read as inconclusive (Error), never as
		// a defensive win (Detected) or an attack success (Evaded) -- nothing
		// was attempted at all.
		{"domain-controller interlock abort is error, not detected", []protocol.ExecResult{dcVetoed}, false, "Error"},
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
