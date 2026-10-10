// Package latmove is the first lateral-movement validation vertical: it proves
// WMI remote process creation (T1047) genuinely achieves cross-machine code
// execution between two domain-joined clients. This slice is
// EXECUTION-VALIDATION ONLY -- no rights-gating, no real observer, no live
// wiring. Self-contained: it does not reuse admatrix (AD-object-abuse axes) or
// controlval (generalized only because 4+ vendor consumers justified it); a
// third real consumer of this evidence shape is the trigger to generalize, not
// this one vertical.
package latmove

import "time"

// TimeWindow bounds when an attempt occurred, for correlation.
type TimeWindow struct {
	Start time.Time
	End   time.Time
}

// AttemptKey identifies one lateral-movement attempt.
type AttemptKey struct {
	RunID       string
	Source      string
	Destination string
	Technique   string
	Window      TimeWindow
}

// CallOutcome is the WMI call's OWN immediate result. SECONDARY/diagnostic
// only -- it never independently establishes Executed, but a reported denial
// combined with an absent marker yields a meaningful AccessDenied.
type CallOutcome string

const (
	CallSucceeded    CallOutcome = "succeeded"
	CallAccessDenied CallOutcome = "access_denied"
	CallErrored      CallOutcome = "errored"
	CallUnknown      CallOutcome = "unknown"
)

// MarkerCheck is the destination-side readback of a unique, per-attempt token.
// This is the SOLE primary determinant of Executed -- "verify postconditions,
// not command-success". Correlated=false means the check could not be trusted
// as belonging to THIS attempt (wrong window, stale token, etc.).
type MarkerCheck struct {
	Correlated bool
	Found      bool
}

// Corroboration is supporting detail only -- the parent-process chain and
// whatever technique-specific secondary log exists (WMI-Activity operational
// log for WMI, Security 4697/7045 for service creation, etc.). NEVER
// outcome-determining on its own, exactly as event 4662 was for DCSync.
// Generic across techniques: SecondaryLogDetail names which log/event this
// attempt's technique produces, so the field stays meaningful without a
// per-technique struct.
type Corroboration struct {
	ParentProcessObserved bool
	ParentProcessName     string
	SecondaryLogObserved  bool
	SecondaryLogDetail    string // e.g. "WMI-Activity/Operational", "Security 4697/7045"
}

// Observation is one recorded attempt's full evidence.
type Observation struct {
	Key           AttemptKey
	Call          CallOutcome
	Marker        MarkerCheck
	Corroboration Corroboration
	Detail        string
}

// AttemptResult is the classified outcome of a lateral-movement attempt.
type AttemptResult string

const (
	ResultExecuted      AttemptResult = "executed"
	ResultAccessDenied  AttemptResult = "access_denied"
	ResultIndeterminate AttemptResult = "indeterminate"
)

// ClassifyAttempt is pure: no I/O, no clock, no hidden state. The marker
// readback is the sole primary determinant; the call outcome and
// corroboration inform Detail but never independently decide the result.
func ClassifyAttempt(obs Observation) AttemptResult {
	switch {
	case !obs.Marker.Correlated:
		return ResultIndeterminate
	case obs.Marker.Found:
		return ResultExecuted
	case obs.Call == CallAccessDenied:
		return ResultAccessDenied
	default:
		return ResultIndeterminate
	}
}
