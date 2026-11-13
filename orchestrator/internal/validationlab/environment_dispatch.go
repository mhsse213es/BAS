package validationlab

import "strings"

// isEnvironmentalDispatchFailure reports whether a dispatch refusal says the lab agent could not take the work, not
// that the content failed. Such a refusal is recorded (ERROR, with the reason) but does not count toward the
// validation attempt cap, so a draft is tried again once the lab is back. A content-side refusal ("no windows steps
// found", "os mismatch") still counts. The SQL count in selectEligible (orchestrator.go) mirrors this rule: keep the two in step.
func isEnvironmentalDispatchFailure(reason string) bool {
	return reason == "offline" || strings.HasPrefix(reason, "agent ")
}

// refundAttempt gives back the attempt that an environmental refusal used up. The backoff timestamp stays, so the
// same draft still waits and the queue moves on to the next draft.
func (o *Orchestrator) refundAttempt(versionID string) {
	o.attemptMu.Lock()
	defer o.attemptMu.Unlock()
	a := o.attempts[versionID]
	if a.n > 0 {
		a.n--
	}
	o.attempts[versionID] = a
}
