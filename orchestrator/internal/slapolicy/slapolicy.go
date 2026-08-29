// Package slapolicy holds the pure logic behind posture-finding SLA
// deadlines: computing a deadline from a policy and a start time, and
// deciding whether a given deadline is breached as of now. No I/O -- the
// API layer resolves the right Policy row and persists the result.
package slapolicy

import "time"

// Policy is one severity's SLA duration -- mirrors one row of the
// sla_policy table.
type Policy struct {
	Severity      string
	DurationHours int
}

// DeadlineFor computes when a clock that started at startedAt expires,
// given the policy in effect for that severity at the moment it started.
func DeadlineFor(policy Policy, startedAt time.Time) time.Time {
	return startedAt.Add(time.Duration(policy.DurationHours) * time.Hour)
}

// EvaluateSLABreach is the single source of truth for "is this clock
// breached" -- a deadline exactly reached counts as breached, not
// exclusively strictly after.
func EvaluateSLABreach(deadlineAt, now time.Time) bool {
	return !now.Before(deadlineAt)
}
