package dbsim

import "testing"

// connOutcome is a role_window audit outcome: connection events, no marker.
func connOutcome(status string, events ...DBProbeAuditEvent) Outcome {
	o := auditOutcome(status, events...)
	o.Probe.AuditBasis = AuditBasisRoleWindow
	return o
}

func connEvent(principal string) DBProbeAuditEvent {
	return DBProbeAuditEvent{Time: t0, Principal: principal, Statement: "connection authorized: user=" + principal + " database=dbsim"}
}

// DB-04-03: one login by the probe role in the window is a pass, on its own
// basis, and is never graded as a marker match.
func TestRoleWindowSingleMatchingLoginPasses(t *testing.T) {
	o := connOutcome(AuditFound, connEvent("dbsim_test"))
	_, rep := mustValid(t, auditMeta(), o)
	if rep.Dimensions.Audit != DimPass {
		t.Fatalf("one role+window login: audit %s, want pass", rep.Dimensions.Audit)
	}
}

// Two logins by the role in the window cannot be attributed to one probe, so
// the result is inconclusive, never a pass.
func TestRoleWindowAmbiguousLoginsAreUnverifiable(t *testing.T) {
	o := connOutcome(AuditFound, connEvent("dbsim_test"), connEvent("dbsim_test"))
	_, rep := mustValid(t, auditMeta(), o)
	if rep.Dimensions.Audit != DimUnverifiable {
		t.Fatalf("two matching logins: audit %s, want unverifiable", rep.Dimensions.Audit)
	}
}

// A login by another role in the window is not evidence for this probe.
func TestRoleWindowOtherRoleIsNotPass(t *testing.T) {
	o := connOutcome(AuditFound, connEvent("someone_else"))
	_, rep := mustValid(t, auditMeta(), o)
	if rep.Dimensions.Audit == DimPass {
		t.Fatal("a login by another role must not pass the role+window check")
	}
}

// Absent with a healthy, caught-up source means no login was recorded: a fail.
func TestRoleWindowAbsentFails(t *testing.T) {
	o := connOutcome(AuditAbsent)
	_, rep := mustValid(t, auditMeta(), o)
	if rep.Dimensions.Audit != DimFail {
		t.Fatalf("absent connection evidence: audit %s, want fail", rep.Dimensions.Audit)
	}
}
