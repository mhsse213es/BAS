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

// failedOutcome is a failed-login audit outcome for DB-04-04: the refusal is
// matched under the throwaway account the probe reported, not the run principal.
func failedOutcome(status, reported string, events ...DBProbeAuditEvent) Outcome {
	o := auditOutcome(status, events...)
	o.Probe.AuditBasis = AuditBasisFailedLogin
	o.Probe.AuditPrincipal = reported
	return o
}

func refusalEvent(principal string) DBProbeAuditEvent {
	return DBProbeAuditEvent{Time: t0, Principal: principal, Statement: `password authentication failed for user "` + principal + `"`}
}

// DB-04-04: one refusal recorded under the throwaway account is a pass.
func TestFailedLoginSingleRefusalUnderThrowawayPasses(t *testing.T) {
	o := failedOutcome(AuditFound, "dbsim_abc_acct", refusalEvent("dbsim_abc_acct"))
	_, rep := mustValid(t, auditMeta(), o)
	if rep.Dimensions.Audit != DimPass {
		t.Fatalf("one refusal under the throwaway account: audit %s, want pass", rep.Dimensions.Audit)
	}
}

// A refusal recorded only under the run principal is not evidence for the
// throwaway account, so it is not a pass.
func TestFailedLoginRefusalUnderRunPrincipalIsNotPass(t *testing.T) {
	o := failedOutcome(AuditFound, "dbsim_abc_acct", refusalEvent("dbsim_test"))
	_, rep := mustValid(t, auditMeta(), o)
	if rep.Dimensions.Audit == DimPass {
		t.Fatal("a refusal under another account must not pass the failed-login check")
	}
}

// Without a reported throwaway name the check cannot be attributed: unverifiable.
func TestFailedLoginWithoutReportedNameIsUnverifiable(t *testing.T) {
	o := failedOutcome(AuditFound, "", refusalEvent("dbsim_test"))
	_, rep := mustValid(t, auditMeta(), o)
	if rep.Dimensions.Audit != DimUnverifiable {
		t.Fatalf("no reported throwaway name: audit %s, want unverifiable", rep.Dimensions.Audit)
	}
}
