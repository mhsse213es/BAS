//go:build darwin

package main

import "testing"

// The decision logic for these checks is tested in simulate_mac_posture_test.go,
// which runs on any build host. What can only be verified on macOS is the
// WIRING: that each check is actually reachable from a run. A check that is
// written but never registered silently contributes nothing, and the coverage
// number would still count it.

func TestSafeSimChecks_IncludesSectionA(t *testing.T) {
	want := []string{
		"SSH Root Login Disabled (PermitRootLogin no)",
		"SSH Empty Passwords Forbidden (PermitEmptyPasswords no)",
		"SSH MaxAuthTries <= 4",
		"SSH Ignores .rhosts Files (IgnoreRhosts yes)",
		"SSH Host-Based Authentication Disabled",
		"Password Policy and Lockout Threshold",
		"Pending Security Updates (CSCRF-5.1)",
		"TCP Services Exposed Beyond Loopback",
		"Guest Account Disabled",
		"Local Administrator Account Count",
		"Audit Flags Cover Login and Admin Activity",
		"Audit Record Retention Configured",
		"Cron Access Restricted to Authorised Users",
		"launchd Directories Writable Only by Root",
		"Firewall Stealth Mode and Logging",
		"Unexpected SUID Binaries",
	}
	got := map[string]bool{}
	for _, cat := range safeSimChecks() {
		for _, c := range cat.Checks {
			got[c.Technique.Name] = true
		}
	}
	for _, name := range want {
		if !got[name] {
			t.Errorf("safeSimChecks does not reach %q -- the check exists but never runs", name)
		}
	}
}

// Section A was scoped to techniques whose Linux equivalent already exists.
// This pins the resulting technique set so a later edit cannot quietly drop one.
func TestSafeSimChecks_TechniqueCoverage(t *testing.T) {
	want := []string{
		"T1046", "T1053", "T1070", "T1078", "T1082", "T1098", "T1110", "T1548.001",
	}
	got := map[string]bool{}
	for _, cat := range safeSimChecks() {
		for _, c := range cat.Checks {
			got[c.Technique.ID] = true
		}
	}
	for _, id := range want {
		if !got[id] {
			t.Errorf("technique %s is not covered by a macOS posture check", id)
		}
	}
}

// Every check must produce a verdict from the taxonomy on a real host,
// whatever state that host is in. A blank result would be scored as neither
// pass nor fail and would silently vanish from the denominator.
func TestSafeSimChecks_AllProduceKnownVerdicts(t *testing.T) {
	valid := map[string]bool{"pass": true, "fail": true, "skipped": true}
	for _, cat := range safeSimChecks() {
		for i := range cat.Checks {
			c := &cat.Checks[i]
			c.run()
			if !valid[c.Result] {
				t.Errorf("%s (%s) returned %q, outside pass|fail|skipped",
					c.Technique.Name, c.Technique.ID, c.Result)
			}
			if c.Details == "" {
				t.Errorf("%s returned no details; a verdict a reader cannot act on is not a finding",
					c.Technique.Name)
			}
		}
	}
}
