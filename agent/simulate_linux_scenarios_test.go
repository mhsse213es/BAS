//go:build linux

package main

import "testing"

// techniqueNames flattens a RunScenarioChecks result to the set of
// Technique.Name strings it contains, for "is this specific check reachable"
// assertions -- the important claim per the 2026-08-26 migration is coverage
// equivalence (the check is actually returned by the scenario's posture
// tier), not merely that the underlying function still exists somewhere.
func techniqueNames(cats []SimCategory) map[string]bool {
	out := make(map[string]bool)
	for _, cat := range cats {
		for _, c := range cat.Checks {
			out[c.Technique.Name] = true
		}
	}
	return out
}

// TestRunScenarioChecks_Apt36KillChainHasRealLinuxChecks proves apt36-kill-chain
// no longer falls back to a bare "not applicable" skip on Linux -- before the
// 2026-08-26 migration, this scenario had zero real Linux checks, so
// retiring apt36-spearphish.yaml would have silently deleted this platform's
// only real posture coverage for this attack objective.
func TestRunScenarioChecks_Apt36KillChainHasRealLinuxChecks(t *testing.T) {
	got := techniqueNames(RunScenarioChecks("apt36-kill-chain"))
	want := []string{
		"/tmp Mounted noexec",
		"/tmp Mounted nosuid",
		"/dev/shm Mounted noexec",
		"AppArmor Enabled and Enforcing",
		"Sticky Bit on World-Writable Directories",
		"Cron Access Restricted to Authorised Users",
		"Shell Init File Integrity",
		"SSH Root Login Disabled (PermitRootLogin no)",
		"UFW Firewall Enabled",
		"IP Forwarding Disabled (net.ipv4.ip_forward)",
	}
	for _, name := range want {
		if !got[name] {
			t.Errorf("apt36-kill-chain (Linux) missing migrated check %q -- apt36-spearphish.yaml coverage not reachable", name)
		}
	}
	if len(got) != len(want) {
		t.Errorf("got %d distinct checks, want %d -- got: %+v", len(got), len(want), got)
	}
}

// TestRunScenarioChecks_PurpleSharpADHasRealLinuxChecks is the AD-pair
// equivalent of the apt36 test above.
func TestRunScenarioChecks_PurpleSharpADHasRealLinuxChecks(t *testing.T) {
	got := techniqueNames(RunScenarioChecks("purplesharp-ad-drill"))
	want := []string{
		"Ptrace Scope (kernel.yama.ptrace_scope)",
		"Core Dumps Restricted (fs.suid_dumpable)",
		"/etc/shadow Permissions",
		"No Accounts with Empty Passwords (/etc/shadow)",
		"Unexpected SUID Binaries",
		"/tmp Mounted nosuid",
		"/etc/passwd Write Protection",
		"SSH Root Login Disabled (PermitRootLogin no)",
		"SSH Host-Based Authentication Disabled",
		"SSH Ignores .rhosts Files (IgnoreRhosts yes)",
	}
	for _, name := range want {
		if !got[name] {
			t.Errorf("purplesharp-ad-drill (Linux) missing migrated check %q -- ad-credential-access.yaml coverage not reachable", name)
		}
	}
	if len(got) != len(want) {
		t.Errorf("got %d distinct checks, want %d -- got: %+v", len(got), len(want), got)
	}
}
