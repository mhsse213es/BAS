//go:build darwin

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

// TestRunScenarioChecks_Apt36KillChainHasRealMacChecks proves apt36-kill-chain
// no longer falls back to a bare "not applicable" skip on macOS -- before the
// 2026-08-26 migration, this scenario had zero real macOS checks, so
// retiring apt36-spearphish.yaml would have silently deleted this platform's
// only real posture coverage for this attack objective.
func TestRunScenarioChecks_Apt36KillChainHasRealMacChecks(t *testing.T) {
	got := techniqueNames(RunScenarioChecks("apt36-kill-chain"))
	want := []string{
		"Gatekeeper Assessment",
		"Code Execution Assessment Policy",
		"XProtect Malware Definitions",
		"LaunchAgents Persistence Surface",
		"Application Layer Firewall",
	}
	for _, name := range want {
		if !got[name] {
			t.Errorf("apt36-kill-chain (macOS) missing migrated check %q -- apt36-spearphish.yaml coverage not reachable", name)
		}
	}
	if len(got) != len(want) {
		t.Errorf("got %d distinct checks, want %d -- got: %+v", len(got), len(want), got)
	}
}

// TestRunScenarioChecks_PurpleSharpADHasRealMacChecks is the AD-pair
// equivalent of the apt36 test above.
func TestRunScenarioChecks_PurpleSharpADHasRealMacChecks(t *testing.T) {
	got := techniqueNames(RunScenarioChecks("purplesharp-ad-drill"))
	want := []string{
		"Keychain Auto-Lock",
		"FileVault Disk Encryption",
		"SSH Remote Login",
		"Screen Sharing / Remote Management",
	}
	for _, name := range want {
		if !got[name] {
			t.Errorf("purplesharp-ad-drill (macOS) missing migrated check %q -- ad-credential-access.yaml coverage not reachable", name)
		}
	}
	if len(got) != len(want) {
		t.Errorf("got %d distinct checks, want %d -- got: %+v", len(got), len(want), got)
	}
}
