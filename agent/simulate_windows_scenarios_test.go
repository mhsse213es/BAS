//go:build windows

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

// TestRunScenarioChecks_PurpleSharpADIsCanonicalSuperset proves
// purplesharp-ad-drill's Windows posture tier -- reached via the same
// RunScenarioChecks dispatch path the agent actually uses -- now carries
// every check ad-credential-access.yaml's retired adCredentialChecks() had,
// migrated 2026-08-26, plus its own pre-existing checks. Asserting on
// RunScenarioChecks (not calling purpleSharpADChecks() directly) proves the
// migrated checks are reachable through the real scenario-ID dispatch a
// posture run actually uses, not just present in the function body.
func TestRunScenarioChecks_PurpleSharpADIsCanonicalSuperset(t *testing.T) {
	got := techniqueNames(RunScenarioChecks("purplesharp-ad-drill"))

	// Migrated from ad-credential-access.yaml -- previously unreachable
	// through purplesharp-ad-drill's posture tier.
	migrated := []string{
		"AutoLogon Credentials in Registry",
		"NTLM Relay Restrictions",
		"Pass-the-Hash Mitigation (Restricted Admin Mode)",
		"SMB Signing Required",
		"LLMNR/NetBIOS Poisoning",
		"UAC Enabled",
		"Remote UAC Token Filtering",
		"AlwaysInstallElevated MSI Policy",
	}
	for _, name := range migrated {
		if !got[name] {
			t.Errorf("purplesharp-ad-drill missing migrated check %q -- ad-credential-access.yaml coverage not yet ported", name)
		}
	}

	// purplesharp-ad-drill's own pre-existing checks must survive the merge.
	original := []string{
		"LSA Protection (RunAsPPL)",
		"WDigest Plaintext Credentials",
		"Windows Credential Guard",
		"LSASS Process Access Auditing",
		"Kerberos RC4 Disabled (Anti-Kerberoasting)",
		"Account Lockout Policy (CSCRF-2.3)",
	}
	for _, name := range original {
		if !got[name] {
			t.Errorf("purplesharp-ad-drill lost its own pre-existing check %q during the merge", name)
		}
	}

	if len(got) != len(migrated)+len(original) {
		t.Errorf("got %d distinct checks, want %d (migrated + original, no duplicates) -- got: %+v",
			len(got), len(migrated)+len(original), got)
	}
}

// TestRunScenarioChecks_Apt36KillChainStillSupersetsSpearphish is a
// regression guard, not a migration (apt36-kill-chain's Windows bundle was
// already a strict superset of apt36-spearphish's before 2026-08-26 -- see
// project memory) -- proves that stays true after this session's edits to
// the same file.
func TestRunScenarioChecks_Apt36KillChainStillSupersetsSpearphish(t *testing.T) {
	legacy := techniqueNames(RunScenarioChecks("apt36-spearphish"))
	successor := techniqueNames(RunScenarioChecks("apt36-kill-chain"))
	for name := range legacy {
		if !successor[name] {
			t.Errorf("apt36-kill-chain no longer covers apt36-spearphish's check %q", name)
		}
	}
}
