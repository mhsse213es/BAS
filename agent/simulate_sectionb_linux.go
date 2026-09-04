//go:build linux

package main

// Section B of the POSIX posture coverage map, Linux half: checks that are
// net-new on both platforms.
//
// The evaluators these feed live in simulate_posix_posture.go and are shared
// with the macOS agent, so the same endpoint state produces the same verdict on
// either OS and the two cannot drift. Only the reads differ, and they are all
// here.

// linuxSectionBChecks returns the Linux half of section B, grouped under the
// same phase names the macOS agent uses.
func linuxSectionBChecks() []SimCategory {
	return []SimCategory{
		{Phase: "credential-hygiene", Checks: []SimCheck{checkCredentialFilePerms()}},
		{Phase: "remote-access", Checks: []SimCheck{checkRemoteAccessSoftware()}},
		{Phase: "trust-store", Checks: []SimCheck{checkTrustStore()}},
		{Phase: "persistence", Checks: []SimCheck{checkSystemdUnitDirPerms()}},
	}
}

// ── T1552.001 · credentials in files ────────────────────────────────────────

func checkCredentialFilePerms() SimCheck {
	return check("T1552.001", "Credential Files Readable Only by Owner", "credential-hygiene", "Critical",
		"A private key or cloud credential readable by another local account hands over working access directly — nothing has to be cracked.",
		"Restore owner-only access: chmod 600 on the affected files, and chmod 700 on ~/.ssh.",
		func() (string, string) {
			// /root is not under /home, and is the account whose keys matter most.
			findings, scanned := scanCredentialStores(homeDirsUnder("/home", "/root"))
			return evalCredentialFiles(findings, scanned)
		})
}

// ── T1219 · remote access software ──────────────────────────────────────────

func checkRemoteAccessSoftware() SimCheck {
	return check("T1219", "Remote Access Software Present", "remote-access", "High",
		"Remote access and RMM tools provide an inbound path that bypasses the network perimeter entirely, and are the usual route in support-desk fraud.",
		"Remove unsanctioned remote access tools, or bring them under managed policy with logging.",
		func() (string, string) {
			// Reuses the security-product inventory's /proc reader: one pass over
			// /proc rather than a process spawn per candidate, for the same reason
			// -- a burst of spawns is what a watching EDR blocks.
			running, diag := scanProcComms("/")
			if len(running) == 0 && len(diag) > 0 {
				return "skipped", "Could not read /proc; remote access software was not assessed."
			}
			return evalRemoteAccessSoftware(matchRemoteAccess(running, pathExists))
		})
}

// ── T1553.004 · root certificate trust store ────────────────────────────────

// linuxTrustAnchorDirs are where an administrator drops a certificate authority
// for system-wide trust. Both the Debian and RHEL locations are read, since the
// agent ships to both and the wrong one simply does not exist.
var linuxTrustAnchorDirs = []string{
	"/usr/local/share/ca-certificates",
	"/etc/pki/ca-trust/source/anchors",
	"/etc/ca-certificates/trust-source/anchors",
}

func checkTrustStore() SimCheck {
	return check("T1553.004", "No Locally Added Root Certificates", "trust-store", "High",
		"Whoever holds the private key for a trusted root can mint certificates this endpoint accepts, which is how TLS interception is established.",
		"Review the local trust anchors and remove any that are not justified, then run update-ca-certificates.",
		func() (string, string) {
			roots, readable := certFilesIn(linuxTrustAnchorDirs)
			return evalTrustStore(roots, readable)
		})
}

// ── T1543.002 · systemd service persistence ─────────────────────────────────

// systemdUnitDirs are where a unit file grants boot persistence as root. The
// local admin directory comes first because it is the one an attacker can
// usually reach; the vendor directories are included because a writable one is
// just as good a foothold.
var systemdUnitDirs = []string{
	"/etc/systemd/system",
	"/lib/systemd/system",
	"/usr/lib/systemd/system",
}

func checkSystemdUnitDirPerms() SimCheck {
	return check("T1543.002", "systemd Unit Directories Writable Only by Root", "persistence", "High",
		"A unit file another account can write executes as root at every boot, which converts local write access into permanent root.",
		"Restore ownership and mode: sudo chown root:root and sudo chmod 755 on the affected systemd directories.",
		func() (string, string) {
			return evalWritableDirs("systemd unit", dirModes(systemdUnitDirs),
				"executes as root at every boot")
		})
}
