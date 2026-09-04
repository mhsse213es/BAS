//go:build linux

package main

import (
	"os"
	"strings"
)

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

// ── Section B, second tranche ───────────────────────────────────────────────
//
// T1048.003 is absent here on purpose: the Linux agent already checks telnet,
// rsh/rlogin and TFTP under T1078 and T1105, so the coverage map scoped that
// row to macOS. T1113 and T1056.001 are absent because Linux has no consent
// surface equivalent to macOS TCC -- that is a genuine platform difference, not
// a gap to fill.

func linuxSectionB2Checks() []SimCategory {
	return []SimCategory{
		{Phase: "recovery-readiness", Checks: []SimCheck{
			checkBackupMechanism(), checkLocalSnapshots(),
		}},
		{Phase: "data-protection", Checks: []SimCheck{
			checkRemovableMedia(), checkBrowserCredentialStores(), checkBrowserExtensions(),
		}},
	}
}

// ── T1486 · backup mechanism ────────────────────────────────────────────────

func checkBackupMechanism() SimCheck {
	return check("T1486", "Backup Mechanism Present", "recovery-readiness", "High",
		"Ransomware that encrypts files in place is survivable only if a restore point exists somewhere.",
		"Install and schedule a backup agent, or confirm the endpoint is covered by a backup taken below the guest.",
		func() (string, string) {
			running, diag := scanProcComms("/")
			if len(running) == 0 && len(diag) > 0 {
				return evalBackupMechanism(nil, false)
			}
			var found []string
			for _, sig := range backupAgentCatalogue {
				matched := false
				for _, p := range sig.procs {
					if running[p] {
						found = append(found, sig.label+" ("+p+" running)")
						matched = true
						break
					}
				}
				if matched {
					continue
				}
				for _, p := range sig.paths {
					if pathExists(p) {
						found = append(found, sig.label+" (installed at "+p+")")
						break
					}
				}
			}
			return evalBackupMechanism(found, true)
		})
}

// ── T1490 · local recovery snapshots ────────────────────────────────────────

// snapshotCapableFS are the filesystems that can hold a point-in-time snapshot
// of the running system.
var snapshotCapableFS = []string{"btrfs", "zfs"}

// snapshotDirs are where the common tooling parks its snapshots.
var snapshotDirs = []string{"/.snapshots", "/timeshift", "/run/timeshift", "/.zfs/snapshot"}

func checkLocalSnapshots() SimCheck {
	return check("T1490", "Local Recovery Snapshots Present", "recovery-readiness", "High",
		"Without a local snapshot there is nothing on this endpoint to roll back to after in-place encryption.",
		"Enable filesystem snapshots (btrfs/ZFS) or a snapshot tool such as Timeshift, and verify they are being taken.",
		func() (string, string) {
			mounts, err := os.ReadFile("/proc/mounts")
			capable := false
			if err == nil {
				for _, fsName := range snapshotCapableFS {
					if strings.Contains(string(mounts), " "+fsName+" ") {
						capable = true
						break
					}
				}
			}
			var snaps []string
			for _, d := range snapshotDirs {
				entries, err := os.ReadDir(d)
				if err != nil {
					continue
				}
				capable = true
				for _, e := range entries {
					if e.IsDir() {
						snaps = append(snaps, d+"/"+e.Name())
					}
				}
			}
			return evalLocalSnapshots(snaps, capable)
		})
}

// ── T1091 · removable media policy ──────────────────────────────────────────

// usbBlacklistDirs hold the modprobe fragments that disable USB mass storage.
var usbBlacklistDirs = []string{"/etc/modprobe.d"}

func checkRemovableMedia() SimCheck {
	return check("T1091", "Removable Storage Restricted", "data-protection", "Medium",
		"Unrestricted removable storage is both an exfiltration path out and a malware delivery path in.",
		"Blacklist the usb-storage module, or deploy usbguard with an allow-list policy.",
		func() (string, string) {
			// usbguard being present is a policy mechanism in its own right.
			running, _ := scanProcComms("/")
			if running["usbguard-daemon"] || pathExists("/etc/usbguard/rules.conf") {
				return evalRemovableMediaPolicy("usbguard is installed with a rules policy", true)
			}
			// A modprobe blacklist is the other readable mechanism.
			for _, dir := range usbBlacklistDirs {
				entries, err := os.ReadDir(dir)
				if err != nil {
					continue
				}
				for _, e := range entries {
					if e.IsDir() {
						continue
					}
					data, err := os.ReadFile(dir + "/" + e.Name())
					if err != nil {
						continue
					}
					text := string(data)
					if strings.Contains(text, "usb-storage") &&
						(strings.Contains(text, "blacklist") || strings.Contains(text, "install usb-storage /bin/")) {
						return evalRemovableMediaPolicy("usb-storage is blacklisted in "+dir+"/"+e.Name(), true)
					}
				}
				// The directory was readable and held no restriction, so this
				// endpoint genuinely has none rather than us being unable to look.
				return evalRemovableMediaPolicy("", true)
			}
			return evalRemovableMediaPolicy("", false)
		})
}

// ── T1555.003 / T1176 · browser surfaces ────────────────────────────────────

// linuxBrowserRoots returns the Chromium-family and Firefox data roots for
// every user home.
func linuxBrowserRoots() (chromium, firefox []string) {
	for _, home := range homeDirsUnder("/home", "/root") {
		chromium = append(chromium,
			home+"/.config/google-chrome",
			home+"/.config/chromium",
			home+"/.config/microsoft-edge",
			home+"/.config/BraveSoftware/Brave-Browser",
		)
		firefox = append(firefox, home+"/.mozilla/firefox")
	}
	return chromium, firefox
}

func checkBrowserCredentialStores() SimCheck {
	return check("T1555.003", "Browser Saved-Password Stores", "data-protection", "High",
		"Saved browser passwords are reusable credentials, and are the first thing infostealer malware collects.",
		"Move saved credentials into a managed password manager and disable the browser's own password store by policy.",
		func() (string, string) {
			chromium, firefox := linuxBrowserRoots()
			stores, profiles, _ := scanBrowserData(chromium, firefox)
			return evalBrowserCredentialStores(stores, profiles)
		})
}

func checkBrowserExtensions() SimCheck {
	return check("T1176", "Browser Extensions Installed", "data-protection", "Medium",
		"An extension reads and rewrites every page the user visits, including the ones they authenticate to.",
		"Restrict installation to an allow-list via managed browser policy.",
		func() (string, string) {
			chromium, firefox := linuxBrowserRoots()
			_, profiles, extensions := scanBrowserData(chromium, firefox)
			return evalBrowserExtensions(extensions, profiles > 0)
		})
}
