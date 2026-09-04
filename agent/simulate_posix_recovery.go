package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Section B, second tranche: recovery readiness, cleartext services, macOS
// consent grants, and the three rows the coverage map marked Constrained.
//
// Shared between Linux and macOS and untagged, for the same reason as
// simulate_posix_posture.go: the judgement is identical on both platforms and
// only the read differs.
//
// THE CONSTRAINED CONTRACT. Three of these depend on a condition the agent may
// not be able to meet -- an MDM-enforced restriction it cannot see, a TCC
// database it cannot open, a per-user browser profile it cannot reach as root.
// When the condition is unmet the check reports THE CONDITION, never a verdict.
// "We could not look" and "there is nothing there" are different statements,
// and collapsing them is how an endpoint ends up looking better than it is --
// or worse, on exactly the estates that are managed properly.

// ---------------------------------------------------------------------------
// T1486 -- backup mechanism present
// ---------------------------------------------------------------------------

// backupAgentCatalogue is the endpoint-visible backup software set.
var backupAgentCatalogue = []remoteAccessSig{
	{"restic", []string{"restic"}, []string{"/usr/bin/restic", "/usr/local/bin/restic"}},
	{"BorgBackup", []string{"borg"}, []string{"/usr/bin/borg", "/usr/local/bin/borg"}},
	{"Duplicity", []string{"duplicity"}, []string{"/usr/bin/duplicity"}},
	{"rsnapshot", []string{"rsnapshot"}, []string{"/usr/bin/rsnapshot"}},
	{"Bacula", []string{"bacula-fd"}, []string{"/opt/bacula", "/usr/sbin/bacula-fd"}},
	{"Amanda", []string{"amandad"}, []string{"/usr/libexec/amanda"}},
	{"Veeam Agent", []string{"veeamservice", "veeamagent"}, []string{"/usr/sbin/veeamservice", "/opt/veeam"}},
	{"Commvault", []string{"cvd", "ClMgrS"}, []string{"/opt/commvault"}},
	{"rclone", []string{"rclone"}, []string{"/usr/bin/rclone", "/usr/local/bin/rclone"}},
}

const backupInvisibleNote = "A backup taken outside the guest -- at the hypervisor, the array, or a " +
	"backup server that pulls rather than pushes -- leaves no trace on the endpoint. " +
	"Absence here is therefore not evidence that this endpoint is unprotected."

// evalBackupMechanism reports endpoint-visible backup software.
//
// Deliberately never fails. On a datacentre estate the backup is usually taken
// below the guest, so a failure here would land on precisely the endpoints most
// likely to be well protected. Present is worth stating; absent is not a finding
// this check is entitled to make.
func evalBackupMechanism(found []string, detectable bool) (string, string) {
	if !detectable {
		return "skipped", "Could not enumerate processes or install paths, so backup tooling was not assessed."
	}
	if len(found) == 0 {
		return "skipped", "No endpoint-visible backup mechanism was found. " + backupInvisibleNote
	}
	sort.Strings(found)
	return "pass", fmt.Sprintf("Backup mechanism present: %s.", strings.Join(found, ", "))
}

// ---------------------------------------------------------------------------
// T1490 -- local recovery snapshots
// ---------------------------------------------------------------------------

// evalLocalSnapshots reports point-in-time snapshots held on the endpoint.
//
// Unlike backup software, this one does fail when none exist: a snapshot is
// either on this filesystem or it is not, and the absence is the whole of the
// finding. Ransomware that encrypts in place is recoverable from a snapshot and
// is not recoverable without one.
func evalLocalSnapshots(snapshots []string, detectable bool) (string, string) {
	if !detectable {
		return "skipped", "No snapshot-capable filesystem or snapshot tool was found, so local recovery points were not assessed."
	}
	if len(snapshots) == 0 {
		return "fail", "No local recovery snapshots exist. Ransomware that encrypts files in place leaves " +
			"nothing on this endpoint to roll back to."
	}
	sort.Strings(snapshots)
	shown := snapshots
	if len(shown) > 3 {
		shown = shown[:3]
	}
	return "pass", fmt.Sprintf("%d local recovery snapshot(s) present, most recent: %s.",
		len(snapshots), strings.Join(shown, ", "))
}

// ---------------------------------------------------------------------------
// T1048.003 -- cleartext services
// ---------------------------------------------------------------------------

// cleartextServiceLabels are launchd jobs that carry credentials and data in
// the clear. SSH is deliberately absent: it is the encrypted alternative.
var cleartextServiceLabels = map[string]string{
	"com.apple.telnetd": "telnet",
	"com.apple.ftpd":    "ftp",
	"com.apple.tftpd":   "tftp",
	"com.apple.rlogind": "rlogin",
	"com.apple.rshd":    "rsh",
	"com.apple.uucpd":   "uucp",
}

// parseLaunchctlCleartext reads `launchctl list` and returns the friendly names
// of any cleartext services loaded.
func parseLaunchctlCleartext(out string) []string {
	var found []string
	seen := map[string]bool{}
	for _, line := range strings.Split(out, "\n") {
		for label, name := range cleartextServiceLabels {
			if strings.Contains(line, label) && !seen[name] {
				seen[name] = true
				found = append(found, name)
			}
		}
	}
	sort.Strings(found)
	return found
}

func evalCleartextServices(found []string, detectable bool) (string, string) {
	if !detectable {
		return "skipped", "Could not list loaded services, so cleartext protocol exposure was not assessed."
	}
	if len(found) == 0 {
		return "pass", "No cleartext remote-access or file-transfer services are loaded."
	}
	return "fail", fmt.Sprintf("Cleartext service(s) loaded: %s. Credentials and data cross the network "+
		"unencrypted and are readable by anything on the path.", strings.Join(found, ", "))
}

// ---------------------------------------------------------------------------
// T1113 / T1056.001 -- macOS consent grants
// ---------------------------------------------------------------------------

// tccGrant is one row of the macOS privacy consent database.
type tccGrant struct {
	Client  string
	Allowed bool
}

// tccAllowedAuthValue is what macOS stores for a granted permission.
const tccAllowedAuthValue = "2"

// parseTCCRows reads `client|auth_value` lines from a sqlite3 query.
func parseTCCRows(out string) []tccGrant {
	var rows []tccGrant
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.Split(line, "|")
		if len(parts) < 2 {
			continue
		}
		rows = append(rows, tccGrant{
			Client:  strings.TrimSpace(parts[0]),
			Allowed: strings.TrimSpace(parts[1]) == tccAllowedAuthValue,
		})
	}
	return rows
}

// evalTCCGrants reports which applications hold a sensitive consent grant.
//
// This is the macOS-only half of the coverage map: Linux has no equivalent
// consent surface, so there is nothing to port rather than a gap to fill.
//
// Every grant is listed, including Apple's own. A screen recorder that is meant
// to be there and one that is not look identical to this check -- deciding
// which is which is the reader's job, and pretending otherwise would mean
// maintaining an allow-list of "acceptable" spyware.
func evalTCCGrants(service string, rows []tccGrant, readable bool) (string, string) {
	if !readable {
		return "skipped", fmt.Sprintf("The privacy consent database could not be read, so %s grants were "+
			"not assessed. Reading it requires Full Disk Access, which this agent has not been given.", service)
	}
	var allowed []string
	for _, r := range rows {
		if r.Allowed {
			allowed = append(allowed, r.Client)
		}
	}
	if len(allowed) == 0 {
		return "pass", fmt.Sprintf("No application holds %s consent.", service)
	}
	sort.Strings(allowed)
	shown := allowed
	if len(shown) > 6 {
		shown = shown[:6]
	}
	return "fail", fmt.Sprintf("%d application(s) hold %s consent: %s. Each can capture this "+
		"user's activity silently, and every one must be recognised.",
		len(allowed), service, strings.Join(shown, ", "))
}

// ---------------------------------------------------------------------------
// T1091 -- removable media policy
// ---------------------------------------------------------------------------

// evalRemovableMediaPolicy reports whether removable storage is restricted.
//
// detectable is the Constrained condition: on macOS this is only knowable when
// the endpoint is MDM-enrolled, and on Linux only when a policy mechanism is
// installed. Unmet, the check reports that -- never "unrestricted", which would
// be a finding the evidence does not support.
func evalRemovableMediaPolicy(policy string, detectable bool) (string, string) {
	if !detectable {
		return "skipped", "No removable-media policy mechanism is readable on this endpoint, so the " +
			"restriction could not be assessed. A policy enforced by MDM is not visible here."
	}
	if policy == "" {
		return "fail", "No removable-media restriction is in force — any USB mass storage device attached " +
			"to this endpoint mounts and can be read from and written to."
	}
	return "pass", "Removable storage is restricted: " + policy + "."
}

// ---------------------------------------------------------------------------
// T1555.003 / T1176 -- browser surfaces
// ---------------------------------------------------------------------------

// browserProfileNote is the Constrained condition both browser checks carry.
const browserProfileNote = "Browser data lives in per-user profile directories; an agent running as a " +
	"service may not be able to read every user's, so this is a partial view."

func evalBrowserCredentialStores(stores []string, scanned int) (string, string) {
	if scanned == 0 {
		return "skipped", "No browser profiles were readable, so saved-credential stores were not assessed. " +
			browserProfileNote
	}
	if len(stores) == 0 {
		return "pass", fmt.Sprintf("No saved-password stores found across %d browser profile(s).", scanned)
	}
	sort.Strings(stores)
	shown := stores
	if len(shown) > 4 {
		shown = shown[:4]
	}
	return "fail", fmt.Sprintf("%d saved-password store(s) present: %s. These hold reusable credentials "+
		"that infostealer malware collects first. %s",
		len(stores), strings.Join(shown, ", "), browserProfileNote)
}

func evalBrowserExtensions(count int, scanned bool) (string, string) {
	if !scanned {
		return "skipped", "No browser profiles were readable, so installed extensions were not assessed. " +
			browserProfileNote
	}
	if count == 0 {
		return "pass", "No browser extensions are installed."
	}
	return "fail", fmt.Sprintf("%d browser extension(s) installed. An extension reads and rewrites every "+
		"page the user visits, including the ones they authenticate to, so each must be one the "+
		"organisation sanctioned. %s", count, browserProfileNote)
}

// ---------------------------------------------------------------------------
// Shared browser reader
// ---------------------------------------------------------------------------

// chromiumCredentialFiles are the saved-password stores Chromium-family
// browsers write into each profile directory.
var chromiumCredentialFiles = []string{"Login Data", "Web Data"}

// scanBrowserData walks browser data roots and reports saved-credential stores,
// how many profiles were readable, and how many extensions are installed.
//
// The two families are laid out differently -- Chromium keeps profiles as
// subdirectories of the browser root with an Extensions folder inside each,
// Firefox keeps them under a profiles directory with an extensions folder --
// but the layouts are identical across Linux and macOS, so only the roots are
// platform-specific.
func scanBrowserData(chromiumRoots, firefoxRoots []string) (stores []string, profiles, extensions int) {
	for _, root := range chromiumRoots {
		entries, err := os.ReadDir(root)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			profileDir := filepath.Join(root, e.Name())
			isProfile := false
			for _, f := range chromiumCredentialFiles {
				if st, err := os.Stat(filepath.Join(profileDir, f)); err == nil && !st.IsDir() {
					isProfile = true
					if f == "Login Data" {
						stores = append(stores, filepath.Join(profileDir, f))
					}
				}
			}
			if !isProfile {
				continue
			}
			profiles++
			if exts, err := os.ReadDir(filepath.Join(profileDir, "Extensions")); err == nil {
				for _, x := range exts {
					if x.IsDir() {
						extensions++
					}
				}
			}
		}
	}
	for _, root := range firefoxRoots {
		entries, err := os.ReadDir(root)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			profileDir := filepath.Join(root, e.Name())
			logins := filepath.Join(profileDir, "logins.json")
			if st, err := os.Stat(logins); err != nil || st.IsDir() {
				continue
			}
			profiles++
			stores = append(stores, logins)
			if exts, err := os.ReadDir(filepath.Join(profileDir, "extensions")); err == nil {
				for _, x := range exts {
					if !x.IsDir() && !strings.HasSuffix(x.Name(), ".xpi") {
						continue
					}
					extensions++
				}
			}
		}
	}
	return stores, profiles, extensions
}
