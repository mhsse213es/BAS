//go:build darwin

package main

import (
	"context"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Section A of the POSIX posture coverage map: macOS equivalents of checks
// simulate_linux.go already runs.
//
// Everything here is the READ that feeds a decision. The decisions themselves
// live in simulate_mac_posture.go, which carries no build tag and is
// unit-tested from the Windows build host -- there is no Mac available to this
// project, so a threshold that could only be verified on macOS could not be
// verified at all.
//
// The phase names these register under deliberately match simulate_linux.go
// rather than this file's MITRE tactic names, so the same finding groups
// identically in a report whichever OS produced it.

// macProbeCmdTimeout bounds a probe that can leave the machine.
// `softwareupdate -l` contacts Apple and would otherwise hang the check.
const macProbeCmdTimeout = 45 * time.Second

// cmdOutBounded is cmdOut with a deadline, for probes that are not purely local.
func cmdOutBounded(name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), macProbeCmdTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).Output()
	return strings.TrimSpace(string(out)), err
}

// macSectionAChecks returns every check in this file, grouped the way the Linux
// agent groups its equivalents.
func macSectionAChecks() []SimCategory {
	return []SimCategory{
		{Phase: "ssh-hardening", Checks: checkSSHDHardening()},
		{Phase: "password-policy", Checks: []SimCheck{checkPasswordPolicy()}},
		{Phase: "cscrf-business-continuity", Checks: []SimCheck{checkPatchCurrency()}},
		{Phase: "network", Checks: []SimCheck{checkListeningServices()}},
		{Phase: "persistence-accounts", Checks: []SimCheck{
			checkGuestAccount(), checkAdminGroup(),
		}},
		{Phase: "access-control", Checks: []SimCheck{
			checkAuditFlags(), checkAuditRetention(),
			checkCronAccess(), checkLaunchDirPerms(),
		}},
		{Phase: "privilege-escalation-suid", Checks: []SimCheck{checkSUIDBinaries()}},
	}
}

// ── T1078 · SSH daemon hardening ────────────────────────────────────────────

// sshdConfigContent returns sshd_config with its drop-ins appended, mirroring
// the Linux reader. Order matters: sshd honours the LAST occurrence of a
// keyword, so drop-ins must follow the main file exactly as they do on disk.
func sshdConfigContent() string {
	var b strings.Builder
	if data, err := os.ReadFile("/etc/ssh/sshd_config"); err == nil {
		b.Write(data)
		b.WriteString("\n")
	}
	matches, _ := filepath.Glob("/etc/ssh/sshd_config.d/*.conf")
	sort.Strings(matches)
	for _, m := range matches {
		if data, err := os.ReadFile(m); err == nil {
			b.Write(data)
			b.WriteString("\n")
		}
	}
	return b.String()
}

// checkSSHDHardening returns the five sshd directives the Linux agent checks.
func checkSSHDHardening() []SimCheck {
	type spec struct {
		name, severity, threat, fix string
		eval                        func(string) (string, string)
	}
	specs := []spec{
		{"SSH Root Login Disabled (PermitRootLogin no)", "High",
			"Direct root login over SSH turns one stolen credential into full control of the endpoint, with no sudo audit trail behind it.",
			"Set PermitRootLogin no in /etc/ssh/sshd_config and reload sshd.", evalSSHRootLogin},
		{"SSH Empty Passwords Forbidden (PermitEmptyPasswords no)", "Critical",
			"An account with an empty password becomes remotely reachable with no credential at all.",
			"Set PermitEmptyPasswords no in /etc/ssh/sshd_config.", evalSSHEmptyPasswords},
		{"SSH MaxAuthTries <= 4", "Medium",
			"A high per-connection attempt limit multiplies how many passwords an attacker tries per unit of effort.",
			"Set MaxAuthTries 4 in /etc/ssh/sshd_config.", evalSSHMaxAuthTries},
		{"SSH Ignores .rhosts Files (IgnoreRhosts yes)", "Medium",
			"Honouring .rhosts lets anyone who can write to a home directory grant themselves passwordless access.",
			"Set IgnoreRhosts yes in /etc/ssh/sshd_config.", evalSSHIgnoreRhosts},
		{"SSH Host-Based Authentication Disabled", "Medium",
			"Host-based auth trusts a peer's claim about which user it is, which a compromised peer can forge.",
			"Set HostbasedAuthentication no in /etc/ssh/sshd_config.", evalSSHHostbasedAuth},
	}
	cfg := sshdConfigContent()
	out := make([]SimCheck, 0, len(specs))
	for _, sp := range specs {
		eval := sp.eval
		out = append(out, check("T1078", sp.name, "ssh-hardening", sp.severity, sp.threat, sp.fix,
			func() (string, string) {
				if strings.TrimSpace(cfg) == "" {
					return "skipped", "sshd_config could not be read, so SSH daemon hardening was not measured."
				}
				return eval(cfg)
			}))
	}
	return out
}

// ── T1110 · password and lockout policy ─────────────────────────────────────

func checkPasswordPolicy() SimCheck {
	return check("T1110", "Password Policy and Lockout Threshold", "password-policy", "High",
		"Without a minimum length and a lockout threshold, password guessing against local accounts is effectively unbounded.",
		"Apply an account policy with pwpolicy, or push one from MDM: minimum 12 characters, lockout after 10 failed attempts.",
		func() (string, string) {
			// pwpolicy exits non-zero when no policy is set, which is NOT the
			// same as the policy being weak. evalPasswordPolicy holds that
			// distinction and withholds rather than inventing a finding.
			out, _ := cmdOut("pwpolicy", "-getaccountpolicies")
			return evalPasswordPolicy(out)
		})
}

// ── T1082 · patch currency ──────────────────────────────────────────────────

func checkPatchCurrency() SimCheck {
	return check("T1082", "Pending Security Updates (CSCRF-5.1)", "cscrf-business-continuity", "High",
		"An endpoint behind the vendor patch level is exposed to publicly documented exploits with published proof-of-concept code.",
		"Apply pending updates: sudo softwareupdate -ia --restart.",
		func() (string, string) {
			out, err := cmdOutBounded("softwareupdate", "-l")
			if err != nil && strings.TrimSpace(out) == "" {
				return "skipped", "Could not query Apple software update; patch currency was not measured."
			}
			return evalSoftwareUpdates(out)
		})
}

// ── T1046 · exposed listening services ──────────────────────────────────────

func checkListeningServices() SimCheck {
	return check("T1046", "TCP Services Exposed Beyond Loopback", "network", "Medium",
		"Every service bound to a routable address is an entry point reachable by anything that can route to this endpoint.",
		"Disable services that do not need network reach, or bind them to 127.0.0.1.",
		func() (string, string) {
			out, err := cmdOut("lsof", "-nP", "-iTCP", "-sTCP:LISTEN")
			if err != nil && strings.TrimSpace(out) == "" {
				return "skipped", "Could not enumerate listening sockets; network exposure was not measured."
			}
			return evalListeningServices(out)
		})
}

// ── T1098 · account manipulation ────────────────────────────────────────────

func checkGuestAccount() SimCheck {
	return check("T1098", "Guest Account Disabled", "persistence-accounts", "High",
		"An enabled guest account gives anyone with physical access a local session with no credential, and a foothold to stage from.",
		"Disable it: System Settings → Users & Groups → Guest User → off.",
		func() (string, string) {
			// This key is absent until the guest account is switched on, so an
			// error here is the answer rather than a failure to measure.
			out, _ := readDefaults("/Library/Preferences/com.apple.loginwindow", "GuestEnabled")
			return evalGuestAccount(out)
		})
}

func checkAdminGroup() SimCheck {
	return check("T1098", "Local Administrator Account Count", "persistence-accounts", "Medium",
		"Every local administrator is an account whose compromise yields full control of the endpoint.",
		"Remove standing admin rights from day-to-day accounts; grant them per-task instead.",
		func() (string, string) {
			out, err := cmdOut("dscl", ".", "-read", "/Groups/admin", "GroupMembership")
			if err != nil && strings.TrimSpace(out) == "" {
				return "skipped", "Could not read administrator group membership."
			}
			return evalAdminGroup(out)
		})
}

// ── T1070 · audit subsystem ─────────────────────────────────────────────────

// auditControlPath is the BSM audit configuration. Apple has been retiring this
// subsystem, so its absence is an OS-version fact, not a misconfiguration.
const auditControlPath = "/etc/security/audit_control"

func readAuditControl() (string, bool) {
	data, err := os.ReadFile(auditControlPath)
	if err != nil {
		return "", false
	}
	return string(data), true
}

func checkAuditFlags() SimCheck {
	return check("T1070", "Audit Flags Cover Login and Admin Activity", "access-control", "High",
		"Without login and administrative audit classes enabled, an intrusion leaves no local record to reconstruct it from.",
		"Set flags:lo,ad in /etc/security/audit_control and restart the audit daemon.",
		func() (string, string) {
			content, present := readAuditControl()
			return evalAuditFlags(content, present)
		})
}

func checkAuditRetention() SimCheck {
	return check("T1070", "Audit Record Retention Configured", "access-control", "Medium",
		"Audit records that roll away before anyone looks at them are not evidence.",
		"Set expire-after in /etc/security/audit_control to match your retention policy.",
		func() (string, string) {
			content, present := readAuditControl()
			return evalAuditRetention(content, present)
		})
}

// ── T1053 · who may schedule work ───────────────────────────────────────────

func checkCronAccess() SimCheck {
	return check("T1053", "Cron Access Restricted to Authorised Users", "access-control", "Medium",
		"Any user who can schedule a recurring job holds persistence that survives reboot.",
		"Create /etc/cron.allow listing only the accounts permitted to schedule jobs.",
		func() (string, string) {
			allow, allowErr := os.ReadFile("/etc/cron.allow")
			_, denyErr := os.Stat("/etc/cron.deny")
			return evalCronAccess(allowErr == nil, string(allow), denyErr == nil)
		})
}

// launchDirs are the system launchd directories. A plist dropped here runs as
// root at boot, so write access to them is write access to root.
var launchDirs = []string{"/Library/LaunchDaemons", "/Library/LaunchAgents"}

func checkLaunchDirPerms() SimCheck {
	return check("T1053", "launchd Directories Writable Only by Root", "access-control", "High",
		"A user who can write to a system launchd directory gains persistence that executes as root at every boot.",
		"Restore ownership and mode: sudo chown root:wheel and sudo chmod 755 on /Library/LaunchDaemons and /Library/LaunchAgents.",
		func() (string, string) {
			modes := map[string]fs.FileMode{}
			for _, d := range launchDirs {
				if st, err := os.Stat(d); err == nil {
					modes[d] = st.Mode()
				}
			}
			return evalLaunchDirPerms(modes)
		})
}

// ── T1562.004 · firewall depth ──────────────────────────────────────────────

func checkFirewallStealth() SimCheck {
	return check("T1562.004", "Firewall Stealth Mode and Logging", "impact", "Medium",
		"A firewall that answers unsolicited probes confirms this host exists to a scanner, and one that logs nothing leaves blocked attempts uninvestigable.",
		"Enable both: sudo socketfilterfw --setstealthmode on --setloggingmode on.",
		func() (string, string) {
			stealth, err1 := cmdOut(socketfilterfwPath, "--getstealthmode")
			logging, err2 := cmdOut(socketfilterfwPath, "--getloggingmode")
			if err1 != nil && err2 != nil {
				return "skipped", "Could not read firewall stealth or logging mode."
			}
			return evalFirewallStealth(stealth, logging)
		})
}

// ── T1548.001 · setuid binaries ─────────────────────────────────────────────

// suidSearchRoots are third-party territory. Apple's own setuid binaries live
// under SIP-protected system paths, are expected, and would bury the finding.
// Scoping here also keeps this off a full-volume walk.
var suidSearchRoots = []string{"/usr/local", "/opt", "/Applications"}

func checkSUIDBinaries() SimCheck {
	return check("T1548.001", "Unexpected SUID Binaries", "privilege-escalation-suid", "High",
		"A setuid binary runs as its owner no matter who invokes it, so a flaw in one is a direct local path to root.",
		"Remove the setuid bit where it is not required: sudo chmod u-s <path>.",
		func() (string, string) {
			args := []string{}
			for _, r := range suidSearchRoots {
				if st, err := os.Stat(r); err == nil && st.IsDir() {
					args = append(args, r)
				}
			}
			if len(args) == 0 {
				return "skipped", "None of the third-party search roots exist; setuid exposure was not measured."
			}
			// -xdev keeps the walk off network and external volumes, which
			// would otherwise dominate the runtime.
			args = append(args, "-xdev", "-type", "f", "-perm", "-4000")
			out, err := cmdOutBounded("find", args...)
			if err != nil && strings.TrimSpace(out) == "" {
				return "skipped", "Could not enumerate setuid binaries."
			}
			return evalSUIDBinaries(out)
		})
}
