package main

import (
	"fmt"
	"io/fs"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// macOS posture evaluators.
//
// Section A of the POSIX posture coverage map: the macOS half of checks whose
// Linux equivalent already exists. Each function is pure -- command output or
// file content in, (result, details) out -- so the pass/fail thresholds are
// verified from the build host instead of only on a Mac. The thin wrappers that
// actually read the system live in simulate_darwin.go.
//
// Every evaluator returns one of pass | fail | skipped, matching the scoring
// taxonomy. Two rules govern which:
//
//   - A threshold is only applied to a value we actually observed. Where a
//     setting is absent, the verdict names the compiled-in default rather than
//     assuming the host is hardened or weak.
//   - Where absence is genuinely ambiguous -- a policy that MDM may enforce
//     invisibly, a subsystem a newer macOS has retired -- the result is
//     "skipped" with the reason, never "fail". Withholding is honest;
//     manufacturing a finding on a correctly managed endpoint is not.

// ---------------------------------------------------------------------------
// T1078 -- SSH daemon hardening (Linux equivalent: 5 checks in simulate_linux)
// ---------------------------------------------------------------------------

// sshdConfigValue returns the effective value of an sshd_config keyword, or ""
// when it is not set.
//
// Two behaviours matter and are pinned by tests: a commented directive is not
// set, and where a keyword appears more than once sshd honours the LAST
// occurrence -- reading the first would report hardening that a later line
// overrides.
func sshdConfigValue(content, keyword string) string {
	want := strings.ToLower(keyword)
	value := ""
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 || strings.ToLower(fields[0]) != want {
			continue
		}
		value = fields[1]
	}
	return value
}

// sshEvaluators is the set under test, keyed by the directive each one reads.
func sshEvaluators() map[string]func(string) (string, string) {
	return map[string]func(string) (string, string){
		"PermitRootLogin":         evalSSHRootLogin,
		"PermitEmptyPasswords":    evalSSHEmptyPasswords,
		"MaxAuthTries":            evalSSHMaxAuthTries,
		"IgnoreRhosts":            evalSSHIgnoreRhosts,
		"HostbasedAuthentication": evalSSHHostbasedAuth,
	}
}

// sshVerdict applies one yes/no directive against the value that hardens it,
// naming the OpenSSH default when the directive is unset. Whether the default
// happens to be safe decides the verdict; either way the reader is told the
// value was not explicitly configured.
func sshVerdict(cfg, keyword, safe, def, riskWhenUnsafe, gainWhenSafe string) (string, string) {
	v := strings.ToLower(sshdConfigValue(cfg, keyword))
	if v == "" {
		if strings.EqualFold(def, safe) {
			return "pass", fmt.Sprintf("%s is not set; the OpenSSH default (%s) applies, which is the hardened value. %s",
				keyword, def, gainWhenSafe)
		}
		return "fail", fmt.Sprintf("%s is not set; the OpenSSH default (%s) applies. %s",
			keyword, def, riskWhenUnsafe)
	}
	if v == safe {
		return "pass", fmt.Sprintf("%s is %s. %s", keyword, v, gainWhenSafe)
	}
	return "fail", fmt.Sprintf("%s is %s. %s", keyword, v, riskWhenUnsafe)
}

func evalSSHRootLogin(cfg string) (string, string) {
	return sshVerdict(cfg, "PermitRootLogin", "no", "prohibit-password",
		"Direct root login over SSH removes the audit trail that sudo provides and makes the root password a single point of compromise.",
		"Interactive root login over SSH is refused.")
}

func evalSSHEmptyPasswords(cfg string) (string, string) {
	return sshVerdict(cfg, "PermitEmptyPasswords", "no", "no",
		"An account with an empty password would be reachable over the network with no credential at all.",
		"Accounts with empty passwords cannot authenticate over SSH.")
}

func evalSSHIgnoreRhosts(cfg string) (string, string) {
	return sshVerdict(cfg, "IgnoreRhosts", "yes", "yes",
		"Honouring .rhosts files lets a writable home directory grant passwordless access.",
		".rhosts files are ignored, so a writable home directory cannot grant access.")
}

func evalSSHHostbasedAuth(cfg string) (string, string) {
	return sshVerdict(cfg, "HostbasedAuthentication", "no", "no",
		"Host-based authentication trusts the calling host's assertion of identity, which a compromised peer can forge.",
		"Host-based authentication is refused; identity is proven per-user.")
}

// maxAuthTriesCeiling matches the Linux check's threshold so the same endpoint
// posture scores the same on both platforms.
const maxAuthTriesCeiling = 4

// sshdMaxAuthTriesDefault is OpenSSH's compiled-in default, which exceeds the
// ceiling -- so a stock host fails this check. That is the intended reading:
// the hardening step has not been taken. The details say so rather than
// implying someone raised the limit deliberately.
const sshdMaxAuthTriesDefault = 6

func evalSSHMaxAuthTries(cfg string) (string, string) {
	raw := sshdConfigValue(cfg, "MaxAuthTries")
	if raw == "" {
		return "fail", fmt.Sprintf("MaxAuthTries is not set; the OpenSSH default (%d) applies, above the ceiling of %d. "+
			"More attempts per connection means more guesses per unit of attacker effort.",
			sshdMaxAuthTriesDefault, maxAuthTriesCeiling)
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return "skipped", fmt.Sprintf("MaxAuthTries is set to %q, which is not a number; the effective limit could not be determined.", raw)
	}
	if n <= maxAuthTriesCeiling {
		return "pass", fmt.Sprintf("MaxAuthTries is %d, at or below the ceiling of %d.", n, maxAuthTriesCeiling)
	}
	return "fail", fmt.Sprintf("MaxAuthTries is %d, above the ceiling of %d. "+
		"More attempts per connection means more guesses per unit of attacker effort.", n, maxAuthTriesCeiling)
}

// ---------------------------------------------------------------------------
// T1110 -- password and lockout policy (Linux equivalent: 6 checks)
// ---------------------------------------------------------------------------

const (
	minPasswordLength     = 12
	maxFailedAttempts     = 10
	passwordPolicyMDMNote = "A policy pushed by MDM is enforced but is not readable through pwpolicy, " +
		"so this is reported as not measured rather than as a weak policy."
)

var (
	pwMinLenRE    = regexp.MustCompile(`\.\{(\d+),`)
	pwFailedRE    = regexp.MustCompile(`policyAttributeMaximumFailedAuthentications[^0-9]*(\d+)`)
	pwMinLenAltRE = regexp.MustCompile(`(?i)minimumLength[^0-9]*(\d+)`)
)

// evalPasswordPolicy reads `pwpolicy -getaccountpolicies`.
//
// An empty or unparseable policy is deliberately NOT a failure. macOS accepts a
// password policy delivered by a configuration profile, which pwpolicy does not
// report; treating silence as absence would invent a finding on exactly the
// endpoints that are managed correctly.
func evalPasswordPolicy(out string) (string, string) {
	minLen, haveMin := 0, false
	if m := pwMinLenRE.FindStringSubmatch(out); m != nil {
		minLen, _ = strconv.Atoi(m[1])
		haveMin = true
	} else if m := pwMinLenAltRE.FindStringSubmatch(out); m != nil {
		minLen, _ = strconv.Atoi(m[1])
		haveMin = true
	}
	failed, haveFailed := 0, false
	if m := pwFailedRE.FindStringSubmatch(out); m != nil {
		failed, _ = strconv.Atoi(m[1])
		haveFailed = true
	}

	if !haveMin && !haveFailed {
		return "skipped", "No local account policy is readable on this endpoint. " + passwordPolicyMDMNote
	}

	var problems []string
	if haveMin && minLen < minPasswordLength {
		problems = append(problems, fmt.Sprintf("minimum length is %d, below the required %d", minLen, minPasswordLength))
	}
	if !haveMin {
		problems = append(problems, "no minimum length is enforced")
	}
	if haveFailed && failed > maxFailedAttempts {
		problems = append(problems, fmt.Sprintf("lockout triggers only after %d failed attempts, above the ceiling of %d", failed, maxFailedAttempts))
	}
	if !haveFailed {
		problems = append(problems, "no failed-attempt lockout is set, so password guessing is unbounded")
	}
	if len(problems) > 0 {
		return "fail", "Account policy is weak: " + strings.Join(problems, "; ") + "."
	}
	return "pass", fmt.Sprintf("Account policy enforces a minimum length of %d and locks out after %d failed attempts.", minLen, failed)
}

// ---------------------------------------------------------------------------
// T1082 -- patch currency (Linux equivalent: CSCRF-5.1 checks)
// ---------------------------------------------------------------------------

var updateLabelRE = regexp.MustCompile(`(?m)^\s*\*\s*Label:\s*(.+)$`)

// evalSoftwareUpdates reads `softwareupdate -l`. Carries the same SEBI CSCRF-5.1
// framing as the Linux patch-currency checks.
func evalSoftwareUpdates(out string) (string, string) {
	lower := strings.ToLower(out)
	if strings.Contains(lower, "no new software available") {
		return "pass", "No pending macOS updates — the endpoint is at the vendor's current patch level (CSCRF-5.1)."
	}
	labels := updateLabelRE.FindAllStringSubmatch(out, -1)
	if len(labels) == 0 {
		return "skipped", "Could not determine pending updates from softwareupdate output; patch currency was not measured."
	}
	names := make([]string, 0, len(labels))
	for _, m := range labels {
		names = append(names, strings.TrimSpace(m[1]))
	}
	shown := names
	if len(shown) > 4 {
		shown = shown[:4]
	}
	return "fail", fmt.Sprintf("%d pending update(s) — the endpoint is behind the vendor's patch level (CSCRF-5.1): %s.",
		len(names), strings.Join(shown, ", "))
}

// ---------------------------------------------------------------------------
// T1046 -- exposed listening services (Linux equivalent: 2 checks)
// ---------------------------------------------------------------------------

var lsofNameRE = regexp.MustCompile(`(\S+):(\d+)\s+\(LISTEN\)`)

// evalListeningServices reads `lsof -nP -iTCP -sTCP:LISTEN`.
//
// Only non-loopback binds count. A service on 127.0.0.1 is not reachable from
// the network and reporting it as exposure would bury the ones that are.
func evalListeningServices(out string) (string, string) {
	exposed := map[string]bool{}
	for _, m := range lsofNameRE.FindAllStringSubmatch(out, -1) {
		host, port := m[1], m[2]
		if isLoopbackHost(host) {
			continue
		}
		exposed[port] = true
	}
	if len(exposed) == 0 {
		if !strings.Contains(out, "LISTEN") {
			return "skipped", "No listening-socket data was returned; network exposure was not measured."
		}
		return "pass", "No TCP services are bound beyond loopback — nothing is reachable from the network."
	}
	ports := make([]string, 0, len(exposed))
	for p := range exposed {
		ports = append(ports, p)
	}
	sort.Strings(ports)
	return "fail", fmt.Sprintf("%d TCP port(s) reachable from the network: %s. Each is an entry point that must be justified.",
		len(ports), strings.Join(ports, ", "))
}

func isLoopbackHost(h string) bool {
	h = strings.Trim(h, "[]")
	return h == "127.0.0.1" || h == "::1" || strings.HasPrefix(h, "127.")
}

// ---------------------------------------------------------------------------
// T1098 -- account manipulation (Linux equivalent: /etc/passwd protection)
// ---------------------------------------------------------------------------

// evalGuestAccount reads `defaults read ... GuestEnabled`. macOS never writes
// the key until the guest account is switched on, so an empty read means off --
// the tool erroring is the answer, not a failure to measure.
func evalGuestAccount(out string) (string, string) {
	v := strings.TrimSpace(out)
	if v == "" || v == "0" {
		return "pass", "The guest account is disabled — no unauthenticated local session is possible."
	}
	if v == "1" {
		return "fail", "The guest account is ENABLED — anyone with physical access gets a local session with no credential."
	}
	return "skipped", fmt.Sprintf("Guest account state could not be read (value %q).", v)
}

// maxLocalAdmins is a policy threshold, not a vulnerability boundary. It is
// stated in the details so a reader can see what the verdict was measured
// against rather than having to infer it.
const maxLocalAdmins = 2

// systemAdminMembers are always present in the admin group and are not local
// user accounts, so they must not inflate the count.
var systemAdminMembers = map[string]bool{"root": true}

// evalAdminGroup reads `dscl . -read /Groups/admin GroupMembership`.
func evalAdminGroup(out string) (string, string) {
	idx := strings.Index(out, "GroupMembership:")
	if idx < 0 {
		return "skipped", "Administrator group membership could not be read; privileged account count was not measured."
	}
	var users []string
	for _, f := range strings.Fields(out[idx+len("GroupMembership:"):]) {
		if !systemAdminMembers[f] {
			users = append(users, f)
		}
	}
	sort.Strings(users)
	if len(users) <= maxLocalAdmins {
		return "pass", fmt.Sprintf("%d local administrator account(s), at or below the threshold of %d: %s.",
			len(users), maxLocalAdmins, strings.Join(users, ", "))
	}
	return "fail", fmt.Sprintf("%d local administrator accounts, above the threshold of %d: %s. "+
		"Every additional admin is another account whose compromise yields full control of the endpoint.",
		len(users), maxLocalAdmins, strings.Join(users, ", "))
}

// ---------------------------------------------------------------------------
// T1070 -- audit subsystem (Linux equivalent: 4 auditd/journald checks)
// ---------------------------------------------------------------------------

// requiredAuditClasses are the audit event classes that make login activity and
// administrative action reconstructable after the fact.
var requiredAuditClasses = []string{"lo", "ad"}

const auditRetiredNote = "The BSM audit subsystem is absent, which is a property of this macOS version " +
	"rather than a misconfiguration; audit posture was not measured."

// evalAuditFlags reads /etc/security/audit_control. present reports whether the
// file exists at all.
func evalAuditFlags(content string, present bool) (string, string) {
	if !present {
		return "skipped", auditRetiredNote
	}
	flags := auditControlField(content, "flags")
	if flags == "" {
		return "fail", "No audit flags are configured — the audit subsystem is present but records nothing."
	}
	set := map[string]bool{}
	for _, f := range strings.Split(flags, ",") {
		set[strings.TrimSpace(f)] = true
	}
	var missing []string
	for _, want := range requiredAuditClasses {
		if !set[want] {
			missing = append(missing, want)
		}
	}
	if len(missing) > 0 {
		return "fail", fmt.Sprintf("Audit flags are %q but do not include %s — login and administrative activity is not fully recorded.",
			flags, strings.Join(missing, ", "))
	}
	return "pass", fmt.Sprintf("Audit flags %q cover login and administrative activity.", flags)
}

// evalAuditRetention checks that audit records survive long enough to
// investigate with. Records that roll away immediately are not evidence.
func evalAuditRetention(content string, present bool) (string, string) {
	if !present {
		return "skipped", auditRetiredNote
	}
	if v := auditControlField(content, "expire-after"); v != "" {
		return "pass", fmt.Sprintf("Audit records are retained per expire-after:%s.", v)
	}
	return "fail", "No audit retention is configured (expire-after unset) — records may roll away before an investigation reaches them."
}

// auditControlField reads one `key:value` line from audit_control.
func auditControlField(content, key string) string {
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if rest, ok := strings.CutPrefix(line, key+":"); ok {
			return strings.TrimSpace(rest)
		}
	}
	return ""
}

// ---------------------------------------------------------------------------
// T1053 -- who may schedule work (Linux equivalent: cron access check)
// ---------------------------------------------------------------------------

// evalCronAccess mirrors the Linux check. cron.allow is authoritative when it
// exists: only the users listed in it may schedule jobs.
//
// An EMPTY cron.allow denies everyone, which is the most restrictive state
// available -- the opposite of the "no restriction" an empty file might suggest.
func evalCronAccess(allowExists bool, allowContent string, denyExists bool) (string, string) {
	if allowExists {
		var users []string
		for _, line := range strings.Split(allowContent, "\n") {
			if u := strings.TrimSpace(line); u != "" && !strings.HasPrefix(u, "#") {
				users = append(users, u)
			}
		}
		if len(users) == 0 {
			return "pass", "cron.allow exists and is empty — no user may schedule cron jobs."
		}
		return "pass", fmt.Sprintf("cron access is restricted by cron.allow to: %s.", strings.Join(users, ", "))
	}
	if denyExists {
		return "fail", "cron access is governed only by cron.deny, so any user not explicitly denied may schedule jobs. " +
			"An allow-list is the restrictive form."
	}
	return "fail", "Neither cron.allow nor cron.deny exists — any local user may schedule recurring jobs, " +
		"which is a persistence surface that survives reboot."
}

// evalLaunchDirPerms checks the launchd directories an attacker would drop a
// persistence plist into. Root-owned and root-writable only is the safe state.
func evalLaunchDirPerms(modes map[string]fs.FileMode) (string, string) {
	if len(modes) == 0 {
		return "skipped", "launchd directory permissions could not be read; the persistence surface was not measured."
	}
	var bad []string
	paths := make([]string, 0, len(modes))
	for p := range modes {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		// 0o022 = group-write or other-write.
		if modes[p].Perm()&0o022 != 0 {
			bad = append(bad, fmt.Sprintf("%s (%04o)", p, modes[p].Perm()))
		}
	}
	if len(bad) > 0 {
		return "fail", fmt.Sprintf("Writable by non-root: %s. A user who can write here gains persistence that runs as root at boot.",
			strings.Join(bad, ", "))
	}
	return "pass", fmt.Sprintf("All %d launchd directories are writable only by root.", len(paths))
}

// ---------------------------------------------------------------------------
// T1562.004 -- firewall depth (macOS already reads the global on/off)
// ---------------------------------------------------------------------------

// evalFirewallStealth reads socketfilterfw's stealth and logging modes. The
// existing T1562.004 check reads only the global state, which says the firewall
// is on but nothing about whether it is answering probes or recording them.
func evalFirewallStealth(stealth, logging string) (string, string) {
	s := strings.ToLower(stealth)
	l := strings.ToLower(logging)
	stealthOn := strings.Contains(s, "enabled") || strings.Contains(s, " on")
	logOn := strings.Contains(l, "on")
	if !strings.Contains(s, "stealth") && !strings.Contains(l, "log") {
		return "skipped", "Firewall stealth and logging modes could not be read."
	}
	var problems []string
	if !stealthOn {
		problems = append(problems, "stealth mode is off, so the host answers unsolicited probes and confirms it exists to a scanner")
	}
	if !logOn {
		problems = append(problems, "firewall logging is off, so blocked connection attempts leave no record to investigate")
	}
	if len(problems) > 0 {
		return "fail", "Firewall is enabled but shallow: " + strings.Join(problems, "; ") + "."
	}
	return "pass", "Firewall stealth mode and connection logging are both on."
}

// ---------------------------------------------------------------------------
// T1548.001 -- setuid binaries (Linux equivalent: Unexpected SUID Binaries)
// ---------------------------------------------------------------------------

// evalSUIDBinaries reads a newline-separated find(1) result.
//
// The search is scoped by the caller to /usr/local, /Applications and /opt --
// third-party territory. Apple's own setuid binaries live under SIP-protected
// system paths, are expected, and would swamp the finding with noise.
func evalSUIDBinaries(out string) (string, string) {
	var found []string
	for _, line := range strings.Split(out, "\n") {
		if p := strings.TrimSpace(line); strings.HasPrefix(p, "/") {
			found = append(found, p)
		}
	}
	if len(found) == 0 {
		return "pass", "No setuid binaries outside Apple's system paths — no third-party binary silently runs as root."
	}
	sort.Strings(found)
	shown := found
	if len(shown) > 5 {
		shown = shown[:5]
	}
	return "fail", fmt.Sprintf("%d setuid binary/binaries outside Apple's system paths: %s. "+
		"Each runs as its owner regardless of who invokes it, so a flaw in one is a local root path.",
		len(found), strings.Join(shown, ", "))
}
