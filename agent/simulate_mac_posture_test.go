package main

import (
	"io/fs"
	"strings"
	"testing"
)

// Section A of the POSIX posture coverage map: macOS checks whose Linux
// equivalent already exists. Every evaluator is pure -- text in, verdict out --
// so the pass/fail thresholds are verified on the build host rather than only
// on a Mac.

func wantResult(t *testing.T, got, want, details string) {
	t.Helper()
	if got != want {
		t.Errorf("result = %q, want %q (details: %s)", got, want, details)
	}
	if strings.TrimSpace(details) == "" {
		t.Error("every verdict must carry details a reader can act on")
	}
}

// ---------------------------------------------------------------------------
// T1078 -- SSH daemon hardening
// ---------------------------------------------------------------------------

const hardenedSSHD = `
PermitRootLogin no
PermitEmptyPasswords no
MaxAuthTries 3
IgnoreRhosts yes
HostbasedAuthentication no
`

const weakSSHD = `
PermitRootLogin yes
PermitEmptyPasswords yes
MaxAuthTries 10
IgnoreRhosts no
HostbasedAuthentication yes
`

func TestSSHDEvaluators_HardenedPasses(t *testing.T) {
	for name, fn := range sshEvaluators() {
		r, d := fn(hardenedSSHD)
		if r != "pass" {
			t.Errorf("%s: result = %q, want pass (%s)", name, r, d)
		}
	}
}

func TestSSHDEvaluators_WeakFails(t *testing.T) {
	for name, fn := range sshEvaluators() {
		r, d := fn(weakSSHD)
		if r != "fail" {
			t.Errorf("%s: result = %q, want fail (%s)", name, r, d)
		}
	}
}

// An absent directive is not a guess in either direction. OpenSSH applies a
// compiled-in default, and the verdict must name it so a reader can tell an
// explicit weakening from an unset value.
func TestSSHDEvaluators_AbsentDirectiveNamesTheDefault(t *testing.T) {
	for name, fn := range sshEvaluators() {
		_, d := fn("# nothing configured\n")
		if !strings.Contains(strings.ToLower(d), "default") {
			t.Errorf("%s: details must say the OpenSSH default applies, got %q", name, d)
		}
	}
}

// A commented-out directive is not set. Reading it as configured would report
// hardening that is not in force.
func TestSSHDConfigValue_IgnoresComments(t *testing.T) {
	if v := sshdConfigValue("#PermitRootLogin yes\n", "PermitRootLogin"); v != "" {
		t.Errorf("commented directive read as %q, want empty", v)
	}
	if v := sshdConfigValue("PermitRootLogin no\n", "permitrootlogin"); v != "no" {
		t.Errorf("keyword match must be case-insensitive, got %q", v)
	}
}

// sshd applies the LAST matching directive in the file.
func TestSSHDConfigValue_LastDirectiveWins(t *testing.T) {
	cfg := "PermitRootLogin no\nPermitRootLogin yes\n"
	if v := sshdConfigValue(cfg, "PermitRootLogin"); v != "yes" {
		t.Errorf("got %q, want yes -- sshd honours the last occurrence", v)
	}
}

// ---------------------------------------------------------------------------
// T1110 -- password policy
// ---------------------------------------------------------------------------

func TestPasswordPolicy_StrongPasses(t *testing.T) {
	out := `policyAttributePassword matches '.{12,}'
policyAttributeMaximumFailedAuthentications 5
policyAttributeExpiresEveryNDays 90`
	r, d := evalPasswordPolicy(out)
	wantResult(t, r, "pass", d)
}

func TestPasswordPolicy_ShortMinimumFails(t *testing.T) {
	out := `policyAttributePassword matches '.{6,}'
policyAttributeMaximumFailedAuthentications 5`
	r, d := evalPasswordPolicy(out)
	wantResult(t, r, "fail", d)
	if !strings.Contains(d, "6") {
		t.Errorf("details must name the observed value, got %q", d)
	}
}

// The honesty case. macOS accepts a password policy pushed by MDM that
// pwpolicy cannot read. An empty result therefore does NOT prove the endpoint
// has no policy, and reporting "fail" would invent a finding on a correctly
// managed Mac.
func TestPasswordPolicy_NoVisiblePolicyIsWithheldNotFailed(t *testing.T) {
	r, d := evalPasswordPolicy("")
	wantResult(t, r, "skipped", d)
	if !strings.Contains(strings.ToUpper(d), "MDM") {
		t.Errorf("details must explain why this is withheld, got %q", d)
	}
}

// ---------------------------------------------------------------------------
// T1082 -- patch currency
// ---------------------------------------------------------------------------

func TestSoftwareUpdates_UpToDatePasses(t *testing.T) {
	r, d := evalSoftwareUpdates("Software Update Tool\n\nNo new software available.\n")
	wantResult(t, r, "pass", d)
}

func TestSoftwareUpdates_PendingUpdatesFail(t *testing.T) {
	out := `Software Update Tool

Software Update found the following new or updated software:
* Label: macOS Sequoia 15.6.1-24G90
	Title: macOS Sequoia 15.6.1, Version: 15.6.1, Size: 4823140KiB, Recommended: YES, Action: restart,
* Label: Safari-18.6
	Title: Safari, Version: 18.6, Size: 128000KiB, Recommended: YES,`
	r, d := evalSoftwareUpdates(out)
	wantResult(t, r, "fail", d)
	if !strings.Contains(d, "2") {
		t.Errorf("details must count the pending updates, got %q", d)
	}
}

// ---------------------------------------------------------------------------
// T1046 -- exposed listening services
// ---------------------------------------------------------------------------

func TestListeningServices_LoopbackOnlyPasses(t *testing.T) {
	out := `COMMAND   PID USER   FD TYPE DEVICE SIZE/OFF NODE NAME
launchd     1 root    7u IPv4 0x1234      0t0  TCP 127.0.0.1:631 (LISTEN)
launchd     1 root    8u IPv6 0x1234      0t0  TCP [::1]:631 (LISTEN)`
	r, d := evalListeningServices(out)
	wantResult(t, r, "pass", d)
}

func TestListeningServices_WildcardBindFails(t *testing.T) {
	out := `COMMAND   PID USER   FD TYPE DEVICE SIZE/OFF NODE NAME
sshd      455 root    5u IPv4 0x1234      0t0  TCP *:22 (LISTEN)
httpd     902 root    4u IPv4 0x1234      0t0  TCP 192.168.1.10:8080 (LISTEN)
launchd     1 root    7u IPv4 0x1234      0t0  TCP 127.0.0.1:631 (LISTEN)`
	r, d := evalListeningServices(out)
	wantResult(t, r, "fail", d)
	if !strings.Contains(d, "22") || !strings.Contains(d, "8080") {
		t.Errorf("details must name the exposed ports, got %q", d)
	}
	if strings.Contains(d, "631") {
		t.Errorf("loopback-only ports must not be reported as exposed: %q", d)
	}
}

// ---------------------------------------------------------------------------
// T1098 -- account manipulation
// ---------------------------------------------------------------------------

func TestGuestAccount_DisabledPasses(t *testing.T) {
	r, d := evalGuestAccount("0")
	wantResult(t, r, "pass", d)
}

func TestGuestAccount_EnabledFails(t *testing.T) {
	r, d := evalGuestAccount("1")
	wantResult(t, r, "fail", d)
}

// `defaults read` errors when the key was never written, which is macOS's way
// of saying the guest account is off.
func TestGuestAccount_UnsetMeansDisabled(t *testing.T) {
	r, d := evalGuestAccount("")
	wantResult(t, r, "pass", d)
}

func TestAdminGroup_CountsNonSystemMembers(t *testing.T) {
	r, d := evalAdminGroup("GroupMembership: root admin_user")
	wantResult(t, r, "pass", d)

	r, d = evalAdminGroup("GroupMembership: root alice bob carol dave")
	wantResult(t, r, "fail", d)
	if !strings.Contains(d, "4") {
		t.Errorf("details must state the count, got %q", d)
	}
	if strings.Contains(d, "root ") {
		t.Errorf("root is a system account and must not inflate the count: %q", d)
	}
}

// ---------------------------------------------------------------------------
// T1070 -- audit subsystem
// ---------------------------------------------------------------------------

func TestAuditFlags_LoginAndAdminPass(t *testing.T) {
	r, d := evalAuditFlags("dir:/var/audit\nflags:lo,ad,aa\nexpire-after:60d\n", true)
	wantResult(t, r, "pass", d)
}

func TestAuditFlags_MissingLoginClassFails(t *testing.T) {
	r, d := evalAuditFlags("dir:/var/audit\nflags:ad\nexpire-after:60d\n", true)
	wantResult(t, r, "fail", d)
	if !strings.Contains(d, "lo") {
		t.Errorf("details must name the missing class, got %q", d)
	}
}

// Apple has been retiring the BSM audit subsystem. Its absence is a property of
// the OS version, not a misconfiguration, and must not read as a failure.
func TestAuditFlags_AbsentSubsystemIsWithheldNotFailed(t *testing.T) {
	r, d := evalAuditFlags("", false)
	wantResult(t, r, "skipped", d)
	if !strings.Contains(strings.ToLower(d), "version") {
		t.Errorf("details must attribute the absence to the OS version, got %q", d)
	}
}

func TestAuditRetention_UnsetFails(t *testing.T) {
	r, d := evalAuditRetention("dir:/var/audit\nflags:lo,ad\n", true)
	wantResult(t, r, "fail", d)
}

// ---------------------------------------------------------------------------
// T1053 -- who may schedule work
// ---------------------------------------------------------------------------

func TestCronAccess_AllowListRestrictsPasses(t *testing.T) {
	r, d := evalCronAccess(true, "root\n", false)
	wantResult(t, r, "pass", d)
}

func TestCronAccess_NoAllowListFails(t *testing.T) {
	r, d := evalCronAccess(false, "", false)
	wantResult(t, r, "fail", d)
}

// An empty cron.allow denies everyone -- the most restrictive state there is,
// and the opposite of the "no restriction" the empty file might suggest.
func TestCronAccess_EmptyAllowListDeniesEveryone(t *testing.T) {
	r, d := evalCronAccess(true, "\n", false)
	wantResult(t, r, "pass", d)
}

func TestLaunchDirPerms_GroupWritableFails(t *testing.T) {
	r, d := evalLaunchDirPerms(map[string]fs.FileMode{
		"/Library/LaunchDaemons": 0o755,
		"/Library/LaunchAgents":  0o775, // group-writable
	})
	wantResult(t, r, "fail", d)
	if !strings.Contains(d, "LaunchAgents") {
		t.Errorf("details must name the offending directory, got %q", d)
	}
}

func TestLaunchDirPerms_RootOnlyPasses(t *testing.T) {
	r, d := evalLaunchDirPerms(map[string]fs.FileMode{
		"/Library/LaunchDaemons": 0o755,
		"/Library/LaunchAgents":  0o755,
	})
	wantResult(t, r, "pass", d)
}

// ---------------------------------------------------------------------------
// T1562.004 -- firewall depth
// ---------------------------------------------------------------------------

func TestFirewallStealth_BothOnPasses(t *testing.T) {
	r, d := evalFirewallStealth("Stealth mode enabled", "Log mode is on")
	wantResult(t, r, "pass", d)
}

func TestFirewallStealth_LoggingOffFails(t *testing.T) {
	r, d := evalFirewallStealth("Stealth mode enabled", "Log mode is off")
	wantResult(t, r, "fail", d)
	if !strings.Contains(strings.ToLower(d), "logging") {
		t.Errorf("details must name what is off, got %q", d)
	}
}

// ---------------------------------------------------------------------------
// T1548.001 -- setuid binaries
// ---------------------------------------------------------------------------

func TestSUIDBinaries_NoneOutsideSystemPasses(t *testing.T) {
	r, d := evalSUIDBinaries("")
	wantResult(t, r, "pass", d)
}

func TestSUIDBinaries_UnexpectedBinaryFails(t *testing.T) {
	r, d := evalSUIDBinaries("/usr/local/bin/escalate\n/Applications/Vendor.app/Contents/helper\n")
	wantResult(t, r, "fail", d)
	if !strings.Contains(d, "escalate") {
		t.Errorf("details must name the binary, got %q", d)
	}
	if !strings.Contains(d, "2") {
		t.Errorf("details must count them, got %q", d)
	}
}

// ---------------------------------------------------------------------------
// Cross-cutting: every evaluator must produce a verdict from the taxonomy.
// ---------------------------------------------------------------------------

func TestMacEvaluators_ProduceOnlyKnownVerdicts(t *testing.T) {
	valid := map[string]bool{"pass": true, "fail": true, "skipped": true}
	results := []string{}
	for _, fn := range sshEvaluators() {
		r, _ := fn("")
		results = append(results, r)
	}
	r, _ := evalPasswordPolicy("garbage")
	results = append(results, r)
	r, _ = evalSoftwareUpdates("garbage")
	results = append(results, r)
	r, _ = evalListeningServices("garbage")
	results = append(results, r)
	r, _ = evalGuestAccount("garbage")
	results = append(results, r)
	r, _ = evalAdminGroup("garbage")
	results = append(results, r)
	r, _ = evalAuditFlags("garbage", true)
	results = append(results, r)
	r, _ = evalSUIDBinaries("garbage")
	results = append(results, r)
	for i, got := range results {
		if !valid[got] {
			t.Errorf("evaluator %d returned %q, outside pass|fail|skipped", i, got)
		}
	}
}
