//go:build linux

package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ── fake-root helpers ────────────────────────────────────────────────────────

type fakeHost struct{ root string }

func newFakeHost(t *testing.T) *fakeHost {
	t.Helper()
	h := &fakeHost{root: t.TempDir()}
	// A /proc that exists but holds no processes is the baseline: absence of a
	// product must be distinguishable from an unreadable /proc.
	if err := os.MkdirAll(filepath.Join(h.root, "proc"), 0o755); err != nil {
		t.Fatalf("mkdir proc: %v", err)
	}
	return h
}

// withProcess adds /proc/<pid>/comm. name is written exactly as given, so a
// test can reproduce the kernel's 15-char truncation faithfully.
func (h *fakeHost) withProcess(t *testing.T, pid, name string) *fakeHost {
	t.Helper()
	dir := filepath.Join(h.root, "proc", pid)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", dir, err)
	}
	h.write(t, filepath.Join(dir, "comm"), name+"\n")
	return h
}

func (h *fakeHost) withDir(t *testing.T, p string) *fakeHost {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(h.root, p), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", p, err)
	}
	return h
}

func (h *fakeHost) withFile(t *testing.T, p, content string) *fakeHost {
	t.Helper()
	full := filepath.Join(h.root, p)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatalf("mkdir for %s: %v", p, err)
	}
	h.write(t, full, content)
	return h
}

func (h *fakeHost) write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func (h *fakeHost) enumerate(t *testing.T) (products, diag []string) {
	t.Helper()
	return enumerateSecurityProductsIn(h.root)
}

// stubAuditRules replaces the auditctl shell-out for the duration of a test.
func stubAuditRules(t *testing.T, n int, err error) {
	t.Helper()
	prev := auditRulesFn
	auditRulesFn = func() (int, error) { return n, err }
	t.Cleanup(func() { auditRulesFn = prev })
}

func joined(lines []string) string { return strings.Join(lines, "\n") }

func mustContain(t *testing.T, lines []string, want string) {
	t.Helper()
	for _, l := range lines {
		if strings.Contains(l, want) {
			return
		}
	}
	t.Errorf("no line contains %q\ngot:\n%s", want, joined(lines))
}

func mustNotContain(t *testing.T, lines []string, unwanted string) {
	t.Helper()
	for _, l := range lines {
		if strings.Contains(l, unwanted) {
			t.Errorf("line must not contain %q, got %q\nall:\n%s", unwanted, l, joined(lines))
		}
	}
}

// ── INVARIANT: installed ≠ running ───────────────────────────────────────────

// A product present only on disk is evidence of installation and nothing more.
// Reporting it as running would turn an inert install into apparent protection.
func TestInvariant_InstalledIsNotRunning(t *testing.T) {
	h := newFakeHost(t).withDir(t, "opt/CrowdStrike")
	products, _ := h.enumerate(t)

	mustContain(t, products, "CrowdStrike Falcon")
	mustContain(t, products, "not running")
	mustNotContain(t, products, "falcon-sensor running")
}

// The converse: a running process is reported as running, not as a bare
// presence claim.
func TestInvariant_RunningIsReportedAsRunning(t *testing.T) {
	h := newFakeHost(t).withProcess(t, "101", "falcon-sensor")
	products, _ := h.enumerate(t)

	mustContain(t, products, "EDR: CrowdStrike Falcon (falcon-sensor running)")
	mustNotContain(t, products, "not running")
}

// ── INVARIANT: running ≠ enforcing ───────────────────────────────────────────

// SELinux permissive logs and blocks nothing. It must never be reported in a
// way that reads as protection.
func TestInvariant_SELinuxPermissiveIsNotProtection(t *testing.T) {
	h := newFakeHost(t).withFile(t, "sys/fs/selinux/enforce", "0\n")
	products, _ := h.enumerate(t)

	mustContain(t, products, "LSM: SELinux (permissive)")
	mustNotContain(t, products, "enforcing")
}

func TestSELinuxEnforcingIsReported(t *testing.T) {
	h := newFakeHost(t).withFile(t, "sys/fs/selinux/enforce", "1\n")
	products, _ := h.enumerate(t)
	mustContain(t, products, "LSM: SELinux (enforcing)")
}

// SELinux simply not being in use is a fact about the host, not a failure to
// look: it must produce neither a product line nor a diagnostic.
//
// proc/modules is supplied so the host is fully inspectable and the assertion
// below is about SELinux alone. (Asserting on diag substrings is deliberately
// avoided here: t.TempDir() embeds the test's own name in the path, so a
// diagnostic quoting a filename would match "SELinux" for reasons that have
// nothing to do with the host's SELinux state.)
func TestSELinuxAbsentIsSilent(t *testing.T) {
	h := newFakeHost(t).withFile(t, "proc/modules", "")
	products, diag := h.enumerate(t)

	mustNotContain(t, products, "SELinux")
	if len(diag) != 0 {
		t.Errorf("a host without SELinux must not raise a diagnostic, got:\n%s", joined(diag))
	}
}

// AppArmor enabled with every profile in complain mode enforces nothing. The
// enforce count must be visible so that cannot be mistaken for protection.
func TestInvariant_AppArmorEnabledWithNoEnforcingProfiles(t *testing.T) {
	h := newFakeHost(t).
		withFile(t, "sys/module/apparmor/parameters/enabled", "Y\n").
		withFile(t, "sys/kernel/security/apparmor/profiles",
			"/usr/bin/foo (complain)\n/usr/bin/bar (complain)\n")
	products, _ := h.enumerate(t)

	mustContain(t, products, "LSM: AppArmor (enabled, 0/2 profiles enforcing)")
}

func TestAppArmorMixedProfileModes(t *testing.T) {
	h := newFakeHost(t).
		withFile(t, "sys/module/apparmor/parameters/enabled", "Y\n").
		withFile(t, "sys/kernel/security/apparmor/profiles",
			"/usr/bin/a (enforce)\n/usr/bin/b (complain)\n/usr/bin/c (enforce)\n")
	products, _ := h.enumerate(t)

	mustContain(t, products, "LSM: AppArmor (enabled, 2/3 profiles enforcing)")
}

func TestAppArmorPresentButDisabled(t *testing.T) {
	h := newFakeHost(t).withFile(t, "sys/module/apparmor/parameters/enabled", "N\n")
	products, _ := h.enumerate(t)
	mustContain(t, products, "LSM: AppArmor (present but disabled)")
}

// ── INVARIANT: daemon running ≠ meaningful coverage ──────────────────────────

// auditd with zero rules records nothing. The count must always accompany the
// daemon state so "auditd running" alone can never imply an audit trail.
func TestInvariant_AuditdRunningWithZeroRules(t *testing.T) {
	stubAuditRules(t, 0, nil)
	h := newFakeHost(t).withProcess(t, "200", "auditd")
	products, _ := h.enumerate(t)

	mustContain(t, products, "Audit: auditd running (0 rules loaded)")

	// The bare, count-free form is exactly what this invariant forbids.
	for _, l := range products {
		if strings.TrimSpace(l) == "Audit: auditd running" {
			t.Errorf("auditd reported without a rule count: %q", l)
		}
	}
}

func TestAuditdWithRules(t *testing.T) {
	stubAuditRules(t, 347, nil)
	h := newFakeHost(t).withProcess(t, "200", "auditd")
	products, _ := h.enumerate(t)
	mustContain(t, products, "Audit: auditd running (347 rules loaded)")
}

// ── INVARIANT: unable to inspect ≠ not present ───────────────────────────────

// An unreadable rule list must report "unknown" and raise a diagnostic. Zero is
// a measurement; unknown is the absence of one, and they must never collapse.
func TestInvariant_AuditRuleCountUnavailableIsUnknownNotZero(t *testing.T) {
	stubAuditRules(t, 0, errors.New("auditctl: not found"))
	h := newFakeHost(t).withProcess(t, "200", "auditd")
	products, diag := h.enumerate(t)

	mustContain(t, products, "rule count unknown")
	mustNotContain(t, products, "0 rules loaded")
	mustContain(t, diag, "auditd rule count unavailable")
}

// An unreadable /proc means we could not look. It must surface as a diagnostic
// rather than silently producing an empty, authoritative-looking inventory.
func TestInvariant_UnreadableProcIsDiagnosticNotAbsence(t *testing.T) {
	root := t.TempDir() // deliberately no /proc at all
	products, diag := enumerateSecurityProductsIn(root)

	if len(products) != 0 {
		t.Errorf("expected no products from an uninspectable host, got:\n%s", joined(products))
	}
	mustContain(t, diag, "process scan unavailable")
	if len(diag) == 0 {
		t.Fatal("an uninspectable host produced an empty inventory with NO diagnostic — indistinguishable from a clean host")
	}
}

// A /sys path that exists but cannot be read is "unknown", never "absent".
//
// The unreadable path is simulated by creating enforce as a DIRECTORY rather
// than by stripping permissions: the agent runs as root on real endpoints (and
// in CI), where permission bits are not enforced and a chmod-based test would
// silently skip. Reading a directory fails with EISDIR, which is exactly the
// "exists but cannot be read" branch under test, and it behaves identically
// whoever runs it.
func TestInvariant_UnreadableSELinuxIsDiagnostic(t *testing.T) {
	h := newFakeHost(t).
		withFile(t, "proc/modules", "").
		withDir(t, "sys/fs/selinux/enforce")

	products, diag := h.enumerate(t)

	mustNotContain(t, products, "SELinux")
	mustContain(t, diag, "SELinux state unknown")
	if len(diag) == 0 {
		t.Fatal("an unreadable SELinux state produced no diagnostic — indistinguishable from SELinux being absent")
	}
}

// ── evidence-source behaviour ────────────────────────────────────────────────

// The kernel truncates /proc/<pid>/comm to 15 characters. A catalogue entry
// longer than that could otherwise never match, producing a silent, permanent
// false negative.
func TestProcCommTruncationIsMatched(t *testing.T) {
	const full = "elastic-endpoint" // 16 chars
	if len(full) <= 15 {
		t.Fatalf("fixture no longer exercises truncation: %q is %d chars", full, len(full))
	}
	h := newFakeHost(t).withProcess(t, "300", full[:15])
	products, _ := h.enumerate(t)
	mustContain(t, products, "Elastic Defend")
}

// Kernel-module evidence supports "sensor loaded" and is reported as such.
func TestKernelModuleEvidence(t *testing.T) {
	h := newFakeHost(t).withFile(t, "proc/modules",
		"falcon_lsm_serviceable 123 0 - Live 0x0000\nnf_tables 456 0 - Live 0x0000\n")
	products, _ := h.enumerate(t)
	mustContain(t, products, "kernel module falcon_lsm_serviceable loaded")
}

// A product seen by several sources at once is reported exactly once, with the
// strongest available claim (running beats installed-on-disk).
func TestMultipleSourcesReportProductOnceAsRunning(t *testing.T) {
	h := newFakeHost(t).
		withProcess(t, "101", "falcon-sensor").
		withDir(t, "opt/CrowdStrike")
	products, _ := h.enumerate(t)

	n := 0
	for _, l := range products {
		if strings.Contains(l, "CrowdStrike Falcon") {
			n++
		}
	}
	if n != 1 {
		t.Errorf("CrowdStrike reported %d times, want exactly 1:\n%s", n, joined(products))
	}
	mustContain(t, products, "falcon-sensor running")
	mustNotContain(t, products, "not running")
}

// Telemetry tooling must stay under its own prefix: osquery observes, it does
// not prevent, and folding it in with EDR would overstate the endpoint's
// defences.
func TestTelemetryIsNotReportedAsEDR(t *testing.T) {
	h := newFakeHost(t).withProcess(t, "400", "osqueryd")
	products, _ := h.enumerate(t)

	mustContain(t, products, "Telemetry: osquery (osqueryd running)")
	for _, l := range products {
		if strings.Contains(l, "osquery") && strings.HasPrefix(l, "EDR:") {
			t.Errorf("telemetry tooling reported under the EDR prefix: %q", l)
		}
	}
}

// ── contract test: the inventory's rendered shape ────────────────────────────

// A golden test over the whole output. The catalogue will keep growing; this
// pins the SEMANTICS of what a line says, so a future edit cannot quietly
// downgrade "installed, not running" to "running", drop a rule count, or let a
// permissive LSM read as enforcing.
func TestInventoryContract_GoldenOutput(t *testing.T) {
	stubAuditRules(t, 0, nil)

	h := newFakeHost(t).
		withProcess(t, "101", "falcon-sensor"). // Falcon process
		withDir(t, "opt/CrowdStrike").          // ...and its install path
		withProcess(t, "200", "auditd").        // auditd running
		withFile(t, "sys/fs/selinux/enforce", "1\n")

	products, diag := h.enumerate(t)

	want := []string{
		"Audit: auditd running (0 rules loaded)",
		"EDR: CrowdStrike Falcon (falcon-sensor running)",
		"LSM: SELinux (enforcing)",
	}
	if joined(products) != joined(want) {
		t.Errorf("inventory contract changed.\n got:\n%s\nwant:\n%s", joined(products), joined(want))
	}

	// /proc/modules is absent on this fake host, so exactly one diagnostic is
	// expected. The point is that it is *reported* rather than swallowed.
	mustContain(t, diag, "kernel-module scan unavailable")
}

// The empty case, stated explicitly: a host we could fully inspect and found
// nothing on reports no products AND no misleading diagnostics about the
// sources that worked.
func TestCleanHostReportsNothingFound(t *testing.T) {
	h := newFakeHost(t).withFile(t, "proc/modules", "")
	products, diag := h.enumerate(t)

	if len(products) != 0 {
		t.Errorf("expected an empty inventory, got:\n%s", joined(products))
	}
	if len(diag) != 0 {
		t.Errorf("a fully inspectable host must produce no diagnostics, got:\n%s", joined(diag))
	}
}
