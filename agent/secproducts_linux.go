//go:build linux

package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// enumerateSecurityProducts gathers what was protecting this endpoint during a
// run. Pure data collection (the dumb-executor's job); the server decides what
// the inventory means.
//
// Unlike the Windows implementation, which drives one large PowerShell script,
// this reads /proc and /sys directly. That is deliberate:
//   - it works on minimal/container hosts with no systemctl, lsmod or dpkg;
//   - it is far faster than spawning a shell per query;
//   - it does not emit a burst of process creations that a watching EDR may
//     block outright -- the very failure mode the Windows version has to
//     defend against.
//
// The one query with no /proc equivalent is auditd's loaded RULE count, which
// shells out to auditctl and degrades to a diag line when that is unavailable.
//
// EVIDENCE SOURCES. These are five independent sources, NOT a ranked list.
// There is no universal ordering: each is strong evidence for its own claim and
// weak or silent on every other claim. Conflating them is how an inventory
// starts overstating an endpoint's defences, so each finding carries the source
// that produced it:
//
//	source                     supports                      does NOT support
//	-------------------------  ----------------------------  -----------------------------
//	/proc/<pid>/comm           product is running            product is configured/effective
//	install path on disk       product is installed          product is running
//	/proc/modules              sensor module is loaded       sensor is enforcing
//	/sys/fs/selinux/enforce    SELinux enforcement mode      any given action was blocked
//	auditd process + rules     daemon runs; N rules loaded   rules cover anything relevant
//
// Note especially the last row: auditd being up says nothing about whether the
// loaded rules capture anything of interest, and this file must never imply it
// does. The same caution applies one level higher -- knowing a control was
// present and enforcing is still NOT evidence that it detected or prevented any
// particular simulated action. Establishing that requires correlating this
// inventory with the simulation's actions, the observed system response, and
// the collected evidence, which is a separate layer above this one. This file
// reports presence and state only.
//
// Package-manager queries (dpkg -l / rpm -qa) are deliberately NOT used: they
// cost seconds, differ per distro, and layer 2 already answers the same
// "installed but not running" question far more cheaply.
//
// HONESTY CONTRACT. A control that exists but is not enforcing must never read
// as protection, and "we could not look" must never collapse into "nothing is
// installed":
//   - SELinux in permissive mode is reported as permissive, never omitted and
//     never flattened into a bare "SELinux present".
//   - auditd running with zero rules is reported as zero rules.
//   - every unreadable path, missing tool or denied permission goes to diag.
//
// products is what we positively observed; diag is every place we could not
// look. The caller logs diag rather than letting absence masquerade as a clean
// bill of health.
func enumerateSecurityProducts() (products []string, diag []string) {
	return enumerateSecurityProductsIn("/")
}

// productKind is the report prefix, and the reason the widest inventory stays
// honest: a preventive control and a log shipper must not read alike.
type productKind string

const (
	kindEDR       productKind = "EDR"
	kindTelemetry productKind = "Telemetry"
)

// productSig identifies one security product by any of three independent
// signals. Matching any one of them is enough to report presence; which one
// matched is carried through to the output so a reader can tell "running" from
// "installed but stopped".
type productSig struct {
	label string
	kind  productKind
	procs []string // /proc/<pid>/comm values
	paths []string // install directories, relative to root
	mods  []string // /proc/modules entries
}

// securitySignatures is the detection catalogue. Process names are matched
// against /proc/<pid>/comm, which the kernel truncates to 15 characters
// (TASK_COMM_LEN-1) -- procMatches handles that, so entries here are written in
// full rather than pre-truncated.
var securitySignatures = []productSig{
	// ── Commercial EDR / AV ────────────────────────────────────────────────
	{
		label: "CrowdStrike Falcon", kind: kindEDR,
		procs: []string{"falcon-sensor", "falconctl"},
		paths: []string{"/opt/CrowdStrike"},
		mods:  []string{"falcon_lsm_serviceable", "falcon_nf_netcontain", "falcon_kal"},
	},
	{
		label: "SentinelOne", kind: kindEDR,
		procs: []string{"sentineld", "sentinelone", "s1-agent"},
		paths: []string{"/opt/sentinelone"},
	},
	{
		label: "Microsoft Defender for Endpoint", kind: kindEDR,
		procs: []string{"wdavdaemon", "mdatp"},
		paths: []string{"/opt/microsoft/mdatp"},
	},
	{
		label: "Trellix/McAfee ENS", kind: kindEDR,
		procs: []string{"mfetpd", "mfemactl"},
		paths: []string{"/opt/McAfee", "/opt/Trellix"},
	},
	{
		label: "VMware Carbon Black", kind: kindEDR,
		procs: []string{"cbagentd", "cbdaemon"},
		paths: []string{"/opt/carbonblack"},
	},
	{
		label: "Palo Alto Cortex XDR", kind: kindEDR,
		procs: []string{"cytool", "traps_pmd"},
		paths: []string{"/opt/traps", "/opt/paloaltonetworks"},
	},
	{
		label: "Sophos", kind: kindEDR,
		procs: []string{"sophos_health", "SophosMcsAgent"},
		paths: []string{"/opt/sophos-spl"},
	},
	{
		label: "Trend Micro Deep Security", kind: kindEDR,
		procs: []string{"ds_agent"},
		paths: []string{"/opt/ds_agent"},
	},
	{
		label: "Tanium", kind: kindEDR,
		procs: []string{"TaniumClient"},
		paths: []string{"/opt/Tanium"},
	},
	{
		label: "Kaspersky Endpoint Security", kind: kindEDR,
		procs: []string{"kesl", "kesl-gui"},
		paths: []string{"/opt/kaspersky"},
	},
	{
		label: "Elastic Defend", kind: kindEDR,
		procs: []string{"elastic-endpoint"},
		paths: []string{"/opt/Elastic/Endpoint"},
	},
	{
		label: "ClamAV", kind: kindEDR,
		procs: []string{"clamd", "freshclam"},
		paths: []string{"/var/lib/clamav"},
	},

	// ── Detection / telemetry tooling ──────────────────────────────────────
	// Reported under a separate prefix on purpose: these observe, they do not
	// prevent. Collapsing them into EDR would overstate the endpoint's defence.
	{
		label: "osquery", kind: kindTelemetry,
		procs: []string{"osqueryd"},
		paths: []string{"/opt/osquery"},
	},
	{
		label: "Sysmon for Linux", kind: kindTelemetry,
		procs: []string{"sysmon", "sysmonEBPF"},
		paths: []string{"/opt/sysmon"},
	},
	{
		label: "Falco", kind: kindTelemetry,
		procs: []string{"falco"},
		paths: []string{"/etc/falco"},
		mods:  []string{"falco"},
	},
	{
		label: "Wazuh/OSSEC", kind: kindTelemetry,
		procs: []string{"wazuh-agentd", "ossec-agentd"},
		paths: []string{"/var/ossec"},
	},
	{
		label: "Elastic Agent", kind: kindTelemetry,
		procs: []string{"elastic-agent"},
		paths: []string{"/opt/Elastic/Agent"},
	},
	{
		label: "Auditbeat", kind: kindTelemetry,
		procs: []string{"auditbeat"},
	},
}

// auditRulesFn is indirected so tests can exercise the rule-count reporting
// without a live auditd. Production points at auditctl.
var auditRulesFn = auditRulesViaAuditctl

func enumerateSecurityProductsIn(root string) (products []string, diag []string) {
	running, procDiag := scanProcComms(root)
	diag = append(diag, procDiag...)

	mods, modDiag := scanKernelModules(root)
	diag = append(diag, modDiag...)

	for _, sig := range securitySignatures {
		if line, ok := matchSignature(root, sig, running, mods); ok {
			products = append(products, line)
		}
	}

	if line, d := selinuxState(root); line != "" {
		products = append(products, line)
	} else if d != "" {
		diag = append(diag, d)
	}

	if line, d := apparmorState(root); line != "" {
		products = append(products, line)
	} else if d != "" {
		diag = append(diag, d)
	}

	if line, d := auditdState(running); line != "" || d != "" {
		if line != "" {
			products = append(products, line)
		}
		if d != "" {
			diag = append(diag, d)
		}
	}

	sort.Strings(products)
	sort.Strings(diag)
	return products, diag
}

// matchSignature reports one product if any layer sees it, preferring the
// strongest evidence. "installed, not running" is a materially different
// statement from "running" and must not be reported as the latter.
func matchSignature(root string, sig productSig, running map[string]bool, mods map[string]bool) (string, bool) {
	for _, p := range sig.procs {
		if procMatches(running, p) {
			return fmt.Sprintf("%s: %s (%s running)", sig.kind, sig.label, p), true
		}
	}
	for _, m := range sig.mods {
		if mods[m] {
			return fmt.Sprintf("%s: %s (kernel module %s loaded)", sig.kind, sig.label, m), true
		}
	}
	for _, p := range sig.paths {
		if dirExists(filepath.Join(root, p)) {
			return fmt.Sprintf("%s: %s (installed at %s, not running)", sig.kind, sig.label, p), true
		}
	}
	return "", false
}

// procMatches accounts for the kernel truncating /proc/<pid>/comm to 15
// characters. Without this, a signature like "elastic-endpoint" (16 chars)
// could never match the "elastic-endpoi" the kernel actually reports.
func procMatches(running map[string]bool, name string) bool {
	if running[name] {
		return true
	}
	const commLen = 15
	if len(name) > commLen && running[name[:commLen]] {
		return true
	}
	return false
}

// scanProcComms returns the set of running process names. A per-PID read that
// fails is skipped silently -- processes exit constantly while we walk, and a
// vanished PID is not a diagnostic. Failing to read /proc at all IS.
func scanProcComms(root string) (map[string]bool, []string) {
	procDir := filepath.Join(root, "proc")
	entries, err := os.ReadDir(procDir)
	if err != nil {
		return map[string]bool{}, []string{fmt.Sprintf("process scan unavailable: cannot read %s: %v", procDir, err)}
	}
	names := make(map[string]bool, len(entries))
	denied := 0
	for _, e := range entries {
		if !e.IsDir() || !isAllDigits(e.Name()) {
			continue
		}
		b, err := os.ReadFile(filepath.Join(procDir, e.Name(), "comm"))
		if err != nil {
			if os.IsPermission(err) {
				denied++
			}
			continue
		}
		if n := strings.TrimSpace(string(b)); n != "" {
			names[n] = true
		}
	}
	var diag []string
	if denied > 0 {
		// Not fatal, but it means the scan is partial -- a product running
		// under another account could be missed, and the reader must know the
		// inventory is incomplete rather than authoritative.
		diag = append(diag, fmt.Sprintf("process scan incomplete: %d /proc entries unreadable (agent lacks privileges); products running under other accounts may be missed", denied))
	}
	return names, diag
}

// scanKernelModules reads /proc/modules. Its absence is normal on a container
// host, so it is reported as a diag line rather than treated as an error.
func scanKernelModules(root string) (map[string]bool, []string) {
	path := filepath.Join(root, "proc", "modules")
	f, err := os.Open(path)
	if err != nil {
		return map[string]bool{}, []string{fmt.Sprintf("kernel-module scan unavailable: cannot read %s: %v", path, err)}
	}
	defer f.Close()

	mods := map[string]bool{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if name, _, found := strings.Cut(strings.TrimSpace(sc.Text()), " "); found && name != "" {
			mods[name] = true
		}
	}
	if err := sc.Err(); err != nil {
		return mods, []string{fmt.Sprintf("kernel-module scan truncated: %v", err)}
	}
	return mods, nil
}

// selinuxState reports SELinux's ACTUAL enforcement mode. Permissive is
// reported as permissive: SELinux in permissive mode logs violations and
// prevents nothing, so reporting bare "SELinux present" would overstate the
// endpoint's protection. An absent /sys/fs/selinux means SELinux is simply not
// in use -- a fact, not a failure, so it produces neither a product nor a diag.
func selinuxState(root string) (product string, diag string) {
	enforcePath := filepath.Join(root, "sys", "fs", "selinux", "enforce")
	b, err := os.ReadFile(enforcePath)
	if err != nil {
		if os.IsNotExist(err) {
			return "", "" // SELinux not enabled on this host
		}
		return "", fmt.Sprintf("SELinux state unknown: cannot read %s: %v", enforcePath, err)
	}
	switch strings.TrimSpace(string(b)) {
	case "1":
		return "LSM: SELinux (enforcing)", ""
	case "0":
		// Permissive logs violations and blocks nothing. It must never be
		// reported as a bare "SELinux present", which would read as protection.
		return "LSM: SELinux (permissive)", ""
	default:
		return "", fmt.Sprintf("SELinux state unknown: unexpected content in %s", enforcePath)
	}
}

// apparmorState reports AppArmor's enabled state and how many profiles are
// actually in enforce mode. A host with AppArmor enabled but every profile in
// complain mode is not being protected by it, so the counts are reported
// rather than a bare "AppArmor present".
func apparmorState(root string) (product string, diag string) {
	enabledPath := filepath.Join(root, "sys", "module", "apparmor", "parameters", "enabled")
	b, err := os.ReadFile(enabledPath)
	if err != nil {
		if os.IsNotExist(err) {
			return "", "" // AppArmor not present on this host
		}
		return "", fmt.Sprintf("AppArmor state unknown: cannot read %s: %v", enabledPath, err)
	}
	if !strings.EqualFold(strings.TrimSpace(string(b)), "Y") {
		return "LSM: AppArmor (present but disabled)", ""
	}

	profilesPath := filepath.Join(root, "sys", "kernel", "security", "apparmor", "profiles")
	pf, err := os.Open(profilesPath)
	if err != nil {
		// Enabled is still worth reporting; say plainly that the enforce count
		// is unknown rather than implying zero.
		return "LSM: AppArmor (enabled, profile modes unknown)",
			fmt.Sprintf("AppArmor profile modes unknown: cannot read %s: %v", profilesPath, err)
	}
	defer pf.Close()

	total, enforcing := 0, 0
	sc := bufio.NewScanner(pf)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		total++
		if strings.HasSuffix(line, "(enforce)") {
			enforcing++
		}
	}
	return fmt.Sprintf("LSM: AppArmor (enabled, %d/%d profiles enforcing)", enforcing, total), ""
}

// auditdState reports whether auditd is running and how many rules it has
// loaded. The rule count must always accompany the daemon state: "auditd
// running" on its own implies an audit trail that a zero-rule daemon does not
// provide. The count is reported as the bare fact -- what it means for coverage
// is the server's judgement, not the agent's.
//
// A non-zero count is still only evidence that rules exist, never evidence that
// they cover anything relevant to a given simulation.
func auditdState(running map[string]bool) (product string, diag string) {
	if !procMatches(running, "auditd") {
		return "", ""
	}
	n, err := auditRulesFn()
	if err != nil {
		// Explicitly "unknown", never 0 -- an unreadable rule list must not be
		// reported as an empty one.
		return "Audit: auditd running (rule count unknown)",
			fmt.Sprintf("auditd rule count unavailable: %v", err)
	}
	return fmt.Sprintf("Audit: auditd running (%d rules loaded)", n), ""
}

// auditRulesViaAuditctl counts loaded audit rules. This is the one probe with
// no /proc equivalent, so it is the only place this file spawns a process.
func auditRulesViaAuditctl() (int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	out, err := exec.CommandContext(ctx, "auditctl", "-l").Output()
	if err != nil {
		return 0, err
	}
	count := 0
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		// auditctl prints this exact sentence when the rule list is empty.
		if line == "" || strings.EqualFold(line, "No rules") {
			continue
		}
		count++
	}
	return count, nil
}

func dirExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.IsDir()
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
