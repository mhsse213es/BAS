package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// macOS security-control inventory.
//
// This file carries NO build tag on purpose. The whole inventory -- catalogue,
// parsers, and the assembly of the report -- takes its command output and its
// filesystem root as arguments, so every branch is exercised from the Windows
// build host. Only the one function that actually spawns a process lives in
// secproducts_darwin.go.
//
// That split matters more here than anywhere else in the agent: there is no Mac
// available to this project, so code that could only be verified by running it
// on macOS could not be verified at all.
//
// EVIDENCE SOURCES. Four independent sources, NOT a ranked list. Each is strong
// evidence for its own claim and silent on every other, so each finding carries
// the source that produced it:
//
//	source                        supports                        does NOT support
//	----------------------------  ------------------------------  --------------------------
//	ps -axco command              product is running              it is configured/effective
//	app bundle / dir on disk      product is installed            it is running
//	systemextensionsctl list      ES extension is ACTIVATED       it inspected anything
//	csrutil / spctl / fdesetup    the control's configured mode   any action was blocked
//	socketfilterfw
//
// Note the last row especially. Gatekeeper being enabled says a policy is in
// force; it does not say Gatekeeper refused any binary we ran. Establishing
// that requires correlating this inventory with the simulation's actions and
// the collected alerts, which is a separate layer above this file. This file
// reports presence and state only.
//
// HONESTY CONTRACT. A control that exists but is not enforcing must never read
// as protection, and "we could not look" must never collapse into "nothing is
// installed":
//   - SIP disabled, Gatekeeper disabled, the firewall off and FileVault off are
//     each reported in upper case as their own finding, never omitted and never
//     flattened into a bare "present".
//   - Output we do not recognise goes to diag. A future macOS release rewording
//     csrutil must not silently become "enabled".
//   - A system extension that is listed but not activated is reported as
//     installed, never as active.
//   - Every failed command goes to diag, so the caller can log it rather than
//     letting absence masquerade as a clean bill of health.
//
// OBSERVATION FOOTPRINT. Exactly one process spawn per control -- six in total,
// regardless of how large the catalogue grows. Never one spawn per candidate
// product: a burst of process creations is precisely what a watching EDR
// blocks, which would make a better-defended Mac report LESS protection than an
// undefended one.

// socketfilterfwPath is the Application Firewall tool. It is not on PATH, so it
// is invoked by absolute path.
const socketfilterfwPath = "/usr/libexec/ApplicationFirewall/socketfilterfw"

// macCommandRunner runs one inventory command and returns its stdout.
type macCommandRunner func(name string, args ...string) ([]byte, error)

// macProductSig identifies one security product by any of three independent
// signals. Matching any one is enough to report presence; which one matched is
// carried into the output so a reader can tell "running" from "installed".
type macProductSig struct {
	label string
	kind  productKind
	procs []string // ps -axco command values
	paths []string // app bundles / install dirs, relative to root
	exts  []string // system-extension bundle IDs
}

// darwinSignatures is the detection catalogue.
//
// Process names are matched against the ps accounting name, which macOS
// truncates to MAXCOMLEN characters -- macProcMatches handles that, so entries
// are written in full rather than pre-truncated.
var darwinSignatures = []macProductSig{
	// ── Commercial EDR / AV ────────────────────────────────────────────────
	{
		label: "CrowdStrike Falcon", kind: kindEDR,
		procs: []string{"falcond", "falconctl", "com.crowdstrike.falcon.Agent"},
		paths: []string{"Applications/Falcon.app", "Library/CS"},
		exts:  []string{"com.crowdstrike.falcon.Agent"},
	},
	{
		label: "SentinelOne", kind: kindEDR,
		procs: []string{"SentinelAgent", "sentineld", "SentinelHelperService"},
		paths: []string{"Applications/SentinelOne", "Library/Sentinel"},
		exts:  []string{"com.sentinelone.extensions-wrapper", "com.sentinelone.network-monitoring"},
	},
	{
		label: "Microsoft Defender for Endpoint", kind: kindEDR,
		procs: []string{"wdavdaemon", "mdatp"},
		paths: []string{"Applications/Microsoft Defender.app", "Library/Application Support/Microsoft/Defender"},
		exts:  []string{"com.microsoft.wdav.epsext", "com.microsoft.wdav.netext"},
	},
	{
		label: "Jamf Protect", kind: kindEDR,
		procs: []string{"JamfProtect", "JamfProtectSvc"},
		paths: []string{"Applications/JamfProtect.app"},
		exts:  []string{"com.jamf.protect.security-extension"},
	},
	{
		label: "Palo Alto Cortex XDR", kind: kindEDR,
		procs: []string{"CortexAgent", "cytool", "traps_pmd"},
		paths: []string{"Applications/Cortex XDR.app", "Library/Application Support/PaloAltoNetworks"},
		exts:  []string{"com.paloaltonetworks.cortex.agent.extension"},
	},
	{
		label: "Sophos Endpoint", kind: kindEDR,
		procs: []string{"SophosScanD", "SophosServiceManager", "SophosEndpoint"},
		paths: []string{"Applications/Sophos", "Library/Sophos Anti-Virus"},
		exts:  []string{"com.sophos.endpoint.scanextension", "com.sophos.endpoint.networkextension"},
	},
	{
		label: "Trellix/McAfee ENS", kind: kindEDR,
		procs: []string{"McAfeeSecurity", "mfetpd"},
		paths: []string{"Applications/McAfee Endpoint Security for Mac.app", "Library/McAfee", "Library/Trellix"},
		exts:  []string{"com.mcafee.CMF.systemextension", "com.trellix.systemextension"},
	},
	{
		label: "VMware Carbon Black", kind: kindEDR,
		procs: []string{"CbOsxSensorService", "repmgr"},
		paths: []string{"Applications/CarbonBlack", "Applications/VMware Carbon Black Cloud"},
		exts:  []string{"com.vmware.carbonblack.cloud.se"},
	},
	{
		label: "Cisco Secure Endpoint", kind: kindEDR,
		procs: []string{"ampdaemon", "ciscoampmac"},
		paths: []string{"opt/cisco/amp", "Library/Application Support/Cisco/AMP for Endpoints Connector"},
		exts:  []string{"com.cisco.endpoint.svc.securityextension"},
	},
	{
		label: "Elastic Defend", kind: kindEDR,
		procs: []string{"elastic-endpoint"},
		paths: []string{"Library/Elastic/Endpoint"},
		exts:  []string{"co.elastic.systemextension"},
	},
	{
		label: "Trend Micro", kind: kindEDR,
		procs: []string{"iCoreService", "TmccMac"},
		paths: []string{"Applications/TrendMicroSecurity.app", "Library/Application Support/TrendMicro"},
	},
	{
		label: "ESET Endpoint Security", kind: kindEDR,
		procs: []string{"esets_daemon", "esets_proxy"},
		paths: []string{"Applications/ESET Endpoint Security.app", "Library/Application Support/ESET"},
	},
	{
		label: "Kaspersky Endpoint Security", kind: kindEDR,
		procs: []string{"kav", "KasperskyEndpointSecurity"},
		paths: []string{"Applications/Kaspersky Endpoint Security for Mac.app", "Library/Application Support/Kaspersky Lab"},
	},
	{
		label: "Malwarebytes", kind: kindEDR,
		procs: []string{"RTProtectionDaemon", "Malwarebytes"},
		paths: []string{"Applications/Malwarebytes.app"},
	},
	{
		label: "Tanium", kind: kindEDR,
		procs: []string{"TaniumClient", "TaniumCX"},
		paths: []string{"Library/Tanium"},
	},

	// ── Telemetry / log shippers ───────────────────────────────────────────
	// Deliberately a separate kind. These collect; they do not prevent, and an
	// inventory that let them read alike would overstate the endpoint.
	{
		label: "osquery", kind: kindTelemetry,
		procs: []string{"osqueryd"},
		paths: []string{"usr/local/bin/osqueryd", "opt/osquery", "private/var/osquery"},
	},
	{
		label: "Splunk Universal Forwarder", kind: kindTelemetry,
		procs: []string{"splunkd"},
		paths: []string{"Applications/SplunkForwarder", "opt/splunkforwarder"},
	},
	{
		label: "Elastic Agent", kind: kindTelemetry,
		procs: []string{"elastic-agent"},
		paths: []string{"Library/Elastic/Agent"},
	},
	{
		label: "Wazuh", kind: kindTelemetry,
		procs: []string{"wazuh-agentd", "ossec-agentd"},
		paths: []string{"Library/Ossec"},
	},
	{
		label: "Datadog Agent", kind: kindTelemetry,
		procs: []string{"datadog-agent", "agent"},
		paths: []string{"opt/datadog-agent"},
	},
	{
		label: "Jamf Pro (MDM)", kind: kindTelemetry,
		procs: []string{"jamf", "jamfAgent"},
		paths: []string{"usr/local/jamf", "Library/Application Support/JAMF"},
	},
	{
		label: "Rapid7 Insight Agent", kind: kindTelemetry,
		procs: []string{"ir_agent"},
		paths: []string{"opt/rapid7/ir_agent"},
	},
}

// enumerateDarwinSecurityProducts gathers what was protecting this Mac during a
// run. Pure data collection (the dumb-executor's job); the server decides what
// the inventory means.
//
// products is what we positively observed; diag is every place we could not
// look. The caller logs diag rather than letting absence masquerade as a clean
// bill of health.
func enumerateDarwinSecurityProducts(root string, run macCommandRunner) (products []string, diag []string) {
	running, procDiag := macRunningProcesses(run)
	if procDiag != "" {
		diag = append(diag, procDiag)
	}

	exts, extDiag := macSystemExtensions(run)
	if extDiag != "" {
		diag = append(diag, extDiag)
	}

	for _, sig := range darwinSignatures {
		if line, ok := matchMacSignature(root, sig, running, exts); ok {
			products = append(products, line)
		}
	}

	for _, probe := range macPlatformControls() {
		line, d := probe(run)
		if line != "" {
			products = append(products, line)
		}
		if d != "" {
			diag = append(diag, d)
		}
	}

	if line := macXProtect(root); line != "" {
		products = append(products, line)
	}

	sort.Strings(products)
	sort.Strings(diag)
	return products, diag
}

// macPlatformControls returns one probe per built-in control. Each spawns at
// most one process, which is what bounds the inventory's observation footprint
// no matter how large the product catalogue grows.
func macPlatformControls() []func(macCommandRunner) (string, string) {
	return []func(macCommandRunner) (string, string){
		macSIPState, macGatekeeperState, macFirewallState, macFileVaultState,
	}
}

// ---------------------------------------------------------------------------
// Product matching
// ---------------------------------------------------------------------------

// matchMacSignature reports one product if any source sees it, preferring the
// strongest evidence. "installed, not running" is a materially different
// statement from "running", and an activated endpoint-security extension is
// stronger than either -- it means the product is wired into the kernel's
// security decision path, not merely present.
func matchMacSignature(root string, sig macProductSig, running map[string]bool, exts map[string]macExtension) (string, bool) {
	for _, id := range sig.exts {
		if e, ok := exts[id]; ok && e.activated {
			return fmt.Sprintf("%s: %s (endpoint security extension activated)", sig.kind, sig.label), true
		}
	}
	for _, p := range sig.procs {
		if macProcMatches(running, p) {
			return fmt.Sprintf("%s: %s (%s running)", sig.kind, sig.label, p), true
		}
	}
	// A listed-but-not-activated extension still proves installation, and is a
	// distinctly interesting state: the product is present and NOT protecting.
	for _, id := range sig.exts {
		if _, ok := exts[id]; ok {
			return fmt.Sprintf("%s: %s (extension present, NOT activated)", sig.kind, sig.label), true
		}
	}
	for _, p := range sig.paths {
		if pathExists(filepath.Join(root, filepath.FromSlash(p))) {
			return fmt.Sprintf("%s: %s (installed at %s, not running)", sig.kind, sig.label, p), true
		}
	}
	return "", false
}

// macMaxComLen is how far macOS truncates the ps accounting name.
const macMaxComLen = 16

// macProcMatches compares against the truncated name ps reports, so a product
// whose process name is longer than the limit is still recognised.
func macProcMatches(running map[string]bool, name string) bool {
	if running[name] {
		return true
	}
	if len(name) > macMaxComLen {
		if running[name[:macMaxComLen]] {
			return true
		}
	}
	// The observed name may itself be a truncation of the signature.
	for obs := range running {
		if len(obs) >= macMaxComLen && strings.HasPrefix(name, obs) {
			return true
		}
	}
	return false
}

func pathExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// ---------------------------------------------------------------------------
// Source: ps
// ---------------------------------------------------------------------------

// macRunningProcesses reads the accounting name of every running process.
// One spawn, regardless of catalogue size.
func macRunningProcesses(run macCommandRunner) (map[string]bool, string) {
	out, err := run("ps", "-axco", "command")
	if err != nil {
		return map[string]bool{}, fmt.Sprintf("running processes unknown: ps failed: %v", err)
	}
	return parsePsCommands(out), ""
}

// parsePsCommands reads `ps -axco command` output: a COMMAND header followed by
// one accounting name per line.
func parsePsCommands(out []byte) map[string]bool {
	set := map[string]bool{}
	for _, line := range strings.Split(string(out), "\n") {
		name := strings.TrimSpace(line)
		if name == "" || name == "COMMAND" {
			continue
		}
		set[name] = true
	}
	return set
}

// ---------------------------------------------------------------------------
// Source: system extensions
// ---------------------------------------------------------------------------

// macExtension is one row of `systemextensionsctl list`.
type macExtension struct {
	teamID    string
	bundleID  string
	state     string
	activated bool
}

func macSystemExtensions(run macCommandRunner) (map[string]macExtension, string) {
	out, err := run("systemextensionsctl", "list")
	if err != nil {
		return map[string]macExtension{}, fmt.Sprintf("system extensions unknown: systemextensionsctl failed: %v", err)
	}
	return parseSystemExtensions(out), ""
}

// parseSystemExtensions reads `systemextensionsctl list`. Rows are tab
// separated and end with a bracketed state such as [activated enabled].
//
// Only a state containing "activated" counts as active. "terminated waiting to
// uninstall on reboot" describes a product that is present and doing nothing,
// and must never be reported as protection.
func parseSystemExtensions(out []byte) map[string]macExtension {
	exts := map[string]macExtension{}
	for _, line := range strings.Split(string(out), "\n") {
		if !strings.Contains(line, "[") || !strings.Contains(line, "]") {
			continue
		}
		open := strings.LastIndex(line, "[")
		close := strings.LastIndex(line, "]")
		if close < open {
			continue
		}
		state := strings.TrimSpace(line[open+1 : close])
		if state == "state" { // the header row
			continue
		}
		fields := strings.Split(line[:open], "\t")
		var cells []string
		for _, f := range fields {
			if f = strings.TrimSpace(f); f != "" {
				cells = append(cells, f)
			}
		}
		// The column layout has shifted between macOS releases, so the bundle
		// ID is located by its reverse-DNS shape rather than by index. That
		// survives a column being added or dropped; an index would not, and
		// would silently start reporting the team ID as the bundle.
		bundleIdx, bundleID := -1, ""
		for i, c := range cells {
			if id, ok := macBundleID(c); ok {
				bundleIdx, bundleID = i, id
				break
			}
		}
		if bundleID == "" {
			continue
		}
		// The team ID is the cell immediately before the bundle, when present.
		team := ""
		if bundleIdx > 0 {
			if t := cells[bundleIdx-1]; t != "*" {
				team = t
			}
		}
		exts[bundleID] = macExtension{
			teamID:    team,
			bundleID:  bundleID,
			state:     state,
			activated: strings.Contains(state, "activated"),
		}
	}
	return exts
}

// ---------------------------------------------------------------------------
// Source: platform controls
// ---------------------------------------------------------------------------

// macSIPState reports System Integrity Protection's configured mode.
//
// SIP disabled is a major weakening of the platform and is reported as its own
// finding in upper case. It is NOT the same as SIP being absent, and neither is
// the same as us being unable to read it -- all three are distinguished here.
func macSIPState(run macCommandRunner) (product, diag string) {
	out, err := run("csrutil", "status")
	if err != nil {
		return "", fmt.Sprintf("System Integrity Protection state unknown: csrutil failed: %v", err)
	}
	s := strings.ToLower(string(out))
	switch {
	case strings.Contains(s, "status: enabled"):
		return "Platform: System Integrity Protection (enabled)", ""
	case strings.Contains(s, "status: disabled"):
		return "Platform: System Integrity Protection (DISABLED)", ""
	}
	return "", fmt.Sprintf("System Integrity Protection state unknown: unrecognised csrutil output: %q",
		truncate(strings.TrimSpace(string(out)), 120))
}

// macGatekeeperState reports whether Gatekeeper assessment is in force.
func macGatekeeperState(run macCommandRunner) (product, diag string) {
	out, err := run("spctl", "--status")
	if err != nil {
		return "", fmt.Sprintf("Gatekeeper state unknown: spctl failed: %v", err)
	}
	s := strings.ToLower(strings.TrimSpace(string(out)))
	switch {
	case strings.Contains(s, "assessments enabled"):
		return "Platform: Gatekeeper (assessments enabled)", ""
	case strings.Contains(s, "assessments disabled"):
		return "Platform: Gatekeeper (DISABLED)", ""
	}
	return "", fmt.Sprintf("Gatekeeper state unknown: unrecognised spctl output: %q", truncate(s, 120))
}

// macFirewallState reports the Application Firewall's global state.
func macFirewallState(run macCommandRunner) (product, diag string) {
	out, err := run(socketfilterfwPath, "--getglobalstate")
	if err != nil {
		return "", fmt.Sprintf("Application Firewall state unknown: socketfilterfw failed: %v", err)
	}
	s := strings.ToLower(strings.TrimSpace(string(out)))
	switch {
	case strings.Contains(s, "state = 1"), strings.Contains(s, "state = 2"),
		strings.Contains(s, "firewall is enabled"):
		return "Platform: Application Firewall (enabled)", ""
	case strings.Contains(s, "state = 0"), strings.Contains(s, "firewall is disabled"):
		return "Platform: Application Firewall (DISABLED)", ""
	}
	return "", fmt.Sprintf("Application Firewall state unknown: unrecognised socketfilterfw output: %q",
		truncate(s, 120))
}

// macFileVaultState reports full-disk encryption. Off is a finding: an attacker
// with physical access reads everything, and a report that omitted it would
// overstate the endpoint.
func macFileVaultState(run macCommandRunner) (product, diag string) {
	out, err := run("fdesetup", "status")
	if err != nil {
		return "", fmt.Sprintf("FileVault state unknown: fdesetup failed: %v", err)
	}
	s := strings.ToLower(strings.TrimSpace(string(out)))
	switch {
	case strings.Contains(s, "filevault is on"):
		return "Platform: FileVault (on)", ""
	case strings.Contains(s, "filevault is off"):
		return "Platform: FileVault (OFF)", ""
	}
	return "", fmt.Sprintf("FileVault state unknown: unrecognised fdesetup output: %q", truncate(s, 120))
}

// macXProtectPaths are Apple's built-in malware signature and remediation
// bundles. Presence on disk is read directly -- no spawn needed.
var macXProtectPaths = []string{
	"Library/Apple/System/Library/CoreServices/XProtect.bundle",
	"System/Library/CoreServices/XProtect.bundle",
}

// macXProtect reports the signature bundle's presence.
//
// Presence means signatures are on disk. It does NOT mean they are current, and
// it certainly does not mean they matched anything -- so the claim stops at
// "present".
func macXProtect(root string) string {
	for _, p := range macXProtectPaths {
		if pathExists(filepath.Join(root, filepath.FromSlash(p))) {
			return "Platform: XProtect (signature bundle present)"
		}
	}
	return ""
}

// macBundleID recognises a systemextensionsctl bundle cell, which is a
// reverse-DNS identifier optionally followed by " (version)".
//
// The header's literal "bundleID (version)" is rejected: it has no dot-
// separated segments, so it cannot pass the shape check.
func macBundleID(cell string) (string, bool) {
	id := cell
	if i := strings.Index(id, " ("); i > 0 {
		id = id[:i]
	}
	id = strings.TrimSpace(id)
	if strings.ContainsAny(id, " 	") {
		return "", false
	}
	parts := strings.Split(id, ".")
	if len(parts) < 3 {
		return "", false
	}
	for _, p := range parts {
		if p == "" {
			return "", false
		}
	}
	return id, true
}
