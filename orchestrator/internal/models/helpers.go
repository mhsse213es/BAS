package models

import "fmt"

// ThreatImpact returns a BFSI-context-aware description of what an attacker
// achieves when a technique succeeds (CheckResult == Fail).
func ThreatImpact(tactic, techID, techName string) string {
	switch tactic {
	case "credential-access":
		return fmt.Sprintf(
			"%s (%s): Attacker obtains valid credentials enabling lateral movement, privilege escalation, "+
				"and persistent access. In BFSI environments this risks access to core banking, SWIFT, "+
				"or payment switch systems.", techName, techID)
	case "lateral-movement":
		return fmt.Sprintf(
			"%s (%s): Attacker moves to adjacent systems expanding compromise blast radius. "+
				"In BFSI this can reach treasury, trading, or inter-bank settlement infrastructure.", techName, techID)
	case "privilege-escalation":
		return fmt.Sprintf(
			"%s (%s): Attacker elevates to SYSTEM or Domain Admin enabling unrestricted access "+
				"to all local and domain resources including AD, GPO, and privileged service accounts.", techName, techID)
	case "persistence":
		return fmt.Sprintf(
			"%s (%s): Attacker maintains long-term access surviving reboots and credential rotations, "+
				"enabling sustained espionage or pre-positioned ransomware in RBI-regulated environments.", techName, techID)
	case "defense-evasion":
		return fmt.Sprintf(
			"%s (%s): Attacker disables or bypasses security controls allowing subsequent techniques "+
				"to execute undetected, defeating SIEM/SOAR alerting and EDR coverage.", techName, techID)
	case "execution":
		return fmt.Sprintf(
			"%s (%s): Attacker executes arbitrary code on the endpoint enabling full control "+
				"of the compromised system and all data accessible from it.", techName, techID)
	case "exfiltration":
		return fmt.Sprintf(
			"%s (%s): Attacker exfiltrates sensitive data — customer PII, financial records, "+
				"UPI transaction logs, or cryptographic keys — triggering DPDPA and RBI breach notification.", techName, techID)
	case "command-and-control":
		return fmt.Sprintf(
			"%s (%s): Attacker establishes a C2 channel enabling persistent remote control, "+
				"tool staging, and coordination of multi-stage attacks from outside the perimeter.", techName, techID)
	case "collection":
		return fmt.Sprintf(
			"%s (%s): Attacker collects sensitive data prior to exfiltration — "+
				"screenshots, keystrokes, or file archives from regulated financial systems.", techName, techID)
	case "impact":
		return fmt.Sprintf(
			"%s (%s): Attacker disrupts, destroys, or manipulates data — ransomware encryption, "+
				"wiper deployment, or transaction manipulation affecting business continuity and SEBI/RBI obligations.", techName, techID)
	case "reconnaissance":
		return fmt.Sprintf(
			"%s (%s): Attacker gathers intelligence about the target environment, "+
				"enabling precision targeting of BFSI-specific assets and personnel.", techName, techID)
	default:
		return fmt.Sprintf(
			"%s (%s): Technique executed against the endpoint. Review result and apply recommended controls.", techName, techID)
	}
}

// Details returns a one-line human-readable summary of a check outcome.
func Details(result CheckResult, techID, techName, desc, tactic, rawOutput string) string {
	status := "BLOCKED — security controls prevented this technique"
	if result == ResultFail {
		status = "EXECUTED — security controls did NOT prevent this technique"
	}
	trimmed := rawOutput
	if len(trimmed) > 500 {
		trimmed = trimmed[:500] + "...[truncated]"
	}
	d := fmt.Sprintf("[%s] %s (%s) — %s", tactic, techName, techID, status)
	if trimmed != "" {
		d += "\nOutput: " + trimmed
	}
	return d
}

// techniqueRemediation holds remediation guidance keyed by ATT&CK technique ID
// for cases where the tactic-level default is misleading. The tactic of a
// technique does not always imply the right control (e.g. T1569.002 is tagged
// "execution" but abuses service DACLs — PowerShell logging is irrelevant; the
// fix is service-permission hardening). Keys are normalised technique IDs.
var techniqueRemediation = map[string]string{
	// Service Execution / SetServiceObjectSecurity — service ACL abuse, not script execution.
	"T1569.002": "1) Audit service DACLs (sc.exe sdshow / SCM) and remove WRITE_DAC, WRITE_OWNER, and CHANGE_CONFIG from non-admin principals.\n" +
		"2) Harden SCM permissions; restrict who may create, reconfigure, or change the security descriptor of services.\n" +
		"3) Review SeTakeOwnershipPrivilege / SeRestorePrivilege assignments — restrict to trusted administrators.\n" +
		"4) Monitor service DACL changes and service-config modifications (Event IDs 7045, 4697) and alert on non-admin actors.",
	// Create or Modify System Service — service-based persistence.
	"T1543.003": "1) Restrict service creation/modification to administrators; audit and baseline all installed services.\n" +
		"2) Enable alerts on new service installation (Event ID 7045) and unexpected ImagePath changes.\n" +
		"3) Enforce signed-binary service images via WDAC/AppLocker; block services launching from user-writable paths.\n" +
		"4) Monitor SCM database (HKLM\\SYSTEM\\CurrentControlSet\\Services) for unauthorised additions.",
	// Modify Registry — registry-specific monitoring, not generic script logging.
	"T1112": "1) Audit and baseline security-relevant registry keys (Run keys, policy hives, ASR/Defender settings, LSA).\n" +
		"2) Enable registry-modification auditing (Sysmon Event IDs 12/13/14) and forward to SIEM.\n" +
		"3) Restrict write access to sensitive hives; alert on changes to Defender/EDR and policy keys.\n" +
		"4) Enable tamper protection so security-product registry settings cannot be silently altered.",
}

// Remediation returns a 4-step numbered remediation guide for a failed check.
func Remediation(result CheckResult, tactic, techID, techName string) string {
	if result == ResultPass || result == ResultBlocked {
		return fmt.Sprintf(
			"Control validated: %s (%s) was blocked. Maintain current security posture and continue monitoring.",
			techName, techID)
	}
	// Technique-specific guidance overrides the tactic default where the tactic
	// would otherwise mislead (e.g. service ACL abuse tagged "execution").
	if r, ok := techniqueRemediation[NormalizeID(techID)]; ok {
		return r
	}
	switch tactic {
	case "credential-access":
		return "1) Enable Credential Guard (Windows) or PAM vaulting for all privileged accounts.\n" +
			"2) Enable LSA Protection (RunAsPPL=1) to prevent LSASS memory dumping.\n" +
			"3) Enable ASR rule: Block credential stealing from LSASS (GUID 9e6c4e1f).\n" +
			"4) Enforce phishing-resistant MFA (FIDO2/hardware token) for all privileged access."
	case "lateral-movement":
		return "1) Disable SMBv1 and restrict NTLM; enforce Kerberos with AES encryption.\n" +
			"2) Implement network micro-segmentation between business units and payment systems.\n" +
			"3) Enable Windows Firewall rules blocking lateral movement ports (445, 135, 5985).\n" +
			"4) Deploy EDR with lateral movement detection and automated isolation capability."
	case "privilege-escalation":
		return "1) Enforce least-privilege; audit and remove unnecessary local admin memberships.\n" +
			"2) Enable UAC at highest level; require elevation approval for all admin actions.\n" +
			"3) Patch known privilege escalation CVEs — cross-reference CISA KEV catalogue.\n" +
			"4) Monitor for token manipulation events (Windows Event IDs 4672, 4673, 4674)."
	case "persistence":
		return "1) Monitor autorun locations: Run keys, scheduled tasks, services, WMI subscriptions.\n" +
			"2) Enable Autoruns/Sysmon monitoring with alerts on new persistence mechanisms.\n" +
			"3) Implement application allowlisting (WDAC or AppLocker) on all endpoints.\n" +
			"4) Audit and remediate all startup entries against a known-good baseline."
	case "defense-evasion":
		return "1) Enable tamper protection on all EDR/AV solutions; alert on protection disablement.\n" +
			"2) Restrict PowerShell to ConstrainedLanguageMode and enable AMSI.\n" +
			"3) Enable Script Block Logging (Event ID 4104) and forward to SIEM.\n" +
			"4) Monitor for security service termination and log clearing events."
	case "execution":
		return "1) Enable PowerShell Script Block Logging and Constrained Language Mode.\n" +
			"2) Implement application allowlisting (AppLocker/WDAC) to restrict code execution.\n" +
			"3) Enable ASR rules targeting script-based and macro-based execution.\n" +
			"4) Monitor for anomalous parent-child process relationships in EDR."
	case "exfiltration":
		return "1) Deploy DLP controls on all network egress points and cloud upload paths.\n" +
			"2) Implement DNS filtering and HTTPS inspection to detect covert exfil channels.\n" +
			"3) Enable CASB for SaaS exfiltration detection and data classification enforcement.\n" +
			"4) Alert on large outbound transfers during off-hours from regulated endpoints."
	case "command-and-control":
		return "1) Deploy DNS filtering to block known C2 domains and DGA-generated hostnames.\n" +
			"2) Enable TLS inspection at the perimeter for outbound HTTPS traffic.\n" +
			"3) Implement network detection for beaconing patterns (periodic, low-volume connections).\n" +
			"4) Restrict outbound connections to an approved destination allowlist."
	case "collection":
		return "1) Enable DLP policies to detect and block sensitive data staging and archiving.\n" +
			"2) Implement file access monitoring (Sysmon Event ID 11) on regulated data stores.\n" +
			"3) Restrict screen capture and keylogging capabilities via AppLocker/WDAC.\n" +
			"4) Alert on anomalous file enumeration and bulk read access patterns."
	case "impact":
		return "1) Implement and test offline backup strategy (3-2-1 rule) per RBI/SEBI BCP guidelines.\n" +
			"2) Enable VSS protection and restrict shadow copy deletion to admin-only with MFA.\n" +
			"3) Deploy ransomware-specific EDR detection rules and automated isolation playbooks.\n" +
			"4) Maintain and regularly test DR and incident response plans per CSCRF requirements."
	default:
		return fmt.Sprintf(
			"1) Review and harden controls for %s (%s) based on vendor hardening guidance.\n"+
				"2) Enable relevant audit logging and forward to SIEM for correlation.\n"+
				"3) Apply CIS Benchmark or vendor-recommended hardening for the affected component.\n"+
				"4) Schedule follow-up simulation to verify remediation effectiveness.",
			techName, techID)
	}
}
