package models

import "strings"

// cvesByTechnique maps a base ATT&CK technique to well-known CVEs in the CISA
// Known Exploited Vulnerabilities (KEV) catalog that are exploited via that
// technique. CISA KEV does NOT itself carry ATT&CK mappings, so this is a
// hand-curated, intentionally CONSERVATIVE bridge: only high-confidence, widely
// documented vulnerabilities are listed, and they are attributed to the single
// clearest technique (the initial exploitation behaviour), not every downstream
// effect. The link is only materialised when the CVE is actually present in the
// seeded cves table, so unknown/retired CVEs are simply ignored — never an error.
//
// Grow this over time as scenarios expand. Every entry should be defensible from
// public reporting; when in doubt, leave it out.
var cvesByTechnique = map[string][]string{
	// T1190 Exploit Public-Facing Application — internet-facing appliance/app RCEs.
	"T1190": {
		"CVE-2021-44228", // Log4Shell (Apache Log4j2 JNDI)
		"CVE-2021-26855", // Microsoft Exchange ProxyLogon (SSRF)
		"CVE-2021-34473", // Microsoft Exchange ProxyShell
		"CVE-2021-34523", // Microsoft Exchange ProxyShell (PrivEsc component)
		"CVE-2021-31207", // Microsoft Exchange ProxyShell (write component)
		"CVE-2024-3400",  // Palo Alto PAN-OS GlobalProtect command injection
		"CVE-2023-34362", // Progress MOVEit Transfer SQL injection
		"CVE-2023-3519",  // Citrix ADC / Gateway RCE
		"CVE-2019-19781", // Citrix ADC / Gateway path traversal
		"CVE-2022-1388",  // F5 BIG-IP iControl REST auth bypass
		"CVE-2018-13379", // Fortinet FortiOS SSL VPN path traversal
		"CVE-2023-46805", // Ivanti Connect Secure auth bypass
		"CVE-2024-21887", // Ivanti Connect Secure command injection
	},

	// T1210 Exploitation of Remote Services — internal network service exploits.
	"T1210": {
		"CVE-2020-1472", // Zerologon (Netlogon EoP)
		"CVE-2017-0144", // EternalBlue (SMBv1, MS17-010)
		"CVE-2019-0708", // BlueKeep (RDP RCE)
	},

	// T1068 Exploitation for Privilege Escalation — local kernel/service EoP.
	"T1068": {
		"CVE-2021-34527", // PrintNightmare (Print Spooler RCE/LPE)
		"CVE-2021-1675",  // PrintNightmare (Print Spooler LPE)
		"CVE-2022-37969", // Windows CLFS driver EoP
		"CVE-2023-21768", // Windows Ancillary Function Driver (afd.sys) EoP
	},

	// T1203 Exploitation for Client Execution — document/browser exploits.
	"T1203": {
		"CVE-2021-40444", // MSHTML remote code execution (malicious docs)
		"CVE-2022-30190", // Follina (MSDT) remote code execution
		"CVE-2017-11882", // Microsoft Equation Editor memory corruption
	},

	// T1187 Forced Authentication — credential coercion via crafted content.
	"T1187": {
		"CVE-2023-23397", // Microsoft Outlook NTLM credential leak (no-click)
	},

	// T1003 OS Credential Dumping — local secret/registry hive exposure.
	"T1003": {
		"CVE-2021-36934", // HiveNightmare / SeriousSAM (SAM/SYSTEM readable)
	},
}

// LookupCVEs returns the curated CISA KEV CVEs associated with a technique,
// resolving sub-techniques (T1190.001 → T1190). Returns nil when none are mapped.
func LookupCVEs(techID string) []string {
	base, _, _ := strings.Cut(techID, ".")
	return cvesByTechnique[strings.ToUpper(base)]
}
