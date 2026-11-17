package rwtaxonomy

import "regexp"

// techniqueIDPattern matches a syntactically valid MITRE ATT&CK technique
// ID: Txxxx or Txxxx.yyy.
var techniqueIDPattern = regexp.MustCompile(`^T[0-9]{4}(\.[0-9]{3})?$`)

// TechniqueDomain maps every MITRE technique ID referenced by the 8
// ransomware scenarios/drills in scenarios/ to its one primary domain in
// THIS ransomware-specific context. A technique mapped here under one
// domain is not a claim that it belongs exclusively to that domain across
// every ATT&CK context -- only that, as used in Audspect's ransomware
// corpus today, this is its primary classification.
var TechniqueDomain = map[string]Domain{
	// Valid Accounts (compromised credentials, no MFA)
	"T1078": DomainInitialAccess,
	// Exploit Public-Facing Application (e.g. ScreenConnect CVE-2024-1709)
	"T1190": DomainInitialAccess,
	// Phishing: Spearphishing Attachment
	"T1566.001": DomainInitialAccess,
	// OS Credential Dumping: LSASS
	"T1003.001": DomainCredentialAccess,
	// OS Credential Dumping: SAM
	"T1003.002": DomainCredentialAccess,
	// OS Credential Dumping: DCSync
	"T1003.006": DomainCredentialAccess,
	// Remote Services: RDP
	"T1021.001": DomainLateralMovement,
	// Remote Services: SMB/Windows Admin Shares
	"T1021.002": DomainLateralMovement,
	// Windows Management Instrumentation (system discovery)
	"T1047": DomainDataDiscoveryAndStaging,
	// Indicator Removal: Clear Windows Event Logs. Ambiguous case,
	// documented per the spec: this could reasonably sit under Defense
	// Evasion (MITRE's own tactic for it) instead. Chosen as Post-Incident
	// Assurance because that domain's own description ("evidence
	// preservation, root-cause findings, regression testing") is precisely
	// about whether evidence survives an attacker's attempt to erase it,
	// while Defense Evasion's description here is specifically about
	// security-tool tampering and agent health, not log/forensic-trail
	// destruction.
	"T1070.001": DomainPostIncidentAssurance,
	// Automated Exfiltration (RClone, Ligolo, Cloudflared)
	"T1020": DomainExfiltration,
	// File and Directory Discovery (BFSI sensitive-file recon ahead of staging)
	"T1083": DomainDataDiscoveryAndStaging,
	// Account Discovery: Domain Account
	"T1087.002": DomainPreparationAndPersistence,
	// Network Share Discovery (ahead of SMB-based lateral movement)
	"T1135": DomainLateralMovement,
	// Lateral Tool Transfer (RMM tool staging: SimpleHelp, AnyDesk)
	"T1570": DomainLateralMovement,
	// Data Encrypted for Impact
	"T1486": DomainEncryptionAndDestruction,
	// Service Stop (backup service stop attempt, em-07 Stage 5A)
	"T1489": DomainRecoveryInhibition,
	// Inhibit System Recovery
	"T1490": DomainRecoveryInhibition,
	// Security Software Discovery
	"T1518.001": DomainPreparationAndPersistence,
	// Web Shell
	"T1505.003": DomainPreparationAndPersistence,
	// Create or Modify System Process: Windows Service
	"T1543.003": DomainPreparationAndPersistence,
	// Archive Collected Data via Utility
	"T1560.001": DomainDataDiscoveryAndStaging,
	// Impair Defenses: Disable or Modify Tools
	"T1562.001": DomainDefenseEvasion,
	// Impair Defenses: Disable Windows Event Logging
	"T1562.008": DomainDefenseEvasion,
	// Impair Defenses: Modify Authentication Process (CVE-2020-1472 Zerologon)
	"T1556": DomainDefenseEvasion,
	// Exfiltration to Cloud Storage
	"T1567.002": DomainExfiltration,
	// Exfiltration Over C2 Channel (Akira Stage 5b: HTTPS POST to the platform's own sink)
	"T1041": DomainExfiltration,
	// Data Staged: Local Data Staging (Akira Stage 5a, synthetic records in a BAS-owned directory)
	"T1074.001": DomainDataDiscoveryAndStaging,
	// Masquerading: Match Legitimate Resource Name or Location / file-type masquerade. Used for
	// Akira Stage 6b (mass rename): renaming files is not encryption, so it is deliberately NOT
	// mapped to Encryption and Destruction. Defense Evasion is the closest ATT&CK tactic; the
	// exact sub-technique is flagged for review.
	"T1036.008": DomainDefenseEvasion,
	// Backup assurance steps (ransomware-backup-recovery-assurance): the technique each step defends against.
	// System Service Discovery (B1 discovery, B6/B7 recovery-point inventory).
	"T1007": DomainDataDiscoveryAndStaging,
	// Credentials from Password Stores (B2 backup credential exposure).
	"T1555": DomainCredentialAccess,
	// Remote Services (L1 remote-service authentication validation).
	"T1021": DomainLateralMovement,
	// System Services: Service Execution (L3 transient remote service).
	"T1569.002": DomainLateralMovement,
	// Akira Windows completeness stages 18-25.
	// External Remote Services (S18).
	"T1133": DomainInitialAccess,
	// Domain Trust Discovery (S19).
	"T1482": DomainDataDiscoveryAndStaging,
	// System Information Discovery (S20; also carries T1057 and T1083).
	"T1082": DomainDataDiscoveryAndStaging,
	// PowerShell (S21; also carries T1047 and T1569.002).
	"T1059.001": DomainPreparationAndPersistence,
	// Kerberoasting (S22).
	"T1558.003": DomainCredentialAccess,
	// Create Account: Local Account (S23; the domain variant T1136.002 is not simulated).
	"T1136.001": DomainPreparationAndPersistence,
	// Registry Run Keys (S24).
	"T1547.001": DomainPreparationAndPersistence,
	// Remote Access Software (S25).
	"T1219": DomainPreparationAndPersistence,
	// Financial Theft (Akira double-extortion correlation step D5: data theft used for extortion).
	"T1657": DomainExfiltration,
	// Data Destruction (B3-B5 backup deletion/immutability/restore).
	"T1485": DomainEncryptionAndDestruction,
}

// DomainFor returns techniqueID's mapped domain and true, or ("", false)
// if techniqueID has no entry.
func DomainFor(techniqueID string) (Domain, bool) {
	d, ok := TechniqueDomain[techniqueID]
	return d, ok
}
