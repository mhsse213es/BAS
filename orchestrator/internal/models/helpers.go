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
			"%s (%s): Attacker exfiltrates sensitive data â€” customer PII, financial records, "+
				"UPI transaction logs, or cryptographic keys â€” triggering DPDPA and RBI breach notification.", techName, techID)
	case "command-and-control":
		return fmt.Sprintf(
			"%s (%s): Attacker establishes a C2 channel enabling persistent remote control, "+
				"tool staging, and coordination of multi-stage attacks from outside the perimeter.", techName, techID)
	case "collection":
		return fmt.Sprintf(
			"%s (%s): Attacker collects sensitive data prior to exfiltration â€” "+
				"screenshots, keystrokes, or file archives from regulated financial systems.", techName, techID)
	case "impact":
		return fmt.Sprintf(
			"%s (%s): Attacker disrupts, destroys, or manipulates data â€” ransomware encryption, "+
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
	status := "BLOCKED â€” security controls prevented this technique"
	if result == ResultFail {
		status = "EXECUTED â€” security controls did NOT prevent this technique"
	}
	if result == ResultVetoed {
		// Falling through to the "BLOCKED" default would fabricate a
		// customer-defense-success message for a technique Audspect's own
		// agent refused to attempt -- never actually tested (verified, B5
		// Task 9 audit).
		status = "VETOED â€” Audspect prevented execution under its local destructive-action policy; customer defenses were not tested"
	}
	trimmed := rawOutput
	if len(trimmed) > 500 {
		trimmed = trimmed[:500] + "...[truncated]"
	}
	d := fmt.Sprintf("[%s] %s (%s) â€” %s", tactic, techName, techID, status)
	if trimmed != "" {
		d += "\nOutput: " + trimmed
	}
	return d
}

// techniqueRemediation holds remediation guidance keyed by ATT&CK technique ID
// for cases where the tactic-level default is misleading. The tactic of a
// technique does not always imply the right control (e.g. T1569.002 is tagged
// "execution" but abuses service DACLs â€” PowerShell logging is irrelevant; the
// fix is service-permission hardening). Keys are normalised technique IDs.
var techniqueRemediation = map[string]string{
	// ── Technique-specific overrides added below ──────────────────────────────

	// OS Credential Dumping — LSASS memory
	"T1003.001": "1) Enable Credential Guard and LSA Protection (RunAsPPL=1).\n2) Enable ASR rule 9e6c4e1f (Block LSASS credential stealing).\n3) Restrict LSASS access; alert on OpenProcess to lsass.exe (Sysmon Event ID 10).\n4) Enforce phishing-resistant MFA so dumped hashes cannot be replayed.",

	// OS Credential Dumping — SAM database
	"T1003.002": "1) Restrict VSS and Volume Shadow Copy access; monitor reg save HKLM\\SAM.\n2) Enable Sysmon Event ID 11 to alert on SAM/SYSTEM hive file reads by non-system processes.\n3) Enforce SYSKEY/BitLocker so offline SAM extraction is not useful.\n4) Rotate local admin passwords via LAPS immediately after any suspected dump.",

	// OS Credential Dumping — LSA Secrets
	"T1003.004": "1) Enable LSA Protection (RunAsPPL) to block direct LSA secret access.\n2) Monitor reg query HKLM\\SECURITY\\Policy\\Secrets (Sysmon Event ID 13).\n3) Restrict SeBackupPrivilege and SeTakeOwnershipPrivilege to trusted admins only.\n4) Rotate service account passwords stored in LSA secrets on a regular schedule.",

	// OS Credential Dumping — Cached Domain Credentials
	"T1003.005": "1) Set CachedLogonsCount to 0 via GPO to disable cached credential storage.\n2) Deploy Credential Guard to protect domain credential hashes.\n3) Monitor access to HKLM\\SECURITY\\Cache (Sysmon Event ID 13) by non-SYSTEM processes.\n4) Alert on nltest/secretsdump-pattern command-line arguments in EDR.",

	// OS Credential Dumping — DCSync
	"T1003.006": "1) Restrict Replication-Get-Changes-All right to only legitimate DC accounts in AD.\n2) Alert on users/computers acquiring DS-Replication-Get-Changes-All (Event ID 4662).\n3) Deploy Microsoft Defender for Identity to detect DCSync patterns.\n4) Audit privileged AD group membership (Domain Admins, Replicating Directory Changes).",

	// Remote Desktop Protocol lateral movement
	"T1021.001": "1) Disable RDP on all endpoints that do not require it; use Privileged Access Workstations.\n2) Enable Network Level Authentication (NLA) and restrict RDP to jump-host IPs only.\n3) Enable MFA for RDP sessions via NPS extension or third-party RDP gateway.\n4) Alert on RDP logins outside business hours and from unexpected source IPs (Event ID 4624 Type 10).",

	// SMB/Windows Admin Shares lateral movement
	"T1021.002": "1) Disable admin shares (IPC$, ADMIN$, C$) via GPO where not operationally required.\n2) Enforce SMB signing on all endpoints and domain controllers.\n3) Implement host-based firewall rules blocking inbound SMB (port 445) between workstations.\n4) Alert on lateral movement via PsExec-style process creation (parent services.exe with UNC image path).",

	// WinRM lateral movement
	"T1021.006": "1) Disable WinRM service on all non-admin endpoints via GPO.\n2) Restrict WinRM access to a dedicated management VLAN and PAW IP ranges.\n3) Enable PowerShell Script Block Logging and alert on remote PS sessions from unexpected hosts.\n4) Monitor WSMan connections (Event ID 6 / Sysmon network events to port 5985/5986).",

	// PowerShell execution
	"T1059.001": "1) Set PowerShell Execution Policy to AllSigned or RemoteSigned via GPO.\n2) Enable PowerShell Script Block Logging (Event ID 4104) and AMSI integration.\n3) Deploy PowerShell Constrained Language Mode (CLM) on all non-admin endpoints.\n4) Enable ASR rule 75668c1f (Block Office apps from creating child processes).",

	// VBScript / wscript / cscript
	"T1059.005": "1) Block wscript.exe and cscript.exe via WDAC or AppLocker rules for standard users.\n2) Enable ASR rule d3e037e1 (Block JavaScript/VBScript from launching downloaded executables).\n3) Associate .vbs/.vbe/.js/.jse with notepad.exe via file association GPO.\n4) Monitor wscript.exe/cscript.exe spawning network connections or child processes.",

	// Process injection (general)
	"T1055": "1) Enable Credential Guard and Kernel Patch Protection (KPP) to protect memory.\n2) Deploy EDR with memory scanning that detects shellcode injection and reflective loading.\n3) Enable ASR rule 75668c1f and 26190899 (Block Office from injecting into other processes).\n4) Alert on VirtualAllocEx/WriteProcessMemory/CreateRemoteThread API chains via EDR telemetry.",

	// Process injection — process hollowing
	"T1055.012": "1) Enable EDR with process creation monitoring and memory integrity scanning.\n2) Alert on processes with mismatched image paths (Sysmon Event ID 25 — process tampering).\n3) Enable Windows Defender's ASR rule blocking credential stealing from LSASS.\n4) Use WDAC to enforce allowed executable allowlist; block unsigned binaries.",

	// Scheduled Task
	"T1053.005": "1) Restrict Task Scheduler access to administrators; audit all existing scheduled tasks.\n2) Alert on new task creation (Event ID 4698) and task modification (Event ID 4702).\n3) Block scheduled tasks that launch from user-writable directories via WDAC.\n4) Enable Sysmon Event ID 1 correlation to identify task-launched child processes.",

	// Registry Run Keys / Startup Folder persistence
	"T1547.001": "1) Audit and baseline all Run/RunOnce keys (Sysmon Event IDs 12/13 on autorun registry paths).\n2) Deploy Autoruns monitoring; alert on any additions not matching known-good baseline.\n3) Enable WDAC to prevent unsigned binaries registered in Run keys from executing.\n4) Periodically enumerate Startup folder and Run keys via EDR scheduled inspection.",

	// Create local account persistence
	"T1136.001": "1) Monitor for new local account creation (Event ID 4720) and alert on any outside change-window.\n2) Enforce a GPO that restricts local account creation to Domain Admins only.\n3) Deploy LAPS and remove all manually set local admin accounts from non-admin systems.\n4) Alert on accounts added to local Administrators group (Event ID 4732).",

	// Disable security tools (tamper)
	"T1562.001": "1) Enable Tamper Protection in Microsoft Defender to block EDR disablement.\n2) Alert on security service stops and registry changes to Defender/EDR keys (Sysmon Event ID 13).\n3) Use a non-deferrable EDR heartbeat alert: if agent goes silent, treat as active incident.\n4) Restrict sc.exe, reg.exe, and taskkill.exe from being used by standard user processes.",

	// Disable Windows Firewall
	"T1562.004": "1) Enforce Windows Firewall policy via GPO that cannot be overridden by local admins.\n2) Alert on netsh advfirewall set allprofiles state off or equivalent registry changes.\n3) Monitor firewall state via Sysmon Event ID 13 on HKLM\\SYSTEM\\CurrentControlSet\\Services\\mpssvc.\n4) Treat any firewall disable event as a P1 security incident requiring immediate response.",

	// Indicator removal — Clear Windows Event Logs
	"T1070.001": "1) Forward all security-relevant event logs to a SIEM in real time; local log clearing becomes irrelevant.\n2) Alert on Event Log Service stops and wevtutil cl / Clear-EventLog commands (Event ID 1102, 104).\n3) Restrict wevtutil.exe and Clear-EventLog rights to Domain Admins only via AppLocker.\n4) Enable audit-log backup to an immutable write-once store for forensic preservation.",

	// Obfuscated Files — encoded commands
	"T1027": "1) Enable AMSI to scan decoded script content before execution regardless of obfuscation.\n2) Enable PowerShell Script Block Logging (Event ID 4104) — captures decoded content.\n3) Alert on -EncodedCommand / -enc flags in PowerShell process command lines.\n4) Deploy UEBA to detect anomalous script execution patterns by user and machine.",

	// Deobfuscate/Decode Files
	"T1140": "1) Monitor certutil.exe and expand.exe usage in EDR for -decode/-urlcache flags.\n2) Enable Script Block Logging to catch inline decode-then-execute patterns.\n3) Block certutil.exe from writing to user-writable directories via WDAC.\n4) Alert on base64 strings of length >512 bytes in process command-line arguments.",

	// Exploitation for Privilege Escalation
	"T1068": "1) Maintain a rigorous patch cadence — prioritise CISA KEV vulnerabilities for emergency patching.\n2) Enable Windows Exploit Protection (DEP, ASLR, CFG, ACG) via GPO for all processes.\n3) Deploy an EDR with kernel exploit detection and alert on unexpected kernel module loads.\n4) Enforce least-privilege: standard users cannot install drivers or interact with kernel objects.",

	// Access Token Manipulation
	"T1134": "1) Restrict SeDebugPrivilege and SeImpersonatePrivilege to trusted system accounts only.\n2) Alert on privilege use events (Event IDs 4672, 4673, 4674) for non-admin accounts.\n3) Deploy EDR rules detecting token duplication via NtDuplicateToken or CreateProcessWithTokenW.\n4) Enable Windows Defender Credential Guard to prevent impersonation of domain credentials.",

	// Token Impersonation / Theft
	"T1134.001": "1) Remove SeImpersonatePrivilege from IIS application pool and service accounts where not needed.\n2) Alert on impersonation token creation by non-SYSTEM processes (Sysmon Event ID 10).\n3) Deploy Windows Defender for Endpoint rules detecting named-pipe impersonation patterns.\n4) Enforce application identity with managed service accounts (gMSA) to reduce token exposure.",

	// Parent PID Spoofing
	"T1134.004": "1) Deploy EDR with process tree integrity validation to detect parent-PID manipulation.\n2) Alert on processes whose reported parent PID does not match the actual creator (Sysmon correlation).\n3) Enable kernel callbacks for process creation (ETW PsSetCreateProcessNotifyRoutine) via EDR.\n4) Use WDAC to enforce trusted process chains and block unsigned process creation.",

	// Bypass UAC
	"T1548.002": "1) Set UAC to Always Notify (highest level) via GPO and do not suppress prompts.\n2) Remove users from local Administrators group; only use dedicated admin accounts with approval.\n3) Alert on auto-elevation abuse: fodhelper.exe, eventvwr.exe launching child processes.\n4) Enable Sysmon rules detecting known UAC bypass binary patterns and registry hijacks.",

	// Port Scanning / Network Service Discovery
	"T1046": "1) Deploy network-based IDS/IPS to detect and alert on rapid port scan patterns.\n2) Implement host-based firewall rules blocking unsolicited inbound probe traffic.\n3) Alert on nmap.exe, masscan.exe, or Test-NetConnection in bulk from endpoint EDR.\n4) Restrict outbound scanning tools via WDAC/AppLocker application control.",

	// WMI execution
	"T1047": "1) Restrict WMI access to administrators; block lateral WMI via host firewall (DCOM port 135).\n2) Enable WMI activity logging (Event ID 5857/5858/5860/5861) and forward to SIEM.\n3) Alert on Win32_Process.Create calls with encoded or obfuscated command lines in EDR.\n4) Deploy ASR rule e6db77e5 (Block persistence through WMI event subscription).",

	// Mshta LOLBin
	"T1218.005": "1) Block mshta.exe from accessing remote URLs via WDAC or AppLocker.\n2) Enable ASR rule 3b576869 (Block Office communication app from creating child processes).\n3) Alert on mshta.exe spawning any network connections or child process creation.\n4) Associate .hta files with a blocked handler via file association GPO.",

	// Rundll32 LOLBin
	"T1218.011": "1) Deploy WDAC rules that block rundll32.exe from loading DLLs from user-writable paths.\n2) Alert on rundll32.exe executing with JavaScript:// or shell32.dll ShellExec_RunDLL patterns.\n3) Enable Sysmon Event ID 7 (ImageLoad) to detect unsigned DLLs loaded via rundll32.\n4) Block rundll32 spawning child network processes via EDR behavioural rule.",

	// Regsvr32 LOLBin
	"T1218.010": "1) Block regsvr32.exe from executing remote COM scriptlet URLs via WDAC.\n2) Alert on regsvr32 /s /n /u /i:http — Squiblydoo pattern — in process command lines.\n3) Enable ASR rule 92e97fa1 (Block Win32 API calls from Office macros).\n4) Monitor regsvr32.exe network connections with Sysmon Event ID 3.",

	// Certutil LOLBin
	"T1218.003": "1) Block certutil.exe -urlcache and -decode operations via WDAC script rules.\n2) Alert on certutil.exe spawning network connections or writing to temp directories.\n3) Enable Sysmon Event ID 11 to detect certutil writing files outside expected PKI paths.\n4) Monitor command-line arguments for -decode, -encode, and -urlcache flags in EDR.",

	// MSBuild LOLBin
	"T1127.001": "1) Block MSBuild.exe from running in non-developer environments via AppLocker/WDAC.\n2) Alert on MSBuild.exe process creation outside of known CI/CD pipelines in EDR.\n3) Restrict developer tools to designated build systems; disable on all endpoint workstations.\n4) Monitor for MSBuild spawning child processes or network connections.",

	// XSLT processing LOLBin
	"T1220": "1) Block msxsl.exe and xsltproc from being executed by standard users via WDAC.\n2) Alert on xslt-processing binaries making network connections or spawning child processes.\n3) Restrict XML/XSLT libraries from executing embedded scripts by disabling script blocks.\n4) Deploy Sysmon Event ID 1 rules alerting on unusual XSLT binary executions.",

	// BITSAdmin LOLBin
	"T1197": "1) Monitor BITS jobs via Event IDs 59, 60, 61 and alert on jobs downloading from external URLs.\n2) Block BITS job creation by standard users via AppLocker/WDAC.\n3) Restrict BITS service to approved update sources via firewall egress rules.\n4) Alert on bitsadmin.exe usage outside of known patch management systems in EDR.",

	// Screen Capture collection
	"T1113": "1) Deploy EDR rules alerting on APIs BitBlt/GDI+ StretchBlt called by non-approved processes.\n2) Block screen capture utilities (IrfanView, ShareX, etc.) from executing via AppLocker on sensitive hosts.\n3) Alert on processes loading GDI32.dll or user32.dll functions associated with screen capture.\n4) Implement DLP policies that detect and block screenshot file creation on regulated endpoints.",

	// Clipboard Data collection
	"T1115": "1) Deploy EDR that alerts on OpenClipboard/GetClipboardData API calls from unknown processes.\n2) Restrict clipboard access in VDI environments using GPO (Do not allow Clipboard redirection).\n3) Alert on PowerShell Get-Clipboard or Win32 Clipboard API usage by non-user-context processes.\n4) Enable application control (WDAC) to block clipboard harvesting tools.",

	// Keylogging collection
	"T1056.001": "1) Deploy EDR with API hooking detection for SetWindowsHookEx keyboard hooks.\n2) Enable Kernel Patch Protection and Secure Boot to block kernel-mode keyloggers.\n3) Alert on processes registering low-level keyboard hooks (Sysmon + ETW hook events).\n4) Use hardware security keys (FIDO2) to ensure keylogged passwords cannot be replayed.",

	// C2 over HTTP/HTTPS
	"T1071.001": "1) Deploy a web proxy with TLS inspection to inspect all outbound HTTPS traffic.\n2) Enable DNS filtering and threat-intel-based URL blocklist at the network perimeter.\n3) Implement beaconing detection: alert on regular low-volume outbound connections at fixed intervals.\n4) Block direct outbound internet access from endpoints; force all traffic through the proxy.",

	// C2 over DNS
	"T1071.004": "1) Deploy DNS filtering (Umbrella/Cloudflare Gateway) to block known C2 and DGA domains.\n2) Alert on high-volume DNS queries or unusually long DNS subdomains (>50 chars) indicating tunnelling.\n3) Restrict endpoints to using only internal DNS resolvers; block external DNS (port 53) egress.\n4) Enable DNS query logging and ingest into SIEM for anomaly detection.",

	// Data Encrypted for Impact (Ransomware)
	"T1486": "1) Implement 3-2-1 immutable backup strategy with offline/air-gapped copies per RBI BCP guidelines.\n2) Enable Controlled Folder Access in Windows Defender to block unauthorised file encryption.\n3) Deploy Ransomware-specific EDR rules; enable automatic device isolation on ransomware detection.\n4) Restrict VSS/shadow copy deletion to Domain Admins with MFA confirmation.",

	// Inhibit System Recovery (VSS deletion)
	"T1490": "1) Restrict vssadmin.exe and wmic shadowcopy delete to privileged accounts only via WDAC.\n2) Enable ASR rule 26190899 (Block credential stealing from Windows local security authority subsystem).\n3) Alert on vssadmin delete shadows, wbadmin delete, or bcdedit /set commands in EDR.\n4) Maintain offline backup copies that cannot be reached from the compromised endpoint.",

	// Exfil via non-standard port
	"T1048.003": "1) Enforce egress firewall rules allowing outbound traffic only on approved ports (80, 443, 25).\n2) Deploy DLP to inspect and block data leaving on non-standard outbound ports.\n3) Alert on outbound connections to ports outside the approved list via Sysmon Event ID 3.\n4) Implement network segmentation so regulated endpoints cannot directly reach the internet.",

	// Pass-the-Hash
	"T1550.002": "1) Enable Windows Defender Credential Guard to protect NTLM hashes in memory.\n2) Disable NTLM where possible; enforce Kerberos AES-256 authentication across the domain.\n3) Enable SMB signing on all systems to prevent relay attacks using pass-the-hash.\n4) Alert on NTLM authentication from workstations to servers outside approved network paths.",

	// Kerberoasting
	"T1558.003": "1) Ensure all service accounts use AES-256 (msDS-SupportedEncryptionTypes) — disable RC4.\n2) Set service account passwords to 25+ character random strings and rotate them regularly.\n3) Alert on Kerberos TGS-REQ requests for service tickets (Event ID 4769) with RC4 encryption.\n4) Deploy Microsoft Defender for Identity or similar to detect Kerberoasting request patterns.",

	// AS-REP Roasting
	"T1558.004": "1) Disable 'Do not require Kerberos preauthentication' for all user accounts in AD.\n2) Alert on AS-REQ requests without preauthentication (Event ID 4768 Failure code 0x18).\n3) Enforce AES-256 Kerberos encryption and disable RC4 via Group Policy.\n4) Audit accounts with UF_DONT_REQUIRE_PREAUTH flag set and remediate immediately.",

	// Network Sniffing / ARP Poisoning
	"T1557.001": "1) Enable Dynamic ARP Inspection (DAI) on managed switches to block ARP poisoning.\n2) Enable DHCP Snooping to restrict DHCP responses to authorised servers only.\n3) Alert on promiscuous-mode network interface detection or ARP cache anomalies via NDR.\n4) Enforce network segmentation so workstations cannot intercept inter-server traffic.",

	// DLL Search Order Hijacking
	"T1574.001": "1) Audit and fix applications loading DLLs from user-writable directories (Process Monitor).\n2) Enable Safe DLL Search Mode (HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\SafeDllSearchMode=1).\n3) Use WDAC to enforce that only signed DLLs from known paths can be loaded by applications.\n4) Monitor Sysmon Event ID 7 for unsigned DLLs being loaded by high-privilege processes.",

	// Reflective Code Loading
	"T1620": "1) Deploy EDR with memory scanning that detects in-memory PE loading without a disk image.\n2) Enable Windows Defender's scanning of reflective injection patterns (AMSI memory scan).\n3) Alert on processes with executable memory regions not backed by a file on disk.\n4) Use process mitigation policies (ACG — Arbitrary Code Guard) to block dynamic code injection.",

	// Domain Trust Discovery
	"T1482": "1) Audit and minimise inter-domain trust relationships; remove legacy or unused trusts.\n2) Alert on nltest /domain_trusts and Get-ADTrust queries from non-DC endpoints in EDR.\n3) Restrict domain enumeration APIs to privileged accounts via AD access control lists.\n4) Deploy Microsoft Defender for Identity to detect trust enumeration reconnaissance patterns.",

	// Security Software Discovery
	"T1518.001": "1) This is reconnaissance — harden by ensuring security tools are not trivially discoverable.\n2) Alert on reg query/WMIC queries enumerating installed software on multiple endpoints.\n3) Use deception technology (honeytokens) to detect systematic tool discovery sweeps.\n4) Restrict WMI and registry enumeration to admin accounts via AppLocker and AD delegation.",

	// Browser Credential Theft
	"T1555.003": "1) Deploy EDR rules alerting on processes reading Chrome/Edge/Firefox credential store files.\n2) Enable Credential Guard; note it does not protect browser-stored passwords — use a PAM vault.\n3) Enforce enterprise password manager policy: no credentials stored in browser vaults on managed devices.\n4) Alert on DPAPI master-key access by processes other than the owning browser.",

	// Windows Credential Manager theft
	"T1555.004": "1) Alert on vaultcmd.exe /listcreds and CredRead API calls by non-approved processes.\n2) Enforce policy that no service or web credentials are stored in Windows Credential Manager.\n3) Deploy EDR rule detecting credential manager access by remote sessions or lateral processes.\n4) Use a privileged access management (PAM) vault for all service and privileged credentials.",

	// Brute Force
	"T1110": "1) Enforce account lockout policy: 5 failed attempts, 30-minute lockout, reset after 15 minutes.\n2) Deploy MFA (phishing-resistant FIDO2/OTP) so cracked passwords alone are insufficient.\n3) Alert on Event ID 4625 (failed logon) bursts from a single source IP in the SIEM.\n4) Implement geo-restriction and impossible-travel alerting for authentication anomalies.",

	// Password Spraying
	"T1110.003": "1) Deploy anomaly detection that alerts on one source attempting authentication across many accounts.\n2) Enforce phishing-resistant MFA to render sprayed passwords useless without second factor.\n3) Alert on distributed low-volume 4625 events spread across many usernames over short windows.\n4) Enable Smart Lockout in Azure AD / Entra ID to detect and throttle spray attempts.",

	// Phishing Attachment
	"T1566.001": "1) Deploy an email gateway with attachment sandboxing and reputation-based filtering.\n2) Enable Mark of the Web (MoTW) enforcement so downloaded attachments open in Protected View.\n3) Enable ASR rules: Block Office macros from internet-delivered files (92e97fa1, d4f940ab).\n4) Conduct regular phishing simulation and awareness training for all staff.",

	// Valid Accounts — credential abuse
	"T1078": "1) Enforce phishing-resistant MFA (FIDO2) on all accounts — especially privileged and external-facing.\n2) Implement Privileged Access Workstations (PAWs) for all administrative activity.\n3) Deploy UEBA to detect anomalous login patterns (unusual time, location, or target resource).\n4) Audit and remove stale accounts; enforce re-certification of all privileged accounts quarterly.",

	// Ingress Tool Transfer (download)
	"T1105": "1) Block curl.exe, wget, bitsadmin, and certutil from downloading files via WDAC.\n2) Implement egress filtering that restricts download of executable file types to approved processes.\n3) Alert on PowerShell Invoke-WebRequest / Invoke-Expression patterns downloading and executing.\n4) Enable proxy SSL inspection to scan downloaded content before delivery to the endpoint.",

	// Cloud Service Discovery
	"T1526": "1) Restrict cloud API enumeration via IAM least-privilege policies — deny ListBuckets, ListFunctions.\n2) Enable CloudTrail/Audit Logs and alert on bulk describe/list calls from non-automated principals.\n3) Deploy CSPM tool to detect and alert on abnormal enumeration activity.\n4) Use Service Control Policies (SCPs) to restrict which cloud services can be queried.",

	// Email credential / account discovery
	"T1589.002": "1) Restrict access to employee directories and LDAP queries to internal networks only.\n2) Alert on large LDAP attribute reads or email harvesting patterns via AD audit logs.\n3) Configure Exchange/O365 to rate-limit and alert on bulk directory enumeration.\n4) Use honeypot accounts with fake email addresses to detect harvesting operations.",

	// Proxy C2
	"T1090": "1) Implement network segmentation — endpoints should not be able to proxy traffic to each other.\n2) Deploy NDR to detect multi-hop proxy chains and unusual peer-to-peer traffic patterns.\n3) Alert on SOCKS/HTTP proxy setup commands (netsh portproxy, SSH -R/-D) in EDR.\n4) Block outbound traffic from endpoints to non-whitelisted external IPs via egress firewall.",
	// Service Execution / SetServiceObjectSecurity â€” service ACL abuse, not script execution.
	"T1569.002": "1) Audit service DACLs (sc.exe sdshow / SCM) and remove WRITE_DAC, WRITE_OWNER, and CHANGE_CONFIG from non-admin principals.\n" +
		"2) Harden SCM permissions; restrict who may create, reconfigure, or change the security descriptor of services.\n" +
		"3) Review SeTakeOwnershipPrivilege / SeRestorePrivilege assignments â€” restrict to trusted administrators.\n" +
		"4) Monitor service DACL changes and service-config modifications (Event IDs 7045, 4697) and alert on non-admin actors.",
	// Create or Modify System Service â€” service-based persistence.
	"T1543.003": "1) Restrict service creation/modification to administrators; audit and baseline all installed services.\n" +
		"2) Enable alerts on new service installation (Event ID 7045) and unexpected ImagePath changes.\n" +
		"3) Enforce signed-binary service images via WDAC/AppLocker; block services launching from user-writable paths.\n" +
		"4) Monitor SCM database (HKLM\\SYSTEM\\CurrentControlSet\\Services) for unauthorised additions.",
	// Modify Registry â€” registry-specific monitoring, not generic script logging.
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
	if result == ResultVetoed {
		// Falling through to technique/tactic remediation guidance below
		// would present real advice (e.g. "Enable Credential Guard...")
		// for a technique that was never actually attempted -- implying a
		// gap was found when the honest state is "not tested" (verified,
		// B5 Task 9 audit).
		return fmt.Sprintf(
			"Not assessed: %s (%s) was not attempted -- Audspect's own agent refused execution under its local destructive-action policy. This tells you nothing about your defenses; no remediation guidance applies.",
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
			"3) Patch known privilege escalation CVEs â€” cross-reference CISA KEV catalogue.\n" +
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


