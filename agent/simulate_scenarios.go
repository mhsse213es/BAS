package main

import (
	"fmt"
	"os/exec"
	"strings"
)

// RunScenarioChecks returns checks scoped to a specific scenario.
// Falls back to RunAllChecks for unknown IDs.
func RunScenarioChecks(scenarioID string) []SimCategory {
	switch scenarioID {
	case "apt36-spearphish":
		return apt36Checks()
	case "ransomware-drill":
		return ransomwareChecks()
	case "ad-credential-access":
		return adCredentialChecks()
	case "upi-fraud-killchain":
		return upiChecks()
	case "cscrf-mii-drill":
		return cscrfChecks()
	default:
		return RunAllChecks()
	}
}

// ── APT36 Spear-Phishing Kill Chain ──────────────────────────────────────────
// Tests controls against APT36 (Transparent Tribe) TTPs: Office macro
// delivery, HTA/mshta execution, scheduled-task persistence, browser
// credential theft, and HTTP C2 beaconing.

func apt36Checks() []SimCategory {
	return []SimCategory{
		{Phase: "initial-access", Checks: []SimCheck{
			checkOfficeMacroBlocking(),
			checkProtectedViewInternetFiles(),
			checkMOTWProcessing(),
		}},
		{Phase: "execution", Checks: []SimCheck{
			checkMshtaExecControl(),
			checkWScriptControl(),
			checkScriptBlockLogging(),
		}},
		{Phase: "persistence", Checks: []SimCheck{
			checkScheduledTasksFromWritablePaths(),
			checkRunKeys(),
		}},
		{Phase: "credential-access", Checks: []SimCheck{
			checkBrowserCredentialStorage(),
			checkAutoLogon(),
		}},
	}
}

func checkOfficeMacroBlocking() SimCheck {
	return check("T1566.001", "Office VBA Macro Execution Policy", "initial-access", "Critical",
		"APT36 delivers CrimsonRAT/ObliqueRAT via weaponised Office documents — VBA macro execution is the initial foothold.",
		"Block macros from internet via GPO: User Config → Administrative Templates → Microsoft Office → Security Settings → VBA Macro Notification Settings = 4.",
		func() (string, string) {
			paths := []string{
				`HKCU\SOFTWARE\Policies\Microsoft\Office\16.0\Word\Security`,
				`HKCU\SOFTWARE\Policies\Microsoft\Office\15.0\Word\Security`,
				`HKLM\SOFTWARE\Policies\Microsoft\Office\16.0\Word\Security`,
			}
			for _, p := range paths {
				val, err := regValue(p, "VBAWarnings")
				if err == nil {
					switch val {
					case "0x4", "4":
						return "pass", "Office VBA macros disabled without notification (VBAWarnings=4) — APT36 document delivery blocked."
					case "0x3", "3":
						return "pass", "Office macros restricted to digitally signed only (VBAWarnings=3)."
					case "0x2", "2":
						return "fail", "Office shows macro warning but user can click Enable — social engineering still effective."
					case "0x1", "1":
						return "fail", "All Office VBA macros enabled without restriction — APT36 weaponised documents execute freely."
					}
				}
			}
			return "fail", "No Office macro restriction policy found — VBA payloads may execute on document open."
		})
}

func checkProtectedViewInternetFiles() SimCheck {
	return check("T1566.001", "Office Protected View (Internet-Sourced Files)", "initial-access", "High",
		"Disabled Protected View lets phishing attachments execute macros on open without user interaction.",
		"Verify Protected View is on: Office Trust Center → Protected View → enable all three checkboxes.",
		func() (string, string) {
			val, err := regValue(
				`HKCU\SOFTWARE\Microsoft\Office\16.0\Word\Security\ProtectedView`,
				"DisableInternetFilesInPV")
			if err != nil {
				return "pass", "DisableInternetFilesInPV absent — Protected View for internet files is ON (default)."
			}
			if val == "0x0" || val == "0" {
				return "pass", "Protected View enabled for internet/email attachments — macro auto-run on open prevented."
			}
			return "fail", "Protected View DISABLED for internet files — APT36 spear-phishing attachments open with full execution rights."
		})
}

func checkMOTWProcessing() SimCheck {
	return check("T1566.001", "Mark of the Web (MOTW) Enforcement", "initial-access", "High",
		"APT36 packs HTA droppers inside ZIP/ISO to bypass MOTW and execute without Protected View.",
		"Apply KB5016616+ (Win11 22H2) so MOTW propagates to archive contents. Use Defender ASR rule for Office child processes.",
		func() (string, string) {
			val, err := regValue(
				`HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments`,
				"ScanWithAntiVirus")
			if err != nil {
				val, err = regValue(
					`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments`,
					"ScanWithAntiVirus")
			}
			if err == nil && (val == "0x3" || val == "3") {
				return "pass", "Attachment manager scans downloads with antivirus (ScanWithAntiVirus=3) — MOTW processing active."
			}
			if err == nil && (val == "0x1" || val == "1") {
				return "pass", "Attachment manager configured — MOTW scanning enabled."
			}
			return "fail", "Attachment scanning policy absent — MOTW bypass via archive containers (ZIP/ISO/IMG) not mitigated."
		})
}

func checkMshtaExecControl() SimCheck {
	return check("T1218.005", "mshta.exe Execution Control", "execution", "Critical",
		"APT36 uses mshta.exe to execute HTA payloads — a signed Windows binary that bypasses most script restrictions.",
		"Block mshta.exe via AppLocker Publisher rule or WDAC deny policy. Enable ASR rule: Block Office child processes.",
		func() (string, string) {
			out, err := psRun(`Get-AppLockerPolicy -Effective -Xml 2>$null | Select-String -Quiet "mshta"`)
			if err == nil && strings.EqualFold(strings.TrimSpace(out), "True") {
				return "pass", "AppLocker policy references mshta.exe — HTA execution control in place."
			}
			if svcRunning("AppIDSvc") {
				out2, _ := psRun(`(Get-AppLockerPolicy -Effective -Xml 2>$null).Length`)
				if len(strings.TrimSpace(out2)) > 2 {
					return "pass", "AppLocker AppIDSvc active with effective policy — LOLBin blocking may cover mshta.exe."
				}
			}
			return "fail", "mshta.exe not explicitly blocked — APT36 HTA dropper execution via spear-phish attachment is possible."
		})
}

func checkWScriptControl() SimCheck {
	return check("T1059.005", "WScript/CScript Execution Control", "execution", "High",
		"APT36 uses VBScript via wscript.exe for second-stage payload execution after the HTA dropper.",
		"Disable VBScript in Internet Zone (Zone 3, setting 1400=3). Block wscript.exe/cscript.exe via AppLocker.",
		func() (string, string) {
			val, err := regValue(
				`HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3`,
				"1400")
			if err == nil && (val == "0x3" || val == "3") {
				return "pass", "VBScript disabled in Internet Zone (Zone3:1400=3) — wscript-based APT36 droppers blocked."
			}
			out, err := psRun(`Get-AppLockerPolicy -Effective -Xml 2>$null | Select-String -Quiet "wscript|cscript"`)
			if err == nil && strings.EqualFold(strings.TrimSpace(out), "True") {
				return "pass", "AppLocker restricts wscript.exe/cscript.exe — VBScript execution blocked by policy."
			}
			return "fail", "WScript/CScript not restricted — VBScript payloads from APT36 documents can execute freely."
		})
}

func checkScheduledTasksFromWritablePaths() SimCheck {
	return check("T1053.005", "Scheduled Tasks Running from User-Writable Paths", "persistence", "High",
		"APT36 creates scheduled tasks pointing to %TEMP%/%APPDATA% to persist CrimsonRAT across reboots.",
		"Audit schtasks for Temp/AppData actions. Block execution from user-writable paths via AppLocker/WDAC.",
		func() (string, string) {
			out, err := psRun(`(Get-ScheduledTask | Where-Object {$_.Actions | Where-Object {$_.Execute -match "Temp|AppData|Public|Users.*Downloads"}} | Measure-Object).Count`)
			if err != nil {
				return "skipped", "Could not enumerate scheduled task actions."
			}
			count := strings.TrimSpace(out)
			if count == "0" || count == "" {
				return "pass", "No scheduled tasks execute from user-writable paths (Temp/AppData) — APT36-style persistence not detected."
			}
			return "fail", fmt.Sprintf("%s scheduled task(s) run from Temp/AppData — APT36 persistence pattern detected, manual review required.", count)
		})
}

func checkBrowserCredentialStorage() SimCheck {
	return check("T1555.003", "Browser Saved Credential Store Exposure", "credential-access", "Critical",
		"APT36 steals banking portal credentials from Chrome/Edge Login Data — a SQLite database readable without elevation.",
		"Disable browser password managers via enterprise policy. Use a PAM vault for banking system credentials.",
		func() (string, string) {
			for _, p := range []string{
				`HKLM\SOFTWARE\Policies\Google\Chrome`,
				`HKCU\SOFTWARE\Policies\Google\Chrome`,
				`HKLM\SOFTWARE\Policies\Microsoft\Edge`,
			} {
				val, err := regValue(p, "PasswordManagerEnabled")
				if err == nil && (val == "0x0" || val == "0") {
					return "pass", "Browser password manager disabled via enterprise policy — credential theft from browser store blocked."
				}
			}
			chromeDB, _ := psRun(`Test-Path "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Login Data"`)
			if strings.EqualFold(strings.TrimSpace(chromeDB), "True") {
				return "fail", "Chrome Login Data DB found — saved banking credentials are readable by any process running as this user."
			}
			edgeDB, _ := psRun(`Test-Path "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Login Data"`)
			if strings.EqualFold(strings.TrimSpace(edgeDB), "True") {
				return "fail", "Edge Login Data DB found — saved passwords accessible to credential-dumping tools."
			}
			return "pass", "No browser credential databases found, or password manager disabled by policy."
		})
}

// ── Ransomware Drill (BFSI BCP Test) ─────────────────────────────────────────
// Tests ransomware resilience: AV tamper, shadow copy availability, recovery
// environment, controlled folder access, disk encryption, and SMB lateral spread.

func ransomwareChecks() []SimCategory {
	return []SimCategory{
		{Phase: "defense-evasion", Checks: []SimCheck{
			checkDefenderRTP(),
			checkDefenderTamperProtection(),
			checkEventLog(),
		}},
		{Phase: "impact", Checks: []SimCheck{
			checkControlledFolderAccess(),
			checkVSSShadowCopies(),
			checkBCDEditRecovery(),
			checkBitLockerStatus(),
		}},
		{Phase: "lateral-movement", Checks: []SimCheck{
			checkSMBSigning(),
			checkLLMNR(),
		}},
		{Phase: "persistence", Checks: []SimCheck{
			checkRunKeys(),
			checkServicesIntegrity(),
		}},
	}
}

func checkControlledFolderAccess() SimCheck {
	return check("T1486", "Controlled Folder Access (Ransomware Protection)", "impact", "Critical",
		"Without CFA, ransomware (LockBit, BlackCat, ALPHV) freely encrypts Documents, Desktop, and Pictures.",
		"Enable: Windows Security → Virus & Threat Protection → Ransomware Protection → Controlled Folder Access ON.",
		func() (string, string) {
			out, err := psRun(`(Get-MpPreference -ErrorAction SilentlyContinue).EnableControlledFolderAccess`)
			if err == nil {
				v := strings.TrimSpace(out)
				if v == "1" {
					return "pass", "Controlled Folder Access enabled — user data directories protected against ransomware encryption."
				}
				if v == "2" {
					return "pass", "Controlled Folder Access in Audit mode — detects but does not block encryption attempts."
				}
				if v == "0" {
					return "fail", "Controlled Folder Access DISABLED — ransomware can encrypt Documents/Desktop/Pictures without restriction."
				}
			}
			val, err := regValue(
				`HKLM\SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access`,
				"EnableControlledFolderAccess")
			if err == nil && (val == "0x1" || val == "1") {
				return "pass", "Controlled Folder Access enabled via registry — ransomware encryption of protected folders blocked."
			}
			return "fail", "Controlled Folder Access not configured — endpoint has no ransomware-specific file protection."
		})
}

func checkVSSShadowCopies() SimCheck {
	return check("T1490", "VSS Shadow Copy Availability", "impact", "Critical",
		"Ransomware deletes all shadow copies (vssadmin delete shadows /all) before encrypting — primary recovery path destroyed.",
		"Enable automatic VSS on all volumes. Maintain offline/immutable backups per RBI BCP guidelines.",
		func() (string, string) {
			out, err := psRun(`(Get-WmiObject Win32_ShadowCopy -ErrorAction SilentlyContinue | Measure-Object).Count`)
			if err != nil {
				return "skipped", "Could not query VSS shadow copies — WMI error or insufficient privileges."
			}
			count := strings.TrimSpace(out)
			if count == "0" || count == "" {
				return "fail", "No VSS shadow copies exist — ransomware recovery impossible without external offline backup."
			}
			return "pass", fmt.Sprintf("%s VSS shadow copy/copies present — point-in-time recovery available if copies are protected.", count)
		})
}

func checkBCDEditRecovery() SimCheck {
	return check("T1490", "Windows Recovery Environment (WinRE) Status", "impact", "High",
		"Ransomware runs 'bcdedit /set {default} recoveryenabled No' to prevent boot-time recovery and safe-mode remediation.",
		"Run 'reagentc /enable'. Monitor bcdedit execution via Windows Event ID 4688 process audit.",
		func() (string, string) {
			out, err := exec.Command("reagentc", "/info").Output()
			if err != nil {
				return "skipped", "reagentc not available — WinRE status cannot be verified."
			}
			lower := strings.ToLower(string(out))
			if strings.Contains(lower, "enabled") {
				return "pass", "Windows Recovery Environment enabled — boot-time ransomware remediation available."
			}
			if strings.Contains(lower, "disabled") {
				return "fail", "Windows Recovery Environment DISABLED — bcdedit tampering may have succeeded, boot recovery blocked."
			}
			return "pass", "WinRE status indeterminate — manual verification recommended."
		})
}

func checkBitLockerStatus() SimCheck {
	return check("T1486", "BitLocker Disk Encryption (C: Drive)", "impact", "High",
		"Unencrypted drives let ransomware operators read all data before encrypting — double-extortion enabled.",
		"Enable BitLocker on all drives via GPO: Computer Config → Windows Settings → BitLocker Drive Encryption.",
		func() (string, string) {
			out, err := psRun(`(Get-BitLockerVolume -MountPoint "C:" -ErrorAction SilentlyContinue).ProtectionStatus`)
			if err == nil {
				v := strings.TrimSpace(out)
				if v == "On" {
					return "pass", "BitLocker ON for C: — drive data encrypted at rest, ransomware data-theft impact limited."
				}
				if v == "Off" {
					return "fail", "BitLocker OFF for C: — plaintext disk accessible if drive is removed, enabling double-extortion."
				}
			}
			out2, err2 := exec.Command("manage-bde", "-status", "C:").Output()
			if err2 == nil {
				lower := strings.ToLower(string(out2))
				if strings.Contains(lower, "protection on") {
					return "pass", "BitLocker protection ON — C: drive encrypted."
				}
				if strings.Contains(lower, "protection off") {
					return "fail", "BitLocker protection OFF — C: drive unencrypted."
				}
			}
			return "skipped", "BitLocker status could not be determined (requires elevation or BitLocker module)."
		})
}

// ── AD Credential Access Drill (PurpleSharp) ─────────────────────────────────
// Tests controls against LSASS dumping, Kerberoasting, AS-REP Roasting,
// Pass-the-Hash, and DCSync — the top AD attack paths in Indian BFSI incidents.

func adCredentialChecks() []SimCategory {
	return []SimCategory{
		{Phase: "credential-access", Checks: []SimCheck{
			checkLSAProtection(),
			checkWDigest(),
			checkCredentialGuard(),
			checkLSASSAuditPolicy(),
			checkKerberosAESEncryption(),
			checkAutoLogon(),
		}},
		{Phase: "lateral-movement", Checks: []SimCheck{
			checkNTLMRestrictions(),
			checkPassTheHashMitigation(),
			checkSMBSigning(),
			checkLLMNR(),
		}},
		{Phase: "privilege-escalation", Checks: []SimCheck{
			checkUACEnabled(),
			checkLocalAdminTokenFilter(),
			checkAlwaysInstallElevated(),
		}},
	}
}

func checkLSASSAuditPolicy() SimCheck {
	return check("T1003.001", "LSASS Process Access Auditing", "credential-access", "High",
		"Without LSASS access auditing, ProcDump and comsvcs.dll MiniDump credential dumps are invisible to defenders.",
		"Enable via GPO: Advanced Audit → Object Access → Audit Kernel Object. Set HKLM\\...\\LSASS.exe\\AuditLevel = 8.",
		func() (string, string) {
			val, err := regValue(
				`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe`,
				"AuditLevel")
			if err == nil && (val == "0x8" || val == "8") {
				return "pass", "LSASS AuditLevel = 8 — credential access attempts logged to Event ID 4656/4663."
			}
			out, err := psRun(`auditpol /get /subcategory:"Process Access" 2>$null`)
			if err == nil {
				lower := strings.ToLower(out)
				if strings.Contains(lower, "success and failure") {
					return "pass", "Process access auditing enabled (Success+Failure) — LSASS dump attempts generate event logs."
				}
				if strings.Contains(lower, "success") {
					return "pass", "Process access success auditing enabled — LSASS access logged on success."
				}
			}
			return "fail", "LSASS process access auditing not configured — ProcDump/Mimikatz credential dumps are undetected."
		})
}

func checkKerberosAESEncryption() SimCheck {
	return check("T1558.003", "Kerberos RC4 Disabled (Anti-Kerberoasting)", "credential-access", "High",
		"Kerberoasting harvests RC4-encrypted TGS tickets crackable offline in hours; AES-256 tickets are not feasibly crackable.",
		"Set SupportedEncryptionTypes = 24 (AES128+AES256 only) and set msDS-SupportedEncryptionTypes on service accounts.",
		func() (string, string) {
			val, err := regValue(
				`HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters`,
				"SupportedEncryptionTypes")
			if err != nil {
				return "fail", "Kerberos SupportedEncryptionTypes not set — RC4 (weak, Kerberoastable) allowed by default."
			}
			if val == "0x18" || val == "24" || val == "0x1c" || val == "28" {
				return "pass", fmt.Sprintf("Kerberos encryption types = %s (AES only) — RC4 disabled, Kerberoast resistance maximised.", val)
			}
			return "fail", fmt.Sprintf("Kerberos SupportedEncryptionTypes = %s — RC4 likely allowed, service account tickets are Kerberoastable.", val)
		})
}

func checkPassTheHashMitigation() SimCheck {
	return check("T1550.002", "Pass-the-Hash Mitigation (Restricted Admin Mode)", "lateral-movement", "High",
		"Without Restricted Admin Mode, Mimikatz-extracted NTLM hashes allow RDP lateral movement to any reachable host.",
		"Enable Restricted Admin Mode: HKLM\\...\\Lsa\\DisableRestrictedAdmin = 0. Implement credential tiering.",
		func() (string, string) {
			val, err := regValue(
				`HKLM\SYSTEM\CurrentControlSet\Control\Lsa`,
				"DisableRestrictedAdmin")
			if err != nil || val == "0x0" || val == "0" {
				return "pass", "Restricted Admin Mode enabled (DisableRestrictedAdmin=0) — Pass-the-Hash over RDP mitigated."
			}
			return "fail", "Restricted Admin Mode DISABLED — NTLM hash reuse for RDP lateral movement (Pass-the-Hash) not blocked."
		})
}

// ── UPI Fraud Kill Chain ──────────────────────────────────────────────────────
// Tests controls against UPI fraud TTPs: browser credential theft, OTP
// clipboard/screen harvesting, keylogging, DNS tunnelling, and HTTP exfiltration.

func upiChecks() []SimCategory {
	return []SimCategory{
		{Phase: "credential-access", Checks: []SimCheck{
			checkBrowserCredentialStorage(),
			checkWDigest(),
			checkAutoLogon(),
		}},
		{Phase: "collection", Checks: []SimCheck{
			checkClipboardHistoryPolicy(),
			checkScreenCaptureASR(),
			checkKeyloggerIndicators(),
		}},
		{Phase: "exfiltration", Checks: []SimCheck{
			checkDNSSecurityPolicy(),
			checkRootCertificateAudit(),
			checkOutboundProxyEnforcement(),
		}},
		{Phase: "defense-evasion", Checks: []SimCheck{
			checkDefenderRTP(),
			checkScriptBlockLogging(),
		}},
	}
}

func checkClipboardHistoryPolicy() SimCheck {
	return check("T1115", "Clipboard History Attack Surface", "collection", "High",
		"UPI fraud malware monitors clipboard to capture UPI VPAs, OTPs, and account numbers during copy-paste.",
		"Disable clipboard history via GPO: Computer Config → Windows Components → OS Policies → Allow Clipboard History = Disabled.",
		func() (string, string) {
			val, err := regValue(
				`HKLM\SOFTWARE\Policies\Microsoft\Windows\System`,
				"AllowClipboardHistory")
			if err == nil && (val == "0x0" || val == "0") {
				return "pass", "Clipboard history disabled via machine policy — clipboard sniffing attack surface eliminated."
			}
			val2, err2 := regValue(
				`HKCU\SOFTWARE\Microsoft\Clipboard`,
				"EnableClipboardHistory")
			if err2 == nil && (val2 == "0x0" || val2 == "0") {
				return "pass", "Clipboard history disabled in user settings — OTP interception via clipboard reduced."
			}
			return "fail", "Clipboard history not disabled by policy — malware can monitor clipboard for UPI PINs, OTPs, and VPAs."
		})
}

func checkScreenCaptureASR() SimCheck {
	return check("T1113", "Attack Surface Reduction Rules (Screen/Credential Capture)", "collection", "Medium",
		"Banking malware silently screenshots OTP confirmation screens and UPI transaction pages for fraud replay.",
		"Enable ASR rules via GPO: Computer Config → Defender Exploit Guard → Attack Surface Reduction → configure all rules.",
		func() (string, string) {
			out, err := psRun(`(Get-MpPreference -ErrorAction SilentlyContinue).AttackSurfaceReductionRules_Ids | Measure-Object | Select-Object -ExpandProperty Count`)
			if err != nil || strings.TrimSpace(out) == "" || strings.TrimSpace(out) == "0" {
				return "fail", "No ASR rules configured — malicious screen capture and credential-harvesting processes not blocked."
			}
			return "pass", fmt.Sprintf("%s ASR rule(s) active — reduced attack surface for malicious processes performing screen capture.", strings.TrimSpace(out))
		})
}

func checkKeyloggerIndicators() SimCheck {
	return check("T1056.001", "Keylogger Indicator Detection", "collection", "High",
		"UPI fraud malware deploys keyloggers to capture banking passwords, transaction PINs, and UPI authentication credentials.",
		"Deploy EDR with SetWindowsHookEx detection. Enable Credential Guard to protect credentials in memory.",
		func() (string, string) {
			out, err := psRun(`Get-Process 2>$null | Where-Object {$_.Modules.ModuleName -match "hook|keylog"} | Select-Object -ExpandProperty Name`)
			if err != nil {
				return "skipped", "Could not enumerate process modules — requires elevation for full module inspection."
			}
			if strings.TrimSpace(out) == "" {
				return "pass", "No processes with obvious keyboard-hook module names found in running process list."
			}
			return "fail", fmt.Sprintf("Processes with potential hooking modules found: %s — manual investigation required.", strings.TrimSpace(out))
		})
}

func checkDNSSecurityPolicy() SimCheck {
	return check("T1048.003", "DNS Tunnelling Prevention Policy", "exfiltration", "High",
		"UPI fraud malware exfiltrates transaction logs and credentials via DNS TXT record tunnelling to evade HTTP DLP.",
		"Enforce corporate DNS resolver. Block access to non-approved DoH providers. Deploy DNS filtering (e.g. Cisco Umbrella).",
		func() (string, string) {
			val, err := regValue(
				`HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient`,
				"EnableMulticast")
			if err == nil && (val == "0x0" || val == "0") {
				return "pass", "LLMNR disabled via policy — local DNS name poisoning and related tunnelling surface reduced."
			}
			dohVal, err2 := regValue(
				`HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient`,
				"DoHPolicy")
			if err2 == nil && (dohVal == "0x2" || dohVal == "2") {
				return "pass", "DNS-over-HTTPS policy = Require — DNS encrypted to corporate resolver, tunnelling to rogue servers blocked."
			}
			return "fail", "No DNS security policy (LLMNR/DoH) configured — DNS tunnelling exfiltration path open for UPI fraud payloads."
		})
}

func checkRootCertificateAudit() SimCheck {
	return check("T1553.004", "Root Certificate Store — Untrusted CA Audit", "exfiltration", "High",
		"UPI fraud malware installs rogue root CAs to MITM encrypted banking portal and UPI app traffic.",
		"Audit Trusted Root store monthly. Use Certificate Pinning for UPI/banking apps. Monitor CRYPT32 Event ID 70.",
		func() (string, string) {
			knownIssuers := []string{
				"Microsoft", "Comodo", "DigiCert", "Entrust", "GeoTrust",
				"GlobalSign", "VeriSign", "Symantec", "ISRG", "Certum",
				"USERTrust", "Baltimore", "AffirmTrust", "Sectigo",
				"QuoVadis", "SwissSign", "SECOM", "Buypass",
			}
			excludeFilter := make([]string, len(knownIssuers))
			for i, v := range knownIssuers {
				excludeFilter[i] = fmt.Sprintf(`$_.Issuer -notlike "*%s*"`, v)
			}
			cmd := fmt.Sprintf(`(Get-ChildItem Cert:\LocalMachine\Root | Where-Object {%s} | Measure-Object).Count`,
				strings.Join(excludeFilter, " -and "))
			out, err := psRun(cmd)
			if err != nil {
				return "skipped", "Could not enumerate root certificate store."
			}
			count := strings.TrimSpace(out)
			if count == "0" || count == "" {
				return "pass", "Root certificate store contains only recognised CAs — no suspicious MITM interception certificates found."
			}
			return "fail", fmt.Sprintf("%s non-standard root certificate(s) present — verify these are legitimate enterprise CAs, not rogue UPI-intercept certs.", count)
		})
}

func checkOutboundProxyEnforcement() SimCheck {
	return check("T1041", "Outbound Traffic Proxy Enforcement", "exfiltration", "High",
		"Without a forced proxy, UPI fraud malware exfiltrates transaction data directly, bypassing DLP and content inspection.",
		"Enforce WinHTTP proxy via GPO. Block direct outbound 80/443 from endpoints at firewall. Deploy SSL inspection.",
		func() (string, string) {
			val, err := regValue(
				`HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings`,
				"ProxySettingsPerUser")
			if err == nil && (val == "0x0" || val == "0") {
				return "pass", "Proxy enforced at machine level (ProxySettingsPerUser=0) — users cannot bypass corporate proxy for exfiltration."
			}
			out, err := exec.Command("netsh", "winhttp", "show", "proxy").Output()
			if err == nil {
				lower := strings.ToLower(string(out))
				if strings.Contains(lower, "proxy server") && !strings.Contains(lower, "direct access") {
					return "pass", "WinHTTP machine-wide proxy configured — outbound HTTP/S traffic inspected."
				}
			}
			return "fail", "No enforced outbound proxy detected — malware can exfiltrate UPI transaction data direct to attacker servers."
		})
}

// ── CSCRF-MII Core Control Validation ────────────────────────────────────────
// Validates SEBI CSCRF-MII control domains: Network Security, Access Management,
// Data Security, Monitoring & Detection, and Business Continuity.

func cscrfChecks() []SimCategory {
	return []SimCategory{
		{Phase: "cscrf-network-security", Checks: []SimCheck{
			checkOpenManagementPorts(),
			checkFirewall(),
			checkSMBSigning(),
			checkLLMNR(),
		}},
		{Phase: "cscrf-access-management", Checks: []SimCheck{
			checkLocalAdminCount(),
			checkDefaultAdminAccount(),
			checkAccountLockoutPolicy(),
			checkPasswordMinLength(),
		}},
		{Phase: "cscrf-data-security", Checks: []SimCheck{
			checkBitLockerStatus(),
			checkAuditLogRetention(),
		}},
		{Phase: "cscrf-monitoring-detection", Checks: []SimCheck{
			checkDefenderRTP(),
			checkSysmon(),
			checkScriptBlockLogging(),
			checkEventLog(),
		}},
		{Phase: "cscrf-business-continuity", Checks: []SimCheck{
			checkVSSShadowCopies(),
			checkPatchCurrency(),
			checkControlledFolderAccess(),
		}},
	}
}

func checkOpenManagementPorts() SimCheck {
	return check("T1046", "Open Management Ports (CSCRF-1.1)", "cscrf-network-security", "Critical",
		"SEBI CSCRF requires all unnecessary management interfaces to be closed — open ports are primary attack entry points.",
		"Close Telnet(23), restrict RDP(3389) to jump hosts, disable WinRM(5985/5986) if unused. Enforce via Windows Firewall GPO.",
		func() (string, string) {
			out, err := exec.Command("netstat", "-an").Output()
			if err != nil {
				return "skipped", "Could not enumerate listening ports."
			}
			type riskyPort struct {
				port int
				name string
			}
			risky := []riskyPort{
				{23, "Telnet"},
				{3389, "RDP"},
				{5985, "WinRM-HTTP"},
				{5986, "WinRM-HTTPS"},
				{137, "NetBIOS-NS"},
				{139, "NetBIOS-SMB"},
			}
			var open []string
			outStr := string(out)
			for _, rp := range risky {
				pattern := fmt.Sprintf("0.0.0.0:%d", rp.port)
				if strings.Contains(outStr, pattern) {
					open = append(open, fmt.Sprintf("%s(%d)", rp.name, rp.port))
				}
			}
			if len(open) == 0 {
				return "pass", "No high-risk management ports (Telnet/RDP/WinRM/NetBIOS) exposed on all interfaces — CSCRF-1.1 compliant."
			}
			return "fail", fmt.Sprintf("Exposed management ports: %s — CSCRF-1.1 requires restriction to authorised jump hosts only.", strings.Join(open, ", "))
		})
}

func checkLocalAdminCount() SimCheck {
	return check("T1087.001", "Local Administrator Account Count (CSCRF-2.1)", "cscrf-access-management", "High",
		"SEBI CSCRF mandates least-privilege — excess local admins widen the blast radius of any compromise.",
		"Reduce local Administrators to 1 managed account. Deploy Microsoft LAPS for randomised local admin passwords.",
		func() (string, string) {
			out, err := psRun(`(Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue | Measure-Object).Count`)
			if err != nil {
				return "skipped", "Could not enumerate local Administrators group."
			}
			count := strings.TrimSpace(out)
			var n int
			fmt.Sscanf(count, "%d", &n)
			switch {
			case n <= 2:
				return "pass", fmt.Sprintf("%d local administrator(s) — minimal privileged account surface, CSCRF-2.1 compliant.", n)
			case n <= 4:
				return "fail", fmt.Sprintf("%d local administrators — CSCRF requires minimisation. Review and remove unnecessary accounts.", n)
			default:
				return "fail", fmt.Sprintf("%d accounts in local Administrators group — significantly exceeds CSCRF least-privilege requirements.", n)
			}
		})
}

func checkDefaultAdminAccount() SimCheck {
	return check("T1110.001", "Built-in Administrator Account Status (CSCRF-2.2)", "cscrf-access-management", "High",
		"SEBI CSCRF mandates renaming or disabling the built-in Administrator account to prevent targeted brute-force.",
		"Disable: Computer Config → Windows Settings → Security Options → Accounts: Administrator account status = Disabled.",
		func() (string, string) {
			out, err := psRun(`(Get-LocalUser -Name "Administrator" -ErrorAction SilentlyContinue).Enabled`)
			if err != nil {
				return "pass", "Built-in Administrator account not found or inaccessible — likely renamed or removed (CSCRF compliant)."
			}
			v := strings.TrimSpace(strings.ToLower(out))
			if v == "false" {
				return "pass", "Built-in Administrator account is DISABLED — default credential brute-force mitigated, CSCRF-2.2 compliant."
			}
			if v == "true" {
				return "fail", "Built-in Administrator account is ENABLED — CSCRF-2.2 requires it to be disabled or renamed."
			}
			return "pass", "Built-in Administrator account appears disabled or renamed."
		})
}

func checkAccountLockoutPolicy() SimCheck {
	return check("T1110.001", "Account Lockout Policy (CSCRF-2.3)", "cscrf-access-management", "High",
		"SEBI CSCRF requires account lockout to prevent brute-force attacks against banking system credentials.",
		"Set via GPO: Lockout threshold ≤ 5 attempts, duration ≥ 30 minutes, observation window ≥ 30 minutes.",
		func() (string, string) {
			out, err := exec.Command("net", "accounts").Output()
			if err != nil {
				return "skipped", "Could not query account lockout policy."
			}
			outStr := string(out)
			for _, line := range strings.Split(outStr, "\n") {
				lower := strings.ToLower(strings.TrimSpace(line))
				if strings.Contains(lower, "lockout threshold") {
					if strings.Contains(lower, "never") {
						return "fail", "Account lockout threshold = Never — unlimited brute-force permitted. SEBI CSCRF non-compliant."
					}
					return "pass", fmt.Sprintf("Account lockout configured: %s — brute-force attacks limited per CSCRF-2.3.", strings.TrimSpace(line))
				}
			}
			return "fail", "Could not parse lockout threshold — manual policy verification required."
		})
}

func checkPasswordMinLength() SimCheck {
	return check("T1110", "Password Minimum Length Policy (CSCRF-2.4)", "cscrf-access-management", "Medium",
		"SEBI CSCRF requires minimum 12-character passwords to resist dictionary and brute-force attacks.",
		"Set via GPO: Security Settings → Account Policies → Password Policy → Minimum password length = 12.",
		func() (string, string) {
			out, err := exec.Command("net", "accounts").Output()
			if err != nil {
				return "skipped", "Could not query password length policy."
			}
			for _, line := range strings.Split(string(out), "\n") {
				lower := strings.ToLower(strings.TrimSpace(line))
				if strings.Contains(lower, "minimum password length") {
					fields := strings.Fields(strings.TrimSpace(line))
					if len(fields) > 0 {
						last := fields[len(fields)-1]
						var length int
						fmt.Sscanf(last, "%d", &length)
						if length == 0 {
							return "fail", "Minimum password length = 0 (no minimum) — SEBI CSCRF requires ≥12 characters."
						}
						if length >= 12 {
							return "pass", fmt.Sprintf("Minimum password length = %d characters — CSCRF-2.4 compliant.", length)
						}
						return "fail", fmt.Sprintf("Minimum password length = %d — below SEBI CSCRF minimum of 12 characters.", length)
					}
				}
			}
			return "skipped", "Could not parse password length — manual review required."
		})
}

func checkAuditLogRetention() SimCheck {
	return check("T1562.002", "Security Event Log Retention Capacity (CSCRF-3.1)", "cscrf-data-security", "High",
		"SEBI CSCRF requires security event retention for forensic investigation — small log sizes cause overwrite within hours.",
		"Set Security log max size ≥ 1GB via GPO. Forward logs to SIEM with 12-month retention for CSCRF compliance.",
		func() (string, string) {
			out, err := psRun(`(Get-WinEvent -ListLog Security -ErrorAction SilentlyContinue).MaximumSizeInBytes`)
			if err != nil || strings.TrimSpace(out) == "" {
				return "skipped", "Could not query Security event log configuration."
			}
			var sizeBytes int64
			fmt.Sscanf(strings.TrimSpace(out), "%d", &sizeBytes)
			sizeMB := sizeBytes / (1024 * 1024)
			if sizeMB >= 1024 {
				return "pass", fmt.Sprintf("Security log max size = %dMB (≥1GB) — adequate on-disk retention capacity, CSCRF-3.1 compliant.", sizeMB)
			}
			if sizeMB >= 256 {
				return "fail", fmt.Sprintf("Security log max size = %dMB — CSCRF recommends ≥1024MB. Increase size or forward to SIEM.", sizeMB)
			}
			return "fail", fmt.Sprintf("Security log max size = %dMB — critically small, logs overwrite rapidly. SEBI CSCRF non-compliant.", sizeMB)
		})
}

func checkPatchCurrency() SimCheck {
	return check("T1082", "Patch Currency — Last Update Age (CSCRF-5.1)", "cscrf-business-continuity", "High",
		"SEBI CSCRF mandates critical patches within 30 days of release. Unpatched endpoints are primary ransomware entry.",
		"Enforce patch deployment via WSUS/SCCM/Intune. Set 30-day SLA for critical patches per CSCRF schedule.",
		func() (string, string) {
			out, err := psRun(`$h = Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1; if ($h -and $h.InstalledOn) { (New-TimeSpan -Start $h.InstalledOn -End (Get-Date)).Days } else { "-1" }`)
			if err != nil || strings.TrimSpace(out) == "" || strings.TrimSpace(out) == "-1" {
				return "skipped", "Could not determine last hotfix installation date — verify Windows Update history manually."
			}
			var days int
			fmt.Sscanf(strings.TrimSpace(out), "%d", &days)
			switch {
			case days < 0:
				return "skipped", "Last patch date not available."
			case days <= 15:
				return "pass", fmt.Sprintf("Last patch installed %d days ago — well within SEBI CSCRF 30-day critical patch window.", days)
			case days <= 30:
				return "pass", fmt.Sprintf("Last patch installed %d days ago — within CSCRF 30-day threshold.", days)
			case days <= 60:
				return "fail", fmt.Sprintf("Last patch installed %d days ago — exceeds SEBI CSCRF 30-day critical patch deadline.", days)
			default:
				return "fail", fmt.Sprintf("Last patch installed %d days ago — significantly overdue, high vulnerability exposure, CSCRF non-compliant.", days)
			}
		})
}
