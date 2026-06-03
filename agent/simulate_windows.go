//go:build windows

package main

import (
	"fmt"
	"os/exec"
	"strings"
)

// ── Windows Helpers ───────────────────────────────────────────────────────────

func regValue(keyPath, valueName string) (string, error) {
	out, err := exec.Command("reg", "query", keyPath, "/v", valueName).Output()
	if err != nil {
		return "", fmt.Errorf("reg query: %w", err)
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.Contains(strings.ToLower(line), strings.ToLower(valueName)) {
			parts := strings.Fields(line)
			if len(parts) >= 3 {
				return parts[len(parts)-1], nil
			}
		}
	}
	return "", fmt.Errorf("%s not found in %s", valueName, keyPath)
}

func psRun(cmd string) (string, error) {
	out, err := exec.Command("powershell",
		"-NoProfile", "-NonInteractive", "-Command", cmd).Output()
	return strings.TrimSpace(string(out)), err
}

func svcRunning(name string) bool {
	out, err := exec.Command("sc", "query", name).Output()
	return err == nil && strings.Contains(string(out), "RUNNING")
}

// ── All Checks Entry Point ────────────────────────────────────────────────────

func RunAllChecks() []SimCategory {
	return []SimCategory{
		credentialAccess(),
		defenseEvasion(),
		executionControls(),
		persistenceChecks(),
		privEscChecks(),
		networkControls(),
	}
}

// ── Scenario Checks Entry Point ───────────────────────────────────────────────

func RunScenarioChecks(scenarioID string) []SimCategory {
	switch scenarioID {
	case "safe-simulation":
		return safeSimChecks()
	case "apt36-spearphish":
		return apt36Checks()
	case "apt36-kill-chain":
		return apt36KillChainChecks()
	case "ransomware-drill":
		return ransomwareDrillChecks()
	case "ad-credential-access":
		return adCredentialChecks()
	case "upi-fraud-killchain":
		return upiFraudChecks()
	case "cscrf-mii-drill":
		return cscrfChecks()
	case "purplesharp-ad-drill":
		return purpleSharpADChecks()
	case "lolbin-execution":
		return lolbinPostureChecks()
	default:
		return RunAllChecks()
	}
}

// lolbinPostureChecks is the POSTURE side of the LOLBin drill — read-only
// validation of the controls that detect or restrict living-off-the-land
// binary abuse (the live mode actually executes the LOLBins).
func lolbinPostureChecks() []SimCategory {
	return []SimCategory{
		{Phase: "execution-controls", Checks: []SimCheck{
			checkAppLocker(),
			checkPSExecutionPolicy(),
			checkPSv2(),
			checkWinRM(),
		}},
		{Phase: "detection-logging", Checks: []SimCheck{
			checkScriptBlockLogging(),
			checkSysmon(),
		}},
	}
}

// purpleSharpADChecks is the POSTURE side of the PurpleSharp AD drill — it
// validates the defences against the three techniques the live scenario runs
// (Password Spraying, Kerberoasting, LSASS dumping). Read-only; no changes.
func purpleSharpADChecks() []SimCategory {
	return []SimCategory{
		{Phase: "credential-access", Checks: []SimCheck{
			checkLSAProtection(),         // vs LSASS dump (T1003.001)
			checkWDigest(),               // vs plaintext creds in LSASS
			checkCredentialGuard(),       // vs LSASS dump
			checkLSASSAuditPolicy(),      // detection of LSASS access
			checkKerberosAESEncryption(), // vs Kerberoasting RC4 (T1558.003)
		}},
		{Phase: "credential-access-policy", Checks: []SimCheck{
			checkAccountLockoutPolicy(), // vs Password Spraying (T1110.003)
		}},
	}
}

// safeSimChecks is the cross-platform safe simulation — a comprehensive,
// read-only superset covering the full kill chain plus data-protection,
// account-security, and monitoring categories. All checks compose existing
// read-only functions; nothing on the endpoint is modified.
func safeSimChecks() []SimCategory {
	return []SimCategory{
		credentialAccess(),
		defenseEvasion(),
		executionControls(),
		persistenceChecks(),
		privEscChecks(),
		networkControls(),
		{Phase: "collection", Checks: []SimCheck{
			checkClipboardHistoryPolicy(),
			checkScreenCaptureASR(),
		}},
		{Phase: "impact", Checks: []SimCheck{
			checkBitLockerStatus(),
			checkVSSShadowCopies(),
			checkControlledFolderAccess(),
		}},
		{Phase: "account-security", Checks: []SimCheck{
			checkAccountLockoutPolicy(),
			checkPasswordMinLength(),
			checkLocalAdminCount(),
			checkDefaultAdminAccount(),
		}},
		{Phase: "monitoring", Checks: []SimCheck{
			checkAuditLogRetention(),
			checkPatchCurrency(),
		}},
	}
}

// ── Credential Access ─────────────────────────────────────────────────────────

func credentialAccess() SimCategory {
	return SimCategory{Phase: "credential-access", Checks: []SimCheck{
		checkLSAProtection(),
		checkWDigest(),
		checkCredentialGuard(),
		checkNTLMRestrictions(),
		checkAutoLogon(),
	}}
}

func checkLSAProtection() SimCheck {
	return check("T1003.001", "LSA Protection (RunAsPPL)", "credential-access", "Critical",
		"Attackers dump credentials from LSASS memory (Mimikatz) to obtain hashes and plaintext passwords.",
		"Set HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\RunAsPPL = 1 and reboot.",
		func() (string, string) {
			val, err := regValue(`HKLM\SYSTEM\CurrentControlSet\Control\Lsa`, "RunAsPPL")
			if err != nil {
				return "fail", "RunAsPPL not set — LSASS process is unprotected against credential dumping."
			}
			if val == "0x1" || val == "1" || val == "0x2" || val == "2" {
				return "pass", fmt.Sprintf("RunAsPPL = %s — LSASS is protected.", val)
			}
			return "fail", fmt.Sprintf("RunAsPPL = %s (expected 1) — LSASS unprotected.", val)
		})
}

func checkWDigest() SimCheck {
	return check("T1003.001", "WDigest Plaintext Credentials", "credential-access", "Critical",
		"WDigest stores plaintext credentials in memory; Mimikatz can read them from LSASS.",
		"Set HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest\\UseLogonCredential = 0.",
		func() (string, string) {
			val, err := regValue(
				`HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest`,
				"UseLogonCredential")
			if err != nil {
				return "pass", "UseLogonCredential key absent — WDigest disabled by default (Windows 8.1+)."
			}
			if val == "0x0" || val == "0" {
				return "pass", "WDigest UseLogonCredential = 0 — plaintext credentials not cached."
			}
			return "fail", fmt.Sprintf("WDigest UseLogonCredential = %s — plaintext credentials are cached in LSASS.", val)
		})
}

func checkCredentialGuard() SimCheck {
	return check("T1003.001", "Windows Credential Guard", "credential-access", "High",
		"Without Credential Guard, domain credentials are accessible via LSASS memory dumps.",
		"Enable Credential Guard via Group Policy: Computer Config → Device Guard → Credential Guard.",
		func() (string, string) {
			val, err := regValue(
				`HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard`,
				"EnableVirtualizationBasedSecurity")
			if err != nil {
				return "fail", "VBS not configured — Credential Guard unavailable."
			}
			if val == "0x1" || val == "1" {
				return "pass", "Virtualization Based Security enabled — Credential Guard can be active."
			}
			return "fail", fmt.Sprintf("EnableVirtualizationBasedSecurity = %s — Credential Guard not enabled.", val)
		})
}

func checkNTLMRestrictions() SimCheck {
	return check("T1558.004", "NTLM Relay Restrictions", "credential-access", "High",
		"Unrestricted NTLM allows relay attacks to authenticate as domain users without knowing passwords.",
		"Configure HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\RestrictNTLMInDomain and enable EPA.",
		func() (string, string) {
			val, err := regValue(`HKLM\SYSTEM\CurrentControlSet\Control\Lsa`, "RestrictNTLM")
			if err != nil {
				return "fail", "RestrictNTLM not configured — NTLM relay attacks not prevented."
			}
			if val == "0x2" || val == "2" {
				return "pass", "RestrictNTLM = 2 — outbound NTLM authentication denied."
			}
			return "fail", fmt.Sprintf("RestrictNTLM = %s (need 2) — NTLM relay not fully blocked.", val)
		})
}

func checkAutoLogon() SimCheck {
	return check("T1552.002", "AutoLogon Credentials in Registry", "credential-access", "Critical",
		"AutoLogon stores credentials in plaintext in the registry, readable by any local process.",
		"Disable AutoLogon: clear HKLM\\...\\Winlogon\\AutoAdminLogon and DefaultPassword.",
		func() (string, string) {
			val, err := regValue(
				`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`,
				"AutoAdminLogon")
			if err != nil || val == "0" || val == "0x0" {
				return "pass", "AutoLogon disabled — no plaintext credentials stored in registry."
			}
			return "fail", "AutoAdminLogon is ENABLED — plaintext credentials may be stored in Winlogon registry key."
		})
}

// ── Defense Evasion ───────────────────────────────────────────────────────────

func defenseEvasion() SimCategory {
	return SimCategory{Phase: "defense-evasion", Checks: []SimCheck{
		checkDefenderRTP(),
		checkDefenderTamperProtection(),
		checkEventLog(),
		checkScriptBlockLogging(),
		checkSysmon(),
	}}
}

func checkDefenderRTP() SimCheck {
	return check("T1562.001", "Windows Defender Real-Time Protection", "defense-evasion", "High",
		"Disabled AV/EDR allows malware to execute, persist, and exfiltrate data undetected.",
		"Enable Defender Real-Time Protection: Settings → Windows Security → Virus & Threat Protection.",
		func() (string, string) {
			out, err := psRun("(Get-MpComputerStatus).RealTimeProtectionEnabled")
			if err != nil {
				return "skipped", "Could not query Defender status — requires admin or WMI access."
			}
			if strings.EqualFold(out, "True") {
				return "pass", "Windows Defender Real-Time Protection is enabled."
			}
			return "fail", "Windows Defender Real-Time Protection is DISABLED — endpoint unprotected."
		})
}

func checkDefenderTamperProtection() SimCheck {
	return check("T1562.001", "Defender Tamper Protection", "defense-evasion", "High",
		"Without tamper protection, attackers disable Defender via registry or API to evade detection.",
		"Enable Tamper Protection: Windows Security → Virus & Threat Protection Settings → Tamper Protection ON.",
		func() (string, string) {
			out, err := psRun("(Get-MpComputerStatus).IsTamperProtected")
			if err != nil {
				return "skipped", "Could not query Defender tamper protection status."
			}
			if strings.EqualFold(out, "True") {
				return "pass", "Defender Tamper Protection is enabled — AV settings are locked."
			}
			return "fail", "Defender Tamper Protection is DISABLED — AV can be turned off by attackers."
		})
}

func checkEventLog() SimCheck {
	return check("T1070.001", "Windows Event Log Service", "defense-evasion", "High",
		"Stopping Event Log lets attackers erase their tracks — no audit trail remains.",
		"Ensure EventLog service is locked against non-admin stops. Forward logs to SIEM.",
		func() (string, string) {
			if svcRunning("eventlog") {
				return "pass", "Windows EventLog service is running — audit trail active."
			}
			return "fail", "Windows EventLog service NOT running — logging is inactive."
		})
}

func checkScriptBlockLogging() SimCheck {
	return check("T1059.001", "PowerShell Script Block Logging", "defense-evasion", "High",
		"Without Script Block Logging, malicious PowerShell is executed and exfiltrated unlogged.",
		"Enable via GPO: Computer Config → PS → Script Block Logging → Enabled.",
		func() (string, string) {
			val, err := regValue(
				`HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging`,
				"EnableScriptBlockLogging")
			if err != nil {
				return "fail", "Script Block Logging not configured — PowerShell attack activity not logged to Event ID 4104."
			}
			if val == "0x1" || val == "1" {
				return "pass", "PowerShell Script Block Logging enabled — all scripts logged to Event ID 4104."
			}
			return "fail", fmt.Sprintf("Script Block Logging = %s — PowerShell not fully logged.", val)
		})
}

func checkSysmon() SimCheck {
	return check("T1562.001", "Sysmon Endpoint Monitoring", "defense-evasion", "Medium",
		"Without Sysmon, process injection, network connections, and file drops are not logged.",
		"Deploy Sysmon with SwiftOnSecurity or Olaf config on all endpoints.",
		func() (string, string) {
			if svcRunning("Sysmon64") {
				return "pass", "Sysmon64 running — advanced endpoint telemetry active."
			}
			if svcRunning("Sysmon") {
				return "pass", "Sysmon running — advanced endpoint telemetry active."
			}
			return "fail", "Sysmon not installed — limited endpoint visibility for threat hunting."
		})
}

// ── Execution Controls ────────────────────────────────────────────────────────

func executionControls() SimCategory {
	return SimCategory{Phase: "execution", Checks: []SimCheck{
		checkPSExecutionPolicy(),
		checkPSv2(),
		checkAppLocker(),
		checkWinRM(),
	}}
}

func checkPSExecutionPolicy() SimCheck {
	return check("T1059.001", "PowerShell Execution Policy", "execution", "High",
		"Unrestricted policy allows attackers to run arbitrary downloaded PowerShell scripts.",
		"Set ExecutionPolicy to AllSigned via GPO for high-security environments.",
		func() (string, string) {
			val, err := regValue(
				`HKLM\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell`,
				"ExecutionPolicy")
			if err != nil {
				val, err = regValue(
					`HKCU\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell`,
					"ExecutionPolicy")
			}
			if err != nil {
				return "fail", "Execution policy not set via registry — scripts can run unrestricted."
			}
			policy := strings.Trim(strings.ToLower(val), `"`)
			switch policy {
			case "allsigned":
				return "pass", "PowerShell execution policy: AllSigned — only signed scripts permitted."
			case "remotesigned":
				return "pass", "PowerShell execution policy: RemoteSigned — remote scripts must be signed."
			case "restricted":
				return "pass", "PowerShell execution policy: Restricted — no scripts allowed."
			default:
				return "fail", fmt.Sprintf("PowerShell execution policy: %s — unsigned scripts can run freely.", val)
			}
		})
}

func checkPSv2() SimCheck {
	return check("T1059.001", "PowerShell v2 Disabled", "execution", "Medium",
		"PowerShell v2 bypasses AMSI and logging — used as downgrade attack vector.",
		"Run: Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root",
		func() (string, string) {
			out, err := psRun("(Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2).State 2>$null")
			if err != nil || out == "" {
				return "skipped", "Could not query PowerShell v2 feature state."
			}
			if strings.Contains(strings.ToLower(out), "disabled") {
				return "pass", "PowerShell v2 is disabled — downgrade-to-bypass attacks blocked."
			}
			return "fail", "PowerShell v2 is ENABLED — attackers can use 'powershell -version 2' to bypass AMSI/logging."
		})
}

func checkAppLocker() SimCheck {
	return check("T1059", "Application Control (AppLocker/WDAC)", "execution", "High",
		"Without application control, attackers run arbitrary executables and scripts.",
		"Configure AppLocker or WDAC to allow-list approved applications only.",
		func() (string, string) {
			if svcRunning("AppIDSvc") {
				return "pass", "AppLocker Application Identity service running — application control active."
			}
			out, err := psRun("Get-AppLockerPolicy -Effective -Xml 2>$null | Measure-Object | Select-Object -ExpandProperty Count")
			if err == nil && strings.TrimSpace(out) != "0" && out != "" {
				return "pass", "AppLocker effective policy found."
			}
			return "fail", "No AppLocker/WDAC policy detected — arbitrary code execution possible."
		})
}

func checkWinRM() SimCheck {
	return check("T1021.006", "WinRM Remote Execution Surface", "execution", "High",
		"Running WinRM allows lateral movement via PowerShell remoting from any network attacker.",
		"Disable if not needed: Stop-Service WinRM; Set-Service WinRM -StartupType Disabled.",
		func() (string, string) {
			if svcRunning("WinRM") {
				return "fail", "WinRM service is RUNNING — remote PowerShell execution enabled. Verify this is required."
			}
			return "pass", "WinRM service is not running — remote PS execution surface minimised."
		})
}

// ── Persistence ───────────────────────────────────────────────────────────────

func persistenceChecks() SimCategory {
	return SimCategory{Phase: "persistence", Checks: []SimCheck{
		checkRunKeys(),
		checkStartupFolder(),
		checkScheduledTasks(),
		checkServicesIntegrity(),
	}}
}

func checkRunKeys() SimCheck {
	return check("T1547.001", "Run Registry Key Inspection", "persistence", "High",
		"Attackers add entries to Run keys to persist malware across reboots.",
		"Audit HKLM\\...\\CurrentVersion\\Run entries. Use Autoruns (Sysinternals) regularly.",
		func() (string, string) {
			out, err := exec.Command("reg", "query",
				`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`).Output()
			if err != nil {
				return "skipped", "Could not query HKLM Run key."
			}
			lines := strings.Split(string(out), "\n")
			var entries []string
			for _, l := range lines {
				l = strings.TrimSpace(l)
				if l != "" && !strings.HasPrefix(l, "HKEY") {
					entries = append(entries, l)
				}
			}
			return "pass", fmt.Sprintf("HKLM Run key: %d entry/entries found — review any unknown entries.", len(entries))
		})
}

func checkStartupFolder() SimCheck {
	return check("T1547.001", "Startup Folder Contents", "persistence", "Medium",
		"Files in startup folders execute on every user login — simple persistence mechanism.",
		"Audit startup folders. Use WDAC to restrict what can execute from startup paths.",
		func() (string, string) {
			out, err := psRun(`(Get-ChildItem "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup" -File -ErrorAction SilentlyContinue | Measure-Object).Count`)
			if err != nil {
				return "skipped", "Could not enumerate startup folder."
			}
			count := strings.TrimSpace(out)
			if count == "0" || count == "" {
				return "pass", "User Startup folder empty — no startup persistence items found."
			}
			return "pass", fmt.Sprintf("Startup folder has %s item(s) — verify all are legitimate.", count)
		})
}

func checkScheduledTasks() SimCheck {
	return check("T1053.005", "Scheduled Task Audit", "persistence", "High",
		"Attackers create scheduled tasks to run malicious code at login, boot, or intervals.",
		"Run 'schtasks /query' regularly. Use Autoruns to identify unknown tasks.",
		func() (string, string) {
			out, err := exec.Command("schtasks", "/query", "/fo", "CSV", "/nh").Output()
			if err != nil {
				return "skipped", "Could not enumerate scheduled tasks."
			}
			count := 0
			for _, l := range strings.Split(string(out), "\n") {
				if strings.TrimSpace(l) != "" {
					count++
				}
			}
			return "pass", fmt.Sprintf("%d scheduled tasks found — audit any recently added or unknown tasks.", count)
		})
}

func checkServicesIntegrity() SimCheck {
	return check("T1543.003", "Service Binary Path Inspection", "persistence", "High",
		"Attackers plant malicious services or hijack writable service binaries for persistence.",
		"Audit services with non-standard binary paths. Restrict write permissions on service directories.",
		func() (string, string) {
			out, err := psRun(`Get-WmiObject Win32_Service | Where-Object {$_.PathName -notlike "*system32*" -and $_.PathName -notlike "*SysWOW64*" -and $_.State -eq "Running"} | Measure-Object | Select-Object -ExpandProperty Count`)
			if err != nil {
				return "skipped", "Could not enumerate non-system services."
			}
			count := strings.TrimSpace(out)
			if count == "0" || count == "" {
				return "pass", "All running services use standard system paths."
			}
			return "pass", fmt.Sprintf("%s service(s) running from non-system paths — verify all are legitimate.", count)
		})
}

// ── Privilege Escalation ──────────────────────────────────────────────────────

func privEscChecks() SimCategory {
	return SimCategory{Phase: "privilege-escalation", Checks: []SimCheck{
		checkUACEnabled(),
		checkUACLevel(),
		checkLocalAdminTokenFilter(),
		checkAlwaysInstallElevated(),
	}}
}

func checkUACEnabled() SimCheck {
	return check("T1548.002", "UAC Enabled", "privilege-escalation", "Critical",
		"Disabled UAC allows any process to silently elevate to Administrator without user consent.",
		"Enable UAC: HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\EnableLUA = 1.",
		func() (string, string) {
			val, err := regValue(
				`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`,
				"EnableLUA")
			if err != nil {
				return "fail", "Could not read EnableLUA — UAC state unknown."
			}
			if val == "0x1" || val == "1" {
				return "pass", "UAC is enabled (EnableLUA = 1)."
			}
			return "fail", "UAC is DISABLED — privilege escalation requires no user consent."
		})
}

func checkUACLevel() SimCheck {
	return check("T1548.002", "UAC Prompt Level", "privilege-escalation", "High",
		"Low UAC level allows silent elevation, enabling UAC bypass techniques.",
		"Set ConsentPromptBehaviorAdmin = 2 (prompt for credentials) for strongest protection.",
		func() (string, string) {
			val, err := regValue(
				`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`,
				"ConsentPromptBehaviorAdmin")
			if err != nil {
				return "skipped", "Could not read ConsentPromptBehaviorAdmin."
			}
			switch val {
			case "0x2", "2":
				return "pass", "UAC level: Prompt for credentials on secure desktop — maximum protection."
			case "0x5", "5":
				return "pass", "UAC level: Prompt for consent on secure desktop — standard protection."
			case "0x0", "0":
				return "fail", "UAC set to 'Elevate without prompting' — silent elevation allowed."
			default:
				return "fail", fmt.Sprintf("UAC ConsentPromptBehaviorAdmin = %s — verify this is appropriate.", val)
			}
		})
}

func checkLocalAdminTokenFilter() SimCheck {
	return check("T1548.002", "Remote UAC Token Filtering", "privilege-escalation", "High",
		"LocalAccountTokenFilterPolicy = 1 allows remote admin with full token — enables pass-the-hash.",
		"Ensure LocalAccountTokenFilterPolicy = 0 (default) to filter remote admin tokens.",
		func() (string, string) {
			val, err := regValue(
				`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`,
				"LocalAccountTokenFilterPolicy")
			if err != nil {
				return "pass", "LocalAccountTokenFilterPolicy not set — default (0) applies, remote admin tokens filtered."
			}
			if val == "0x0" || val == "0" {
				return "pass", "LocalAccountTokenFilterPolicy = 0 — remote admin tokens filtered (pass-the-hash limited)."
			}
			return "fail", "LocalAccountTokenFilterPolicy = 1 — remote admin unfiltered, pass-the-hash risk elevated."
		})
}

func checkAlwaysInstallElevated() SimCheck {
	return check("T1548.002", "AlwaysInstallElevated MSI Policy", "privilege-escalation", "Critical",
		"AlwaysInstallElevated lets any user install MSI packages as SYSTEM — trivial privesc.",
		"Ensure AlwaysInstallElevated = 0 in both HKLM and HKCU. Never enable this policy.",
		func() (string, string) {
			val1, _ := regValue(`HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer`, "AlwaysInstallElevated")
			val2, _ := regValue(`HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer`, "AlwaysInstallElevated")
			if (val1 == "0x1" || val1 == "1") && (val2 == "0x1" || val2 == "1") {
				return "fail", "AlwaysInstallElevated enabled in HKLM and HKCU — any user can escalate to SYSTEM via MSI."
			}
			return "pass", "AlwaysInstallElevated not enabled — MSI privilege escalation path blocked."
		})
}

// ── Network / Lateral Movement ────────────────────────────────────────────────

func networkControls() SimCategory {
	return SimCategory{Phase: "lateral-movement", Checks: []SimCheck{
		checkSMBSigning(),
		checkRDPNLA(),
		checkFirewall(),
		checkLLMNR(),
	}}
}

func checkSMBSigning() SimCheck {
	return check("T1021.002", "SMB Signing Required", "lateral-movement", "High",
		"Without SMB signing, relay attacks can authenticate as other users across the network.",
		"Set HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters\\RequireSecuritySignature = 1.",
		func() (string, string) {
			val, err := regValue(
				`HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters`,
				"RequireSecuritySignature")
			if err != nil {
				return "fail", "SMB RequireSecuritySignature not configured — SMB relay attacks possible."
			}
			if val == "0x1" || val == "1" {
				return "pass", "SMB signing required — relay attacks against this host are blocked."
			}
			return "fail", fmt.Sprintf("RequireSecuritySignature = %s — SMB relay attacks possible.", val)
		})
}

func checkRDPNLA() SimCheck {
	return check("T1021.001", "RDP Network Level Authentication", "lateral-movement", "High",
		"RDP without NLA exposes the login screen before authentication — enables pre-auth exploitation.",
		"Enable NLA: HKLM\\...\\RDP-Tcp\\UserAuthentication = 1, or via System Properties → Remote.",
		func() (string, string) {
			deny, err := regValue(
				`HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server`,
				"fDenyTSConnections")
			if err == nil && (deny == "0x1" || deny == "1") {
				return "pass", "RDP is disabled — no RDP attack surface exposed."
			}
			val, err := regValue(
				`HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp`,
				"UserAuthentication")
			if err != nil {
				return "fail", "RDP appears enabled but NLA setting could not be verified."
			}
			if val == "0x1" || val == "1" {
				return "pass", "RDP NLA (Network Level Authentication) is enabled."
			}
			return "fail", "RDP is enabled WITHOUT NLA — pre-authentication attack surface exposed."
		})
}

func checkFirewall() SimCheck {
	return check("T1562.004", "Windows Firewall Active (All Profiles)", "lateral-movement", "High",
		"Disabled firewall removes network access control — unrestricted inbound connections allowed.",
		"Enable Windows Firewall on all profiles (Domain, Private, Public) via GPO.",
		func() (string, string) {
			out, err := psRun("(Get-NetFirewallProfile | Where-Object {$_.Enabled -eq $false} | Measure-Object).Count")
			if err != nil {
				return "skipped", "Could not query Windows Firewall profile status."
			}
			if strings.TrimSpace(out) == "0" {
				return "pass", "Windows Firewall enabled on all profiles (Domain, Private, Public)."
			}
			return "fail", fmt.Sprintf("%s firewall profile(s) disabled — network attack surface increased.", strings.TrimSpace(out))
		})
}

func checkLLMNR() SimCheck {
	return check("T1557.001", "LLMNR/NetBIOS Poisoning", "lateral-movement", "High",
		"LLMNR and NetBIOS can be poisoned (Responder) to capture NTLM hashes on local network.",
		"Disable LLMNR via GPO: Computer Config → DNS Client → Turn off multicast name resolution.",
		func() (string, string) {
			val, err := regValue(
				`HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient`,
				"EnableMulticast")
			if err == nil && (val == "0x0" || val == "0") {
				return "pass", "LLMNR disabled via GPO — network name poisoning attacks blocked."
			}
			return "fail", "LLMNR not disabled via GPO — susceptible to credential capture via Responder/Inveigh."
		})
}

// ── APT36 Spear-Phishing Kill Chain ──────────────────────────────────────────

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

// apt36KillChainChecks is the POSTURE side of the APT36 Kill Chain three-tier
// scenario. Categories are split by outcome so the UI can surface two distinct
// posture dimensions: prevention (attack blocked) and detection (attack visible).
func apt36KillChainChecks() []SimCategory {
	return []SimCategory{
		{Phase: "prevention-posture", Checks: []SimCheck{
			checkOfficeMacroBlocking(),
			checkProtectedViewInternetFiles(),
			checkMOTWProcessing(),
			checkOfficeChildProcessASR(),
			checkOfficeCOMAbuse(),
			checkMshtaExecControl(),
			checkWScriptControl(),
		}},
		{Phase: "detection-posture", Checks: []SimCheck{
			checkAMSIEnforcement(),
			checkScriptBlockLogging(),
			checkSysmon(),
			checkKeyloggerIndicators(),
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

func checkOfficeChildProcessASR() SimCheck {
	const ruleGUID = "D4F940AB-401B-4EFC-AADC-AD5F3C50688A"
	return check("T1566.001", "ASR Rule — Block Office Child Process Spawning", "prevention-posture", "Critical",
		"APT36 weaponised documents spawn cmd.exe/powershell.exe as Office child processes to execute CrimsonRAT. This ASR rule directly blocks that chain.",
		"Enable ASR rule D4F940AB-401B-4EFC-AADC-AD5F3C50688A via GPO (Block Office apps from creating child processes).",
		func() (string, string) {
			out, err := psRun(fmt.Sprintf(`(Get-MpPreference -ErrorAction SilentlyContinue).AttackSurfaceReductionRules_Ids | Where-Object {$_ -eq "%s"}`, ruleGUID))
			if err == nil && strings.TrimSpace(out) != "" {
				actionOut, err2 := psRun(fmt.Sprintf(
					`$ids = @((Get-MpPreference).AttackSurfaceReductionRules_Ids); $idx = [array]::IndexOf($ids, "%s"); if ($idx -ge 0) { @((Get-MpPreference).AttackSurfaceReductionRules_Actions)[$idx] }`,
					ruleGUID))
				if err2 == nil {
					switch strings.TrimSpace(actionOut) {
					case "1":
						return "pass", "ASR rule D4F940AB ENABLED — APT36 winword.exe→cmd.exe/powershell.exe child-process chain blocked."
					case "2":
						return "pass", "ASR rule D4F940AB AUDIT — detects but does not block APT36 Office child-process chain."
					}
				}
				return "pass", "ASR rule D4F940AB present — Office child process spawning restricted."
			}
			return "fail", "ASR rule D4F940AB not configured — Office can spawn cmd.exe/powershell.exe (APT36 initial access vector open)."
		})
}

func checkOfficeCOMAbuse() SimCheck {
	const ruleGUID = "3B576869-A4EC-4529-8536-B80A7769E899"
	return check("T1559.001", "ASR Rule — Block Win32 API Calls from Office Macros", "prevention-posture", "High",
		"APT36 uses Office COM automation (GetObject/CreateObject) to execute payloads without spawning a visible child process, evading process-chain detections.",
		"Enable ASR rule 3B576869-A4EC-4529-8536-B80A7769E899 via GPO (Block Win32 API calls from Office macros).",
		func() (string, string) {
			out, err := psRun(fmt.Sprintf(`(Get-MpPreference -ErrorAction SilentlyContinue).AttackSurfaceReductionRules_Ids | Where-Object {$_ -eq "%s"}`, ruleGUID))
			if err == nil && strings.TrimSpace(out) != "" {
				return "pass", "ASR rule 3B576869 (Block Win32 API calls from Office macros) enabled — COM/API abuse from Office macros restricted."
			}
			val, err2 := regValue(`HKLM\SOFTWARE\Microsoft\Ole`, "EnableDCOM")
			if err2 == nil && strings.EqualFold(val, "N") {
				return "pass", "DCOM disabled — Office COM-object lateral movement and GetObject/CreateObject abuse restricted."
			}
			return "fail", "ASR rule 3B576869 not configured — Office macros can invoke Win32 APIs and COM objects (APT36 GetObject/CreateObject vector open)."
		})
}

func checkAMSIEnforcement() SimCheck {
	return check("T1562.001", "AMSI Enforcement (Anti-Malware Scan Interface)", "detection-posture", "High",
		"APT36 PowerShell stagers and CrimsonRAT loaders use AMSI bypass techniques to evade real-time script scanning before initial execution.",
		"Ensure AmsiEnable≠0 in HKCU\\SOFTWARE\\Microsoft\\Windows Script\\Settings. Deploy EDR with AMSI provider integration.",
		func() (string, string) {
			val, err := regValue(`HKCU\SOFTWARE\Microsoft\Windows Script\Settings`, "AmsiEnable")
			if err == nil && (val == "0x0" || val == "0") {
				return "fail", "AMSI explicitly disabled via registry (AmsiEnable=0) — PowerShell and VBScript payload scanning bypassed."
			}
			out, err2 := psRun(`(Get-ChildItem "HKLM:\SOFTWARE\Microsoft\AMSI\Providers" -ErrorAction SilentlyContinue | Measure-Object).Count`)
			if err2 == nil {
				var n int
				fmt.Sscanf(strings.TrimSpace(out), "%d", &n)
				if n > 0 {
					return "pass", fmt.Sprintf("AMSI enabled with %d registered provider(s) — PowerShell, VBScript, and Office macro content scanned at runtime.", n)
				}
			}
			return "fail", "No AMSI providers registered — malicious PowerShell, VBScript, and Office macro payloads not scanned at execution."
		})
}

// ── Ransomware Drill (Three-Tier) ────────────────────────────────────────────

// ransomwareDrillChecks is the POSTURE side of the ransomware drill. Six
// categories surface both "Can we block?" (prevention) and "Can we recover?"
// (recovery-posture) independently — the distinction that matters most for
// BFSI BCP/DR reviews.
func ransomwareDrillChecks() []SimCategory {
	return []SimCategory{
		{Phase: "prevention-posture", Checks: []SimCheck{
			checkControlledFolderAccess(),
			checkAppLocker(),
			checkDefenderRTP(),
			checkDefenderTamperProtection(),
		}},
		{Phase: "detection-posture", Checks: []SimCheck{
			checkSysmon(),
			checkScriptBlockLogging(),
			checkEventLog(),
			checkAuditLogRetention(),
		}},
		{Phase: "backup-resilience", Checks: []SimCheck{
			checkVSSWriterHealth(),
			checkWindowsBackupPresence(),
			checkVSSServiceStatus(),
			checkBackupPrivSeparation(),
		}},
		{Phase: "identity-hardening", Checks: []SimCheck{
			checkLAPSDeployment(),
			checkRDPNLA(),
			checkLocalAdminCount(),
			checkPrivilegedLocalAccounts(),
		}},
		{Phase: "lateral-movement", Checks: []SimCheck{
			checkSMBSigning(),
			checkLLMNR(),
		}},
		{Phase: "recovery-posture", Checks: []SimCheck{
			checkVSSShadowCopies(),
			checkBCDEditRecovery(),
			checkBitLockerStatus(),
		}},
	}
}

func checkVSSWriterHealth() SimCheck {
	return check("T1490", "VSS Writer Health", "backup-resilience", "Critical",
		"Ransomware corrupts VSS writers before executing so that in-flight backups silently fail — recovery points are absent at the moment they are most needed.",
		"Run 'vssadmin list writers'. Repair any FAILED or TIMED OUT writers. Monitor VSS event log (Source: VSS) for writer failures.",
		func() (string, string) {
			out, err := exec.Command("vssadmin", "list", "writers").Output()
			if err != nil {
				return "skipped", "Could not query VSS writers — vssadmin not available or requires elevation."
			}
			lower := strings.ToLower(string(out))
			if strings.Contains(lower, "failed") || strings.Contains(lower, "timed out") {
				return "fail", "One or more VSS writers are in FAILED or TIMED OUT state — backup operations will silently fail before ransomware even executes."
			}
			count := strings.Count(lower, "writer name:")
			if count > 0 {
				return "pass", fmt.Sprintf("%d VSS writer(s) found, none in failed state — backup chain is intact.", count)
			}
			return "fail", "No VSS writers detected — VSS subsystem may not be functional."
		})
}

func checkWindowsBackupPresence() SimCheck {
	return check("T1490", "Backup Agent / Service Presence", "backup-resilience", "High",
		"Without any backup solution, ransomware recovery depends entirely on external systems. Absence of a local backup agent is a critical resilience gap.",
		"Deploy Windows Server Backup (wbadmin) or a supported third-party agent (Veeam, Acronis). Verify scheduled backup jobs run and complete successfully.",
		func() (string, string) {
			out, err := psRun(`Test-Path "$env:SystemRoot\System32\wbadmin.exe"`)
			if err == nil && strings.EqualFold(strings.TrimSpace(out), "True") {
				if svcRunning("sdrsvc") {
					return "pass", "Windows Server Backup (wbadmin.exe + sdrsvc service) installed and running — local backup capability active."
				}
				return "pass", "Windows Backup (wbadmin.exe) installed; sdrsvc not currently running — verify scheduled backup jobs are active."
			}
			for _, svc := range []string{"VeeamBackupSvc", "AcrSch2Svc", "AcronisAgent", "BackupExecAgentAccelerator"} {
				if svcRunning(svc) {
					return "pass", fmt.Sprintf("Third-party backup agent running (%s) — backup capability present.", svc)
				}
			}
			return "fail", "No backup service detected (Windows Backup or third-party agent) — ransomware recovery has no local backup path."
		})
}

func checkVSSServiceStatus() SimCheck {
	return check("T1490", "VSS Service Configuration", "backup-resilience", "Critical",
		"Ransomware disables the VSS service before executing to ensure no recovery snapshot can be created post-encryption.",
		"Set VSS service startup type to Automatic (Delayed). Alert on VSS service state change via Security EID 7036.",
		func() (string, string) {
			if !svcRunning("vss") {
				return "fail", "VSS (Volume Shadow Copy) service is NOT running — shadow copy creation is unavailable. Recovery snapshots cannot be created."
			}
			out, err := psRun(`(Get-Service -Name vss -ErrorAction SilentlyContinue).StartType`)
			if err == nil {
				st := strings.ToLower(strings.TrimSpace(out))
				if strings.Contains(st, "automatic") {
					return "pass", "VSS service running with Automatic startup — protected against simple service-disable attacks."
				}
				return "pass", fmt.Sprintf("VSS service running (StartType=%s) — operational but Automatic startup recommended for resilience.", strings.TrimSpace(out))
			}
			return "pass", "VSS service running — snapshot creation capability active."
		})
}

func checkBackupPrivSeparation() SimCheck {
	return check("T1490", "Backup Privilege Separation (SeBackupPrivilege)", "backup-resilience", "High",
		"If SeBackupPrivilege is held by broad admin groups, ransomware operators can read all files regardless of NTFS ACLs — enabling full data exfiltration before encryption.",
		"Restrict SeBackupPrivilege to a dedicated backup service account only (Computer Config → User Rights Assignment → Back up files and directories).",
		func() (string, string) {
			out, err := exec.Command("whoami", "/priv").Output()
			if err != nil {
				return "skipped", "Could not query current privileges."
			}
			lower := strings.ToLower(string(out))
			if strings.Contains(lower, "sebackupprivilege") && strings.Contains(lower, "enabled") {
				return "fail", "SeBackupPrivilege ENABLED for current session — this account can read all files regardless of ACLs (ransomware exfil vector active)."
			}
			if strings.Contains(lower, "sebackupprivilege") {
				return "pass", "SeBackupPrivilege present but disabled in current token — not immediately exploitable."
			}
			return "pass", "SeBackupPrivilege absent from current session — backup privilege exposure contained for this account."
		})
}

func checkLAPSDeployment() SimCheck {
	return check("T1550.002", "LAPS — Local Admin Password Uniqueness", "identity-hardening", "Critical",
		"Without LAPS, local administrator passwords are identical across all workstations — one compromised machine grants lateral movement to every endpoint at scale.",
		"Deploy Microsoft LAPS (legacy AdmPwd.dll) or Windows LAPS (built-in Windows 11/Server 2022+). Set rotation interval ≤ 30 days.",
		func() (string, string) {
			// Windows LAPS (built-in, Server 2022+/Win11 22H2+)
			val, err := regValue(`HKLM\SOFTWARE\Microsoft\Policies\LAPS`, "BackupDirectory")
			if err == nil && val != "0x0" && val != "0" {
				return "pass", "Windows LAPS configured (BackupDirectory set) — local admin passwords are unique and rotated per policy."
			}
			// Legacy LAPS (AdmPwd CSE)
			out, err2 := psRun(`Test-Path "C:\Program Files\LAPS\CSE\AdmPwd.dll"`)
			if err2 == nil && strings.EqualFold(strings.TrimSpace(out), "True") {
				return "pass", "Legacy Microsoft LAPS (AdmPwd.dll) detected — local admin passwords are managed and unique per machine."
			}
			// LAPS policy via registry (GPO push)
			_, err3 := regValue(`HKLM\SOFTWARE\Policies\Microsoft Services\AdmPwd`, "AdmPwdEnabled")
			if err3 == nil {
				return "pass", "LAPS AdmPwdEnabled policy key detected — local admin password management active."
			}
			return "fail", "LAPS not detected — local administrator passwords likely identical across workstations. Lateral movement via pass-the-hash scales to the entire estate."
		})
}

func checkPrivilegedLocalAccounts() SimCheck {
	return check("T1087.001", "Built-in Privileged Account Exposure", "identity-hardening", "High",
		"Ransomware operators use enabled built-in Administrator and Guest accounts as lateral movement anchors — default names with predictable or reused passwords.",
		"Disable built-in Administrator and Guest. Rename if policy requires. Use LAPS for any remaining local admin account.",
		func() (string, string) {
			adminOut, _ := psRun(`(Get-LocalUser -Name "Administrator" -ErrorAction SilentlyContinue).Enabled`)
			guestOut, _ := psRun(`(Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue).Enabled`)
			adminOn := strings.EqualFold(strings.TrimSpace(adminOut), "True")
			guestOn := strings.EqualFold(strings.TrimSpace(guestOut), "True")
			switch {
			case adminOn && guestOn:
				return "fail", "Built-in Administrator AND Guest accounts enabled — maximum default-account lateral-movement exposure for ransomware operators."
			case adminOn:
				return "fail", "Built-in Administrator account ENABLED — ransomware targets this for credential-stuffing and hash-reuse lateral spread."
			case guestOn:
				return "fail", "Guest account ENABLED — anonymous share access facilitated; ransomware reconnaissance and traversal easier."
			default:
				return "pass", "Built-in Administrator and Guest accounts disabled — default-account lateral movement vectors contained."
			}
		})
}

// ── Ransomware Drill (legacy — kept for shared-function reuse) ───────────────
// ransomwareChecks is the original posture-only set reused by safeSimChecks and
// the Linux/macOS simulate files. Windows "ransomware-drill" routes to
// ransomwareDrillChecks() above; this remains for cross-platform consistency.
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

// ── AD Credential Access Drill ────────────────────────────────────────────────

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

// ── UPI Fraud Kill Chain (Three-Tier) ────────────────────────────────────────

// upiFraudChecks is the POSTURE side of the UPI Fraud Kill Chain three-tier
// scenario. Six categories cover the full fraud stack including the browser and
// mobile attack surfaces unique to UPI/payment fraud.
func upiFraudChecks() []SimCategory {
	return []SimCategory{
		{Phase: "prevention-posture", Checks: []SimCheck{
			checkBrowserCredentialStorage(),
			checkAutoLogon(),
			checkAppLocker(),
			checkDefenderRTP(),
		}},
		{Phase: "detection-posture", Checks: []SimCheck{
			checkSysmon(),
			checkScriptBlockLogging(),
			checkDefenderTamperProtection(),
			checkKeyloggerIndicators(),
		}},
		{Phase: "payment-security", Checks: []SimCheck{
			checkDNSSecurityPolicy(),
			checkRootCertificateAudit(),
			checkOutboundProxyEnforcement(),
			checkScreenCaptureASR(),
		}},
		{Phase: "collection-exposure", Checks: []SimCheck{
			checkClipboardHistoryPolicy(),
			checkWDigest(),
			checkLLMNR(),
		}},
		{Phase: "browser-isolation", Checks: []SimCheck{
			checkSmartScreen(),
			checkBrowserExtensionPolicy(),
		}},
		{Phase: "mobile-linkage", Checks: []SimCheck{
			checkPhoneLinkDisabled(),
			checkCloudClipboard(),
		}},
	}
}

func checkSmartScreen() SimCheck {
	return check("T1566.001", "SmartScreen / Defender SmartScreen Enforcement", "browser-isolation", "High",
		"UPI phishing portals and fake banking apps bypass user warnings when SmartScreen is disabled — employees open credential-harvesting pages without any browser alert.",
		"Enable SmartScreen via GPO: Computer Config → Windows Components → File Explorer → Configure Windows Defender SmartScreen = Warn.",
		func() (string, string) {
			// Policy-enforced SmartScreen (all apps)
			val, err := regValue(`HKLM\SOFTWARE\Policies\Microsoft\Windows\System`, "EnableSmartScreen")
			if err == nil && (val == "0x1" || val == "1" || val == "0x2" || val == "2") {
				return "pass", fmt.Sprintf("SmartScreen enforced by policy (EnableSmartScreen=%s) — UPI phishing page warnings active.", val)
			}
			// Edge SmartScreen policy
			val2, err2 := regValue(`HKLM\SOFTWARE\Policies\Microsoft\Edge`, "SmartScreenEnabled")
			if err2 == nil {
				if val2 == "0x1" || val2 == "1" {
					return "pass", "Edge SmartScreen enabled via policy — banking phishing URLs blocked at browser level."
				}
				if val2 == "0x0" || val2 == "0" {
					return "fail", "Edge SmartScreen DISABLED by policy — UPI fraud phishing pages not filtered in Edge."
				}
			}
			// User-level SmartScreen (fallback)
			val3, _ := regValue(`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer`, "SmartScreenEnabled")
			switch strings.ToLower(strings.Trim(val3, `"`)) {
			case "requireadmin", "prompt":
				return "pass", fmt.Sprintf("SmartScreen = %s — fake banking portal warnings active.", val3)
			case "off", "0x0", "0":
				return "fail", "SmartScreen DISABLED — UPI phishing portals and fake banking apps open without any warning."
			}
			return "fail", "SmartScreen policy not configured — default browser protection against UPI phishing portals not verified."
		})
}

func checkBrowserExtensionPolicy() SimCheck {
	return check("T1176", "Browser Extension Allowlist / Blocklist Policy", "browser-isolation", "High",
		"Malicious browser extensions intercept OTPs, harvest UPI credentials, and silently modify payment page content without user awareness.",
		"Configure extension allowlisting via GPO: Chrome/Edge → Extensions → ExtensionInstallAllowlist or set ExtensionInstallBlocklist = *.",
		func() (string, string) {
			// Chrome allowlist
			_, err := regValue(`HKLM\SOFTWARE\Policies\Google\Chrome\ExtensionInstallAllowlist`, "1")
			if err == nil {
				return "pass", "Chrome ExtensionInstallAllowlist configured — only approved extensions permitted."
			}
			// Chrome blocklist = * (deny all except force-installed)
			val2, err2 := regValue(`HKLM\SOFTWARE\Policies\Google\Chrome`, "ExtensionInstallBlocklist")
			if err2 == nil && strings.Contains(val2, "*") {
				return "pass", "Chrome ExtensionInstallBlocklist = * — no unapproved extensions can install."
			}
			// Edge allowlist
			_, err3 := regValue(`HKLM\SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallAllowlist`, "1")
			if err3 == nil {
				return "pass", "Edge ExtensionInstallAllowlist configured — only approved extensions permitted."
			}
			// Edge blocklist
			val4, err4 := regValue(`HKLM\SOFTWARE\Policies\Microsoft\Edge`, "ExtensionInstallBlocklist")
			if err4 == nil && strings.Contains(val4, "*") {
				return "pass", "Edge ExtensionInstallBlocklist = * — unapproved extension installation blocked."
			}
			return "fail", "No browser extension allowlist or blocklist policy found — malicious payment-page hijacking extensions can be installed by users."
		})
}

func checkPhoneLinkDisabled() SimCheck {
	return check("T1111", "Phone Link OTP Relay Exposure", "mobile-linkage", "High",
		"Windows Phone Link (formerly 'Your Phone') relays SMS OTPs from mobile to desktop — UPI fraud malware reads OTP notifications without physical phone access.",
		"Disable Phone Link via GPO: set HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PhoneLink\\PhoneLinkEnabled = 0.",
		func() (string, string) {
			val, err := regValue(`HKLM\SOFTWARE\Policies\Microsoft\Windows\PhoneLink`, "PhoneLinkEnabled")
			if err == nil && (val == "0x0" || val == "0") {
				return "pass", "Phone Link disabled via policy — SMS OTP relay to desktop blocked."
			}
			out, err2 := psRun(`(Get-AppxPackage -Name "Microsoft.YourPhone" -ErrorAction SilentlyContinue) -ne $null`)
			if err2 == nil && strings.EqualFold(strings.TrimSpace(out), "True") {
				return "fail", "Phone Link (Microsoft.YourPhone) installed and not policy-restricted — SMS OTP relay to PC is possible. Restrict for BFSI compliance."
			}
			out2, _ := psRun(`(Get-AppxPackage -Name "MicrosoftCorporationII.PhoneLink" -ErrorAction SilentlyContinue) -ne $null`)
			if strings.EqualFold(strings.TrimSpace(out2), "True") {
				return "fail", "Phone Link (MicrosoftCorporationII.PhoneLink) installed — SMS OTP relay attack surface present."
			}
			return "pass", "Phone Link app not installed or restricted — SMS OTP relay surface removed."
		})
}

func checkCloudClipboard() SimCheck {
	return check("T1115", "Cloud Clipboard Sync (VPA/OTP Cross-Device Risk)", "mobile-linkage", "High",
		"Windows Cloud Clipboard syncs content across all signed-in devices — a copied UPI VPA or OTP is accessible from any compromised linked device.",
		"Disable via GPO: Computer Config → Windows Components → OS Policies → Allow Clipboard Sync Across Devices = Disabled.",
		func() (string, string) {
			// Machine-level cross-device clipboard
			val, err := regValue(`HKLM\SOFTWARE\Policies\Microsoft\Windows\System`, "AllowCrossDeviceClipboard")
			if err == nil && (val == "0x0" || val == "0") {
				return "pass", "Cross-device clipboard sync disabled by machine policy — UPI OTP/VPA clipboard interception across devices blocked."
			}
			// Check if cloud upload is enabled
			val2, err2 := regValue(`HKCU\SOFTWARE\Microsoft\Clipboard`, "CloudClipboardAutomaticUpload")
			if err2 == nil && (val2 == "0x1" || val2 == "1") {
				return "fail", "Cloud clipboard auto-upload ENABLED — copied UPI OTPs and VPAs may sync to other linked devices (cross-device OTP relay risk)."
			}
			val3, err3 := regValue(`HKCU\SOFTWARE\Microsoft\Clipboard`, "EnableClipboardHistory")
			if err3 == nil && (val3 == "0x1" || val3 == "1") {
				return "fail", "Clipboard history enabled without cross-device restriction — copied payment data persists and may sync."
			}
			return "fail", "Cloud clipboard cross-device sync not explicitly disabled by policy — UPI OTP/VPA interception surface not fully restricted."
		})
}

// ── UPI Fraud Kill Chain (legacy posture-only) ────────────────────────────────

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
