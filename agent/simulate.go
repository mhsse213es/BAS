package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// SimCategory is a group of related ATT&CK-aligned checks.
type SimCategory struct {
	Phase  string     `json:"phase"`
	Checks []SimCheck `json:"checks"`
}

// SimCheck is a single simulation result — matches orchestrator SimulationResult schema.
type SimCheck struct {
	ID           string    `json:"id"`
	Technique    Tech      `json:"technique"`
	Result       string    `json:"result"`       // pass | fail | skipped
	Severity     string    `json:"severity"`     // Critical | High | Medium | Low
	ThreatImpact string    `json:"threatImpact"`
	Details      string    `json:"details"`
	Remediation  string    `json:"remediation"`
	RawOutput    string    `json:"rawOutput,omitempty"`
	DurationMs   int64     `json:"durationMs"`
	ExecutedAt   time.Time `json:"executedAt"`
	Framework    string    `json:"framework"`
}

// Tech is a MITRE ATT&CK technique reference.
type Tech struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Tactic string `json:"tactic"`
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func checkID(techID, name string) string {
	h := sha256.Sum256([]byte(techID + name))
	return hex.EncodeToString(h[:])[:8]
}

// regValue reads a single Windows registry value using reg.exe.
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

// psRun runs a PowerShell command and returns trimmed stdout.
func psRun(cmd string) (string, error) {
	out, err := exec.Command("powershell",
		"-NoProfile", "-NonInteractive", "-Command", cmd).Output()
	return strings.TrimSpace(string(out)), err
}

// svcRunning returns true if the named Windows service is in RUNNING state.
func svcRunning(name string) bool {
	out, err := exec.Command("sc", "query", name).Output()
	return err == nil && strings.Contains(string(out), "RUNNING")
}

// check builds a SimCheck, runs fn(), and records timing.
func check(techID, name, tactic, severity, threat, fix string,
	fn func() (result, details string)) SimCheck {

	start := time.Now()
	result, details := fn()
	return SimCheck{
		ID:           checkID(techID, name),
		Technique:    Tech{ID: techID, Name: name, Tactic: tactic},
		Result:       result,
		Severity:     severity,
		ThreatImpact: threat,
		Details:      details,
		Remediation:  fix,
		DurationMs:   time.Since(start).Milliseconds(),
		ExecutedAt:   time.Now(),
		Framework:    "custom",
	}
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
			// First check if RDP is even enabled
			deny, err := regValue(
				`HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server`,
				"fDenyTSConnections")
			if err == nil && (deny == "0x1" || deny == "1") {
				return "pass", "RDP is disabled — no RDP attack surface exposed."
			}
			// RDP enabled — check NLA
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
