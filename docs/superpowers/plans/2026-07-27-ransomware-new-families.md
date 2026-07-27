# Ransomware Readiness Suite — New Family Content (Deliverable 2) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship 5 new builtin ransomware scenarios (BlackCat/ALPHV, Akira, Play, RansomHub, Cl0p) with structured `detection_profiles:` from day one, following the Deliverable 1 pattern and the canonical 8-phase stage taxonomy approved in the design spec.

**Architecture:** 4 new detection-profile YAML files (one per genuinely-new technique: BYOVD staging, AD discovery, security-process termination, RDP/NLA posture) plus 5 new scenario YAML files, each walking the canonical taxonomy and reusing ~9 already-shipped detection profiles and their proven command patterns. No Go code changes — same load-time validation and Provider Registry already handle new content correctly.

**Tech Stack:** YAML scenario/profile content, PowerShell (`executor: powershell`) steps, Go test (`internal/scenario` package) for the wiring-guard test.

## Global Constraints

- Every new detection profile uses `provider: microsoft_defender` — the only EDR-category provider whose registry default is `VerificationAutomatic` (spec: "Provider choice is deliberate, not decorative").
- Windows-only (`supported_os: [windows]`) — no Linux/ESXi content in this deliverable.
- No literal exploitation of real CVEs. Initial-access vectors tied to a specific vulnerability (Play's ProxyNotShell/FortiOS, Cl0p's MOVEit/GoAnywhere) are documented in `description:` only, never an executed step.
- No real driver loading, no real security-product process termination, no unrestricted VSS deletion — see each task's safety notes below.
- Every new/modified builtin file must be signed via `go run scripts/signer.go sign private_key.pem <path>` (run from `orchestrator/`) before it will load.
- `mitre_phases:` in each scenario lists only phases with a real executable step (matches `lockbit-kill-chain.yaml`'s existing convention).
- All new files are pure YAML content — no Go code changes in this plan.

---

## Task 1: New Detection Profiles

**Files:**
- Create: `scenarios/detection-profiles/windows_vulnerable_driver_load.yaml` (+ `.sig`)
- Create: `scenarios/detection-profiles/windows_ad_discovery.yaml` (+ `.sig`)
- Create: `scenarios/detection-profiles/windows_security_process_termination.yaml` (+ `.sig`)
- Create: `scenarios/detection-profiles/windows_rdp_nla_posture.yaml` (+ `.sig`)

**Interfaces:**
- Produces: 4 profile names (`windows_vulnerable_driver_load`, `windows_ad_discovery`, `windows_security_process_termination`, `windows_rdp_nla_posture`) that Tasks 2–5 reference via `detection_profiles:` entries.

- [ ] **Step 1: Create `windows_vulnerable_driver_load.yaml`**

```yaml
# Detection Validation Profile — vulnerable-driver (BYOVD) staging for EDR
# termination (T1562.001). RansomHub's EDRKillShifter tool (RentDrv2 /
# ThreatFireMonitor vulnerable drivers), also documented reused by Play and
# other ransomware groups per Halcyon reporting (2024).
profile: windows_vulnerable_driver_load
version: 1
expected_detection:
  - id: byovd-kernel-service-edr
    provider: microsoft_defender
    confidence: required
    finding:
      severity: Critical
      title: "Kernel-mode service registration (BYOVD precursor) not detected"
      remediation: >-
        Alert on `sc.exe create` / `New-Service` with `type= kernel` from a
        non-driver-installer process, and enforce Microsoft's vulnerable
        driver blocklist (HVCI / WDAC or the built-in
        Microsoft-recommended-driver-block-list). This is a near-zero-
        false-positive BYOVD staging IOC used by RansomHub's EDRKillShifter
        and multiple other ransomware EDR-killer tools to disable
        endpoint protection immediately before encryption.
      reference: "MITRE ATT&CK T1562.001 — Impair Defenses: Disable or Modify Tools (BYOVD)"
```

- [ ] **Step 2: Create `windows_ad_discovery.yaml`**

```yaml
# Detection Validation Profile — AdFind/Grixba-style Active Directory
# enumeration (T1087.002 / T1018). Documented recon pattern for BlackCat,
# Play (via Grixba), and RansomHub affiliates before credential theft and
# lateral movement.
profile: windows_ad_discovery
version: 1
expected_detection:
  - id: ad-discovery-edr
    provider: microsoft_defender
    confidence: recommended
    finding:
      severity: Medium
      title: "Domain account/group/controller enumeration not detected"
      remediation: >-
        Alert on `nltest.exe /dclist`, `net group "Domain Admins" /domain`,
        and `net view` chained together from a single host in a short
        window — a common pre-credential-theft recon pattern that does not
        require the AdFind binary and can be performed entirely with
        built-in LOLBins.
      reference: "MITRE ATT&CK T1087.002 — Account Discovery: Domain Account"
```

- [ ] **Step 3: Create `windows_security_process_termination.yaml`**

```yaml
# Detection Validation Profile — security-process termination via taskkill
# (T1562.001). Cl0p's classic encryptor targets specific AV/EDR process
# names by image name before encrypting.
profile: windows_security_process_termination
version: 1
expected_detection:
  - id: security-process-taskkill-edr
    provider: microsoft_defender
    confidence: required
    finding:
      severity: Critical
      title: "taskkill targeting security-product process names not detected"
      remediation: >-
        Alert on `taskkill.exe /F /IM` (or `Stop-Process`) invoked with an
        AV/EDR-associated process image name as its argument, independent
        of whether the named process actually exists on the host — the
        command-line pattern itself is the high-fidelity signal Cl0p's
        encryptor produces immediately before deploying.
      reference: "MITRE ATT&CK T1562.001 — Impair Defenses: Disable or Modify Tools"
```

- [ ] **Step 4: Create `windows_rdp_nla_posture.yaml`**

```yaml
# Detection Validation Profile — RDP enabled without Network Level
# Authentication (T1021.001). Akira's documented initial-access
# precondition: brute-forceable/credential-stuffable RDP or VPN without MFA.
profile: windows_rdp_nla_posture
version: 1
expected_detection:
  - id: rdp-nla-posture-edr
    provider: microsoft_defender
    confidence: recommended
    finding:
      severity: High
      title: "RDP enabled without NLA enforcement"
      remediation: >-
        Enforce Network Level Authentication on every RDP-reachable
        endpoint and require MFA for RDP/VPN logon. Akira and multiple
        other ransomware affiliates use RDP/VPN access without MFA as
        their primary initial-access vector.
      reference: "MITRE ATT&CK T1021.001 — Remote Services: Remote Desktop Protocol"
```

- [ ] **Step 5: Validate all 4 files parse as valid YAML**

Run (from repo root):
```bash
python3 -c "
import yaml
for f in ['windows_vulnerable_driver_load','windows_ad_discovery','windows_security_process_termination','windows_rdp_nla_posture']:
    yaml.safe_load(open(f'scenarios/detection-profiles/{f}.yaml'))
    print(f, 'OK')
"
```
Expected: `<name> OK` printed 4 times, no exceptions.

- [ ] **Step 6: Sign all 4 files**

From `orchestrator/`:
```bash
go run scripts/signer.go sign private_key.pem ../scenarios/detection-profiles/windows_vulnerable_driver_load.yaml
go run scripts/signer.go sign private_key.pem ../scenarios/detection-profiles/windows_ad_discovery.yaml
go run scripts/signer.go sign private_key.pem ../scenarios/detection-profiles/windows_security_process_termination.yaml
go run scripts/signer.go sign private_key.pem ../scenarios/detection-profiles/windows_rdp_nla_posture.yaml
```
Expected: each produces a `.sig` file alongside the `.yaml`, no errors.

- [ ] **Step 7: Commit**

```bash
git add scenarios/detection-profiles/windows_vulnerable_driver_load.yaml scenarios/detection-profiles/windows_vulnerable_driver_load.yaml.sig scenarios/detection-profiles/windows_ad_discovery.yaml scenarios/detection-profiles/windows_ad_discovery.yaml.sig scenarios/detection-profiles/windows_security_process_termination.yaml scenarios/detection-profiles/windows_security_process_termination.yaml.sig scenarios/detection-profiles/windows_rdp_nla_posture.yaml scenarios/detection-profiles/windows_rdp_nla_posture.yaml.sig
git commit -m "feat(scenarios): 4 new detection profiles for Ransomware Readiness Deliverable 2"
git push
```

---

## Task 2: `blackcat-kill-chain.yaml`

**Files:**
- Create: `scenarios/blackcat-kill-chain.yaml` (+ `.sig`)

**Interfaces:**
- Consumes: profiles from Task 1 (`windows_ad_discovery`) plus existing profiles `windows_security_software_discovery`, `windows_sam_theft`, `windows_defender_tampering`, `windows_malicious_service`, `windows_ransomware_encryption`, `windows_vss_inhibition`, `windows_log_manipulation`.

**Safety notes:** Steps 4 (Defender RTP disable) and 5 (malicious service) are `fidelity: lab-only` / `production_safe: false` — same risk classification already shipped in `ransomware-drill.yaml`, read by campaign policy to exclude them from production-targeted campaigns. All other steps are `production_safe: true`.

- [ ] **Step 1: Create `scenarios/blackcat-kill-chain.yaml`**

```yaml
id: blackcat-kill-chain
name: BlackCat/ALPHV Kill Chain — Ransomware Emulation
description: >
  Eight-stage telemetry-safe emulation of the BlackCat/ALPHV ransomware kill
  chain targeting Windows endpoints. Reflects documented BlackCat tradecraft
  validated against CISA AA23-353A: Rust-based Ransomware-as-a-Service,
  intermittent encryption, self-propagation via PsExec/Group Policy.

  KILL CHAIN STAGES:
    1. Domain Discovery      — AD/privileged-account/DC enumeration (T1087.002)
    2. Defense Discovery     — security software enumeration (T1518.001)
    3. Credential Access     — SAM/SYSTEM hive theft via reg save (T1003.002)
    4. Defense Evasion       — Defender Real-Time Protection disable (T1562.001)
    5. Lateral Movement      — malicious service, PsExec-style (T1543.003)
    6. Ransomware Simulation — XOR-encoded benign file + ransom note, .blackcat extension (T1486)
    7. Recovery Inhibition   — VSS snapshot enumeration (T1490)
    8. Log Clearing Attempt  — wevtutil cl attempt, blocked or audit (T1070.001)

  NOTE: BlackCat's real initial access is via purchased access-broker
  credentials, valid accounts, or phishing — not represented as an
  executable step since none of these are safely agent-simulatable.

  SAFETY: No real encryption of user data. XOR is applied to a single BAS-
  created temp file with [BAS-SIM-BLACKCAT] content only. Ransom note is
  cleaned up immediately. Stages 4 and 5 are lab-only (Defender RTP toggle,
  throwaway service creation) — both self-restore/self-clean within the
  step but are excluded from production campaigns via fidelity metadata.
  All other stages are production-safe. Windows only. [BAS-SIM] tagged
  throughout.
author: Audspect Research
executable: true
local_check: false
supported_os: [windows]
tags:
  - blackcat
  - alphv
  - ransomware
  - bfsi
  - kill-chain
  - t1003
  - t1070
  - t1087
  - t1486
  - t1490
  - t1518
  - t1543
  - t1562
  - mitre
mitre_phases:
  - discovery
  - credential-access
  - defense-evasion
  - lateral-movement
  - impact

live_policy:
  block_on_domain_controller: false
  require_dc_reachable: false
  max_spray_attempts: 0
  spray_account_allowlist: []
  execution_window: ""

steps:

  # ---------------------------------------------------------------------------
  # Stage 1 — Domain Discovery (T1087.002)
  # ---------------------------------------------------------------------------
  - name: "BlackCat Stage 1 — AD Domain & Privileged Account Discovery (T1087.002)"
    technique_id: T1087.002
    detection_profiles:
      - windows_ad_discovery
    framework: custom
    executor: powershell
    requires_priv: user
    timeout_sec: 30
    fidelity: telemetry-safe
    production_safe: true
    risk: low
    blast_radius: "Runs net group \"Domain Admins\" /domain, net view, and nltest /dclist: (all read-only, current-token). No accounts touched. Generates Sysmon EID 1 (net.exe / nltest.exe)."
    reversible: true
    telemetry:
      - "Sysmon EID 1: net.exe group / view, nltest.exe /dclist"
      - "Security EID 4688: net.exe and nltest.exe spawned by powershell.exe"
    detection:
      - "EDR: nltest.exe /dclist and net group 'Domain Admins' /domain from a single host — Sigma rule proc_creation_win_net_enum.yml"
      - "SIEM: domain-controller and privileged-group enumeration chained together — pre-credential-theft recon IOC"
    command: |
      $ErrorActionPreference = 'SilentlyContinue'
      $domainAdmins = & net.exe group "Domain Admins" /domain 2>&1 | Out-String
      $computers    = & net.exe view 2>&1 | Out-String
      $dcList       = & nltest.exe /dclist: 2>&1 | Out-String
      $domainJoined = $domainAdmins -notmatch 'workstation is not|not be found|is not part'
      Write-Output "EXEC T1087.002: AdFind-style domain enumeration -- Domain Admins group, network computer list (net view), and DC list (nltest) queried (domain_joined=$domainJoined). BlackCat/ALPHV uses this recon to map privileged accounts and domain controllers before credential theft. [BAS-SIM-BLACKCAT-S1]"
      Write-Output "FAIL: domain enumeration completed unimpeded via built-in LOLBins (net.exe, nltest.exe) -- no AdFind binary required. Alert on nltest.exe /dclist and net group 'Domain Admins' /domain from non-IT accounts."
    cleanup: ""

  # ---------------------------------------------------------------------------
  # Stage 2 — Defense Discovery (T1518.001)
  # ---------------------------------------------------------------------------
  - name: "BlackCat Stage 2 — Security Software Discovery (T1518.001)"
    technique_id: T1518.001
    detection_profiles:
      - windows_security_software_discovery
    framework: custom
    executor: powershell
    requires_priv: user
    timeout_sec: 30
    fidelity: telemetry-safe
    production_safe: true
    risk: low
    blast_radius: "Queries WMI AntiVirusProduct, AntiSpywareProduct, FirewallProduct to enumerate installed security products. Read-only. Generates ScriptBlock EID 4104 and WMI-Activity EID 5857-5861."
    reversible: true
    telemetry:
      - "WMI-Activity EID 5857-5861: Get-WmiObject SecurityCenter2 query"
      - "PowerShell ScriptBlock EID 4104: AntiVirusProduct WMI class enumeration"
      - "Sysmon EID 1: powershell.exe WMI query (ransomware reconnaissance pattern)"
    detection:
      - "EDR: WMI security product enumeration from PowerShell  -  Sigma rule win_wmi_security_product_discovery.yml"
      - "SIEM: Get-WmiObject Win32_Product or SecurityCenter2 — pre-ransomware recon IOC"
    command: |
      $ErrorActionPreference = 'SilentlyContinue'
      $avProducts = Get-WmiObject -Namespace 'root\SecurityCenter2' -Class 'AntiVirusProduct' -ErrorAction SilentlyContinue
      $fwProducts = Get-WmiObject -Namespace 'root\SecurityCenter2' -Class 'FirewallProduct' -ErrorAction SilentlyContinue
      $avNames = ($avProducts | ForEach-Object { $_.displayName }) -join ', '
      $fwNames = ($fwProducts | ForEach-Object { $_.displayName }) -join ', '
      if ($avProducts -or $fwProducts) {
        Write-Output "EXEC T1518.001: security software enumerated. AV=[$avNames] FW=[$fwNames]. BlackCat uses this to decide whether to proceed or disable controls. [BAS-SIM-BLACKCAT-S2]"
        Write-Output "FAIL: security product names are enumerable via WMI SecurityCenter2. EDR should alert on this WMI class access from PowerShell."
      } else {
        Write-Output "PASS: SecurityCenter2 namespace not accessible or no products registered  -  WMI security product enumeration blocked/empty. [BAS-SIM-BLACKCAT-S2]"
      }
    cleanup: ""

  # ---------------------------------------------------------------------------
  # Stage 3 — Credential Access: SAM/SYSTEM Hive Theft (T1003.002)
  # ---------------------------------------------------------------------------
  - name: "BlackCat Stage 3 — SAM & SYSTEM Hive Theft via reg save (T1003.002)"
    technique_id: T1003.002
    detection_profiles:
      - windows_sam_theft
    framework: custom
    executor: powershell
    requires_priv: admin
    timeout_sec: 40
    fidelity: telemetry-safe
    production_safe: true
    risk: high
    reversible: true
    blast_radius: "Attempts reg save HKLM\\SAM and HKLM\\SYSTEM to a temp file, then deletes both immediately. The saved SAM hive is encrypted with the bootkey (which is NOT exported), so the artifact is unusable, and it is removed in the same step. Generates Sysmon EID 1 (reg.exe save) + EID 11 (file create) + immediate delete."
    telemetry:
      - "Sysmon EID 1: reg.exe save HKLM\\SAM / HKLM\\SYSTEM"
      - "Sysmon EID 11: hive file written to %TEMP% then deleted"
      - "Security EID 4688: reg.exe with 'save' argument targeting SAM/SYSTEM"
    detection:
      - "EDR: reg.exe save hklm\\sam — Sigma proc_creation_win_reg_save_sam.yml (offline hash-theft IOC)"
      - "SIEM: reg SAVE targeting SAM or SYSTEM hive — page immediately, extremely rare in normal ops"
    command: |
      $ErrorActionPreference = 'SilentlyContinue'
      $runId = if ($env:BAS_RUN_ID) { $env:BAS_RUN_ID.Substring(0,[Math]::Min(8,$env:BAS_RUN_ID.Length)) } else { '{0:x8}' -f (Get-Random -Maximum 0x7FFFFFFF) }
      $samOut = Join-Path $env:TEMP "bas_blackcat_sam_$runId.hive"
      $sysOut = Join-Path $env:TEMP "bas_blackcat_sys_$runId.hive"
      & reg.exe save HKLM\SAM $samOut /y 2>&1 | Out-Null
      & reg.exe save HKLM\SYSTEM $sysOut /y 2>&1 | Out-Null
      $samSaved = Test-Path $samOut
      $sysSaved = Test-Path $sysOut
      Remove-Item $samOut,$sysOut -Force -ErrorAction SilentlyContinue
      if ($samSaved -or $sysSaved) {
        Write-Output "EXEC T1003.002: reg save of SAM=$samSaved SYSTEM=$sysSaved to %TEMP% then deleted. BlackCat steals these hives for OFFLINE hash extraction. reg.exe SAVE telemetry (Sysmon EID 1) expected. [BAS-SIM-BLACKCAT-S3]"
        Write-Output "FAIL: reg.exe was able to SAVE the SAM/SYSTEM hive unblocked — local password hashes can be exfiltrated for offline cracking. 'reg save hklm\\sam' should be a paging alert. Verify EDR blocked or at least alerted."
      } else {
        Write-Output "PASS: reg save of SAM/SYSTEM was blocked or denied — EDR/WDAC prevented offline hive theft. [BAS-SIM-BLACKCAT-S3]"
      }
    cleanup: |
      Remove-Item (Join-Path $env:TEMP 'bas_blackcat_sam_*') -Force -ErrorAction SilentlyContinue
      Remove-Item (Join-Path $env:TEMP 'bas_blackcat_sys_*') -Force -ErrorAction SilentlyContinue

  # ---------------------------------------------------------------------------
  # Stage 4 — Defense Evasion: Defender RTP Disable (T1562.001)
  # ---------------------------------------------------------------------------
  - name: "BlackCat Stage 4 — Defender RTP Disable (lab  -  mandatory restoration + health check) (T1562.001)"
    technique_id: T1562.001
    detection_profiles:
      - windows_defender_tampering
    framework: custom
    executor: powershell
    requires_priv: admin
    timeout_sec: 45
    fidelity: lab-only
    production_safe: false
    risk: high
    blast_radius: "Attempts to disable Defender Real-Time Protection via Set-MpPreference. Immediately re-enables. Post-test health verification confirms restoration. EDR will alert."
    reversible: true
    telemetry:
      - "Security EID 4657 (registry value modified): HKLM\\...\\Windows Defender\\DisableRealtimeMonitoring"
      - "Defender event log: EID 5001 (RTP disabled) + EID 5000 (re-enabled)"
    detection:
      - "EDR: Defender RTP disabled  -  immediate P1 alert in any mature SOC"
      - "SIEM: WMI/registry change to Defender configuration from non-management process"
    command: |
      $ErrorActionPreference = 'SilentlyContinue'
      $before = (Get-MpComputerStatus -ErrorAction SilentlyContinue).RealTimeProtectionEnabled
      Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue
      $disabled = -not (Get-MpComputerStatus -ErrorAction SilentlyContinue).RealTimeProtectionEnabled
      Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction SilentlyContinue
      $restored = (Get-MpComputerStatus -ErrorAction SilentlyContinue).RealTimeProtectionEnabled
      $tamperBlocked = (Get-MpComputerStatus -ErrorAction SilentlyContinue).IsTamperProtected
      if (-not $disabled) {
        Write-Output "PASS: Defender RTP disable attempt failed  -  Tamper Protection or EDR blocked the change (tamperProtected=$tamperBlocked). [BAS-SIM-BLACKCAT-S4]"
      } elseif ($restored) {
        Write-Output "FAIL: Defender RTP was disabled then re-enabled (restoration verified=true). HEALTH: RTP now $restored, tamperProtected=$tamperBlocked. Expect Defender EID 5001+5000. [BAS-SIM-BLACKCAT-S4]"
      } else {
        Set-MpPreference -DisableRealtimeMonitoring $false -Force -ErrorAction SilentlyContinue
        Write-Output "CRITICAL: Defender RTP disabled and re-enable failed  -  manual restoration required. Run: Set-MpPreference -DisableRealtimeMonitoring $false [BAS-SIM-BLACKCAT-S4]"
      }
    cleanup: |
      Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction SilentlyContinue

  # ---------------------------------------------------------------------------
  # Stage 5 — Lateral Movement: Malicious Service (T1543.003)
  # ---------------------------------------------------------------------------
  - name: "BlackCat Stage 5 — Malicious Service Probe (lab  -  PsExec-style self-propagation) (T1543.003)"
    technique_id: T1543.003
    detection_profiles:
      - windows_malicious_service
    framework: custom
    executor: powershell
    requires_priv: admin
    timeout_sec: 45
    fidelity: lab-only
    production_safe: false
    risk: medium
    blast_radius: "Creates a benign service (cmd.exe /c echo) via sc.exe, logs binary path + parent process + execution lineage, starts, stops, deletes. Used by BlackCat/ALPHV for lateral spread via PsExec-style service deployment."
    reversible: true
    telemetry:
      - "Security EID 4697 (service installed) + EID 7045 (new service installed in system)"
      - "Security EID 4688 (sc.exe create + start + stop + delete)"
    detection:
      - "SIEM: new service installed with binary path in non-standard directory  -  PsExec lateral-spread signal"
      - "EDR: service binary path pointing to cmd.exe or user-writable path"
    command: |
      $ErrorActionPreference = 'SilentlyContinue'
      $svcName   = 'BAS-SIM-BlackCatSvc'
      $svcBin    = "$env:SystemRoot\System32\cmd.exe /c echo BAS-SIM-T1543"
      $parentPid = $PID
      $parentImg = (Get-Process -Id $parentPid -ErrorAction SilentlyContinue).MainModule.FileName
      sc.exe create $svcName binPath= "`"$svcBin`"" start= demand 2>&1 | Out-Null
      $created = (Get-Service -Name $svcName -ErrorAction SilentlyContinue) -ne $null
      if ($created) {
        sc.exe start $svcName 2>&1 | Out-Null
        Start-Sleep -Milliseconds 500
        sc.exe stop  $svcName 2>&1 | Out-Null
        sc.exe delete $svcName 2>&1 | Out-Null
        $gone = (Get-Service -Name $svcName -ErrorAction SilentlyContinue) -eq $null
        Write-Output "FAIL: service '$svcName' created+started+deleted (removed=$gone). BinaryPath='$svcBin'. Parent=$parentImg (PID=$parentPid). Expect EID 4697+7045. BlackCat/PsExec service deployment vector confirmed. [BAS-SIM-BLACKCAT-S5]"
      } else {
        Write-Output "PASS: sc.exe service creation blocked  -  AppLocker / restricted token / policy prevented malicious service deployment. [BAS-SIM-BLACKCAT-S5]"
      }
    cleanup: |
      sc.exe stop   BAS-SIM-BlackCatSvc 2>&1 | Out-Null
      sc.exe delete BAS-SIM-BlackCatSvc 2>&1 | Out-Null

  # ---------------------------------------------------------------------------
  # Stage 6 — Ransomware Impact Simulation (T1486)
  # ---------------------------------------------------------------------------
  - name: "BlackCat Stage 6 — Ransomware Payload Simulation (T1486)"
    technique_id: T1486
    detection_profiles:
      - windows_ransomware_encryption
    framework: custom
    executor: powershell
    requires_priv: user
    timeout_sec: 30
    fidelity: telemetry-safe
    production_safe: true
    risk: low
    blast_radius: "Creates one BAS-owned plaintext file in %TEMP%, XOR-encodes it (simulating encryption), writes a benign ransom note ([BAS-SIM-BLACKCAT] only), then DELETES BOTH immediately. No user data touched. No real ransomware code. Generates Sysmon EID 11 (file create x2) and EID 23 (file delete x2). Real BlackCat uses intermittent (partial-file) encryption to evade heuristics -- not functionally replicated here since chunk size does not change the endpoint detection surface being validated."
    reversible: true
    telemetry:
      - "Sysmon EID 11: bas_blackcat_<id>.txt created in %TEMP%"
      - "Sysmon EID 11: bas_blackcat_<id>.blackcat (encrypted simulation) created"
      - "Sysmon EID 11: bas_ransom_<id>.txt (ransom note) created"
      - "Sysmon EID 23: all files deleted in cleanup"
    detection:
      - "EDR: high-frequency file create + rename + delete in short window  -  Sigma rule win_security_susp_file_modifications.yml"
      - "Defender: ransom-pattern file creation heuristic (many .blackcat extension files)"
      - "EDR: PowerShell creating and immediately deleting files with suspicious extension"
    command: |
      $ErrorActionPreference = 'SilentlyContinue'
      $runId = if ($env:BAS_RUN_ID) { $env:BAS_RUN_ID.Substring(0,[Math]::Min(8,$env:BAS_RUN_ID.Length)) } else { '{0:x8}' -f (Get-Random -Maximum 0x7FFFFFFF) }
      $plainFile = Join-Path $env:TEMP "bas_blackcat_$runId.txt"
      $encFile   = Join-Path $env:TEMP "bas_blackcat_$runId.blackcat"
      $noteFile  = Join-Path $env:TEMP "bas_ransom_$runId.txt"
      $plainContent = '[BAS-SIM-BLACKCAT] T1486 ransomware simulation target file'
      [System.IO.File]::WriteAllText($plainFile, $plainContent, [System.Text.Encoding]::UTF8)
      # Simulate XOR encryption (key=0x42 = 'B' for BlackCat)
      $key = 0x42
      $bytes = [System.Text.Encoding]::UTF8.GetBytes($plainContent)
      $enc   = $bytes | ForEach-Object { $_ -bxor $key }
      [System.IO.File]::WriteAllBytes($encFile, [byte[]]$enc)
      # Ransom note (benign BAS simulation content only)
      $note = '[BAS-SIM-BLACKCAT] ALPHV/BlackCat Ransomware Simulation Note' + [char]13 + [char]10 +
              'This is a BAS simulation. No real files were encrypted.' + [char]13 + [char]10 +
              'Run ID: ' + $runId
      [System.IO.File]::WriteAllText($noteFile, $note, [System.Text.Encoding]::UTF8)
      $created = (Test-Path $plainFile) -and (Test-Path $encFile) -and (Test-Path $noteFile)
      Remove-Item $plainFile,$encFile,$noteFile -Force -ErrorAction SilentlyContinue
      $cleaned = -not (Test-Path $plainFile) -and -not (Test-Path $encFile) -and -not (Test-Path $noteFile)
      if ($created) {
        Write-Output "EXEC T1486: ransomware simulation completed — target file XOR-encoded (.blackcat), ransom note written, all cleaned=$cleaned. Sysmon EID 11+23 expected. [BAS-SIM-BLACKCAT-S6]"
        Write-Output "FAIL: File encryption simulation ran unblocked. Defender ransomware protection and controlled folder access should have flagged this pattern."
      } else {
        Write-Output "PASS: Ransomware simulation file creation blocked  -  Controlled Folder Access or EDR prevented file write to %TEMP%. [BAS-SIM-BLACKCAT-S6]"
      }
    cleanup: |
      Remove-Item (Join-Path $env:TEMP 'bas_blackcat_*') -Force -ErrorAction SilentlyContinue
      Remove-Item (Join-Path $env:TEMP 'bas_ransom_*') -Force -ErrorAction SilentlyContinue

  # ---------------------------------------------------------------------------
  # Stage 7 — Recovery Inhibition: VSS Enumeration (T1490)
  # ---------------------------------------------------------------------------
  - name: "BlackCat Stage 7 — VSS Snapshot Enumeration (T1490)"
    technique_id: T1490
    detection_profiles:
      - windows_vss_inhibition
    framework: custom
    executor: powershell
    requires_priv: admin
    timeout_sec: 20
    fidelity: telemetry-safe
    production_safe: true
    risk: low
    blast_radius: "Runs vssadmin list shadows to enumerate VSS snapshots (READ ONLY). BlackCat deletes these via 'vssadmin delete shadows /all /quiet' — we enumerate only to show the attack surface. Generates Sysmon EID 1: vssadmin.exe with 'list' argument."
    reversible: true
    telemetry:
      - "Sysmon EID 1: vssadmin.exe list shadows (pre-wipe reconnaissance)"
      - "Security EID 4688: vssadmin.exe spawned by powershell.exe"
    detection:
      - "EDR: vssadmin.exe invoked from PowerShell  -  Sigma rule proc_creation_win_vssadmin_susp_commands.yml"
      - "SIEM: vssadmin list shadows — pre-ransomware VSS enumeration IOC (LockBit, Conti, BlackCat all do this)"
    command: |
      $ErrorActionPreference = 'SilentlyContinue'
      $vssOut = & vssadmin.exe list shadows 2>&1 | Out-String
      $shadowCount = ([regex]::Matches($vssOut, 'Shadow Copy ID')).Count
      if ($shadowCount -gt 0) {
        Write-Output "EXEC T1490: $shadowCount VSS shadow copy(ies) enumerated. BlackCat would now run 'vssadmin delete shadows /all /quiet' to destroy backups. Sysmon EID 1 vssadmin.exe logged. [BAS-SIM-BLACKCAT-S7]"
        Write-Output "FAIL: VSS snapshots exist and are enumerable ($shadowCount found). If BlackCat reached this stage, backups would be destroyed before encryption. Ensure immutable cloud backup or Veeam hardened repo is NOT reachable from endpoint."
      } else {
        Write-Output "PASS: No VSS shadow copies found or vssadmin blocked  -  recovery inhibition surface is reduced. [BAS-SIM-BLACKCAT-S7]"
      }
    cleanup: ""

  # ---------------------------------------------------------------------------
  # Stage 8 — Indicator Removal: Event Log Clearing Attempt (T1070.001)
  # ---------------------------------------------------------------------------
  - name: "BlackCat Stage 8 — Event Log Clearing Attempt (T1070.001)"
    technique_id: T1070.001
    detection_profiles:
      - windows_log_manipulation
    framework: custom
    executor: powershell
    requires_priv: admin
    timeout_sec: 20
    fidelity: telemetry-safe
    production_safe: true
    risk: low
    blast_radius: "Creates a BAS-owned custom event log (BAS-Sim-BlackCat), attempts wevtutil cl on it, then removes the log. Does NOT touch System/Security/Application logs. Generates Security EID 1102 if the clear succeeds, and Sysmon EID 1 wevtutil.exe."
    reversible: true
    telemetry:
      - "Sysmon EID 1: wevtutil.exe with cl argument (log-clearing pattern)"
      - "Security EID 1102: audit log cleared (if wevtutil cl succeeds on custom log)"
      - "Security EID 4688: wevtutil.exe spawned by powershell.exe"
    detection:
      - "EDR: wevtutil.exe with 'cl' argument  -  Sigma rule proc_creation_win_wevtutil_clear_logs.yml"
      - "SIEM: Security EID 1102 event log cleared  -  high-priority anti-forensics IOC"
      - "SIEM: wevtutil.exe invoked from PowerShell at unusual time"
    command: |
      $ErrorActionPreference = 'SilentlyContinue'
      $logName = 'BAS-Sim-BlackCat'
      $exists = [System.Diagnostics.EventLog]::Exists($logName)
      if (-not $exists) {
        try { New-EventLog -LogName $logName -Source 'BAS-Sim' -ErrorAction Stop } catch {}
      }
      $created = [System.Diagnostics.EventLog]::Exists($logName)
      if ($created) {
        $clOut = & wevtutil.exe cl $logName 2>&1 | Out-String
        $cleared = $clOut -notmatch 'Access is denied|The specified channel could not be found|error'
        try { Remove-EventLog -LogName $logName -ErrorAction SilentlyContinue } catch {}
        if ($cleared) {
          Write-Output "EXEC T1070.001: wevtutil cl on BAS custom log succeeded (exit 0). BlackCat uses 'wevtutil cl System' 'wevtutil cl Security' after ransomware deployment. Sysmon EID 1 wevtutil.exe logged. [BAS-SIM-BLACKCAT-S8]"
          Write-Output "FAIL: wevtutil cl ran without EDR intervention. Ensure wevtutil.exe invocation from PowerShell triggers an alert. Security EID 1102 should generate a SIEM alert."
        } else {
          Write-Output "PASS: wevtutil cl was blocked or failed  -  $($clOut.Trim()). [BAS-SIM-BLACKCAT-S8]"
        }
      } else {
        Write-Output "SKIP: Could not create test event log (insufficient privilege). wevtutil cl test skipped. [BAS-SIM-BLACKCAT-S8]"
      }
    cleanup: |
      try { Remove-EventLog -LogName 'BAS-Sim-BlackCat' -ErrorAction SilentlyContinue } catch {}
```

- [ ] **Step 2: Validate YAML structural validity**

```bash
python3 -c "import yaml; yaml.safe_load(open('scenarios/blackcat-kill-chain.yaml')); print('OK')"
```
Expected: `OK`, no exceptions.

- [ ] **Step 3: Manual PowerShell syntax sanity check**

For each of the 8 `command:` and 6 non-empty `cleanup:` blocks in the file, extract the script text and parse it (does not execute):
```powershell
$errors = $null
[System.Management.Automation.Language.Parser]::ParseInput($script, [ref]$null, [ref]$errors) | Out-Null
if ($errors) { $errors }
```
Expected: no parse errors for any block. There is no automated Go-side tool for this — manual authoring-time check per the design spec (same as the DLP Validation Suite plan's Step 6).

- [ ] **Step 4: Sign the file**

From `orchestrator/`:
```bash
go run scripts/signer.go sign private_key.pem ../scenarios/blackcat-kill-chain.yaml
```
Expected: `blackcat-kill-chain.yaml.sig` created, no errors.

- [ ] **Step 5: Commit**

```bash
git add scenarios/blackcat-kill-chain.yaml scenarios/blackcat-kill-chain.yaml.sig
git commit -m "feat(scenarios): BlackCat/ALPHV kill-chain scenario (Ransomware Readiness Deliverable 2)"
git push
```

---

## Task 3: `akira-kill-chain.yaml`

**Files:**
- Create: `scenarios/akira-kill-chain.yaml` (+ `.sig`)

**Interfaces:**
- Consumes: `windows_rdp_nla_posture` (Task 1) plus existing profiles `windows_network_share_discovery`, `windows_sam_theft`, `windows_defender_tampering`, `windows_smb_lateral_probe`, `windows_ransomware_encryption`, `windows_vss_inhibition`, `windows_log_manipulation`.

**Safety notes:** Stage 8 (VSS deletion via WMI) is `fidelity: lab-only` / `production_safe: false`, gated behind `BAS_CONFIRM_VSS_DELETE=true` — exact same opt-in gate already shipped in `ransomware-drill.yaml`. Deletes only the single oldest C: shadow copy. Defaults to a clean SKIP.

- [ ] **Step 1: Create `scenarios/akira-kill-chain.yaml`**

```yaml
id: akira-kill-chain
name: Akira Kill Chain — Ransomware Emulation
description: >
  Nine-stage telemetry-safe emulation of the Akira ransomware kill chain
  targeting Windows endpoints. Reflects documented Akira tradecraft
  validated against CISA AA24-109A: RDP/VPN-without-MFA initial access,
  credential dumping, and VSS deletion via WMI (Get-WmiObject
  Win32_ShadowCopy) rather than vssadmin.

  KILL CHAIN STAGES:
    1. Initial Access        — RDP/NLA exposure posture check (T1021.001)
    2. Discovery              — network share discovery (T1135)
    3. Credential Access      — SAM/SYSTEM hive theft via reg save (T1003.002)
    4. Defense Evasion        — Defender exclusion invocation probe (T1562.001)
    5. Lateral Movement       — SMB admin share reachability check (T1021.002)
    6. Ransomware Simulation  — XOR-encoded benign file + ransom note, .akira extension (T1486)
    7. Recovery Inhibition A  — VSS snapshot enumeration, vssadmin (T1490)
    8. Recovery Inhibition B  — VSS deletion via WMI Win32_ShadowCopy.Delete() (T1490, lab-only)
    9. Log Clearing Attempt   — wevtutil cl attempt, blocked or audit (T1070.001)

  SAFETY: No real encryption of user data. XOR is applied to a single BAS-
  created temp file with [BAS-SIM-AKIRA] content only. Ransom note is
  cleaned up immediately. Stage 8 is lab-only and default-disabled — it
  requires the operator to explicitly set BAS_CONFIRM_VSS_DELETE=true in
  an isolated lab; without it, the step SKIPs with no state change and
  deletes at most ONE (the oldest) real C: shadow copy when enabled. All
  other stages are production-safe. Windows only. [BAS-SIM] tagged
  throughout.
author: Audspect Research
executable: true
local_check: false
supported_os: [windows]
tags:
  - akira
  - ransomware
  - bfsi
  - kill-chain
  - t1003
  - t1021
  - t1070
  - t1135
  - t1486
  - t1490
  - t1562
  - mitre
mitre_phases:
  - initial-access
  - discovery
  - credential-access
  - defense-evasion
  - lateral-movement
  - impact

live_policy:
  block_on_domain_controller: false
  require_dc_reachable: false
  max_spray_attempts: 0
  spray_account_allowlist: []
  execution_window: ""

steps:

  # ---------------------------------------------------------------------------
  # Stage 1 — Initial Access: RDP / NLA Posture (T1021.001)
  # ---------------------------------------------------------------------------
  - name: "Akira Stage 1 — RDP / NLA Exposure Posture Check (T1021.001)"
    technique_id: T1021.001
    detection_profiles:
      - windows_rdp_nla_posture
    framework: custom
    executor: powershell
    requires_priv: user
    timeout_sec: 15
    fidelity: telemetry-safe
    production_safe: true
    risk: low
    blast_radius: "Reads two registry values (read-only): fDenyTSConnections under HKLM Terminal Server, and UserAuthentication under the RDP-Tcp WinStation. No state change. No connection attempted."
    reversible: true
    telemetry:
      - "Security EID 4657 (registry value queried, if SACL auditing enabled on the key)"
    detection:
      - "SIEM: registry query of Terminal Server RDP/NLA configuration from a non-management process — RDP-exposure recon IOC"
    command: |
      $ErrorActionPreference = 'SilentlyContinue'
      $rdpEnabled = (Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections' -ErrorAction SilentlyContinue).fDenyTSConnections -eq 0
      $nlaEnforced = (Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'UserAuthentication' -ErrorAction SilentlyContinue).UserAuthentication -eq 1
      Write-Output "EXEC T1021.001: RDP enabled=$rdpEnabled, NLA enforced=$nlaEnforced. Akira's documented initial-access pattern is RDP/VPN access without MFA -- this posture check surfaces the same exposure without attempting an actual logon. [BAS-SIM-AKIRA-S1]"
      if ($rdpEnabled -and -not $nlaEnforced) {
        Write-Output "FAIL: RDP is enabled without Network Level Authentication enforced -- a documented Akira initial-access precondition. Enforce NLA and require MFA on all RDP-reachable endpoints."
      } elseif (-not $rdpEnabled) {
        Write-Output "PASS: RDP is disabled on this endpoint -- Akira's RDP-based initial-access vector does not apply here."
      } else {
        Write-Output "PASS: RDP is enabled with NLA enforced -- reduces (does not eliminate) unauthenticated RDP exposure."
      }
    cleanup: ""

  # ---------------------------------------------------------------------------
  # Stage 2 — Discovery: Network Share Discovery (T1135)
  # ---------------------------------------------------------------------------
  - name: "Akira Stage 2 — Network Share Discovery (T1135)"
    technique_id: T1135
    detection_profiles:
      - windows_network_share_discovery
    framework: custom
    executor: powershell
    requires_priv: user
    timeout_sec: 30
    fidelity: telemetry-safe
    production_safe: true
    risk: low
    reversible: true
    blast_radius: "Enumerates local administrative shares via net view and WMI Win32_Share. No shares accessed, no files read."
    telemetry:
      - "Security EID 4688: net.exe and powershell.exe share enumeration"
      - "Security EID 5140: if SACL object access auditing enabled on shares"
    detection:
      - "SIEM: net view / Win32_Share query from non-admin process — ransomware lateral-spread staging signal"
    command: |
      $ErrorActionPreference = 'SilentlyContinue'
      $wmiShares = @(Get-WmiObject -Class Win32_Share -ErrorAction SilentlyContinue)
      $netOut = & net view \\$env:COMPUTERNAME 2>&1
      $shareCount = if ($wmiShares) { $wmiShares.Count } else { 0 }
      Write-Output "EXEC: network share discovery — $shareCount share(s) via Win32_Share. net view executed for cmdline telemetry. Akira maps shares before lateral spread and mass encryption. [BAS-SIM-AKIRA-S2]"
    cleanup: ""

  # ---------------------------------------------------------------------------
  # Stage 3 — Credential Access: SAM/SYSTEM Hive Theft (T1003.002)
  # ---------------------------------------------------------------------------
  - name: "Akira Stage 3 — SAM & SYSTEM Hive Theft via reg save (T1003.002)"
    technique_id: T1003.002
    detection_profiles:
      - windows_sam_theft
    framework: custom
    executor: powershell
    requires_priv: admin
    timeout_sec: 40
    fidelity: telemetry-safe
    production_safe: true
    risk: high
    reversible: true
    blast_radius: "Attempts reg save HKLM\\SAM and HKLM\\SYSTEM to a temp file, then deletes both immediately. The saved SAM hive is encrypted with the bootkey (which is NOT exported), so the artifact is unusable, and it is removed in the same step. Generates Sysmon EID 1 (reg.exe save) + EID 11 (file create) + immediate delete."
    telemetry:
      - "Sysmon EID 1: reg.exe save HKLM\\SAM / HKLM\\SYSTEM"
      - "Sysmon EID 11: hive file written to %TEMP% then deleted"
      - "Security EID 4688: reg.exe with 'save' argument targeting SAM/SYSTEM"
    detection:
      - "EDR: reg.exe save hklm\\sam — Sigma proc_creation_win_reg_save_sam.yml (offline hash-theft IOC)"
      - "SIEM: reg SAVE targeting SAM or SYSTEM hive — page immediately, extremely rare in normal ops"
    command: |
      $ErrorActionPreference = 'SilentlyContinue'
      $runId = if ($env:BAS_RUN_ID) { $env:BAS_RUN_ID.Substring(0,[Math]::Min(8,$env:BAS_RUN_ID.Length)) } else { '{0:x8}' -f (Get-Random -Maximum 0x7FFFFFFF) }
      $samOut = Join-Path $env:TEMP "bas_akira_sam_$runId.hive"
      $sysOut = Join-Path $env:TEMP "bas_akira_sys_$runId.hive"
      & reg.exe save HKLM\SAM $samOut /y 2>&1 | Out-Null
      & reg.exe save HKLM\SYSTEM $sysOut /y 2>&1 | Out-Null
      $samSaved = Test-Path $samOut
      $sysSaved = Test-Path $sysOut
      Remove-Item $samOut,$sysOut -Force -ErrorAction SilentlyContinue
      if ($samSaved -or $sysSaved) {
        Write-Output "EXEC T1003.002: reg save of SAM=$samSaved SYSTEM=$sysSaved to %TEMP% then deleted. Akira steals these hives for OFFLINE hash extraction and LSASS-adjacent credential dumping. reg.exe SAVE telemetry (Sysmon EID 1) expected. [BAS-SIM-AKIRA-S3]"
        Write-Output "FAIL: reg.exe was able to SAVE the SAM/SYSTEM hive unblocked — local password hashes can be exfiltrated for offline cracking. 'reg save hklm\\sam' should be a paging alert. Verify EDR blocked or at least alerted."
      } else {
        Write-Output "PASS: reg save of SAM/SYSTEM was blocked or denied — EDR/WDAC prevented offline hive theft. [BAS-SIM-AKIRA-S3]"
      }
    cleanup: |
      Remove-Item (Join-Path $env:TEMP 'bas_akira_sam_*') -Force -ErrorAction SilentlyContinue
      Remove-Item (Join-Path $env:TEMP 'bas_akira_sys_*') -Force -ErrorAction SilentlyContinue

  # ---------------------------------------------------------------------------
  # Stage 4 — Defense Evasion: Defender Exclusion Invocation (T1562.001)
  # ---------------------------------------------------------------------------
  - name: "Akira Stage 4 — Defender Exclusion Invocation (cmdline probe  -  no state change) (T1562.001)"
    technique_id: T1562.001
    detection_profiles:
      - windows_defender_tampering
    framework: custom
    executor: powershell
    requires_priv: user
    timeout_sec: 20
    fidelity: telemetry-safe
    production_safe: true
    risk: low
    blast_radius: "Invokes Add-MpPreference cmdline in a dry-run context that exits before modifying any exclusion. Security state is NOT changed."
    reversible: true
    telemetry:
      - "Security EID 4688 (powershell.exe with Add-MpPreference -ExclusionPath in command line)"
      - "PowerShell EID 4104 (script block: Add-MpPreference invocation) if ScriptBlock logging enabled"
    detection:
      - "EDR: PowerShell invoking Add-MpPreference  -  primary Defender tampering signal"
      - "SIEM: cmdline containing Add-MpPreference and ExclusionPath from a non-management process"
    command: |
      $ErrorActionPreference = 'SilentlyContinue'
      $cmdLine = 'Add-MpPreference -ExclusionPath $env:TEMP'
      Write-Output "EXEC: Defender exclusion invocation probe  -  cmdline '$cmdLine' logged to EID 4104/4688. Security state NOT modified (dry-run). Akira disables Defender before mass encryption. [BAS-SIM-AKIRA-S4]"
      Write-Output "TELEMETRY: if ScriptBlock logging (EID 4104) captured this block, the control is detecting Defender tampering attempts correctly."
    cleanup: ""

  # ---------------------------------------------------------------------------
  # Stage 5 — Lateral Movement: SMB Admin Share Probe (T1021.002)
  # ---------------------------------------------------------------------------
  - name: "Akira Stage 5 — SMB Admin Share Lateral Movement Probe (T1021.002)"
    technique_id: T1021.002
    detection_profiles:
      - windows_smb_lateral_probe
    framework: custom
    executor: powershell
    requires_priv: user
    timeout_sec: 20
    fidelity: telemetry-safe
    production_safe: true
    risk: low
    blast_radius: "Tests whether \\127.0.0.1\\ADMIN$ is accessible with the current user token via net use (loopback). Disconnects immediately. Generates Security EID 4624 Type 3 + Sysmon EID 3 loopback."
    reversible: true
    telemetry:
      - "Sysmon EID 1: net.exe with use \\\\127.0.0.1\\ADMIN$ argument"
      - "Security EID 4624: Logon Type 3 (network) from 127.0.0.1 to ADMIN$"
      - "Security EID 5140: network share ADMIN$ accessed"
    detection:
      - "EDR: net use to ADMIN$ from PowerShell  -  Sigma rule proc_creation_win_net_admin_share_access.yml"
      - "SIEM: EID 5140 access to ADMIN$ outside of IT provisioning window — lateral movement IOC"
    command: |
      $ErrorActionPreference = 'SilentlyContinue'
      $netOut = & net use '\\127.0.0.1\ADMIN$' 2>&1 | Out-String
      & net use '\\127.0.0.1\ADMIN$' /delete 2>&1 | Out-Null
      $accessible = $netOut -match 'command completed successfully'
      $authFailed = $netOut -match 'System error 5|Access is denied|System error 1326|logon failure'
      if ($accessible) {
        Write-Output "EXEC T1021.002: \\\\127.0.0.1\\ADMIN$ accessible with current token (disconnected). Akira would use harvested creds here to push its encryptor laterally. Security EID 5140 logged. [BAS-SIM-AKIRA-S5]"
        Write-Output "FAIL: ADMIN$ share accessible from user context — disable admin shares via GPO (AutoShareWks=0) or ensure SMB signing + LAPS is enforced."
      } elseif ($authFailed) {
        Write-Output "PASS: ADMIN$ access denied (auth failure or disabled)  -  lateral movement via admin share blocked. [BAS-SIM-AKIRA-S5]"
      } else {
        Write-Output "INFO: ADMIN$ probe result inconclusive: $($netOut.Trim()). [BAS-SIM-AKIRA-S5]"
      }
    cleanup: |
      & net use '\\127.0.0.1\ADMIN$' /delete 2>&1 | Out-Null

  # ---------------------------------------------------------------------------
  # Stage 6 — Ransomware Impact Simulation (T1486)
  # ---------------------------------------------------------------------------
  - name: "Akira Stage 6 — Ransomware Payload Simulation (T1486)"
    technique_id: T1486
    detection_profiles:
      - windows_ransomware_encryption
    framework: custom
    executor: powershell
    requires_priv: user
    timeout_sec: 30
    fidelity: telemetry-safe
    production_safe: true
    risk: low
    blast_radius: "Creates one BAS-owned plaintext file in %TEMP%, XOR-encodes it (simulating encryption), writes a benign ransom note ([BAS-SIM-AKIRA] only), then DELETES BOTH immediately. No user data touched. No real ransomware code. Generates Sysmon EID 11 (file create x2) and EID 23 (file delete x2)."
    reversible: true
    telemetry:
      - "Sysmon EID 11: bas_akira_<id>.txt created in %TEMP%"
      - "Sysmon EID 11: bas_akira_<id>.akira (encrypted simulation) created"
      - "Sysmon EID 11: bas_ransom_<id>.txt (ransom note) created"
      - "Sysmon EID 23: all files deleted in cleanup"
    detection:
      - "EDR: high-frequency file create + rename + delete in short window  -  Sigma rule win_security_susp_file_modifications.yml"
      - "Defender: ransom-pattern file creation heuristic (many .akira extension files)"
      - "EDR: PowerShell creating and immediately deleting files with suspicious extension"
    command: |
      $ErrorActionPreference = 'SilentlyContinue'
      $runId = if ($env:BAS_RUN_ID) { $env:BAS_RUN_ID.Substring(0,[Math]::Min(8,$env:BAS_RUN_ID.Length)) } else { '{0:x8}' -f (Get-Random -Maximum 0x7FFFFFFF) }
      $plainFile = Join-Path $env:TEMP "bas_akira_$runId.txt"
      $encFile   = Join-Path $env:TEMP "bas_akira_$runId.akira"
      $noteFile  = Join-Path $env:TEMP "bas_ransom_$runId.txt"
      $plainContent = '[BAS-SIM-AKIRA] T1486 ransomware simulation target file'
      [System.IO.File]::WriteAllText($plainFile, $plainContent, [System.Text.Encoding]::UTF8)
      # Simulate XOR encryption (key=0x41 = 'A' for Akira)
      $key = 0x41
      $bytes = [System.Text.Encoding]::UTF8.GetBytes($plainContent)
      $enc   = $bytes | ForEach-Object { $_ -bxor $key }
      [System.IO.File]::WriteAllBytes($encFile, [byte[]]$enc)
      $note = '[BAS-SIM-AKIRA] Akira Ransomware Simulation Note' + [char]13 + [char]10 +
              'This is a BAS simulation. No real files were encrypted.' + [char]13 + [char]10 +
              'Run ID: ' + $runId
      [System.IO.File]::WriteAllText($noteFile, $note, [System.Text.Encoding]::UTF8)
      $created = (Test-Path $plainFile) -and (Test-Path $encFile) -and (Test-Path $noteFile)
      Remove-Item $plainFile,$encFile,$noteFile -Force -ErrorAction SilentlyContinue
      $cleaned = -not (Test-Path $plainFile) -and -not (Test-Path $encFile) -and -not (Test-Path $noteFile)
      if ($created) {
        Write-Output "EXEC T1486: ransomware simulation completed — target file XOR-encoded (.akira), ransom note written, all cleaned=$cleaned. Sysmon EID 11+23 expected. [BAS-SIM-AKIRA-S6]"
        Write-Output "FAIL: File encryption simulation ran unblocked. Defender ransomware protection and controlled folder access should have flagged this pattern."
      } else {
        Write-Output "PASS: Ransomware simulation file creation blocked  -  Controlled Folder Access or EDR prevented file write to %TEMP%. [BAS-SIM-AKIRA-S6]"
      }
    cleanup: |
      Remove-Item (Join-Path $env:TEMP 'bas_akira_*') -Force -ErrorAction SilentlyContinue
      Remove-Item (Join-Path $env:TEMP 'bas_ransom_*') -Force -ErrorAction SilentlyContinue

  # ---------------------------------------------------------------------------
  # Stage 7 — Recovery Inhibition A: VSS Enumeration (T1490)
  # ---------------------------------------------------------------------------
  - name: "Akira Stage 7 — VSS Snapshot Enumeration (T1490)"
    technique_id: T1490
    detection_profiles:
      - windows_vss_inhibition
    framework: custom
    executor: powershell
    requires_priv: admin
    timeout_sec: 20
    fidelity: telemetry-safe
    production_safe: true
    risk: low
    blast_radius: "Runs vssadmin list shadows to enumerate VSS snapshots (READ ONLY). Akira deletes these via WMI Win32_ShadowCopy.Delete() (see Stage 8) — we enumerate only to show the attack surface. Generates Sysmon EID 1: vssadmin.exe with 'list' argument."
    reversible: true
    telemetry:
      - "Sysmon EID 1: vssadmin.exe list shadows (pre-wipe reconnaissance)"
      - "Security EID 4688: vssadmin.exe spawned by powershell.exe"
    detection:
      - "EDR: vssadmin.exe invoked from PowerShell  -  Sigma rule proc_creation_win_vssadmin_susp_commands.yml"
      - "SIEM: vssadmin list shadows — pre-ransomware VSS enumeration IOC"
    command: |
      $ErrorActionPreference = 'SilentlyContinue'
      $vssOut = & vssadmin.exe list shadows 2>&1 | Out-String
      $shadowCount = ([regex]::Matches($vssOut, 'Shadow Copy ID')).Count
      if ($shadowCount -gt 0) {
        Write-Output "EXEC T1490: $shadowCount VSS shadow copy(ies) enumerated. Akira would now delete these via WMI Win32_ShadowCopy.Delete() to destroy backups. Sysmon EID 1 vssadmin.exe logged. [BAS-SIM-AKIRA-S7]"
        Write-Output "FAIL: VSS snapshots exist and are enumerable ($shadowCount found). If Akira reached this stage, backups would be destroyed before encryption. Ensure immutable cloud backup or Veeam hardened repo is NOT reachable from endpoint."
      } else {
        Write-Output "PASS: No VSS shadow copies found or vssadmin blocked  -  recovery inhibition surface is reduced. [BAS-SIM-AKIRA-S7]"
      }
    cleanup: ""

  # ---------------------------------------------------------------------------
  # Stage 8 — Recovery Inhibition B: VSS Deletion via WMI (T1490, lab-only)
  # ---------------------------------------------------------------------------
  - name: "Akira Stage 8 — VSS Shadow Copy Deletion via WMI (lab  -  requires BAS_CONFIRM_VSS_DELETE=true) (T1490)"
    technique_id: T1490
    detection_profiles:
      - windows_vss_inhibition
    framework: custom
    executor: powershell
    requires_priv: admin
    timeout_sec: 60
    fidelity: lab-only
    production_safe: false
    risk: high
    blast_radius: "Deletes ONE oldest VSS shadow copy of C: via WMI Win32_ShadowCopy.Delete() -- Akira's exact documented command style (CISA AA24-109A: 'Get-WmiObject Win32_Shadowcopy | ForEach-Object {$_.Delete()}'), as opposed to LockBit/BlackCat's vssadmin-based deletion. Requires explicit BAS_CONFIRM_VSS_DELETE=true env var and verifies a snapshot exists first. Default-disabled without the flag."
    reversible: false
    telemetry:
      - "Security EID 8224 (VSS service shutdown) + EID 524 (shadow copy deletion)"
      - "PowerShell EID 4104: Get-WmiObject Win32_ShadowCopy | ForEach-Object Delete()"
    detection:
      - "EDR: PowerShell WMI-based shadow copy deletion (Win32_ShadowCopy.Delete())  -  Akira's documented signature VSS-kill pattern, distinct from vssadmin.exe"
      - "SIEM: shadow copy count decrease; alert if count drops to 0"
    command: |
      $ErrorActionPreference = 'SilentlyContinue'
      $confirm = $env:BAS_CONFIRM_VSS_DELETE
      if (-not $confirm -or $confirm -ne 'true') {
        Write-Output "SKIP: BAS_CONFIRM_VSS_DELETE not set to 'true'  -  WMI-based VSS deletion skipped (default-disabled per ransomware safety policy). Set env var explicitly in isolated lab to enable. [BAS-SIM-AKIRA-S8]"
        return
      }
      $shadows = Get-WmiObject Win32_ShadowCopy -ErrorAction SilentlyContinue | Where-Object { $_.VolumeName -match 'C:' }
      if (-not $shadows -or @($shadows).Count -eq 0) {
        Write-Output "SKIP: no C: VSS shadow copies exist  -  nothing to delete. Create a snapshot first with: vssadmin create shadow /for=C:"
        return
      }
      $oldest = @($shadows | Sort-Object InstallDate)[0]
      $oldest.Delete()
      $remaining = @(Get-WmiObject Win32_ShadowCopy -ErrorAction SilentlyContinue | Where-Object { $_.VolumeName -match 'C:' }).Count
      Write-Output "FAIL: VSS shadow copy deleted via WMI Win32_ShadowCopy.Delete() -- Akira's exact documented command is 'Get-WmiObject Win32_Shadowcopy | ForEach-Object {\$_.Delete()}'. $remaining shadow copy/copies remaining on C:. Create a new snapshot to restore recovery capability. [BAS-SIM-AKIRA-S8]"
    cleanup: ""

  # ---------------------------------------------------------------------------
  # Stage 9 — Indicator Removal: Event Log Clearing Attempt (T1070.001)
  # ---------------------------------------------------------------------------
  - name: "Akira Stage 9 — Event Log Clearing Attempt (T1070.001)"
    technique_id: T1070.001
    detection_profiles:
      - windows_log_manipulation
    framework: custom
    executor: powershell
    requires_priv: admin
    timeout_sec: 20
    fidelity: telemetry-safe
    production_safe: true
    risk: low
    blast_radius: "Creates a BAS-owned custom event log (BAS-Sim-Akira), attempts wevtutil cl on it, then removes the log. Does NOT touch System/Security/Application logs. Generates Security EID 1102 if the clear succeeds, and Sysmon EID 1 wevtutil.exe."
    reversible: true
    telemetry:
      - "Sysmon EID 1: wevtutil.exe with cl argument (log-clearing pattern)"
      - "Security EID 1102: audit log cleared (if wevtutil cl succeeds on custom log)"
      - "Security EID 4688: wevtutil.exe spawned by powershell.exe"
    detection:
      - "EDR: wevtutil.exe with 'cl' argument  -  Sigma rule proc_creation_win_wevtutil_clear_logs.yml"
      - "SIEM: Security EID 1102 event log cleared  -  high-priority anti-forensics IOC"
      - "SIEM: wevtutil.exe invoked from PowerShell at unusual time"
    command: |
      $ErrorActionPreference = 'SilentlyContinue'
      $logName = 'BAS-Sim-Akira'
      $exists = [System.Diagnostics.EventLog]::Exists($logName)
      if (-not $exists) {
        try { New-EventLog -LogName $logName -Source 'BAS-Sim' -ErrorAction Stop } catch {}
      }
      $created = [System.Diagnostics.EventLog]::Exists($logName)
      if ($created) {
        $clOut = & wevtutil.exe cl $logName 2>&1 | Out-String
        $cleared = $clOut -notmatch 'Access is denied|The specified channel could not be found|error'
        try { Remove-EventLog -LogName $logName -ErrorAction SilentlyContinue } catch {}
        if ($cleared) {
          Write-Output "EXEC T1070.001: wevtutil cl on BAS custom log succeeded (exit 0). Akira uses 'wevtutil cl System' 'wevtutil cl Security' after ransomware deployment. Sysmon EID 1 wevtutil.exe logged. [BAS-SIM-AKIRA-S9]"
          Write-Output "FAIL: wevtutil cl ran without EDR intervention. Ensure wevtutil.exe invocation from PowerShell triggers an alert. Security EID 1102 should generate a SIEM alert."
        } else {
          Write-Output "PASS: wevtutil cl was blocked or failed  -  $($clOut.Trim()). [BAS-SIM-AKIRA-S9]"
        }
      } else {
        Write-Output "SKIP: Could not create test event log (insufficient privilege). wevtutil cl test skipped. [BAS-SIM-AKIRA-S9]"
      }
    cleanup: |
      try { Remove-EventLog -LogName 'BAS-Sim-Akira' -ErrorAction SilentlyContinue } catch {}
```

- [ ] **Step 2: Validate YAML structural validity**

```bash
python3 -c "import yaml; yaml.safe_load(open('scenarios/akira-kill-chain.yaml')); print('OK')"
```
Expected: `OK`, no exceptions.

- [ ] **Step 3: Manual PowerShell syntax sanity check**

Same procedure as Task 2 Step 3, applied to all 9 `command:` blocks and 6 non-empty `cleanup:` blocks in this file.
Expected: no parse errors for any block.

- [ ] **Step 4: Sign the file**

From `orchestrator/`:
```bash
go run scripts/signer.go sign private_key.pem ../scenarios/akira-kill-chain.yaml
```
Expected: `akira-kill-chain.yaml.sig` created, no errors.

- [ ] **Step 5: Commit**

```bash
git add scenarios/akira-kill-chain.yaml scenarios/akira-kill-chain.yaml.sig
git commit -m "feat(scenarios): Akira kill-chain scenario (Ransomware Readiness Deliverable 2)"
git push
```

---

## Task 4: `play-kill-chain.yaml`

**Files:**
- Create: `scenarios/play-kill-chain.yaml` (+ `.sig`)

**Interfaces:**
- Consumes: `windows_ad_discovery`, `windows_vulnerable_driver_load` (Task 1) plus existing profiles `windows_network_share_discovery`, `windows_defender_tampering`, `windows_smb_lateral_probe`, `windows_ransomware_encryption`, `windows_vss_inhibition`, `windows_log_manipulation`.

**Safety notes:** Stage 3 (Defender RTP disable) is `fidelity: lab-only` / `production_safe: false`, same classification already shipped elsewhere. Stage 4 (BYOVD probe) never loads a real driver — `binPath` points at a guaranteed-nonexistent file; the kernel-service registration itself is real (and is exactly what should be flagged), but code execution is physically impossible.

- [ ] **Step 1: Create `scenarios/play-kill-chain.yaml`**

```yaml
id: play-kill-chain
name: Play Kill Chain — Ransomware Emulation
description: >
  Eight-stage telemetry-safe emulation of the Play (Playcrypt) ransomware
  kill chain targeting Windows endpoints. Reflects documented Play
  tradecraft validated against CISA AA23-352A: ProxyNotShell/FortiOS
  exploitation, AdFind + Grixba-style AD/network recon, GPO-pushed
  Defender disable, intermittent encryption, and a documented .PLAY
  extension.

  KILL CHAIN STAGES:
    1. Discovery              — AdFind-style AD enumeration (T1087.002)
    2. Discovery              — Grixba-style network/share scan (T1135)
    3. Defense Evasion        — GPO-style Defender RTP disable (T1562.001)
    4. Defense Evasion        — EDR-killer / vulnerable-driver staging probe (T1562.001)
    5. Lateral Movement       — SMB admin share reachability check (T1021.002)
    6. Ransomware Simulation  — XOR-encoded benign file + ransom note, .PLAY extension (T1486)
    7. Recovery Inhibition    — VSS snapshot enumeration (T1490)
    8. Log Clearing Attempt   — wevtutil cl attempt, blocked or audit (T1070.001)

  NOTE: Play's real initial access — ProxyNotShell (CVE-2022-41040 /
  CVE-2022-41082) or FortiOS (CVE-2018-13379 / CVE-2020-12812) exploitation
  — is not represented as an executable step since a specific vulnerable
  app is rarely present on a generic endpoint; a step that SKIPs almost
  universally has no testing value.

  SAFETY: No real encryption of user data. XOR is applied to a single BAS-
  created temp file with [BAS-SIM-PLAY] content only. Ransom note is
  cleaned up immediately. Stage 3 is lab-only (self-restores within the
  step, excluded from production campaigns via fidelity metadata). Stage 4
  never loads a real driver -- the kernel-service binPath points at a
  file that is guaranteed not to exist, so the load is physically
  impossible; only the (real, detectable) service-registration call
  happens. All other stages are production-safe. Windows only. [BAS-SIM]
  tagged throughout.
author: Audspect Research
executable: true
local_check: false
supported_os: [windows]
tags:
  - play
  - playcrypt
  - ransomware
  - bfsi
  - kill-chain
  - t1021
  - t1070
  - t1086
  - t1087
  - t1135
  - t1486
  - t1490
  - t1562
  - mitre
mitre_phases:
  - discovery
  - defense-evasion
  - lateral-movement
  - impact

live_policy:
  block_on_domain_controller: false
  require_dc_reachable: false
  max_spray_attempts: 0
  spray_account_allowlist: []
  execution_window: ""

steps:

  # ---------------------------------------------------------------------------
  # Stage 1 — Discovery: AdFind-Style AD Enumeration (T1087.002)
  # ---------------------------------------------------------------------------
  - name: "Play Stage 1 — AdFind-Style AD Enumeration (T1087.002)"
    technique_id: T1087.002
    detection_profiles:
      - windows_ad_discovery
    framework: custom
    executor: powershell
    requires_priv: user
    timeout_sec: 30
    fidelity: telemetry-safe
    production_safe: true
    risk: low
    blast_radius: "Runs net group \"Domain Admins\" /domain, net view, and nltest /dclist: (all read-only, current-token). No accounts touched. Generates Sysmon EID 1 (net.exe / nltest.exe)."
    reversible: true
    telemetry:
      - "Sysmon EID 1: net.exe group / view, nltest.exe /dclist"
      - "Security EID 4688: net.exe and nltest.exe spawned by powershell.exe"
    detection:
      - "EDR: nltest.exe /dclist and net group 'Domain Admins' /domain from a single host — Sigma rule proc_creation_win_net_enum.yml"
      - "SIEM: domain-controller and privileged-group enumeration chained together — pre-credential-theft recon IOC"
    command: |
      $ErrorActionPreference = 'SilentlyContinue'
      $domainAdmins = & net.exe group "Domain Admins" /domain 2>&1 | Out-String
      $computers    = & net.exe view 2>&1 | Out-String
      $dcList       = & nltest.exe /dclist: 2>&1 | Out-String
      $domainJoined = $domainAdmins -notmatch 'workstation is not|not be found|is not part'
      Write-Output "EXEC T1087.002: AdFind/Grixba-style domain enumeration -- Domain Admins group, network computer list (net view), and DC list (nltest) queried (domain_joined=$domainJoined). Play uses AdFind for AD queries and Grixba to scan for security software before deployment. [BAS-SIM-PLAY-S1]"
      Write-Output "FAIL: domain enumeration completed unimpeded via built-in LOLBins (net.exe, nltest.exe) -- no AdFind binary required. Alert on nltest.exe /dclist and net group 'Domain Admins' /domain from non-IT accounts."
    cleanup: ""

  # ---------------------------------------------------------------------------
  # Stage 2 — Discovery: Grixba-Style Network & Share Scan (T1135)
  # ---------------------------------------------------------------------------
  - name: "Play Stage 2 — Grixba-Style Network & Share Discovery (T1135)"
    technique_id: T1135
    detection_profiles:
      - windows_network_share_discovery
    framework: custom
    executor: powershell
    requires_priv: user
    timeout_sec: 30
    fidelity: telemetry-safe
    production_safe: true
    risk: low
    reversible: true
    blast_radius: "Enumerates local administrative shares via net view and WMI Win32_Share. No shares accessed, no files read."
    telemetry:
      - "Security EID 4688: net.exe and powershell.exe share enumeration"
      - "Security EID 5140: if SACL object access auditing enabled on shares"
    detection:
      - "SIEM: net view / Win32_Share query from non-admin process — ransomware lateral-spread staging signal, matches Play's Grixba network scanner behavior"
    command: |
      $ErrorActionPreference = 'SilentlyContinue'
      $wmiShares = @(Get-WmiObject -Class Win32_Share -ErrorAction SilentlyContinue)
      $netOut = & net view \\$env:COMPUTERNAME 2>&1
      $shareCount = if ($wmiShares) { $wmiShares.Count } else { 0 }
      Write-Output "EXEC: network share discovery — $shareCount share(s) via Win32_Share. net view executed for cmdline telemetry. Play's Grixba tool performs this same network/share scan to identify lateral-movement and security-software targets. [BAS-SIM-PLAY-S2]"
    cleanup: ""

  # ---------------------------------------------------------------------------
  # Stage 3 — Defense Evasion: GPO-Style Defender RTP Disable (T1562.001)
  # ---------------------------------------------------------------------------
  - name: "Play Stage 3 — GPO-Style Defender RTP Disable (lab  -  mandatory restoration + health check) (T1562.001)"
    technique_id: T1562.001
    detection_profiles:
      - windows_defender_tampering
    framework: custom
    executor: powershell
    requires_priv: admin
    timeout_sec: 45
    fidelity: lab-only
    production_safe: false
    risk: high
    blast_radius: "Attempts to disable Defender Real-Time Protection via Set-MpPreference (Play pushes this via GPO across the domain in real incidents; this step simulates the single-endpoint effect). Immediately re-enables. Post-test health verification confirms restoration. EDR will alert."
    reversible: true
    telemetry:
      - "Security EID 4657 (registry value modified): HKLM\\...\\Windows Defender\\DisableRealtimeMonitoring"
      - "Defender event log: EID 5001 (RTP disabled) + EID 5000 (re-enabled)"
    detection:
      - "EDR: Defender RTP disabled  -  immediate P1 alert in any mature SOC"
      - "SIEM: WMI/registry change to Defender configuration from non-management process, or GPO push targeting Defender settings"
    command: |
      $ErrorActionPreference = 'SilentlyContinue'
      $before = (Get-MpComputerStatus -ErrorAction SilentlyContinue).RealTimeProtectionEnabled
      Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue
      $disabled = -not (Get-MpComputerStatus -ErrorAction SilentlyContinue).RealTimeProtectionEnabled
      Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction SilentlyContinue
      $restored = (Get-MpComputerStatus -ErrorAction SilentlyContinue).RealTimeProtectionEnabled
      $tamperBlocked = (Get-MpComputerStatus -ErrorAction SilentlyContinue).IsTamperProtected
      if (-not $disabled) {
        Write-Output "PASS: Defender RTP disable attempt failed  -  Tamper Protection or EDR blocked the change (tamperProtected=$tamperBlocked). [BAS-SIM-PLAY-S3]"
      } elseif ($restored) {
        Write-Output "FAIL: Defender RTP was disabled then re-enabled (restoration verified=true). HEALTH: RTP now $restored, tamperProtected=$tamperBlocked. Expect Defender EID 5001+5000. [BAS-SIM-PLAY-S3]"
      } else {
        Set-MpPreference -DisableRealtimeMonitoring $false -Force -ErrorAction SilentlyContinue
        Write-Output "CRITICAL: Defender RTP disabled and re-enable failed  -  manual restoration required. Run: Set-MpPreference -DisableRealtimeMonitoring $false [BAS-SIM-PLAY-S3]"
      }
    cleanup: |
      Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction SilentlyContinue

  # ---------------------------------------------------------------------------
  # Stage 4 — Defense Evasion: EDR-Killer / BYOVD Staging Probe (T1562.001)
  # ---------------------------------------------------------------------------
  - name: "Play Stage 4 — EDR-Killer / Vulnerable-Driver Staging Probe (T1562.001)"
    technique_id: T1562.001
    detection_profiles:
      - windows_vulnerable_driver_load
    framework: custom
    executor: powershell
    requires_priv: admin
    timeout_sec: 20
    fidelity: telemetry-safe
    production_safe: true
    risk: low
    blast_radius: "Registers a kernel-type Windows service via sc.exe pointing at a guaranteed-nonexistent driver file path, then immediately deletes the service. No driver is ever loaded -- the binPath never resolves, so the load is physically impossible. Only the service-registration API call happens. Generates Security EID 4697/7045 (service installed) + EID 4688 (sc.exe create/delete)."
    reversible: true
    telemetry:
      - "Security EID 4697 / 7045: kernel-type service installed"
      - "Security EID 4688: sc.exe create ... type= kernel / sc.exe delete"
    detection:
      - "EDR: sc.exe create with 'type= kernel' from a non-driver-installer process -- near-zero-false-positive BYOVD staging IOC used by RansomHub's EDRKillShifter tool, also documented reused by Play affiliates per Halcyon reporting (2024)"
      - "SIEM: enforce the Microsoft-recommended vulnerable-driver blocklist / HVCI"
    command: |
      $ErrorActionPreference = 'SilentlyContinue'
      $svcName = 'BAS-Sim-EDRKill-Probe'
      $bogusPath = 'C:\Windows\Temp\bas_edrkill_probe_nonexistent.sys'
      & sc.exe create $svcName type= kernel binPath= $bogusPath start= demand 2>&1 | Out-Null
      $created = (& sc.exe query $svcName 2>&1 | Out-String) -match 'SERVICE_NAME'
      & sc.exe delete $svcName 2>&1 | Out-Null
      if ($created) {
        Write-Output "EXEC T1562.001: kernel-mode service registration succeeded (no driver code executed -- binPath points to a nonexistent file, load is physically impossible). Play affiliates have been documented reusing RansomHub's EDRKillShifter BYOVD tool to disable EDR before encryption. [BAS-SIM-PLAY-S4]"
        Write-Output "FAIL: kernel-type service creation via sc.exe was not blocked. Alert on 'sc create ... type= kernel' from non-driver-installer processes -- this is a near-zero-false-positive BYOVD precursor."
      } else {
        Write-Output "PASS: kernel-type service registration was blocked or denied -- BYOVD staging surface is reduced. [BAS-SIM-PLAY-S4]"
      }
    cleanup: |
      & sc.exe delete BAS-Sim-EDRKill-Probe 2>&1 | Out-Null

  # ---------------------------------------------------------------------------
  # Stage 5 — Lateral Movement: SMB Admin Share Probe (T1021.002)
  # ---------------------------------------------------------------------------
  - name: "Play Stage 5 — SMB Admin Share Lateral Movement Probe (T1021.002)"
    technique_id: T1021.002
    detection_profiles:
      - windows_smb_lateral_probe
    framework: custom
    executor: powershell
    requires_priv: user
    timeout_sec: 20
    fidelity: telemetry-safe
    production_safe: true
    risk: low
    blast_radius: "Tests whether \\127.0.0.1\\ADMIN$ is accessible with the current user token via net use (loopback). Disconnects immediately. Generates Security EID 4624 Type 3 + Sysmon EID 3 loopback."
    reversible: true
    telemetry:
      - "Sysmon EID 1: net.exe with use \\\\127.0.0.1\\ADMIN$ argument"
      - "Security EID 4624: Logon Type 3 (network) from 127.0.0.1 to ADMIN$"
      - "Security EID 5140: network share ADMIN$ accessed"
    detection:
      - "EDR: net use to ADMIN$ from PowerShell  -  Sigma rule proc_creation_win_net_admin_share_access.yml"
      - "SIEM: EID 5140 access to ADMIN$ outside of IT provisioning window — lateral movement IOC"
    command: |
      $ErrorActionPreference = 'SilentlyContinue'
      $netOut = & net use '\\127.0.0.1\ADMIN$' 2>&1 | Out-String
      & net use '\\127.0.0.1\ADMIN$' /delete 2>&1 | Out-Null
      $accessible = $netOut -match 'command completed successfully'
      $authFailed = $netOut -match 'System error 5|Access is denied|System error 1326|logon failure'
      if ($accessible) {
        Write-Output "EXEC T1021.002: \\\\127.0.0.1\\ADMIN$ accessible with current token (disconnected). Play would use harvested creds here to push its encryptor laterally. Security EID 5140 logged. [BAS-SIM-PLAY-S5]"
        Write-Output "FAIL: ADMIN$ share accessible from user context — disable admin shares via GPO (AutoShareWks=0) or ensure SMB signing + LAPS is enforced."
      } elseif ($authFailed) {
        Write-Output "PASS: ADMIN$ access denied (auth failure or disabled)  -  lateral movement via admin share blocked. [BAS-SIM-PLAY-S5]"
      } else {
        Write-Output "INFO: ADMIN$ probe result inconclusive: $($netOut.Trim()). [BAS-SIM-PLAY-S5]"
      }
    cleanup: |
      & net use '\\127.0.0.1\ADMIN$' /delete 2>&1 | Out-Null

  # ---------------------------------------------------------------------------
  # Stage 6 — Ransomware Impact Simulation (T1486)
  # ---------------------------------------------------------------------------
  - name: "Play Stage 6 — Ransomware Payload Simulation (T1486)"
    technique_id: T1486
    detection_profiles:
      - windows_ransomware_encryption
    framework: custom
    executor: powershell
    requires_priv: user
    timeout_sec: 30
    fidelity: telemetry-safe
    production_safe: true
    risk: low
    blast_radius: "Creates one BAS-owned plaintext file in %TEMP%, XOR-encodes it (simulating encryption), writes a benign ransom note ([BAS-SIM-PLAY] only), then DELETES BOTH immediately. No user data touched. No real ransomware code. Generates Sysmon EID 11 (file create x2) and EID 23 (file delete x2). Real Play uses intermittent (partial-file) encryption to evade heuristics -- not functionally replicated here since chunk size does not change the endpoint detection surface being validated."
    reversible: true
    telemetry:
      - "Sysmon EID 11: bas_play_<id>.txt created in %TEMP%"
      - "Sysmon EID 11: bas_play_<id>.PLAY (encrypted simulation) created"
      - "Sysmon EID 11: bas_ransom_<id>.txt (ransom note) created"
      - "Sysmon EID 23: all files deleted in cleanup"
    detection:
      - "EDR: high-frequency file create + rename + delete in short window  -  Sigma rule win_security_susp_file_modifications.yml"
      - "Defender: ransom-pattern file creation heuristic (many .PLAY extension files -- Play's real, documented extension)"
      - "EDR: PowerShell creating and immediately deleting files with suspicious extension"
    command: |
      $ErrorActionPreference = 'SilentlyContinue'
      $runId = if ($env:BAS_RUN_ID) { $env:BAS_RUN_ID.Substring(0,[Math]::Min(8,$env:BAS_RUN_ID.Length)) } else { '{0:x8}' -f (Get-Random -Maximum 0x7FFFFFFF) }
      $plainFile = Join-Path $env:TEMP "bas_play_$runId.txt"
      $encFile   = Join-Path $env:TEMP "bas_play_$runId.PLAY"
      $noteFile  = Join-Path $env:TEMP "bas_ransom_$runId.txt"
      $plainContent = '[BAS-SIM-PLAY] T1486 ransomware simulation target file'
      [System.IO.File]::WriteAllText($plainFile, $plainContent, [System.Text.Encoding]::UTF8)
      # Simulate XOR encryption (key=0x50 = 'P' for Play)
      $key = 0x50
      $bytes = [System.Text.Encoding]::UTF8.GetBytes($plainContent)
      $enc   = $bytes | ForEach-Object { $_ -bxor $key }
      [System.IO.File]::WriteAllBytes($encFile, [byte[]]$enc)
      $note = '[BAS-SIM-PLAY] Play Ransomware Simulation Note' + [char]13 + [char]10 +
              'This is a BAS simulation. No real files were encrypted.' + [char]13 + [char]10 +
              'Run ID: ' + $runId
      [System.IO.File]::WriteAllText($noteFile, $note, [System.Text.Encoding]::UTF8)
      $created = (Test-Path $plainFile) -and (Test-Path $encFile) -and (Test-Path $noteFile)
      Remove-Item $plainFile,$encFile,$noteFile -Force -ErrorAction SilentlyContinue
      $cleaned = -not (Test-Path $plainFile) -and -not (Test-Path $encFile) -and -not (Test-Path $noteFile)
      if ($created) {
        Write-Output "EXEC T1486: ransomware simulation completed — target file XOR-encoded (.PLAY), ransom note written, all cleaned=$cleaned. Sysmon EID 11+23 expected. [BAS-SIM-PLAY-S6]"
        Write-Output "FAIL: File encryption simulation ran unblocked. Defender ransomware protection and controlled folder access should have flagged this pattern."
      } else {
        Write-Output "PASS: Ransomware simulation file creation blocked  -  Controlled Folder Access or EDR prevented file write to %TEMP%. [BAS-SIM-PLAY-S6]"
      }
    cleanup: |
      Remove-Item (Join-Path $env:TEMP 'bas_play_*') -Force -ErrorAction SilentlyContinue
      Remove-Item (Join-Path $env:TEMP 'bas_ransom_*') -Force -ErrorAction SilentlyContinue

  # ---------------------------------------------------------------------------
  # Stage 7 — Recovery Inhibition: VSS Enumeration (T1490)
  # ---------------------------------------------------------------------------
  - name: "Play Stage 7 — VSS Snapshot Enumeration (T1490)"
    technique_id: T1490
    detection_profiles:
      - windows_vss_inhibition
    framework: custom
    executor: powershell
    requires_priv: admin
    timeout_sec: 20
    fidelity: telemetry-safe
    production_safe: true
    risk: low
    blast_radius: "Runs vssadmin list shadows to enumerate VSS snapshots (READ ONLY). Play deletes these via vssadmin after Grixba-driven recon completes — we enumerate only to show the attack surface. Generates Sysmon EID 1: vssadmin.exe with 'list' argument."
    reversible: true
    telemetry:
      - "Sysmon EID 1: vssadmin.exe list shadows (pre-wipe reconnaissance)"
      - "Security EID 4688: vssadmin.exe spawned by powershell.exe"
    detection:
      - "EDR: vssadmin.exe invoked from PowerShell  -  Sigma rule proc_creation_win_vssadmin_susp_commands.yml"
      - "SIEM: vssadmin list shadows — pre-ransomware VSS enumeration IOC"
    command: |
      $ErrorActionPreference = 'SilentlyContinue'
      $vssOut = & vssadmin.exe list shadows 2>&1 | Out-String
      $shadowCount = ([regex]::Matches($vssOut, 'Shadow Copy ID')).Count
      if ($shadowCount -gt 0) {
        Write-Output "EXEC T1490: $shadowCount VSS shadow copy(ies) enumerated. Play would now run 'vssadmin delete shadows /all /quiet' to destroy backups. Sysmon EID 1 vssadmin.exe logged. [BAS-SIM-PLAY-S7]"
        Write-Output "FAIL: VSS snapshots exist and are enumerable ($shadowCount found). If Play reached this stage, backups would be destroyed before encryption. Ensure immutable cloud backup or Veeam hardened repo is NOT reachable from endpoint."
      } else {
        Write-Output "PASS: No VSS shadow copies found or vssadmin blocked  -  recovery inhibition surface is reduced. [BAS-SIM-PLAY-S7]"
      }
    cleanup: ""

  # ---------------------------------------------------------------------------
  # Stage 8 — Indicator Removal: Event Log Clearing Attempt (T1070.001)
  # ---------------------------------------------------------------------------
  - name: "Play Stage 8 — Event Log Clearing Attempt (T1070.001)"
    technique_id: T1070.001
    detection_profiles:
      - windows_log_manipulation
    framework: custom
    executor: powershell
    requires_priv: admin
    timeout_sec: 20
    fidelity: telemetry-safe
    production_safe: true
    risk: low
    blast_radius: "Creates a BAS-owned custom event log (BAS-Sim-Play), attempts wevtutil cl on it, then removes the log. Does NOT touch System/Security/Application logs. Generates Security EID 1102 if the clear succeeds, and Sysmon EID 1 wevtutil.exe."
    reversible: true
    telemetry:
      - "Sysmon EID 1: wevtutil.exe with cl argument (log-clearing pattern)"
      - "Security EID 1102: audit log cleared (if wevtutil cl succeeds on custom log)"
      - "Security EID 4688: wevtutil.exe spawned by powershell.exe"
    detection:
      - "EDR: wevtutil.exe with 'cl' argument  -  Sigma rule proc_creation_win_wevtutil_clear_logs.yml"
      - "SIEM: Security EID 1102 event log cleared  -  high-priority anti-forensics IOC"
      - "SIEM: wevtutil.exe invoked from PowerShell at unusual time"
    command: |
      $ErrorActionPreference = 'SilentlyContinue'
      $logName = 'BAS-Sim-Play'
      $exists = [System.Diagnostics.EventLog]::Exists($logName)
      if (-not $exists) {
        try { New-EventLog -LogName $logName -Source 'BAS-Sim' -ErrorAction Stop } catch {}
      }
      $created = [System.Diagnostics.EventLog]::Exists($logName)
      if ($created) {
        $clOut = & wevtutil.exe cl $logName 2>&1 | Out-String
        $cleared = $clOut -notmatch 'Access is denied|The specified channel could not be found|error'
        try { Remove-EventLog -LogName $logName -ErrorAction SilentlyContinue } catch {}
        if ($cleared) {
          Write-Output "EXEC T1070.001: wevtutil cl on BAS custom log succeeded (exit 0). Play uses PowerTool/GMER-class utilities and wevtutil to remove log files after deployment. Sysmon EID 1 wevtutil.exe logged. [BAS-SIM-PLAY-S8]"
          Write-Output "FAIL: wevtutil cl ran without EDR intervention. Ensure wevtutil.exe invocation from PowerShell triggers an alert. Security EID 1102 should generate a SIEM alert."
        } else {
          Write-Output "PASS: wevtutil cl was blocked or failed  -  $($clOut.Trim()). [BAS-SIM-PLAY-S8]"
        }
      } else {
        Write-Output "SKIP: Could not create test event log (insufficient privilege). wevtutil cl test skipped. [BAS-SIM-PLAY-S8]"
      }
    cleanup: |
      try { Remove-EventLog -LogName 'BAS-Sim-Play' -ErrorAction SilentlyContinue } catch {}
```

- [ ] **Step 2: Validate YAML structural validity**

```bash
python3 -c "import yaml; yaml.safe_load(open('scenarios/play-kill-chain.yaml')); print('OK')"
```
Expected: `OK`, no exceptions.

- [ ] **Step 3: Manual PowerShell syntax sanity check**

Same procedure as Task 2 Step 3, applied to all 8 `command:` blocks and 5 non-empty `cleanup:` blocks in this file.
Expected: no parse errors for any block.

- [ ] **Step 4: Sign the file**

From `orchestrator/`:
```bash
go run scripts/signer.go sign private_key.pem ../scenarios/play-kill-chain.yaml
```
Expected: `play-kill-chain.yaml.sig` created, no errors.

- [ ] **Step 5: Commit**

```bash
git add scenarios/play-kill-chain.yaml scenarios/play-kill-chain.yaml.sig
git commit -m "feat(scenarios): Play kill-chain scenario (Ransomware Readiness Deliverable 2)"
git push
```

---

## Task 5: `ransomhub-kill-chain.yaml`

**Files:**
- Create: `scenarios/ransomhub-kill-chain.yaml` (+ `.sig`)

**Interfaces:**
- Consumes: `windows_vulnerable_driver_load` (Task 1) plus existing profiles `windows_security_software_discovery`, `windows_network_share_discovery`, `windows_sam_theft`, `windows_defender_tampering`, `windows_ransomware_encryption`, `windows_vss_inhibition`, `windows_log_manipulation`.

**Safety notes:** Stage 5 (BYOVD probe) uses the identical safe design as Play's Stage 4 — same static service name `BAS-Sim-EDRKill-Probe`, guaranteed-nonexistent `binPath`, no real driver ever loads.

- [ ] **Step 1: Create `scenarios/ransomhub-kill-chain.yaml`**

```yaml
id: ransomhub-kill-chain
name: RansomHub Kill Chain — Ransomware Emulation
description: >
  Eight-stage telemetry-safe emulation of the RansomHub ransomware kill
  chain targeting Windows endpoints. Reflects documented RansomHub
  tradecraft validated against CISA AA24-242A: double-extortion RaaS
  (formerly Cyclops/Knight lineage) using the EDRKillShifter BYOVD tool
  (RentDrv2 / ThreatFireMonitor vulnerable drivers) to disable EDR before
  encryption.

  KILL CHAIN STAGES:
    1. Discovery              — security software discovery (T1518.001)
    2. Discovery              — network share discovery (T1135)
    3. Credential Access      — SAM/SYSTEM hive theft via reg save (T1003.002)
    4. Defense Evasion        — Defender exclusion invocation probe (T1562.001)
    5. Defense Evasion        — EDRKillShifter-style vulnerable-driver staging probe (T1562.001)
    6. Ransomware Simulation  — XOR-encoded benign file + double-extortion ransom note, .ransomhub extension (T1486)
    7. Recovery Inhibition    — VSS snapshot enumeration (T1490)
    8. Log Clearing Attempt   — wevtutil cl attempt, blocked or audit (T1070.001)

  NOTE: RansomHub's real initial access is RaaS affiliate-driven and varies
  per intrusion — not represented as a single executable step.

  SAFETY: No real encryption or exfiltration of user data. XOR is applied
  to a single BAS-created temp file with [BAS-SIM-RANSOMHUB] content only.
  Ransom note is cleaned up immediately. Stage 5 never loads a real driver
  -- the kernel-service binPath points at a file that is guaranteed not to
  exist, so the load is physically impossible; only the (real, detectable)
  service-registration call happens. All stages are production-safe.
  Windows only. [BAS-SIM] tagged throughout.
author: Audspect Research
executable: true
local_check: false
supported_os: [windows]
tags:
  - ransomhub
  - ransomware
  - bfsi
  - kill-chain
  - t1003
  - t1070
  - t1135
  - t1486
  - t1490
  - t1518
  - t1562
  - mitre
mitre_phases:
  - discovery
  - credential-access
  - defense-evasion
  - impact

live_policy:
  block_on_domain_controller: false
  require_dc_reachable: false
  max_spray_attempts: 0
  spray_account_allowlist: []
  execution_window: ""

steps:

  # ---------------------------------------------------------------------------
  # Stage 1 — Defense Discovery (T1518.001)
  # ---------------------------------------------------------------------------
  - name: "RansomHub Stage 1 — Security Software Discovery (T1518.001)"
    technique_id: T1518.001
    detection_profiles:
      - windows_security_software_discovery
    framework: custom
    executor: powershell
    requires_priv: user
    timeout_sec: 30
    fidelity: telemetry-safe
    production_safe: true
    risk: low
    blast_radius: "Queries WMI AntiVirusProduct, AntiSpywareProduct, FirewallProduct to enumerate installed security products. Read-only. Generates ScriptBlock EID 4104 and WMI-Activity EID 5857-5861."
    reversible: true
    telemetry:
      - "WMI-Activity EID 5857-5861: Get-WmiObject SecurityCenter2 query"
      - "PowerShell ScriptBlock EID 4104: AntiVirusProduct WMI class enumeration"
      - "Sysmon EID 1: powershell.exe WMI query (ransomware reconnaissance pattern)"
    detection:
      - "EDR: WMI security product enumeration from PowerShell  -  Sigma rule win_wmi_security_product_discovery.yml"
      - "SIEM: Get-WmiObject Win32_Product or SecurityCenter2 — pre-ransomware recon IOC"
    command: |
      $ErrorActionPreference = 'SilentlyContinue'
      $avProducts = Get-WmiObject -Namespace 'root\SecurityCenter2' -Class 'AntiVirusProduct' -ErrorAction SilentlyContinue
      $fwProducts = Get-WmiObject -Namespace 'root\SecurityCenter2' -Class 'FirewallProduct' -ErrorAction SilentlyContinue
      $avNames = ($avProducts | ForEach-Object { $_.displayName }) -join ', '
      $fwNames = ($fwProducts | ForEach-Object { $_.displayName }) -join ', '
      if ($avProducts -or $fwProducts) {
        Write-Output "EXEC T1518.001: security software enumerated. AV=[$avNames] FW=[$fwNames]. RansomHub affiliates use this to decide whether to proceed or stage EDRKillShifter. [BAS-SIM-RANSOMHUB-S1]"
        Write-Output "FAIL: security product names are enumerable via WMI SecurityCenter2. EDR should alert on this WMI class access from PowerShell."
      } else {
        Write-Output "PASS: SecurityCenter2 namespace not accessible or no products registered  -  WMI security product enumeration blocked/empty. [BAS-SIM-RANSOMHUB-S1]"
      }
    cleanup: ""

  # ---------------------------------------------------------------------------
  # Stage 2 — Discovery: Network Share Discovery (T1135)
  # ---------------------------------------------------------------------------
  - name: "RansomHub Stage 2 — Network Share Discovery (T1135)"
    technique_id: T1135
    detection_profiles:
      - windows_network_share_discovery
    framework: custom
    executor: powershell
    requires_priv: user
    timeout_sec: 30
    fidelity: telemetry-safe
    production_safe: true
    risk: low
    reversible: true
    blast_radius: "Enumerates local administrative shares via net view and WMI Win32_Share. No shares accessed, no files read."
    telemetry:
      - "Security EID 4688: net.exe and powershell.exe share enumeration"
      - "Security EID 5140: if SACL object access auditing enabled on shares"
    detection:
      - "SIEM: net view / Win32_Share query from non-admin process — ransomware lateral-spread staging signal"
    command: |
      $ErrorActionPreference = 'SilentlyContinue'
      $wmiShares = @(Get-WmiObject -Class Win32_Share -ErrorAction SilentlyContinue)
      $netOut = & net view \\$env:COMPUTERNAME 2>&1
      $shareCount = if ($wmiShares) { $wmiShares.Count } else { 0 }
      Write-Output "EXEC: network share discovery — $shareCount share(s) via Win32_Share. net view executed for cmdline telemetry. RansomHub affiliates use tools like Nmap/AngryIP alongside built-in share enumeration before mass encryption. [BAS-SIM-RANSOMHUB-S2]"
    cleanup: ""

  # ---------------------------------------------------------------------------
  # Stage 3 — Credential Access: SAM/SYSTEM Hive Theft (T1003.002)
  # ---------------------------------------------------------------------------
  - name: "RansomHub Stage 3 — SAM & SYSTEM Hive Theft via reg save (T1003.002)"
    technique_id: T1003.002
    detection_profiles:
      - windows_sam_theft
    framework: custom
    executor: powershell
    requires_priv: admin
    timeout_sec: 40
    fidelity: telemetry-safe
    production_safe: true
    risk: high
    reversible: true
    blast_radius: "Attempts reg save HKLM\\SAM and HKLM\\SYSTEM to a temp file, then deletes both immediately. The saved SAM hive is encrypted with the bootkey (which is NOT exported), so the artifact is unusable, and it is removed in the same step. Generates Sysmon EID 1 (reg.exe save) + EID 11 (file create) + immediate delete."
    telemetry:
      - "Sysmon EID 1: reg.exe save HKLM\\SAM / HKLM\\SYSTEM"
      - "Sysmon EID 11: hive file written to %TEMP% then deleted"
      - "Security EID 4688: reg.exe with 'save' argument targeting SAM/SYSTEM"
    detection:
      - "EDR: reg.exe save hklm\\sam — Sigma proc_creation_win_reg_save_sam.yml (offline hash-theft IOC)"
      - "SIEM: reg SAVE targeting SAM or SYSTEM hive — page immediately, extremely rare in normal ops"
    command: |
      $ErrorActionPreference = 'SilentlyContinue'
      $runId = if ($env:BAS_RUN_ID) { $env:BAS_RUN_ID.Substring(0,[Math]::Min(8,$env:BAS_RUN_ID.Length)) } else { '{0:x8}' -f (Get-Random -Maximum 0x7FFFFFFF) }
      $samOut = Join-Path $env:TEMP "bas_ransomhub_sam_$runId.hive"
      $sysOut = Join-Path $env:TEMP "bas_ransomhub_sys_$runId.hive"
      & reg.exe save HKLM\SAM $samOut /y 2>&1 | Out-Null
      & reg.exe save HKLM\SYSTEM $sysOut /y 2>&1 | Out-Null
      $samSaved = Test-Path $samOut
      $sysSaved = Test-Path $sysOut
      Remove-Item $samOut,$sysOut -Force -ErrorAction SilentlyContinue
      if ($samSaved -or $sysSaved) {
        Write-Output "EXEC T1003.002: reg save of SAM=$samSaved SYSTEM=$sysSaved to %TEMP% then deleted. RansomHub affiliates steal these hives for OFFLINE hash extraction. reg.exe SAVE telemetry (Sysmon EID 1) expected. [BAS-SIM-RANSOMHUB-S3]"
        Write-Output "FAIL: reg.exe was able to SAVE the SAM/SYSTEM hive unblocked — local password hashes can be exfiltrated for offline cracking. 'reg save hklm\\sam' should be a paging alert. Verify EDR blocked or at least alerted."
      } else {
        Write-Output "PASS: reg save of SAM/SYSTEM was blocked or denied — EDR/WDAC prevented offline hive theft. [BAS-SIM-RANSOMHUB-S3]"
      }
    cleanup: |
      Remove-Item (Join-Path $env:TEMP 'bas_ransomhub_sam_*') -Force -ErrorAction SilentlyContinue
      Remove-Item (Join-Path $env:TEMP 'bas_ransomhub_sys_*') -Force -ErrorAction SilentlyContinue

  # ---------------------------------------------------------------------------
  # Stage 4 — Defense Evasion: Defender Exclusion Invocation (T1562.001)
  # ---------------------------------------------------------------------------
  - name: "RansomHub Stage 4 — Defender Exclusion Invocation (cmdline probe  -  no state change) (T1562.001)"
    technique_id: T1562.001
    detection_profiles:
      - windows_defender_tampering
    framework: custom
    executor: powershell
    requires_priv: user
    timeout_sec: 20
    fidelity: telemetry-safe
    production_safe: true
    risk: low
    blast_radius: "Invokes Add-MpPreference cmdline in a dry-run context that exits before modifying any exclusion. Security state is NOT changed."
    reversible: true
    telemetry:
      - "Security EID 4688 (powershell.exe with Add-MpPreference -ExclusionPath in command line)"
      - "PowerShell EID 4104 (script block: Add-MpPreference invocation) if ScriptBlock logging enabled"
    detection:
      - "EDR: PowerShell invoking Add-MpPreference  -  primary Defender tampering signal"
      - "SIEM: cmdline containing Add-MpPreference and ExclusionPath from a non-management process"
    command: |
      $ErrorActionPreference = 'SilentlyContinue'
      $cmdLine = 'Add-MpPreference -ExclusionPath $env:TEMP'
      Write-Output "EXEC: Defender exclusion invocation probe  -  cmdline '$cmdLine' logged to EID 4104/4688. Security state NOT modified (dry-run). RansomHub disables Defender alongside its EDRKillShifter tool before encrypting. [BAS-SIM-RANSOMHUB-S4]"
      Write-Output "TELEMETRY: if ScriptBlock logging (EID 4104) captured this block, the control is detecting Defender tampering attempts correctly."
    cleanup: ""

  # ---------------------------------------------------------------------------
  # Stage 5 — Defense Evasion: EDRKillShifter-Style BYOVD Staging Probe (T1562.001)
  # ---------------------------------------------------------------------------
  - name: "RansomHub Stage 5 — EDRKillShifter-Style Vulnerable-Driver Staging Probe (T1562.001)"
    technique_id: T1562.001
    detection_profiles:
      - windows_vulnerable_driver_load
    framework: custom
    executor: powershell
    requires_priv: admin
    timeout_sec: 20
    fidelity: telemetry-safe
    production_safe: true
    risk: low
    blast_radius: "Registers a kernel-type Windows service via sc.exe pointing at a guaranteed-nonexistent driver file path, then immediately deletes the service. No driver is ever loaded -- the binPath never resolves, so the load is physically impossible. Only the service-registration API call happens. This is RansomHub's own signature tool (EDRKillShifter, which stages the RentDrv2 / ThreatFireMonitor vulnerable drivers per Trend Micro/Intel471 reporting). Generates Security EID 4697/7045 (service installed) + EID 4688 (sc.exe create/delete)."
    reversible: true
    telemetry:
      - "Security EID 4697 / 7045: kernel-type service installed"
      - "Security EID 4688: sc.exe create ... type= kernel / sc.exe delete"
    detection:
      - "EDR: sc.exe create with 'type= kernel' from a non-driver-installer process -- near-zero-false-positive BYOVD staging IOC, RansomHub's exact EDRKillShifter staging pattern"
      - "SIEM: enforce the Microsoft-recommended vulnerable-driver blocklist / HVCI"
    command: |
      $ErrorActionPreference = 'SilentlyContinue'
      $svcName = 'BAS-Sim-EDRKill-Probe'
      $bogusPath = 'C:\Windows\Temp\bas_edrkill_probe_nonexistent.sys'
      & sc.exe create $svcName type= kernel binPath= $bogusPath start= demand 2>&1 | Out-Null
      $created = (& sc.exe query $svcName 2>&1 | Out-String) -match 'SERVICE_NAME'
      & sc.exe delete $svcName 2>&1 | Out-Null
      if ($created) {
        Write-Output "EXEC T1562.001: kernel-mode service registration succeeded (no driver code executed -- binPath points to a nonexistent file, load is physically impossible). RansomHub's EDRKillShifter uses this exact 'sc create type= kernel' step to stage RentDrv2/ThreatFireMonitor before killing EDR processes. [BAS-SIM-RANSOMHUB-S5]"
        Write-Output "FAIL: kernel-type service creation via sc.exe was not blocked. Alert on 'sc create ... type= kernel' from non-driver-installer processes -- this is a near-zero-false-positive BYOVD precursor."
      } else {
        Write-Output "PASS: kernel-type service registration was blocked or denied -- BYOVD staging surface is reduced. [BAS-SIM-RANSOMHUB-S5]"
      }
    cleanup: |
      & sc.exe delete BAS-Sim-EDRKill-Probe 2>&1 | Out-Null

  # ---------------------------------------------------------------------------
  # Stage 6 — Ransomware Impact Simulation, Double-Extortion Note (T1486)
  # ---------------------------------------------------------------------------
  - name: "RansomHub Stage 6 — Ransomware Payload Simulation, Double-Extortion Note (T1486)"
    technique_id: T1486
    detection_profiles:
      - windows_ransomware_encryption
    framework: custom
    executor: powershell
    requires_priv: user
    timeout_sec: 30
    fidelity: telemetry-safe
    production_safe: true
    risk: low
    blast_radius: "Creates one BAS-owned plaintext file in %TEMP%, XOR-encodes it (simulating encryption), writes a benign double-extortion-style ransom note ([BAS-SIM-RANSOMHUB] only), then DELETES BOTH immediately. No user data touched. No real ransomware code. Generates Sysmon EID 11 (file create x2) and EID 23 (file delete x2)."
    reversible: true
    telemetry:
      - "Sysmon EID 11: bas_ransomhub_<id>.txt created in %TEMP%"
      - "Sysmon EID 11: bas_ransomhub_<id>.ransomhub (encrypted simulation) created"
      - "Sysmon EID 11: bas_ransom_<id>.txt (ransom note) created"
      - "Sysmon EID 23: all files deleted in cleanup"
    detection:
      - "EDR: high-frequency file create + rename + delete in short window  -  Sigma rule win_security_susp_file_modifications.yml"
      - "Defender: ransom-pattern file creation heuristic"
      - "EDR: PowerShell creating and immediately deleting files with suspicious extension"
    command: |
      $ErrorActionPreference = 'SilentlyContinue'
      $runId = if ($env:BAS_RUN_ID) { $env:BAS_RUN_ID.Substring(0,[Math]::Min(8,$env:BAS_RUN_ID.Length)) } else { '{0:x8}' -f (Get-Random -Maximum 0x7FFFFFFF) }
      $plainFile = Join-Path $env:TEMP "bas_ransomhub_$runId.txt"
      $encFile   = Join-Path $env:TEMP "bas_ransomhub_$runId.ransomhub"
      $noteFile  = Join-Path $env:TEMP "bas_ransom_$runId.txt"
      $plainContent = '[BAS-SIM-RANSOMHUB] T1486 ransomware simulation target file'
      [System.IO.File]::WriteAllText($plainFile, $plainContent, [System.Text.Encoding]::UTF8)
      # Simulate XOR encryption (key=0x52 = 'R' for RansomHub)
      $key = 0x52
      $bytes = [System.Text.Encoding]::UTF8.GetBytes($plainContent)
      $enc   = $bytes | ForEach-Object { $_ -bxor $key }
      [System.IO.File]::WriteAllBytes($encFile, [byte[]]$enc)
      $note = '[BAS-SIM-RANSOMHUB] RansomHub Ransomware Simulation Note (double extortion)' + [char]13 + [char]10 +
              'This is a BAS simulation. No real files were encrypted or exfiltrated.' + [char]13 + [char]10 +
              'Run ID: ' + $runId
      [System.IO.File]::WriteAllText($noteFile, $note, [System.Text.Encoding]::UTF8)
      $created = (Test-Path $plainFile) -and (Test-Path $encFile) -and (Test-Path $noteFile)
      Remove-Item $plainFile,$encFile,$noteFile -Force -ErrorAction SilentlyContinue
      $cleaned = -not (Test-Path $plainFile) -and -not (Test-Path $encFile) -and -not (Test-Path $noteFile)
      if ($created) {
        Write-Output "EXEC T1486: ransomware simulation completed — target file XOR-encoded (.ransomhub), double-extortion-style ransom note written, all cleaned=$cleaned. Sysmon EID 11+23 expected. [BAS-SIM-RANSOMHUB-S6]"
        Write-Output "FAIL: File encryption simulation ran unblocked. Defender ransomware protection and controlled folder access should have flagged this pattern."
      } else {
        Write-Output "PASS: Ransomware simulation file creation blocked  -  Controlled Folder Access or EDR prevented file write to %TEMP%. [BAS-SIM-RANSOMHUB-S6]"
      }
    cleanup: |
      Remove-Item (Join-Path $env:TEMP 'bas_ransomhub_*') -Force -ErrorAction SilentlyContinue
      Remove-Item (Join-Path $env:TEMP 'bas_ransom_*') -Force -ErrorAction SilentlyContinue

  # ---------------------------------------------------------------------------
  # Stage 7 — Recovery Inhibition: VSS Enumeration (T1490)
  # ---------------------------------------------------------------------------
  - name: "RansomHub Stage 7 — VSS Snapshot Enumeration (T1490)"
    technique_id: T1490
    detection_profiles:
      - windows_vss_inhibition
    framework: custom
    executor: powershell
    requires_priv: admin
    timeout_sec: 20
    fidelity: telemetry-safe
    production_safe: true
    risk: low
    blast_radius: "Runs vssadmin list shadows to enumerate VSS snapshots (READ ONLY). RansomHub deletes these via vssadmin/PowerShell before encryption — we enumerate only to show the attack surface. Generates Sysmon EID 1: vssadmin.exe with 'list' argument."
    reversible: true
    telemetry:
      - "Sysmon EID 1: vssadmin.exe list shadows (pre-wipe reconnaissance)"
      - "Security EID 4688: vssadmin.exe spawned by powershell.exe"
    detection:
      - "EDR: vssadmin.exe invoked from PowerShell  -  Sigma rule proc_creation_win_vssadmin_susp_commands.yml"
      - "SIEM: vssadmin list shadows — pre-ransomware VSS enumeration IOC"
    command: |
      $ErrorActionPreference = 'SilentlyContinue'
      $vssOut = & vssadmin.exe list shadows 2>&1 | Out-String
      $shadowCount = ([regex]::Matches($vssOut, 'Shadow Copy ID')).Count
      if ($shadowCount -gt 0) {
        Write-Output "EXEC T1490: $shadowCount VSS shadow copy(ies) enumerated. RansomHub would now delete these to destroy backups before encryption. Sysmon EID 1 vssadmin.exe logged. [BAS-SIM-RANSOMHUB-S7]"
        Write-Output "FAIL: VSS snapshots exist and are enumerable ($shadowCount found). If RansomHub reached this stage, backups would be destroyed before encryption. Ensure immutable cloud backup or Veeam hardened repo is NOT reachable from endpoint."
      } else {
        Write-Output "PASS: No VSS shadow copies found or vssadmin blocked  -  recovery inhibition surface is reduced. [BAS-SIM-RANSOMHUB-S7]"
      }
    cleanup: ""

  # ---------------------------------------------------------------------------
  # Stage 8 — Indicator Removal: Event Log Clearing Attempt (T1070.001)
  # ---------------------------------------------------------------------------
  - name: "RansomHub Stage 8 — Event Log Clearing Attempt (T1070.001)"
    technique_id: T1070.001
    detection_profiles:
      - windows_log_manipulation
    framework: custom
    executor: powershell
    requires_priv: admin
    timeout_sec: 20
    fidelity: telemetry-safe
    production_safe: true
    risk: low
    blast_radius: "Creates a BAS-owned custom event log (BAS-Sim-RansomHub), attempts wevtutil cl on it, then removes the log. Does NOT touch System/Security/Application logs. Generates Security EID 1102 if the clear succeeds, and Sysmon EID 1 wevtutil.exe."
    reversible: true
    telemetry:
      - "Sysmon EID 1: wevtutil.exe with cl argument (log-clearing pattern)"
      - "Security EID 1102: audit log cleared (if wevtutil cl succeeds on custom log)"
      - "Security EID 4688: wevtutil.exe spawned by powershell.exe"
    detection:
      - "EDR: wevtutil.exe with 'cl' argument  -  Sigma rule proc_creation_win_wevtutil_clear_logs.yml"
      - "SIEM: Security EID 1102 event log cleared  -  high-priority anti-forensics IOC"
      - "SIEM: wevtutil.exe invoked from PowerShell at unusual time"
    command: |
      $ErrorActionPreference = 'SilentlyContinue'
      $logName = 'BAS-Sim-RansomHub'
      $exists = [System.Diagnostics.EventLog]::Exists($logName)
      if (-not $exists) {
        try { New-EventLog -LogName $logName -Source 'BAS-Sim' -ErrorAction Stop } catch {}
      }
      $created = [System.Diagnostics.EventLog]::Exists($logName)
      if ($created) {
        $clOut = & wevtutil.exe cl $logName 2>&1 | Out-String
        $cleared = $clOut -notmatch 'Access is denied|The specified channel could not be found|error'
        try { Remove-EventLog -LogName $logName -ErrorAction SilentlyContinue } catch {}
        if ($cleared) {
          Write-Output "EXEC T1070.001: wevtutil cl on BAS custom log succeeded (exit 0). RansomHub affiliates clear logs post-deployment. Sysmon EID 1 wevtutil.exe logged. [BAS-SIM-RANSOMHUB-S8]"
          Write-Output "FAIL: wevtutil cl ran without EDR intervention. Ensure wevtutil.exe invocation from PowerShell triggers an alert. Security EID 1102 should generate a SIEM alert."
        } else {
          Write-Output "PASS: wevtutil cl was blocked or failed  -  $($clOut.Trim()). [BAS-SIM-RANSOMHUB-S8]"
        }
      } else {
        Write-Output "SKIP: Could not create test event log (insufficient privilege). wevtutil cl test skipped. [BAS-SIM-RANSOMHUB-S8]"
      }
    cleanup: |
      try { Remove-EventLog -LogName 'BAS-Sim-RansomHub' -ErrorAction SilentlyContinue } catch {}
```

- [ ] **Step 2: Validate YAML structural validity**

```bash
python3 -c "import yaml; yaml.safe_load(open('scenarios/ransomhub-kill-chain.yaml')); print('OK')"
```
Expected: `OK`, no exceptions.

- [ ] **Step 3: Manual PowerShell syntax sanity check**

Same procedure as Task 2 Step 3, applied to all 8 `command:` blocks and 5 non-empty `cleanup:` blocks in this file.
Expected: no parse errors for any block.

- [ ] **Step 4: Sign the file**

From `orchestrator/`:
```bash
go run scripts/signer.go sign private_key.pem ../scenarios/ransomhub-kill-chain.yaml
```
Expected: `ransomhub-kill-chain.yaml.sig` created, no errors.

- [ ] **Step 5: Commit**

```bash
git add scenarios/ransomhub-kill-chain.yaml scenarios/ransomhub-kill-chain.yaml.sig
git commit -m "feat(scenarios): RansomHub kill-chain scenario (Ransomware Readiness Deliverable 2)"
git push
```

---

## Task 6: `clop-kill-chain.yaml`

**Files:**
- Create: `scenarios/clop-kill-chain.yaml` (+ `.sig`)

**Interfaces:**
- Consumes: `windows_security_process_termination` (Task 1) plus existing profiles `windows_file_discovery`, `windows_archive_staging`, `windows_cloud_egress`, `windows_log_manipulation`.

**Safety notes:** Stage 2 (security-process termination) targets a synthetic, run-ID-suffixed process name that can never match a real process — no real AV/EDR process is ever affected.

- [ ] **Step 1: Create `scenarios/clop-kill-chain.yaml`**

```yaml
id: clop-kill-chain
name: Cl0p Kill Chain — Ransomware Emulation
description: >
  Five-stage telemetry-safe emulation of the Cl0p (TA505-lineage) ransomware
  kill chain targeting Windows endpoints. Reflects documented Cl0p
  tradecraft validated against CISA AA23-158A: mass exploitation of
  MOVEit/GoAnywhere/Accellion managed file-transfer software. 2023+ Cl0p
  campaigns were largely pure-exfiltration extortion with NO ransomware
  binary deployed in most victims — this scenario is deliberately lean,
  reflecting that reality rather than forcing a full encryption kill chain
  onto a family that has, in its most consequential recent campaigns,
  skipped encryption entirely.

  KILL CHAIN STAGES:
    1. Discovery         — BFSI high-value file target reconnaissance (T1083)
    2. Defense Evasion   — security-process termination probe, taskkill /im pattern (T1562.001)
    3. Collection        — archive staging via Compress-Archive (T1560.001)
    4. Exfiltration      — cloud storage egress reachability (T1567.002)
    5. Log Clearing Attempt — wevtutil cl attempt, blocked or audit (T1070.001)

  NOTE: Cl0p's real initial access — mass exploitation of a specific
  vulnerable file-transfer application (CVE-2023-34362 and siblings) — is
  not represented as an executable step for the same reason as Play's
  ProxyNotShell/FortiOS vector: the vulnerable app is rarely present on a
  generic endpoint. Credential Access, Lateral Movement, Encryption, and
  Recovery Inhibition are genuinely absent from this scenario — they are
  not part of Cl0p's documented 2023+ MOVEit-era kill chain, per the
  canonical taxonomy's "omit a phase the family doesn't exhibit" rule.

  SAFETY: Stage 2 targets a synthetic, run-ID-suffixed process name that is
  guaranteed never to match a real process — no real AV/EDR process is
  ever affected. Stage 3/4 use synthetic decoy data only, no real files
  touched, no real upload performed (connectivity probe only). All stages
  are production-safe. Windows only. [BAS-SIM] tagged throughout.
author: Audspect Research
executable: true
local_check: false
supported_os: [windows]
tags:
  - clop
  - cl0p
  - ta505
  - ransomware
  - bfsi
  - kill-chain
  - t1070
  - t1083
  - t1560
  - t1562
  - t1567
  - mitre
mitre_phases:
  - discovery
  - defense-evasion
  - collection
  - exfiltration

live_policy:
  block_on_domain_controller: false
  require_dc_reachable: false
  max_spray_attempts: 0
  spray_account_allowlist: []
  execution_window: ""

steps:

  # ---------------------------------------------------------------------------
  # Stage 1 — Discovery: BFSI File Target Reconnaissance (T1083)
  # ---------------------------------------------------------------------------
  - name: "Cl0p Stage 1 — BFSI File Target Reconnaissance (T1083)"
    technique_id: T1083
    detection_profiles:
      - windows_file_discovery
    framework: custom
    executor: powershell
    requires_priv: user
    timeout_sec: 30
    fidelity: telemetry-safe
    production_safe: true
    risk: low
    reversible: true
    blast_radius: "Read-only traversal of Desktop/Documents/Downloads (depth=2). No file opened or modified."
    telemetry:
      - "Security EID 4688: powershell.exe with file-enumeration command line"
      - "DLP: enumeration of filenames matching financial/PII patterns"
    detection:
      - "UEBA: bulk file enumeration from a single process — pre-exfiltration staging signal"
      - "EDR: PowerShell scanning user profile paths for BFSI-pattern filenames"
    command: |
      $ErrorActionPreference = 'SilentlyContinue'
      $bfsiPatterns = @('*finance*','*customer*','*swift*','*payment*','*account*','*salary*','*export*','*backup*','*password*','*.xlsx','*.csv','*.docx','*.pdf','*.db','*.bak')
      $scanPaths = @(
        [Environment]::GetFolderPath('Desktop'),
        [Environment]::GetFolderPath('MyDocuments'),
        (Join-Path $env:USERPROFILE 'Downloads')
      )
      $found = 0
      foreach ($root in $scanPaths) {
        if (-not (Test-Path $root)) { continue }
        Get-ChildItem -Path $root -Depth 2 -File -ErrorAction SilentlyContinue | ForEach-Object {
          foreach ($p in $bfsiPatterns) { if ($_.Name -like $p) { $found++; break } }
        }
      }
      Write-Output "EXEC: BFSI file recon across Desktop/Documents/Downloads (depth=2). Found $found matching file(s). Read-only — no files opened. Cl0p's MOVEit/GoAnywhere campaigns mass-exploit file-transfer software then hunt for high-value files like these to exfiltrate. [BAS-SIM-CLOP-S1]"
    cleanup: ""

  # ---------------------------------------------------------------------------
  # Stage 2 — Defense Evasion: Security Process Termination Probe (T1562.001)
  # ---------------------------------------------------------------------------
  - name: "Cl0p Stage 2 — Security Process Termination Probe (T1562.001)"
    technique_id: T1562.001
    detection_profiles:
      - windows_security_process_termination
    framework: custom
    executor: powershell
    requires_priv: admin
    timeout_sec: 20
    fidelity: telemetry-safe
    production_safe: true
    risk: low
    blast_radius: "Spawns taskkill.exe /F /IM against a synthetic, run-ID-suffixed process name that is guaranteed never to match a real process. No real process is ever affected. Generates Security EID 4688 (taskkill.exe with /IM argument)."
    reversible: true
    telemetry:
      - "Security EID 4688: taskkill.exe /F /IM <process-name>"
      - "PowerShell EID 4104: taskkill invocation script block"
    detection:
      - "EDR: taskkill.exe /F /IM targeting AV/EDR-style process image names, independent of whether the target exists -- Cl0p's classic encryptor runs this exact command pattern against real security-product process names before encrypting"
      - "SIEM: taskkill.exe spawned from PowerShell targeting a security-product-style process name"
    command: |
      $ErrorActionPreference = 'SilentlyContinue'
      $runId = if ($env:BAS_RUN_ID) { $env:BAS_RUN_ID.Substring(0,[Math]::Min(8,$env:BAS_RUN_ID.Length)) } else { '{0:x8}' -f (Get-Random -Maximum 0x7FFFFFFF) }
      $fakeTarget = "BAS-Sim-AVKill-$runId.exe"
      try {
        $out = & taskkill.exe /F /IM $fakeTarget 2>&1 | Out-String
        $spawned = $true
      } catch {
        $spawned = $false
      }
      if ($spawned) {
        Write-Output "EXEC T1562.001: taskkill.exe /F /IM spawned with a synthetic AV/EDR-style process name ($fakeTarget -- guaranteed not to match any real process, target result: $($out.Trim())). Cl0p's classic encryptor runs this identical command pattern against real security-product process names before encrypting. [BAS-SIM-CLOP-S2]"
        Write-Output "FAIL: taskkill.exe /F /IM was allowed to spawn from PowerShell unimpeded. Alert on taskkill.exe/Stop-Process targeting known AV/EDR process image names, independent of whether the named process exists on the host."
      } else {
        Write-Output "PASS: taskkill.exe spawn was blocked (AppLocker/WDAC/EDR prevented process creation). [BAS-SIM-CLOP-S2]"
      }
    cleanup: ""

  # ---------------------------------------------------------------------------
  # Stage 3 — Collection: Archive Staging via Compress-Archive (T1560.001)
  # ---------------------------------------------------------------------------
  - name: "Cl0p Stage 3 — Archive Staging via Compress-Archive (T1560.001)"
    technique_id: T1560.001
    detection_profiles:
      - windows_archive_staging
    framework: custom
    executor: powershell
    requires_priv: user
    timeout_sec: 30
    fidelity: telemetry-safe
    production_safe: true
    risk: low
    reversible: true
    blast_radius: "Compresses a BAS-owned decoy staging directory into a .zip with the built-in Compress-Archive cmdlet. Cl0p archives collected data to shrink and obscure it before exfil. Synthetic data only. Generates Sysmon EID 11 (zip file created) and PowerShell EID 4104."
    telemetry:
      - "Sysmon EID 11: <staging>.zip created"
      - "PowerShell EID 4104: Compress-Archive of a sensitive directory"
    detection:
      - "EDR: Compress-Archive / zip creation over collected data — Sigma posh_ps_compress_archive.yml"
      - "DLP: archive containing PAN/Aadhaar/card content — archive-inspection trigger"
    command: |
      $ErrorActionPreference = 'SilentlyContinue'
      $runId = if ($env:BAS_RUN_ID) { $env:BAS_RUN_ID.Substring(0,[Math]::Min(8,$env:BAS_RUN_ID.Length)) } else { '{0:x8}' -f (Get-Random -Maximum 0x7FFFFFFF) }
      $work = Join-Path $env:TEMP "bas_clop_$runId"
      $staged = Join-Path $work "staged"
      if (-not (Test-Path $staged)) { New-Item -ItemType Directory -Path $staged -Force | Out-Null; "[BAS-SIM-CLOP] decoy" | Out-File (Join-Path $staged 'decoy.txt') -Encoding utf8 }
      $zip = Join-Path $work "clop_bundle.zip"
      Compress-Archive -Path (Join-Path $staged '*') -DestinationPath $zip -Force -ErrorAction SilentlyContinue
      $made = Test-Path $zip
      $size = if ($made) { (Get-Item $zip).Length } else { 0 }
      if ($made) {
        Write-Output "EXEC T1560.001: Compress-Archive produced $zip ($size bytes). Cl0p's MOVEit/GoAnywhere campaigns stage and compress exfiltrated files this same way before transfer. [BAS-SIM-CLOP-S3]"
        Write-Output "FAIL: A zip of the staged sensitive data was created unblocked. DLP should inspect INSIDE archives — verify flagged data is detected even once compressed, and that archiving of flagged data raises an alert."
      } else {
        Write-Output "PASS: archive creation was blocked or failed — archiving of collected data restricted. [BAS-SIM-CLOP-S3]"
      }
    cleanup: |
      Remove-Item (Join-Path $env:TEMP 'bas_clop_*') -Recurse -Force -ErrorAction SilentlyContinue

  # ---------------------------------------------------------------------------
  # Stage 4 — Exfiltration: Cloud Storage Egress Reachability (T1567.002)
  # ---------------------------------------------------------------------------
  - name: "Cl0p Stage 4 — Cloud Storage Egress Reachability (T1567.002)"
    technique_id: T1567.002
    detection_profiles:
      - windows_cloud_egress
    framework: custom
    executor: powershell
    requires_priv: user
    timeout_sec: 30
    fidelity: telemetry-safe
    production_safe: true
    risk: low
    reversible: true
    blast_radius: "Tests whether the endpoint can reach public cloud-storage upload endpoints (a benign HEAD/connectivity probe to well-known storage hostnames) — the exfil-to-cloud path Cl0p's post-MOVEit exfiltration-only campaigns rely on. NO account, NO upload, NO data: connectivity reachability only. Generates Sysmon EID 22 (DNS) and EID 3 (outbound TLS attempt)."
    telemetry:
      - "Sysmon EID 22: DNS queries to public cloud-storage hostnames"
      - "Sysmon EID 3: outbound TCP/443 to cloud-storage endpoints"
    detection:
      - "Proxy/CASB: uploads to unsanctioned cloud storage — DLP/CASB egress policy trigger"
      - "SIEM: workstation reaching consumer cloud-storage APIs — shadow-IT / exfil IOC"
    command: |
      $ErrorActionPreference = 'SilentlyContinue'
      $endpoints = @('storage.googleapis.com','s3.amazonaws.com','blob.core.windows.net','api.dropboxapi.com')
      $reachable = @()
      foreach ($e in $endpoints) {
        try {
          $tcp = New-Object System.Net.Sockets.TcpClient
          $iar = $tcp.BeginConnect($e, 443, $null, $null)
          if ($iar.AsyncWaitHandle.WaitOne(3000, $false) -and $tcp.Connected) { $reachable += $e }
          $tcp.Close()
        } catch {}
      }
      Write-Output "EXEC T1567.002: probed cloud-storage egress reachability. reachable=[$($reachable -join ', ')] (probe only, no upload). Cl0p's 2023+ campaigns were largely pure-exfiltration extortion with no encryption deployed -- this is the path the stolen BFSI data would leave through. [BAS-SIM-CLOP-S4]"
      if ($reachable.Count -gt 0) {
        Write-Output "FAIL: The endpoint can directly reach $($reachable.Count) public cloud-storage endpoint(s) on TCP/443 — a real data-theft path to unsanctioned storage. Route egress through a proxy/CASB that enforces a sanctioned-tenant allowlist and DLP upload inspection."
      } else {
        Write-Output "PASS: no direct egress to public cloud-storage endpoints — uploads are forced through a controlled path (or blocked). [BAS-SIM-CLOP-S4]"
      }
    cleanup: |
      Remove-Item (Join-Path $env:TEMP 'bas_clop_*') -Recurse -Force -ErrorAction SilentlyContinue

  # ---------------------------------------------------------------------------
  # Stage 5 — Indicator Removal: Event Log Clearing Attempt (T1070.001)
  # ---------------------------------------------------------------------------
  - name: "Cl0p Stage 5 — Event Log Clearing Attempt (T1070.001)"
    technique_id: T1070.001
    detection_profiles:
      - windows_log_manipulation
    framework: custom
    executor: powershell
    requires_priv: admin
    timeout_sec: 20
    fidelity: telemetry-safe
    production_safe: true
    risk: low
    blast_radius: "Creates a BAS-owned custom event log (BAS-Sim-Clop), attempts wevtutil cl on it, then removes the log. Does NOT touch System/Security/Application logs. Generates Security EID 1102 if the clear succeeds, and Sysmon EID 1 wevtutil.exe."
    reversible: true
    telemetry:
      - "Sysmon EID 1: wevtutil.exe with cl argument (log-clearing pattern)"
      - "Security EID 1102: audit log cleared (if wevtutil cl succeeds on custom log)"
      - "Security EID 4688: wevtutil.exe spawned by powershell.exe"
    detection:
      - "EDR: wevtutil.exe with 'cl' argument  -  Sigma rule proc_creation_win_wevtutil_clear_logs.yml"
      - "SIEM: Security EID 1102 event log cleared  -  high-priority anti-forensics IOC"
      - "SIEM: wevtutil.exe invoked from PowerShell at unusual time"
    command: |
      $ErrorActionPreference = 'SilentlyContinue'
      $logName = 'BAS-Sim-Clop'
      $exists = [System.Diagnostics.EventLog]::Exists($logName)
      if (-not $exists) {
        try { New-EventLog -LogName $logName -Source 'BAS-Sim' -ErrorAction Stop } catch {}
      }
      $created = [System.Diagnostics.EventLog]::Exists($logName)
      if ($created) {
        $clOut = & wevtutil.exe cl $logName 2>&1 | Out-String
        $cleared = $clOut -notmatch 'Access is denied|The specified channel could not be found|error'
        try { Remove-EventLog -LogName $logName -ErrorAction SilentlyContinue } catch {}
        if ($cleared) {
          Write-Output "EXEC T1070.001: wevtutil cl on BAS custom log succeeded (exit 0). Cl0p/TA505-lineage tooling clears logs post-exfiltration. Sysmon EID 1 wevtutil.exe logged. [BAS-SIM-CLOP-S5]"
          Write-Output "FAIL: wevtutil cl ran without EDR intervention. Ensure wevtutil.exe invocation from PowerShell triggers an alert. Security EID 1102 should generate a SIEM alert."
        } else {
          Write-Output "PASS: wevtutil cl was blocked or failed  -  $($clOut.Trim()). [BAS-SIM-CLOP-S5]"
        }
      } else {
        Write-Output "SKIP: Could not create test event log (insufficient privilege). wevtutil cl test skipped. [BAS-SIM-CLOP-S5]"
      }
    cleanup: |
      try { Remove-EventLog -LogName 'BAS-Sim-Clop' -ErrorAction SilentlyContinue } catch {}
```

- [ ] **Step 2: Validate YAML structural validity**

```bash
python3 -c "import yaml; yaml.safe_load(open('scenarios/clop-kill-chain.yaml')); print('OK')"
```
Expected: `OK`, no exceptions.

- [ ] **Step 3: Manual PowerShell syntax sanity check**

Same procedure as Task 2 Step 3, applied to all 5 `command:` blocks and 3 non-empty `cleanup:` blocks in this file.
Expected: no parse errors for any block.

- [ ] **Step 4: Sign the file**

From `orchestrator/`:
```bash
go run scripts/signer.go sign private_key.pem ../scenarios/clop-kill-chain.yaml
```
Expected: `clop-kill-chain.yaml.sig` created, no errors.

- [ ] **Step 5: Commit**

```bash
git add scenarios/clop-kill-chain.yaml scenarios/clop-kill-chain.yaml.sig
git commit -m "feat(scenarios): Cl0p kill-chain scenario (Ransomware Readiness Deliverable 2)"
git push
```

---

## Task 7: Wiring-Guard Test + Final Regression

**Files:**
- Modify: `orchestrator/internal/scenario/engine_test.go` (append new test function)

**Interfaces:**
- Consumes: `ParseYAML(b []byte) (*Scenario, error)` (`internal/scenario/engine.go:137`), `Scenario.Steps []Step`, `Step.Name string`, `Step.DetectionProfiles []string` (`internal/scenario/types.go:161`) — same interfaces `TestParseYAML_RansomwareScenariosDetectionProfilesWired` (Deliverable 1) already uses. `"os"` is already imported in `engine_test.go`.

- [ ] **Step 1: Append the wiring-guard test to `orchestrator/internal/scenario/engine_test.go`**

Add immediately after `TestParseYAML_RansomwareScenariosDetectionProfilesWired` (the Deliverable 1 test):

```go
func TestParseYAML_NewRansomwareFamiliesDetectionProfilesWired(t *testing.T) {
	cases := []struct {
		file        string
		stepName    string
		wantProfile string
	}{
		{"../../../scenarios/blackcat-kill-chain.yaml", "BlackCat Stage 1 — AD Domain & Privileged Account Discovery (T1087.002)", "windows_ad_discovery"},
		{"../../../scenarios/blackcat-kill-chain.yaml", "BlackCat Stage 2 — Security Software Discovery (T1518.001)", "windows_security_software_discovery"},
		{"../../../scenarios/blackcat-kill-chain.yaml", "BlackCat Stage 3 — SAM & SYSTEM Hive Theft via reg save (T1003.002)", "windows_sam_theft"},
		{"../../../scenarios/blackcat-kill-chain.yaml", "BlackCat Stage 4 — Defender RTP Disable (lab  -  mandatory restoration + health check) (T1562.001)", "windows_defender_tampering"},
		{"../../../scenarios/blackcat-kill-chain.yaml", "BlackCat Stage 5 — Malicious Service Probe (lab  -  PsExec-style self-propagation) (T1543.003)", "windows_malicious_service"},
		{"../../../scenarios/blackcat-kill-chain.yaml", "BlackCat Stage 6 — Ransomware Payload Simulation (T1486)", "windows_ransomware_encryption"},
		{"../../../scenarios/blackcat-kill-chain.yaml", "BlackCat Stage 7 — VSS Snapshot Enumeration (T1490)", "windows_vss_inhibition"},
		{"../../../scenarios/blackcat-kill-chain.yaml", "BlackCat Stage 8 — Event Log Clearing Attempt (T1070.001)", "windows_log_manipulation"},

		{"../../../scenarios/akira-kill-chain.yaml", "Akira Stage 1 — RDP / NLA Exposure Posture Check (T1021.001)", "windows_rdp_nla_posture"},
		{"../../../scenarios/akira-kill-chain.yaml", "Akira Stage 2 — Network Share Discovery (T1135)", "windows_network_share_discovery"},
		{"../../../scenarios/akira-kill-chain.yaml", "Akira Stage 3 — SAM & SYSTEM Hive Theft via reg save (T1003.002)", "windows_sam_theft"},
		{"../../../scenarios/akira-kill-chain.yaml", "Akira Stage 4 — Defender Exclusion Invocation (cmdline probe  -  no state change) (T1562.001)", "windows_defender_tampering"},
		{"../../../scenarios/akira-kill-chain.yaml", "Akira Stage 5 — SMB Admin Share Lateral Movement Probe (T1021.002)", "windows_smb_lateral_probe"},
		{"../../../scenarios/akira-kill-chain.yaml", "Akira Stage 6 — Ransomware Payload Simulation (T1486)", "windows_ransomware_encryption"},
		{"../../../scenarios/akira-kill-chain.yaml", "Akira Stage 7 — VSS Snapshot Enumeration (T1490)", "windows_vss_inhibition"},
		{"../../../scenarios/akira-kill-chain.yaml", "Akira Stage 8 — VSS Shadow Copy Deletion via WMI (lab  -  requires BAS_CONFIRM_VSS_DELETE=true) (T1490)", "windows_vss_inhibition"},
		{"../../../scenarios/akira-kill-chain.yaml", "Akira Stage 9 — Event Log Clearing Attempt (T1070.001)", "windows_log_manipulation"},

		{"../../../scenarios/play-kill-chain.yaml", "Play Stage 1 — AdFind-Style AD Enumeration (T1087.002)", "windows_ad_discovery"},
		{"../../../scenarios/play-kill-chain.yaml", "Play Stage 2 — Grixba-Style Network & Share Discovery (T1135)", "windows_network_share_discovery"},
		{"../../../scenarios/play-kill-chain.yaml", "Play Stage 3 — GPO-Style Defender RTP Disable (lab  -  mandatory restoration + health check) (T1562.001)", "windows_defender_tampering"},
		{"../../../scenarios/play-kill-chain.yaml", "Play Stage 4 — EDR-Killer / Vulnerable-Driver Staging Probe (T1562.001)", "windows_vulnerable_driver_load"},
		{"../../../scenarios/play-kill-chain.yaml", "Play Stage 5 — SMB Admin Share Lateral Movement Probe (T1021.002)", "windows_smb_lateral_probe"},
		{"../../../scenarios/play-kill-chain.yaml", "Play Stage 6 — Ransomware Payload Simulation (T1486)", "windows_ransomware_encryption"},
		{"../../../scenarios/play-kill-chain.yaml", "Play Stage 7 — VSS Snapshot Enumeration (T1490)", "windows_vss_inhibition"},
		{"../../../scenarios/play-kill-chain.yaml", "Play Stage 8 — Event Log Clearing Attempt (T1070.001)", "windows_log_manipulation"},

		{"../../../scenarios/ransomhub-kill-chain.yaml", "RansomHub Stage 1 — Security Software Discovery (T1518.001)", "windows_security_software_discovery"},
		{"../../../scenarios/ransomhub-kill-chain.yaml", "RansomHub Stage 2 — Network Share Discovery (T1135)", "windows_network_share_discovery"},
		{"../../../scenarios/ransomhub-kill-chain.yaml", "RansomHub Stage 3 — SAM & SYSTEM Hive Theft via reg save (T1003.002)", "windows_sam_theft"},
		{"../../../scenarios/ransomhub-kill-chain.yaml", "RansomHub Stage 4 — Defender Exclusion Invocation (cmdline probe  -  no state change) (T1562.001)", "windows_defender_tampering"},
		{"../../../scenarios/ransomhub-kill-chain.yaml", "RansomHub Stage 5 — EDRKillShifter-Style Vulnerable-Driver Staging Probe (T1562.001)", "windows_vulnerable_driver_load"},
		{"../../../scenarios/ransomhub-kill-chain.yaml", "RansomHub Stage 6 — Ransomware Payload Simulation, Double-Extortion Note (T1486)", "windows_ransomware_encryption"},
		{"../../../scenarios/ransomhub-kill-chain.yaml", "RansomHub Stage 7 — VSS Snapshot Enumeration (T1490)", "windows_vss_inhibition"},
		{"../../../scenarios/ransomhub-kill-chain.yaml", "RansomHub Stage 8 — Event Log Clearing Attempt (T1070.001)", "windows_log_manipulation"},

		{"../../../scenarios/clop-kill-chain.yaml", "Cl0p Stage 1 — BFSI File Target Reconnaissance (T1083)", "windows_file_discovery"},
		{"../../../scenarios/clop-kill-chain.yaml", "Cl0p Stage 2 — Security Process Termination Probe (T1562.001)", "windows_security_process_termination"},
		{"../../../scenarios/clop-kill-chain.yaml", "Cl0p Stage 3 — Archive Staging via Compress-Archive (T1560.001)", "windows_archive_staging"},
		{"../../../scenarios/clop-kill-chain.yaml", "Cl0p Stage 4 — Cloud Storage Egress Reachability (T1567.002)", "windows_cloud_egress"},
		{"../../../scenarios/clop-kill-chain.yaml", "Cl0p Stage 5 — Event Log Clearing Attempt (T1070.001)", "windows_log_manipulation"},
	}

	parsed := map[string]*Scenario{}
	for _, tc := range cases {
		if _, ok := parsed[tc.file]; ok {
			continue
		}
		data, err := os.ReadFile(tc.file)
		if err != nil {
			t.Fatalf("read %s: %v", tc.file, err)
		}
		sc, err := ParseYAML(data)
		if err != nil {
			t.Fatalf("ParseYAML %s: %v", tc.file, err)
		}
		parsed[tc.file] = sc
	}

	for _, tc := range cases {
		sc := parsed[tc.file]
		var step *Step
		for i := range sc.Steps {
			if sc.Steps[i].Name == tc.stepName {
				step = &sc.Steps[i]
				break
			}
		}
		if step == nil {
			t.Errorf("%s: step %q not found", tc.file, tc.stepName)
			continue
		}
		if len(step.DetectionProfiles) != 1 || step.DetectionProfiles[0] != tc.wantProfile {
			t.Errorf("%s / %q: DetectionProfiles = %v, want [%s]", tc.file, tc.stepName, step.DetectionProfiles, tc.wantProfile)
		}
	}
}
```

Note: this table has 38 cases (8 BlackCat + 9 Akira + 8 Play + 8 RansomHub + 5 Cl0p), matching the 38 steps written across Tasks 2–6.

- [ ] **Step 2: Run the test to verify it passes**

Run: `go test ./internal/scenario/... -run TestParseYAML_NewRansomwareFamiliesDetectionProfilesWired -v -count=1`
Expected: PASS, all 38 cases.

- [ ] **Step 3: Confirm the test can actually fail (temporarily break one assertion)**

Temporarily change the first case's `wantProfile` from `"windows_ad_discovery"` to `"wrong_profile_name"`, run:
```bash
go test ./internal/scenario/... -run TestParseYAML_NewRansomwareFamiliesDetectionProfilesWired -v -count=1
```
Expected: FAIL, with a diagnostic like `blackcat-kill-chain.yaml / "BlackCat Stage 1 — AD Domain & Privileged Account Discovery (T1087.002)": DetectionProfiles = [windows_ad_discovery], want [wrong_profile_name]`.

Revert the case back to `"windows_ad_discovery"`.

- [ ] **Step 4: Run the test again to verify it passes after revert**

Run: `go test ./internal/scenario/... -run TestParseYAML_NewRansomwareFamiliesDetectionProfilesWired -v -count=1`
Expected: PASS, all 38 cases.

- [ ] **Step 5: Run the full `internal/scenario` package suite**

Run: `go test ./internal/scenario/... -v -count=1`
Expected: 100% PASS, including all pre-existing tests (Deliverable 1's `TestParseYAML_RansomwareScenariosDetectionProfilesWired` and every other test in the package) unmodified.

- [ ] **Step 6: Build the whole module**

Run (from `orchestrator/`): `go build ./...`
Expected: no errors, no output.

- [ ] **Step 7: Vet the whole module**

Run (from `orchestrator/`): `go vet ./...`
Expected: no output.

- [ ] **Step 8: Commit**

```bash
git add orchestrator/internal/scenario/engine_test.go
git commit -m "test(scenario): wiring-guard for Ransomware Readiness Deliverable 2 — 38 steps assert detection_profiles"
git push
```
