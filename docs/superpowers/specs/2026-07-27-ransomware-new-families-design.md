# Ransomware Readiness Suite — New Family Content (Deliverable 2) — Design

**Scope:** Deliverable 2 of the "Ransomware Readiness suite" roadmap item ([[project_scenario_roadmap]]), authored against the completed Deliverable 1 baseline ([[project_ransomware_modernization_baseline]]). Five new builtin ransomware scenarios — BlackCat/ALPHV, Akira, Play, RansomHub, Cl0p — each with structured `detection_profiles:` from day one, following the canonical stage taxonomy established during this brainstorm.

## Problem

The Ransomware Readiness suite currently has one modern, wired scenario family: LockBit (`lockbit-kill-chain.yaml`), plus two generic/older scenarios (`ransomware-drill.yaml`, `endpoint-mastery/em-07-ransomware-readiness.yaml`) that Deliverable 1 wired onto the same Detection Validation model. All three are Windows-endpoint ransomware, but they represent one family's tradecraft (LockBit) generalized loosely — the platform has no content reflecting the four other ransomware families that, together with LockBit, account for the large majority of documented ransomware incidents in 2023–2025 CISA #StopRansomware advisories: BlackCat/ALPHV, Akira, Play, RansomHub, and Cl0p (MOVEit mass-exploitation campaign). A customer evaluating ransomware-readiness coverage today cannot validate detection against any of these five without hand-authoring content themselves.

## Non-goals

- **No changes to existing scenario files.** `lockbit-kill-chain.yaml`, `ransomware-drill.yaml`, `endpoint-mastery/em-07-ransomware-readiness.yaml`, and every other existing builtin scenario are untouched. This is 100% new, additive content.
- **No Linux/ESXi content.** All five families are documented to ship dedicated Linux/VMware-ESXi encryptor variants (a real differentiator from Windows-only LockBit), but this deliverable stays Windows-only — same platform scope as every existing ransomware scenario. An "ESXi/Linux Ransomware Extension" is tracked as a possible future roadmap item, not started here.
- **No literal exploitation of the real initial-access CVEs.** Where a family's documented initial access is a specific vulnerability (Play's ProxyNotShell/FortiOS CVEs, Cl0p's MOVEit/GoAnywhere CVE-2023-34362 and siblings), that vector is described in the scenario's `description:`/citation only — never an executed step. Where initial access is a safely-probable posture condition instead (Akira's RDP-without-MFA), it becomes a real, safe, read-only step.
- **No actual driver loading, no real security-product process termination, no unrestricted VSS deletion.** Every technique that could plausibly harm a production endpoint if implemented literally (BYOVD EDR-killer, `taskkill` against AV/EDR processes, VSS snapshot deletion) is either a guaranteed-safe proxy (impossible-to-load driver path, synthetic process name) or gated behind the existing `BAS_CONFIRM_VSS_DELETE=true` lab-only opt-in already shipped in `ransomware-drill.yaml`. See "Safety design" below.
- **No Go code changes.** Same reasoning as Deliverable 1 — `internal/scenario` load-time validation and the Provider Registry already handle new profile/provider references correctly.

## Architecture

### Canonical stage taxonomy

Every new scenario walks the same 8-phase skeleton: **Initial Access → Discovery → Credential Access → Defense Evasion → Lateral Movement → Encryption → Recovery Inhibition → Cleanup**. A family that doesn't documentarily exhibit a phase omits it entirely rather than forcing a step that doesn't fit (Cl0p is the clearest case — see its table below). `mitre_phases:` in each scenario's frontmatter lists only phases that have a real executable step, matching the existing convention in `lockbit-kill-chain.yaml` (its `mitre_phases:` list excludes phases only narrated in `description:`).

### Grounding citations (verified, not recalled from memory)

| Family | Advisory | Notable distinguishing tradecraft |
|---|---|---|
| BlackCat/ALPHV | CISA AA23-353A | Rust-based RaaS, intermittent encryption, self-propagation via PsExec/Group Policy |
| Akira | CISA AA24-109A | RDP/VPN-without-MFA initial access; VSS deletion via `Get-WmiObject Win32_ShadowCopy` (WMI, not `vssadmin`) |
| Play | CISA AA23-352A | ProxyNotShell/FortiOS exploitation; AdFind + Grixba-style AD/network recon; GPO-pushed Defender disable; intermittent encryption; `.PLAY` extension |
| RansomHub | CISA AA24-242A | EDRKillShifter BYOVD tool (RentDrv2/ThreatFireMonitor vulnerable drivers) to kill EDR — also documented reused by Play and other groups per Halcyon reporting |
| Cl0p | CISA AA23-158A | Mass exploitation of MOVEit (CVE-2023-34362) / GoAnywhere / Accellion MFT software; 2023+ campaigns were largely pure-exfiltration extortion with **no ransomware binary deployed** in most victims |

### New detection profiles (4 new; ~9 existing profiles reused)

All four use `provider: microsoft_defender` deliberately — the only EDR-category provider whose registry default is `VerificationAutomatic` (`internal/scenario/providers.go`), the same principle Deliverable 1 established: a profile with the "right" vendor name but a manual-default provider looks modernized while remaining as inert as free-text detection bullets.

**`scenarios/detection-profiles/windows_vulnerable_driver_load.yaml`** (T1562.001 — BYOVD EDR-killer staging; RansomHub's EDRKillShifter, also documented reused by Play):
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

**`scenarios/detection-profiles/windows_ad_discovery.yaml`** (T1087.002/T1018 — AdFind/Grixba-style domain enumeration; BlackCat, Play, RansomHub):
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

**`scenarios/detection-profiles/windows_security_process_termination.yaml`** (T1562.001 — Cl0p's classic `taskkill /f /im <AV-process>` pattern):
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

**`scenarios/detection-profiles/windows_rdp_nla_posture.yaml`** (T1021.001 — Akira's documented RDP/VPN-without-MFA initial access):
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

### Novel command implementations

The five behaviors below have no existing scenario step to copy — everything else reuses an existing, already-audited step's command pattern verbatim with family-specific flavor substitutions (run-ID tag, ransom-note text/extension, `[BAS-SIM-<FAMILY>-S<n>]` marker). See the per-family tables for exact reuse pointers.

**AD discovery** (used by BlackCat, Play, RansomHub — adapts the safe read-only pattern already proven in `volt-typhoon-lotl.yaml` Stage 4, adding DC enumeration):
```powershell
$ErrorActionPreference = 'SilentlyContinue'
$domainAdmins = & net.exe group "Domain Admins" /domain 2>&1 | Out-String
$computers    = & net.exe view 2>&1 | Out-String
$dcList       = & nltest.exe /dclist: 2>&1 | Out-String
$domainJoined = $domainAdmins -notmatch 'workstation is not|not be found|is not part'
Write-Output "EXEC T1087.002: AdFind-style domain enumeration -- Domain Admins group, network computer list (net view), and DC list (nltest) queried (domain_joined=$domainJoined). <FAMILY> uses this recon to map privileged accounts and domain controllers before credential theft. [BAS-SIM-<FAM>-Sx]"
Write-Output "FAIL: domain enumeration completed unimpeded via built-in LOLBins (net.exe, nltest.exe) -- no AdFind binary required. Alert on nltest.exe /dclist and net group 'Domain Admins' /domain from non-IT accounts."
```
`cleanup: ""` (read-only, nothing to clean up).

**BYOVD kernel-service staging probe** (used by Play, RansomHub — never loads real driver code):
```powershell
$ErrorActionPreference = 'SilentlyContinue'
$runId = if ($env:BAS_RUN_ID) { $env:BAS_RUN_ID.Substring(0,[Math]::Min(8,$env:BAS_RUN_ID.Length)) } else { '{0:x8}' -f (Get-Random -Maximum 0x7FFFFFFF) }
$svcName = "BAS-Sim-EDRKill-$runId"
$bogusPath = "C:\Windows\Temp\bas_nonexistent_$runId.sys"
& sc.exe create $svcName type= kernel binPath= $bogusPath start= demand 2>&1 | Out-Null
$created = (& sc.exe query $svcName 2>&1 | Out-String) -match 'SERVICE_NAME'
& sc.exe delete $svcName 2>&1 | Out-Null
if ($created) {
  Write-Output "EXEC T1562.001: kernel-mode service registration succeeded (no driver code executed -- binPath points to a nonexistent file, load is physically impossible). This is the exact 'sc create type= kernel' step RansomHub's EDRKillShifter and similar BYOVD tools use to stage a vulnerable driver before killing EDR processes. [BAS-SIM-<FAM>-Sx]"
  Write-Output "FAIL: kernel-type service creation via sc.exe was not blocked. Alert on 'sc create ... type= kernel' from non-driver-installer processes -- this is a near-zero-false-positive BYOVD precursor."
} else {
  Write-Output "PASS: kernel-type service registration was blocked or denied -- BYOVD staging surface is reduced. [BAS-SIM-<FAM>-Sx]"
}
```
`cleanup: |` — `& sc.exe delete $svcName 2>&1 | Out-Null` (idempotent safety net).

**Synthetic security-process taskkill** (used by Cl0p — target name can never match a real process):
```powershell
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
  Write-Output "EXEC T1562.001: taskkill.exe /F /IM spawned with a synthetic AV/EDR-style process name ($fakeTarget -- guaranteed not to match any real process, target result: $($out.Trim())). Cl0p's classic encryptor runs this identical command pattern against real security-product process names before encrypting. [BAS-SIM-CLOP-Sx]"
  Write-Output "FAIL: taskkill.exe /F /IM was allowed to spawn from PowerShell unimpeded. Alert on taskkill.exe/Stop-Process targeting known AV/EDR process image names, independent of whether the named process exists on the host."
} else {
  Write-Output "PASS: taskkill.exe spawn was blocked (AppLocker/WDAC/EDR prevented process creation). [BAS-SIM-CLOP-Sx]"
}
```
`cleanup: ""` (nothing persists).

**RDP/NLA posture check** (used by Akira as its Initial Access step — read-only registry query):
```powershell
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
```
`cleanup: ""` (read-only).

**Gated WMI-based VSS deletion** (Akira's Recovery Inhibition step — adapts the existing gated pattern already shipped in `ransomware-drill.yaml`'s "VSS Shadow Copy Deletion" step, swapping `vssadmin delete shadows` for Akira's documented exact WMI command):
```powershell
$ErrorActionPreference = 'SilentlyContinue'
$confirm = $env:BAS_CONFIRM_VSS_DELETE
if (-not $confirm -or $confirm -ne 'true') {
  Write-Output "SKIP: BAS_CONFIRM_VSS_DELETE not set to 'true' -- WMI-based VSS deletion skipped (default-disabled per ransomware safety policy). Set env var explicitly in an isolated lab to enable. [BAS-SIM-AKIRA-S7]"
  return
}
$shadows = Get-WmiObject Win32_ShadowCopy -ErrorAction SilentlyContinue | Where-Object { $_.VolumeName -match 'C:' }
if (-not $shadows -or @($shadows).Count -eq 0) {
  Write-Output "SKIP: no C: VSS shadow copies exist -- nothing to delete. Create a snapshot first with: vssadmin create shadow /for=C:"
  return
}
$oldest = @($shadows | Sort-Object InstallDate)[0]
$oldest.Delete()
$remaining = @(Get-WmiObject Win32_ShadowCopy -ErrorAction SilentlyContinue | Where-Object { $_.VolumeName -match 'C:' }).Count
Write-Output "FAIL: VSS shadow copy deleted via WMI Win32_ShadowCopy.Delete() -- Akira's exact documented command is 'Get-WmiObject Win32_Shadowcopy | ForEach-Object {\$_.Delete()}'. $remaining shadow copy/copies remaining on C:. Create a new snapshot to restore recovery capability. [BAS-SIM-AKIRA-S7]"
```
`cleanup: ""` — same as the existing precedent (deletion is irreversible by design; opt-in gate is the safety control, not cleanup).
`fidelity: lab-only`, `production_safe: false`, `risk: high` — same classification as the existing precedent step.

### Per-family stage tables

For every step below whose command isn't shown above, "reuse" means: copy that source step's `command:`/`cleanup:` verbatim, then substitute the `[BAS-SIM-<FAMILY>-S<n>]` tag, any family-specific temp-file/note naming (e.g. `bas_lockbit_*` → `bas_blackcat_*`), and the ransom-note extension/text called out in the table. `technique_id`, `requires_priv`, `timeout_sec`, `fidelity`, `production_safe`, `risk`, `blast_radius`, `reversible`, `telemetry`, and `detection` fields carry over unchanged from the source step unless noted.

#### `scenarios/blackcat-kill-chain.yaml` (8 steps; Initial Access citation-only — RaaS affiliates use purchased access/valid accounts/phishing, nothing safely agent-simulatable)

| # | Phase | Technique | Profile | Command source |
|---|---|---|---|---|
| 1 | Discovery | AD domain enumeration (T1087.002) | `windows_ad_discovery` | Novel command above |
| 2 | Discovery | Security software discovery (T1518.001) | `windows_security_software_discovery` | Reuse `lockbit-kill-chain.yaml` Stage 1 |
| 3 | Credential Access | SAM/registry hive theft (T1003.002) | `windows_sam_theft` | Reuse `volt-typhoon-lotl.yaml` Stage 5 (`reg save HKLM\SAM`/`HKLM\SYSTEM`) |
| 4 | Defense Evasion | Defender tampering (T1562.001) | `windows_defender_tampering` | Reuse `ransomware-drill.yaml` "Defender RTP Disable" step |
| 5 | Lateral Movement | Malicious service — PsExec/GPO self-propagation (T1543.003) | `windows_malicious_service` | Reuse `ransomware-drill.yaml` "Malicious Service Probe" step |
| 6 | Encryption | Ransomware simulation (T1486) | `windows_ransomware_encryption` | Reuse `lockbit-kill-chain.yaml` Stage 4; extension `.blackcat`; note in description that real BlackCat uses intermittent (partial-file) encryption — not functionally replicated since detection surface is unaffected by chunk size |
| 7 | Recovery Inhibition | VSS enumeration, production-safe (T1490) | `windows_vss_inhibition` | Reuse `lockbit-kill-chain.yaml` Stage 2 |
| 8 | Cleanup | Log clearing (T1070.001) | `windows_log_manipulation` | Reuse `lockbit-kill-chain.yaml` Stage 5 |

#### `scenarios/akira-kill-chain.yaml` (9 steps)

| # | Phase | Technique | Profile | Command source |
|---|---|---|---|---|
| 1 | Initial Access | RDP/NLA exposure posture check (T1021.001) | `windows_rdp_nla_posture` | Novel command above |
| 2 | Discovery | Network share discovery (T1135) | `windows_network_share_discovery` | Reuse `em-07-ransomware-readiness.yaml` Stage 1B |
| 3 | Credential Access | SAM/registry hive theft (T1003.002) | `windows_sam_theft` | Reuse `volt-typhoon-lotl.yaml` Stage 5 |
| 4 | Defense Evasion | Defender tampering (T1562.001) | `windows_defender_tampering` | Reuse `ransomware-drill.yaml` "Defender Exclusion Invocation" step |
| 5 | Lateral Movement | SMB ADMIN$ probe (T1021.002) | `windows_smb_lateral_probe` | Reuse `lockbit-kill-chain.yaml` Stage 3 |
| 6 | Encryption | Ransomware simulation (T1486) | `windows_ransomware_encryption` | Reuse `lockbit-kill-chain.yaml` Stage 4; extension `.akira` |
| 7 | Recovery Inhibition | VSS enumeration, `vssadmin`, production-safe (T1490) | `windows_vss_inhibition` | Reuse `lockbit-kill-chain.yaml` Stage 2 |
| 8 | Recovery Inhibition | VSS deletion via WMI `Win32_ShadowCopy` — Akira's exact documented command, **lab-only**, gated `BAS_CONFIRM_VSS_DELETE=true` (T1490) | `windows_vss_inhibition` | Novel command above (adapts `ransomware-drill.yaml`'s gated pattern) |
| 9 | Cleanup | Log clearing (T1070.001) | `windows_log_manipulation` | Reuse `lockbit-kill-chain.yaml` Stage 5 |

#### `scenarios/play-kill-chain.yaml` (8 steps; Initial Access citation-only — ProxyNotShell/FortiOS exploitation of a specific vulnerable app rarely present on a generic endpoint isn't worth a step that SKIPs almost universally)

| # | Phase | Technique | Profile | Command source |
|---|---|---|---|---|
| 1 | Discovery | AdFind-style AD enumeration (T1087.002) | `windows_ad_discovery` | Novel command above |
| 2 | Discovery | Grixba-style network/share scan (T1135) | `windows_network_share_discovery` | Reuse `em-07-ransomware-readiness.yaml` Stage 1B |
| 3 | Defense Evasion | GPO-pushed Defender disable (T1562.001) | `windows_defender_tampering` | Reuse `ransomware-drill.yaml` "Defender RTP Disable" step |
| 4 | Defense Evasion | EDR-killer/BYOVD staging probe (T1562.001) | `windows_vulnerable_driver_load` | Novel command above |
| 5 | Lateral Movement | SMB ADMIN$ probe (T1021.002) | `windows_smb_lateral_probe` | Reuse `lockbit-kill-chain.yaml` Stage 3 |
| 6 | Encryption | Ransomware simulation (T1486) | `windows_ransomware_encryption` | Reuse `lockbit-kill-chain.yaml` Stage 4; extension `.PLAY` (Play's actual documented extension); note intermittent encryption in description, not functionally replicated |
| 7 | Recovery Inhibition | VSS enumeration, production-safe (T1490) | `windows_vss_inhibition` | Reuse `lockbit-kill-chain.yaml` Stage 2 |
| 8 | Cleanup | Log clearing (T1070.001) | `windows_log_manipulation` | Reuse `lockbit-kill-chain.yaml` Stage 5 |

#### `scenarios/ransomhub-kill-chain.yaml` (8 steps; Initial Access citation-only — RaaS affiliate-driven, varies)

| # | Phase | Technique | Profile | Command source |
|---|---|---|---|---|
| 1 | Discovery | Security software discovery (T1518.001) | `windows_security_software_discovery` | Reuse `lockbit-kill-chain.yaml` Stage 1 |
| 2 | Discovery | Network share discovery (T1135) | `windows_network_share_discovery` | Reuse `em-07-ransomware-readiness.yaml` Stage 1B |
| 3 | Credential Access | SAM/registry hive theft (T1003.002) | `windows_sam_theft` | Reuse `volt-typhoon-lotl.yaml` Stage 5 |
| 4 | Defense Evasion | Defender tampering (T1562.001) | `windows_defender_tampering` | Reuse `ransomware-drill.yaml` "Defender Exclusion Invocation" step |
| 5 | Defense Evasion | EDRKillShifter-style BYOVD staging probe — RansomHub's own signature tool (T1562.001) | `windows_vulnerable_driver_load` | Novel command above |
| 6 | Encryption | Ransomware simulation, double-extortion note (T1486) | `windows_ransomware_encryption` | Reuse `lockbit-kill-chain.yaml` Stage 4; extension `.ransomhub` |
| 7 | Recovery Inhibition | VSS enumeration, production-safe (T1490) | `windows_vss_inhibition` | Reuse `lockbit-kill-chain.yaml` Stage 2 |
| 8 | Cleanup | Log clearing (T1070.001) | `windows_log_manipulation` | Reuse `lockbit-kill-chain.yaml` Stage 5 |

#### `scenarios/clop-kill-chain.yaml` (5 steps — deliberately lean; Credential Access/Lateral Movement/Encryption/Recovery Inhibition genuinely absent from documented 2023+ Cl0p/MOVEit campaigns. Initial Access — mass exploitation of MOVEit/GoAnywhere/Accellion — citation-only, same reasoning as Play.)

| # | Phase | Technique | Profile | Command source |
|---|---|---|---|---|
| 1 | Discovery | High-value BFSI file discovery (T1083) | `windows_file_discovery` | Reuse `em-07-ransomware-readiness.yaml` Stage 1A |
| 2 | Defense Evasion | Security-process termination, `taskkill /im` pattern (T1562.001) | `windows_security_process_termination` | Novel command above |
| 3 | Collection | Archive staging of discovered files (T1560) | `windows_archive_staging` | Reuse `collection-staging-exfil.yaml` archive-staging step |
| 4 | Exfiltration | Cloud egress / mass data transfer (T1567) | `windows_cloud_egress` | Reuse `collection-staging-exfil.yaml` cloud-egress step |
| 5 | Cleanup | Log clearing (T1070.001) | `windows_log_manipulation` | Reuse `lockbit-kill-chain.yaml` Stage 5 |

### File/task structure

**18 new builtin files** (each paired with a `.sig`):
- 5 scenarios: `scenarios/blackcat-kill-chain.yaml`, `akira-kill-chain.yaml`, `play-kill-chain.yaml`, `ransomhub-kill-chain.yaml`, `clop-kill-chain.yaml`
- 4 detection profiles: `scenarios/detection-profiles/windows_vulnerable_driver_load.yaml`, `windows_ad_discovery.yaml`, `windows_security_process_termination.yaml`, `windows_rdp_nla_posture.yaml`

No Go code changes.

**Implementation task order** (7 tasks — profiles first since scenarios reference them):
1. 4 new detection-profile files
2. `blackcat-kill-chain.yaml` (8 steps)
3. `akira-kill-chain.yaml` (9 steps)
4. `play-kill-chain.yaml` (8 steps)
5. `ransomhub-kill-chain.yaml` (8 steps)
6. `clop-kill-chain.yaml` (5 steps)
7. Wiring-guard test + final regression

### Testing, signing, migration

- **Per-file validation:** `python3 -c "import yaml; yaml.safe_load(open('...'))"` for structural validity on every new file, plus the standing PowerShell-AST-parser check on every `command:`/`cleanup:` block before committing (existing repo convention for all new scenario content).
- **Wiring-guard test:** new function `TestParseYAML_NewRansomwareFamiliesDetectionProfilesWired` in `orchestrator/internal/scenario/engine_test.go` — kept separate from Deliverable 1's `TestParseYAML_RansomwareScenariosDetectionProfilesWired` (different file set, no reason to conflate). Table-driven, asserting `DetectionProfiles` for all 38 steps across the 5 new files. Same "prove it can fail" check as Deliverable 1 (temporarily break one assertion, confirm FAIL, revert) before the final commit.
- **Full regression:** `go test ./internal/scenario/... -v -count=1`, `go build ./...`, `go vet ./...` — all must pass clean, matching Deliverable 1's bar.
- **Signing:** `go run scripts/signer.go sign private_key.pem <path>` (run from `orchestrator/`) for all 18 new files.
- **Migration:** none — these are brand-new files; no existing scenario behavior changes; no back-compat concerns.

### Safety design summary

Three techniques in this deliverable could plausibly cause real harm if implemented literally on a production BFSI endpoint. Each has a specific, deliberate safety design:

1. **BYOVD/EDR-killer staging** (`windows_vulnerable_driver_load`, used by Play & RansomHub): never loads a real driver. `sc.exe create ... type= kernel binPath=<a path that is guaranteed not to exist>` — the kernel-service registration is real (and is exactly what EDR should flag), but the driver load is physically impossible since the target file never exists. Immediately `sc.exe delete`'d.
2. **Security-process termination** (`windows_security_process_termination`, used by Cl0p): never targets a real AV/EDR process name (unlike `windows_backup_service_stop`, which safely stops-and-restarts real but non-security OS services — killing a live security product's process mid-test is a materially bigger operational risk and is out of scope here). Targets a synthetic, run-ID-suffixed name that can never match a real process, while still producing the exact `taskkill.exe /F /IM` command-line telemetry a real EDR should alert on.
3. **WMI-based VSS deletion** (Akira's Recovery Inhibition step, extending `windows_vss_inhibition`): genuinely destructive and irreversible, so it is **not** production-safe by default. Reuses the exact `BAS_CONFIRM_VSS_DELETE=true` opt-in gate already shipped and tested in `ransomware-drill.yaml`, deletes only the single oldest C: shadow copy, and defaults to a clean `SKIP` with no state change unless the operator explicitly opts in inside an isolated lab.

All other new steps (AD discovery, RDP/NLA posture check) are read-only queries with no state change, same safety class as existing discovery-phase steps throughout the codebase.
