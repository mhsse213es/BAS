# Black Basta Kill Chain Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `scenarios/black-basta-kill-chain.yaml`, a 10-step real-world-grounded Black Basta ransomware kill chain, fully registered across the corpus's touchpoints and signed — sub-project #10's first family-content pass.

**Architecture:** Every step reuses an already-shipped safe-simulation pattern verbatim from the existing corpus (apt36/em-04/Akira/BlackCat/Clop/ransomware-drill) — no new simulation technique, no `execclass.go` changes, no `dispatch.go` changes (verified this session: Step 9/10's step name and skip-text are copied byte-for-byte from `ransomware-drill.yaml`, which `dispatch.go` already recognizes). Two technique IDs (T1566.001, T1003.001) are new to the corpus and need new `internal/rwtaxonomy` domain-mapping entries; every other technique this scenario uses is already mapped.

**Tech Stack:** YAML (scenario content), Go (tests + 7 registration touchpoints), PowerShell (step commands) — no new dependencies.

**Spec:** `docs/superpowers/specs/2026-10-12-black-basta-kill-chain-design.md`

## Global Constraints

- No `execclass.go` changes — every `(technique_id, action_key)` pair this scenario uses already has a catalog entry, confirmed by reading the file this session.
- No `dispatch.go` changes — Step 9's name (`"VSS + Backup Catalog Enumeration"`) and Step 10's skip-text (`"bas_confirm_vss_delete not set"`, `"no c: vss shadow copies exist"`) are copied verbatim from `ransomware-drill.yaml`, which `dispatch.go` already recognizes case-insensitively. Confirmed by reading `dispatch.go` this session — do not add any new recognition code.
- None of the 9 existing scenario YAMLs are modified.
- **Finding from this plan's own grounding, not in the original spec table:** `contentregistry.structuralCheck`'s shipped validation requires `confirmed` to have **≥2** `threat_intel_sources` entries, with no structural way to treat "one definitive government advisory" as sufficient on its own (the schema has no source-tier field). The spec's confidence table is revised accordingly: T1566.001, T1562.001, and T1543.003 move from `confirmed` to `reported` (each has only one named, confidently-cited source) — see the corrected table in Task 1. T1083/T1486/T1490 keep `confirmed` because each genuinely has 2+ independently-named sources. This is a deliberate, conservative resolution, not a workaround — every step's final confidence is honest about its actual citation count.
- `internal/rwtaxonomy`'s `TechniqueDomain` map is missing entries for **T1566.001** and **T1003.001** (confirmed by reading `mapping.go` this session — every other technique this scenario uses, T1021.002/T1083/T1486/T1490/T1543.003/T1562.001/T1567.002, already has an entry). Both must be added in Task 2, or `rwtaxonomy`'s own `TestTechniqueDomain_MatchesRealCorpus` will correctly fail the moment this scenario is registered into its corpus list.
- T1190 (ConnectWise CVE-2024-1709 exploitation) is documented in the scenario's `description:` as a real, unmodeled alternative initial-access path — never represented as tested coverage, never added as a step.

## Review Focus

- `action_key` must be set explicitly for every technique with more than one `execclass.go` catalog entry (T1003.001, T1562.001, T1543.003, T1486, T1490) — an omitted or wrong `action_key` on a multi-entry technique is the single easiest mistake to make, and resolves to the wrong simulation behavior silently. (Task 1)
- Step 10's skip-text must match `dispatch.go`'s recognition exactly — verified character-for-character against the real file in this plan's grounding, not assumed. (Task 1, Task 4)
- Every step's `family_attribution_confidence`/`threat_intel_sources` pair must independently satisfy `contentregistry.structuralCheck`'s already-shipped rules (this content is itself subject to the validation infrastructure pass #10 just shipped) — a step that fails its own scenario's structural check would still load (structural failure is diagnostic-only, never a runtime gate) but would be a real authoring defect. (Task 1, Task 4)
- The T1190 alternative-path note and both documented source disagreements (T1003.001 vs. CISA's T1068 classification; T1567.002 vs. the T1048 alternative mapping) must land somewhere real and readable — the `Step` schema has no freeform per-step notes field (confirmed by reading `types.go`), so both go in the scenario-level `description:`. (Task 1)
- All 7 registration touchpoints — including `internal/rwtaxonomy`'s two new domain-mapping entries, which are easy to miss since they're not just a file-list append like the other 6 — must each get an owning step. (Task 2)

---

### Task 1: Write the scenario YAML and its parse smoke test

**Files:**
- Create: `scenarios/black-basta-kill-chain.yaml`
- Create: `orchestrator/internal/scenario/black_basta_kill_chain_test.go`

**Interfaces:**
- Consumes: `scenario.ParseYAML` (`orchestrator/internal/scenario/engine.go:274`), `scenario.FamilyAttribution{Unsourced,Inferred,Reported,Confirmed}` constants and `scenario.ThreatIntelSource{Reference,URL}` (from sub-project #10's infrastructure pass, already shipped).
- Produces: the scenario file and its `id: black-basta-kill-chain`, consumed by every touchpoint in Task 2.

- [ ] **Step 1: Write the failing smoke test**

Create `orchestrator/internal/scenario/black_basta_kill_chain_test.go`:

```go
package scenario

import (
	"os"
	"path/filepath"
	"testing"
)

func TestBlackBastaKillChain_ParsesWithTenStepsWindowsOnlyFullyGrounded(t *testing.T) {
	dir, err := filepath.Abs("../../../scenarios")
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "black-basta-kill-chain.yaml"))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	sc, err := ParseYAML(b)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(sc.SupportedOS) != 1 || sc.SupportedOS[0] != "windows" {
		t.Fatalf("SupportedOS = %v, want [windows]", sc.SupportedOS)
	}
	wantTechniques := []string{
		"T1566.001", "T1003.001", "T1562.001", "T1543.003", "T1021.002",
		"T1083", "T1567.002", "T1486", "T1490", "T1490",
	}
	if len(sc.Steps) != len(wantTechniques) {
		t.Fatalf("got %d steps, want %d", len(sc.Steps), len(wantTechniques))
	}
	for i, want := range wantTechniques {
		if got := sc.Steps[i].TechniqueID; got != want {
			t.Errorf("step %d: technique_id = %q, want %q", i, got, want)
		}
	}
	for i, st := range sc.Steps {
		if st.FamilyAttributionConfidence == "" {
			t.Errorf("step %d (%s): family_attribution_confidence is empty -- every technique-tagged step in this scenario must have real grounding", i, st.TechniqueID)
			continue
		}
		if len(st.ThreatIntelSources) == 0 {
			t.Errorf("step %d (%s): family_attribution_confidence=%q but threat_intel_sources is empty", i, st.TechniqueID, st.FamilyAttributionConfidence)
		}
		if st.FamilyAttributionConfidence == FamilyAttributionConfirmed && len(st.ThreatIntelSources) < 2 {
			t.Errorf("step %d (%s): confirmed with only %d source(s) -- contentregistry's structural check requires >=2", i, st.TechniqueID, len(st.ThreatIntelSources))
		}
		if st.LastReviewed == "" {
			t.Errorf("step %d (%s): last_reviewed is empty", i, st.TechniqueID)
		}
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/scenario/ -run TestBlackBastaKillChain_ParsesWithTenStepsWindowsOnlyFullyGrounded -v`
Expected: FAIL — `read: ... black-basta-kill-chain.yaml: ... cannot find the file specified` (the file doesn't exist yet).

- [ ] **Step 3: Write the scenario file**

Create `scenarios/black-basta-kill-chain.yaml` with this exact content:

```yaml
id: black-basta-kill-chain
name: Black Basta Kill Chain — Ransomware Emulation
description: >
  Ten-stage telemetry-safe emulation of the Black Basta ransomware kill
  chain targeting Windows endpoints. Reflects documented Black Basta
  tradecraft validated against CISA/FBI/HHS/MS-ISAC Advisory AA24-131A
  (#StopRansomware: Black Basta): spearphishing initial access, Backstab-
  style EDR tampering, and vssadmin.exe-based shadow-copy deletion (a
  different mechanism than Akira's WMI-based deletion — each family's
  scenario models its own documented tradecraft, never a generic
  stand-in).

  KILL CHAIN STAGES:
    1. Initial Access      — Office child-process chain, phishing-document behavioral emulation (T1566.001)
    2. Credential Access    — LSASS handle-access probe, Mimikatz-style (T1003.001)
    3. Defense Evasion      — EDR-tampering invocation probe (T1562.001)
    4. Persistence          — Windows service create/start/stop/delete (T1543.003)
    5. Lateral Movement     — SMB admin-share reachability check (T1021.002)
    6. Discovery            — BFSI file-target reconnaissance (T1083)
    7. Exfiltration         — cloud/Mega storage egress reachability (T1567.002)
    8. Ransomware Simulation — isolated-range XOR encryption simulation (T1486)
    9. Recovery Inhibition A — VSS + backup-catalog enumeration (T1490)
   10. Recovery Inhibition B — vssadmin-based VSS deletion (T1490, lab-only)

  ALTERNATIVE INITIAL ACCESS (documented, NOT modeled): CISA AA24-131A also
  documents Black Basta affiliates exploiting ConnectWise vulnerability
  CVE-2024-1709 (T1190) as a secondary initial-access path emerging
  February 2024. This scenario does not model T1190 — no safe simulation
  contract exists for a single-product CVE exploit, and introducing one
  is only worth doing with a real control-validation objective, not
  merely to raise technique count. T1190 is documented here as a known,
  unmodeled gap, never represented as tested coverage.

  DOCUMENTED SOURCE DISAGREEMENTS (preserved, not silently resolved):
    - Stage 2 (T1003.001): CISA AA24-131A's own table categorizes Black
      Basta's Mimikatz reference under T1068 (Exploitation for Privilege
      Escalation), grouped with Zerologon/NoPac/PrintNightmare, not under
      T1003. This scenario models T1003.001 per MITRE's general tool-to-
      technique convention (Mimikatz's sekurlsa module is MITRE's own
      canonical T1003.001 example), since the step emulates credential-
      dumping behavior specifically — not because CISA's table itself
      uses that ID. family_attribution_confidence is "reported", not
      "confirmed", on this basis.
    - Stage 7 (T1567.002): some sources map Black Basta's Rclone/WinSCP-
      based exfiltration to T1048 (Exfiltration Over Alternative
      Protocol) rather than T1567.002. This scenario models T1567.002,
      consistent with Qualys and Trend Micro's Ransomware Spotlight and
      with rwevidence's own existing T1567.002 model, but the T1048
      mapping disagreement is preserved here, not treated as resolved.

  REVIEW NOTE ON CONFIDENCE LEVELS: several steps are grounded in a single
  highly-authoritative source (a government advisory or MITRE ATT&CK's
  own curated Software page) but are still rated "reported" rather than
  "confirmed" — this scenario's structural validation requires at least
  two independent citations for "confirmed", and a single source's
  authority, however strong, cannot be distinguished from a weaker one
  by that mechanical count. "Confirmed" here always means at least two
  genuinely distinct sources were found and cited; "reported" covers both
  single-source and some multi-source cases.

  ORDERING CAVEAT: this step sequence is a representative, documented
  kill chain for authoring purposes — it is not a claim that every real
  Black Basta incident follows this exact order, and not a definitive
  reconstruction of operational chronology.

  SAFETY: No real encryption of user data, no real credential extraction,
  no real EDR/Defender configuration change, no real phishing email or
  document. Stage 10 is lab-only and default-disabled — it requires the
  operator to explicitly set BAS_CONFIRM_VSS_DELETE=true in an isolated
  lab; without it, the step SKIPs with no state change and deletes at
  most ONE (the oldest) real C: shadow copy when enabled. All other
  stages are production-safe. Windows only. [BAS-SIM] tagged throughout.
author: Audspect Research
executable: true
local_check: false
supported_os: [windows]
tags:
  - black-basta
  - ransomware
  - bfsi
  - kill-chain
  - t1003
  - t1021
  - t1083
  - t1486
  - t1490
  - t1543
  - t1562
  - t1567
  - mitre
mitre_phases:
  - initial-access
  - credential-access
  - defense-evasion
  - persistence
  - lateral-movement
  - discovery
  - exfiltration
  - impact

live_policy:
  block_on_domain_controller: false
  require_dc_reachable: false
  max_spray_attempts: 0
  spray_account_allowlist: []
  execution_window: ""

steps:

  # ---------------------------------------------------------------------------
  # Stage 1 — Initial Access: Office Child Process Chain (T1566.001)
  # ---------------------------------------------------------------------------
  - name: "Black Basta Stage 1 — Office Child Process Chain (winword.exe -> powershell.exe) (T1566.001)"
    technique_id: T1566.001
    framework: custom
    executor: powershell
    requires_priv: user
    timeout_sec: 30
    fidelity: telemetry-safe
    production_safe: true
    risk: low
    blast_radius: "Copies cmd.exe to a temp winword.exe, spawns powershell.exe with a benign exit, deletes the copy. No real macro, document, or phishing email."
    reversible: true
    telemetry:
      - "Sysmon EID 1 (process create): Image=powershell.exe, ParentImage=%TEMP%\\winword.exe"
      - "Security EID 4688 (process create with command line) if process auditing enabled"
    detection:
      - "EDR: Office process (winword.exe) spawning a shell  -  primary phishing-document initial-access detection signal"
      - "SIEM: parent-child rule winword.exe -> powershell.exe / cmd.exe"
    threat_intel_sources:
      - reference: "CISA/FBI/HHS/MS-ISAC Advisory AA24-131A — #StopRansomware: Black Basta"
        url: "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-131a"
    last_reviewed: "2026-10-12"
    family_attribution_confidence: reported
    command: |
      $ErrorActionPreference = 'SilentlyContinue'
      $tmp = Join-Path $env:TEMP 'winword.exe'
      Copy-Item "$env:SystemRoot\System32\cmd.exe" $tmp -Force
      $psi = New-Object System.Diagnostics.ProcessStartInfo
      $psi.FileName = $tmp
      $psi.Arguments = '/c powershell.exe -NoProfile -NonInteractive -Command "Write-Output BAS-SIM-T1566"'
      $psi.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Hidden
      $psi.CreateNoWindow = $true
      $p = [System.Diagnostics.Process]::Start($psi)
      if ($p) { $p.WaitForExit(10000) | Out-Null; $ec = $p.ExitCode } else { $ec = -1 }
      Remove-Item $tmp -Force -ErrorAction SilentlyContinue
      if ($ec -ge 0) {
        Write-Output "EXEC: winword.exe->powershell.exe child-process chain fired (exit $ec)  -  expect Sysmon EID 1 with ParentImage=winword.exe. Benign payload only. [BAS-SIM-BLACKBASTA-S1]"
      } else {
        Write-Output "PASS: child process could not be started  -  AppLocker/WDAC/EDR blocked Office process spawning (good)."
      }
    cleanup: |
      Remove-Item (Join-Path $env:TEMP 'winword.exe') -Force -ErrorAction SilentlyContinue

  # ---------------------------------------------------------------------------
  # Stage 2 — Credential Access: LSASS Handle Access (T1003.001)
  # ---------------------------------------------------------------------------
  - name: "Black Basta Stage 2 — LSASS Handle Access (PROCESS_VM_READ), Mimikatz-style (T1003.001)"
    technique_id: T1003.001
    action_key: handle_probe
    framework: custom
    executor: powershell
    requires_priv: admin
    timeout_sec: 30
    fidelity: telemetry-safe
    production_safe: true
    risk: medium
    reversible: true
    blast_radius: "Opens a read handle to lsass.exe with PROCESS_VM_READ, then immediately closes it. No memory is read or dumped."
    telemetry:
      - "Sysmon EID 10: SourceImage=powershell.exe TargetImage=lsass.exe GrantedAccess=0x1010"
    detection:
      - "EDR: handle to LSASS with VM_READ — Sigma sysmon_lsass_memdump.yml family"
    threat_intel_sources:
      - reference: "Kroll — Black Basta: Technical Analysis (names Mimikatz among Black Basta's tools)"
        url: "https://www.kroll.com/en/publications/cyber/black-basta-technical-analysis"
    last_reviewed: "2026-10-12"
    family_attribution_confidence: reported
    command: |
      $ErrorActionPreference = 'SilentlyContinue'
      $sig = @'
      using System;
      using System.Runtime.InteropServices;
      public static class BasMem {
        [DllImport("kernel32.dll", SetLastError=true)] public static extern IntPtr OpenProcess(uint a, bool i, int pid);
        [DllImport("kernel32.dll", SetLastError=true)] public static extern bool CloseHandle(IntPtr h);
      }
      '@
      try { Add-Type -TypeDefinition $sig -ErrorAction Stop } catch { Write-Output "SKIP: could not compile P/Invoke probe."; return }
      $lsass = Get-Process lsass -ErrorAction SilentlyContinue | Select-Object -First 1
      if (-not $lsass) { Write-Output "SKIP: lsass.exe not found."; return }
      $h = [BasMem]::OpenProcess(0x1010, $false, $lsass.Id)
      if ($h -ne [IntPtr]::Zero) {
        [void][BasMem]::CloseHandle($h)
        Write-Output "FAIL: opened a PROCESS_VM_READ handle to LSASS unblocked — credential memory is reachable. Enable RunAsPPL/Credential Guard. [BAS-SIM-BLACKBASTA-S2]"
      } else {
        $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Write-Output "PASS: access to LSASS was DENIED (Win32 error $err) — RunAsPPL/Credential Guard/EDR protected LSASS memory. [BAS-SIM-BLACKBASTA-S2]"
      }
    cleanup: ""

  # ---------------------------------------------------------------------------
  # Stage 3 — Defense Evasion: EDR-Tampering Invocation Probe (T1562.001)
  # ---------------------------------------------------------------------------
  - name: "Black Basta Stage 3 — EDR-Tampering Invocation Probe (cmdline probe  -  no state change) (T1562.001)"
    technique_id: T1562.001
    action_key: enumerate
    detection_profiles:
      - windows_defender_tampering
    framework: custom
    executor: powershell
    requires_priv: user
    timeout_sec: 20
    fidelity: telemetry-safe
    production_safe: true
    risk: low
    blast_radius: "Invokes Add-MpPreference cmdline in a dry-run context that exits before modifying any exclusion. Security state is NOT changed. Represents Black Basta's documented use of a tool (Backstab) to disable EDR."
    reversible: true
    telemetry:
      - "Security EID 4688 (powershell.exe with Add-MpPreference -ExclusionPath in command line)"
      - "PowerShell EID 4104 (script block: Add-MpPreference invocation) if ScriptBlock logging enabled"
    detection:
      - "EDR: PowerShell invoking Add-MpPreference  -  primary EDR/Defender tampering signal"
      - "SIEM: cmdline containing Add-MpPreference and ExclusionPath from a non-management process"
    threat_intel_sources:
      - reference: "CISA/FBI/HHS/MS-ISAC Advisory AA24-131A — #StopRansomware: Black Basta (Table 4: deployed a tool called Backstab to disable EDR tooling)"
        url: "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-131a"
    last_reviewed: "2026-10-12"
    family_attribution_confidence: reported
    command: |
      $ErrorActionPreference = 'SilentlyContinue'
      $cmdLine = 'Add-MpPreference -ExclusionPath $env:TEMP'
      Write-Output "EXEC: EDR-tampering invocation probe  -  cmdline '$cmdLine' logged to EID 4104/4688. Security state NOT modified (dry-run). Black Basta is documented using Backstab to disable EDR before encryption. [BAS-SIM-BLACKBASTA-S3]"
      Write-Output "TELEMETRY: if ScriptBlock logging (EID 4104) captured this block, the control is detecting EDR tampering attempts correctly."
    cleanup: ""

  # ---------------------------------------------------------------------------
  # Stage 4 — Persistence: Windows Service Create/Start/Stop/Delete (T1543.003)
  # ---------------------------------------------------------------------------
  - name: "Black Basta Stage 4 — Windows Service Persistence Probe (sc.exe create/start/stop/delete) (T1543.003)"
    technique_id: T1543.003
    action_key: service_create_start_stop_delete
    detection_profiles:
      - windows_malicious_service
    framework: custom
    executor: powershell
    requires_priv: admin
    timeout_sec: 45
    fidelity: lab-only
    production_safe: false
    risk: medium
    blast_radius: "Creates a benign service (cmd.exe /c echo) via sc.exe, logs binary path + parent process + execution lineage, starts, stops, deletes. MITRE ATT&CK documents Black Basta creating a new service to establish persistence."
    reversible: true
    telemetry:
      - "Security EID 4697 (service installed) + EID 7045 (new service installed in system)"
      - "Security EID 4688 (sc.exe create + start + stop + delete)"
    detection:
      - "SIEM: new service installed with binary path in non-standard directory  -  persistence signal"
      - "EDR: service binary path pointing to cmd.exe or user-writable path"
    threat_intel_sources:
      - reference: "MITRE ATT&CK — Black Basta (Software S1070): \"Black Basta can create a new service to establish persistence.\""
        url: "https://attack.mitre.org/software/S1070/"
    last_reviewed: "2026-10-12"
    family_attribution_confidence: reported
    command: |
      $ErrorActionPreference = 'SilentlyContinue'
      $svcName   = 'BAS-SIM-BlackBastaSvc'
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
        Write-Output "FAIL: service '$svcName' created+started+deleted (removed=$gone). BinaryPath='$svcBin'. Parent=$parentImg (PID=$parentPid). Expect EID 4697+7045. Black Basta-style service persistence confirmed. [BAS-SIM-BLACKBASTA-S4]"
      } else {
        Write-Output "PASS: sc.exe service creation blocked  -  AppLocker / restricted token / policy prevented malicious service deployment. [BAS-SIM-BLACKBASTA-S4]"
      }
    cleanup: |
      sc.exe stop   BAS-SIM-BlackBastaSvc 2>&1 | Out-Null
      sc.exe delete BAS-SIM-BlackBastaSvc 2>&1 | Out-Null

  # ---------------------------------------------------------------------------
  # Stage 5 — Lateral Movement: SMB Admin Share Probe (T1021.002)
  # ---------------------------------------------------------------------------
  - name: "Black Basta Stage 5 — SMB Admin Share Lateral Movement Probe (T1021.002)"
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
    threat_intel_sources:
      - reference: "Elisity — How to Stop Lateral Movement in Black Basta, Akira, and LockBit Ransomware Attacks"
        url: "https://www.elisity.com/blog/how-to-stop-lateral-movement-in-black-basta-akira-and-lockbit-ransomware-attacks"
    last_reviewed: "2026-10-12"
    family_attribution_confidence: reported
    command: |
      $ErrorActionPreference = 'SilentlyContinue'
      $netOut = & net use '\\127.0.0.1\ADMIN$' 2>&1 | Out-String
      & net use '\\127.0.0.1\ADMIN$' /delete 2>&1 | Out-Null
      $accessible = $netOut -match 'command completed successfully'
      $authFailed = $netOut -match 'System error 5|Access is denied|System error 1326|logon failure'
      if ($accessible) {
        Write-Output "EXEC T1021.002: \\\\127.0.0.1\\ADMIN$ accessible with current token (disconnected). Black Basta would use harvested creds here to push its encryptor laterally. Security EID 5140 logged. [BAS-SIM-BLACKBASTA-S5]"
        Write-Output "FAIL: ADMIN$ share accessible from user context — disable admin shares via GPO (AutoShareWks=0) or ensure SMB signing + LAPS is enforced."
      } elseif ($authFailed) {
        Write-Output "PASS: ADMIN$ access denied (auth failure or disabled)  -  lateral movement via admin share blocked. [BAS-SIM-BLACKBASTA-S5]"
      } else {
        Write-Output "INFO: ADMIN$ probe result inconclusive: $($netOut.Trim()). [BAS-SIM-BLACKBASTA-S5]"
      }
    cleanup: |
      & net use '\\127.0.0.1\ADMIN$' /delete 2>&1 | Out-Null

  # ---------------------------------------------------------------------------
  # Stage 6 — Discovery: BFSI File Target Reconnaissance (T1083)
  # ---------------------------------------------------------------------------
  - name: "Black Basta Stage 6 — BFSI File Target Reconnaissance (T1083)"
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
      - "UEBA: bulk file enumeration from a single process — pre-exfiltration/pre-encryption staging signal"
      - "EDR: PowerShell scanning user profile paths for BFSI-pattern filenames"
    threat_intel_sources:
      - reference: "MITRE ATT&CK — Black Basta (Software S1070): \"Black Basta can enumerate specific files for encryption.\""
        url: "https://attack.mitre.org/software/S1070/"
      - reference: "Qualys — What Is Black Basta Ransomware and How to Mitigate Attack"
        url: "https://blog.qualys.com/vulnerabilities-threat-research/2024/09/19/black-basta-ransomware-what-you-need-to-know"
      - reference: "Trend Micro — Ransomware Spotlight: Black Basta"
        url: "https://www.trendmicro.com/vinfo/us/security/news/ransomware-spotlight/ransomware-spotlight-blackbasta"
    last_reviewed: "2026-10-12"
    family_attribution_confidence: confirmed
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
      Write-Output "EXEC: BFSI file recon across Desktop/Documents/Downloads (depth=2). Found $found matching file(s). Read-only — no files opened. Black Basta enumerates files like these before encryption/exfiltration. [BAS-SIM-BLACKBASTA-S6]"
    cleanup: ""

  # ---------------------------------------------------------------------------
  # Stage 7 — Exfiltration: Cloud/Mega Storage Egress Reachability (T1567.002)
  # ---------------------------------------------------------------------------
  - name: "Black Basta Stage 7 — Cloud Storage Egress Reachability (T1567.002)"
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
    blast_radius: "Tests whether the endpoint can reach public cloud-storage upload endpoints, including Mega (Black Basta's documented exfil destination), via a benign HEAD/connectivity probe. NO account, NO upload, NO data: connectivity reachability only. Generates Sysmon EID 22 (DNS) and EID 3 (outbound TLS attempt)."
    telemetry:
      - "Sysmon EID 22: DNS queries to public cloud-storage hostnames"
      - "Sysmon EID 3: outbound TCP/443 to cloud-storage endpoints"
    detection:
      - "Proxy/CASB: uploads to unsanctioned cloud storage — DLP/CASB egress policy trigger"
      - "SIEM: workstation reaching consumer cloud-storage APIs — shadow-IT / exfil IOC"
    threat_intel_sources:
      - reference: "Qualys — What Is Black Basta Ransomware and How to Mitigate Attack (Rclone/WinSCP exfiltration to Mega)"
        url: "https://blog.qualys.com/vulnerabilities-threat-research/2024/09/19/black-basta-ransomware-what-you-need-to-know"
      - reference: "Trend Micro — Ransomware Spotlight: Black Basta"
        url: "https://www.trendmicro.com/vinfo/us/security/news/ransomware-spotlight/ransomware-spotlight-blackbasta"
    last_reviewed: "2026-10-12"
    family_attribution_confidence: reported
    command: |
      $ErrorActionPreference = 'SilentlyContinue'
      $endpoints = @('storage.googleapis.com','s3.amazonaws.com','blob.core.windows.net','api.dropboxapi.com','g.api.mega.co.nz')
      $reachable = @()
      foreach ($e in $endpoints) {
        try {
          $tcp = New-Object System.Net.Sockets.TcpClient
          $iar = $tcp.BeginConnect($e, 443, $null, $null)
          if ($iar.AsyncWaitHandle.WaitOne(3000, $false) -and $tcp.Connected) { $reachable += $e }
          $tcp.Close()
        } catch {}
      }
      Write-Output "EXEC T1567.002: probed cloud-storage egress reachability (including Mega). reachable=[$($reachable -join ', ')] (probe only, no upload). Black Basta's documented exfiltration path uses Rclone/WinSCP to transfer data to actor-controlled accounts, often on Mega. [BAS-SIM-BLACKBASTA-S7]"
      if ($reachable.Count -gt 0) {
        Write-Output "FAIL: The endpoint can directly reach $($reachable.Count) public cloud-storage endpoint(s) on TCP/443 — a real data-theft path to unsanctioned storage. Route egress through a proxy/CASB that enforces a sanctioned-tenant allowlist and DLP upload inspection."
      } else {
        Write-Output "PASS: no direct egress to public cloud-storage endpoints — uploads are forced through a controlled path (or blocked). [BAS-SIM-BLACKBASTA-S7]"
      }
    cleanup: ""

  # ---------------------------------------------------------------------------
  # Stage 8 — Ransomware Impact Simulation (T1486)
  # ---------------------------------------------------------------------------
  - name: "Black Basta Stage 8 — XOR Encryption Simulation (lab  -  isolated temp dir, forced cleanup) (T1486)"
    technique_id: T1486
    action_key: ransomware_sim_sandboxed
    detection_profiles:
      - windows_ransomware_encryption
    framework: custom
    executor: powershell
    requires_priv: user
    timeout_sec: 60
    fidelity: lab-only
    production_safe: false
    risk: high
    blast_radius: "Creates isolated %TEMP%\\bas_range_<id>\\ with <=3 benign dummy files, XOR-encrypts in-place, drops marker ransom note, XOR-decrypts to restore, deletes entire directory. File cap + size cap + cleanup verification enforced. Black Basta's real encryptor uses ChaCha20, multithreaded -- this simulation never performs real cryptographic operations on real data."
    reversible: true
    telemetry:
      - "Sysmon EID 11 (file create/modify): bas_range_<id>\\ directory + .bas_locked files"
      - "Security EID 4663 (file write) if object access auditing enabled"
    detection:
      - "EDR: rapid sequential file modification pattern across multiple files  -  encryption behaviour"
      - "SIEM: high file-modify rate from powershell.exe on %TEMP% path  -  ransomware staging signal"
    threat_intel_sources:
      - reference: "CISA/FBI/HHS/MS-ISAC Advisory AA24-131A — #StopRansomware: Black Basta (Table 6: used a public key to fully encrypt files)"
        url: "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-131a"
      - reference: "MITRE ATT&CK — Black Basta (Software S1070): ChaCha20 cipher, multithreaded"
        url: "https://attack.mitre.org/software/S1070/"
    last_reviewed: "2026-10-12"
    family_attribution_confidence: confirmed
    command: |
      $ErrorActionPreference = 'SilentlyContinue'
      $runId   = if ($env:BAS_RUN_ID) { $env:BAS_RUN_ID.Substring(0,[Math]::Min(8,$env:BAS_RUN_ID.Length)) } else { '{0:x8}' -f (Get-Random -Maximum 0x7FFFFFFF) }
      $maxFiles = 3
      $maxBytes = 10240
      $rangeDir = Join-Path $env:TEMP "bas_range_$runId"
      New-Item -ItemType Directory -Path $rangeDir -Force | Out-Null
      $dummies = @('finance_q4.txt','customer_export.txt','swift_ops.txt')
      foreach ($f in $dummies[0..($maxFiles-1)]) {
        $content = "BAS-SIM DUMMY DATA run-id=$runId file=$f" * 10
        if ([System.Text.Encoding]::UTF8.GetByteCount($content) -gt $maxBytes) { $content = $content.Substring(0,$maxBytes/2) }
        Set-Content -Path (Join-Path $rangeDir $f) -Value $content -Encoding UTF8
      }
      $key = 0xAB
      $encFiles = @()
      Get-ChildItem -Path $rangeDir -File | ForEach-Object {
        $bytes  = [System.IO.File]::ReadAllBytes($_.FullName)
        $xored  = $bytes | ForEach-Object { $_ -bxor $key }
        $locked = $_.FullName + '.bas_locked'
        [System.IO.File]::WriteAllBytes($locked, [byte[]]$xored)
        Remove-Item $_.FullName -Force
        $encFiles += $locked
      }
      $noteFile = Join-Path $rangeDir 'README_RESTORE_BAS_SIM.txt'
      Set-Content -Path $noteFile -Value "BAS-SIM RANSOM NOTE  -  run-id=$runId  -  THIS IS A CONTROLLED DRILL" -Encoding UTF8
      Write-Output "EXEC: $($encFiles.Count) file(s) XOR-encrypted in $rangeDir  -  expect EDR encryption-behaviour alert. Restoring now. [BAS-SIM-BLACKBASTA-S8]"
      foreach ($enc in $encFiles) {
        $bytes  = [System.IO.File]::ReadAllBytes($enc)
        $plain  = $bytes | ForEach-Object { $_ -bxor $key }
        $orig   = $enc -replace '\.bas_locked$',''
        [System.IO.File]::WriteAllBytes($orig, [byte[]]$plain)
        Remove-Item $enc -Force
      }
      Remove-Item $noteFile -Force -ErrorAction SilentlyContinue
      Remove-Item $rangeDir -Recurse -Force -ErrorAction SilentlyContinue
      $cleaned = -not (Test-Path $rangeDir)
      Write-Output "CLEANUP: range directory removed=$cleaned. No encrypted data remains. [BAS-SIM-BLACKBASTA-S8]"
    cleanup: |
      Remove-Item (Join-Path $env:TEMP "bas_range_*") -Recurse -Force -ErrorAction SilentlyContinue

  # ---------------------------------------------------------------------------
  # Stage 9 — Recovery Inhibition A: VSS + Backup Catalog Enumeration (T1490)
  # ---------------------------------------------------------------------------
  - name: "VSS + Backup Catalog Enumeration"
    technique_id: T1490
    action_key: enumerate
    detection_profiles:
      - windows_vss_inhibition
    framework: custom
    executor: powershell
    requires_priv: user
    timeout_sec: 30
    fidelity: telemetry-safe
    production_safe: true
    risk: low
    blast_radius: "Read-only enumeration of VSS shadow copies and wbadmin backup catalog. No shadows deleted; no backup jobs modified."
    reversible: true
    telemetry:
      - "Security EID 4688 (vssadmin.exe + wbadmin.exe invocations)"
    detection:
      - "SIEM: vssadmin list shadows from a non-backup process  -  ransomware pre-deletion recon"
      - "EDR: wbadmin get versions invocation  -  backup catalog discovery before destruction"
    threat_intel_sources:
      - reference: "CISA/FBI/HHS/MS-ISAC Advisory AA24-131A — #StopRansomware: Black Basta (Table 6: used the vssadmin.exe program to delete shadow copies)"
        url: "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-131a"
      - reference: "Qualys — What Is Black Basta Ransomware and How to Mitigate Attack (vssadmin-based shadow-copy deletion hunting query)"
        url: "https://blog.qualys.com/vulnerabilities-threat-research/2024/09/19/black-basta-ransomware-what-you-need-to-know"
    last_reviewed: "2026-10-12"
    family_attribution_confidence: confirmed
    command: |
      $ErrorActionPreference = 'SilentlyContinue'
      $vssOut   = & vssadmin list shadows 2>&1
      $shadowCount = ([regex]::Matches(($vssOut -join "`n"), 'Shadow Copy ID')).Count
      $wbaOut   = & wbadmin get versions 2>&1
      $backupCount = ([regex]::Matches(($wbaOut -join "`n"), 'Backup time')).Count
      Write-Output "EXEC: VSS enumeration  -  $shadowCount shadow copy/copies found. Backup catalog: $backupCount version(s) via wbadmin. Black Basta enumerates these before vssadmin-based deletion. No copies removed. [BAS-SIM]"
    cleanup: ""

  # ---------------------------------------------------------------------------
  # Stage 10 — Recovery Inhibition B: vssadmin-Based VSS Deletion (T1490, lab-only)
  # ---------------------------------------------------------------------------
  - name: "VSS Shadow Copy Deletion (lab  -  requires BAS_CONFIRM_VSS_DELETE=true)"
    technique_id: T1490
    action_key: vss_delete
    detection_profiles:
      - windows_vss_inhibition
    framework: custom
    executor: powershell
    requires_priv: admin
    timeout_sec: 60
    fidelity: lab-only
    production_safe: false
    risk: high
    blast_radius: "Deletes ONE oldest VSS shadow copy of C: via vssadmin.exe -- Black Basta's exact documented command per CISA AA24-131A, as opposed to Akira's WMI Win32_ShadowCopy.Delete()-based deletion. Requires explicit BAS_CONFIRM_VSS_DELETE=true env var and verifies a snapshot exists first. Default-disabled without the flag."
    reversible: false
    telemetry:
      - "Security EID 8224 (VSS service shutdown) + EID 524 (shadow copy deletion)"
      - "Security EID 4688 (vssadmin.exe with delete command)"
    detection:
      - "EDR: vssadmin.exe with 'delete shadows' argument  -  #1 ransomware pre-encryption technique"
      - "SIEM: shadow copy count decrease; alert if count drops to 0"
    threat_intel_sources:
      - reference: "CISA/FBI/HHS/MS-ISAC Advisory AA24-131A — #StopRansomware: Black Basta (Table 6: used the vssadmin.exe program to delete shadow copies)"
        url: "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-131a"
      - reference: "Qualys — What Is Black Basta Ransomware and How to Mitigate Attack (vssadmin-based shadow-copy deletion hunting query)"
        url: "https://blog.qualys.com/vulnerabilities-threat-research/2024/09/19/black-basta-ransomware-what-you-need-to-know"
    last_reviewed: "2026-10-12"
    family_attribution_confidence: confirmed
    command: |
      $ErrorActionPreference = 'SilentlyContinue'
      $confirm = $env:BAS_CONFIRM_VSS_DELETE
      if (-not $confirm -or $confirm -ne 'true') {
        Write-Output "SKIP: BAS_CONFIRM_VSS_DELETE not set to 'true'  -  VSS deletion skipped (default-disabled per ransm safety policy). Set env var explicitly in isolated lab to enable. [BAS-SIM]"
        return
      }
      $shadows = Get-WmiObject Win32_ShadowCopy -ErrorAction SilentlyContinue | Where-Object { $_.VolumeName -match 'C:' }
      if (-not $shadows -or @($shadows).Count -eq 0) {
        Write-Output "SKIP: no C: VSS shadow copies exist  -  nothing to delete. Create a snapshot first with: vssadmin create shadow /for=C:"
        return
      }
      $oldest = @($shadows | Sort-Object InstallDate)[0]
      $id = $oldest.ID
      & vssadmin delete shadows /Shadow=$id /Quiet 2>&1 | Out-Null
      $remaining = @(Get-WmiObject Win32_ShadowCopy -ErrorAction SilentlyContinue | Where-Object { $_.VolumeName -match 'C:' }).Count
      Write-Output "FAIL: VSS shadow copy $id deleted  -  expect EID 8224/524. $remaining shadow copy/copies remaining on C:. Create a new snapshot to restore recovery capability. [BAS-SIM]"
    cleanup: ""
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `go test ./internal/scenario/ -run TestBlackBastaKillChain_ParsesWithTenStepsWindowsOnlyFullyGrounded -v`
Expected: PASS.

- [ ] **Step 5: Run the full `internal/scenario` suite**

Run: `go test ./internal/scenario/ -v`
Expected: `ok`, every existing test still passes alongside the new one.

- [ ] **Step 6: Commit**

```bash
git add scenarios/black-basta-kill-chain.yaml orchestrator/internal/scenario/black_basta_kill_chain_test.go
git commit -m "feat(scenarios): Black Basta kill chain -- 10-stage CISA AA24-131A-grounded ransomware emulation"
```

---

### Task 2: Register across all 7 touchpoints, including 2 new rwtaxonomy domain mappings

**Files:**
- Modify: `orchestrator/internal/api/rwevidence_dispatch.go`
- Modify: `orchestrator/internal/rwdetect/profiles.go`
- Modify: `orchestrator/internal/rwdetect/profiles_test.go`
- Modify: `orchestrator/internal/rwevidence/realcorpus_test.go`
- Modify: `orchestrator/internal/rwtaxonomy/mapping.go`
- Modify: `orchestrator/internal/rwtaxonomy/mapping_corpus_test.go`
- Modify: `orchestrator/internal/contentregistry/realcorpus_test.go`
- Modify: `orchestrator/web/src/features/ransomware.js`

**Interfaces:**
- Consumes: `scenario.FamilyAttribution*` constants are not needed here; this task only touches content-list registration and technique-domain mapping.
- Produces: `black-basta-kill-chain` recognized by every touchpoint; `rwtaxonomy.TechniqueDomain["T1566.001"]` and `["T1003.001"]` exist.

- [ ] **Step 1: Add the two missing rwtaxonomy domain mappings (fail-closed proof first)**

Run: `go test ./internal/rwtaxonomy/ -run TestTechniqueDomain_MatchesRealCorpus -v` (before touching any file in this task)
Expected: PASS — the new scenario file isn't registered into `ransomwareScenarioFiles` yet, so `TechniqueDomain` isn't checked against it. This establishes the pre-task baseline.

In `orchestrator/internal/rwtaxonomy/mapping.go`, add two entries to the `TechniqueDomain` map (alongside the existing `"T1003.002": DomainCredentialAccess` and any other adjacent entries — exact insertion point doesn't matter, Go map literals are unordered):

```go
	"T1566.001": DomainInitialAccess,
	"T1003.001": DomainCredentialAccess,
```

- [ ] **Step 2: Register the new file in all 7 touchpoints**

In `orchestrator/internal/api/rwevidence_dispatch.go`, add to the `ransomwareScenarioIDs` map:

```go
	"black-basta-kill-chain":     true,
```

In `orchestrator/internal/rwdetect/profiles.go`, add to `RansomwareRelevantProfiles` (no new detection-profile names are introduced by this scenario — every `detection_profiles` entry it uses, `windows_defender_tampering`/`windows_malicious_service`/`windows_smb_lateral_probe`/`windows_file_discovery`/`windows_cloud_egress`/`windows_ransomware_encryption`/`windows_vss_inhibition`, already exists in the list — **no edit needed to this file**; confirm by re-reading it and checking all 7 names are already present before skipping this file).

In `orchestrator/internal/rwdetect/profiles_test.go`, `orchestrator/internal/rwevidence/realcorpus_test.go`, `orchestrator/internal/rwtaxonomy/mapping_corpus_test.go`, and `orchestrator/internal/contentregistry/realcorpus_test.go` — each has its own `ransomwareScenarioFiles` (or equivalently-named) slice; add one line to each:

```go
	"black-basta-kill-chain.yaml",
```

In `orchestrator/web/src/features/ransomware.js`, append to the `RR_SCENARIO_IDS` array:

```js
  , 'black-basta-kill-chain'
```

(adjust comma placement to match the array's existing style — the array currently ends with `'linux-ransomware-drill'`).

- [ ] **Step 3: Run each touchpoint's own real-corpus test**

Run: `go test ./internal/rwtaxonomy/ -run TestTechniqueDomain_MatchesRealCorpus -v`
Expected: PASS — the new file is now registered, and both new mappings resolve its two new technique IDs correctly.

Run: `go test ./internal/rwdetect/ -run TestRansomwareRelevantProfiles_MatchesRealCorpus -v`
Expected: PASS.

Run: `go test ./internal/rwevidence/ -run TestRealCorpus_EveryTechniqueTaggedStepIsAccountedFor -v`
Expected: PASS — every technique-tagged step (all 10) gets exactly 5 `CapabilityResult`s from `EvaluateStep`, same as every other scenario in the corpus.

Run: `go test ./internal/api/ -run TestRansomwareScenarioIDs_MatchesRealCorpus -v`
Expected: PASS (this test spins up one Postgres testcontainer regardless, per `internal/api`'s `TestMain` — expected, not a regression).

Run: `go test ./internal/contentregistry/ -run TestRealRansomwareCorpus_StillParsesAndStructurallyPasses -v`
Expected: PASS — confirms Black Basta's own structural check (including this pass's `stepProvenanceProblems` rules) comes back `"PASS"`, proving the content's `threat_intel_sources`/`family_attribution_confidence` values are internally self-consistent, not just present.

- [ ] **Step 4: Manually verify `ransomware.js`**

Confirm the `RR_SCENARIO_IDS` array now has exactly 10 entries, comma-separated, with `'black-basta-kill-chain'` last (no test harness exists for this file — same situation sub-project #9 documented).

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/api/rwevidence_dispatch.go orchestrator/internal/rwdetect/profiles_test.go orchestrator/internal/rwevidence/realcorpus_test.go orchestrator/internal/rwtaxonomy/mapping.go orchestrator/internal/rwtaxonomy/mapping_corpus_test.go orchestrator/internal/contentregistry/realcorpus_test.go orchestrator/web/src/features/ransomware.js
git commit -m "feat(rwevidence): register black-basta-kill-chain across all 7 scenario-list touchpoints"
```

---

### Task 3: Sign the scenario

**Files:** none (signing only).

**Interfaces:**
- Consumes: `scenarios/black-basta-kill-chain.yaml` from Task 1.
- Produces: `scenarios/black-basta-kill-chain.yaml.sig`.

- [ ] **Step 1: Sign**

Run (from `orchestrator/`): `go run scripts/signer.go sign private_key.pem ../scenarios/black-basta-kill-chain.yaml`
Expected: `[+] Signed ../scenarios/black-basta-kill-chain.yaml -> ../scenarios/black-basta-kill-chain.yaml.sig`

- [ ] **Step 2: Verify all**

Run: `go run scripts/signer.go verify-all ../scenarios`
Expected: `ok=119 fail=0` (118 from before this scenario, +1).

- [ ] **Step 3: Commit**

```bash
git add scenarios/black-basta-kill-chain.yaml.sig
git commit -m "chore(scenarios): sign black-basta-kill-chain.yaml"
```

---

### Task 4: Final regression

**Files:** none (verification only).

**Interfaces:**
- Consumes: everything from Tasks 1-3.
- Produces: nothing — this is the plan's final gate before review.

- [ ] **Step 1: Confirm Step 10's skip-text against `dispatch.go` one more time, end to end**

Run: `go test ./internal/rwevidence/ -run TestClassify -v` (the existing `classifyRansomwareStep` unit tests, unchanged by this plan)
Expected: `ok` — all pass unchanged, confirming no `dispatch.go` edit was needed and none was made.

- [ ] **Step 2: Run the full regression**

`internal/contentregistry` has a `TestMain` with a shared-DB testcontainer; `internal/api` is also testcontainer-backed as a whole package; `internal/scenario`, `internal/rwdetect`, `internal/rwevidence`, `internal/rwtaxonomy` are pure Go (no `TestMain`, no DB). Running `internal/contentregistry` together with `internal/api` would be 2 testcontainer-backed packages at once — follow this session's established host-RAM discipline and run `internal/api` separately with `-p 1`.

Run: `go test ./internal/scenario/ ./internal/rwdetect/ ./internal/rwevidence/ ./internal/rwtaxonomy/ ./internal/contentregistry/ -v`
Expected: `ok` for all five packages, 0 FAIL.

Run: `go test ./internal/api/ -p 1 -timeout 20m -v`
Expected: `ok`, 0 FAIL (same ~900s runtime observed for sub-project #9's equivalent run — safe to run in the background while continuing other work if needed).

- [ ] **Step 3: gofmt check**

Run: `gofmt -l orchestrator/internal/scenario/black_basta_kill_chain_test.go orchestrator/internal/api/rwevidence_dispatch.go orchestrator/internal/rwdetect/profiles_test.go orchestrator/internal/rwevidence/realcorpus_test.go orchestrator/internal/rwtaxonomy/mapping.go orchestrator/internal/rwtaxonomy/mapping_corpus_test.go orchestrator/internal/contentregistry/realcorpus_test.go`
Expected: empty output.

No commit for this task — pure verification over Tasks 1-3's already-committed code.
