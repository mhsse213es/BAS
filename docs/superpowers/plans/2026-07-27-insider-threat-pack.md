# Insider Threat Pack Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship one new builtin scenario, `insider-threat-kill-chain.yaml` (3 steps), covering the two genuinely-uncovered Insider Threat behaviors — personal-webmail exfiltration and mass file rename/delete sabotage — plus an insider-framed reuse of the existing sensitive-file-search step, wired with structured `detection_profiles:` from day one.

**Architecture:** 2 new detection-profile YAML files (`windows_webmail_egress`, `windows_data_destruction`) plus 1 new scenario YAML file. Provider selection follows the honest, already-precedented classification per behavior — `microsoft_sentinel`/`microsoft_purview` (manual-verify) for the webmail reachability probe, matching `windows_cloud_egress`'s existing shape; `microsoft_defender` (auto-verify) for the mass-destruction step, matching `windows_ransomware_encryption`'s existing shape. No Go code changes.

**Tech Stack:** YAML scenario/profile content, PowerShell (`executor: powershell`) steps, Go test (`internal/scenario` package) for the wiring-guard test.

## Global Constraints

- `windows_webmail_egress` uses `provider: microsoft_sentinel` (`type: network`, `confidence: required`) + `provider: microsoft_purview` (`type: dlp`, `confidence: recommended`) — not `microsoft_defender` — because a TCP-reachability probe is a network/CASB/SIEM detection point, not an EDR signature (spec: "Provider selection — corrected from first assumption").
- `windows_data_destruction` uses `provider: microsoft_defender`, `confidence: required` — genuinely EDR-detectable, same reasoning as `windows_ransomware_encryption`.
- No real user/production data is ever touched. The webmail step is a TCP-connect probe only (no message composed, no attachment sent). The sabotage step only creates and destroys its own freshly-created, BAS-owned synthetic decoy files in a throwaway `%TEMP%` directory.
- `supported_os: [windows]`, Windows only.
- Every new/modified builtin file must be signed via `go run scripts/signer.go sign private_key.pem <path>` (run from `orchestrator/`) before it will load.
- `insider-threat-kill-chain.yaml`'s description cross-references `dlp-exfiltration-validation.yaml` and `collection-staging-exfil.yaml` for the channels it deliberately doesn't re-test (USB/clipboard/print/archive/local-staging/protocol-exfil/cloud-storage-reachability).
- All new files are pure YAML content — no Go code changes in this plan.

---

## Task 1: New Detection Profiles

**Files:**
- Create: `scenarios/detection-profiles/windows_webmail_egress.yaml` (+ `.sig`)
- Create: `scenarios/detection-profiles/windows_data_destruction.yaml` (+ `.sig`)

**Interfaces:**
- Produces: 2 profile names (`windows_webmail_egress`, `windows_data_destruction`) that Task 2 references via `detection_profiles:` entries.

- [ ] **Step 1: Create `windows_webmail_egress.yaml`**

```yaml
# Detection Validation Profile — exfiltration via personal webmail (T1567).
# Same technical category as windows_cloud_egress (reachability probe, not
# an EDR signature) — personal webmail bypasses corporate email DLP
# entirely since it never transits corporate mail flow.
profile: windows_webmail_egress
version: 1
expected_detection:
  - id: webmailegress-network-upload
    provider: microsoft_sentinel
    type: network
    confidence: required
    finding:
      severity: High
      title: "Personal webmail exfiltration path not detected"
      remediation: >-
        Alert on outbound connections to personal webmail domains (Gmail,
        Outlook.com, Yahoo Mail, Proton) and large attachment/compose
        activity from endpoints. Personal webmail bypasses corporate email
        DLP entirely since it never transits corporate mail flow.
      reference: "MITRE ATT&CK T1567 — Exfiltration Over Web Service"
  - id: webmailegress-dlp-block
    provider: microsoft_purview
    type: dlp
    confidence: recommended
    finding:
      severity: Medium
      title: "No DLP/CASB policy on personal webmail categories"
      remediation: >-
        Apply a CASB/proxy policy that blocks or inspects personal webmail
        categories; alert the SOC on attempted access from managed
        endpoints.
      reference: "MITRE ATT&CK T1567 — Exfiltration Over Web Service"
```

- [ ] **Step 2: Create `windows_data_destruction.yaml`**

```yaml
# Detection Validation Profile — mass file rename/delete (T1485). The
# insider-sabotage counterpart to windows_ransomware_encryption: same
# bulk-destruction EDR signature, without encryption or a ransom note.
profile: windows_data_destruction
version: 1
expected_detection:
  - id: mass-destruction-edr
    provider: microsoft_defender
    confidence: required
    finding:
      severity: Critical
      title: "Mass file rename/delete pattern not detected"
      remediation: >-
        Enable Controlled Folder Access and ransomware-specific behavioral
        protection to also alert on high-frequency file rename+delete in a
        short window even when no known ransomware extension is involved
        -- a departing/malicious insider destroying evidence produces the
        same bulk-destruction signature as ransomware impact, without
        encryption.
      reference: "MITRE ATT&CK T1485 — Data Destruction"
```

- [ ] **Step 3: Validate both files parse as valid YAML**

Run (from repo root):
```bash
python3 -c "
import yaml
for f in ['windows_webmail_egress','windows_data_destruction']:
    yaml.safe_load(open(f'scenarios/detection-profiles/{f}.yaml'))
    print(f, 'OK')
"
```
Expected: `<name> OK` printed twice, no exceptions.

- [ ] **Step 4: Sign both files**

From `orchestrator/`:
```bash
go run scripts/signer.go sign private_key.pem ../scenarios/detection-profiles/windows_webmail_egress.yaml
go run scripts/signer.go sign private_key.pem ../scenarios/detection-profiles/windows_data_destruction.yaml
```
Expected: each produces a `.sig` file alongside the `.yaml`, no errors.

- [ ] **Step 5: Commit**

```bash
git add scenarios/detection-profiles/windows_webmail_egress.yaml scenarios/detection-profiles/windows_webmail_egress.yaml.sig scenarios/detection-profiles/windows_data_destruction.yaml scenarios/detection-profiles/windows_data_destruction.yaml.sig
git commit -m "feat(scenarios): 2 new detection profiles for Insider Threat pack"
git push
```

---

## Task 2: `insider-threat-kill-chain.yaml`

**Files:**
- Create: `scenarios/insider-threat-kill-chain.yaml` (+ `.sig`)

**Interfaces:**
- Consumes: `windows_webmail_egress`, `windows_data_destruction` (Task 1) plus existing profile `windows_file_discovery`.

**Safety notes:** Stage 2 is a TCP-connect probe only (no message composed, no attachment uploaded, no account touched) — same safety class as the already-shipped `windows_cloud_egress` step in `collection-staging-exfil.yaml`. Stage 3 only creates and destroys its own freshly-created, BAS-owned synthetic decoy files in a throwaway `%TEMP%` directory — no real user or production data is ever touched.

- [ ] **Step 1: Create `scenarios/insider-threat-kill-chain.yaml`**

```yaml
id: insider-threat-kill-chain
name: Insider Threat Kill Chain — Data Theft & Sabotage Emulation
description: >
  Three-stage telemetry-safe emulation of a departing/disgruntled insider
  threat targeting Windows endpoints: sensitive-file search outside normal
  job scope, exfiltration via personal webmail (bypassing corporate email
  DLP), and destructive sabotage of evidence/backups on the way out.

  KILL CHAIN STAGES:
    1. Sensitive-File Search    — BFSI-pattern file reconnaissance (T1083 / T1005)
    2. Webmail Exfiltration     — personal webmail egress reachability (T1567)
    3. Sabotage                 — mass file rename/delete of evidence (T1485)

  SEE ALSO: for USB/clipboard/print/archive-based exfiltration validation,
  see dlp-exfiltration-validation.yaml. For bulk file staging and
  protocol-based exfiltration (HTTP/DNS/FTP/WebDAV/generic cloud storage),
  see collection-staging-exfil.yaml. This scenario deliberately does not
  re-test those channels.

  SAFETY: Stage 2 is a TCP-reachability probe only — no message composed,
  no attachment sent, no personal account touched. Stage 3 only creates
  and destroys its own BAS-owned, freshly-created synthetic decoy files in
  a throwaway %TEMP% directory — no real user or production data is ever
  touched. Windows only. [BAS-SIM] tagged throughout.
author: Audspect Research
executable: true
local_check: false
supported_os: [windows]
tags:
  - insider-threat
  - data-theft
  - sabotage
  - bfsi
  - kill-chain
  - t1005
  - t1083
  - t1485
  - t1567
  - mitre
mitre_phases:
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
  # Stage 1 — Sensitive-File Search Outside Normal Job Scope (T1083 / T1005)
  # ---------------------------------------------------------------------------
  - name: "Insider Stage 1 — Sensitive-File Search Outside Normal Job Scope (T1083 / T1005)"
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
      - "UEBA: bulk file enumeration from a single process — pre-exfiltration staging signal, especially outside an employee's normal job scope"
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
      Write-Output "EXEC: sensitive-file search across Desktop/Documents/Downloads (depth=2). Found $found matching file(s). Read-only — no files opened. A departing/malicious insider searches for high-value files outside their normal job scope this same way before exfiltrating them. [BAS-SIM-INSIDER-S1]"
    cleanup: ""

  # ---------------------------------------------------------------------------
  # Stage 2 — Personal Webmail Exfiltration Reachability (T1567)
  # ---------------------------------------------------------------------------
  - name: "Insider Stage 2 — Personal Webmail Exfiltration Reachability (T1567)"
    technique_id: T1567
    detection_profiles:
      - windows_webmail_egress
    framework: custom
    executor: powershell
    requires_priv: user
    timeout_sec: 30
    fidelity: telemetry-safe
    production_safe: true
    risk: low
    reversible: true
    blast_radius: "Tests whether the endpoint can reach major personal webmail providers (a benign connectivity probe to well-known hostnames on TCP/443). NO message composed, NO attachment uploaded, NO account touched: connectivity reachability only. Generates Sysmon EID 22 (DNS) and EID 3 (outbound TLS attempt)."
    telemetry:
      - "Sysmon EID 22: DNS queries to personal webmail hostnames"
      - "Sysmon EID 3: outbound TCP/443 to personal webmail endpoints"
    detection:
      - "Proxy/CASB: access to personal webmail categories — DLP/CASB egress policy trigger"
      - "SIEM: workstation reaching personal webmail APIs outside corporate mail flow — insider exfiltration IOC"
    command: |
      $ErrorActionPreference = 'SilentlyContinue'
      $endpoints = @('mail.google.com','outlook.live.com','mail.yahoo.com','mail.proton.me')
      $reachable = @()
      foreach ($e in $endpoints) {
        try {
          $tcp = New-Object System.Net.Sockets.TcpClient
          $iar = $tcp.BeginConnect($e, 443, $null, $null)
          if ($iar.AsyncWaitHandle.WaitOne(3000, $false) -and $tcp.Connected) { $reachable += $e }
          $tcp.Close()
        } catch {}
      }
      Write-Output "EXEC T1567: probed personal-webmail egress reachability. reachable=[$($reachable -join ', ')] (probe only, no message sent, no attachment uploaded). A departing/malicious insider can exfiltrate sensitive files by attaching them to a personal webmail message -- this bypasses corporate email DLP entirely since it never transits the corporate mail flow. [BAS-SIM-INSIDER-S2]"
      if ($reachable.Count -gt 0) {
        Write-Output "FAIL: The endpoint can directly reach $($reachable.Count) personal webmail provider(s) on TCP/443 -- a real insider data-theft path outside corporate email DLP. Route egress through a proxy/CASB that blocks or inspects personal webmail categories, and alert on large uploads to these domains."
      } else {
        Write-Output "PASS: no direct egress to personal webmail providers -- access is blocked or forced through a controlled/inspected path. [BAS-SIM-INSIDER-S2]"
      }
    cleanup: ""

  # ---------------------------------------------------------------------------
  # Stage 3 — Mass File Rename/Delete Sabotage (T1485)
  # ---------------------------------------------------------------------------
  - name: "Insider Stage 3 — Mass File Rename/Delete Sabotage (T1485)"
    technique_id: T1485
    detection_profiles:
      - windows_data_destruction
    framework: custom
    executor: powershell
    requires_priv: user
    timeout_sec: 30
    fidelity: telemetry-safe
    production_safe: true
    risk: low
    reversible: true
    blast_radius: "Creates ~7 BAS-owned synthetic decoy files with realistic sensitive-sounding names in a throwaway %TEMP% directory, mass-renames them, mass-deletes them, then removes the directory. Only ever touches its own just-created decoys -- no real user or production data is touched. Generates Sysmon EID 11 (file create x7), EID 23 (file delete, rename+delete pattern)."
    telemetry:
      - "Sysmon EID 11: 7 decoy files created in %TEMP%\\bas_insider_<id>\\"
      - "Sysmon EID 23: rapid rename+delete of all 7 files in the same short-lived batch"
    detection:
      - "EDR: high-frequency file rename + delete in a short window from a single process -- Controlled Folder Access / ransomware-specific behavioral protection, applied to non-ransomware-labeled bulk destruction"
      - "SIEM: burst of file-delete events against files with sensitive-sounding names outside a backup/cleanup job window"
    command: |
      $ErrorActionPreference = 'SilentlyContinue'
      $runId = if ($env:BAS_RUN_ID) { $env:BAS_RUN_ID.Substring(0,[Math]::Min(8,$env:BAS_RUN_ID.Length)) } else { '{0:x8}' -f (Get-Random -Maximum 0x7FFFFFFF) }
      $work = Join-Path $env:TEMP "bas_insider_$runId"
      New-Item -ItemType Directory -Path $work -Force | Out-Null
      $names = @('Customer_Export','Payroll_Q3','Board_Minutes','Client_SSNs','Source_Code_Backup','Vendor_Contracts','Audit_Findings')
      $created = 0
      foreach ($n in $names) {
        $p = Join-Path $work "$n.txt"
        "[BAS-SIM-INSIDER] synthetic decoy content" | Out-File $p -Encoding utf8
        if (Test-Path $p) { $created++ }
      }
      $renamed = 0
      Get-ChildItem -Path $work -File | ForEach-Object {
        $newName = [guid]::NewGuid().ToString('N').Substring(0,12) + '.bas_wiped'
        Rename-Item -Path $_.FullName -NewName $newName -ErrorAction SilentlyContinue
        if (Test-Path (Join-Path $work $newName)) { $renamed++ }
      }
      $deleted = 0
      Get-ChildItem -Path $work -File | ForEach-Object {
        Remove-Item -Path $_.FullName -Force -ErrorAction SilentlyContinue
        $deleted++
      }
      $remaining = @(Get-ChildItem -Path $work -File -ErrorAction SilentlyContinue).Count
      Remove-Item $work -Recurse -Force -ErrorAction SilentlyContinue
      if ($created -gt 0 -and $renamed -gt 0 -and $deleted -gt 0) {
        Write-Output "EXEC T1485: $created BAS-owned decoy files created, $renamed mass-renamed, $deleted mass-deleted in a single short-lived batch (remaining=$remaining). A malicious/departing insider destroys evidence and denies recovery this same way -- rapid bulk rename+delete of many files in one process lifetime. [BAS-SIM-INSIDER-S3]"
        Write-Output "FAIL: bulk file rename+delete completed unimpeded on $created files. This is the same behavioral signature Controlled Folder Access and ransomware-specific EDR protections are built to catch -- verify it fires for non-ransomware-labeled bulk destruction too, not only known ransomware extensions."
      } else {
        Write-Output "PASS: bulk file rename/delete was blocked or failed (created=$created renamed=$renamed deleted=$deleted) -- Controlled Folder Access or EDR prevented the pattern. [BAS-SIM-INSIDER-S3]"
      }
    cleanup: |
      Remove-Item (Join-Path $env:TEMP 'bas_insider_*') -Recurse -Force -ErrorAction SilentlyContinue
```

- [ ] **Step 2: Validate YAML structural validity**

```bash
python3 -c "import yaml; yaml.safe_load(open('scenarios/insider-threat-kill-chain.yaml')); print('OK')"
```
Expected: `OK`, no exceptions.

- [ ] **Step 3: Manual PowerShell syntax sanity check**

For each of the 3 `command:` blocks and the 1 non-empty `cleanup:` block in the file, extract the script text and parse it (does not execute):
```powershell
$errors = $null
[System.Management.Automation.Language.Parser]::ParseInput($script, [ref]$null, [ref]$errors) | Out-Null
if ($errors) { $errors }
```
Expected: no parse errors for any block.

- [ ] **Step 4: Sign the file**

From `orchestrator/`:
```bash
go run scripts/signer.go sign private_key.pem ../scenarios/insider-threat-kill-chain.yaml
```
Expected: `insider-threat-kill-chain.yaml.sig` created, no errors.

- [ ] **Step 5: Commit**

```bash
git add scenarios/insider-threat-kill-chain.yaml scenarios/insider-threat-kill-chain.yaml.sig
git commit -m "feat(scenarios): Insider Threat kill-chain scenario"
git push
```

---

## Task 3: Wiring-Guard Test + Final Regression

**Files:**
- Modify: `orchestrator/internal/scenario/engine_test.go` (append new test function)

**Interfaces:**
- Consumes: `ParseYAML(b []byte) (*Scenario, error)` (`internal/scenario/engine.go:137`), `Scenario.Steps []Step`, `Step.Name string`, `Step.DetectionProfiles []string` (`internal/scenario/types.go:161`) — same interfaces every prior wiring-guard test this cycle uses. `"os"` is already imported in `engine_test.go`.

- [ ] **Step 1: Append the wiring-guard test to `orchestrator/internal/scenario/engine_test.go`**

Add immediately after `TestParseYAML_NewRansomwareFamiliesDetectionProfilesWired` (the most recent prior wiring-guard test):

```go
func TestParseYAML_InsiderThreatDetectionProfilesWired(t *testing.T) {
	cases := []struct {
		file        string
		stepName    string
		wantProfile string
	}{
		{"../../../scenarios/insider-threat-kill-chain.yaml", "Insider Stage 1 — Sensitive-File Search Outside Normal Job Scope (T1083 / T1005)", "windows_file_discovery"},
		{"../../../scenarios/insider-threat-kill-chain.yaml", "Insider Stage 2 — Personal Webmail Exfiltration Reachability (T1567)", "windows_webmail_egress"},
		{"../../../scenarios/insider-threat-kill-chain.yaml", "Insider Stage 3 — Mass File Rename/Delete Sabotage (T1485)", "windows_data_destruction"},
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

- [ ] **Step 2: Run the test to verify it passes**

Run: `go test ./internal/scenario/... -run TestParseYAML_InsiderThreatDetectionProfilesWired -v -count=1`
Expected: PASS, all 3 cases.

- [ ] **Step 3: Confirm the test can actually fail (temporarily break one assertion)**

Temporarily change the first case's `wantProfile` from `"windows_file_discovery"` to `"wrong_profile_name"`, run:
```bash
go test ./internal/scenario/... -run TestParseYAML_InsiderThreatDetectionProfilesWired -v -count=1
```
Expected: FAIL, with a diagnostic like `insider-threat-kill-chain.yaml / "Insider Stage 1 — Sensitive-File Search Outside Normal Job Scope (T1083 / T1005)": DetectionProfiles = [windows_file_discovery], want [wrong_profile_name]`.

Revert the case back to `"windows_file_discovery"`.

- [ ] **Step 4: Run the test again to verify it passes after revert**

Run: `go test ./internal/scenario/... -run TestParseYAML_InsiderThreatDetectionProfilesWired -v -count=1`
Expected: PASS, all 3 cases.

- [ ] **Step 5: Run the full `internal/scenario` package suite**

Run: `go test ./internal/scenario/... -v -count=1`
Expected: 100% PASS, including all pre-existing tests (both ransomware wiring-guard tests and every other test in the package) unmodified.

- [ ] **Step 6: Build the whole module**

Run (from `orchestrator/`): `go build ./...`
Expected: no errors, no output.

- [ ] **Step 7: Vet the whole module**

Run (from `orchestrator/`): `go vet ./...`
Expected: no output.

- [ ] **Step 8: Commit**

```bash
git add orchestrator/internal/scenario/engine_test.go
git commit -m "test(scenario): wiring-guard for Insider Threat pack — 3 steps assert detection_profiles"
git push
```
