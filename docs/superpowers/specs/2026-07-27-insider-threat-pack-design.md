# Insider Threat Pack — Design

**Scope:** Priority #3 item in the scenario roadmap ([[project_scenario_roadmap]]), following the completed Ransomware Readiness suite. Net-new content only: mass file rename/delete (sabotage), personal-webmail exfiltration, and an insider-framed sensitive-file-search step, packaged as one combined scenario.

## Problem

The roadmap's Insider Threat pack was originally listed as 8 behaviors: USB copy, mass rename/delete, sensitive-file search, archive, cloud upload, email staging, clipboard, print. Checking existing content first revealed 5 of those 8 already ship, under a different framing:

- `dlp-exfiltration-validation.yaml` — USB copy, clipboard, print, archive staging, local staging (all 5, DLP/data-protection framed).
- `collection-staging-exfil.yaml` — sensitive-file discovery, bulk staging, archive (2 methods), HTTP/DNS/FTP/WebDAV exfiltration, generic cloud-storage-reachability (external-adversary framed).

Building all 8 behaviors fresh under a new "Insider Threat" label would duplicate 5 already-shipped, already-tested behaviors — the same "two-generation content debt" the Ransomware Modernization Baseline (Deliverable 1) existed to avoid. Two genuinely new behaviors have no existing coverage anywhere: destructive/sabotage file operations, and personal webmail as an exfiltration channel outside corporate email DLP.

## Non-goals

- **No re-testing of USB/clipboard/print/archive/local-staging.** Already covered by `dlp-exfiltration-validation.yaml`. This scenario's description cross-references it explicitly rather than duplicating its steps.
- **No re-testing of bulk file staging or protocol-based exfiltration (HTTP/DNS/FTP/WebDAV/generic cloud storage).** Already covered by `collection-staging-exfil.yaml`. Cross-referenced, not duplicated.
- **No two-file split (Data Theft vs Sabotage).** A real insider incident usually combines both — a departing/disgruntled employee steals data, then destroys evidence on the way out. One combined scenario tells that coherent story; splitting 3 stages across 2 files would produce two near-empty scenarios.
- **No actual email sent, no actual upload.** The webmail step is a TCP-reachability probe only, identical safety class to the already-shipped `windows_cloud_egress` — no message composed, no attachment sent, no personal account touched.
- **No real user/production files touched by the sabotage step.** Only BAS-owned, freshly-created synthetic decoy files in a throwaway `%TEMP%` directory are renamed and deleted — same discipline as every existing scenario (`[BAS-SIM]` tagged, synthetic content only).
- **No Go code changes.** Pure scenario/profile YAML content, same as the Ransomware Readiness deliverables — `internal/scenario`'s load-time validation and Provider Registry already handle new content correctly.

## Architecture

### Provider selection — corrected from first assumption

`windows_cloud_egress` (the existing profile closest in shape to what a webmail probe needs) actually uses `provider: microsoft_sentinel` / `microsoft_purview`, **not** `microsoft_defender` — a reachability probe to an external site is a network/CASB/SIEM detection point, not an EDR signature. The "always use `microsoft_defender`" rule from the Ransomware Readiness work was specific to that domain's genuinely-EDR-detectable behaviors (VSS deletion, mass encryption, Defender tampering), not a blanket rule. This pack follows the **honest, already-precedented** classification per behavior:

| Stage | Technique | Profile | Provider | Why |
|---|---|---|---|---|
| 1. Sensitive-file search | T1083/T1005 | `windows_file_discovery` (existing, reused as-is) | `microsoft_defender`, `optional` | Already shipped, unchanged |
| 2. Personal-webmail exfiltration reachability | T1567 | `windows_webmail_egress` (new) | `microsoft_sentinel` (network) + `microsoft_purview` (dlp) | Same category as `windows_cloud_egress` — a reachability probe, not an EDR signature |
| 3. Mass file rename/delete (sabotage) | T1485 | `windows_data_destruction` (new) | `microsoft_defender`, `required` | Genuinely EDR-detectable — same reasoning as ransomware's mass-encryption step: rapid bulk file modify/delete is a real, purpose-built EDR heuristic (Controlled Folder Access / ransomware-specific behavioral protection) |

### New detection profiles

**`scenarios/detection-profiles/windows_webmail_egress.yaml`** (T1567 — personal webmail as an exfil channel outside corporate email DLP; mirrors `windows_cloud_egress`'s exact 2-entry network+DLP shape):
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

**`scenarios/detection-profiles/windows_data_destruction.yaml`** (T1485 — mass rename/delete; mirrors `windows_ransomware_encryption`'s shape, genuinely EDR-detectable):
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

### Novel command implementations

**Personal-webmail reachability probe** (adapts `collection-staging-exfil.yaml`'s "Exfil Stage 10 — Cloud Storage Egress Reachability" TCP-connect pattern, swapping endpoints from cloud-storage hosts to personal-webmail hosts):
```powershell
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
```
`cleanup: ""` (read-only probe, no state left).

**Mass file rename/delete sabotage** (creates ~5-10 BAS-owned decoy files with realistic sensitive-sounding names, mass-renames them, mass-deletes them, then removes the directory — only ever touches its own just-created decoys):
```powershell
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
```
`cleanup: |` — `Remove-Item (Join-Path $env:TEMP 'bas_insider_*') -Recurse -Force -ErrorAction SilentlyContinue` (defensive safety net in case the main command is interrupted mid-run; the main command already removes its own directory on the happy path).

`requires_priv: user` (all operations in `%TEMP%`, no admin needed), `risk: low` (only BAS-owned decoys touched), `production_safe: true`, `reversible: true` (no real user/system data touched — same convention as the ransomware encryption-simulation steps, which also delete their own created artifacts).

### Reused step

**Sensitive-file search** (Stage 1): reuses `em-07-ransomware-readiness.yaml` Stage 1A's exact command verbatim (BFSI-pattern file scan across Desktop/Documents/Downloads, depth=2, read-only), with only the `Write-Output` narrative and `[BAS-SIM-INSIDER-S1]` tag changed to insider framing (searching for files matching sensitive patterns is the same mechanical action whether framed as external-attacker reconnaissance or insider misuse of legitimate access — the distinguishing signal in a real incident is behavioral/contextual, e.g. access outside normal job scope, which this BAS step documents in its description but cannot mechanically verify). `technique_id`, `requires_priv`, `timeout_sec`, `fidelity`, `production_safe`, `risk`, `blast_radius`, `reversible`, `telemetry`, and `detection` fields all carry over unchanged from the source step (`user`, `telemetry-safe`, `production_safe: true`, `risk: low`) — same convention established in the Ransomware Readiness deliverables.

### File and task structure

**3 new builtin files** (each `.sig`-paired), no Go code changes:
- `scenarios/insider-threat-kill-chain.yaml` (3 steps)
- `scenarios/detection-profiles/windows_webmail_egress.yaml`
- `scenarios/detection-profiles/windows_data_destruction.yaml`

`id: insider-threat-kill-chain`, `mitre_phases: [discovery, exfiltration, impact]`, `supported_os: [windows]`. Description narrates a single coherent story — a departing/disgruntled employee searches for sensitive files outside normal job scope, exfiltrates via personal webmail, then destroys evidence on the way out — and explicitly cross-references `dlp-exfiltration-validation.yaml` and `collection-staging-exfil.yaml` for the channels this scenario deliberately doesn't re-test.

**Task decomposition (3 tasks):**
1. 2 new detection profiles (`windows_webmail_egress`, `windows_data_destruction`)
2. `insider-threat-kill-chain.yaml` (3 steps)
3. Wiring-guard test + final regression

### Testing, signing

- **Per-file validation:** `python3 -c "import yaml; yaml.safe_load(open('...'))"` structural check on all 3 new files, plus PowerShell AST syntax check (`[System.Management.Automation.Language.Parser]::ParseInput`) on the 3 command/cleanup blocks — both already run against this spec's exact command text during design, zero syntax errors.
- **Wiring-guard test:** new function `TestParseYAML_InsiderThreatDetectionProfilesWired` in `orchestrator/internal/scenario/engine_test.go` (kept separate from the ransomware wiring-guard tests — different file), 3-case table asserting `DetectionProfiles`. Same "prove it can fail" check as every prior deliverable this cycle (temporarily break one assertion, confirm FAIL, revert).
- **Full regression:** `go test ./internal/scenario/... -v -count=1`, `go build ./...`, `go vet ./...` — all must pass clean.
- **Signing:** `go run scripts/signer.go sign private_key.pem <path>` (run from `orchestrator/`) for all 3 new files.
- **Migration:** none — brand-new files, no existing scenario behavior changes.
