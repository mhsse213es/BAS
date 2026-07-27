# Ransomware Modernization Baseline Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give the three existing ransomware scenarios (`lockbit-kill-chain.yaml`, `ransomware-drill.yaml`, `endpoint-mastery/em-07-ransomware-readiness.yaml`) structured detection profiles so they participate in Detection Validation, the verification store, and future Purple Team templates — closing the integration-debt gap before any new ransomware family content is authored.

**Architecture:** Nine new detection-profile YAML files under `scenarios/detection-profiles/` (all `provider: microsoft_defender`, the only EDR-category provider that auto-verifies per Phase A0/A1), plus one additive `detection_profiles:` line on each of 24 existing scenario steps across the three files. Zero Go code changes except one new wiring-guard test.

**Tech Stack:** YAML, the existing `scenario.ParseYAML` Go loader, `scripts/signer.go` (RSA-4096 content signing).

## Global Constraints

- No stage restructuring: stage names, order, step count, `command:`, `cleanup:` stay byte-for-byte identical across all three scenario files. Only `detection_profiles:` is added.
- Every new profile uses `provider: microsoft_defender` (the only EDR-category provider defaulting to `VerificationAutomatic`) — this is the mechanism that actually closes the integration gap, not decoration.
- No new ransomware family content (BlackCat/Akira/Play/RansomHub/Cl0p) — that's a separate future deliverable.
- No consolidation of `ransomware-drill.yaml`/`em-07-ransomware-readiness.yaml`'s technique overlap.
- Every new/modified builtin content file must be signed (`go run scripts/signer.go sign private_key.pem <path>`, from `orchestrator/`) — the server refuses unsigned or signature-mismatched builtin content at load.
- Docker Desktop is not required for this plan — no `internal/reporting`/`internal/verification`/`internal/exercise` tests are touched, only `internal/scenario`'s pure YAML-loader tests.

---

### Task 1: Nine new detection-profile files

**Files:**
- Create: `scenarios/detection-profiles/windows_security_software_discovery.yaml` (+ `.sig`)
- Create: `scenarios/detection-profiles/windows_vss_inhibition.yaml` (+ `.sig`)
- Create: `scenarios/detection-profiles/windows_smb_lateral_probe.yaml` (+ `.sig`)
- Create: `scenarios/detection-profiles/windows_ransomware_encryption.yaml` (+ `.sig`)
- Create: `scenarios/detection-profiles/windows_file_discovery.yaml` (+ `.sig`)
- Create: `scenarios/detection-profiles/windows_defender_tampering.yaml` (+ `.sig`)
- Create: `scenarios/detection-profiles/windows_malicious_service.yaml` (+ `.sig`)
- Create: `scenarios/detection-profiles/windows_network_share_discovery.yaml` (+ `.sig`)
- Create: `scenarios/detection-profiles/windows_backup_service_stop.yaml` (+ `.sig`)

**Interfaces:**
- Produces: 9 profile names (`windows_security_software_discovery`, `windows_vss_inhibition`, `windows_smb_lateral_probe`, `windows_ransomware_encryption`, `windows_file_discovery`, `windows_defender_tampering`, `windows_malicious_service`, `windows_network_share_discovery`, `windows_backup_service_stop`) — consumed by Tasks 2-4's `detection_profiles:` references and Task 5's wiring test.

- [ ] **Step 1: Create `windows_security_software_discovery.yaml`**

```yaml
# Detection Validation Profile — security-software discovery (T1518.001).
# Ransomware precursor: enumerating installed AV/EDR before payload deployment.
profile: windows_security_software_discovery
version: 1
expected_detection:
  - id: secsoft-discovery-edr
    provider: microsoft_defender
    confidence: recommended
    finding:
      severity: Medium
      title: "Security software discovery not detected"
      remediation: >-
        Alert on enumeration of AV/EDR processes and services (e.g. querying
        Windows Security Center, WMI AntiVirusProduct class, or common vendor
        process/service names) — a common ransomware precursor to confirm the
        target environment before deploying a payload.
      reference: "MITRE ATT&CK T1518.001 — Security Software Discovery"
```

- [ ] **Step 2: Create `windows_vss_inhibition.yaml`**

```yaml
# Detection Validation Profile — inhibit system recovery (T1490). The single
# highest-value ransomware precursor signature: an attacker who can delete
# shadow copies and backup catalogs has removed the victim's ability to
# recover without paying. Four sub-behaviors, one profile — all are the same
# underlying intent (destroy recovery options) observed at different layers.
profile: windows_vss_inhibition
version: 1
expected_detection:
  - id: vss-enum-edr
    provider: microsoft_defender
    confidence: required
    finding:
      severity: High
      title: "VSS/shadow-copy enumeration not detected"
      remediation: >-
        Alert on vssadmin/wmic shadowcopy/Get-CimInstance Win32_ShadowCopy
        enumeration — reconnaissance immediately preceding shadow-copy
        deletion.
      reference: "MITRE ATT&CK T1490 — Inhibit System Recovery"
  - id: vss-delete-edr
    provider: microsoft_defender
    confidence: required
    finding:
      severity: Critical
      title: "VSS/shadow-copy deletion not blocked"
      remediation: >-
        Enable Defender's "Block process creations originating from PSExec
        and WMI commands" and "Block process modifications of backups" ASR
        rules; alert on vssadmin delete shadows / wmic shadowcopy delete.
        This is the single most actionable ransomware kill-switch available
        to endpoint controls.
      reference: "MITRE ATT&CK T1490 — Inhibit System Recovery"
  - id: backup-catalog-delete-edr
    provider: microsoft_defender
    confidence: required
    finding:
      severity: Critical
      title: "Backup catalog deletion not blocked"
      remediation: >-
        Alert on wbadmin delete catalog / wbadmin delete systemstatebackup —
        removes the Windows Server Backup catalog, another recovery-removal
        vector distinct from VSS.
      reference: "MITRE ATT&CK T1490 — Inhibit System Recovery"
  - id: bootloader-recovery-disable-edr
    provider: microsoft_defender
    confidence: required
    finding:
      severity: Critical
      title: "Bootloader recovery-options tampering not blocked"
      remediation: >-
        Alert on bcdedit /set {default} recoveryenabled no and bcdedit
        /set {default} bootstatuspolicy ignoreallfailures — disables Windows
        Recovery Environment, a final recovery-removal step.
      reference: "MITRE ATT&CK T1490 — Inhibit System Recovery"
```

- [ ] **Step 3: Create `windows_smb_lateral_probe.yaml`**

```yaml
# Detection Validation Profile — SMB/Windows Admin Shares lateral movement
# probe (T1021.002). LockBit-style spreading via administrative shares.
profile: windows_smb_lateral_probe
version: 1
expected_detection:
  - id: smb-lateral-edr
    provider: microsoft_defender
    confidence: recommended
    finding:
      severity: Medium
      title: "SMB admin-share lateral movement probe not detected"
      remediation: >-
        Alert on connections to ADMIN$/C$ shares from non-administrative
        source hosts, or unusual volume of admin-share authentication
        attempts — a common ransomware lateral-spreading technique.
      reference: "MITRE ATT&CK T1021.002 — SMB/Windows Admin Shares"
```

- [ ] **Step 4: Create `windows_ransomware_encryption.yaml`**

```yaml
# Detection Validation Profile — data encrypted for impact (T1486). The
# defining ransomware behavior: mass file encryption plus the accompanying
# ransom note. This is what Defender's ransomware-specific protections
# (Controlled Folder Access, behavioral ransomware detection) exist for.
profile: windows_ransomware_encryption
version: 1
expected_detection:
  - id: mass-encryption-edr
    provider: microsoft_defender
    confidence: required
    finding:
      severity: Critical
      title: "Mass file encryption pattern not detected/blocked"
      remediation: >-
        Enable Controlled Folder Access and Defender's ransomware-specific
        behavioral protection. Alert on high-frequency file create+rename+
        delete in a short window, or a burst of files acquiring a new,
        unrecognized extension — the canonical ransomware encryption
        signature.
      reference: "MITRE ATT&CK T1486 — Data Encrypted for Impact"
  - id: ransom-note-edr
    provider: microsoft_defender
    confidence: required
    finding:
      severity: Critical
      title: "Ransom note deployment not detected"
      remediation: >-
        Alert on identical/near-identical text files being written to
        multiple directories in a short window — ransom-note deployment is
        a distinctive, high-fidelity signal that co-occurs with mass
        encryption.
      reference: "MITRE ATT&CK T1486 — Data Encrypted for Impact"
```

- [ ] **Step 5: Create `windows_file_discovery.yaml`**

```yaml
# Detection Validation Profile — file and directory discovery (T1083).
# Pre-encryption target enumeration; informational — very noisy, low
# standalone signal, but relevant context alongside later-stage detections.
profile: windows_file_discovery
version: 1
expected_detection:
  - id: file-discovery-edr
    provider: microsoft_defender
    confidence: optional
    finding:
      severity: Low
      title: "Mass file enumeration not observed as a distinct signal"
      remediation: >-
        File-discovery commands alone rarely warrant standalone detection —
        this expectation is informational, correlated with later-stage
        (encryption, VSS-inhibition) detections rather than scored on its
        own.
      reference: "MITRE ATT&CK T1083 — File and Directory Discovery"
```

- [ ] **Step 6: Create `windows_defender_tampering.yaml`**

```yaml
# Detection Validation Profile — impair defenses via Defender tampering
# (T1562.001). Attackers disable/exclude before deploying payloads;
# Tamper Protection exists specifically to prevent this class of action.
profile: windows_defender_tampering
version: 1
expected_detection:
  - id: defender-exclusion-edr
    provider: microsoft_defender
    confidence: required
    finding:
      severity: High
      title: "Defender exclusion addition not detected/blocked"
      remediation: >-
        Enable Tamper Protection to block unauthorized Add-MpPreference
        -ExclusionPath/-ExclusionProcess changes; alert on exclusion-list
        modifications outside change-managed maintenance windows.
      reference: "MITRE ATT&CK T1562.001 — Disable or Modify Tools"
  - id: defender-rtp-disable-edr
    provider: microsoft_defender
    confidence: required
    finding:
      severity: High
      title: "Defender real-time protection disable not detected/blocked"
      remediation: >-
        Enable Tamper Protection to block Set-MpPreference
        -DisableRealtimeMonitoring; RTP disable immediately preceding
        payload execution is a high-fidelity ransomware precursor.
      reference: "MITRE ATT&CK T1562.001 — Disable or Modify Tools"
```

- [ ] **Step 7: Create `windows_malicious_service.yaml`**

```yaml
# Detection Validation Profile — Windows service creation (T1543.003) used
# for persistence or as a ransomware deployment vector (e.g. PsExec-style
# service-based lateral execution).
profile: windows_malicious_service
version: 1
expected_detection:
  - id: malicious-service-edr
    provider: microsoft_defender
    confidence: recommended
    finding:
      severity: Medium
      title: "Suspicious service creation not detected"
      remediation: >-
        Alert on new-service creation (Security EID 4697 / System EID 7045)
        with an unusual binary path, especially from a non-administrative
        parent process or shortly before other ransomware-precursor
        activity.
      reference: "MITRE ATT&CK T1543.003 — Windows Service"
```

- [ ] **Step 8: Create `windows_network_share_discovery.yaml`**

```yaml
# Detection Validation Profile — network share discovery (T1135).
# Reconnaissance for lateral-spreading targets; informational, low
# standalone signal like T1083.
profile: windows_network_share_discovery
version: 1
expected_detection:
  - id: share-discovery-edr
    provider: microsoft_defender
    confidence: optional
    finding:
      severity: Low
      title: "Network share enumeration not observed as a distinct signal"
      remediation: >-
        Share-enumeration commands alone rarely warrant standalone
        detection — informational, correlated with later lateral-movement
        or encryption-stage detections.
      reference: "MITRE ATT&CK T1135 — Network Share Discovery"
```

- [ ] **Step 9: Create `windows_backup_service_stop.yaml`**

```yaml
# Detection Validation Profile — service stop (T1489) targeting backup
# services specifically — removes the last line of defense before
# encryption, alongside VSS/backup-catalog deletion.
profile: windows_backup_service_stop
version: 1
expected_detection:
  - id: backup-service-stop-edr
    provider: microsoft_defender
    confidence: required
    finding:
      severity: Critical
      title: "Backup service stop not detected/blocked"
      remediation: >-
        Alert on Stop-Service/sc stop targeting known backup-agent service
        names (Veeam, Backup Exec, Windows Server Backup, etc.) — stopping
        the backup service immediately before encryption is a
        high-fidelity, high-severity ransomware precursor.
      reference: "MITRE ATT&CK T1489 — Service Stop"
```

- [ ] **Step 10: Sign all 9 new profiles**

Run (from `orchestrator/`):

```bash
go run scripts/signer.go sign private_key.pem ../scenarios/detection-profiles/windows_security_software_discovery.yaml
go run scripts/signer.go sign private_key.pem ../scenarios/detection-profiles/windows_vss_inhibition.yaml
go run scripts/signer.go sign private_key.pem ../scenarios/detection-profiles/windows_smb_lateral_probe.yaml
go run scripts/signer.go sign private_key.pem ../scenarios/detection-profiles/windows_ransomware_encryption.yaml
go run scripts/signer.go sign private_key.pem ../scenarios/detection-profiles/windows_file_discovery.yaml
go run scripts/signer.go sign private_key.pem ../scenarios/detection-profiles/windows_defender_tampering.yaml
go run scripts/signer.go sign private_key.pem ../scenarios/detection-profiles/windows_malicious_service.yaml
go run scripts/signer.go sign private_key.pem ../scenarios/detection-profiles/windows_network_share_discovery.yaml
go run scripts/signer.go sign private_key.pem ../scenarios/detection-profiles/windows_backup_service_stop.yaml
```

Expected: each prints `[+] Signed ... -> ....sig`, producing 9 new `.sig` files.

- [ ] **Step 11: Commit**

```bash
git add scenarios/detection-profiles/windows_security_software_discovery.yaml scenarios/detection-profiles/windows_security_software_discovery.yaml.sig scenarios/detection-profiles/windows_vss_inhibition.yaml scenarios/detection-profiles/windows_vss_inhibition.yaml.sig scenarios/detection-profiles/windows_smb_lateral_probe.yaml scenarios/detection-profiles/windows_smb_lateral_probe.yaml.sig scenarios/detection-profiles/windows_ransomware_encryption.yaml scenarios/detection-profiles/windows_ransomware_encryption.yaml.sig scenarios/detection-profiles/windows_file_discovery.yaml scenarios/detection-profiles/windows_file_discovery.yaml.sig scenarios/detection-profiles/windows_defender_tampering.yaml scenarios/detection-profiles/windows_defender_tampering.yaml.sig scenarios/detection-profiles/windows_malicious_service.yaml scenarios/detection-profiles/windows_malicious_service.yaml.sig scenarios/detection-profiles/windows_network_share_discovery.yaml scenarios/detection-profiles/windows_network_share_discovery.yaml.sig scenarios/detection-profiles/windows_backup_service_stop.yaml scenarios/detection-profiles/windows_backup_service_stop.yaml.sig
git commit -m "feat(scenarios): 9 new ransomware detection profiles (Ransomware Modernization Baseline)"
git push
```

---

### Task 2: Wire `lockbit-kill-chain.yaml` (5 steps)

**Files:**
- Modify: `scenarios/lockbit-kill-chain.yaml` (+ re-sign `.sig`)

**Interfaces:**
- Consumes: the 9 profile names from Task 1.

- [ ] **Step 1: Add `detection_profiles:` to Stage 1 (T1518.001)**

Current:

```yaml
  - name: "LockBit Stage 1 — Security Software Discovery (T1518.001)"
    technique_id: T1518.001
    framework: custom
```

Replace with:

```yaml
  - name: "LockBit Stage 1 — Security Software Discovery (T1518.001)"
    technique_id: T1518.001
    detection_profiles:
      - windows_security_software_discovery
    framework: custom
```

- [ ] **Step 2: Add `detection_profiles:` to Stage 2 (T1490)**

Current:

```yaml
  - name: "LockBit Stage 2 — VSS Snapshot Enumeration (T1490)"
    technique_id: T1490
    framework: custom
```

Replace with:

```yaml
  - name: "LockBit Stage 2 — VSS Snapshot Enumeration (T1490)"
    technique_id: T1490
    detection_profiles:
      - windows_vss_inhibition
    framework: custom
```

- [ ] **Step 3: Add `detection_profiles:` to Stage 3 (T1021.002)**

Current:

```yaml
  - name: "LockBit Stage 3 — SMB Admin Share Lateral Movement Probe (T1021.002)"
    technique_id: T1021.002
    framework: custom
```

Replace with:

```yaml
  - name: "LockBit Stage 3 — SMB Admin Share Lateral Movement Probe (T1021.002)"
    technique_id: T1021.002
    detection_profiles:
      - windows_smb_lateral_probe
    framework: custom
```

- [ ] **Step 4: Add `detection_profiles:` to Stage 4 (T1486)**

Current:

```yaml
  - name: "LockBit Stage 4 — Ransomware Payload Simulation (T1486)"
    technique_id: T1486
    framework: custom
```

Replace with:

```yaml
  - name: "LockBit Stage 4 — Ransomware Payload Simulation (T1486)"
    technique_id: T1486
    detection_profiles:
      - windows_ransomware_encryption
    framework: custom
```

- [ ] **Step 5: Add `detection_profiles:` to Stage 5 (T1070.001)**

Current:

```yaml
  - name: "LockBit Stage 5 — Event Log Clearing Attempt (T1070.001)"
    technique_id: T1070.001
    framework: custom
```

Replace with (reuses the pre-existing `windows_log_manipulation` profile — no new file):

```yaml
  - name: "LockBit Stage 5 — Event Log Clearing Attempt (T1070.001)"
    technique_id: T1070.001
    detection_profiles:
      - windows_log_manipulation
    framework: custom
```

- [ ] **Step 6: Validate the file is valid YAML**

Run (from repo root): `python3 -c "import yaml; yaml.safe_load(open('scenarios/lockbit-kill-chain.yaml'))"`
Expected: exits 0, no output. (This catches a YAML syntax error immediately; Task 5 adds the actual Go-level assertion that the right profile names are wired to the right steps.)

- [ ] **Step 7: Re-sign the modified file**

Run (from `orchestrator/`): `go run scripts/signer.go sign private_key.pem ../scenarios/lockbit-kill-chain.yaml`
Expected: `[+] Signed ../scenarios/lockbit-kill-chain.yaml -> ../scenarios/lockbit-kill-chain.yaml.sig`

- [ ] **Step 8: Commit**

```bash
git add scenarios/lockbit-kill-chain.yaml scenarios/lockbit-kill-chain.yaml.sig
git commit -m "feat(scenarios): wire detection profiles into lockbit-kill-chain.yaml"
git push
```

---

### Task 3: Wire `ransomware-drill.yaml` (9 steps)

**Files:**
- Modify: `scenarios/ransomware-drill.yaml` (+ re-sign `.sig`)

**Interfaces:**
- Consumes: the 9 profile names from Task 1.

- [ ] **Step 1: Add `detection_profiles:` to "File Enumeration" (T1083)**

Current:

```yaml
  - name: "File Enumeration (BFSI high-value filename markers)"
    technique_id: T1083
    framework: custom
```

Replace with:

```yaml
  - name: "File Enumeration (BFSI high-value filename markers)"
    technique_id: T1083
    detection_profiles:
      - windows_file_discovery
    framework: custom
```

- [ ] **Step 2: Add `detection_profiles:` to "Defender Exclusion Invocation" (T1562.001)**

Current:

```yaml
  - name: "Defender Exclusion Invocation (cmdline probe  -  no state change)"
    technique_id: T1562.001
    framework: custom
```

Replace with:

```yaml
  - name: "Defender Exclusion Invocation (cmdline probe  -  no state change)"
    technique_id: T1562.001
    detection_profiles:
      - windows_defender_tampering
    framework: custom
```

- [ ] **Step 3: Add `detection_profiles:` to "Event Log Clear Probe" (T1070.001)**

Current:

```yaml
  - name: "Event Log Clear Probe (nonexistent log  -  process telemetry only)"
    technique_id: T1070.001
    framework: custom
```

Replace with:

```yaml
  - name: "Event Log Clear Probe (nonexistent log  -  process telemetry only)"
    technique_id: T1070.001
    detection_profiles:
      - windows_log_manipulation
    framework: custom
```

- [ ] **Step 4: Add `detection_profiles:` to "VSS + Backup Catalog Enumeration" (T1490)**

Current:

```yaml
  - name: "VSS + Backup Catalog Enumeration"
    technique_id: T1490
    framework: custom
```

Replace with:

```yaml
  - name: "VSS + Backup Catalog Enumeration"
    technique_id: T1490
    detection_profiles:
      - windows_vss_inhibition
    framework: custom
```

- [ ] **Step 5: Add `detection_profiles:` to "Benign File Rename Probe" (T1486)**

Current:

```yaml
  - name: "Benign File Rename Probe (.bas_locked extension)"
    technique_id: T1486
    framework: custom
```

Replace with:

```yaml
  - name: "Benign File Rename Probe (.bas_locked extension)"
    technique_id: T1486
    detection_profiles:
      - windows_ransomware_encryption
    framework: custom
```

- [ ] **Step 6: Add `detection_profiles:` to "XOR Encryption Simulation" (T1486)**

Current:

```yaml
  - name: "XOR Encryption Simulation (lab  -  isolated temp dir, forced cleanup)"
    technique_id: T1486
    framework: custom
```

Replace with:

```yaml
  - name: "XOR Encryption Simulation (lab  -  isolated temp dir, forced cleanup)"
    technique_id: T1486
    detection_profiles:
      - windows_ransomware_encryption
    framework: custom
```

- [ ] **Step 7: Add `detection_profiles:` to "VSS Shadow Copy Deletion" (T1490)**

Current:

```yaml
  - name: "VSS Shadow Copy Deletion (lab  -  requires BAS_CONFIRM_VSS_DELETE=true)"
    technique_id: T1490
    framework: custom
```

Replace with:

```yaml
  - name: "VSS Shadow Copy Deletion (lab  -  requires BAS_CONFIRM_VSS_DELETE=true)"
    technique_id: T1490
    detection_profiles:
      - windows_vss_inhibition
    framework: custom
```

- [ ] **Step 8: Add `detection_profiles:` to "Defender RTP Disable" (T1562.001)**

Current:

```yaml
  - name: "Defender RTP Disable (lab  -  mandatory restoration + health check)"
    technique_id: T1562.001
    framework: custom
```

Replace with:

```yaml
  - name: "Defender RTP Disable (lab  -  mandatory restoration + health check)"
    technique_id: T1562.001
    detection_profiles:
      - windows_defender_tampering
    framework: custom
```

- [ ] **Step 9: Add `detection_profiles:` to "Malicious Service Probe" (T1543.003)**

Current:

```yaml
  - name: "Malicious Service Probe (lab  -  creation + lineage logging)"
    technique_id: T1543.003
    framework: custom
```

Replace with:

```yaml
  - name: "Malicious Service Probe (lab  -  creation + lineage logging)"
    technique_id: T1543.003
    detection_profiles:
      - windows_malicious_service
    framework: custom
```

- [ ] **Step 10: Validate the file is valid YAML**

Run (from repo root): `python3 -c "import yaml; yaml.safe_load(open('scenarios/ransomware-drill.yaml'))"`
Expected: exits 0, no output.

- [ ] **Step 11: Re-sign the modified file**

Run (from `orchestrator/`): `go run scripts/signer.go sign private_key.pem ../scenarios/ransomware-drill.yaml`
Expected: `[+] Signed ../scenarios/ransomware-drill.yaml -> ../scenarios/ransomware-drill.yaml.sig`

- [ ] **Step 12: Commit**

```bash
git add scenarios/ransomware-drill.yaml scenarios/ransomware-drill.yaml.sig
git commit -m "feat(scenarios): wire detection profiles into ransomware-drill.yaml"
git push
```

---

### Task 4: Wire `endpoint-mastery/em-07-ransomware-readiness.yaml` (10 steps)

**Files:**
- Modify: `scenarios/endpoint-mastery/em-07-ransomware-readiness.yaml` (+ re-sign `.sig`)

**Interfaces:**
- Consumes: the 9 profile names from Task 1.

- [ ] **Step 1: Add `detection_profiles:` to "Stage 1A — BFSI File Target Reconnaissance" (T1083)**

Current:

```yaml
  - name: "Stage 1A — BFSI File Target Reconnaissance"
    technique_id: T1083
    framework: custom
```

Replace with:

```yaml
  - name: "Stage 1A — BFSI File Target Reconnaissance"
    technique_id: T1083
    detection_profiles:
      - windows_file_discovery
    framework: custom
```

- [ ] **Step 2: Add `detection_profiles:` to "Stage 1B — Network Share Discovery" (T1135)**

Current:

```yaml
  - name: "Stage 1B — Network Share Discovery"
    technique_id: T1135
    framework: custom
```

Replace with:

```yaml
  - name: "Stage 1B — Network Share Discovery"
    technique_id: T1135
    detection_profiles:
      - windows_network_share_discovery
    framework: custom
```

- [ ] **Step 3: Add `detection_profiles:` to "Stage 2A — Defender Exclusion Invocation Probe" (T1562.001)**

Current:

```yaml
  - name: "Stage 2A — Defender Exclusion Invocation Probe"
    technique_id: T1562.001
    framework: custom
```

Replace with:

```yaml
  - name: "Stage 2A — Defender Exclusion Invocation Probe"
    technique_id: T1562.001
    detection_profiles:
      - windows_defender_tampering
    framework: custom
```

- [ ] **Step 4: Add `detection_profiles:` to "Stage 2B — Event Log Clear Probe" (T1070.001)**

Current:

```yaml
  - name: "Stage 2B — Event Log Clear Probe"
    technique_id: T1070.001
    framework: custom
```

Replace with:

```yaml
  - name: "Stage 2B — Event Log Clear Probe"
    technique_id: T1070.001
    detection_profiles:
      - windows_log_manipulation
    framework: custom
```

- [ ] **Step 5: Add `detection_profiles:` to "Stage 3A — Canary File Mass Encryption Loop" (T1486)**

Current:

```yaml
  - name: "Stage 3A — Canary File Mass Encryption Loop"
    technique_id: T1486
    framework: custom
```

Replace with:

```yaml
  - name: "Stage 3A — Canary File Mass Encryption Loop"
    technique_id: T1486
    detection_profiles:
      - windows_ransomware_encryption
    framework: custom
```

- [ ] **Step 6: Add `detection_profiles:` to "Stage 3B — Ransom Note Drop (Canary Directory)" (T1486)**

Current:

```yaml
  - name: "Stage 3B — Ransom Note Drop (Canary Directory)"
    technique_id: T1486
    framework: custom
```

Replace with:

```yaml
  - name: "Stage 3B — Ransom Note Drop (Canary Directory)"
    technique_id: T1486
    detection_profiles:
      - windows_ransomware_encryption
    framework: custom
```

- [ ] **Step 7: Add `detection_profiles:` to "Stage 4A — VSS Shadow Copy Deletion Signature" (T1490)**

Current:

```yaml
  - name: "Stage 4A — VSS Shadow Copy Deletion Signature"
    technique_id: T1490
    framework: custom
```

Replace with:

```yaml
  - name: "Stage 4A — VSS Shadow Copy Deletion Signature"
    technique_id: T1490
    detection_profiles:
      - windows_vss_inhibition
    framework: custom
```

- [ ] **Step 8: Add `detection_profiles:` to "Stage 4B — wbadmin Backup Catalog Delete Probe" (T1490)**

Current:

```yaml
  - name: "Stage 4B — wbadmin Backup Catalog Delete Probe"
    technique_id: T1490
    framework: custom
```

Replace with:

```yaml
  - name: "Stage 4B — wbadmin Backup Catalog Delete Probe"
    technique_id: T1490
    detection_profiles:
      - windows_vss_inhibition
    framework: custom
```

- [ ] **Step 9: Add `detection_profiles:` to "Stage 4C — BCDEdit Bootloader Recovery Disable Probe" (T1490)**

Current:

```yaml
  - name: "Stage 4C — BCDEdit Bootloader Recovery Disable Probe"
    technique_id: T1490
    framework: custom
```

Replace with:

```yaml
  - name: "Stage 4C — BCDEdit Bootloader Recovery Disable Probe"
    technique_id: T1490
    detection_profiles:
      - windows_vss_inhibition
    framework: custom
```

- [ ] **Step 10: Add `detection_profiles:` to "Stage 5A — Backup Service Stop Attempt" (T1489)**

Current:

```yaml
  - name: "Stage 5A — Backup Service Stop Attempt"
    technique_id: T1489
    framework: custom
```

Replace with:

```yaml
  - name: "Stage 5A — Backup Service Stop Attempt"
    technique_id: T1489
    detection_profiles:
      - windows_backup_service_stop
    framework: custom
```

- [ ] **Step 11: Validate the file is valid YAML**

Run (from repo root): `python3 -c "import yaml; yaml.safe_load(open('scenarios/endpoint-mastery/em-07-ransomware-readiness.yaml'))"`
Expected: exits 0, no output.

- [ ] **Step 12: Re-sign the modified file**

Run (from `orchestrator/`): `go run scripts/signer.go sign private_key.pem ../scenarios/endpoint-mastery/em-07-ransomware-readiness.yaml`
Expected: `[+] Signed ../scenarios/endpoint-mastery/em-07-ransomware-readiness.yaml -> ../scenarios/endpoint-mastery/em-07-ransomware-readiness.yaml.sig`

- [ ] **Step 13: Commit**

```bash
git add scenarios/endpoint-mastery/em-07-ransomware-readiness.yaml scenarios/endpoint-mastery/em-07-ransomware-readiness.yaml.sig
git commit -m "feat(scenarios): wire detection profiles into em-07-ransomware-readiness.yaml"
git push
```

---

### Task 5: Wiring-guard test + final regression

**Files:**
- Modify: `orchestrator/internal/scenario/engine_test.go` (new test)

**Interfaces:**
- Consumes: `scenario.ParseYAML` (pre-existing), `Step.DetectionProfiles []string` (pre-existing field, `orchestrator/internal/scenario/types.go:161`). All 24 (scenario, step, profile) tuples from Tasks 2-4.

- [ ] **Step 1: Write the failing test**

Add to `orchestrator/internal/scenario/engine_test.go`:

```go
func TestParseYAML_RansomwareScenariosDetectionProfilesWired(t *testing.T) {
	cases := []struct {
		file        string
		stepName    string
		wantProfile string
	}{
		{"../../scenarios/lockbit-kill-chain.yaml", "LockBit Stage 1 — Security Software Discovery (T1518.001)", "windows_security_software_discovery"},
		{"../../scenarios/lockbit-kill-chain.yaml", "LockBit Stage 2 — VSS Snapshot Enumeration (T1490)", "windows_vss_inhibition"},
		{"../../scenarios/lockbit-kill-chain.yaml", "LockBit Stage 3 — SMB Admin Share Lateral Movement Probe (T1021.002)", "windows_smb_lateral_probe"},
		{"../../scenarios/lockbit-kill-chain.yaml", "LockBit Stage 4 — Ransomware Payload Simulation (T1486)", "windows_ransomware_encryption"},
		{"../../scenarios/lockbit-kill-chain.yaml", "LockBit Stage 5 — Event Log Clearing Attempt (T1070.001)", "windows_log_manipulation"},

		{"../../scenarios/ransomware-drill.yaml", "File Enumeration (BFSI high-value filename markers)", "windows_file_discovery"},
		{"../../scenarios/ransomware-drill.yaml", "Defender Exclusion Invocation (cmdline probe  -  no state change)", "windows_defender_tampering"},
		{"../../scenarios/ransomware-drill.yaml", "Event Log Clear Probe (nonexistent log  -  process telemetry only)", "windows_log_manipulation"},
		{"../../scenarios/ransomware-drill.yaml", "VSS + Backup Catalog Enumeration", "windows_vss_inhibition"},
		{"../../scenarios/ransomware-drill.yaml", "Benign File Rename Probe (.bas_locked extension)", "windows_ransomware_encryption"},
		{"../../scenarios/ransomware-drill.yaml", "XOR Encryption Simulation (lab  -  isolated temp dir, forced cleanup)", "windows_ransomware_encryption"},
		{"../../scenarios/ransomware-drill.yaml", "VSS Shadow Copy Deletion (lab  -  requires BAS_CONFIRM_VSS_DELETE=true)", "windows_vss_inhibition"},
		{"../../scenarios/ransomware-drill.yaml", "Defender RTP Disable (lab  -  mandatory restoration + health check)", "windows_defender_tampering"},
		{"../../scenarios/ransomware-drill.yaml", "Malicious Service Probe (lab  -  creation + lineage logging)", "windows_malicious_service"},

		{"../../scenarios/endpoint-mastery/em-07-ransomware-readiness.yaml", "Stage 1A — BFSI File Target Reconnaissance", "windows_file_discovery"},
		{"../../scenarios/endpoint-mastery/em-07-ransomware-readiness.yaml", "Stage 1B — Network Share Discovery", "windows_network_share_discovery"},
		{"../../scenarios/endpoint-mastery/em-07-ransomware-readiness.yaml", "Stage 2A — Defender Exclusion Invocation Probe", "windows_defender_tampering"},
		{"../../scenarios/endpoint-mastery/em-07-ransomware-readiness.yaml", "Stage 2B — Event Log Clear Probe", "windows_log_manipulation"},
		{"../../scenarios/endpoint-mastery/em-07-ransomware-readiness.yaml", "Stage 3A — Canary File Mass Encryption Loop", "windows_ransomware_encryption"},
		{"../../scenarios/endpoint-mastery/em-07-ransomware-readiness.yaml", "Stage 3B — Ransom Note Drop (Canary Directory)", "windows_ransomware_encryption"},
		{"../../scenarios/endpoint-mastery/em-07-ransomware-readiness.yaml", "Stage 4A — VSS Shadow Copy Deletion Signature", "windows_vss_inhibition"},
		{"../../scenarios/endpoint-mastery/em-07-ransomware-readiness.yaml", "Stage 4B — wbadmin Backup Catalog Delete Probe", "windows_vss_inhibition"},
		{"../../scenarios/endpoint-mastery/em-07-ransomware-readiness.yaml", "Stage 4C — BCDEdit Bootloader Recovery Disable Probe", "windows_vss_inhibition"},
		{"../../scenarios/endpoint-mastery/em-07-ransomware-readiness.yaml", "Stage 5A — Backup Service Stop Attempt", "windows_backup_service_stop"},
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

`orchestrator/internal/scenario/engine_test.go` already imports `"os"` — no import change needed. `ParseYAML(b []byte) (*Scenario, error)`, `Scenario.Steps []Step`, and `Step.Name string` are all pre-existing, confirmed field/function names this test only reads.

Note on test ordering: unlike a typical TDD red-green cycle, this test's content dependency (the `detection_profiles:` wiring) was already committed in Tasks 1-4, which ran before this task. There is no "write failing test, then implement" step here — the content already exists. This step instead confirms the test's assertions are meaningful by first deliberately breaking one, then fixing it back.

- [ ] **Step 2: Confirm the test can actually fail (temporarily break one assertion)**

Temporarily change the first case's `wantProfile` from `"windows_security_software_discovery"` to `"wrong_profile_name"`, run:

Run (from `orchestrator/`): `go test ./internal/scenario/... -run TestParseYAML_RansomwareScenariosDetectionProfilesWired -v`
Expected: FAIL — `.../lockbit-kill-chain.yaml / "LockBit Stage 1 — Security Software Discovery (T1518.001)": DetectionProfiles = [windows_security_software_discovery], want [wrong_profile_name]`

Revert the case back to `"windows_security_software_discovery"`.

- [ ] **Step 3: Run test to verify it passes**

Run: `go test ./internal/scenario/... -run TestParseYAML_RansomwareScenariosDetectionProfilesWired -v`
Expected: PASS (all 24 cases)

- [ ] **Step 4: Run the full `internal/scenario` package suite**

Run: `go test ./internal/scenario/... -v -count=1`
Expected: 100% PASS, including every pre-existing test unmodified

- [ ] **Step 5: Verify it compiles**

Run: `go build ./...`
Expected: no errors

- [ ] **Step 6: Run `go vet`**

Run: `go vet ./...`
Expected: no output

- [ ] **Step 7: Commit**

```bash
git add orchestrator/internal/scenario/engine_test.go
git commit -m "test(scenario): wiring-guard for Ransomware Modernization Baseline — 24 steps assert detection_profiles"
git push
```
