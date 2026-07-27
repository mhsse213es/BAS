# Ransomware Modernization Baseline — Design Spec

**Status:** Approved for planning
**Author:** Audspect (brainstormed 2026-07-27)
**Scope:** Deliverable 1 of the "Ransomware Readiness suite" roadmap item ([[project_scenario_roadmap]]). Integration-debt-only: give the three existing ransomware scenarios structured detection profiles so they participate in Detection Validation, the verification store, and future Purple Team templates. Content-debt (new families: BlackCat, Akira, Play, RansomHub, Cl0p) is explicitly deferred to Deliverable 2, authored against this baseline once it exists.

## Problem

Three ransomware scenarios already exist — `lockbit-kill-chain.yaml` (5 stages, named LockBit 3.0), `ransomware-drill.yaml` (9 stages, generic "Enterprise Resilience Validation"), `endpoint-mastery/em-07-ransomware-readiness.yaml` (9 stages) — but none have `detection_profiles`/structured `expected_detection`. They predate the Detection Validation Pack and still only carry free-text `detection:` bullet points (human-readable documentation, consumed by no code path). This means none of the three:

- Appear in Detection Validation reports' expected-vs-actual gap analysis.
- Produce `verification_history` records (automatic or otherwise).
- Can be referenced by a future Ransomware Purple Team exercise template the way the 5 flagship scenarios (`apt29-kill-chain`, `volt-typhoon-lotl`, `kerberoasting-ad-drill`, `collection-staging-exfil`, `dlp-exfiltration-validation`) already are — Phase A1's `bridgeVerifiedDetections`/Phase B's templates have nothing to observe for a ransomware drill today.

Authoring five new ransomware families (BlackCat, Akira, Play, RansomHub, Cl0p) on top of this gap would produce a two-generation content library — some scenarios modern, some not — the exact technical debt this spec exists to avoid.

## Non-goals

- **No new ransomware family content.** BlackCat/Akira/Play/RansomHub/Cl0p are Deliverable 2, a separate future spec, authored against this baseline once it lands.
- **No stage restructuring.** Stage names, order, step count, `command:`, `cleanup:` — all stay byte-for-byte identical across all three scenario files. Only `detection_profiles:` is added to relevant steps. The existing free-text `detection:` bullets are left in place as documentation, not deleted.
- **No consolidation of `ransomware-drill.yaml`/`em-07-ransomware-readiness.yaml`'s real technique-coverage overlap.** Real, but migration and consolidation are separate concerns — merging scenarios mid-migration would conflate "which detection field wins" with "which scenario survives." A future cleanup spec, if ever prioritized, addresses this on the modernized baseline.
- **No canonical stage-taxonomy retrofit.** The "Initial Access → Discovery → Credential Access → ... → Encryption → Recovery Inhibition → Cleanup" structure discussed during brainstorming is a naming convention for Deliverable 2's *new* families, not a relabeling of these three already-authored, already-tested scenarios.
- **No Go code changes.** This is 100% scenario/profile YAML content. `internal/scenario`'s `detection_profiles.go` load-time validation and `internal/reporting`'s verification pipeline already work correctly (proven repeatedly across Phase A0/A1/B) — this deliverable gives three existing scenarios data to flow through already-tested mechanisms, not new mechanisms.

## Architecture

Nine new detection-profile files under `scenarios/detection-profiles/`, following the existing `windows_<behavior>.yaml` naming/structure convention exactly (see `windows_log_manipulation.yaml` for the canonical shape: `profile`/`version`/`expected_detection` list, each entry `id`/`provider`/`confidence`/`finding{severity,title,remediation,reference}` — `type`/`verification` left unset to inherit the provider's registry defaults). Plus reuse of the existing `windows_log_manipulation.yaml` (T1070.001 — Clear Windows Event Logs), which all three scenarios already exercise.

**Provider choice is deliberate, not decorative.** Every new profile uses `provider: microsoft_defender` — the only EDR-category provider whose registry default is `VerificationAutomatic` (`internal/scenario/providers.go`). This is the exact mechanism Phase A0's poller and Phase A1's bridge depend on: an expectation whose provider defaults to `VerificationManual` (SIEM/Identity/DLP-via-Purview/Sigma) never auto-resolves without a human manually attesting or a configured SP3 connector (the "Verification dependencies" finding from the Purple Team Phase B spec). Choosing `microsoft_defender` throughout is what actually closes the integration gap this spec exists to close — a profile with the "right" vendor name but a manual-default provider would look modernized while remaining just as inert as the free-text bullets it replaces.

**Confidence reflects real detectability**, not a uniform default: `required` for behaviors a real EDR product ships purpose-built detection for (VSS inhibition, mass file encryption, Defender tampering, backup-service stop — all textbook ransomware precursor/impact signatures), `recommended` for behaviors that are real signals but less universally alerted on (security-software discovery, SMB lateral probing, malicious service creation), `optional` for pure-enumeration behaviors with high noise and low standalone signal (file discovery, network share discovery) — informational only, never penalizing a score.

### New profile files

**`windows_security_software_discovery.yaml`** (T1518.001):
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

**`windows_vss_inhibition.yaml`** (T1490, 4 entries — VSS enumeration, VSS deletion, backup-catalog deletion, bootloader recovery-disable, matching the four distinct T1490 sub-behaviors across the three scenarios):
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

**`windows_smb_lateral_probe.yaml`** (T1021.002):
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

**`windows_ransomware_encryption.yaml`** (T1486, 2 entries — the core behavior):
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

**`windows_file_discovery.yaml`** (T1083):
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

**`windows_defender_tampering.yaml`** (T1562.001, 2 entries):
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

**`windows_malicious_service.yaml`** (T1543.003):
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

**`windows_network_share_discovery.yaml`** (T1135):
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

**`windows_backup_service_stop.yaml`** (T1489):
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

## Scenario file changes

Each modified step gains exactly one line, `detection_profiles: [<profile>]`, alongside its existing `technique_id:` — no other field changes.

**`lockbit-kill-chain.yaml`** (5 steps, all gain profiles):
| Stage | technique_id | `detection_profiles:` |
|---|---|---|
| Stage 1 — Security Software Discovery | T1518.001 | `[windows_security_software_discovery]` |
| Stage 2 — VSS Snapshot Enumeration | T1490 | `[windows_vss_inhibition]` |
| Stage 3 — SMB Admin Share Lateral Movement Probe | T1021.002 | `[windows_smb_lateral_probe]` |
| Stage 4 — Ransomware Payload Simulation | T1486 | `[windows_ransomware_encryption]` |
| Stage 5 — Event Log Clearing Attempt | T1070.001 | `[windows_log_manipulation]` |

**`ransomware-drill.yaml`** (9 steps, all gain profiles):
| Step | technique_id | `detection_profiles:` |
|---|---|---|
| File Enumeration | T1083 | `[windows_file_discovery]` |
| Defender Exclusion Invocation | T1562.001 | `[windows_defender_tampering]` |
| Event Log Clear Probe | T1070.001 | `[windows_log_manipulation]` |
| VSS + Backup Catalog Enumeration | T1490 | `[windows_vss_inhibition]` |
| Benign File Rename Probe | T1486 | `[windows_ransomware_encryption]` |
| XOR Encryption Simulation | T1486 | `[windows_ransomware_encryption]` |
| VSS Shadow Copy Deletion | T1490 | `[windows_vss_inhibition]` |
| Defender RTP Disable | T1562.001 | `[windows_defender_tampering]` |
| Malicious Service Probe | T1543.003 | `[windows_malicious_service]` |

**`endpoint-mastery/em-07-ransomware-readiness.yaml`** (10 steps, all gain profiles):
| Step | technique_id | `detection_profiles:` |
|---|---|---|
| Stage 1A — BFSI File Target Reconnaissance | T1083 | `[windows_file_discovery]` |
| Stage 1B — Network Share Discovery | T1135 | `[windows_network_share_discovery]` |
| Stage 2A — Defender Exclusion Invocation Probe | T1562.001 | `[windows_defender_tampering]` |
| Stage 2B — Event Log Clear Probe | T1070.001 | `[windows_log_manipulation]` |
| Stage 3A — Canary File Mass Encryption Loop | T1486 | `[windows_ransomware_encryption]` |
| Stage 3B — Ransom Note Drop | T1486 | `[windows_ransomware_encryption]` |
| Stage 4A — VSS Shadow Copy Deletion Signature | T1490 | `[windows_vss_inhibition]` |
| Stage 4B — wbadmin Backup Catalog Delete Probe | T1490 | `[windows_vss_inhibition]` |
| Stage 4C — BCDEdit Bootloader Recovery Disable Probe | T1490 | `[windows_vss_inhibition]` |
| Stage 5A — Backup Service Stop Attempt | T1489 | `[windows_backup_service_stop]` |

Multiple steps referencing the same profile (e.g. both `ransomware-drill.yaml`'s "Benign File Rename Probe" and "XOR Encryption Simulation" steps referencing `windows_ransomware_encryption`) is intentional and consistent with existing convention — a profile groups related expectations for one *behavior*, and more than one scenario step can exercise that same behavior.

## Migration & signing mechanics

1. Write all 9 new profile files under `scenarios/detection-profiles/`.
2. Add the `detection_profiles:` line to each of the 24 steps listed above (5 + 9 + 10) across the three existing scenario files — additive, one line per step, no other change.
3. Sign every new and modified file: `go run scripts/signer.go sign private_key.pem <path>` (from `orchestrator/`) for the 9 new profiles and the 3 modified scenarios, producing/updating `.sig` files. Builtin content is refused at load if unsigned or if the signature doesn't match current content — modifying a scenario file without re-signing it breaks that scenario entirely at next server start.

## Testing approach

- **Load-time profile validation**: `internal/scenario/detection_profiles.go`'s existing `validateExpectation` (provider key exists in the registry, confidence is one of required/recommended/optional) already runs for every profile at startup — no new Go code, the 9 new profiles get this validation for free.
- **`TestParseYAML_RansomwareScenariosDetectionProfilesWired`** (new, `internal/scenario/engine_test.go`, mirroring the wiring-guard pattern from Phase A1/B): parses all three modified scenario files via `scenario.ParseYAML` and asserts every one of the 24 listed steps has the correct non-empty `Step.DetectionProfiles []string` — table-driven, one row per (scenario, step, expected profile name).
- **Regression**: re-run the full `internal/scenario` package test suite — confirms the additive `detection_profiles:` field doesn't break existing parsing for any of the three files, and that `windows_log_manipulation.yaml`'s existing consumers (Volt Typhoon) are unaffected by these three scenarios newly referencing it too (profiles are read-only content, referencing one from multiple scenarios has no shared-mutable-state risk).
- **PowerShell syntax**: unaffected — no `command:`/`cleanup:` blocks change; the manual `[System.Management.Automation.Language.Parser]::ParseInput()` spot-check from prior sessions is unnecessary here since no PowerShell content is touched, only YAML metadata fields.
- **Manual verification**: after implementation, confirm `go build ./...` and `go vet ./...` are clean (they should be — no `.go` files change in this deliverable at all, only `.yaml`).
