# Audspect BAS — Scenarios Guide

**Platform Version:** v1.7.3

---

## Overview

A **scenario** is a named, versioned collection of simulation steps that tests one or more MITRE ATT&CK techniques on a target endpoint. Scenarios are the primary unit of work in Audspect BAS — everything (runs, findings, scores, reports) flows from a scenario execution.

---

## Built-in Scenario Library

Audspect BAS ships with 14+ signed built-in scenarios covering the full ATT&CK kill chain:

| Scenario | Framework | Techniques | Description |
|---|---|---|---|
| Safe Simulation | Custom | 5 | Read-only OS queries; safest baseline |
| Full Posture Scan | ART (All Windows) | 300+ | Comprehensive endpoint security posture |
| Selective ART Test | ART (Selective) | 40–80 | Focused technique subset; faster runtime |
| Endpoint Mastery | ART | 60+ | Deep endpoint control validation |
| LOLBin Execution Coverage | ART | 25+ | Living-off-the-land binary abuse |
| APT36 Kill Chain | Caldera + ART | 30+ | South Asia threat actor emulation |
| Caldera Full Windows | Caldera | 200+ | Full Caldera ability set |
| Caldera Selective | Caldera | 30+ | Targeted Caldera abilities |
| AD Credential Access | ART | 20+ | Active Directory credential techniques |
| Atomic Red Team Selective | ART | Variable | Analyst-selected ART atomic tests |
| Full Security Posture Scan | ART + Custom | 50+ | Combined posture + live execution |
| RBI CSCRF / SEBI MII Drill | Custom | 15+ | Regulatory compliance scenario |
| CIS Ubuntu L1 | Custom | 25+ | CIS Benchmark Level 1 hardening checks |
| Attack Path Collection | Native | N/A | Network topology + privilege graph collection |

---

## Execution Frameworks

Each scenario step is executed using one of three frameworks:

### Custom (Posture)

Custom steps run operator-authored PowerShell (Windows) or Bash (Linux) scripts on the agent. The script's exit code determines the verdict: `0` = PASS, `1` = FAIL, `2` = ERROR, `3` = SKIPPED.

Custom steps are used for:
- Configuration checks (registry, file presence, service state)
- OS hardening verification
- Application-specific controls
- CIS benchmark checks

### ART (Atomic Red Team)

ART steps map to entries in the Atomic Red Team library. The orchestrator resolves the atomic test YAML server-side, selects the appropriate executor for the agent's OS, and dispatches a fully-formed command to the agent. The agent executes and returns raw stdout/stderr.

The orchestrator interprets the raw output against the expected-pass/expected-fail patterns in the atomic definition to assign a verdict.

**ART modes:**

| Mode | Description |
|---|---|
| `art_selective` | Specific technique IDs chosen by the analyst |
| `art_all_windows` | All atomics applicable to Windows (300+ techniques) |

### Caldera

Caldera steps use the CTID Adversary Emulation Library (2,213+ abilities baked into the `bas-caldera` image). The orchestrator fetches ability details from the Caldera REST API, builds the step command, and dispatches to the agent via a Caldera operation.

---

## Hybrid Execution Modes

Scenarios can mix frameworks within a single run using three execution modes:

| Mode | What Runs | Use Case |
|---|---|---|
| **Posture** | Custom/posture steps only | Fast configuration checks; no live attack tooling |
| **Telemetry** | Live execution; SIEM/EDR monitoring | Test whether controls generate alerts |
| **Lab** | Payload-bearing steps included | Full payload delivery (lab environments only; requires explicit enable) |

Lab mode is disabled by default and requires the `lab_mode: true` flag both in the scenario YAML and in the agent's enrollment config.

---

## Scenario Lifecycle

```
Draft (YAML authored)
     │
     ▼
Signed (RSA-4096 .sig generated)
     │
     ▼
Loaded (Orchestrator verifies signature on startup or watch event)
     │
     ▼
Available (Visible in dashboard, runnable)
     │
     ▼
Dispatched (Run created, step commands sent to agent)
     │
     ▼
Completed / Partial / Failed
```

---

## Scenario YAML Format

```yaml
id: custom-endpoint-hardening
name: "Endpoint Hardening Checks"
version: "1.0.0"
description: "Validates Windows endpoint hardening posture."
tags:
  - windows
  - hardening
  - cis
tactics:
  - defense-evasion
  - credential-access
os_support:
  - windows
framework: custom
author: "Security Team"

steps:
  - id: step-001
    technique: "T1562.001"
    tactic: "defense-evasion"
    name: "Check Windows Defender is enabled"
    severity: high
    framework: custom
    executor: powershell
    command: |
      $status = (Get-MpComputerStatus).AntivirusEnabled
      if ($status -eq $true) { exit 0 } else { exit 1 }
    remediation: |
      Enable Windows Defender:
      Set-MpPreference -DisableRealtimeMonitoring $false
    expected_telemetry: "No telemetry expected; this is a configuration check."

  - id: step-002
    technique: "T1003.001"
    tactic: "credential-access"
    name: "LSASS memory dump attempt"
    severity: critical
    framework: art
    art_technique: "T1003.001"
    art_test_index: 0
    remediation: |
      Enable Credential Guard. Ensure EDR has LSASS protection active.
      Review EDR exclusions for lsass.exe.
```

### Required fields

| Field | Type | Description |
|---|---|---|
| `id` | string | Unique identifier; slug format |
| `name` | string | Human-readable name (dashboard display) |
| `version` | string | Semantic version |
| `steps` | array | One or more step definitions |

### Step required fields

| Field | Type | Description |
|---|---|---|
| `id` | string | Unique within this scenario |
| `technique` | string | MITRE ATT&CK technique ID (e.g., `T1003.001`) |
| `tactic` | string | MITRE ATT&CK tactic slug |
| `name` | string | Step display name |
| `severity` | string | `critical` / `high` / `medium` / `low` |
| `framework` | string | `custom` / `art` / `caldera` |

---

## Creating Custom Scenarios

### Via the dashboard builder

1. Navigate to **Scenarios** → **New Scenario**
2. Enter metadata: name, description, tags, OS support
3. Add steps using the step builder:
   - Select framework: Custom / ART / Caldera
   - For Custom: write the PowerShell/Bash check and set expected exit code
   - For ART: search and select an atomic test from the library
   - For Caldera: browse available abilities
4. Click **Save** — the orchestrator signs the YAML automatically
5. The scenario is immediately available to run

### Via YAML upload

1. Author the YAML following the format above
2. Navigate to **Scenarios** → **Upload** → drag and drop the YAML file
3. The orchestrator signs it on upload
4. Scenario appears in the list with a green signature badge

---

## Scenario Signing

Every scenario must have a valid RSA-4096 signature. The orchestrator:
- Rejects loading of unsigned scenarios
- Verifies signatures on the 15-second filesystem watch cycle
- Re-verifies the signature at dispatch time before sending to an agent

**Signatures are managed automatically when:**
- Using the dashboard builder (signed on save)
- Uploading YAML via the dashboard (signed on upload)
- Running `windows-build.ps1` for built-in scenarios (step 0b in the build pipeline)

**Do not modify scenario YAML files in place after signing.** Any change to the YAML (including adding a comment or changing whitespace) invalidates the signature.

---

## Scenario Metadata Tags

| Tag | Purpose |
|---|---|
| `windows` / `linux` / `macos` | OS applicability |
| `art` / `caldera` / `custom` | Framework type |
| `apt36` / `fin7` / `apt28` | Threat actor attribution |
| `credential-access` / `lateral-movement` / etc. | MITRE tactic tags |
| `rbi` / `sebi` / `cis` / `pci` | Compliance framework |
| `safe` | Marks scenario as non-destructive (no live payload) |
| `lab-only` | Marks scenario as requiring lab mode |

---

## Timeouts and Retries

| Setting | Default | Notes |
|---|---|---|
| Per-step timeout | 60 seconds | ART atomics only; custom steps: 30s |
| Run-level timeout | 30 minutes | Entire scenario must complete within this window |
| Step retry on ERROR | None | Steps do not retry on ERROR by default |
| Run retry on Partial | Manual | Analyst must manually retry partial runs |

---

## Dependencies and Prerequisites

ART atomics can declare prerequisites (e.g., required tools or files). The orchestrator resolves prerequisites from the `art_atomics` database and checks whether they are satisfied before dispatching the step.

If prerequisites are not met, the step is assigned `SKIPPED` with a note on which prerequisite was missing.

---

## Rollback

Custom posture steps can declare a `cleanup` block executed after the step regardless of verdict:

```yaml
steps:
  - id: step-001
    ...
    command: |
      # Create test file
      New-Item -Path C:\test-bas-marker.txt -Force
      if (Test-Path ...) { exit 0 } else { exit 1 }
    cleanup: |
      # Always remove test artifact
      Remove-Item -Path C:\test-bas-marker.txt -ErrorAction SilentlyContinue
```

ART atomics use the `cleanup_command` defined in the atomic YAML, executed automatically after each test.

---

## Publishing and Versioning

Scenarios carry a `version` field in their YAML. When a scenario is edited and saved:
- The version string is expected to be updated by the author
- The old signed YAML is replaced by the new signed version
- Existing runs that referenced the old version retain a snapshot of the step definitions used at run time

Scenario history (who ran what, when, with which version) is stored in the `runs` table and is visible in the Runs history.

---

*© Audspect — Confidential — Customer Distribution*
